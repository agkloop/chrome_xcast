package main

import (
	"context"
	"io"
	"mime"
	"net/http"
	"sync"
	"time"
)

// prefetcher reads HLS segments ahead of the TV: when the TV asks for one, the
// next pfDepth segments of the same playlist are fetched, pfParallel at a
// time, so a slow moment at the site is covered by segments already here.
// Playlists are followed separately (a stream with its own audio has two).
// What the TV moved away from (a seek, another quality) is dropped and its
// fetches cancelled. Bounded memory; anything unusual (ranges, huge segments,
// errors) simply falls back to a normal on-demand fetch.
const (
	pfMaxTotal = 64 << 20 // held, plus pfMaxItem for each fetch in flight
	pfMaxItem  = 16 << 20
	pfMaxNext  = 50000
	pfMaxLists = 64
	pfDepth    = 4
	pfParallel = 2
	// A playlist the TV has not asked from for this many segment requests
	// (it switched to another quality) loses what was fetched for it.
	pfForget = 3 * pfDepth
)

type pfItem struct {
	ready  chan struct{} // closed once the fetch is over
	done   bool          // fetch over (under pf.mu)
	ok     bool
	hdr    http.Header
	body   []byte
	list   string
	cancel context.CancelFunc
}

type prefetcher struct {
	mu       sync.Mutex
	next     map[string]string // segment -> the one after it
	list     map[string]string // segment -> its playlist
	items    map[string]*pfItem
	pos      map[string]string // playlist -> segment the TV asked for last
	seen     map[string]int    // playlist -> value of asks at that moment
	asks     int               // segment requests so far
	inflight int
	size     int
	closed   bool
}

func newPrefetcher() *prefetcher {
	return &prefetcher{
		next: map[string]string{}, list: map[string]string{}, items: map[string]*pfItem{},
		pos: map[string]string{}, seen: map[string]int{},
	}
}

// learn records the order of one playlist's segments.
func (pf *prefetcher) learn(playlist string, segments []string) {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	if len(pf.next)+len(segments) > pfMaxNext {
		pf.next, pf.list = map[string]string{}, map[string]string{}
	}
	for i := 0; i < len(segments) && len(pf.next) < pfMaxNext; i++ {
		pf.list[segments[i]] = playlist
		if i+1 < len(segments) && segments[i] != segments[i+1] { // byte-range playlists repeat one URL
			pf.next[segments[i]] = segments[i+1]
		}
	}
}

// take hands over a prefetched segment, waiting if it is still in flight.
func (pf *prefetcher) take(ctx context.Context, target string) *pfItem {
	pf.mu.Lock()
	it := pf.items[target]
	pf.mu.Unlock()
	if it == nil {
		return nil
	}
	select {
	case <-it.ready:
	case <-ctx.Done():
		return nil
	}
	pf.mu.Lock()
	if pf.items[target] == it {
		pf.forget(target, it)
	}
	pf.mu.Unlock()
	if !it.ok {
		return nil
	}
	return it
}

// kick notes that the TV asked for current and fetches what follows it.
func (pf *prefetcher) kick(s *session, current string) {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	list, ok := pf.list[current]
	if !ok || pf.closed {
		return
	}
	if _, known := pf.pos[list]; !known && len(pf.pos) >= pfMaxLists {
		pf.pos, pf.seen = map[string]string{}, map[string]int{}
	}
	pf.asks++
	pf.pos[list], pf.seen[list] = current, pf.asks

	ahead := map[string]bool{}
	for t, i := current, 0; i < pfDepth; i++ {
		if t = pf.next[t]; t == "" {
			break
		}
		ahead[t] = true
	}
	for t, it := range pf.items {
		stale := pf.asks-pf.seen[it.list] > pfForget
		if stale || (it.list == list && !ahead[t]) {
			it.cancel()
			pf.forget(t, it)
		}
	}
	pf.fill(s, list)
}

// fill starts fetches for the segments after the TV's position in list, as
// far as the limits allow. Called with pf.mu held.
func (pf *prefetcher) fill(s *session, list string) {
	t, ok := pf.pos[list]
	if !ok || pf.closed || pf.asks-pf.seen[list] > pfForget {
		return
	}
	for i := 0; i < pfDepth; i++ {
		if t = pf.next[t]; t == "" {
			return
		}
		if pf.items[t] != nil {
			continue // held, in flight, or failed: the TV fetches that one itself
		}
		if pf.inflight >= pfParallel || pf.size+pfMaxItem > pfMaxTotal {
			return
		}
		// Bound to the session: revoking it stops the fetch at once.
		ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
		it := &pfItem{ready: make(chan struct{}), list: list, cancel: cancel}
		pf.items[t] = it
		pf.inflight++
		pf.size += pfMaxItem
		go pf.fetch(ctx, s, t, it)
	}
}

func (pf *prefetcher) fetch(ctx context.Context, s *session, target string, it *pfItem) {
	defer close(it.ready)
	defer it.cancel()
	hdr, body := fetchSegment(ctx, s, target)
	pf.mu.Lock()
	defer pf.mu.Unlock()
	it.done = true
	if pf.closed {
		return
	}
	pf.inflight--
	pf.size -= pfMaxItem
	// Unless it was dropped while in flight. A failed one stays as a marker,
	// so it is not fetched again and again: the TV's own request goes upstream
	// and gets the real answer.
	if pf.items[target] == it && body != nil {
		it.ok, it.hdr, it.body = true, hdr, body
		pf.size += len(body)
	}
	for l := range pf.pos { // the slot is free again
		pf.fill(s, l)
	}
}

// forget removes an item. Called with pf.mu held.
func (pf *prefetcher) forget(target string, it *pfItem) {
	delete(pf.items, target)
	if it.done && it.ok {
		pf.size -= len(it.body)
	}
}

func fetchSegment(ctx context.Context, s *session, target string) (http.Header, []byte) {
	resp, err := s.up.get(ctx, http.MethodGet, target, nil, true)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ContentLength > pfMaxItem {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, pfMaxItem+1))
	if err != nil || len(body) > pfMaxItem {
		return nil, nil
	}
	// Same rule as forward: the TV's own request then gets the refusal.
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); isDocument(mt, body[:min(len(body), 512)]) {
		return nil, nil
	}
	hdr := resp.Header.Clone()
	hdr.Del("Content-Length") // net/http sets the real one
	return hdr, body
}

func (pf *prefetcher) clear() {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	pf.closed = true
	for _, it := range pf.items {
		it.cancel()
	}
	pf.items, pf.size, pf.inflight = map[string]*pfItem{}, 0, 0
}

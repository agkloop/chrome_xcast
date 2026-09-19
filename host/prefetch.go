package main

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"
)

// prefetcher pulls the next HLS segment while the TV is still downloading the
// current one, hiding upstream latency on far-away origins. Bounded memory;
// anything unusual (ranges, huge segments, errors) simply falls back to a
// normal on-demand fetch.
const (
	pfMaxTotal = 32 << 20
	pfMaxItem  = 12 << 20
	pfMaxNext  = 50000
)

type pfItem struct {
	ready chan struct{}
	ok    bool
	hdr   http.Header
	body  []byte
}

type prefetcher struct {
	mu     sync.Mutex
	next   map[string]string
	items  map[string]*pfItem
	order  []string
	size   int
	closed bool
}

func newPrefetcher() *prefetcher {
	return &prefetcher{next: map[string]string{}, items: map[string]*pfItem{}}
}

func (pf *prefetcher) learn(segments []string) {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	if len(pf.next)+len(segments) > pfMaxNext {
		pf.next = map[string]string{}
	}
	for i := 0; i+1 < len(segments) && len(pf.next) < pfMaxNext; i++ {
		if segments[i] != segments[i+1] { // byte-range playlists repeat one URL
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
		delete(pf.items, target)
		pf.size -= len(it.body)
	}
	pf.mu.Unlock()
	if !it.ok {
		return nil
	}
	return it
}

func (pf *prefetcher) kick(s *session, current string) {
	pf.mu.Lock()
	target := pf.next[current]
	if target == "" || pf.items[target] != nil || pf.closed {
		pf.mu.Unlock()
		return
	}
	it := &pfItem{ready: make(chan struct{})}
	pf.items[target] = it
	if len(pf.order) > 256 { // forget entries that were consumed long ago
		live := pf.order[:0]
		for _, k := range pf.order {
			if pf.items[k] != nil {
				live = append(live, k)
			}
		}
		pf.order = live
	}
	pf.order = append(pf.order, target)
	pf.mu.Unlock()

	go func() {
		defer close(it.ready)
		// Bound to the session: revoking it stops the fetch at once.
		ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
		defer cancel()
		defer func() {
			pf.mu.Lock()
			if !it.ok && pf.items[target] == it {
				delete(pf.items, target) // failed: let the TV's own request go upstream
			}
			pf.mu.Unlock()
		}()
		resp, err := s.up.get(ctx, http.MethodGet, target, nil, true)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK || resp.ContentLength > pfMaxItem {
			return
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, pfMaxItem+1))
		if err != nil || len(body) > pfMaxItem {
			return
		}
		hdr := resp.Header.Clone()
		hdr.Del("Content-Length") // net/http sets the real one
		pf.mu.Lock()
		defer pf.mu.Unlock()
		if pf.closed || pf.items[target] != it {
			return
		}
		it.ok, it.hdr, it.body = true, hdr, body
		pf.size += len(body)
		for pf.size > pfMaxTotal && len(pf.order) > 0 { // drop oldest, e.g. after a seek
			old := pf.order[0]
			pf.order = pf.order[1:]
			if o := pf.items[old]; o != nil && o != it {
				pf.size -= len(o.body)
				delete(pf.items, old)
			}
		}
	}()
}

func (pf *prefetcher) clear() {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	pf.closed = true
	pf.items, pf.order, pf.size = map[string]*pfItem{}, nil, 0
}

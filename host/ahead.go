package main

import (
	"io"
	"sync"
)

// Read-ahead for bodies the relay streams to the TV (a whole video file, a
// segment that was not prefetched). Without it the relay reads from the site
// only as fast as the TV drains its socket, so every slow moment at the site
// reaches the TV. With it the relay keeps reading up to aheadMax bytes past
// what the TV has taken, and a hiccup is covered by what was read before.
//
// Memory is bounded twice: aheadMax per response, and aheadSlots responses at
// a time (the TV plays one or two); any others are copied as before, in large
// pieces. A paused TV stops draining; the buffer fills and reading stops too,
// so the site sees the same back-pressure it always did, aheadMax later.
const (
	aheadChunk = 128 << 10
	aheadMax   = 16 << 20
)

var (
	aheadSlots = make(chan struct{}, 4)
	chunkPool  = sync.Pool{New: func() any { b := make([]byte, aheadChunk); return &b }}
)

// relayBody copies body to w. stop must make a blocked body.Read return (it
// cancels the upstream request); it is called before relayBody returns.
func relayBody(w io.Writer, body io.Reader, stop func()) {
	select {
	case aheadSlots <- struct{}{}:
		defer func() { <-aheadSlots }()
		copyAhead(w, body, stop)
	default:
		bp := chunkPool.Get().(*[]byte)
		defer chunkPool.Put(bp)
		// Hides body's WriteTo, which would copy in the body's own small pieces.
		_, _ = io.CopyBuffer(w, struct{ io.Reader }{body}, *bp)
		stop()
	}
}

type aheadQueue struct {
	mu     sync.Mutex
	cond   sync.Cond
	chunks []*[]byte
	size   int   // capacity of queued chunks: what they hold in memory
	err    error // why reading ended (io.EOF when it simply finished)
	gone   bool  // the TV went away: stop reading
}

func copyAhead(w io.Writer, r io.Reader, stop func()) {
	q := &aheadQueue{}
	q.cond.L = &q.mu
	reader := make(chan struct{})
	go func() {
		defer close(reader)
		q.fill(r)
	}()
	defer func() {
		q.mu.Lock()
		q.gone = true
		left := q.chunks
		q.chunks, q.size = nil, 0
		q.cond.Broadcast()
		q.mu.Unlock()
		for _, bp := range left {
			chunkPool.Put(bp)
		}
		stop()
		<-reader // body is never read after relayBody returns
	}()
	for {
		q.mu.Lock()
		for len(q.chunks) == 0 && q.err == nil {
			q.cond.Wait()
		}
		if len(q.chunks) == 0 {
			q.mu.Unlock()
			return
		}
		bp := q.chunks[0]
		q.chunks = q.chunks[1:]
		q.mu.Unlock()

		_, err := w.Write(*bp)
		*bp = (*bp)[:cap(*bp)]
		chunkPool.Put(bp)
		q.mu.Lock()
		q.size -= aheadChunk
		q.cond.Broadcast()
		q.mu.Unlock()
		if err != nil {
			return
		}
	}
}

// fill reads r into chunks. A chunk is handed over as soon as the TV has
// nothing else waiting, so a starved TV gets bytes at once; while the TV is
// busy, reads keep filling the same chunk, so small reads do not waste memory.
func (q *aheadQueue) fill(r io.Reader) {
	var cur *[]byte
	for {
		if cur == nil {
			q.mu.Lock()
			for q.size >= aheadMax && !q.gone {
				q.cond.Wait()
			}
			if q.gone {
				q.mu.Unlock()
				return
			}
			q.size += aheadChunk
			q.mu.Unlock()
			cur = chunkPool.Get().(*[]byte)
			*cur = (*cur)[:0]
		}
		n, err := r.Read((*cur)[len(*cur):cap(*cur)])
		*cur = (*cur)[:len(*cur)+n]

		q.mu.Lock()
		if q.gone {
			q.mu.Unlock()
			*cur = (*cur)[:cap(*cur)]
			chunkPool.Put(cur)
			return
		}
		if len(*cur) > 0 && (len(*cur) == cap(*cur) || len(q.chunks) == 0 || err != nil) {
			q.chunks = append(q.chunks, cur)
			cur = nil
		}
		if err != nil {
			if cur != nil { // empty: give its room back
				q.size -= aheadChunk
				*cur = (*cur)[:cap(*cur)]
				chunkPool.Put(cur)
			}
			q.err = err
		}
		q.cond.Broadcast()
		q.mu.Unlock()
		if err != nil {
			return
		}
	}
}

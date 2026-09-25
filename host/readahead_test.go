package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !ok(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

func TestPrefetchWindow(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	var now, peak atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		if n := now.Add(1); n > peak.Load() {
			peak.Store(n)
		}
		defer now.Add(-1)
		time.Sleep(15 * time.Millisecond)
		if strings.HasSuffix(r.URL.Path, "/bad.ts") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "video/mp2t")
		io.WriteString(w, "SEG"+r.URL.Path)
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL + "/v.m3u8")
	s := &session{up: newUpstream(loopbackPolicy(), u, &mediaReq{}), pf: newPrefetcher()}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	defer s.close()
	pf := s.pf

	seg := func(list string, i int) string { return fmt.Sprintf("%s/%s/%d.ts", up.URL, list, i) }
	var video, audio []string
	for i := 0; i < 40; i++ {
		video, audio = append(video, seg("v", i)), append(audio, seg("a", i))
	}
	video[30] = up.URL + "/v/bad.ts"
	pf.learn("video", video)
	pf.learn("audio", audio)

	count := func(p string) int { mu.Lock(); defer mu.Unlock(); return hits[p] }
	held := func() []string {
		pf.mu.Lock()
		defer pf.mu.Unlock()
		var out []string
		for k := range pf.items {
			out = append(out, strings.TrimPrefix(k, up.URL))
		}
		sort.Strings(out)
		return out
	}
	settled := func() bool {
		pf.mu.Lock()
		defer pf.mu.Unlock()
		if pf.inflight != 0 {
			return false
		}
		sum := 0
		for _, it := range pf.items {
			if it.ok {
				sum += len(it.body)
			}
		}
		if pf.size != sum {
			t.Fatalf("accounting: size %d, held %d", pf.size, sum)
		}
		return true
	}
	ask := func(target string) { // what forward does for a plain segment request
		t.Helper()
		if it := pf.take(context.Background(), target); it != nil && string(it.body) != "SEG"+strings.TrimPrefix(target, up.URL) {
			t.Fatalf("wrong body for %s: %q", target, it.body)
		}
		pf.kick(s, target)
	}

	// The TV asks for segment 0: the next four follow, two at a time.
	ask(video[0])
	waitFor(t, "four segments ahead", func() bool { return count("/v/4.ts") == 1 && settled() })
	if count("/v/5.ts") != 0 || peak.Load() > pfParallel {
		t.Fatalf("fetched past the window or too many at once: v5=%d, peak %d", count("/v/5.ts"), peak.Load())
	}
	if got := strings.Join(held(), " "); got != "/v/1.ts /v/2.ts /v/3.ts /v/4.ts" {
		t.Fatalf("held %s", got)
	}
	// Taking one moves the window by one; the one handed over is not fetched twice.
	ask(video[1])
	waitFor(t, "window moved", func() bool { return count("/v/5.ts") == 1 && settled() })
	if count("/v/1.ts") != 1 {
		t.Fatalf("segment 1 fetched %d times", count("/v/1.ts"))
	}

	// Audio is a playlist of its own: its read-ahead does not disturb video's.
	ask(audio[0])
	waitFor(t, "audio ahead", func() bool { return count("/a/4.ts") == 1 && settled() })
	if got := strings.Join(held(), " "); got != "/a/1.ts /a/2.ts /a/3.ts /a/4.ts /v/2.ts /v/3.ts /v/4.ts /v/5.ts" {
		t.Fatalf("held %s", got)
	}

	// A seek drops what was fetched for the old position.
	ask(video[20])
	waitFor(t, "window after seek", func() bool { return count("/v/24.ts") == 1 && settled() })
	if got := strings.Join(held(), " "); got != "/a/1.ts /a/2.ts /a/3.ts /a/4.ts /v/21.ts /v/22.ts /v/23.ts /v/24.ts" {
		t.Fatalf("held after seek %s", got)
	}

	// A failed segment is left to the TV and not fetched again and again.
	for i := 26; i <= 29; i++ {
		ask(video[i])
	}
	waitFor(t, "failure in window", func() bool { return count("/v/33.ts") == 1 && settled() })
	for i := 0; i < 5; i++ {
		pf.kick(s, video[29])
	}
	time.Sleep(50 * time.Millisecond)
	if count("/v/bad.ts") != 1 {
		t.Fatalf("failed segment fetched %d times", count("/v/bad.ts"))
	}
	if it := pf.take(context.Background(), video[30]); it != nil {
		t.Fatal("failed segment handed to the TV")
	}

	// Audio the TV stopped asking for (it switched to another quality) is let go.
	for i := 31; i < 39; i++ {
		ask(video[i])
	}
	waitFor(t, "stale playlist dropped", func() bool {
		return settled() && !strings.Contains(strings.Join(held(), " "), "/a/")
	})

	s.close()
	if pf.size != 0 || len(pf.items) != 0 {
		t.Fatalf("revoked session keeps %d bytes", pf.size)
	}
	pf.kick(s, video[1])
	if len(pf.items) != 0 {
		t.Fatal("revoked session still fetches")
	}
}

// slowSource hands out n bytes in small pieces, as a network read does.
type slowSource struct {
	n, piece int
	read     atomic.Int64
	block    chan struct{} // if set, Read waits on it before each piece
}

func (s *slowSource) Read(p []byte) (int, error) {
	if s.block != nil {
		<-s.block
	}
	left := s.n - int(s.read.Load())
	if left <= 0 {
		return 0, io.EOF
	}
	k, base := min(len(p), s.piece, left), int(s.read.Load())
	for i := range p[:k] {
		p[i] = byte(base + i)
	}
	s.read.Add(int64(k))
	return k, nil
}

// gateWriter blocks every Write until open is closed.
type gateWriter struct {
	open chan struct{}
	mu   sync.Mutex
	buf  bytes.Buffer
	err  error
}

func (g *gateWriter) Write(p []byte) (int, error) {
	<-g.open
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.err != nil {
		return 0, g.err
	}
	return g.buf.Write(p)
}

func TestCopyAhead(t *testing.T) {
	// The site keeps being read while the TV is busy, then everything arrives in order.
	src := &slowSource{n: 3 << 20, piece: 9000}
	w := &gateWriter{open: make(chan struct{})}
	done := make(chan struct{})
	go func() { defer close(done); relayBody(w, src, func() {}) }()
	waitFor(t, "read-ahead while the TV is busy", func() bool { return src.read.Load() == int64(src.n) })
	close(w.open)
	<-done
	want := make([]byte, src.n)
	for i := range want {
		want[i] = byte(i)
	}
	if !bytes.Equal(w.buf.Bytes(), want) {
		t.Fatalf("relayed %d bytes, not what the site sent", w.buf.Len())
	}

	// Bounded: a TV that stops reading stops the reading at aheadMax.
	endless := &slowSource{n: 1 << 40, piece: 1 << 20}
	w = &gateWriter{open: make(chan struct{})}
	stopped := make(chan struct{})
	done = make(chan struct{})
	go func() {
		defer close(done)
		relayBody(w, endless, func() { close(stopped) })
	}()
	waitFor(t, "buffer full", func() bool { return endless.read.Load() >= aheadMax-aheadChunk })
	time.Sleep(50 * time.Millisecond)
	if got := endless.read.Load(); got > aheadMax {
		t.Fatalf("read %d bytes ahead of a paused TV, want up to %d", got, aheadMax)
	}
	// The TV goes away: the upstream request is stopped and nothing is left running.
	w.err = errors.New("TV gone")
	close(w.open)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("relay kept going after the TV went away")
	}
	select {
	case <-stopped:
	default:
		t.Fatal("upstream request not stopped")
	}

	// A starved TV gets what has arrived at once, without waiting for a full chunk.
	trickle := &slowSource{n: 10, piece: 5, block: make(chan struct{}, 1)}
	w = &gateWriter{open: make(chan struct{})}
	close(w.open)
	done = make(chan struct{})
	go func() { defer close(done); relayBody(w, trickle, func() {}) }()
	trickle.block <- struct{}{}
	waitFor(t, "first bytes delivered", func() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.buf.Len() == 5 })
	close(trickle.block)
	<-done
	if w.buf.Len() != 10 {
		t.Fatalf("delivered %d of 10 bytes", w.buf.Len())
	}

	// With every read-ahead slot taken, a response is still copied, in large pieces.
	for i := 0; i < cap(aheadSlots); i++ {
		aheadSlots <- struct{}{}
	}
	var out bytes.Buffer
	calls := &countWriter{w: &out}
	relayBody(calls, &slowSource{n: 1 << 20, piece: 1 << 20}, func() {})
	for i := 0; i < cap(aheadSlots); i++ {
		<-aheadSlots
	}
	if out.Len() != 1<<20 || calls.n > (1<<20)/aheadChunk {
		t.Fatalf("fallback copy: %d bytes in %d writes", out.Len(), calls.n)
	}
}

type countWriter struct {
	w io.Writer
	n int
}

func (c *countWriter) Write(p []byte) (int, error) { c.n++; return c.w.Write(p) }

func TestKeepAwake(t *testing.T) {
	var starts, stops atomic.Int32
	w := &waker{start: func() func() { starts.Add(1); return func() { stops.Add(1) } }}
	w.hold()
	w.hold()
	if starts.Load() != 1 || !w.held() {
		t.Fatalf("hold started %d times", starts.Load())
	}
	w.releaseIn(time.Hour)
	w.hold() // playing again before the pause ran out
	w.releaseIn(20 * time.Millisecond)
	waitFor(t, "release after the pause", func() bool { return !w.held() })
	if stops.Load() != 1 {
		t.Fatalf("stopped %d times", stops.Load())
	}
	// A pause timer that fires while hold is running must not undo it: here
	// it fires while the lock is held and runs only after hold's work is done.
	w.hold()
	w.releaseIn(time.Millisecond)
	w.mu.Lock()
	time.Sleep(20 * time.Millisecond)
	w.cancelTimer() // what hold does under the lock
	w.mu.Unlock()
	time.Sleep(20 * time.Millisecond)
	if !w.held() {
		t.Fatal("a stale pause timer released a hold")
	}
	w.release()
	if w.held() || starts.Load() != stops.Load() {
		t.Fatalf("starts %d, stops %d", starts.Load(), stops.Load())
	}

	// The host holds only while the TV reads from this computer.
	h := newHost(func(any) {})
	w = &waker{start: w.start}
	h.awake = w
	status := func(state string) {
		h.onCastEvent("MEDIA_STATUS", []byte(`{"status":[{"mediaSessionId":7,"playerState":"`+state+`"}]}`))
	}
	h.mu.Lock()
	h.app, h.metrics = &receiverApp{}, newCastMetrics("direct")
	h.mu.Unlock()
	if status("PLAYING"); w.held() {
		t.Fatal("kept awake for a direct cast")
	}
	h.mu.Lock()
	h.metrics = newCastMetrics("proxy")
	h.mu.Unlock()
	for _, c := range []struct {
		state string
		held  bool
	}{{"BUFFERING", true}, {"PLAYING", true}, {"PAUSED", true}, {"PLAYING", true}, {"IDLE", false}, {"PLAYING", true}} {
		if status(c.state); w.held() != c.held {
			t.Fatalf("after %s held = %v", c.state, w.held())
		}
	}
	w.mu.Lock()
	pending := w.timer != nil
	w.mu.Unlock()
	if pending {
		t.Fatal("pause timer survives playing again")
	}
	h.shutdown()
	if w.held() {
		t.Fatal("still held after the helper shut down")
	}
}

func TestCaffeinate(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}
	stop := caffeinate()
	if stop == nil {
		t.Fatal("caffeinate did not start")
	}
	stop()
}

package main

import (
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// castMetrics describes the cast that is playing right now. It lives in
// memory only, is replaced by the next cast and dies with the helper: nothing
// about what was watched is ever written down.
type castMetrics struct {
	mode    string
	started time.Time

	// Relay counters (stay zero in direct mode: the TV fetches by itself).
	bytes        atomic.Int64
	requests     atomic.Int64
	segments     atomic.Int64 // plain media requests the read-ahead could have served
	prefetchHits atomic.Int64
	retries      atomic.Int64
	errors       atomic.Int64
	ttfbMicros   atomic.Int64 // moving average of upstream time to first byte

	mu          sync.Mutex
	firstPlay   time.Time
	stalls      int
	stallTotal  time.Duration
	stallSince  time.Time
	ignoreUntil time.Time // buffering right after a seek is not a stall
	lastBytes   int64
	lastSample  time.Time
}

func newCastMetrics(mode string) *castMetrics {
	now := time.Now()
	return &castMetrics{mode: mode, started: now, lastSample: now}
}

func (m *castMetrics) noteTTFB(d time.Duration) {
	if m == nil {
		return
	}
	us := d.Microseconds()
	if old := m.ttfbMicros.Load(); old != 0 {
		us = (old*7 + us) / 8
	}
	m.ttfbMicros.Store(us)
}

// noteState turns the TV's player states into start time and stall counts.
func (m *castMetrics) noteState(state string) {
	if m == nil {
		return
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	switch state {
	case "PLAYING":
		if m.firstPlay.IsZero() {
			m.firstPlay = now
		}
		if !m.stallSince.IsZero() {
			m.stallTotal += now.Sub(m.stallSince)
			m.stallSince = time.Time{}
		}
	case "BUFFERING":
		if !m.firstPlay.IsZero() && m.stallSince.IsZero() && now.After(m.ignoreUntil) {
			m.stalls++
			m.stallSince = now
		}
	default: // PAUSED, IDLE: not a stall
		if !m.stallSince.IsZero() {
			m.stallTotal += now.Sub(m.stallSince)
			m.stallSince = time.Time{}
		}
	}
}

func (m *castMetrics) noteSeek() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.ignoreUntil = time.Now().Add(4 * time.Second)
	m.mu.Unlock()
}

// snapshot is what the popup gets once a second.
func (m *castMetrics) snapshot() map[string]any {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	total := m.bytes.Load()
	mbps := 0.0
	if dt := now.Sub(m.lastSample).Seconds(); dt > 0 {
		mbps = float64(total-m.lastBytes) * 8 / 1e6 / dt
	}
	m.lastBytes, m.lastSample = total, now
	stall := m.stallTotal
	if !m.stallSince.IsZero() {
		stall += now.Sub(m.stallSince)
	}
	out := map[string]any{
		"type":         "metrics",
		"mode":         m.mode,
		"mbps":         mbps,
		"bytes":        total,
		"requests":     m.requests.Load(),
		"segments":     m.segments.Load(),
		"prefetchHits": m.prefetchHits.Load(),
		"retries":      m.retries.Load(),
		"errors":       m.errors.Load(),
		"ttfbMs":       float64(m.ttfbMicros.Load()) / 1000,
		"stalls":       m.stalls,
		"stallMs":      stall.Milliseconds(),
		"elapsedMs":    now.Sub(m.started).Milliseconds(),
	}
	if !m.firstPlay.IsZero() {
		out["startMs"] = m.firstPlay.Sub(m.started).Milliseconds()
	}
	return out
}

// countingWriter counts relayed bytes as they leave, so speed is live even
// during one long response (a progressive MP4).
type countingWriter struct {
	w io.Writer
	m *castMetrics
}

func (c countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if c.m != nil {
		c.m.bytes.Add(int64(n))
	}
	return n, err
}

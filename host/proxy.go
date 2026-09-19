package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"html"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Security model of the LAN proxy:
//   - listens only on the interface that routes to the TV, random port
//   - accepts TCP only from the TV's IP (dropped before any HTTP parsing)
//   - every upstream URL travels as an AES-256-GCM token under a per-session
//     random key: the proxy fetches only what the helper itself handed out
//     (no open proxy), and nobody sniffing the LAN can read which site, video
//     or access token is behind a request
//   - upstream dials are policy-checked (no pivot into your LAN)
//   - GET/HEAD only, nothing is logged but hostnames
//   - a session dies when its cast ends, when the TV connection is lost for
//     good, or after sessionIdle without a request (a paused TV asks for
//     nothing, so this has to outlast a long pause)
const (
	maxManifestURIs = 20000    // URIs rewritten per playlist
	maxRewritten    = 32 << 20 // bytes of rewritten manifest
	maxConns        = 32       // simultaneous connections from the TV
	sessionIdle     = 12 * time.Hour
	maxSessions     = 4
	upstreamIdle    = 20 * time.Second // stalled upstream body read
)

var b64 = base64.RawURLEncoding

type proxy struct {
	srv   *http.Server
	base  string
	local netip.Addr

	mu       sync.RWMutex
	sessions map[string]*session

	stopJanitor chan struct{}
	closeOnce   sync.Once
}

type session struct {
	id       string
	aead     cipher.AEAD
	nonceKey []byte
	up       *upstream
	device   netip.Addr
	lastUse  atomic.Int64
	pf       *prefetcher
	m        *castMetrics    // nil-safe; set by the host once the cast is planned
	ctx      context.Context // cancelled at revocation: stops background fetches
	cancel   context.CancelFunc
}

func (s *session) close() {
	s.cancel()
	s.pf.clear()
	if s.up != nil {
		s.up.client.CloseIdleConnections()
	}
}

func (s *session) touch() { s.lastUse.Store(time.Now().UnixNano()) }

func localAddrFor(dev netip.Addr) (netip.Addr, error) {
	c, err := net.Dial("udp4", netip.AddrPortFrom(dev, 8009).String()) // routing lookup only, sends nothing
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap(), nil
}

func startProxy(dev netip.Addr) (*proxy, error) {
	local, err := localAddrFor(dev)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp4", netip.AddrPortFrom(local, 0).String())
	if err != nil {
		return nil, err
	}
	p := &proxy{local: local, base: "http://" + ln.Addr().String(), sessions: map[string]*session{}}
	p.srv = &http.Server{
		Handler:           p,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	go func() { _ = p.srv.Serve(&gateListener{Listener: ln, p: p}) }()
	p.stopJanitor = make(chan struct{})
	go p.janitor()
	return p, nil
}

func (p *proxy) janitor() {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-p.stopJanitor:
			return
		case <-t.C:
			p.mu.RLock()
			var stale []*session
			for _, s := range p.sessions {
				if time.Since(time.Unix(0, s.lastUse.Load())) > sessionIdle {
					stale = append(stale, s)
				}
			}
			p.mu.RUnlock()
			for _, s := range stale {
				p.drop(s)
			}
		}
	}
}

func (p *proxy) Close() {
	p.closeOnce.Do(func() {
		if p.stopJanitor != nil {
			close(p.stopJanitor)
		}
	})
	p.keepOnly(nil)
	_ = p.srv.Close()
}

// keepOnly revokes every session except keep (nil revokes all).
func (p *proxy) keepOnly(keep *session) {
	p.mu.Lock()
	var dead []*session
	for id, s := range p.sessions {
		if s != keep {
			delete(p.sessions, id)
			dead = append(dead, s)
		}
	}
	p.mu.Unlock()
	for _, s := range dead {
		s.close()
	}
}

func (p *proxy) drop(s *session) {
	p.mu.Lock()
	_, ok := p.sessions[s.id]
	delete(p.sessions, s.id)
	p.mu.Unlock()
	if ok {
		s.close()
	}
}

func (p *proxy) lookup(id string) *session {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.sessions[id]
}

func (p *proxy) serves(ip netip.Addr) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, s := range p.sessions {
		if s.device == ip {
			return true
		}
	}
	return false
}

// gateListener drops connections from anyone but the TV before HTTP parsing.
type gateListener struct {
	net.Listener
	p    *proxy
	open atomic.Int32
}

// countedConn releases its slot exactly once.
type countedConn struct {
	net.Conn
	l    *gateListener
	once sync.Once
}

func (c *countedConn) Close() error {
	c.once.Do(func() { c.l.open.Add(-1) })
	return c.Conn.Close()
}

func (l *gateListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
			if l.p.serves(a.AddrPort().Addr().Unmap()) && l.open.Load() < maxConns {
				l.open.Add(1)
				return &countedConn{Conn: c, l: l}, nil
			}
		}
		c.Close()
	}
}

func (p *proxy) newSession(up *upstream, dev netip.Addr) (*session, error) {
	secret := make([]byte, 16+32+32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(secret[16:48])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	s := &session{id: b64.EncodeToString(secret[:16]), aead: aead, nonceKey: secret[48:], up: up, device: dev, pf: newPrefetcher()}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.touch()
	// The session that is playing right now stays valid until the new cast has
	// actually started (see host.castMedia); only a runaway count evicts.
	p.mu.Lock()
	var evict *session
	if len(p.sessions) >= maxSessions {
		for _, o := range p.sessions {
			if evict == nil || o.lastUse.Load() < evict.lastUse.Load() {
				evict = o
			}
		}
		delete(p.sessions, evict.id)
	}
	p.sessions[s.id] = s
	p.mu.Unlock()
	if evict != nil {
		evict.close()
	}
	return s, nil
}

// seal turns an upstream URL into an opaque, authenticated token. The nonce is
// derived from the plaintext (synthetic IV), so a URL always maps to the same
// token, which keeps live playlists stable across refreshes, while distinct
// URLs never share a nonce. kind is bound as associated data: a single-file
// grant cannot be replayed as a directory grant.
func (s *session) seal(kind byte, target string) string {
	m := hmac.New(sha256.New, s.nonceKey)
	m.Write([]byte{kind})
	m.Write([]byte(target))
	nonce := m.Sum(nil)[:s.aead.NonceSize()]
	return b64.EncodeToString(s.aead.Seal(nonce, nonce, []byte(target), []byte{kind}))
}

func (s *session) open(kind byte, token string) (string, bool) {
	raw, err := b64.DecodeString(token)
	if err != nil || len(raw) < s.aead.NonceSize() {
		return "", false
	}
	n := s.aead.NonceSize()
	pt, err := s.aead.Open(nil, raw[:n], raw[n:], []byte{kind})
	return string(pt), err == nil
}

// fileURL grants exactly one upstream URL.
func (p *proxy) fileURL(s *session, target string) string {
	return p.base + "/" + s.id + "/u/" + s.seal('u', target) + "/" + hintName(target)
}

// dirURL grants a directory, so relative references inside a DASH manifest
// resolve naturally without rewriting every template. Only the file names
// below that directory stay readable on the LAN.
func (p *proxy) dirURL(s *session, u *url.URL) string {
	esc := u.EscapedPath()
	if esc == "" {
		esc = "/"
	}
	i := strings.LastIndexByte(esc, '/')
	prefix := u.Scheme + "://" + u.Host + esc[:i+1]
	rest := esc[i+1:]
	if u.RawQuery != "" {
		rest += "?" + u.RawQuery
	}
	return p.base + "/" + s.id + "/p/" + s.seal('p', prefix) + "/" + rest
}

func (p *proxy) entryURL(s *session, u *url.URL, kind string) string {
	if kind == "dash" {
		return p.dirURL(s, u)
	}
	return p.fileURL(s, u.String())
}

func splitPath(r *http.Request) []string {
	return strings.SplitN(strings.TrimPrefix(r.URL.EscapedPath(), "/"), "/", 4)
}

func (s *session) resolve(r *http.Request) (string, bool) {
	parts := splitPath(r)
	if len(parts) != 4 || subtle.ConstantTimeCompare([]byte(parts[0]), []byte(s.id)) != 1 {
		return "", false
	}
	kind := parts[1]
	if kind != "u" && kind != "p" {
		return "", false
	}
	target, ok := s.open(kind[0], parts[2])
	if !ok {
		return "", false
	}
	if kind == "u" {
		return target, true
	}
	rest := parts[3]
	if dec, err := url.PathUnescape(rest); err != nil || strings.Contains(dec, "..") {
		return "", false // never let a relative path climb out of the granted directory
	}
	if r.URL.RawQuery != "" {
		rest += "?" + r.URL.RawQuery
	}
	// Belt and braces: the final URL must still be on the granted scheme, host,
	// port and directory after normalisation.
	grant, err1 := url.Parse(target)
	full, err2 := url.Parse(target + rest)
	if err1 != nil || err2 != nil || full.Scheme != grant.Scheme || full.Host != grant.Host || full.User != nil ||
		!strings.HasPrefix(dirOf(full.Path), dirOf(grant.Path)) {
		return "", false
	}
	return target + rest, true
}

// dirOf returns the cleaned path with a trailing slash, for prefix checks.
func dirOf(p string) string {
	c := path.Clean("/" + p)
	if c != "/" {
		c += "/"
	}
	return c
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var s *session
	if parts := splitPath(r); len(parts) == 4 {
		s = p.lookup(parts[0])
	}
	ra, err := netip.ParseAddrPort(r.RemoteAddr)
	// The Host check defeats DNS rebinding from anything that browses on the TV.
	if s == nil || err != nil || ra.Addr().Unmap() != s.device || "http://"+r.Host != p.base {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if time.Since(time.Unix(0, s.lastUse.Load())) > sessionIdle {
		p.drop(s)
		http.Error(w, "session expired", http.StatusGone)
		return
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Expose-Headers", "Content-Length, Content-Range, Accept-Ranges")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Resource-Policy", "cross-origin")
	switch r.Method {
	case http.MethodOptions:
		h.Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Range, Content-Type")
		h.Set("Access-Control-Max-Age", "600")
		if r.Header.Get("Access-Control-Request-Private-Network") == "true" {
			h.Set("Access-Control-Allow-Private-Network", "true") // Private/Local Network Access preflight
		}
		w.WriteHeader(http.StatusNoContent)
		return
	case http.MethodGet, http.MethodHead:
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	target, ok := s.resolve(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.touch()
	p.forward(w, r, s, target)
}

func (p *proxy) forward(w http.ResponseWriter, r *http.Request, s *session, target string) {
	hdr := http.Header{}
	for _, k := range [...]string{"Range", "If-Range", "Accept"} {
		if v := r.Header.Get(k); v != "" {
			hdr.Set(k, v)
		}
	}
	plain := r.Method == http.MethodGet && hdr.Get("Range") == ""
	if plain {
		if it := s.pf.take(r.Context(), target); it != nil {
			s.pf.kick(s, target)
			copyHeaders(w.Header(), it.hdr)
			w.WriteHeader(http.StatusOK)
			if s.m != nil {
				s.m.requests.Add(1)
				s.m.segments.Add(1)
				s.m.prefetchHits.Add(1)
			}
			_, _ = countingWriter{w, s.m}.Write(it.body)
			return
		}
	}

	// Cancelled when the TV goes away or when the upstream body stalls.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	var resp *http.Response
	var err error
	if s.m != nil {
		s.m.requests.Add(1)
	}
	for attempt := 0; ; attempt++ {
		asked := time.Now()
		resp, err = s.up.get(ctx, r.Method, target, hdr, true)
		if err == nil {
			s.m.noteTTFB(time.Since(asked))
		}
		if attempt == 1 && s.m != nil {
			s.m.retries.Add(1)
		}
		transient := err != nil || resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504
		if !transient || attempt == 1 || ctx.Err() != nil {
			break
		}
		if resp != nil {
			resp.Body.Close()
		}
		select { // one retry: nothing has been written to the TV yet
		case <-time.After(300 * time.Millisecond):
		case <-ctx.Done():
		}
	}
	if s.m != nil && (err != nil || resp.StatusCode >= 400) {
		s.m.errors.Add(1)
	}
	if err != nil {
		debugf("upstream: %v", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	watched := &idleReader{r: resp.Body, t: time.AfterFunc(upstreamIdle, cancel), d: upstreamIdle}
	watched.t.Stop()
	defer watched.t.Stop()

	body := bufio.NewReaderSize(watched, 4096)
	if resp.StatusCode == http.StatusOK && r.Method == http.MethodGet {
		final := resp.Request.URL
		head, _ := body.Peek(512)
		mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		switch {
		case strings.Contains(mt, "mpegurl") || bytes.HasPrefix(bytes.TrimLeft(head, "\ufeff \t\r\n"), []byte("#EXTM3U")):
			serveRewritten(w, body, "application/vnd.apple.mpegurl", func(b []byte) []byte {
				out, segments := rewriteHLS(b, final, func(u *url.URL) string { return p.fileURL(s, u.String()) })
				s.pf.learn(segments)
				return out
			})
			return
		case strings.Contains(mt, "dash+xml") || strings.HasSuffix(strings.ToLower(final.Path), ".mpd"):
			serveRewritten(w, body, ctDASH, func(b []byte) []byte {
				return rewriteMPD(b, func(u *url.URL) string { return p.dirURL(s, u) })
			})
			return
		}
	}

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if r.Method == http.MethodHead {
		return
	}
	if plain && resp.StatusCode == http.StatusOK {
		s.pf.kick(s, target)
		if s.m != nil {
			s.m.segments.Add(1)
		}
	}
	_, _ = io.Copy(countingWriter{w, s.m}, body)
}

var passHeaders = [...]string{"Content-Type", "Content-Length", "Content-Range", "Accept-Ranges", "Last-Modified", "Etag", "Cache-Control", "Expires"}

func copyHeaders(dst, src http.Header) {
	for _, k := range passHeaders {
		if v := src.Get(k); v != "" {
			dst.Set(k, v)
		}
	}
}

// idleReader arms a watchdog only while blocked reading from upstream, so a
// paused TV (which simply stops draining the socket) is never cut off.
type idleReader struct {
	r io.Reader
	t *time.Timer
	d time.Duration
}

func (i *idleReader) Read(p []byte) (int, error) {
	i.t.Reset(i.d)
	n, err := i.r.Read(p)
	i.t.Stop()
	return n, err
}

func serveRewritten(w http.ResponseWriter, body io.Reader, ct string, fn func([]byte) []byte) {
	b, err := io.ReadAll(io.LimitReader(body, maxManifest+1))
	if err != nil || len(b) > maxManifest {
		http.Error(w, "manifest unreadable", http.StatusBadGateway)
		return
	}
	out := fn(b)
	if out == nil {
		http.Error(w, "manifest too large", http.StatusBadGateway)
		return
	}
	h := w.Header()
	h.Set("Content-Type", ct)
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Length", strconv.Itoa(len(out)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

var uriAttr = regexp.MustCompile(`URI="([^"]*)"`)

// rewriteHLS points every URI in a playlist (segments, variants, keys, init
// maps, renditions) back through the proxy. Non-http URIs (data:, skd:) stay.
// For media playlists it also returns the upstream segment URLs in order.
func rewriteHLS(src []byte, base *url.URL, proxied func(*url.URL) string) (out []byte, segments []string) {
	master := bytes.Contains(src, []byte("#EXT-X-STREAM-INF"))
	lines := strings.Split(string(src), "\n")
	// Each URI grows into a ~150-byte token: a playlist of millions of tiny
	// lines must not be able to exhaust memory.
	uris, size := 0, 0
	over := func(t string) bool {
		uris++
		size += len(t)
		return uris > maxManifestURIs || size > maxRewritten
	}
	for i, line := range lines {
		t := strings.TrimRight(line, "\r")
		switch {
		case t == "":
		case strings.HasPrefix(t, "#"):
			t = uriAttr.ReplaceAllStringFunc(t, func(m string) string {
				if u := resolveHTTP(base, m[5:len(m)-1]); u != nil {
					t := proxied(u)
					if over(t) {
						return m
					}
					return `URI="` + t + `"`
				}
				return m
			})
		default:
			if u := resolveHTTP(base, strings.TrimSpace(t)); u != nil {
				if !master {
					segments = append(segments, u.String())
				}
				t = proxied(u)
				if over(t) {
					return nil, nil
				}
			}
		}
		lines[i] = t
	}
	if uris > maxManifestURIs || size > maxRewritten {
		return nil, nil
	}
	return []byte(strings.Join(lines, "\n")), segments
}

var baseURLRe = regexp.MustCompile(`(<BaseURL[^>]*>)\s*([^<]+?)\s*(</BaseURL>)`)

// rewriteMPD redirects absolute BaseURLs through a directory grant. Relative
// ones already resolve against the (proxied) manifest location.
func rewriteMPD(src []byte, grant func(*url.URL) string) []byte {
	return baseURLRe.ReplaceAllFunc(src, func(m []byte) []byte {
		sub := baseURLRe.FindSubmatch(m)
		u, err := url.Parse(html.UnescapeString(string(sub[2])))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return m
		}
		return []byte(string(sub[1]) + html.EscapeString(grant(u)) + string(sub[3]))
	})
}

// hintName gives the TV a file extension to go by and nothing else: the real
// file name could identify the video to someone watching the LAN.
func hintName(target string) string {
	ext := ""
	if u, err := url.Parse(target); err == nil {
		ext = strings.ToLower(path.Ext(u.Path))
	}
	switch ext {
	case ".m3u8", ".mpd", ".mp4", ".m4s", ".m4v", ".m4a", ".ts", ".aac", ".mp3", ".webm", ".vtt", ".key":
		return "media" + ext
	}
	return "media"
}

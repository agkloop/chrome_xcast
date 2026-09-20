package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// loopbackPolicy lets tests reach httptest servers; production policies can
// never contain a loopback address (see TestNewPolicy).
func loopbackPolicy() *policy {
	return &policy{allowed: map[netip.Addr]bool{netip.MustParseAddr("127.0.0.1"): true}}
}

func TestCastMessageRoundTrip(t *testing.T) {
	in := castMsg{src: "a", dst: "receiver-0", ns: nsMedia, payload: strings.Repeat(`{"x":1}`, 100)}
	frame := encodeMsg(in)
	if got := binary.BigEndian.Uint32(frame); int(got) != len(frame)-4 {
		t.Fatalf("length prefix %d, want %d", got, len(frame)-4)
	}
	out, err := decodeMsg(frame[4:])
	if err != nil || out.src != in.src || out.dst != in.dst || out.ns != in.ns || out.payload != in.payload || out.binary != nil {
		t.Fatalf("round trip = %+v, %v", out, err)
	}
	bin, err := decodeMsg(encodeMsg(castMsg{src: "a", dst: "b", ns: nsAuth, binary: []byte{0, 1, 2}})[4:])
	if err != nil || string(bin.binary) != "\x00\x01\x02" || bin.payload != "" {
		t.Fatalf("binary round trip = %+v, %v", bin, err)
	}
	if _, err := decodeMsg([]byte{0x12, 0xff, 0xff, 0x03}); err == nil {
		t.Fatal("truncated field must fail")
	}
}

func TestCastMetrics(t *testing.T) {
	m := newCastMetrics("proxy")
	m.noteState("BUFFERING") // loading before the first frame is not a stall
	m.noteState("PLAYING")
	m.noteState("BUFFERING")
	time.Sleep(30 * time.Millisecond)
	m.noteState("PLAYING")
	m.noteSeek()
	m.noteState("BUFFERING") // caused by the seek: not a stall either
	m.noteState("PLAYING")
	m.noteState("PAUSED")
	var sink strings.Builder
	countingWriter{&sink, m}.Write(make([]byte, 125000))
	snap := m.snapshot()
	if snap["stalls"] != 1 || snap["stallMs"].(int64) < 25 || snap["bytes"].(int64) != 125000 || snap["mbps"].(float64) <= 0 {
		t.Fatalf("snapshot = %v", snap)
	}
	if _, ok := snap["startMs"]; !ok {
		t.Fatal("start time missing after the first PLAYING")
	}
	var none *castMetrics // direct mode and tests pass nil around freely
	none.noteState("PLAYING")
	none.noteTTFB(time.Second)
	none.noteSeek()
}

func TestRealTrustAnchors(t *testing.T) {
	pool := mustLoadRoots() // panics on a swapped or corrupted anchor
	if pool.Equal(x509.NewCertPool()) {
		t.Fatal("no Cast trust anchors embedded")
	}
	if got := cleanLabel("Living\u202eVT mooR\x00 Room", 64); got != "LivingVT mooR Room" {
		t.Fatalf("cleanLabel = %q", got)
	}
}

func TestIsPublic(t *testing.T) {
	for ip, want := range map[string]bool{
		"8.8.8.8": true, "2606:4700::1": true,
		"127.0.0.1": false, "10.1.2.3": false, "192.168.1.1": false, "172.16.0.1": false,
		"169.254.169.254": false, "100.64.0.1": false, "::1": false, "fd00::1": false,
		"::ffff:192.168.1.1": false, "0.0.0.0": false, "224.0.0.251": false,
		"64:ff9b::a00:1": false, "2002:c0a8:101::1": false, "2001:0:4136:e378::1": false,
		"64:ff9b::a00:1%en0": false, "2002:c0a8:101::1%en0": false, "2606:4700::1%en0": false,
		"::127.0.0.1": false, "fec0::1": false, "192.88.99.1": false,
	} {
		if got := isPublic(netip.MustParseAddr(ip)); got != want {
			t.Errorf("isPublic(%s) = %v, want %v", ip, got, want)
		}
	}
}

func encName(name string) []byte {
	var b []byte
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

func rr(name string, typ uint16, rdata []byte) []byte {
	b := encName(name)
	b = binary.BigEndian.AppendUint16(b, typ)
	b = binary.BigEndian.AppendUint16(b, 0x8001)
	b = binary.BigEndian.AppendUint32(b, 120)
	b = binary.BigEndian.AppendUint16(b, uint16(len(rdata)))
	return append(b, rdata...)
}

func TestParseCastRecords(t *testing.T) {
	inst := "Chromecast-abc._googlecast._tcp.local"
	srv := append([]byte{0, 0, 0, 0, 0x1f, 0x49}, encName("abc.local")...)
	var txt []byte
	for _, kv := range []string{"id=abc123", "md=Chromecast", "fn=Living Room TV"} {
		txt = append(append(txt, byte(len(kv))), kv...)
	}
	msg := []byte{0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 3}
	msg = append(msg, rr(castService, 12, encName(inst))...)
	msg = append(msg, rr(inst, 33, srv)...)
	msg = append(msg, rr(inst, 16, txt)...)
	msg = append(msg, rr("abc.local", 1, []byte{192, 168, 1, 77})...) // spoofable: must be ignored

	devs := parseCastRecords(msg, netip.MustParseAddr("192.168.1.50"))
	if len(devs) != 1 {
		t.Fatalf("got %d devices", len(devs))
	}
	want := Device{ID: "abc123", Name: "Living Room TV", Model: "Chromecast", Host: "192.168.1.50", Port: 8009}
	if devs[0] != want {
		t.Fatalf("got %+v, want %+v", devs[0], want)
	}
	if parseCastRecords(msg[:40], netip.MustParseAddr("192.168.1.99")) != nil {
		t.Fatal("truncated packet should yield nothing")
	}
}

func TestProxyEndToEnd(t *testing.T) {
	const referer = "http://site.example/watch/1?user=me"
	var seg1Hits, seg2Hits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v/master.m3u8", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=1\nlow/index.m3u8\n")
	})
	mux.HandleFunc("/v/low/index.m3u8", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "#EXTM3U\n#EXT-X-MAP:URI=\"init.mp4\"\n#EXTINF:4,\nseg1.m4s\n#EXTINF:4,\nseg2.m4s\n#EXTINF:4,\nhttp://10.255.255.1/evil.ts\n#EXT-X-ENDLIST\n")
	})
	mux.HandleFunc("/v/low/seg1.m4s", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Referer") != "http://site.example/" { // origin only: the page path stays private
			http.Error(w, "hotlink", http.StatusForbidden)
			return
		}
		if r.Header.Get("Cookie") != "" {
			t.Error("cookie sent over plain http")
		}
		if seg1Hits.Add(1) == 1 {
			http.Error(w, "flaky", http.StatusServiceUnavailable) // first hit fails: proxy must retry
			return
		}
		io.WriteString(w, "SEGMENT")
	})
	mux.HandleFunc("/v/low/seg2.m4s", func(w http.ResponseWriter, r *http.Request) {
		seg2Hits.Add(1)
		io.WriteString(w, "SEGMENT2")
	})
	up := httptest.NewServer(mux)
	defer up.Close()

	ctx := context.Background()
	u, _ := url.Parse(up.URL + "/v/master.m3u8")
	upst := newUpstream(loopbackPolicy(), u, &mediaReq{Referer: referer, Cookie: "sid=1"})

	info, err := upst.inspect(ctx, u.String(), "", true, 0)
	if err != nil || info.kind != "hls" || !info.fmp4 || info.live {
		t.Fatalf("inspect = %+v, %v", info, err)
	}

	dev := netip.MustParseAddr("127.0.0.1")
	p, err := startProxy(dev)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	s, _ := p.newSession(upst, dev)
	s.m = newCastMetrics("proxy")
	entry := p.entryURL(s, u)

	get := func(raw string) (int, string, http.Header) {
		t.Helper()
		resp, err := http.Get(raw)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), resp.Header
	}
	uris := func(playlist string) []string {
		var out []string
		for _, l := range strings.Split(playlist, "\n") {
			if l != "" && !strings.HasPrefix(l, "#") {
				out = append(out, l)
			}
		}
		return out
	}

	code, master, _ := get(entry)
	variants := uris(master)
	if code != 200 || len(variants) != 1 || !strings.HasPrefix(variants[0], p.base) {
		t.Fatalf("master: %d %q", code, master)
	}
	_, media, _ := get(variants[0])
	if !strings.Contains(media, `URI="`+p.base) {
		t.Fatalf("init map not proxied: %q", media)
	}
	segs := uris(media)
	if len(segs) != 3 {
		t.Fatalf("segments: %q", media)
	}
	code, body, hdr := get(segs[0])
	if code != 200 || body != "SEGMENT" || hdr.Get("Access-Control-Allow-Origin") != "*" || seg1Hits.Load() != 2 {
		t.Fatalf("segment (after one retry): %d %q %v hits=%d", code, body, hdr, seg1Hits.Load())
	}
	// The next segment is fetched ahead of the TV asking for it, and only once.
	for i := 0; i < 100 && seg2Hits.Load() == 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if seg2Hits.Load() != 1 {
		t.Fatalf("segment 2 not prefetched: hits=%d", seg2Hits.Load())
	}
	if code, body, _ := get(segs[1]); code != 200 || body != "SEGMENT2" || seg2Hits.Load() != 1 {
		t.Fatalf("prefetched segment: %d %q hits=%d", code, body, seg2Hits.Load())
	}
	if code, _, _ := get(segs[2]); code != http.StatusBadGateway {
		t.Fatalf("playlist-injected private address fetched: %d", code)
	}

	if got := s.m.snapshot(); got["prefetchHits"].(int64) != 1 || got["retries"].(int64) < 1 || got["bytes"].(int64) < int64(len("SEGMENT")+len("SEGMENT2")) || got["errors"].(int64) < 1 {
		t.Fatalf("relay metrics = %v", got)
	}
	// Tampering with the signed target must not grant anything.
	parts := strings.Split(strings.TrimPrefix(entry, p.base+"/"), "/")
	parts[2] = b64.EncodeToString([]byte("http://example.com/other.m3u8"))
	if code, _, _ := get(p.base + "/" + strings.Join(parts, "/")); code != 404 {
		t.Fatalf("forged URL returned %d", code)
	}
	// Someone sniffing the LAN must not learn the site, the video or its token.
	for _, leak := range []string{b64.EncodeToString([]byte(up.URL))[:16], "master", "index", "seg1", "init"} {
		if strings.Contains(entry+master+media, leak) {
			t.Fatalf("proxy URL leaks %q", leak)
		}
	}
	if entry != p.entryURL(s, u) {
		t.Fatal("tokens must be stable for the same URL")
	}
	// A second cast must not cut off the first until it is committed.
	s2, _ := p.newSession(upst, dev)
	if code, _, _ := get(segs[0]); code != 200 {
		t.Fatalf("old session died when a new one was merely created: %d", code)
	}
	p.drop(s2) // the new cast failed
	if code, _, _ := get(segs[0]); code != 200 {
		t.Fatalf("old session died with the failed cast: %d", code)
	}
	if code, _, _ := get(p.entryURL(s2, u)); code != http.StatusForbidden {
		t.Fatalf("dropped session still served: %d", code)
	}
	s3, _ := p.newSession(upst, dev)
	p.keepOnly(s3) // the new cast is playing
	if code, _, _ := get(segs[0]); code != http.StatusForbidden {
		t.Fatalf("superseded session still served: %d", code)
	}
	if code, _, _ := get(p.entryURL(s3, u)); code != 200 {
		t.Fatalf("committed session: %d", code)
	}

	// Once everything is revoked, new connections are refused outright.
	p.keepOnly(nil)
	http.DefaultClient.CloseIdleConnections()
	if resp, err := http.Get(segs[0]); err == nil {
		resp.Body.Close()
		t.Fatal("new connection accepted after revoke")
	}
}

func TestNewPolicy(t *testing.T) {
	ctx := context.Background()
	lan, lo, meta := netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("169.254.169.254")
	if p := newPolicy(ctx, "192.168.1.10", false); !p.local || p.permit(lan) {
		t.Fatal("LAN stream must be flagged and blocked until the user confirms")
	}
	if p := newPolicy(ctx, "192.168.1.10", true); !p.permit(lan) || p.permit(netip.MustParseAddr("192.168.1.1")) {
		t.Fatal("confirmed LAN stream: exactly that address must be allowed")
	}
	for _, h := range []string{"127.0.0.1", "169.254.169.254", "localhost"} {
		if p := newPolicy(ctx, h, true); p.permit(lo) || p.permit(meta) {
			t.Fatalf("%s: loopback/metadata must never be allowed", h)
		}
	}
}

func TestRedirectAndCookieScope(t *testing.T) {
	var plainHits, otherSawCookie atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainHits.Add(1)
		if r.Header.Get("Cookie") != "" {
			t.Error("cookie sent over plain http")
		}
	}))
	defer plain.Close()
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" {
			otherSawCookie.Add(1)
		}
	}))
	defer other.Close()
	mux := http.NewServeMux()
	// Media paths throughout: a path that is not media gets no cookie to begin with.
	echo := func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "cookie="+r.Header.Get("Cookie")) }
	mux.HandleFunc("/ok.mp4", echo)
	mux.HandleFunc("/account", echo)
	mux.HandleFunc("/page.mp4", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/account", http.StatusFound) })
	mux.HandleFunc("/other.mp4", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/x.mp4", http.StatusFound)
	})
	mux.HandleFunc("/down.mp4", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/x.mp4", http.StatusFound)
	})
	mux.HandleFunc("/lan.mp4", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://10.255.255.1/x.mp4", http.StatusFound)
	})
	main := httptest.NewTLSServer(mux)
	defer main.Close()

	u, _ := url.Parse(main.URL + "/ok.mp4")
	up := newUpstream(loopbackPolicy(), u, &mediaReq{Cookie: "sid=secret"})
	pool := x509.NewCertPool()
	pool.AddCert(main.Certificate())
	up.client.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
	ctx := context.Background()

	for path, want := range map[string]string{
		"/ok.mp4":   "cookie=sid=secret",
		"/account":  "cookie=", // its own host, but not media
		"/page.mp4": "cookie=", // media that redirects to a page
	} {
		resp, err := up.get(ctx, http.MethodGet, main.URL+path, nil, true)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != want {
			t.Fatalf("%s: upstream saw %q, want %q", path, b, want)
		}
	}
	resp, err := up.get(ctx, http.MethodGet, main.URL+"/other.mp4", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if otherSawCookie.Load() != 0 {
		t.Fatal("cookie followed a redirect to another host")
	}
	if _, err = up.get(ctx, http.MethodGet, main.URL+"/down.mp4", nil, true); err == nil || plainHits.Load() != 0 {
		t.Fatalf("https to http downgrade was followed (err=%v hits=%d)", err, plainHits.Load())
	}
	if _, err = up.get(ctx, http.MethodGet, main.URL+"/lan.mp4", nil, true); err == nil {
		t.Fatal("redirect into a private address was followed")
	}
	if resp, err = up.get(ctx, http.MethodGet, plain.URL+"/x.mp4", nil, true); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close() // the handler itself asserts that no cookie arrived
	if err != nil && strings.Contains(err.Error(), "secret") {
		t.Fatal("error text leaks the cookie")
	}
}

func TestDirGrantContainment(t *testing.T) {
	p := &proxy{base: "http://proxy", sessions: map[string]*session{}}
	s, err := p.newSession(nil, netip.MustParseAddr("192.168.1.2"))
	if err != nil {
		t.Fatal(err)
	}
	base, _ := url.Parse("https://cdn.example/a/b/manifest.mpd?token=1")
	prefix, ok := p.dirURL(s, base)
	if !ok || !strings.HasSuffix(prefix, "/") || strings.Contains(prefix, "manifest") || strings.Contains(prefix, "token=1") {
		t.Fatalf("directory grant must end with the token and show nothing of the URL: %q", prefix)
	}
	for rest, want := range map[string]string{
		"manifest.mpd?token=1":  "https://cdn.example/a/b/manifest.mpd?token=1",
		"video/seg-1.m4s":       "https://cdn.example/a/b/video/seg-1.m4s",
		"../secret":             "",
		"%2e%2e/secret":         "",
		"video/%2E%2E/%2E%2E/x": "",
		"x/..%2f..%2fsecret":    "",
	} {
		r := httptest.NewRequest(http.MethodGet, prefix+rest, nil)
		got, ok := s.resolve(r)
		if (want == "") == ok || got != want {
			t.Errorf("resolve(%q) = %q, %v; want %q", rest, got, ok, want)
		}
	}
	// A grant signed as a single file must not work as a directory grant.
	forged := strings.Replace(p.fileURL(s, "https://cdn.example/a/"), "/u/", "/p/", 1)
	if _, ok := s.resolve(httptest.NewRequest(http.MethodGet, forged, nil)); ok {
		t.Fatal("file grant accepted as directory grant")
	}
}

func TestRewriteMPD(t *testing.T) {
	base, _ := url.Parse("https://site.example/vod/42/manifest.mpd?sig=SECRET")
	file := func(u *url.URL) string { return "http://proxy/u/" + b64.EncodeToString([]byte(u.String())) }
	dir := func(u *url.URL) (string, bool) {
		d := u.Scheme + "://" + u.Host + u.Path[:strings.LastIndex(u.Path, "/")+1]
		return "http://proxy/p/" + b64.EncodeToString([]byte(d)) + "/", d != "https://site.example/"
	}
	granted := func(out, kind, target string) bool {
		return strings.Contains(out, "http://proxy/"+kind+"/"+b64.EncodeToString([]byte(target)))
	}

	// Every place a DASH manifest can name another host.
	src := `<?xml version="1.0"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" xmlns:xlink="http://www.w3.org/1999/xlink" type="dynamic">
  <ProgramInformation><Title>t &amp; t</Title></ProgramInformation>
  <Location>https://site.example/vod/42/manifest.mpd?sig=NEXT</Location>
  <UTCTiming schemeIdUri="urn:mpeg:dash:utc:http-xsdate:2014" value="https://time.example/now?iso"/>
  <Period>
    <BaseURL>https://cdn.example/a/b/</BaseURL>
    <AdaptationSet>
      <BaseURL>video/</BaseURL>
      <SegmentTemplate media="https://cdn2.example/x/$RepresentationID$/seg-$Number$.m4s?tok=T" initialization='//cdn2.example/x/init.mp4'/>
      <Representation id="on-demand"><BaseURL>https://cdn.example/a/b/whole.mp4?sig=S</BaseURL>
        <SegmentBase><Initialization sourceURL="https://cdn.example/a/b/init-2.mp4"/></SegmentBase>
      </Representation>
      <SegmentList><SegmentURL media="https://cdn.example/a/b/s1.m4s" fake=" media='https://decoy.example/x' "/></SegmentList>
    </AdaptationSet>
  </Period>
</MPD>`
	out := string(rewriteMPD([]byte(src), base, true, file, dir))
	for _, host := range []string{"site.example", "cdn.example", "cdn2.example", "time.example", "SECRET", "NEXT", "sig=S", "manifest.mpd"} {
		if strings.Contains(out, host) {
			t.Errorf("rewritten manifest still names %q:\n%s", host, out)
		}
	}
	for _, want := range [][2]string{
		{"p", "https://site.example/vod/42/"}, // its own directory, for relative references
		{"p", "https://cdn.example/a/b/"},
		{"p", "https://cdn2.example/x/"}, // a template: granted up to the first placeholder
		{"u", "https://cdn2.example/x/init.mp4"},
		{"u", "https://cdn.example/a/b/whole.mp4?sig=S"},
		{"u", "https://cdn.example/a/b/init-2.mp4"},
		{"u", "https://cdn.example/a/b/s1.m4s"},
		{"u", "https://time.example/now?iso"},
	} {
		if !granted(out, want[0], want[1]) {
			t.Errorf("no %s grant for %s in:\n%s", want[0], want[1], out)
		}
	}
	// decoy.example sits inside another attribute's value, dressed up as a
	// media attribute: it must neither be taken for one nor hide the real one.
	for _, keep := range []string{"/$RepresentationID$/seg-$Number$.m4s?tok=T", "<BaseURL>video/</BaseURL>", "t &amp; t", `xmlns:xlink="http://www.w3.org/1999/xlink"`, "decoy.example"} {
		if !strings.Contains(out, keep) {
			t.Errorf("lost %q in:\n%s", keep, out)
		}
	}
	if strings.Contains(out, "<Location") {
		t.Errorf("Location kept:\n%s", out)
	}
	if err := xml.Unmarshal([]byte(out), new(struct{})); err != nil {
		t.Errorf("rewritten manifest is not well-formed: %v", err)
	}

	// A top-level base of the manifest's own is resolved against its URL and
	// takes the place of the inserted one.
	out = string(rewriteMPD([]byte(`<MPD><BaseURL>media/</BaseURL><Period/></MPD>`), base, false, file, dir))
	if !granted(out, "p", "https://site.example/vod/42/media/") || strings.Count(out, "<BaseURL>") != 1 {
		t.Errorf("relative top-level base: %s", out)
	}
	// An empty base says nothing; a declared encoding is no reason to refuse.
	out = string(rewriteMPD([]byte(`<?xml version="1.0" encoding="ISO-8859-1"?><MPD><BaseURL/><Period/></MPD>`), base, false, file, dir))
	if !strings.Contains(out, "<MPD><BaseURL/><Period/></MPD>") {
		t.Errorf("empty top-level base: %q", out)
	}
	// A remote element would be fetched from the site and spliced in unseen.
	remote := []byte(`<MPD xmlns:xlink="http://www.w3.org/1999/xlink"><Period xlink:href="https://site.example/period.xml"/></MPD>`)
	if rewriteMPD(remote, base, true, file, dir) != nil {
		t.Error("remote element accepted under Private relay")
	}
	if rewriteMPD(remote, base, false, file, dir) == nil {
		t.Error("remote element refused without Private relay")
	}
	// Refused: a grant the proxy will not give, and XML that is not XML.
	top, _ := url.Parse("https://site.example/manifest.mpd")
	for name, bad := range map[string][]byte{
		"top directory": []byte(`<MPD><Period/></MPD>`),
		"bad nesting":   []byte(`<MPD><Period></MPD></Period>`),
		"unclosed":      []byte(`<MPD><Period>`),
		"markup in URL": []byte(`<MPD><BaseURL>a<b/></BaseURL></MPD>`),
	} {
		b := base
		if name == "top directory" {
			b = top
		}
		if got := rewriteMPD(bad, b, false, file, dir); got != nil {
			t.Errorf("%s: accepted: %s", name, got)
		}
	}
}

// Issues 1 and 5 of SECURITY-ISSUES.md: whoever holds a grant (a hostile
// playlist, or a device that took the TV's address) must get neither the
// user's cookies onto a page, nor a page back.
func TestRelayOnlyMedia(t *testing.T) {
	var mu sync.Mutex
	cookies := map[string]string{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cookies[r.URL.Path] = r.Header.Get("Cookie")
		mu.Unlock()
		switch path.Ext(r.URL.Path) {
		case ".mpd":
			w.Header().Set("Content-Type", ctDASH)
			io.WriteString(w, `<MPD><Period><AdaptationSet><SegmentTemplate media="seg-$Number$.m4s"/></AdaptationSet></Period></MPD>`)
		case ".m4s":
			w.Header().Set("Content-Type", "video/iso.segment")
			io.WriteString(w, "SEGMENT")
		case ".json":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"email":"me@example.com"}`)
		case ".ts": // a page that answers under a media-looking name
			w.Header().Set("Content-Type", "application/octet-stream")
			io.WriteString(w, "\n <!DOCTYPE HTML><html>account</html>")
		case ".mp4":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, "<html>please log in, me@example.com</html>")
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, "<html>account</html>")
		}
	})
	site := httptest.NewTLSServer(mux)
	defer site.Close()
	u, _ := url.Parse(site.URL + "/vod/42/manifest.mpd?sig=SECRET")
	up := newUpstream(loopbackPolicy(), u, &mediaReq{Cookie: "sid=secret"})
	pool := x509.NewCertPool()
	pool.AddCert(site.Certificate())
	up.client.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool

	dev := netip.MustParseAddr("127.0.0.1")
	p, err := startProxy(dev)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	s, _ := p.newSession(up, dev)
	get := func(raw string) (int, string) {
		t.Helper()
		resp, err := http.Get(raw)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	sent := func(path string) string {
		mu.Lock()
		defer mu.Unlock()
		return cookies[path]
	}

	// Issue 2: nothing of the DASH URL is readable, and it still plays.
	entry := p.entryURL(s, u)
	code, manifest := get(entry)
	if code != 200 || strings.Contains(entry+manifest, "manifest") || strings.Contains(entry+manifest, "SECRET") || strings.Contains(entry+manifest, "vod") {
		t.Fatalf("DASH entry: %d %q %q", code, entry, manifest)
	}
	if sent("/vod/42/manifest.mpd") != "sid=secret" {
		t.Fatal("the manifest itself is media: it needs the cookie")
	}
	m := regexp.MustCompile(`<BaseURL>([^<]+)</BaseURL>`).FindStringSubmatch(manifest)
	if m == nil {
		t.Fatalf("no base for relative references in %q", manifest)
	}
	dirGrant := m[1]
	if code, body := get(dirGrant + "seg-1.m4s"); code != 200 || body != "SEGMENT" || sent("/vod/42/seg-1.m4s") != "sid=secret" {
		t.Fatalf("relative segment through the base: %d %q cookie=%q", code, body, sent("/vod/42/seg-1.m4s"))
	}

	// Issue 1: the same grant, asked for something that is not the video.
	for _, rest := range []string{"account", "api/me.json", "page.ts", "clip.mp4"} {
		code, body := get(dirGrant + rest)
		if code == 200 || strings.Contains(body, "account") || strings.Contains(body, "example.com") {
			t.Errorf("directory grant returned a document for %q: %d %q", rest, code, body)
		}
	}
	if c := sent("/vod/42/account"); c != "" {
		t.Errorf("cookie %q sent to a path that is not media (directory grant)", c)
	}
	if c := sent("/vod/42/api/me.json"); c != "" {
		t.Errorf("cookie %q sent to a JSON endpoint", c)
	}
	// Issue 5: a single-file token, as a hostile playlist would earn one.
	if code, body := get(p.fileURL(s, site.URL+"/settings")); code == 200 || body == "<html>account</html>" || sent("/settings") != "" {
		t.Errorf("file grant for a page: %d %q cookie=%q", code, body, sent("/settings"))
	}

	// With cookies, a stream at the top of the host is not relayed at all.
	top, _ := url.Parse(site.URL + "/manifest.mpd")
	if _, ok := p.dirURL(s, top); ok {
		t.Error("directory grant on the whole cookie host")
	}
	if code, _ := get(p.entryURL(s, top)); code != http.StatusBadGateway {
		t.Errorf("top-level DASH manifest relayed with cookies: %d", code)
	}
	plain, _ := p.newSession(newUpstream(loopbackPolicy(), top, &mediaReq{}), dev)
	if _, ok := p.dirURL(plain, top); !ok {
		t.Error("without cookies the top directory is an ordinary grant")
	}
}

// Issue 3: Referer and Origin are decided again for every redirect.
func TestRedirectReferrer(t *testing.T) {
	type seen struct{ referer, origin string }
	got := make(chan seen, 1)
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- seen{r.Header.Get("Referer"), r.Header.Get("Origin")}
	}))
	defer cdn.Close()
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v.mp4" && r.Header.Get("Referer") != "http://"+r.Host+"/watch/1?user=me" {
			t.Errorf("the page's own host gets the full Referer, got %q", r.Header.Get("Referer"))
		}
		http.Redirect(w, r, cdn.URL+"/signed.mp4?sig=SECRET2", http.StatusFound)
	}))
	defer site.Close()
	ctx := context.Background()
	u, _ := url.Parse(site.URL + "/v.mp4?sig=SECRET1")

	up := newUpstream(loopbackPolicy(), u, &mediaReq{Referer: site.URL + "/watch/1?user=me"})
	resp, err := up.get(ctx, http.MethodGet, u.String(), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if s := <-got; s.referer != site.URL+"/" || s.origin != site.URL {
		t.Errorf("second host saw Referer %q Origin %q, want the bare origin", s.referer, s.origin)
	}

	// No Referer intended: net/http must not invent one from the signed URL.
	for _, creds := range []bool{true, false} {
		up = newUpstream(loopbackPolicy(), u, &mediaReq{})
		if resp, err = up.get(ctx, http.MethodGet, site.URL+"/x.mp4?sig=SECRET1", http.Header{"Origin": {receiverOrigin}}, creds); err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if s := <-got; s.referer != "" {
			t.Errorf("creds=%v: destination saw an invented Referer %q", creds, s.referer)
		}
	}
}

// testPKI stands in for Google's Cast root during tests.
var testRootKey, testRootCert = func() (*rsa.PrivateKey, *x509.Certificate) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Cast Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}()

func TestMain(m *testing.M) {
	castRoots = x509.NewCertPool()
	castRoots.AddCert(testRootCert)
	os.Exit(m.Run())
}

// newDeviceKey issues a device certificate under the test root; selfSigned
// produces what a rogue box on the LAN would have instead.
func newDeviceKey(t *testing.T, selfSigned ...bool) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "device"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	parent, signer := testRootCert, testRootKey
	if len(selfSigned) > 0 && selfSigned[0] {
		parent, signer = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	return key, der
}

// fakeReceiver speaks just enough Cast v2 to exercise auth/launch/load/control.
// signWith may differ from the advertised device certificate to play an impostor.
func fakeReceiver(t *testing.T, signWith *rsa.PrivateKey, deviceCert []byte) (addr string, loads chan map[string]any, kill func()) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	loads = make(chan map[string]any, 4)
	conns := make(chan net.Conn, 16)
	kill = func() { (<-conns).Close() }
	serve := func(conn net.Conn) {
		defer conn.Close()
		reply := func(to castMsg, v map[string]any) {
			b, _ := json.Marshal(v)
			conn.Write(encodeMsg(castMsg{src: to.dst, dst: to.src, ns: to.ns, payload: string(b)}))
		}
		var hdr [4]byte
		for {
			if _, err := io.ReadFull(conn, hdr[:]); err != nil {
				return
			}
			buf := make([]byte, binary.BigEndian.Uint32(hdr[:]))
			if _, err := io.ReadFull(conn, buf); err != nil {
				return
			}
			m, _ := decodeMsg(buf)
			if m.ns == nsAuth {
				outer, _, _ := pbFields(m.binary)
				challenge, _, _ := pbFields(outer[1])
				digest := sha256.Sum256(append(append([]byte{}, challenge[2]...), der...))
				sig, _ := rsa.SignPKCS1v15(rand.Reader, signWith, crypto.SHA256, digest[:])
				resp := appendField(nil, 1, string(sig))
				resp = appendField(resp, 2, string(deviceCert))
				resp = appendField(resp, 5, string(challenge[2]))
				resp = append(resp, 0x30, 0x01) // hash_algorithm = SHA256
				conn.Write(encodeMsg(castMsg{src: receiverID, dst: m.src, ns: nsAuth, binary: appendField(nil, 2, string(resp))}))
				continue
			}
			var p map[string]any
			json.Unmarshal([]byte(m.payload), &p)
			rid := p["requestId"]
			switch p["type"] {
			case "GET_STATUS":
				if m.ns == nsMedia {
					reply(m, map[string]any{"type": "MEDIA_STATUS", "requestId": rid, "status": []any{map[string]any{"mediaSessionId": 7, "playerState": "PLAYING"}}})
					continue
				}
				fallthrough
			case "LAUNCH":
				reply(m, map[string]any{"type": "RECEIVER_STATUS", "requestId": rid, "status": map[string]any{
					"applications": []any{map[string]any{"appId": defaultReceiver, "transportId": "t-1", "sessionId": "s-1"}}}})
			case "LOAD":
				if m.dst != "t-1" {
					return
				}
				loads <- p
				reply(m, map[string]any{"type": "MEDIA_STATUS", "requestId": rid, "status": []any{map[string]any{"mediaSessionId": 7, "playerState": "BUFFERING"}}})
			case "PAUSE":
				reply(m, map[string]any{"type": "MEDIA_STATUS", "requestId": rid, "status": []any{map[string]any{"mediaSessionId": 7, "playerState": "PAUSED"}}})
			case "EDIT_TRACKS_INFO":
				loads <- p
				reply(m, map[string]any{"type": "MEDIA_STATUS", "requestId": rid, "status": []any{map[string]any{"mediaSessionId": 7, "playerState": "PLAYING", "activeTrackIds": p["activeTrackIds"]}}})
			}
		}
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conns <- conn
			go serve(conn)
		}
	}()
	return ln.Addr().String(), loads, kill
}

func TestReconnectKeepsSession(t *testing.T) {
	old := rejoinWaits
	rejoinWaits = []time.Duration{50 * time.Millisecond, 50 * time.Millisecond}
	defer func() { rejoinWaits = old }()

	devKey, devCert := newDeviceKey(t)
	addr, _, kill := fakeReceiver(t, devKey, devCert)
	events := make(chan map[string]any, 16)
	h := newHost(func(v any) {
		b, _ := json.Marshal(v)
		var m map[string]any
		json.Unmarshal(b, &m)
		events <- m
	})
	h.pins = &pinStore{path: filepath.Join(t.TempDir(), "pins.json")}
	defer h.shutdown()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Concurrent casts share one connection instead of racing to dial two.
	results := make(chan *castConn, 2)
	for i := 0; i < 2; i++ {
		go func() {
			h.castMu.Lock()
			defer h.castMu.Unlock()
			cc, err := h.connect(ctx, addr, "tv")
			if err != nil {
				t.Error(err)
			}
			results <- cc
		}()
	}
	first, second := <-results, <-results
	if first == nil || first != second {
		t.Fatal("concurrent casts did not share one TV connection")
	}
	app, err := first.launch(ctx, defaultReceiver)
	if err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	h.app = app
	h.mu.Unlock()

	kill() // Wi-Fi blip while the TV keeps playing
	deadline := time.Now().Add(5 * time.Second)
	for {
		h.mu.Lock()
		cc, rejoined := h.cc, h.cc != nil && h.cc != first && h.app != nil
		h.mu.Unlock()
		if rejoined && cc.alive() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("control connection was not re-established")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for len(events) > 0 {
		if e := <-events; e["type"] == "disconnected" {
			t.Fatal("reported a disconnect although the session was recovered")
		}
	}
	if err := h.control(ctx, "pause", 0); err != nil {
		t.Fatalf("control after reconnect: %v", err)
	}
}

func TestDeviceIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pins := &pinStore{path: filepath.Join(t.TempDir(), "pins.json")}
	verify := func(fp string) error { return pins.check("living-room", fp) }
	code := func(err error) string {
		var ce *codedErr
		if errors.As(err, &ce) {
			return ce.code
		}
		return ""
	}

	tvKey, tvCert := newDeviceKey(t)
	for i := 0; i < 2; i++ { // first use pins, second use matches
		addr, _, _ := fakeReceiver(t, tvKey, tvCert)
		cc, err := dialCast(ctx, addr, verify, nil, nil)
		if err != nil {
			t.Fatalf("genuine TV, connection %d: %v", i+1, err)
		}
		cc.Close()
	}

	// Another device claiming the same identity slot: valid signature, wrong key.
	otherKey, otherCert := newDeviceKey(t)
	addr, _, _ := fakeReceiver(t, otherKey, otherCert)
	if _, err := dialCast(ctx, addr, verify, nil, nil); code(err) != "DEVICE_IDENTITY" {
		t.Fatalf("different device accepted: %v", err)
	}
	// A man in the middle replaying the real TV's certificate cannot sign for it.
	addr, _, _ = fakeReceiver(t, otherKey, tvCert)
	if _, err := dialCast(ctx, addr, verify, nil, nil); code(err) != "DEVICE_AUTH" {
		t.Fatalf("forged signature accepted: %v", err)
	}
	// A box that is not a genuine Cast device (no certificate under the Cast
	// root) is refused even on first use, before any pin exists.
	rogueKey, rogueCert := newDeviceKey(t, true)
	addr, _, _ = fakeReceiver(t, rogueKey, rogueCert)
	if _, err := dialCast(ctx, addr, func(fp string) error { return pins.check("never-seen", fp) }, nil, nil); code(err) != "DEVICE_AUTH" {
		t.Fatalf("non-Cast device accepted on first use: %v", err)
	}
	// A damaged pin file must block casting, not silently re-trust everything.
	good, _ := os.ReadFile(pins.path)
	os.WriteFile(pins.path, []byte("{not json"), 0o600)
	if err := pins.check("living-room", "00"); code(err) != "DEVICE_AUTH" {
		t.Fatalf("corrupt pin file treated as empty: %v", err)
	}
	os.WriteFile(pins.path, good, 0o600)
	// Explicit user reset allows re-pinning.
	if err := pins.forget("living-room"); err != nil {
		t.Fatal(err)
	}
	addr, _, _ = fakeReceiver(t, otherKey, otherCert)
	cc, err := dialCast(ctx, addr, verify, nil, nil)
	if err != nil {
		t.Fatalf("after forget: %v", err)
	}
	cc.Close()
}

func TestCastLaunchLoadControl(t *testing.T) {
	devKey, devCert := newDeviceKey(t)
	addr, loads, kill := fakeReceiver(t, devKey, devCert)
	events := make(chan string, 8)
	closed := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cc, err := dialCast(ctx, addr, func(string) error { return nil },
		func(typ string, _ json.RawMessage) { events <- typ }, func(*castConn) { close(closed) })
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	app, err := cc.launch(ctx, defaultReceiver)
	if err != nil || app.transportID != "t-1" {
		t.Fatalf("launch = %+v, %v", app, err)
	}
	plan := &mediaPlan{mode: "direct", contentID: "https://cdn.example/x.m3u8", mediaInfo: mediaInfo{contentType: ctHLS, fmp4: true}}
	msid, err := cc.load(ctx, app, plan.loadMedia("Title"), 42)
	if err != nil || msid != 7 {
		t.Fatalf("load = %d, %v", msid, err)
	}
	got := <-loads
	media := got["media"].(map[string]any)
	if media["hlsSegmentFormat"] != "fmp4" || got["currentTime"] != float64(42) || got["sessionId"] != "s-1" {
		t.Fatalf("LOAD payload %v", got)
	}
	if _, err := cc.mediaCmd(ctx, app, map[string]any{"type": "PAUSE", "mediaSessionId": msid}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-events:
	case <-ctx.Done():
		t.Fatal("no status event forwarded")
	}
	kill() // TV drops off the network: the owner must hear about it
	select {
	case <-closed:
	case <-ctx.Done():
		t.Fatal("connection loss not reported")
	}
}

// The popup warms the connection to the picked TV before Cast is pressed.
func TestWarm(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	events := make(chan any, 8)
	h := newHost(func(v any) { events <- v })
	h.pins = &pinStore{path: filepath.Join(t.TempDir(), "pins.json")}
	current := func() *castConn {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.cc
	}

	tvKey, tvCert := newDeviceKey(t)
	addr, _, kill := fakeReceiver(t, tvKey, tvCert)
	// Never cast to: opening the popup must not connect, let alone pin it.
	h.warmAddr(ctx, addr, "living-room")
	if current() != nil || h.pins.known("living-room") {
		t.Fatal("warmed a TV that was never cast to")
	}
	// Cast to before (its identity is pinned): the connection is made ahead...
	cc, err := dialCast(ctx, addr, func(fp string) error { return h.pins.check("living-room", fp) }, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cc.Close()
	h.warmAddr(ctx, addr, "living-room")
	warmed := current()
	if warmed == nil || !warmed.alive() {
		t.Fatal("known TV not warmed")
	}
	// ...and the cast then uses it instead of dialling again.
	h.castMu.Lock()
	got, err := h.connect(ctx, addr, "living-room")
	h.castMu.Unlock()
	if err != nil || got != warmed {
		t.Fatalf("cast did not reuse the warmed connection: %v", err)
	}
	// While something plays, its connection is left alone.
	otherKey, otherCert := newDeviceKey(t)
	other, _, _ := fakeReceiver(t, otherKey, otherCert)
	cc, err = dialCast(ctx, other, func(fp string) error { return h.pins.check("bedroom", fp) }, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cc.Close()
	h.mu.Lock()
	h.app = &receiverApp{}
	h.mu.Unlock()
	h.warmAddr(ctx, other, "bedroom")
	if current() != warmed {
		t.Fatal("warming another TV took the connection of the one that plays")
	}
	// An idle one gives way when another TV is picked, and comes back after.
	h.mu.Lock()
	h.app = nil
	h.mu.Unlock()
	h.warmAddr(ctx, other, "bedroom")
	if c := current(); c == nil || c == warmed || c.addr != other {
		t.Fatal("picking another TV did not warm it")
	}
	h.warmAddr(ctx, addr, "living-room")
	warmed = current()
	if warmed == nil || warmed.addr != addr {
		t.Fatal("picking the first TV again did not warm it")
	}
	// An idle connection that drops is nobody's business.
	for i := 0; i < 3; i++ {
		kill() // oldest first: the one that pinned the TV, the first warmed one, this one
	}
	for i := 0; i < 200 && current() != nil; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if current() != nil {
		t.Fatal("dead connection still held")
	}
	select {
	case ev := <-events:
		t.Fatalf("idle connection loss reported to the popup: %v", ev)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestNativeFraming(t *testing.T) {
	pr, pw := net.Pipe()
	out := make(chan map[string]any, 1)
	h := newHost(func(v any) { b, _ := json.Marshal(v); var m map[string]any; json.Unmarshal(b, &m); out <- m })
	if r, err := h.dispatch(context.Background(), request{Type: "hello"}); err != nil || r["proto"] != protoVersion {
		t.Fatalf("hello = %v, %v", r, err)
	}
	go h.serve(pr)

	send := func(b []byte) {
		var n [4]byte
		binary.NativeEndian.PutUint32(n[:], uint32(len(b)))
		pw.Write(append(n[:], b...))
	}
	send([]byte(`{"id":1,"type":"cast","evil":true}`))
	if m := <-out; m["code"] != "BAD_REQUEST" {
		t.Fatalf("unknown field accepted: %v", m)
	}
	send([]byte(`{"id":2,"type":"cast","device":{"host":"8.8.8.8"},"media":{"url":"https://x/y.mp4"}}`))
	if m := <-out; m["code"] != "BAD_REQUEST" || m["id"] != float64(2) {
		t.Fatalf("public device accepted: %v", m)
	}
	send([]byte(`{"id":3,"type":"cast","device":{"host":"192.168.1.5"},"media":{"url":"file:///etc/passwd"}}`))
	if m := <-out; m["code"] != "BAD_REQUEST" {
		t.Fatalf("file URL accepted: %v", m)
	}
	pw.Close()
}

// Subtitle and audio tracks: the TV's list reaches the popup bounded, and the
// popup's choice reaches the TV.
func TestTracks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	events := make(chan map[string]any, 8)
	h := newHost(func(v any) { b, _ := json.Marshal(v); var m map[string]any; json.Unmarshal(b, &m); events <- m })

	long := strings.Repeat("é", 300)
	status := map[string]any{"type": "MEDIA_STATUS", "status": []any{map[string]any{
		"mediaSessionId": 7, "playerState": "PLAYING", "currentTime": 12, "activeTrackIds": []int{2},
		"media": map[string]any{"duration": 600, "tracks": []any{
			map[string]any{"trackId": 1, "type": "VIDEO"},
			map[string]any{"trackId": 2, "type": "AUDIO", "name": "English", "language": "en"},
			map[string]any{"trackId": 3, "type": "TEXT", "name": long, "language": "fr"},
		}},
	}}}
	raw, _ := json.Marshal(status)
	h.onCastEvent("MEDIA_STATUS", raw)
	ev := <-events
	tracks, _ := ev["tracks"].([]any)
	if len(tracks) != 2 || ev["duration"] != float64(600) {
		t.Fatalf("media event = %v", ev)
	}
	if name := tracks[1].(map[string]any)["name"].(string); len([]rune(name)) != 64 {
		t.Fatalf("track name not bounded: %d characters", len([]rune(name)))
	}
	if ids, _ := ev["activeTrackIds"].([]any); len(ids) != 1 || ids[0] != float64(2) {
		t.Fatalf("active tracks = %v", ev["activeTrackIds"])
	}
	// A later report without `media` says nothing about tracks: the popup keeps its list.
	h.onCastEvent("MEDIA_STATUS", []byte(`{"status":[{"mediaSessionId":7,"playerState":"PAUSED"}]}`))
	if ev = <-events; ev["tracks"] != nil || ev["activeTrackIds"] != nil {
		t.Fatalf("report without media carries tracks: %v", ev)
	}

	if err := h.setTracks(ctx, []int64{3}); err == nil {
		t.Fatal("tracks switched although nothing is casting")
	}
	devKey, devCert := newDeviceKey(t)
	addr, edits, _ := fakeReceiver(t, devKey, devCert)
	cc, err := dialCast(ctx, addr, func(string) error { return nil }, h.onCastEvent, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	app, err := cc.launch(ctx, defaultReceiver)
	if err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	h.cc, h.app, h.msid = cc, app, 7
	h.mu.Unlock()
	for _, ids := range [][]int64{{2, 3}, nil} {
		if err := h.setTracks(ctx, ids); err != nil {
			t.Fatal(err)
		}
		got := <-edits
		list, isList := got["activeTrackIds"].([]any)
		if got["type"] != "EDIT_TRACKS_INFO" || got["mediaSessionId"] != float64(7) || !isList || len(list) != len(ids) {
			t.Fatalf("sent to the TV for %v: %v", ids, got)
		}
	}
	if err := h.setTracks(ctx, make([]int64, 9)); err == nil {
		t.Fatal("nine tracks accepted")
	}
}

// xcast <file>: a video from this computer goes to the TV through the relay,
// under a token like any other, and only the command line can ask for it.
func TestCastLocalFile(t *testing.T) {
	dir := t.TempDir()
	body := bytes.Repeat([]byte("0123456789abcdef"), 4096) // 64 KB
	file := filepath.Join(dir, "Holiday in Rome.mp4")
	if err := os.WriteFile(file, body, 0o600); err != nil {
		t.Fatal(err)
	}
	h := newHost(func(any) {})
	defer h.shutdown()
	dev := netip.MustParseAddr("127.0.0.1")

	plan, err := h.planFile(dev, file)
	if err != nil || plan.mode != "proxy" || plan.contentType != "video/mp4" || plan.live {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
	for _, leak := range []string{"Holiday", "Rome", filepath.Base(dir)} {
		if strings.Contains(plan.contentID, leak) {
			t.Fatalf("the URL the TV gets shows %q: %s", leak, plan.contentID)
		}
	}
	do := func(method, raw, rng string) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest(method, raw, nil)
		if rng != "" {
			req.Header.Set("Range", rng)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}
	resp, got := do(http.MethodGet, plan.contentID, "")
	if resp.StatusCode != 200 || !bytes.Equal(got, body) || resp.Header.Get("Content-Type") != "video/mp4" ||
		resp.Header.Get("Accept-Ranges") != "bytes" || resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("whole file: %d, %d bytes, %v", resp.StatusCode, len(got), resp.Header)
	}
	// The TV seeks with Range requests.
	resp, got = do(http.MethodGet, plan.contentID, "bytes=16-31")
	if resp.StatusCode != http.StatusPartialContent || string(got) != "0123456789abcdef" || resp.Header.Get("Content-Range") != fmt.Sprintf("bytes 16-31/%d", len(body)) {
		t.Fatalf("range: %d %q %q", resp.StatusCode, got, resp.Header.Get("Content-Range"))
	}
	if resp, got = do(http.MethodHead, plan.contentID, ""); resp.StatusCode != 200 || len(got) != 0 || resp.ContentLength != int64(len(body)) {
		t.Fatalf("HEAD: %d, length %d", resp.StatusCode, resp.ContentLength)
	}

	// The grant is for that one file. Another path under the same session, a
	// file grant forged for a session that has no file, and an upstream grant
	// on a file session all get nothing.
	p := h.prox
	other := filepath.Join(dir, "secret.mp4")
	os.WriteFile(other, []byte("SECRET"), 0o600)
	forged := p.base + "/" + plan.sess.id + "/f/" + plan.sess.seal('f', other) + "/media.mp4"
	if resp, got = do(http.MethodGet, forged, ""); resp.StatusCode != 404 || bytes.Contains(got, []byte("SECRET")) {
		t.Fatalf("second file served from a one-file session: %d %q", resp.StatusCode, got)
	}
	web, _ := p.newSession(nil, dev)
	if resp, got = do(http.MethodGet, p.base+"/"+web.id+"/f/"+web.seal('f', other)+"/media.mp4", ""); resp.StatusCode != 404 || bytes.Contains(got, []byte("SECRET")) {
		t.Fatalf("file grant honoured by a session without a file: %d %q", resp.StatusCode, got)
	}
	if resp, _ = do(http.MethodGet, p.fileURL(plan.sess, "https://example.com/x.mp4"), ""); resp.StatusCode != 404 {
		t.Fatalf("file session fetched from upstream: %d", resp.StatusCode)
	}

	// What cannot be cast is refused before any TV is involved.
	os.WriteFile(filepath.Join(dir, "film.mkv"), body, 0o600)
	os.WriteFile(filepath.Join(dir, "list.m3u8"), []byte("#EXTM3U"), 0o600)
	for _, bad := range []string{filepath.Join(dir, "film.mkv"), filepath.Join(dir, "list.m3u8"), filepath.Join(dir, "missing.mp4"), dir} {
		if _, err := localFileType(bad); err == nil {
			t.Errorf("%s accepted", filepath.Base(bad))
		}
	}

	// The extension cannot name a file: the field has no JSON name, and the
	// native messaging decoder refuses what it does not know.
	for _, raw := range []string{`{"type":"cast","media":{"url":"https://a.example/v.mp4","file":"/etc/passwd"}}`, `{"type":"cast","media":{"url":"https://a.example/v.mp4","File":"/etc/passwd"}}`} {
		var req request
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err == nil && req.Media != nil && req.Media.file != "" {
			t.Fatalf("a native message set the local file: %s", raw)
		} else if err == nil {
			t.Fatalf("unknown field accepted: %s", raw)
		}
	}
}

func TestPlayCommandLine(t *testing.T) {
	for in, want := range map[string]float64{"90": 90, "1:30": 90, "1:02:03": 3723, " 0:05 ": 5, "12.5": 12.5} {
		if got, err := parseClock(in); err != nil || got != want {
			t.Errorf("parseClock(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "a", "1:2:3:4", "-5", "1:-2", "NaN", "Inf"} {
		if got, err := parseClock(in); err == nil {
			t.Errorf("parseClock(%q) = %v, want an error", in, got)
		}
	}
	if clock(3723) != "1:02:03" || clock(65) != "1:05" {
		t.Errorf("clock: %s %s", clock(3723), clock(65))
	}

	devs := []Device{
		{ID: "a", Name: "Living Room TV", Model: "Chromecast", Host: "192.168.1.20", Port: 8009, Known: true},
		{ID: "b", Name: "Bedroom TV", Model: "Nest Hub", Host: "192.168.1.21", Port: 8009},
	}
	pick := func(want, typed string) (string, string, error) {
		var out strings.Builder
		d, err := chooseDevice(devs, want, strings.NewReader(typed), &out)
		return d.ID, out.String(), err
	}
	for _, c := range []struct{ want, typed, id string }{
		{"", "2\n", "b"},
		{"", "\n", "a"},        // Enter takes the first, which is a TV used before
		{"", "9\nx\n2\n", "b"}, // asks again
		{"bedroom", "", "b"},
		{"192.168.1.20", "", "a"},
	} {
		if id, out, err := pick(c.want, c.typed); err != nil || id != c.id {
			t.Errorf("chooseDevice(%q, %q) = %q, %v\n%s", c.want, c.typed, id, err, out)
		}
	}
	// Nothing plays on a TV nobody chose.
	for _, c := range []struct{ want, typed string }{{"", ""}, {"", "q\n"}, {"tv", ""}, {"kitchen", ""}, {"", "7\n8\n9\n"}} {
		if id, _, err := pick(c.want, c.typed); err == nil {
			t.Errorf("chooseDevice(%q, %q) picked %q by itself", c.want, c.typed, id)
		}
	}
	if _, out, _ := pick("", "q\n"); !strings.Contains(out, "used before") || !strings.Contains(out, "new:") {
		t.Errorf("the list does not tell known TVs from new ones:\n%s", out)
	}
	one := devs[:1]
	if d, err := chooseDevice(one, "", strings.NewReader(""), io.Discard); err == nil {
		t.Errorf("a single TV was picked without asking: %v", d.Name)
	}
	if _, err := chooseDevice(nil, "", strings.NewReader("1\n"), io.Discard); err == nil {
		t.Error("picked from an empty list")
	}
}

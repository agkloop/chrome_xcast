package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"
	"unicode/utf8"
)

// Everything fuzzed here parses bytes that someone else chose: a web server
// (playlists, manifests), any machine on the LAN (mDNS, the Cast socket before
// and after the identity check) or the browser (native messaging). The targets
// check only that the parser returns, without panicking, and keeps to the
// limits it documents. What it should return is host_test.go's business.
//
//	go test -run='^$' -fuzz='^FuzzRewriteHLS$' -fuzztime=20s .
//
// A rate that drops to 0 execs/sec is the engine shrinking a new input, not a
// parser that hangs; -fuzzminimizetime=1x keeps it from spending the run there.

// fuzzSession is a session as the proxy hands them out, minus the listener.
func fuzzSession(f *testing.F) (*proxy, *session) {
	p := &proxy{base: "http://proxy", sessions: map[string]*session{}}
	s, err := p.newSession(nil, netip.MustParseAddr("192.168.1.2"))
	if err != nil {
		f.Fatal(err)
	}
	return p, s
}

// meteredReader records the largest single read asked of it, which is how
// much the reader under test was prepared to buffer for one message.
type meteredReader struct {
	r   io.Reader
	max int
}

func (m *meteredReader) Read(p []byte) (int, error) {
	m.max = max(m.max, len(p))
	return m.r.Read(p)
}

var hlsSeeds = []string{
	"",
	"#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=1\nlow/index.m3u8\n",
	"#EXTM3U\n#EXT-X-MAP:URI=\"init.mp4\"\n#EXTINF:4,\nseg1.m4s\n#EXTINF:4,\nseg2.m4s\n#EXTINF:4,\nhttp://10.255.255.1/evil.ts\n#EXT-X-ENDLIST\n",
	"#EXTM3U\r\n#EXT-X-KEY:METHOD=AES-128,URI=\"key.bin\",IV=0x1\r\n#EXTINF:4,\r\nseg1.ts\r\n\r\n",
	"#EXT-X-MEDIA:TYPE=AUDIO,URI=\"a.m3u8\",NAME=\"x\",URI=\"b.m3u8\"\n#EXT-X-KEY:URI=\"key.bin",
	"#EXT-X-MAP:URI=\"data:text/plain,x\"\n#EXT-X-SESSION-KEY:URI=\"skd://k\"\n#EXT-X-KEY:URI=\"\"\nseg.ts",
	"\ufeff#EXTM3U\n\xff\xfeseg\x80.ts\n%zz\n://\nhttp://[::1\n  //other.example/x.ts?a=b#frag \n",
	strings.Repeat("s\n", maxManifestURIs+1),
	strings.Repeat("#EXT-X-KEY:URI=\"k\"\n", maxManifestURIs+1),
}

func FuzzRewriteHLS(f *testing.F) {
	for _, s := range hlsSeeds {
		f.Add([]byte(s))
	}
	p, s := fuzzSession(f)
	base, _ := url.Parse("https://cdn.example/v/low/index.m3u8?token=1")
	f.Fuzz(func(t *testing.T, src []byte) {
		if len(src) > maxManifest {
			t.Skip() // serveRewritten never passes on more
		}
		uris, grown := 0, 0
		out, _ := rewriteHLS(src, base, func(u *url.URL) string {
			tok := p.fileURL(s, u.String())
			uris++
			grown += len(tok)
			return tok
		})
		if out != nil && (uris > maxManifestURIs || grown > maxRewritten) {
			t.Fatalf("served a playlist with %d rewritten URIs, %d bytes of tokens", uris, grown)
		}
	})
}

func FuzzScanHLS(f *testing.F) {
	for _, s := range hlsSeeds {
		f.Add([]byte(s))
	}
	base, _ := url.Parse("https://cdn.example/v/master.m3u8")
	f.Fuzz(func(t *testing.T, body []byte) {
		scanHLS(body, base)
	})
}

func FuzzParseCastRecords(f *testing.F) {
	inst := "Chromecast-abc._googlecast._tcp.local"
	txt := func(kvs ...string) (b []byte) {
		for _, kv := range kvs {
			b = append(append(b, byte(len(kv))), kv...)
		}
		return b
	}
	answers := func(n uint16, rrs ...[]byte) []byte {
		msg := []byte{0, 0, 0x84, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint16(msg[6:], n)
		return append(msg, bytes.Join(rrs, nil)...)
	}
	srv := append([]byte{0, 0, 0, 0, 0x1f, 0x49}, encName("abc.local")...)
	good := answers(4,
		rr(castService, 12, encName(inst)),
		rr(inst, 33, srv),
		rr(inst, 16, txt("id=abc123", "md=Chromecast", "fn=Living Room TV")),
		rr("abc.local", 1, []byte{192, 168, 1, 77}))
	for _, seed := range [][]byte{
		nil,
		good,
		good[:40],
		// Counts that promise far more records than the packet holds.
		{0, 0, 0x84, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		// A name that is a compression pointer to itself, and one past the end.
		answers(1, []byte{0xc0, 12, 0, 12, 0x80, 1, 0, 0, 0, 120, 0, 2, 0xc0, 12}),
		answers(1, []byte{0xc0, 0xff, 0, 16, 0x80, 1, 0, 0, 0, 120, 0, 0}),
		// TXT strings that overrun their record; an SRV too short to hold a port.
		answers(2, rr(inst, 16, []byte{200, 'i', 'd', '='}), rr(inst, 33, []byte{0, 0, 0})),
		// Names built to fool whoever reads the list: overlong, control
		// characters, a right-to-left override, broken UTF-8.
		answers(1, rr(inst, 16, txt("id="+strings.Repeat("x", 200), "fn=\x00TV\r\n\u202egpj.exe\xff\xfe", "md="+strings.Repeat("\u00e9", 100)))),
	} {
		f.Add(seed)
	}
	src := netip.MustParseAddr("192.168.1.50")
	f.Fuzz(func(t *testing.T, msg []byte) {
		for _, d := range parseCastRecords(msg, src) {
			for _, label := range []string{d.ID, d.Name, d.Model} {
				if utf8.RuneCountInString(label) > 64 {
					t.Fatalf("label of %d characters reached the device list: %q", utf8.RuneCountInString(label), label)
				}
			}
		}
	})
}

func nativeFrame(body []byte) []byte {
	return append(binary.NativeEndian.AppendUint32(nil, uint32(len(body))), body...)
}

func FuzzNativeFraming(f *testing.F) {
	declare := func(n uint32, body string) []byte {
		return append(binary.NativeEndian.AppendUint32(nil, n), body...)
	}
	blocked := nativeFrame([]byte(`{"id":2,"type":"cast","device":{"host":"8.8.8.8"},"media":{"url":"https://x/y.mp4"}}`))
	for _, seed := range [][]byte{
		nil,
		{1, 0},
		nativeFrame([]byte(`{"id":1,"type":"cast","evil":true}`)),
		blocked,
		nativeFrame([]byte(`{"id":3,"type":"cast","device":{"host":"192.168.1.5"},"media":{"url":"file:///etc/passwd"}}`)),
		append(nativeFrame([]byte(`{"id":4,"type":"discover","timeoutMs":300}`)), nativeFrame([]byte(`{"id":5,"type":"forget","device":{"host":"192.168.1.5"}}`))...),
		nativeFrame([]byte("{\"id\":6,\r\n\"type\":\"control\",\"action\":\"seek\",\"value\":1e999}")),
		nativeFrame([]byte(`{"id":7,"type":"cast`)),
		nativeFrame([]byte("{\"type\":\"\xff\xfe\x80\"}")),
		declare(0, ""),
		declare(0xffffffff, "{}"),
		declare(maxDrain+1, "{}"),
		declare(maxDrain, "{}"),
		declare(maxInMsg+1, "{}"),
		// Oversized but whole: skipped, and the request behind it still read.
		append(nativeFrame(bytes.Repeat([]byte("a"), maxInMsg+1)), blocked...),
	} {
		f.Add(seed)
	}

	// With every handler slot taken, a well-formed request is turned away as
	// BUSY instead of being acted on: no input may start a real scan or cast.
	for range cap(handlerSlots) {
		handlerSlots <- struct{}{}
	}
	f.Cleanup(func() {
		for range cap(handlerSlots) {
			<-handlerSlots
		}
	})
	h := &host{emit: nativeEmitter(io.Discard), pins: &pinStore{path: filepath.Join(f.TempDir(), "pins.json")}}

	f.Fuzz(func(t *testing.T, stream []byte) {
		in := &meteredReader{r: bytes.NewReader(stream)}
		// serve answers requests on goroutines of their own; the bubble does not
		// end until they have, so none is left to find a slot free later.
		synctest.Test(t, func(*testing.T) { _ = h.serve(in) })
		if in.max > maxInMsg {
			t.Fatalf("buffered %d bytes for one message", in.max)
		}
	})
}

func FuzzDecodeMsg(f *testing.F) {
	for _, seed := range [][]byte{
		nil,
		encodeMsg(castMsg{src: "a", dst: "receiver-0", ns: nsMedia, payload: strings.Repeat(`{"x":1}`, 100)})[4:],
		encodeMsg(castMsg{src: "a", dst: "b", ns: nsAuth, binary: []byte{0, 1, 2}})[4:],
		{0x12, 0xff, 0xff, 0x03},
		{0x12, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01},
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		{0x09, 1, 2, 3, 0x0d, 1, 2},
		{0x0b},
		{0x32, 0x03, 0xff, 0xfe, 0x80},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = decodeMsg(b)
	})
}

// tvConn is the TV's end of a Cast connection as a script: reads replay the
// input, and whatever the helper says back is dropped.
type tvConn struct {
	net.Conn
	in meteredReader
}

func (c *tvConn) Read(p []byte) (int, error)       { return c.in.Read(p) }
func (c *tvConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *tvConn) Close() error                     { return nil }
func (c *tvConn) SetReadDeadline(time.Time) error  { return nil }
func (c *tvConn) SetWriteDeadline(time.Time) error { return nil }

func FuzzCastReadLoop(f *testing.F) {
	say := func(src, ns, payload string) []byte {
		return encodeMsg(castMsg{src: src, dst: senderID, ns: ns, payload: payload})
	}
	declare := func(n uint32, body string) []byte {
		return append(binary.BigEndian.AppendUint32(nil, n), body...)
	}
	for _, seed := range [][]byte{
		nil,
		{0, 0},
		say(receiverID, nsHeartbeat, `{"type":"PING"}`),
		append(say("t-1", nsMedia, `{"type":"MEDIA_STATUS","requestId":1,"status":[{"mediaSessionId":7,"playerState":"PLAYING"}]}`),
			say(receiverID, nsReceiver, "{\"type\":\"RECEIVER_STATUS\",\r\n\"requestId\":0}")...),
		append(say("t-1", nsConn, `{"type":"CLOSE"}`), say(receiverID, nsConn, `{"type":"CLOSE"}`)...),
		encodeMsg(castMsg{src: receiverID, dst: senderID, ns: nsAuth, binary: []byte{0x12, 0x00}}),
		say(receiverID, nsMedia, `{"type":"MEDIA_STATUS`),
		say(receiverID, nsMedia, "{\"type\":\"\xff\xfe\x80\"}"),
		declare(0, ""),
		declare(100, "abc"),
		declare(maxFrame+1, "abc"),
		declare(0xffffffff, "abc"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, stream []byte) {
		conn := &tvConn{in: meteredReader{r: bytes.NewReader(stream)}}
		c := &castConn{
			conn:      conn,
			onEvent:   func(string, json.RawMessage) {},
			authCh:    make(chan []byte, 1),
			pending:   map[int64]chan json.RawMessage{1: make(chan json.RawMessage, 1)},
			connected: map[string]bool{receiverID: true, "t-1": true},
			done:      make(chan struct{}),
		}
		c.authed.Store(true) // past the identity check, where the TV has the most say
		c.readLoop()
		if conn.in.max > maxFrame {
			t.Fatalf("buffered %d bytes for one frame", conn.in.max)
		}
	})
}

func FuzzVerifyAuthReply(f *testing.F) {
	nonce, peerDER := []byte("0123456789abcdef"), []byte("tls certificate")
	digest := sha256.Sum256(append(append([]byte{}, nonce...), peerDER...))
	sig, err := rsa.SignPKCS1v15(rand.Reader, testRootKey, crypto.SHA256, digest[:])
	if err != nil {
		f.Fatal(err)
	}
	// The shape of a genuine reply: signature, device certificate, one
	// intermediate, the echoed nonce, hash_algorithm = SHA256.
	resp := appendField(nil, 1, string(sig))
	resp = appendField(resp, 2, string(testRootCert.Raw))
	resp = appendField(resp, 3, string(testRootCert.Raw))
	resp = appendField(resp, 5, string(nonce))
	resp = append(resp, 0x30, 0x01)
	reply := appendField(nil, 2, string(resp))
	for _, seed := range [][]byte{
		nil,
		reply,
		reply[:len(reply)/2],
		appendField(nil, 2, string(appendField(appendField(nil, 1, "sig"), 2, "not a certificate"))),
		appendField(nil, 2, string(appendField(appendField(nil, 1, strings.Repeat("s", 1025)), 2, strings.Repeat("c", 8193)))),
		appendField(nil, 3, "\x08\x01"), // an AuthError instead of a response
		{0x12, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01},
		{0x12, 0x02, 0x0d, 0x01},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = verifyAuthReply(raw, nonce, peerDER, castRoots)
	})
}

// Command xcast-host is the native messaging helper for the XCast extension.
// It discovers Cast devices, drives them over the Cast v2 protocol, and runs a
// locked-down LAN proxy for streams the TV cannot fetch on its own.
//
// Standard library only: no third-party code runs next to your cookies.
package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"
	"time"
)

// Chrome never needs to send us more than a small JSON command.
const (
	maxInMsg = 64 << 10
	maxDrain = 4 << 20 // Chrome's own cap for extension-to-host messages
)

type request struct {
	ID        int64      `json:"id"`
	Type      string     `json:"type"`
	Device    *deviceRef `json:"device,omitempty"`
	Media     *mediaReq  `json:"media,omitempty"`
	Action    string     `json:"action,omitempty"`
	Value     float64    `json:"value,omitempty"`
	TrackIDs  []int64    `json:"trackIds,omitempty"`
	TimeoutMs int        `json:"timeoutMs,omitempty"`
}

type codedErr struct{ code, msg string }

func (e *codedErr) Error() string { return e.msg }

func bad(msg string) error { return &codedErr{"BAD_REQUEST", msg} }

// debugf logs only when XCAST_DEBUG is set: Chrome forwards a native host's
// stderr to its own log, and even a bare hostname says what you watch.
var debugOn = os.Getenv("XCAST_DEBUG") != ""

func debugf(format string, args ...any) {
	if debugOn {
		log.Printf(format, args...)
	}
}

// harden applies process-level limits before any untrusted input is read.
func harden() {
	// No core dumps: process memory can hold session cookies.
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})
	// Soft memory ceiling: a hostile stream must not balloon the helper.
	debug.SetMemoryLimit(384 << 20)
	// Crash output must never include argument values (URLs, cookies).
	debug.SetTraceback("none")
}

// allowedOrigin is baked in by the installer:
//
//	-ldflags "-X main.allowedOrigin=chrome-extension://<id>/"
//
// Chrome passes the calling extension's origin as argv[1] and already enforces
// allowed_origins from the host manifest; this is a second, independent gate
// should that (user-writable) manifest be edited to let another extension in.
var allowedOrigin string

func callerAllowed(args []string) bool {
	return allowedOrigin != "" && len(args) >= 2 &&
		subtle.ConstantTimeCompare([]byte(allowedOrigin), []byte(args[1])) == 1
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("xcast-host: ")
	harden()
	// Chrome passes the caller origin as argv[1]; only our debug flags are special.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-discover":
			cliDiscover()
			return
		case "-cast":
			cliCast(os.Args[2:])
			return
		case "-check":
			cliCheck(os.Args[2:])
			return
		case "-probe":
			cliProbe(os.Args[2:])
			return
		case "-selftest":
			cliSelfTest()
			return
		}
	}
	if !callerAllowed(os.Args) {
		log.Print("refusing to serve: caller is not the registered extension")
		os.Exit(2)
	}
	h := newHost(nativeEmitter(os.Stdout))
	err := h.serve(os.Stdin)
	h.shutdown()
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

// nativeEmitter frames messages for Chrome: native-endian uint32 length + JSON.
func nativeEmitter(w io.Writer) func(any) {
	var mu sync.Mutex
	return func(v any) {
		b, err := json.Marshal(v)
		if err != nil {
			return
		}
		frame := make([]byte, 4, 4+len(b))
		binary.NativeEndian.PutUint32(frame, uint32(len(b)))
		frame = append(frame, b...)
		mu.Lock()
		defer mu.Unlock()
		if _, err := w.Write(frame); err != nil {
			os.Exit(0) // Chrome went away.
		}
	}
}

func (h *host) serve(in io.Reader) error {
	var n [4]byte
	for {
		if _, err := io.ReadFull(in, n[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		size := binary.NativeEndian.Uint32(n[:])
		if size == 0 || size > maxDrain {
			return fmt.Errorf("rejected message of %d bytes", size)
		}
		if size > maxInMsg {
			// Oversized but plausible (a page with a huge URL): skip it and keep
			// serving, so one tab cannot take down a cast started from another.
			if _, err := io.CopyN(io.Discard, in, int64(size)); err != nil {
				return err
			}
			h.emit(map[string]any{"id": 0, "ok": false, "code": "BAD_REQUEST", "error": "request too large"})
			continue
		}
		buf := make([]byte, size)
		if _, err := io.ReadFull(in, buf); err != nil {
			return err
		}
		var req request
		dec := json.NewDecoder(bytes.NewReader(buf))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			h.emit(map[string]any{"id": 0, "ok": false, "code": "BAD_REQUEST", "error": "malformed request"})
			continue
		}
		go h.handle(req)
	}
}

func cliDiscover() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := discover(ctx, 2*time.Second, func(d Device) {
		fmt.Printf("%-28s %-24s %s:%d\n", d.Name, d.Model, d.Host, d.Port)
	})
	if err != nil {
		log.Fatal(err)
	}
}

// cliCheck runs only the identity check against a TV; nothing is played.
func cliCheck(args []string) {
	if len(args) < 1 {
		log.Fatal("usage: xcast-host -check <tv-ip>")
	}
	d := deviceRef{Host: args[0]}
	addr, _, err := d.validate()
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cc, err := dialCast(ctx, addr, func(fp string) error {
		fmt.Println("device key fingerprint:", fp)
		return nil
	}, nil, nil)
	if err != nil {
		log.Fatal(err)
	}
	cc.Close()
	fmt.Println("identity check passed")
}

// cliSelfTest is run by the installer inside the sandbox: everything the
// helper needs must work there, and what it must not reach must be blocked.
func cliSelfTest() {
	fail := func(what string, err error) { log.Fatalf("selftest: %s: %v", what, err) }
	pins := defaultPinStore()
	if err := pins.check("selftest", "00"); err != nil {
		fail("data directory not writable", err)
	}
	if err := pins.forget("selftest"); err != nil {
		fail("data directory not writable", err)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		fail("cannot listen", err)
	}
	ln.Close()
	// Exercise the system certificate verifier for real. Any verdict about the
	// certificate is fine; what must not happen is the verifier itself failing
	// to start, which is how a too-tight sandbox shows up (and would break
	// every HTTPS stream).
	block, _ := pem.Decode(mustRead("roots/cast_root_ca.pem"))
	probe, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fail("embedded certificate", err)
	}
	if _, err := probe.Verify(x509.VerifyOptions{}); err != nil {
		var ua x509.UnknownAuthorityError
		var ci x509.CertificateInvalidError
		if !errors.As(err, &ua) && !errors.As(err, &ci) {
			fail("system certificate verifier unavailable", err)
		}
	}
	if os.Getenv("XCAST_DATA") != "" { // sandboxed run: your files must be out of reach
		home, _ := os.UserHomeDir()
		if _, err := os.ReadDir(home); err == nil {
			log.Fatal("selftest: sandbox is not confining the helper")
		}
	}
	fmt.Println("ok")
}

func mustRead(name string) []byte {
	b, err := rootFS.ReadFile(name)
	if err != nil {
		log.Fatal(err)
	}
	return b
}

// cliProbe reports how a stream would be cast, without touching any TV.
func cliProbe(args []string) {
	if len(args) < 1 {
		log.Fatal("usage: xcast-host -probe <url>")
	}
	m := &mediaReq{URL: args[0]}
	u, err := m.validate()
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pol := newPolicy(ctx, u.Hostname(), false)
	if pol.local {
		log.Fatal("stream host is on the local network")
	}
	info, err := newUpstream(pol, u, m).inspect(ctx, u.String(), "", false, 0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("type=%s kind=%s live=%v fmp4=%v tv-can-fetch-directly=%v\n", info.contentType, info.kind, info.live, info.fmp4, info.corsOK)
}

func cliCast(args []string) {
	if len(args) < 2 {
		log.Fatal("usage: xcast-host -cast <tv-ip> <url> [auto|direct|proxy]")
	}
	mode := "auto"
	if len(args) > 2 {
		mode = args[2]
	}
	h := newHost(func(v any) {
		b, _ := json.Marshal(v)
		log.Printf("event %s", b)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	res, err := h.dispatch(ctx, request{
		Type:   "cast",
		Device: &deviceRef{Host: args[0]},
		Media:  &mediaReq{URL: args[1], Mode: mode},
	})
	cancel()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("casting mode=%v type=%v live=%v (Ctrl-C stops the proxy)", res["mode"], res["contentType"], res["live"])
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	h.shutdown()
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type deviceRef struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Host string `json:"host"`
	Port int    `json:"port,omitempty"`
}

// pinKey names the device in the identity pin store.
func (d *deviceRef) pinKey() string {
	if d.ID != "" {
		return d.ID
	}
	return "ip:" + d.Host
}

func (d *deviceRef) validate() (string, netip.Addr, error) {
	if len(d.ID) > 128 || len(d.Name) > 256 {
		return "", netip.Addr{}, bad("field too long")
	}
	ip, err := netip.ParseAddr(d.Host)
	if err != nil || !isLAN(ip) {
		return "", netip.Addr{}, bad("device must be a LAN IPv4 address")
	}
	port := d.Port
	if port == 0 {
		port = 8009
	}
	if port < 1 || port > 65535 {
		return "", netip.Addr{}, bad("invalid device port")
	}
	return netip.AddrPortFrom(ip, uint16(port)).String(), ip, nil
}

type host struct {
	emit func(any)
	pins *pinStore

	castMu sync.Mutex // one cast or reconnect at a time

	mu     sync.Mutex
	cc     *castConn
	ccKey  string // pin key of the device behind cc
	app    *receiverApp
	msid   int64
	prox   *proxy
	closed bool

	metrics     *castMetrics
	metricsOnce sync.Once
}

func newHost(emit func(any)) *host { return &host{emit: emit, pins: defaultPinStore()} }

const loadTimeout = 20 * time.Second

// Back-off between attempts to get a lost control connection back.
var rejoinWaits = []time.Duration{time.Second, 3 * time.Second, 8 * time.Second}

// handlerSlots bounds concurrent requests; the extension never needs more.
var handlerSlots = make(chan struct{}, 8)

func (h *host) handle(req request) {
	select {
	case handlerSlots <- struct{}{}:
		defer func() { <-handlerSlots }()
	default:
		h.emit(map[string]any{"id": req.ID, "ok": false, "code": "BUSY", "error": "too many requests at once"})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	res, err := h.dispatch(ctx, req)
	if err != nil {
		code := "ERROR"
		var ce *codedErr
		if errors.As(err, &ce) {
			code = ce.code
		}
		h.emit(map[string]any{"id": req.ID, "ok": false, "code": code, "error": err.Error()})
		return
	}
	if res == nil {
		res = map[string]any{}
	}
	res["id"], res["ok"] = req.ID, true
	h.emit(res)
}

// protoVersion goes up whenever the extension starts to rely on something a
// helper built before would not do. The two are installed separately (reload
// the extension, run install.sh), so one can be left behind.
const protoVersion = 1

func (h *host) dispatch(ctx context.Context, req request) (map[string]any, error) {
	switch req.Type {
	case "hello":
		return map[string]any{"proto": protoVersion}, nil
	case "discover":
		win := time.Duration(req.TimeoutMs) * time.Millisecond
		if win < 300*time.Millisecond || win > 5*time.Second {
			win = 1500 * time.Millisecond
		}
		devs, err := discover(ctx, win, func(d Device) {
			d.Known = h.pins.known(d.ID)
			h.emit(map[string]any{"type": "device", "device": d})
		})
		if err != nil {
			return nil, &codedErr{"DISCOVERY", "TV search failed: " + err.Error()}
		}
		for i := range devs {
			devs[i].Known = h.pins.known(devs[i].ID)
		}
		// TVs used before come first, so a flood of fake announcements cannot
		// push the real one off the list.
		sort.SliceStable(devs, func(i, j int) bool { return devs[i].Known && !devs[j].Known })
		if len(devs) > maxDevices {
			devs = devs[:maxDevices]
		}
		return map[string]any{"devices": devs}, nil
	case "warm":
		h.warm(ctx, req.Device)
		return nil, nil
	case "cast":
		return h.castMedia(ctx, req.Device, req.Media)
	case "control":
		if req.Action == "tracks" {
			return nil, h.setTracks(ctx, req.TrackIDs)
		}
		return nil, h.control(ctx, req.Action, req.Value)
	case "forget":
		// Only after the user confirmed they replaced or factory-reset the TV.
		if req.Device == nil {
			return nil, bad("device is required")
		}
		if _, _, err := req.Device.validate(); err != nil {
			return nil, err
		}
		if err := h.pins.forget(req.Device.pinKey()); err != nil {
			return nil, &codedErr{"DEVICE_AUTH", "cannot update stored TV identities: " + err.Error()}
		}
		return nil, nil
	}
	return nil, bad("unknown request type")
}

// warm opens the control connection to the TV picked in the popup, so that
// Cast does not have to wait for the TLS handshake and the device check. It is
// best effort and stays out of the way:
//   - only a TV that was cast to before: merely opening the popup must not pin
//     a new device's identity
//   - never while a cast or reconnect runs, and never while something plays:
//     the connection that exists (or is being won back) controls that stream.
//     An idle one, left from warming another TV, is replaced
//   - nothing is launched (that would wake the TV), and errors stay here: the
//     cast reports them if they persist
func (h *host) warm(ctx context.Context, d *deviceRef) {
	if d == nil {
		return
	}
	if addr, _, err := d.validate(); err == nil {
		h.warmAddr(ctx, addr, d.pinKey())
	}
}

func (h *host) warmAddr(ctx context.Context, addr, pinKey string) {
	if !h.pins.known(pinKey) || !h.castMu.TryLock() {
		return
	}
	defer h.castMu.Unlock()
	h.mu.Lock()
	skip := h.app != nil || (h.cc != nil && h.cc.addr == addr && h.cc.alive())
	h.mu.Unlock()
	if skip {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, _ = h.connect(ctx, addr, pinKey)
}

// castMedia overlaps the slow parts: starting the receiver app on the TV
// (seconds) runs in parallel with probing the stream and preparing the proxy.
func (h *host) castMedia(ctx context.Context, d *deviceRef, m *mediaReq) (map[string]any, error) {
	if d == nil || m == nil {
		return nil, bad("device and media are required")
	}
	addr, devIP, err := d.validate()
	if err != nil {
		return nil, err
	}
	var u *url.URL
	if m.file == "" {
		if u, err = m.validate(); err != nil {
			return nil, err
		}
	}

	h.castMu.Lock()
	defer h.castMu.Unlock()
	castStarted := time.Now()
	h.mu.Lock()
	before := h.cc
	h.mu.Unlock()

	var (
		wg               sync.WaitGroup
		cc               *castConn
		app              *receiverApp
		up               *upstream
		plan             *mediaPlan
		castErr, planErr error
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		if cc, castErr = h.connect(ctx, addr, d.pinKey()); castErr == nil {
			app, castErr = cc.launch(ctx, defaultReceiver)
		}
	}()
	go func() {
		defer wg.Done()
		if m.file != "" {
			plan, planErr = h.planFile(devIP, m.file)
			return
		}
		pol := newPolicy(ctx, u.Hostname(), m.AllowLocal)
		if pol.local && !m.AllowLocal {
			planErr = &codedErr{"LOCAL_STREAM", "this video is served from your local network"}
			return
		}
		up = newUpstream(pol, u, m) // one connection pool per cast, shared by probes, fallback and proxy
		plan, planErr = h.plan(ctx, devIP, up, u, m, m.Mode == "proxy" || (m.Cookie != "" && m.Mode != "direct"))
	}()
	wg.Wait()
	discard := func() {
		if plan != nil && plan.sess != nil {
			h.proxyDo(func(p *proxy) { p.drop(plan.sess) })
		} else if up != nil {
			up.client.CloseIdleConnections()
		}
		// If this attempt replaced the connection to the TV that was playing,
		// nobody controls that stream any more: its relay session must not
		// stay valid (with its cookies) for hours.
		h.mu.Lock()
		switched := before != nil && h.cc != before
		if switched {
			h.app = nil
		}
		h.mu.Unlock()
		if switched {
			h.proxyDo(func(p *proxy) { p.keepOnly(nil) })
		}
	}
	if planErr != nil {
		discard()
		return nil, planErr
	}
	if castErr != nil {
		discard()
		return nil, castErr
	}

	at := m.CurrentTime
	if plan.live {
		at = 0
	}
	// Attached before the TV is told to load, i.e. before the relay session
	// sees its first request: nothing is missed and nothing races.
	cm := newCastMetrics("")
	cm.started = castStarted // "started in" counts from the click
	load := func() (int64, error) {
		cm.mode = plan.mode
		if plan.sess != nil {
			plan.sess.m = cm
		}
		lctx, cancel := context.WithTimeout(ctx, loadTimeout)
		defer cancel()
		return cc.load(lctx, app, plan.loadMedia(m.Title), at)
	}
	msid, err := load()
	if err != nil && plan.mode == "direct" && m.Mode != "direct" && ctx.Err() == nil {
		// The TV could not fetch it itself (hotlink or CORS check on segments): retry via proxy.
		if plan, err = h.plan(ctx, devIP, up, u, m, true); err == nil {
			msid, err = load()
		}
	}
	if err != nil {
		discard() // whatever was playing before keeps its own session
		return nil, err
	}
	// Only now that the new stream plays is the previous session retired.
	h.proxyDo(func(p *proxy) { p.keepOnly(plan.sess) })
	if plan.sess == nil {
		up.client.CloseIdleConnections()
	}
	h.mu.Lock()
	h.app, h.msid, h.metrics = app, msid, cm
	h.mu.Unlock()
	h.metricsOnce.Do(func() { go h.publishMetrics() })
	return map[string]any{"mode": plan.mode, "contentType": plan.contentType, "live": plan.live}, nil
}

// publishMetrics sends the popup one snapshot a second while something plays.
func (h *host) publishMetrics() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for range t.C {
		h.mu.Lock()
		m, playing, closed := h.metrics, h.app != nil, h.closed
		h.mu.Unlock()
		if closed {
			return
		}
		if m != nil && playing {
			h.emit(m.snapshot())
		}
	}
}

func (h *host) proxyDo(fn func(*proxy)) {
	h.mu.Lock()
	p := h.prox
	h.mu.Unlock()
	if p != nil {
		fn(p)
	}
}

// plan decides between letting the TV fetch the stream itself and relaying it.
// The credential-less probe (what the TV would see) and the browser-like probe
// run concurrently so needing the proxy costs no extra round trips.
func (h *host) plan(ctx context.Context, devIP netip.Addr, up *upstream, u *url.URL, m *mediaReq, forceProxy bool) (*mediaPlan, error) {
	raw := u.String()
	type probe struct {
		info *mediaInfo
		err  error
	}
	asBrowser := make(chan probe, 1)
	if m.Mode != "direct" {
		go func() {
			info, err := up.inspect(ctx, raw, m.ContentType, true, 0)
			asBrowser <- probe{info, err}
		}()
	}
	if !forceProxy {
		info, err := up.inspect(ctx, raw, m.ContentType, false, 0)
		if err == nil && info.corsOK {
			return &mediaPlan{mode: "direct", contentID: raw, mediaInfo: *info}, nil
		}
		if m.Mode == "direct" {
			if info == nil {
				info = &mediaInfo{contentType: guessType(u, m.ContentType)}
				if info.contentType == "" {
					info.contentType = "video/mp4"
				}
			}
			return &mediaPlan{mode: "direct", contentID: raw, mediaInfo: *info}, nil
		}
	}
	r := <-asBrowser
	if r.err != nil {
		return nil, r.err
	}
	p, err := h.ensureProxy(devIP)
	if err != nil {
		return nil, err
	}
	s, err := p.newSession(up, devIP)
	if err != nil {
		return nil, err
	}
	s.private = m.Mode == "proxy"
	if r.info.kind == "dash" {
		// Said here, where the popup can show it. The rewriter refuses the same
		// thing later, for a manifest reached through a redirect.
		if _, ok := p.dirURL(s, u); !ok {
			p.drop(s)
			return nil, &codedErr{"UPSTREAM", u.Hostname() + " serves this DASH stream from its top directory. Relaying that with your cookies would open the whole site to the TV's network, so XCast does not."}
		}
	}
	return &mediaPlan{mode: "proxy", contentID: p.entryURL(s, u), mediaInfo: *r.info, sess: s}, nil
}

// planFile prepares a video file from this computer: always through the
// relay, which is the only way the TV can reach it. Nothing is transcoded, so
// only containers a Cast receiver plays are accepted.
func (h *host) planFile(devIP netip.Addr, file string) (*mediaPlan, error) {
	ct, err := localFileType(file)
	if err != nil {
		return nil, err
	}
	p, err := h.ensureProxy(devIP)
	if err != nil {
		return nil, err
	}
	s, err := p.newSession(nil, devIP)
	if err != nil {
		return nil, err
	}
	s.file, s.fileType = file, ct
	return &mediaPlan{mode: "proxy", contentID: p.localURL(s), mediaInfo: mediaInfo{kind: "file", contentType: ct}, sess: s}, nil
}

// localFileType says what the TV will be told a local file is, going by its
// name, or why it cannot be cast.
func localFileType(file string) (string, error) {
	ct := guessType(&url.URL{Path: file}, "")
	if ct == "" || kindOf(ct) != "file" {
		return "", &codedErr{"UNSUPPORTED", "the TV plays .mp4, .m4v, .mov, .webm, .mp3, .m4a and .aac files. Others have to be converted first, for example: ffmpeg -i in.mkv -c copy out.mp4"}
	}
	if st, err := os.Stat(file); err != nil || !st.Mode().IsRegular() {
		return "", &codedErr{"BAD_REQUEST", "cannot read " + file}
	}
	return ct, nil
}

func (h *host) ensureProxy(dev netip.Addr) (*proxy, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.prox != nil {
		if local, err := localAddrFor(dev); err == nil && local == h.prox.local {
			return h.prox, nil
		}
		h.prox.Close()
		h.prox = nil
	}
	p, err := startProxy(dev)
	if err != nil {
		return nil, &codedErr{"PROXY", "cannot start local proxy: " + err.Error()}
	}
	h.prox = p
	return p, nil
}

// connect must be called with castMu held.
func (h *host) connect(ctx context.Context, addr, pinKey string) (*castConn, error) {
	h.mu.Lock()
	cur := h.cc
	if cur != nil && cur.addr == addr && h.ccKey == pinKey && cur.alive() {
		h.mu.Unlock()
		return cur, nil
	}
	h.cc, h.app = nil, nil // detach first: a deliberate close must not trigger a reconnect
	h.mu.Unlock()
	if cur != nil {
		cur.Close()
	}
	cc, err := h.dial(ctx, addr, pinKey)
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	h.cc, h.ccKey = cc, pinKey
	h.mu.Unlock()
	return cc, nil
}

func (h *host) dial(ctx context.Context, addr, pinKey string) (*castConn, error) {
	verify := func(fp string) error { return h.pins.check(pinKey, fp) }
	cc, err := dialCast(ctx, addr, verify, h.onCastEvent, h.onCastClosed)
	if err != nil {
		var ce *codedErr
		if errors.As(err, &ce) {
			return nil, err
		}
		return nil, &codedErr{"DEVICE", "cannot reach TV: " + err.Error()}
	}
	return cc, nil
}

// onCastClosed runs when the control connection dies on its own (Wi-Fi blip,
// TV reboot). The TV may well still be playing from our proxy, so try to get
// the control channel back before giving up and revoking everything.
func (h *host) onCastClosed(c *castConn) {
	h.mu.Lock()
	if h.cc != c || h.closed {
		h.mu.Unlock()
		return
	}
	key, playing := h.ccKey, h.app != nil
	h.cc = nil
	h.mu.Unlock()
	if !playing {
		return // an idle (warmed) connection: nothing was controlled, nothing to report
	}
	for _, wait := range rejoinWaits {
		time.Sleep(wait)
		if done, ok := h.rejoin(c.addr, key); done {
			if ok {
				return
			}
			break
		}
	}
	h.mu.Lock()
	superseded := h.cc != nil || h.closed
	if !superseded {
		h.app = nil
	}
	h.mu.Unlock()
	if superseded {
		return
	}
	h.proxyDo(func(p *proxy) { p.keepOnly(nil) })
	h.emit(map[string]any{"type": "disconnected", "reason": "lost connection to the TV"})
}

// rejoin reports done when retrying is pointless, ok when control is back.
func (h *host) rejoin(addr, key string) (done, ok bool) {
	h.castMu.Lock()
	defer h.castMu.Unlock()
	h.mu.Lock()
	superseded := h.cc != nil || h.closed
	h.mu.Unlock()
	if superseded {
		return true, true // a newer cast owns the state now
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cc, err := h.dial(ctx, addr, key)
	if err != nil {
		var ce *codedErr
		return errors.As(err, &ce) && ce.code == "DEVICE_IDENTITY", false
	}
	app, err := cc.join(ctx, defaultReceiver)
	if err != nil {
		cc.ready.Store(false)
		cc.Close()
		var ce *codedErr
		return errors.As(err, &ce) && ce.code == "NO_SESSION", false
	}
	h.mu.Lock()
	h.cc, h.ccKey, h.app = cc, key, app
	h.mu.Unlock()
	_, _ = cc.mediaCmd(ctx, app, map[string]any{"type": "GET_STATUS"}) // refreshes msid via onCastEvent
	return true, true
}

func (h *host) onCastEvent(typ string, raw json.RawMessage) {
	switch typ {
	case "MEDIA_STATUS":
		var st struct {
			Status []struct {
				MediaSessionID int64    `json:"mediaSessionId"`
				PlayerState    string   `json:"playerState"`
				IdleReason     string   `json:"idleReason"`
				CurrentTime    float64  `json:"currentTime"`
				ActiveTrackIDs *[]int64 `json:"activeTrackIds"`
				Media          *struct {
					Duration float64 `json:"duration"`
					Tracks   []struct {
						ID       int64  `json:"trackId"`
						Type     string `json:"type"`
						Name     string `json:"name"`
						Language string `json:"language"`
					} `json:"tracks"`
				} `json:"media"`
			} `json:"status"`
		}
		if json.Unmarshal(raw, &st) != nil || len(st.Status) == 0 {
			return
		}
		s := st.Status[0]
		h.mu.Lock()
		if s.MediaSessionID != 0 {
			h.msid = s.MediaSessionID
		}
		m := h.metrics
		h.mu.Unlock()
		m.noteState(s.PlayerState)
		ev := map[string]any{"type": "media", "state": s.PlayerState, "currentTime": s.CurrentTime, "idleReason": s.IdleReason}
		if s.Media != nil {
			ev["duration"] = s.Media.Duration
			// Subtitle and audio tracks the TV found in the stream. Their names
			// come from the site's manifest: bounded here, shown as text only.
			tracks := []map[string]any{}
			for _, t := range s.Media.Tracks {
				if (t.Type == "TEXT" || t.Type == "AUDIO") && len(tracks) < maxTracks {
					tracks = append(tracks, map[string]any{"id": t.ID, "type": t.Type, "name": clip(t.Name, 64), "language": clip(t.Language, 16)})
				}
			}
			ev["tracks"] = tracks
		}
		if s.ActiveTrackIDs != nil {
			ev["activeTrackIds"] = *s.ActiveTrackIDs
		}
		h.emit(ev)
	case "RECEIVER_STATUS":
		var st struct {
			Status struct {
				Volume struct {
					Level float64 `json:"level"`
					Muted bool    `json:"muted"`
				} `json:"volume"`
			} `json:"status"`
		}
		if json.Unmarshal(raw, &st) == nil {
			h.emit(map[string]any{"type": "volume", "level": st.Status.Volume.Level, "muted": st.Status.Volume.Muted})
		}
	}
}

const maxTracks = 64

// clip bounds a string from the TV to n characters.
func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// setTracks switches subtitle and audio tracks: ids lists every track that
// should be on (none: subtitles off, the default audio stays).
func (h *host) setTracks(ctx context.Context, ids []int64) error {
	h.mu.Lock()
	cc, app, msid := h.cc, h.app, h.msid
	h.mu.Unlock()
	if cc == nil || app == nil || !cc.alive() {
		return &codedErr{"NO_SESSION", "nothing is casting"}
	}
	if len(ids) > 8 {
		return bad("too many tracks")
	}
	if ids == nil {
		ids = []int64{} // the TV wants a list, not null
	}
	_, err := cc.mediaCmd(ctx, app, map[string]any{"type": "EDIT_TRACKS_INFO", "mediaSessionId": msid, "activeTrackIds": ids})
	return err
}

func (h *host) control(ctx context.Context, action string, v float64) error {
	h.mu.Lock()
	cc, app, msid := h.cc, h.app, h.msid
	h.mu.Unlock()
	if cc == nil || app == nil || !cc.alive() {
		return &codedErr{"NO_SESSION", "nothing is casting"}
	}
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return bad("invalid value")
	}
	if action == "seek" || action == "seekBy" {
		h.mu.Lock()
		m := h.metrics
		h.mu.Unlock()
		m.noteSeek()
	}
	var err error
	switch action {
	case "play", "pause":
		_, err = cc.mediaCmd(ctx, app, map[string]any{"type": strings.ToUpper(action), "mediaSessionId": msid})
	case "seek":
		_, err = cc.mediaCmd(ctx, app, map[string]any{"type": "SEEK", "mediaSessionId": msid, "currentTime": math.Max(v, 0)})
	case "seekBy":
		var raw json.RawMessage
		if raw, err = cc.mediaCmd(ctx, app, map[string]any{"type": "GET_STATUS"}); err == nil {
			var st struct {
				Status []struct {
					CurrentTime float64 `json:"currentTime"`
				} `json:"status"`
			}
			if json.Unmarshal(raw, &st) != nil || len(st.Status) == 0 {
				return &codedErr{"DEVICE", "no playback position"}
			}
			_, err = cc.mediaCmd(ctx, app, map[string]any{"type": "SEEK", "mediaSessionId": msid, "currentTime": math.Max(st.Status[0].CurrentTime+v, 0)})
		}
	case "volume":
		_, err = cc.request(ctx, nsReceiver, receiverID, map[string]any{"type": "SET_VOLUME", "volume": map[string]any{"level": math.Min(math.Max(v, 0), 1)}})
	case "stop":
		_, _ = cc.request(ctx, nsReceiver, receiverID, map[string]any{"type": "STOP", "sessionId": app.sessionID})
		h.mu.Lock()
		h.app = nil
		h.mu.Unlock()
		h.proxyDo(func(p *proxy) { p.keepOnly(nil) }) // revoke the proxy immediately
	default:
		return bad("unknown action")
	}
	return err
}

func (h *host) shutdown() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	if h.cc != nil {
		h.cc.Close()
	}
	if h.prox != nil {
		h.prox.Close()
	}
}

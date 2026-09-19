package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	nsAuth          = "urn:x-cast:com.google.cast.tp.deviceauth"
	nsConn          = "urn:x-cast:com.google.cast.tp.connection"
	nsHeartbeat     = "urn:x-cast:com.google.cast.tp.heartbeat"
	nsReceiver      = "urn:x-cast:com.google.cast.receiver"
	nsMedia         = "urn:x-cast:com.google.cast.media"
	defaultReceiver = "CC1AD845" // Google's Default Media Receiver
	senderID        = "sender-xcast"
	receiverID      = "receiver-0"
	maxFrame        = 64 << 10 // Cast protocol message limit
)

type castMsg struct {
	src, dst, ns, payload string
	binary                []byte // set instead of payload for binary messages
}

// encodeMsg hand-encodes the CastMessage protobuf (string or binary payload)
// with its 4-byte big-endian length prefix. Six fields do not justify a
// protobuf dependency.
func encodeMsg(m castMsg) []byte {
	b := make([]byte, 4, 32+len(m.src)+len(m.dst)+len(m.ns)+len(m.payload))
	b = append(b, 0x08, 0x00) // protocol_version = CASTV2_1_0
	b = appendField(b, 2, m.src)
	b = appendField(b, 3, m.dst)
	b = appendField(b, 4, m.ns)
	if m.binary != nil {
		b = append(b, 0x28, 0x01) // payload_type = BINARY
		b = appendField(b, 7, string(m.binary))
	} else {
		b = append(b, 0x28, 0x00) // payload_type = STRING
		b = appendField(b, 6, m.payload)
	}
	binary.BigEndian.PutUint32(b, uint32(len(b)-4))
	return b
}

func appendField(b []byte, field byte, s string) []byte {
	b = append(b, field<<3|2)
	b = binary.AppendUvarint(b, uint64(len(s)))
	return append(b, s...)
}

func decodeMsg(b []byte) (castMsg, error) {
	var m castMsg
	errBad := errors.New("malformed cast message")
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return m, errBad
		}
		b = b[n:]
		switch key & 7 {
		case 0:
			if _, n = binary.Uvarint(b); n <= 0 {
				return m, errBad
			}
			b = b[n:]
		case 1:
			if len(b) < 8 {
				return m, errBad
			}
			b = b[8:]
		case 5:
			if len(b) < 4 {
				return m, errBad
			}
			b = b[4:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || l > uint64(len(b)-n) {
				return m, errBad
			}
			v := string(b[n : n+int(l)])
			b = b[n+int(l):]
			switch key >> 3 {
			case 2:
				m.src = v
			case 3:
				m.dst = v
			case 4:
				m.ns = v
			case 6:
				m.payload = v
			case 7:
				m.binary = []byte(v)
			}
		default:
			return m, errBad
		}
	}
	return m, nil
}

type receiverApp struct{ transportID, sessionID string }

type castConn struct {
	addr    string
	conn    net.Conn
	onEvent func(typ string, payload json.RawMessage)
	onClose func(*castConn)
	peerDER []byte
	authCh  chan []byte

	wmu    sync.Mutex
	nextID atomic.Int64

	mu        sync.Mutex
	pending   map[int64]chan json.RawMessage
	connected map[string]bool

	done      chan struct{}
	closeOnce sync.Once
	ready     atomic.Bool // onClose fires only for connections that were handed out
	authed    atomic.Bool // until set, only identity-check replies are read
}

// dialCast connects, proves the device's identity (see auth.go) and only then
// opens the virtual connection. verify receives the device key fingerprint.
func dialCast(ctx context.Context, addr string, verify func(fingerprint string) error, onEvent func(string, json.RawMessage), onClose func(*castConn)) (*castConn, error) {
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 15 * time.Second},
		// Cast devices present a self-signed TLS certificate that rotates every
		// two days, so chain verification is impossible here. Identity is proven
		// right after the handshake instead: the device signs this very
		// certificate with its long-lived device key, which we pin.
		Config: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		conn.Close()
		return nil, errors.New("TV sent no certificate")
	}
	c := &castConn{
		addr:      addr,
		conn:      conn,
		onEvent:   onEvent,
		onClose:   onClose,
		peerDER:   certs[0].Raw,
		authCh:    make(chan []byte, 1),
		pending:   map[int64]chan json.RawMessage{},
		connected: map[string]bool{receiverID: true},
		done:      make(chan struct{}),
	}
	go c.readLoop()
	if verify != nil {
		if err := c.authenticate(ctx, verify); err != nil {
			c.Close() // onClose stays silent: ready was never set
			return nil, err
		}
	}
	c.authed.Store(true)
	if err := c.send(nsConn, receiverID, map[string]any{"type": "CONNECT"}); err != nil {
		c.Close()
		return nil, err
	}
	c.ready.Store(true)
	go c.heartbeat()
	return c, nil
}

func (c *castConn) alive() bool {
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}

func (c *castConn) Close() {
	c.closeOnce.Do(func() {
		close(c.done)
		c.conn.Close()
		if c.onClose != nil && c.ready.Load() {
			go c.onClose(c)
		}
	})
}

func (c *castConn) send(ns, dst string, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.write(castMsg{src: senderID, dst: dst, ns: ns, payload: string(payload)})
}

func (c *castConn) write(m castMsg) error {
	frame := encodeMsg(m)
	var err error
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = c.conn.Write(frame)
	return err
}

func (c *castConn) request(ctx context.Context, ns, dst string, v map[string]any) (json.RawMessage, error) {
	id := c.nextID.Add(1)
	v["requestId"] = id
	ch := make(chan json.RawMessage, 1)
	c.mu.Lock()
	c.pending[id] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}()
	if err := c.send(ns, dst, v); err != nil {
		return nil, &codedErr{"DEVICE", "cannot talk to TV"}
	}
	select {
	case raw := <-ch:
		return raw, nil
	case <-ctx.Done():
		return nil, &codedErr{"DEVICE", "TV did not answer in time"}
	case <-c.done:
		return nil, &codedErr{"DEVICE", "connection to TV closed"}
	}
}

func (c *castConn) readLoop() {
	defer c.Close()
	var hdr [4]byte
	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(20 * time.Second))
		if _, err := io.ReadFull(c.conn, hdr[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n > maxFrame {
			return
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(c.conn, buf); err != nil {
			return
		}
		if m, err := decodeMsg(buf); err == nil {
			c.dispatch(m)
		}
	}
}

func (c *castConn) dispatch(m castMsg) {
	if m.ns == nsAuth {
		select {
		case c.authCh <- m.binary:
		default:
		}
		return
	}
	if !c.authed.Load() {
		return // an unproven peer gets no say over playback state or the UI
	}
	var head struct {
		Type      string `json:"type"`
		RequestID int64  `json:"requestId"`
	}
	if json.Unmarshal([]byte(m.payload), &head) != nil {
		return
	}
	switch m.ns {
	case nsHeartbeat:
		if head.Type == "PING" {
			_ = c.send(nsHeartbeat, m.src, map[string]any{"type": "PONG"})
		}
		return
	case nsConn:
		if head.Type == "CLOSE" {
			if m.src == receiverID {
				c.Close()
				return
			}
			c.mu.Lock()
			delete(c.connected, m.src)
			c.mu.Unlock()
		}
		return
	}
	raw := json.RawMessage(m.payload)
	if head.RequestID != 0 {
		c.mu.Lock()
		ch := c.pending[head.RequestID]
		c.mu.Unlock()
		if ch != nil {
			select {
			case ch <- raw:
			default:
			}
		}
	}
	if c.onEvent != nil && (head.Type == "MEDIA_STATUS" || head.Type == "RECEIVER_STATUS") {
		c.onEvent(head.Type, raw)
	}
}

func (c *castConn) heartbeat() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			if c.send(nsHeartbeat, receiverID, map[string]any{"type": "PING"}) != nil {
				c.Close()
				return
			}
		}
	}
}

func (c *castConn) connectTo(dst string) error {
	c.mu.Lock()
	already := c.connected[dst]
	c.connected[dst] = true
	c.mu.Unlock()
	if already {
		return nil
	}
	return c.send(nsConn, dst, map[string]any{"type": "CONNECT"})
}

// launch starts (or reuses, if already running) the receiver app.
func (c *castConn) launch(ctx context.Context, appID string) (*receiverApp, error) {
	return c.appFrom(ctx, map[string]any{"type": "LAUNCH", "appId": appID}, appID)
}

func (c *castConn) appFrom(ctx context.Context, req map[string]any, appID string) (*receiverApp, error) {
	raw, err := c.request(ctx, nsReceiver, receiverID, req)
	if err != nil {
		return nil, err
	}
	var st struct {
		Type   string `json:"type"`
		Reason string `json:"reason"`
		Status struct {
			Applications []struct {
				AppID       string `json:"appId"`
				TransportID string `json:"transportId"`
				SessionID   string `json:"sessionId"`
			} `json:"applications"`
		} `json:"status"`
	}
	if json.Unmarshal(raw, &st) != nil {
		return nil, &codedErr{"DEVICE", "bad reply from TV"}
	}
	for _, a := range st.Status.Applications {
		if a.AppID == appID && a.TransportID != "" {
			app := &receiverApp{transportID: a.TransportID, sessionID: a.SessionID}
			return app, c.connectTo(app.transportID)
		}
	}
	if req["type"] != "LAUNCH" {
		return nil, &codedErr{"NO_SESSION", "player is no longer running on the TV"}
	}
	return nil, &codedErr{"DEVICE", strings.TrimSpace("TV refused to start the player: " + st.Type + " " + st.Reason)}
}

// join attaches to the receiver app if it is still running; it never launches.
func (c *castConn) join(ctx context.Context, appID string) (*receiverApp, error) {
	return c.appFrom(ctx, map[string]any{"type": "GET_STATUS"}, appID)
}

func (c *castConn) load(ctx context.Context, app *receiverApp, media map[string]any, at float64) (int64, error) {
	req := map[string]any{"type": "LOAD", "sessionId": app.sessionID, "media": media, "autoplay": true}
	if at > 0 {
		req["currentTime"] = at
	}
	raw, err := c.request(ctx, nsMedia, app.transportID, req)
	if err != nil {
		return 0, err
	}
	var st struct {
		Type   string `json:"type"`
		Status []struct {
			MediaSessionID int64 `json:"mediaSessionId"`
		} `json:"status"`
	}
	if json.Unmarshal(raw, &st) != nil || st.Type != "MEDIA_STATUS" || len(st.Status) == 0 {
		return 0, &codedErr{"LOAD_FAILED", "TV could not play this stream"}
	}
	return st.Status[0].MediaSessionID, nil
}

func (c *castConn) mediaCmd(ctx context.Context, app *receiverApp, v map[string]any) (json.RawMessage, error) {
	raw, err := c.request(ctx, nsMedia, app.transportID, v)
	if err != nil {
		return nil, err
	}
	var head struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &head) != nil || head.Type != "MEDIA_STATUS" {
		return nil, &codedErr{"DEVICE", fmt.Sprintf("TV rejected %v", v["type"])}
	}
	return raw, nil
}

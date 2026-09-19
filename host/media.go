package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
)

const (
	ctHLS       = "application/x-mpegURL"
	ctDASH      = "application/dash+xml"
	maxManifest = 8 << 20
	defaultUA   = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
	// Origin the Default Media Receiver fetches from; used to predict CORS.
	receiverOrigin = "https://www.gstatic.com"
)

var allowedTypes = map[string]bool{
	ctHLS: true, ctDASH: true, "video/mp4": true, "video/webm": true, "audio/mp4": true, "audio/mpeg": true,
}

type mediaReq struct {
	URL         string  `json:"url"`
	ContentType string  `json:"contentType,omitempty"`
	Referer     string  `json:"referer,omitempty"`
	Cookie      string  `json:"cookie,omitempty"`
	UserAgent   string  `json:"userAgent,omitempty"`
	CurrentTime float64 `json:"currentTime,omitempty"`
	Title       string  `json:"title,omitempty"`
	Mode        string  `json:"mode,omitempty"`
	AllowLocal  bool    `json:"allowLocal,omitempty"`
}

func (m *mediaReq) validate() (*url.URL, error) {
	if len(m.URL) > 8192 || len(m.Referer) > 8192 || len(m.Cookie) > 8192 || len(m.UserAgent) > 512 || len(m.Title) > 512 {
		return nil, bad("field too long")
	}
	if strings.ContainsAny(m.Cookie+m.UserAgent+m.Referer, "\r\n\x00") {
		return nil, bad("invalid header value")
	}
	u, err := url.Parse(m.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || strings.Contains(u.Host, "%") {
		return nil, bad("stream must be a plain http(s) URL")
	}
	if r, err := url.Parse(m.Referer); m.Referer != "" && (err != nil || (r.Scheme != "http" && r.Scheme != "https")) {
		m.Referer = "" // about:srcdoc frames etc.; just don't send one
	}
	if m.ContentType != "" && !allowedTypes[m.ContentType] {
		return nil, bad("unsupported content type")
	}
	switch m.Mode {
	case "", "auto", "direct", "proxy":
	default:
		return nil, bad("mode must be auto, direct or proxy")
	}
	if math.IsNaN(m.CurrentTime) || m.CurrentTime < 0 || m.CurrentTime > 1e7 {
		m.CurrentTime = 0
	}
	return u, nil
}

func guessType(u *url.URL, ct string) string {
	if ct != "" {
		return ct
	}
	switch strings.ToLower(path.Ext(u.Path)) {
	case ".m3u8":
		return ctHLS
	case ".mpd":
		return ctDASH
	case ".mp4", ".m4v", ".mov":
		return "video/mp4"
	case ".webm":
		return "video/webm"
	case ".mp3":
		return "audio/mpeg"
	case ".m4a", ".aac":
		return "audio/mp4"
	}
	return ""
}

func kindOf(ct string) string {
	switch ct {
	case ctHLS:
		return "hls"
	case ctDASH:
		return "dash"
	}
	return "file"
}

func typeFromHeader(h string) string {
	mt, _, _ := mime.ParseMediaType(h)
	switch {
	case strings.Contains(mt, "mpegurl"):
		return ctHLS
	case strings.Contains(mt, "dash+xml"):
		return ctDASH
	case allowedTypes[mt]:
		return mt
	}
	return "video/mp4"
}

// upstream fetches from the origin the way the user's browser would.
type upstream struct {
	client     *http.Client
	referer    string
	origin     string
	ua         string
	cookie     string
	cookieHost string
}

func newUpstream(pol *policy, u *url.URL, m *mediaReq) *upstream {
	up := &upstream{client: pol.client(), referer: m.Referer, ua: m.UserAgent, cookie: m.Cookie, cookieHost: strings.ToLower(u.Hostname())}
	if up.ua == "" {
		up.ua = defaultUA
	}
	if r, err := url.Parse(m.Referer); err == nil && r.Host != "" {
		up.origin = r.Scheme + "://" + r.Host
	}
	return up
}

// get never returns an error containing the full URL: signed URLs are secrets.
func (up *upstream) get(ctx context.Context, method, raw string, hdr http.Header, creds bool) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, raw, nil)
	if err != nil {
		return nil, &codedErr{"UPSTREAM", "invalid upstream URL"}
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	req.Header.Set("User-Agent", up.ua)
	if creds {
		// Same rule as the browser's default (strict-origin-when-cross-origin):
		// other hosts learn which site you are on, never which page.
		switch {
		case up.origin == "":
		case up.origin == req.URL.Scheme+"://"+req.URL.Host:
			req.Header.Set("Referer", up.referer)
		case !(strings.HasPrefix(up.origin, "https:") && req.URL.Scheme == "http"):
			req.Header.Set("Referer", up.origin+"/")
		}
		if up.origin != "" && up.origin != req.URL.Scheme+"://"+req.URL.Host {
			req.Header.Set("Origin", up.origin)
		}
		// Cookies only go to the exact host they were read for, and only over
		// TLS; CheckRedirect drops them on any redirect that leaves that host.
		if up.cookie != "" && req.URL.Scheme == "https" && strings.EqualFold(req.URL.Hostname(), up.cookieHost) {
			req.Header.Set("Cookie", up.cookie)
		}
	}
	resp, err := up.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, &codedErr{"UPSTREAM", fmt.Sprintf("cannot fetch from %s: %v", req.URL.Hostname(), err)}
	}
	return resp, nil
}

func statusErr(resp *http.Response) error {
	host := resp.Request.URL.Hostname()
	switch c := resp.StatusCode; {
	case c < 400:
		return nil
	case c == 401 || c == 403:
		return &codedErr{"UPSTREAM_AUTH", fmt.Sprintf("%s refused access (%d)", host, c)}
	case c == 404 || c == 410:
		return &codedErr{"UPSTREAM", fmt.Sprintf("%s: stream not found, link may have expired (%d)", host, c)}
	default:
		return &codedErr{"UPSTREAM", fmt.Sprintf("%s answered %d", host, c)}
	}
}

type mediaInfo struct {
	kind, contentType string
	live, fmp4        bool
	corsOK            bool // a receiver could fetch this without our proxy
}

// inspect fetches only what it needs (manifest text, or a 1-byte range for
// files) to learn the real type, HLS segment format, liveness and whether
// the TV could fetch it directly. creds=false mimics the receiver.
func (up *upstream) inspect(ctx context.Context, raw, ct string, creds bool, depth int) (*mediaInfo, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, &codedErr{"UPSTREAM", "invalid upstream URL"}
	}
	info := &mediaInfo{contentType: guessType(u, ct)}
	hdr := http.Header{}
	if !creds {
		hdr.Set("Origin", receiverOrigin)
	}
	if info.contentType != "" && kindOf(info.contentType) == "file" {
		hdr.Set("Range", "bytes=0-0")
	}
	resp, err := up.get(ctx, http.MethodGet, raw, hdr, creds)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := statusErr(resp); err != nil {
		return nil, err
	}
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	info.corsOK = acao == "*" || acao == receiverOrigin

	br := bufio.NewReaderSize(io.LimitReader(resp.Body, maxManifest+1), 4096)
	head, _ := br.Peek(512)
	switch {
	case bytes.HasPrefix(bytes.TrimLeft(head, "\ufeff \t\r\n"), []byte("#EXTM3U")):
		info.contentType = ctHLS
	case bytes.Contains(head, []byte("<MPD")):
		info.contentType = ctDASH
	case info.contentType == "" || kindOf(info.contentType) != "file":
		info.contentType = typeFromHeader(resp.Header.Get("Content-Type"))
	}
	info.kind = kindOf(info.contentType)

	switch info.kind {
	case "file":
		info.corsOK = true // progressive media needs no CORS on the receiver
	case "hls":
		body, err := io.ReadAll(br)
		if err != nil || len(body) > maxManifest {
			return nil, &codedErr{"UPSTREAM", "playlist unreadable or too large"}
		}
		variant, fmp4, live := scanHLS(body, resp.Request.URL)
		info.fmp4, info.live = fmp4, live
		if variant != nil && depth == 0 {
			vi, err := up.inspect(ctx, variant.String(), ctHLS, creds, 1)
			switch {
			case err != nil && creds:
				return nil, err
			case err != nil:
				info.corsOK = false
			default:
				info.fmp4, info.live = vi.fmp4, vi.live
				info.corsOK = info.corsOK && vi.corsOK
			}
		}
	}
	return info, nil
}

// scanHLS returns the first variant of a master playlist, or the segment
// format and liveness of a media playlist.
func scanHLS(body []byte, base *url.URL) (variant *url.URL, fmp4, live bool) {
	master, ended, wantVariant := false, false, false
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "#EXT-X-STREAM-INF"):
			master, wantVariant = true, true
		case strings.HasPrefix(line, "#EXT-X-MAP"):
			fmp4 = true
		case strings.HasPrefix(line, "#EXT-X-ENDLIST"):
			ended = true
		case line != "" && !strings.HasPrefix(line, "#"):
			if wantVariant && variant == nil {
				variant = resolveHTTP(base, line)
			}
			wantVariant = false
		}
	}
	return variant, fmp4, !master && !ended
}

func resolveHTTP(base *url.URL, ref string) *url.URL {
	r, err := url.Parse(ref)
	if err != nil {
		return nil
	}
	u := base.ResolveReference(r)
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil
	}
	u.Fragment = ""
	return u
}

type mediaPlan struct {
	mode, contentID string
	mediaInfo
	sess *session // nil in direct mode
}

func (p *mediaPlan) loadMedia(title string) map[string]any {
	media := map[string]any{
		"contentId":   p.contentID,
		"contentUrl":  p.contentID,
		"contentType": p.contentType,
		"streamType":  "BUFFERED",
		"metadata":    map[string]any{"metadataType": 0, "title": title},
	}
	if p.live {
		media["streamType"] = "LIVE"
	}
	if p.fmp4 {
		media["hlsSegmentFormat"] = "fmp4"
		media["hlsVideoSegmentFormat"] = "fmp4"
	}
	return media
}

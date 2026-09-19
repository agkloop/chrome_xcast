package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

// Ranges that are not globally routable but that netip's helpers don't cover.
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), // 6to4 relay anycast
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
	// IPv6 ranges that embed an IPv4 address and could smuggle a private one.
	netip.MustParsePrefix("64:ff9b::/96"),   // NAT64
	netip.MustParsePrefix("64:ff9b:1::/48"), // local-use NAT64
	netip.MustParsePrefix("2002::/16"),      // 6to4
	netip.MustParsePrefix("2001::/32"),      // Teredo
}

var globalUnicastV6 = netip.MustParsePrefix("2000::/3")

func isPublic(ip netip.Addr) bool {
	// A zone ("%en0") makes every Prefix.Contains below answer false, which
	// would wave a blocked range through. No public address needs a zone.
	if ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	// IPv6: only allocated global unicast space, minus the ranges below.
	// That also rules out ::/96, fec0::/10 and the NAT64 prefixes.
	if ip.Is6() && !globalUnicastV6.Contains(ip) {
		return false
	}
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// isLAN reports whether ip can be a Cast device on the local network.
func isLAN(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.Is4() && (ip.IsPrivate() || ip.IsLinkLocalUnicast())
}

// policy decides which IPs the upstream client may connect to. Public
// addresses are always fine. An RFC 1918 / ULA address is allowed only when
// the user's chosen stream itself lives there (e.g. a NAS) and the user
// confirmed that. Loopback, link-local and metadata addresses are never
// allowed, so neither a hostile page nor a playlist can steer the helper at
// services on this machine or at your router.
type policy struct {
	allowed map[netip.Addr]bool // at most one entry
	local   bool                // the stream host resolves to a private address
}

func newPolicy(ctx context.Context, host string, allowLocal bool) *policy {
	p := &policy{allowed: map[netip.Addr]bool{}}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ips, _ := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	for _, ip := range ips {
		if ip = ip.Unmap(); ip.Zone() == "" && ip.IsPrivate() {
			p.local = true
			// Exactly one: a name answering with twenty LAN addresses gets one.
			if allowLocal && len(p.allowed) == 0 {
				p.allowed[ip] = true
			}
		}
	}
	return p
}

func (p *policy) permit(ip netip.Addr) bool {
	if ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	return isPublic(ip) || p.allowed[ip]
}

// client returns an HTTP client whose every connection (including redirects
// and DNS-rebinding attempts) is checked against the policy at dial time.
func (p *policy) client() *http.Client {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return err
			}
			if !p.permit(ap.Addr()) {
				return fmt.Errorf("blocked non-public address %s", ap.Addr())
			}
			return nil
		},
	}
	tr := &http.Transport{
		Proxy:                 nil, // dial checks must see the real destination
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		DisableCompression:    true, // pass bytes through untouched
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			prev, first := via[len(via)-1].URL, via[0].URL
			switch {
			case req.URL.Scheme != "http" && req.URL.Scheme != "https":
				return errors.New("redirect to unsupported scheme")
			case prev.Scheme == "https" && req.URL.Scheme != "https":
				return errors.New("refused https to http downgrade")
			}
			// net/http keeps Cookie on redirects to subdomains; we promise exact host.
			if req.URL.Scheme != "https" || !strings.EqualFold(req.URL.Host, first.Host) {
				req.Header.Del("Cookie")
			}
			return nil
		},
	}
}

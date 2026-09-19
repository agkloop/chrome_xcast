package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	castService = "_googlecast._tcp.local"
	maxDevices  = 32 // per scan; a LAN host must not be able to flood the list
)

// cleanLabel makes a LAN-supplied string safe to show: no control or
// bidirectional-override characters (used to disguise names), bounded length.
func cleanLabel(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r < 0x20, r == 0x7f, r >= 0x80 && r < 0xa0:
			return -1
		case r == 0x061c, r >= 0x200b && r <= 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0xfeff, r == 0xfffd:
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	if r := []rune(s); len(r) > max {
		s = string(r[:max])
	}
	return strings.TrimSpace(s)
}

type Device struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Model string `json:"model"`
	Host  string `json:"host"`
	Port  int    `json:"port"`
	Known bool   `json:"known"` // its identity is already pinned, i.e. cast to before
}

// discover queries every LAN interface (a VPN's default route must not hide
// the TV). Per interface it sends from an ephemeral port, which responders
// answer by unicast (RFC 6762 §6.7), and it also listens on the mDNS group for
// devices that only ever answer by multicast. found is called per new device.
func discover(ctx context.Context, window time.Duration, found func(Device)) ([]Device, error) {
	ctx, cancel := context.WithTimeout(ctx, window)
	defer cancel()

	type packet struct {
		data []byte
		src  netip.Addr
	}
	packets := make(chan packet, 64)
	var wg sync.WaitGroup
	listen := func(conn *net.UDPConn) {
		wg.Add(1)
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		go func() {
			defer wg.Done()
			defer stop()
			defer conn.Close()
			buf := make([]byte, 9000)
			for {
				n, from, err := conn.ReadFromUDPAddrPort(buf)
				if err != nil {
					return
				}
				select {
				case packets <- packet{append([]byte(nil), buf[:n]...), from.Addr().Unmap()}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	group := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	query := buildQuery(castService)
	sent := 0
	var lastErr error
	for _, ifi := range lanInterfaces() {
		if mc, err := net.ListenMulticastUDP("udp4", &ifi.Interface, group); err == nil {
			listen(mc)
		}
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ifi.addr.AsSlice()})
		if err != nil {
			lastErr = err
			continue
		}
		if err := setMulticastInterface(conn, ifi.addr); err != nil {
			lastErr = err
			conn.Close()
			continue
		}
		listen(conn)
		_, err = conn.WriteToUDP(query, group)
		if err != nil {
			lastErr = err
		}
		if err == nil {
			sent++
			resend := time.AfterFunc(250*time.Millisecond, func() { _, _ = conn.WriteToUDP(query, group) })
			defer resend.Stop()
		}
	}
	if sent == 0 {
		cancel()
		wg.Wait()
		switch {
		case lastErr == nil:
			return nil, errors.New("this computer is not on a local network")
		case errors.Is(lastErr, syscall.EHOSTUNREACH), errors.Is(lastErr, syscall.EPERM), errors.Is(lastErr, syscall.EACCES):
			// How macOS reports its Local Network privacy block. Chrome hands
			// responsibility for a native host to the host itself, so the
			// permission belongs to this binary, identified by its signature:
			// every rebuild is a new program to macOS and must be allowed again.
			return nil, errors.New(`macOS is blocking local network access for XCast's helper. Allow "xcast-host" in System Settings > Privacy & Security > Local Network, then try again. Reinstalling the helper resets this permission`)
		}
		return nil, lastErr
	}
	go func() { wg.Wait(); close(packets) }()

	out := []Device{}
	seen := map[string]bool{}
	for p := range packets {
		if !isLAN(p.src) {
			continue
		}
		for _, d := range parseCastRecords(p.data, p.src) {
			if seen[d.ID] || len(out) >= 8*maxDevices {
				continue
			}
			seen[d.ID] = true
			out = append(out, d)
			found(d)
		}
	}
	return out, nil
}

type lanInterface struct {
	net.Interface
	addr netip.Addr
}

func lanInterfaces() []lanInterface {
	var out []lanInterface
	ifs, _ := net.Interfaces()
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 || ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagPointToPoint != 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok && isLAN(ip.Unmap()) {
					out = append(out, lanInterface{ifi, ip.Unmap()})
					break
				}
			}
		}
	}
	return out
}

// setMulticastInterface pins outgoing multicast to the interface owning addr;
// binding the socket alone does not do that on BSD/macOS.
func setMulticastInterface(conn *net.UDPConn, addr netip.Addr) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := raw.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInet4Addr(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, addr.As4())
	}); err != nil {
		return err
	}
	return serr
}

func buildQuery(name string) []byte {
	b := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	// QTYPE=PTR, QCLASS=IN with the unicast-response bit.
	return append(b, 0, 0, 12, 0x80, 1)
}

// parseCastRecords trusts only the packet's source address for the device's
// location: A records are ignored, so one LAN host cannot point a "TV" entry
// at another machine.
func parseCastRecords(msg []byte, src netip.Addr) []Device {
	if len(msg) < 12 || msg[2]&0x80 == 0 {
		return nil
	}
	be := func(o int) int { return int(binary.BigEndian.Uint16(msg[o:])) }
	qd, total := be(4), be(6)+be(8)+be(10)

	type inst struct {
		txt  map[string]string
		port int
	}
	insts := map[string]*inst{}
	get := func(name string) *inst {
		name = strings.ToLower(name)
		if insts[name] == nil {
			insts[name] = &inst{txt: map[string]string{}}
		}
		return insts[name]
	}
	off := 12
	for i := 0; i < qd; i++ {
		_, o, err := readName(msg, off)
		if err != nil || o+4 > len(msg) {
			return nil
		}
		off = o + 4
	}
	for i := 0; i < total; i++ {
		name, o, err := readName(msg, off)
		if err != nil || o+10 > len(msg) {
			break
		}
		typ, rdlen := be(o), be(o+8)
		rd, end := o+10, o+10+rdlen
		if end > len(msg) {
			break
		}
		switch typ {
		case 12: // PTR
			if target, _, err := readName(msg, rd); err == nil && isCastInstance(target) {
				get(target)
			}
		case 33: // SRV
			if rdlen >= 7 {
				get(name).port = be(rd + 4)
			}
		case 16: // TXT
			in := get(name)
			for p := rd; p < end; {
				l := int(msg[p])
				if p+1+l > end {
					break
				}
				if k, v, ok := strings.Cut(string(msg[p+1:p+1+l]), "="); ok {
					in.txt[strings.ToLower(k)] = v
				}
				p += 1 + l
			}
		}
		off = end
	}

	var out []Device
	for name, in := range insts {
		if !isCastInstance(name) {
			continue
		}
		d := Device{ID: cleanLabel(in.txt["id"], 64), Name: cleanLabel(in.txt["fn"], 64), Model: cleanLabel(in.txt["md"], 64), Host: src.String(), Port: in.port}
		if d.ID == "" {
			d.ID = cleanLabel(name, 64)
		}
		if d.Name == "" {
			first, _, _ := strings.Cut(name, ".")
			d.Name = cleanLabel(first, 64)
		}
		if d.ID == "" || d.Name == "" {
			continue
		}
		if d.Port == 0 {
			d.Port = 8009
		}
		// Cast listens on 8009; speaker groups use high ports. Anything else
		// would aim our TLS hello at some other service on the LAN.
		if d.Port != 8009 && d.Port < 1024 {
			continue
		}
		out = append(out, d)
	}
	return out
}

func isCastInstance(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), "."+castService)
}

// readName decodes a DNS name with compression, returning the offset just
// past the name at its original position.
func readName(msg []byte, off int) (string, int, error) {
	errBad := errors.New("bad dns name")
	var labels []string
	ret, jumped, hops := 0, false, 0
	for {
		if off >= len(msg) {
			return "", 0, errBad
		}
		l := int(msg[off])
		switch {
		case l == 0:
			if !jumped {
				ret = off + 1
			}
			return strings.Join(labels, "."), ret, nil
		case l&0xC0 == 0xC0:
			if off+1 >= len(msg) || hops > 16 {
				return "", 0, errBad
			}
			if !jumped {
				ret = off + 2
			}
			jumped = true
			hops++
			off = int(binary.BigEndian.Uint16(msg[off:]) & 0x3FFF)
		case l&0xC0 != 0:
			return "", 0, errBad
		default:
			if off+1+l > len(msg) || len(labels) > 64 {
				return "", 0, errBad
			}
			labels = append(labels, string(msg[off+1:off+1+l]))
			off += 1 + l
		}
	}
}

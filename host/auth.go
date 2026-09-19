package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Cast device authentication. The TLS certificate a Cast device presents is
// self-signed and rotates every two days, so it proves nothing by itself.
// After the handshake we send a nonce; the device answers with its long-lived
// device certificate and a signature, made with that certificate's key, over
// nonce || TLS certificate. Verifying it proves the TLS session ends at the
// holder of the device key (no man in the middle). The key's fingerprint is
// then pinned per device on first use, so a different box cannot later pose
// as your TV, even on the same IP and with the same name.
//
// Before any of that counts, the device certificate must chain up to one of
// Google's Cast root CAs (chain.go), which is what protects the very first
// connection: a rogue box on the LAN has no such certificate for its own key.

var errAuth = &codedErr{"DEVICE_AUTH", "TV failed the identity check; refusing to cast"}

func (c *castConn) authenticate(ctx context.Context, verify func(string) error) error {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	// DeviceAuthMessage{challenge{signature_algorithm=RSASSA_PKCS1v15, sender_nonce, hash_algorithm=SHA256}}
	ch := []byte{0x08, 0x01}
	ch = appendField(ch, 2, string(nonce))
	ch = append(ch, 0x18, 0x01)
	msg := appendField(nil, 1, string(ch))
	if err := c.write(castMsg{src: senderID, dst: receiverID, ns: nsAuth, binary: msg}); err != nil {
		return &codedErr{"DEVICE", "cannot talk to TV"}
	}
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	select {
	case raw := <-c.authCh:
		fp, err := verifyAuthReply(raw, nonce, c.peerDER, castRoots)
		if err != nil {
			return errAuth
		}
		return verify(fp)
	case <-timeout.C:
		return &codedErr{"DEVICE_AUTH", "TV did not answer the identity check"}
	case <-ctx.Done():
		return &codedErr{"DEVICE", "TV did not answer in time"}
	case <-c.done:
		return &codedErr{"DEVICE", "connection to TV closed"}
	}
}

// pbFields splits one protobuf message into its length-delimited and varint fields.
func pbFields(b []byte) (bytesF map[uint64][]byte, ints map[uint64]uint64, err error) {
	bytesF, ints = map[uint64][]byte{}, map[uint64]uint64{}
	bad := errors.New("malformed auth message")
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, nil, bad
		}
		b = b[n:]
		switch key & 7 {
		case 0:
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return nil, nil, bad
			}
			ints[key>>3], b = v, b[n:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || l > uint64(len(b)-n) {
				return nil, nil, bad
			}
			if _, dup := bytesF[key>>3]; !dup { // keep the first of repeated fields
				bytesF[key>>3] = b[n : n+int(l)]
			}
			b = b[n+int(l):]
		default:
			return nil, nil, bad
		}
	}
	return bytesF, ints, nil
}

// pbRepeated returns every occurrence of one length-delimited field.
func pbRepeated(b []byte, field uint64) (out [][]byte) {
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return nil
		}
		b = b[n:]
		switch key & 7 {
		case 0:
			if _, n = binary.Uvarint(b); n <= 0 {
				return nil
			}
			b = b[n:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || l > uint64(len(b)-n) {
				return nil
			}
			if key>>3 == field {
				out = append(out, b[n:n+int(l)])
			}
			b = b[n+int(l):]
		default:
			return nil
		}
	}
	return out
}

// verifyAuthReply checks the device's signature and returns the SHA-256
// fingerprint of the device public key.
func verifyAuthReply(raw, nonce, peerDER []byte, roots *x509.CertPool) (string, error) {
	outer, _, err := pbFields(raw)
	if err != nil || outer[2] == nil {
		return "", errors.New("no auth response")
	}
	f, ints, err := pbFields(outer[2]) // AuthResponse
	if err != nil {
		return "", err
	}
	sig, certDER := f[1], f[2]
	if len(sig) == 0 || len(certDER) == 0 {
		return "", errors.New("incomplete auth response")
	}
	if echoed, ok := f[5]; ok && !bytes.Equal(echoed, nonce) {
		return "", errors.New("nonce mismatch")
	}
	if len(sig) > 1024 || len(certDER) > 8192 {
		return "", errors.New("oversized auth response")
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", err
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() < 2048 {
		return "", errors.New("unsupported device key")
	}
	if err := verifyDeviceChain(cert, pbRepeated(outer[2], 3), roots); err != nil {
		return "", err
	}
	// We ask for SHA-256 and accept nothing weaker: the peer does not get to
	// pick the hash.
	if ints[6] != 1 {
		return "", errors.New("device did not sign with SHA-256")
	}
	signed := append(append([]byte{}, nonce...), peerDER...)
	d := sha256.Sum256(signed)
	if ints[4] == 2 {
		err = rsa.VerifyPSS(pub, crypto.SHA256, d[:], sig, nil)
	} else {
		err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, d[:], sig)
	}
	if err != nil {
		return "", err
	}
	fp := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(fp[:]), nil
}

// pinStore remembers each device's key fingerprint (trust on first use).
type pinStore struct {
	mu   sync.Mutex
	path string
}

// dataDir is the only place the helper ever writes (and, when sandboxed, the
// only place it can).
func dataDir() string {
	if d := os.Getenv("XCAST_DATA"); filepath.IsAbs(d) {
		return d
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "XCast", "data")
}

func defaultPinStore() *pinStore {
	dir := dataDir()
	if dir == "" {
		return &pinStore{}
	}
	return &pinStore{path: filepath.Join(dir, "pins.json")}
}

// load fails closed: a pin file that exists but cannot be read or parsed must
// never be treated as "no TVs pinned yet", or every TV would be re-trusted.
func (s *pinStore) load() (map[string]string, error) {
	pins := map[string]string{}
	b, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return pins, nil
	case err != nil:
		return nil, err
	case len(b) > 1<<20:
		return nil, errors.New("pin file too large")
	}
	if err := json.Unmarshal(b, &pins); err != nil {
		return nil, err
	}
	return pins, nil
}

func (s *pinStore) save(pins map[string]string) error {
	if s.path == "" {
		return errors.New("no config directory")
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(pins, "", "  ")
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// check pins fp for key on first use and refuses any later change.
func (s *pinStore) check(key, fp string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	pins, err := s.load()
	if err != nil {
		return &codedErr{"DEVICE_AUTH", "stored TV identities are unreadable; refusing to cast: " + err.Error()}
	}
	switch known, ok := pins[key]; {
	case !ok:
		pins[key] = fp
		if err := s.save(pins); err != nil {
			return &codedErr{"DEVICE_AUTH", "cannot store TV identity: " + err.Error()}
		}
		return nil
	case known == fp:
		return nil
	}
	return &codedErr{"DEVICE_IDENTITY", "this is not the TV you used before under this name; refusing to cast"}
}

func (s *pinStore) known(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	pins, err := s.load()
	_, ok := pins[key]
	return err == nil && ok
}

func (s *pinStore) forget(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	pins, err := s.load()
	if err != nil {
		return err
	}
	delete(pins, key)
	return s.save(pins)
}

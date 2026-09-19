package main

import (
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"time"
)

// Google's two Cast trust anchors, taken from the Chromium/Open Screen source
// (cast/common/certificate/*_root_ca*_der-inc.h). Every genuine Cast device,
// including third-party Android TV boxes, carries a device certificate that
// chains up to one of them. Their SHA-256 fingerprints are checked at start-up
// so a tampered source tree cannot quietly swap the anchors.
//
//go:embed roots/*.pem
var rootFS embed.FS

var rootFingerprints = map[string]string{
	"roots/cast_root_ca.pem":   "809af14700b3fe2611ad597eb1584d6354313b64ccdb3390f097fa3e5826d6ca",
	"roots/eureka_root_ca.pem": "caf6d1e37b532203e01a76bf07187bb731ccd38801565ab2211a2c0ab7f3bc46",
}

var castRoots = mustLoadRoots()

func mustLoadRoots() *x509.CertPool {
	pool := x509.NewCertPool()
	for name, want := range rootFingerprints {
		pemBytes, err := rootFS.ReadFile(name)
		if err != nil {
			panic("missing trust anchor " + name)
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			panic("unreadable trust anchor " + name)
		}
		if got := sha256.Sum256(block.Bytes); hex.EncodeToString(got[:]) != want {
			panic("trust anchor fingerprint mismatch: " + name)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic("unparsable trust anchor " + name)
		}
		pool.AddCert(cert)
	}
	return pool
}

// verifyDeviceChain proves the device certificate was issued under Google's
// Cast PKI. This is what protects the very first connection to a TV: a rogue
// box on the LAN cannot produce such a certificate for a key it holds.
//
// Not checked: Google's Cast CRL (revocation of individual leaked device keys).
func verifyDeviceChain(leaf *x509.Certificate, intermediates [][]byte, roots *x509.CertPool) error {
	if len(intermediates) > 4 {
		return errors.New("too many intermediates")
	}
	pool := x509.NewCertPool()
	for _, der := range intermediates {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		pool.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: pool,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err
}

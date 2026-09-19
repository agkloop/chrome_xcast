# Cast trust anchors

`cast_root_ca.pem` and `eureka_root_ca.pem` are Google's two Cast root CA
certificates, converted to PEM from the Open Screen / Chromium source:

- `cast/common/certificate/cast_root_ca_cert_der-inc.h`
- `cast/common/certificate/eureka_root_ca_der-inc.h`

Source: https://chromium.googlesource.com/openscreen/ (BSD-style license,
Copyright The Chromium Authors).

Their SHA-256 fingerprints are hard-coded in `../chain.go` and checked at
start-up, so a swapped file stops the helper instead of being trusted.

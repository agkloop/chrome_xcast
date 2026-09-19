#!/usr/bin/env python3
"""XCast test lab: a local stand-in for a typical embedded-player site.

Serves, on this computer's LAN address only:
  /                 index
  /embed.html       a page embedding a cross-origin HTTPS player in an iframe
  /protected.html   a blob:-source player whose stream is hotlink-protected
  /hls/...          the stream: 403 unless the Referer is this site
  /mp4.html         a plain <video src> pointing at a signed, expiring MP4 URL
  /v2/...           the MP4: needs a valid token, an unexpired time and this
                    site's Referer; supports Range requests (seeking)

The video is a synthetic test pattern generated with ffmpeg. Every request is
printed with who asked and which Referer they sent, so you can see whether the
TV fetched the stream itself or XCast relayed it.
"""
import hashlib
import hmac
import http.server
import os
import re
import secrets
import socket
import sys
import time
import urllib.parse

PORT = 8787
ROOT = os.path.dirname(os.path.abspath(__file__))


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # routing lookup only, sends nothing
        return s.getsockname()[0]
    finally:
        s.close()


HOST = sys.argv[1] if len(sys.argv) > 1 else lan_ip()
ORIGIN = f"http://{HOST}:{PORT}"


SECRET = secrets.token_bytes(32)  # new on every start: old links die with the server
TTL = 4 * 3600


def sign(path, expires):
    mac = hmac.new(SECRET, f"{path}|{expires}".encode(), hashlib.sha256).digest()[:16]
    return __import__("base64").urlsafe_b64encode(mac).decode().rstrip("=")


def signed_url(path):
    e = int(time.time()) + TTL
    # protocol-relative, like many video hosts write it
    return f"//{HOST}:{PORT}{path}?s={sign(path, e)}&e={e}&_t={int(time.time())}"


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=ROOT, **kw)

    def log_message(self, fmt, *args):
        pass

    def note(self, verdict):
        who = "this computer" if self.client_address[0] == HOST else self.client_address[0]
        ref = self.headers.get("Referer") or "-"
        rng = self.headers.get("Range") or ""
        print(f"{verdict:<4} {self.path:<24} from {who:<15} referer={ref} {rng}", flush=True)

    def serve_page_with_token(self):
        body = open(os.path.join(ROOT, "mp4.html"), encoding="utf-8").read()
        body = body.replace("{{VIDEO_URL}}", signed_url("/v2/7k9labvideo.mp4")).encode()
        self.note("200")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def serve_signed_file(self, head=False):
        url = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(url.query)
        token, expires = q.get("s", [""])[0], q.get("e", ["0"])[0]
        why = None
        if not expires.isdigit() or not hmac.compare_digest(token, sign(url.path, int(expires))):
            why = "bad token"
        elif int(expires) < time.time():
            why = "link expired"
        elif not (self.headers.get("Referer") or "").startswith(ORIGIN + "/"):
            why = "hotlinking not allowed"
        full = os.path.normpath(os.path.join(ROOT, url.path.lstrip("/")))
        if why is None and not (full.startswith(os.path.join(ROOT, "v2") + os.sep) and os.path.isfile(full)):
            why = "not found"
        if why:
            self.note("403")
            self.send_error(404 if why == "not found" else 403, why)
            return
        size = os.path.getsize(full)
        start, end = 0, size - 1
        m = re.fullmatch(r"bytes=(\d*)-(\d*)", self.headers.get("Range") or "")
        if m and (m.group(1) or m.group(2)):
            if m.group(1):
                start = int(m.group(1))
                end = min(int(m.group(2)), size - 1) if m.group(2) else size - 1
            else:
                start = max(size - int(m.group(2)), 0)
            if start > end or start >= size:
                self.send_response(416)
                self.send_header("Content-Range", f"bytes */{size}")
                self.end_headers()
                return
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            self.note("206")
        else:
            self.send_response(200)
            self.note("200")
        self.send_header("Content-Type", "video/mp4")
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Content-Length", str(end - start + 1))
        self.end_headers()
        if head:
            return
        with open(full, "rb") as f:
            f.seek(start)
            left = end - start + 1
            try:
                while left > 0:
                    chunk = f.read(min(256 * 1024, left))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    left -= len(chunk)
            except (BrokenPipeError, ConnectionResetError):
                pass  # players drop connections when they seek

    def do_HEAD(self):
        if self.path.startswith("/v2/"):
            return self.serve_signed_file(head=True)
        super().do_HEAD()

    def do_GET(self):
        if self.path.split("?")[0] == "/mp4.html":
            return self.serve_page_with_token()
        if self.path.startswith("/v2/"):
            return self.serve_signed_file()
        if self.path.startswith("/hls/"):
            # Hotlink protection, as many video hosts do it: the stream is only
            # served to requests that come from this site's own pages. No CORS
            # headers either, so a TV cannot use it directly.
            if not (self.headers.get("Referer") or "").startswith(ORIGIN + "/"):
                self.note("403")
                self.send_error(403, "hotlinking not allowed")
                return
        self.note("200")
        super().do_GET()

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


if __name__ == "__main__":
    srv = http.server.ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"XCast test lab: {ORIGIN}/   (Ctrl-C to stop)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass

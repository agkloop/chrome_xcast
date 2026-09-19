# Open security issues

These came out of an independent review of the Go helper (`host/`). They are **not fixed**. Each entry says where the problem is, what it allows, what a fix has to achieve, and how to tell the fix worked. Line numbers drift, so entries name functions instead.

Until issue 1 is closed:

- do not allow XCast to use your cookies for DASH (`.mpd`) streams;
- use XCast only on a network you trust.

| # | Severity | Summary |
|---|---|---|
| 1 | High | The relay trusts the TV's IP address alone, and DASH directory grants carry your cookies to any path on the host |
| 2 | Medium | DASH relay URLs show the manifest's file name and signed query string |
| 3 | Medium | Referer and Origin leak across redirects |
| 4 | Low | Absolute URLs inside DASH manifests bypass Private relay |
| 5 | Low | A playlist can trigger cookie-bearing requests to any path on the cookie host |

---

## 1. Relay trusts the TV's IP alone; directory grants carry cookies anywhere on the host

**Severity:** High. **Needs:** an attacker on your LAN, a relayed DASH stream, and cookies granted for the stream's host.

**Where:** `host/proxy.go`: `gateListener.Accept`, `ServeHTTP`, `session.resolve` (the `p` grant kind), `forward`. `host/media.go`: the cookie rule in `upstream.get`.

**Problem.** Two things combine.

1. The proxy decides who may talk to it by source IP. The relay URL it hands the TV is not secret on the LAN: it travels as plain HTTP, and any Cast controller on the network can ask a TV what it is playing and get that URL back. A device that takes over the TV's IP address (ARP spoofing) therefore passes the gate and holds a valid URL.
2. A directory grant (`p`, used for DASH) covers every path and query below the granted directory. When the manifest sits near the root of the host, that is nearly the whole site. `forward` attaches your cookies to each such request and returns the response body.

**Impact.** The attacker can read pages on the cookie host with your login, not just the video.

**What a fix must achieve.**

- Cookies are attached only to requests that are clearly media. Decide this from the request path (a media file extension) and confirm it from the response content type. A request with no media extension gets no cookies.
- The relay never returns document-type responses (HTML, JSON, JavaScript, generic XML), whether or not cookies are involved. Manifests are recognised before this check and are exempt.
- A directory grant is limited to the manifest's own directory. If that directory is the host root and cookies are set, refuse to relay and say why.

This does not stop an attacker who takes over the TV's IP from pulling the *video* through the relay. That is inherent to a plain-HTTP link and is a documented limit. The fix removes the step from "can watch the same video" to "can read your account".

**Done when** a test shows that a directory-grant request for a non-media path on the cookie host reaches upstream without a `Cookie` header, and that an HTML or JSON upstream response comes back from the relay as an error, not as content.

**Side effect to document.** HLS key or licence endpoints that have no media file extension and require cookies will stop working. That trade is intended.

---

## 2. DASH relay URLs show the manifest's file name and query string

**Severity:** Medium. **Needs:** someone who can see LAN traffic, or any Cast controller on the network.

**Where:** `host/proxy.go`: `dirURL`, `entryURL`, `rewriteMPD`.

**Problem.** For DASH, the entry URL given to the TV is a directory grant. `dirURL` seals only the directory part and appends the manifest's file name and query string in clear text after the token. Signed streams keep their access token in that query string. HLS and MP4 are not affected: they use single-file tokens that seal the whole URL.

**Impact.** The README's promise that the site, the video URL and its access token are unreadable on the LAN does not hold for DASH.

**What a fix must achieve.**

- The DASH entry URL is a single-file token like every other entry URL, so nothing of the original URL is readable.
- Relative references inside the manifest must still resolve. That means the rewritten manifest has to carry a proxied base location for them, because they can no longer resolve against the entry URL itself.
- `dirURL` returns a base ending in `/` with nothing readable after the token.

**Done when** a test casts a DASH URL that has a recognisable file name and a query string, and neither appears anywhere in the URL the TV receives or in the rewritten manifest. Relative segment references in that manifest must still load through the relay.

---

## 3. Referer and Origin leak across redirects

**Severity:** Medium (privacy).

**Where:** `host/netsec.go`: `CheckRedirect` in `policy.client`. `host/media.go`: the Referer rule in `upstream.get`.

**Problem.** The Referer rule (full URL to the page's own origin, bare origin to everyone else) is applied only to the first request. Go's HTTP client then behaves differently from a browser on redirects:

- an explicit Referer is carried along unchanged, so a same-origin stream URL that redirects to a third-party CDN hands that CDN the full page URL;
- when no Referer was sent, the client invents one from the previous URL, which can be a signed stream URL;
- the `Origin` header is carried along too.

**What a fix must achieve.** On every redirect, recompute both headers for the new destination with the same rule as the first request: nothing if none was intended, the full value only to the host it was meant for, the bare origin to any other host.

**Done when** a test follows a redirect from the page's own host to a second host and the second host sees only the bare origin. A second test sends no Referer at all, follows a redirect, and the destination sees no Referer header.

---

## 4. Absolute URLs inside DASH manifests bypass Private relay

**Severity:** Low (privacy). **Needs:** Private relay switched on and a DASH stream.

**Where:** `host/proxy.go`: `rewriteMPD`.

**Problem.** Only `<BaseURL>` elements are rewritten. A DASH manifest can also carry absolute URLs in segment template attributes (`media`, `initialization`, `index`, `sourceURL`), in `<Location>` elements, and in `xlink:href`. The TV fetches those straight from the site.

**Impact.** With Private relay on, the site still sees the TV's user agent and your network's real address for those requests, and they do not go through a VPN on the computer.

**What a fix must achieve.** Every absolute http(s) URL in a relayed manifest either goes through the relay or is removed. Template URLs contain placeholders (`$Number$` and similar), so they need a directory grant on the part of the path before the first placeholder, not a single-file token. `<Location>` can simply be dropped: the player then reloads the manifest from the URL it already has, which is the relay. If a manifest contains an absolute URL the rewriter cannot handle, refuse to relay it while Private relay is on.

**Done when** a test manifest containing each of those forms comes out of the rewriter with no absolute upstream host left in it.

This touches the same function as issue 2, so fix them together.

---

## 5. A playlist can trigger cookie-bearing requests to any path on the cookie host

**Severity:** Low. **Needs:** cookies granted for the host, and a hostile playlist served from, or reachable through, that host.

**Where:** `host/media.go`: the cookie rule in `upstream.get`. `host/proxy.go`: `rewriteHLS`.

**Problem.** Every URI in a relayed playlist becomes a relay token, and any request to the cookie host gets your cookies. A hostile playlist can list arbitrary paths on that host. The attacker cannot read the responses (unless combined with issue 1), so this is a blind, GET-only request that ignores SameSite rules.

**What a fix must achieve.** The same media-only cookie rule as issue 1. Closing issue 1 properly closes this as well.

**Done when** the test for issue 1 also covers a single-file token for a non-media path.

---

## Lower priority, recorded so they are not lost

- **Cast revocation list is not checked.** The device certificate chain is validated up to Google's Cast root, but a leaked device key that Google has revoked would still pass. `host/chain.go`.
- **Discovery replies can be forged.** A UDP source address can be spoofed on a LAN, so a forged reply can make a "TV" entry point at another local machine. The effect is a TLS hello sent to that machine; the identity check then fails. `host/mdns.go`.
- **Same friendly name, new device id.** A different *genuine* Cast device advertising your TV's name is a first-use device, not a refused one. The popup marks it `new` and shows its IP. It does not yet ask for an explicit confirmation when a new device shares its name with one you already trust. `extension/popup.js`.
- **Token length reveals URL length**, and identical URLs produce identical tokens. This is a deliberate trade-off to keep live playlists stable. `host/proxy.go`, `session.seal`.
- **The helper's network fingerprint is Go's, not Chrome's.** A site that inspects TLS or HTTP/2 fingerprints can tell relay traffic from browser traffic.
- **No fixed extension ID.** Add a `key` to `extension/manifest.json` so the ID survives moving the folder.
- **Never exercised end to end.** The extension has not been loaded in Chrome, the installer has not been run, and nothing has been cast to a TV. Expect ordinary bugs there before any of the above matters.

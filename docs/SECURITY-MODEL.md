# XCast security and privacy model

What protects you, layer by layer, and what XCast keeps from the sites you cast from.
Closed and open issues are listed in [../SECURITY-ISSUES.md](../SECURITY-ISSUES.md).

## Security model

The relay rules below were tightened after an independent review; [SECURITY-ISSUES.md](../SECURITY-ISSUES.md) says what changed and what is still open.

### Extension

| Area | Control |
|---|---|
| Permissions | Required: `activeTab`, `scripting`, `storage`, `nativeMessaging`. Optional, requested per site when needed: `cookies` and `https://*/*` host access. No `<all_urls>`, no `webRequest`, no content scripts by default. |
| Page scanning | Runs only when you click XCast, in the extension's isolated world, with a 3-second deadline. URLs from the page are parsed and length-capped before use, so a page cannot crash or hang the popup. |
| Cross-origin player iframes | Access is requested per site, only when you click to scan one. HTTPS sites only. While Chrome's Allow/Deny prompt is open the popup says so, reports a refusal, and offers to ask from a tab instead (`grant.html`), which accepts exactly one `https://host` and nothing wider. |
| Site watcher (`watch.js`) | Registered only for sites you explicitly chose to watch. A grant given for another reason (iframe scan, cookies, "on all sites") never installs it. It records media URLs in the isolated world, where the page cannot read or change them. |
| Messaging | The service worker and the popup accept messages only from the extension's own pages, and type-check them. `externally_connectable` is empty, so no other extension or page can connect. |
| Rendering | `textContent` only. CSP is `default-src 'none'` with Trusted Types required. |
| Storage | `chrome.storage.local` is closed to content scripts (`TRUSTED_CONTEXTS`). The device list is capped at 20 entries that expire after 30 days, with typed, length-checked fields. |
| Device names | Names come from the LAN. The helper strips control and bidirectional-text characters and caps the length. A TV you have never cast to, or one that shares its name with another, is shown with a `new` tag and its IP address. |
| Automatic mode (optional, off by default) | One switch in the popup, one Chrome prompt, once: access to all HTTPS sites. Embedded players are then scanned without per-site prompts and the watcher runs on every HTTPS page from load. This trades the per-site model above for convenience: XCast could then read any page, although its code still only reads one when you click the icon. Switching it off removes the access and the watcher. Chrome's own "on all sites" setting alone never turns it on. |
| Incognito | Not allowed. |

### TV identity

| Area | Control |
|---|---|
| Genuine device | After the TLS handshake the TV must sign its current TLS certificate, plus a fresh nonce, with its device key (SHA-256 only). The device certificate must chain up to one of Google's two Cast root CAs. The roots are embedded, and their fingerprints are checked at start-up. A box that is not a genuine Cast device is refused even on first use. |
| Same device as before | The device key is pinned per device id on first use (`data/pins.json`, mode 0600). A later change is refused. Re-trusting a replaced TV takes two clicks. A pin file that exists but cannot be read blocks casting instead of re-trusting everything. |
| Before the check passes | Nothing the TV sends is processed except the identity reply. |
| Limits | The pin is keyed by the id the device advertises, so a *different genuine* Cast device using the same friendly name is a new device, not a refused one. The `new` tag and IP address are what tell you. Google's Cast revocation list (leaked device keys) is not checked. |

### Helper process

| Area | Control |
|---|---|
| Who can start it | Chrome launches it only for your extension ID (`allowed_origins`). The helper also compares the origin Chrome passes in with the one baked into the binary at install time. |
| Sandbox | Deny by default. It can use the network, read the system trust store, `stat` its own install folder (macOS's certificate verifier requires that), and write only to its own `data/` folder. It cannot read or list your files or start other programs. |
| Process limits | No core dumps, no crash tracebacks (they could contain URLs or cookies), 384 MB soft memory limit, at most 8 requests at once. |
| Input | Messages are capped at 64 KB; a larger one is rejected without ending a running cast. Unknown fields are rejected and every field is validated. The TV must be a private LAN IPv4 address. |
| Supply chain | Zero third-party dependencies. Supported, pinned Go toolchain. Built with `-trimpath` in a clean environment. Hardened-runtime signature. |

### LAN proxy

| Area | Control |
|---|---|
| Listener | Binds only to the interface facing the TV, on a random port. Connections from any IP other than the TV are closed before HTTP parsing, at most 32 at a time. The `Host` header must match, which defeats DNS rebinding. **(open issue 1: source IP is the only gate; someone who takes over the TV's IP address passes it.)** |
| URLs | Each upstream URL is an AES-256-GCM token under a random per-session key, with the grant type bound in. The proxy fetches only what the helper itself issued, so it is not an open proxy. This holds for DASH too: the entry URL is a single-file token, and the directory grants its manifest needs end with the token. Only what follows the first placeholder of an absolute segment template stays readable, because the player fills it in. |
| Upstream connections | Every dial, including redirects and DNS rebinding attempts, is checked. Refused always: loopback, link-local, CGNAT, metadata, any IPv6 address with a zone, all IPv6 outside global unicast, and the IPv4-embedding ranges (NAT64, 6to4, Teredo). A private LAN address is allowed only when the stream you chose is hosted there and you confirmed it in the popup, and then exactly one address. |
| Manifests | At most 8 MB in, 20,000 URIs and 32 MB out. |
| Sessions | Revoked immediately when you stop, when a newer cast starts playing, when a switch to another TV fails, or when the TV is lost for good. A timer removes idle ones; otherwise they last 12 hours, because a paused TV asks for nothing. Revocation also stops background prefetching. |
| Responses | CORS headers for the receiver, `nosniff`, `Referrer-Policy: no-referrer`, and the private-network-access preflight header. |

### Cookies

| Area | Control |
|---|---|
| Consent | Off by default. Asked only after the stream host answers 401 or 403. Consent is stored per pair of *site in the address bar* and *video host*. The Chrome permission alone never counts as consent. The prompt warns when the video host is not the site you are on. |
| Which cookies | Only what Chrome itself would attach to such a request: all of them when the cookie's domain covers the page you are on, otherwise only `SameSite=None; Secure` ones. |
| Where they go | Only over HTTPS, only to the exact host they were read for. Removed on any redirect that leaves that host. `https→http` redirects are refused. They live only in helper memory and never appear in logs or errors. Only to paths with a media file extension (playlists, manifests, segments, `.key`), also after a redirect: a playlist, or someone on the LAN holding a directory grant, cannot aim them at a page. With cookies in play, a DASH stream served from the top directory of its host is not relayed at all. |

## Privacy from the streaming site

The goal: a site learns nothing through XCast that it would not learn from you watching in Chrome.

| Concern | Behaviour |
|---|---|
| Detecting the extension | Nothing is injected until you click XCast. There are no web-accessible resources, and page scripts only read. The visible effects are pausing the local video after a cast starts, and the page reload you ask for when you choose to watch a site. |
| Referer | Other hosts get only the site origin, never the page path or query. Decided again for every redirect, as a browser does: a redirect to another host never carries the page address, and no Referer is invented from a signed stream URL. |
| Request headers | Only User-Agent (your browser's), Referer/Origin as above, Range and Accept. No extension identifier. The helper's TLS and HTTP fingerprint is Go's, not Chrome's, so a site that looks for it can tell the two apart. |
| The TV | Direct mode lets the TV fetch the stream, so the site sees the TV's user agent, and the TV ignores any VPN on this computer. **Private relay** in the popup forces everything through this computer instead. In a relayed DASH manifest every URL goes through the relay (base URLs, segment URLs and templates, clock URLs); `Location` is dropped, and with Private relay on a manifest that pulls in remote elements (`xlink:href`) is refused. |
| What the TV shows | The title sent to the TV is `XCast · <site hostname>`, or just `XCast` with Private relay on. Never the page title: a TV repeats the title, and in direct mode the stream URL, to every Cast controller on your network. |
| Your LAN | Relay URLs are encrypted tokens, and file names are replaced by `media.<ext>`. The relay hands out media only: pages and data (HTML, JSON, scripts, plain XML) and the bodies of upstream errors are never returned. The video bytes themselves travel as plain HTTP. |
| Data kept | Extension: discovered TVs, last TV, the relay switch, the sites you chose to watch, and your cookie-consent pairs (site and video host). Those last two lists are hostnames of sites you used XCast on. Helper: TV key pins. No record of individual videos, no analytics, no network calls other than to the stream host and the TV. |

What XCast cannot hide: the stream host sees your IP address (as it does in Chrome). The helper uses the system DNS resolver, so Chrome's "secure DNS" does not cover its lookups. A browser-only VPN or proxy extension does not cover the helper or the TV; a system-wide VPN covers the helper, and with Private relay the TV's traffic too, apart from open issue 4.


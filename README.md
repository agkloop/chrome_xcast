# XCast

Cast web video to a Chromecast, including sites without a Cast button.

- `extension/`: Chrome MV3 extension (vanilla JS, no dependencies)
- `host/`: `xcast-host`, a native messaging helper written in Go with only the standard library
- `install/`: macOS installer and the helper's sandbox profile
- `testlab/`: (run `testlab/make-media.sh` once to generate its test videos with ffmpeg) a local stand-in for a typical embedded-player site (`python3 testlab/server.py`), with a synthetic test video: a cross-origin iframe player, a `blob:`-source player whose stream is hotlink-protected, and a plain `<video>` with a signed, expiring MP4 link. `testlab/nm_cast.py` casts a URL through the installed helper without the browser

## Status

**Not ready for daily use.** Read this before installing.

- The Go helper builds, passes `go vet`, and passes its 13 tests with the race detector. `govulncheck` reports no known vulnerabilities on a supported toolchain.
- The installer has been run on macOS 26. The sandbox self-test passes, the binary carries a hardened-runtime signature, and the helper refuses a caller that is not the registered extension.
- Tested from the command line against a real Cast device (a Xiaomi Android TV box), from inside the sandbox: discovery, the identity check, a **direct** cast and a **relayed** cast of a public HLS test stream. Both reached `PLAYING` on the TV.
- Tested against the test lab's hotlink-protected stream, speaking the extension's protocol to the installed sandboxed helper: the local-network confirmation gate, the automatic fall-back to relay when the TV's own fetch gets 403, playback on the TV, and pause, seek, play and stop. The lab server's log shows every stream request came from this computer with the site's Referer, none from the TV.
- Also tested against the lab's signed, expiring MP4 link (a plain `<video src="//host/file.mp4?s=…&e=…">`): relayed cast, playback, and a seek that reached the lab server as Range requests.
- Not tested: DASH streams, cookie-protected streams, and reconnect after a real network drop.
- The extension was loaded into Chrome 153 (a separate throwaway profile, driven over the DevTools pipe). Verified: the manifest is accepted, the ID matches the one the installer was given, the toolbar popup renders without errors, the popup reaches the sandboxed helper through the service worker, and the helper accepts Chrome as the registered caller. The page scanner found the HLS stream on a legal demo page and ignored an unparsable `src` and a fake `?x=.mp4` URL.
- **Blocked at TV discovery from Chrome** until the helper is allowed under System Settings > Privacy & Security > Local Network (entry "xcast-host"; see Known limits for why this repeats after a reinstall). The helper says so in the popup. Until it is allowed, casting from the extension cannot work, so the cast and playback controls have not been tested through Chrome.
- Not tested in Chrome: clicking the toolbar icon by hand (automation cannot grant `activeTab`, so the popup's own scan of the page was not exercised), and every permission prompt.
- **Open security issues remain, one of them High.** They are listed in [SECURITY-ISSUES.md](SECURITY-ISSUES.md). Until they are fixed:
  - do not allow XCast to use your cookies for DASH (`.mpd`) streams;
  - use XCast only on a network you trust.

## Setup (macOS)

Requires Go. Any recent version works: the build fetches and checksum-verifies the pinned toolchain (`go1.27.1`, see `host/go.mod`).

1. Open `chrome://extensions`, turn on Developer mode, click **Load unpacked**, and select `extension/`. Copy the extension ID.
2. Run `install/install-macos.sh <extension-id>`.
3. Play a video, click XCast, pick the TV, click **Cast**.

The installer:

- builds in a clean environment (no inherited `GOFLAGS`, proxy or toolchain overrides);
- bakes your extension's origin into the binary;
- signs the binary with the hardened runtime;
- installs a wrapper that starts the helper inside a deny-by-default sandbox (`install/xcast.sb`);
- runs a self-test inside the sandbox (data folder, listening socket, the system certificate verifier, and that your home folder is out of reach) and refuses to install if it fails;
- refuses to run as root, and refuses install folders that are symlinks or not owned by you.

XCast is disabled in incognito windows (`"incognito": "not_allowed"`).

Command-line checks, none of which need the extension:

```sh
cd ~/Library/Application\ Support/XCast
./xcast-host-sandboxed -discover                # list Cast devices
./xcast-host-sandboxed -check <tv-ip>     # identity check only, plays nothing
./xcast-host-sandboxed -probe https://example.com/video.m3u8   # how a stream would be cast, touches no TV
./xcast-host-sandboxed -cast <tv-ip> https://example.com/video.m3u8
```

Set `XCAST_DEBUG=1` to get log output. Without it the helper logs nothing, because even a hostname says what you watch.

## How it works

1. The popup reads the page's `<video>` elements and resource timing entries to find the real `.m3u8`, `.mpd` or `.mp4` URL. MSE players only expose `blob:` URLs, so the timing entries are what find their manifests. A URL counts as video by its path or, where Chrome exposes it, by its response type; never by its query string. Open shadow roots are searched for `<video>` too, and while the popup is open it keeps looking for about 30 seconds, since many players only fetch the stream once you press play.
2. The helper does two things in parallel:
   - connects to the TV, checks its identity, and starts the Default Media Receiver;
   - probes the stream, both the way the TV would fetch it and the way your browser would.
3. If the TV can fetch the stream directly, it does, and your computer is not involved in playback. This is **direct** mode.
4. If the stream fails the TV's checks (CORS, Referer, cookies), the helper relays it through a LAN proxy. This is **proxy** mode. The proxy streams bytes through without transcoding and rewrites HLS and DASH manifests so segment requests also go through it. It fetches the next HLS segment ahead of the TV (32 MB cap) and retries a failed upstream request once.
5. If a direct load fails on the TV, the helper retries once through the proxy.
6. A cast that is already playing keeps its proxy session until the new cast has actually started. If the control connection to the TV drops, the helper reconnects (after 1, 3 and 8 seconds) and rejoins the running player. Only when that fails does it revoke the proxy and report a disconnect.

## Security model

Items marked **(open issue)** do not fully hold yet. See [SECURITY-ISSUES.md](SECURITY-ISSUES.md).

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
| URLs | Each upstream URL is an AES-256-GCM token under a random per-session key, with the grant type bound in. The proxy fetches only what the helper itself issued, so it is not an open proxy. **(open issue 2: DASH entry URLs still show the manifest's file name and query string.)** |
| Upstream connections | Every dial, including redirects and DNS rebinding attempts, is checked. Refused always: loopback, link-local, CGNAT, metadata, any IPv6 address with a zone, all IPv6 outside global unicast, and the IPv4-embedding ranges (NAT64, 6to4, Teredo). A private LAN address is allowed only when the stream you chose is hosted there and you confirmed it in the popup, and then exactly one address. |
| Manifests | At most 8 MB in, 20,000 URIs and 32 MB out. |
| Sessions | Revoked immediately when you stop, when a newer cast starts playing, when a switch to another TV fails, or when the TV is lost for good. A timer removes idle ones; otherwise they last 12 hours, because a paused TV asks for nothing. Revocation also stops background prefetching. |
| Responses | CORS headers for the receiver, `nosniff`, `Referrer-Policy: no-referrer`, and the private-network-access preflight header. |

### Cookies

| Area | Control |
|---|---|
| Consent | Off by default. Asked only after the stream host answers 401 or 403. Consent is stored per pair of *site in the address bar* and *video host*. The Chrome permission alone never counts as consent. The prompt warns when the video host is not the site you are on. |
| Which cookies | Only what Chrome itself would attach to such a request: all of them when the cookie's domain covers the page you are on, otherwise only `SameSite=None; Secure` ones. |
| Where they go | Only over HTTPS, only to the exact host they were read for. Removed on any redirect that leaves that host. `https→http` redirects are refused. They live only in helper memory and never appear in logs or errors. **(open issues 1 and 5: a relay request for any path on that host still carries them.)** |

## Privacy from the streaming site

The goal: a site learns nothing through XCast that it would not learn from you watching in Chrome.

| Concern | Behaviour |
|---|---|
| Detecting the extension | Nothing is injected until you click XCast. There are no web-accessible resources, and page scripts only read. The visible effects are pausing the local video after a cast starts, and the page reload you ask for when you choose to watch a site. |
| Referer | Other hosts get only the site origin, never the page path or query. **(open issue 3: not yet true across redirects.)** |
| Request headers | Only User-Agent (your browser's), Referer/Origin as above, Range and Accept. No extension identifier. The helper's TLS and HTTP fingerprint is Go's, not Chrome's, so a site that looks for it can tell the two apart. |
| The TV | Direct mode lets the TV fetch the stream, so the site sees the TV's user agent, and the TV ignores any VPN on this computer. **Private relay** in the popup forces everything through this computer instead. **(open issue 4: absolute URLs inside DASH manifests still go direct.)** |
| What the TV shows | The title sent to the TV is `XCast · <site hostname>`, or just `XCast` with Private relay on. Never the page title: a TV repeats the title, and in direct mode the stream URL, to every Cast controller on your network. |
| Your LAN | Relay URLs are encrypted tokens, and file names are replaced by `media.<ext>`. **(open issue 2: not yet for DASH.)** The video bytes themselves travel as plain HTTP. |
| Data kept | Extension: discovered TVs, last TV, the relay switch, the sites you chose to watch, and your cookie-consent pairs (site and video host). Those last two lists are hostnames of sites you used XCast on. Helper: TV key pins. No record of individual videos, no analytics, no network calls other than to the stream host and the TV. |

What XCast cannot hide: the stream host sees your IP address (as it does in Chrome). The helper uses the system DNS resolver, so Chrome's "secure DNS" does not cover its lookups. A browser-only VPN or proxy extension does not cover the helper or the TV; a system-wide VPN covers the helper, and with Private relay the TV's traffic too, apart from open issue 4.

## Known limits

- **DRM streams won't work.** Netflix, Disney+, Prime and other Widevine-protected streams can't be cast this way. Use Chrome's built-in "Cast tab" for those.
- **The proxy link between computer and TV is plain HTTP**, because the receiver does not trust local certificates.
- **Same-user malware is out of scope.** Anything running as you can replace the helper binary or the native messaging manifest. The hardened runtime and the baked-in origin raise the bar; they do not remove this.
- **Partitioned (CHIPS) cookies are not read**, so some embedded players that rely on them will fail to authenticate.
- **No fixed extension ID.** The manifest has no `key`, so moving the `extension/` folder changes the ID and you must rerun the installer.
- **The helper needs macOS's Local Network permission, again after every reinstall.** Chrome hands responsibility for a native host to the host itself, so the permission belongs to `xcast-host`, not to Chrome. macOS identifies the binary by its code-signature hash, and an ad-hoc signed binary gets a new hash whenever it is rebuilt from changed source. After each install, allow "xcast-host" in System Settings > Privacy & Security > Local Network (macOS prompts on first use). Signing with a stable identity (Developer ID or a self-signed code-signing certificate) would make the permission survive rebuilds.

# How XCast works

1. The popup reads the page's `<video>` elements and resource timing entries to find the real `.m3u8`, `.mpd` or `.mp4` URL. MSE players only expose `blob:` URLs, so the timing entries are what find their manifests. A URL counts as video by its path or, where Chrome exposes it, by its response type; never by its query string. Open shadow roots are searched for `<video>` too, and while the popup is open it keeps looking for about 30 seconds, since many players only fetch the stream once you press play.
2. The helper does two things in parallel:
   - connects to the TV, checks its identity, and starts the Default Media Receiver. For a TV you have cast to before, the connection and the identity check are already done when you press Cast: the popup asks for them as soon as it opens with that TV picked. Nothing is started on the TV at that point, so it does not wake up;
   - probes the stream, both the way the TV would fetch it and the way your browser would.
3. If the TV can fetch the stream directly, it does, and your computer is not involved in playback. This is **direct** mode.
4. If the stream fails the TV's checks (CORS, Referer, cookies), the helper relays it through a LAN proxy. This is **proxy** mode. The proxy streams bytes through without transcoding and rewrites HLS and DASH manifests so segment requests also go through it. It fetches the next HLS segment ahead of the TV (32 MB cap) and retries a failed upstream request once.
5. If a direct load fails on the TV, the helper retries once through the proxy.
6. A cast that is already playing keeps its proxy session until the new cast has actually started. If the control connection to the TV drops, the helper reconnects (after 1, 3 and 8 seconds) and rejoins the running player. Only when that fails does it revoke the proxy and report a disconnect.


## Test status

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
- **Open security issues remain, one of them High.** They are listed in [SECURITY-ISSUES.md](../SECURITY-ISSUES.md). Until they are fixed:
  - do not allow XCast to use your cookies for DASH (`.mpd`) streams;
  - use XCast only on a network you trust.


## The test lab

`testlab/` is a local stand-in for a typical embedded-player site, with generated test video:

```sh
testlab/make-media.sh      # once; needs ffmpeg
python3 testlab/server.py  # prints the address to open
```

| Page | Imitates |
|---|---|
| `embed.html` | a player inside a cross-origin HTTPS iframe |
| `protected.html` | a `blob:`-source player whose stream is only served with the site's Referer |
| `mp4.html` | a plain `<video>` with a signed, expiring MP4 link |

`testlab/nm_cast.py <tv-ip> <url> <referer>` casts a URL through the installed helper without the browser.

# XCast

Cast web video to your Chromecast or Android TV from sites that have no Cast button.

XCast finds the real video stream on the page and tells the TV to play it. If the site blocks the TV from fetching the video, XCast relays it through your computer. Nothing is re-encoded.

> **Early software.** It works in our tests. The five issues an independent review found in the relay are [closed in code and covered by tests](SECURITY-ISSUES.md), but relayed DASH (`.mpd`) streams have not been played on a real TV since, and a few lower-priority points remain open. Use it on a network you trust.

## Install (macOS)

You need Google Chrome and [Go](https://go.dev/dl/) (`brew install go`). The helper is built from source on your computer, so there is no binary to trust.

```sh
git clone https://github.com/agkloop/chrome_xcast.git
cd chrome_xcast
./install.sh
```

Then load the extension:

1. Open `chrome://extensions` and turn on **Developer mode**.
2. Click **Load unpacked** and choose the `extension` folder.

The first time you use it, macOS asks to let **xcast-host** find devices on your local network. Click **Allow**. If you missed it: System Settings > Privacy & Security > Local Network. macOS asks again after every reinstall.

## Use

1. Start the video on the page.
2. Click the XCast icon. It lists the video it found and the TVs on your network.
3. Pick the TV and click **Cast**. Pause, seek, volume and stop are in the same popup.

While something plays, the popup shows **stats for this cast**: relay speed with a one-minute graph, how often the TV ran out of video, how long the start took, data relayed, and how quickly the site answers. In direct mode the TV fetches the video itself, so only stalls and start time are known. The numbers live in memory for the current cast only and are never stored.

Two switches in the popup:

- **Automatic on all sites.** Off by default: XCast asks before looking inside a player embedded from another site. Turn it on (one Chrome prompt, once) and it never asks again. The price is that XCast then has access to every HTTPS page you visit.
- **Private relay.** Sends everything through your computer, so the site never sees your TV, and a VPN on your computer covers the TV's traffic too.

## When it doesn't work

| What you see | Why, and what to do |
|---|---|
| "Helper not installed" | Run `./install.sh`, then reload the extension in `chrome://extensions`. |
| "macOS is blocking local network access" | Allow **xcast-host** under System Settings > Privacy & Security > Local Network. |
| No TV in the list | The TV and the computer must be on the same network. Check with `~/Library/Application\ Support/XCast/xcast-host-sandboxed -discover`. |
| "No video found" | Press play first; XCast keeps looking for about 30 seconds. If the player is embedded from another site, allow the scan it offers, or turn on **Automatic on all sites**. |
| The site has its own Cast button (YouTube, Twitch, Spotify…) | Use that button. It plays through the TV's own app, in better quality. |
| Netflix, Disney+, Prime Video and other DRM services | Cannot be cast this way by any extension. Use Chrome's menu > Cast > Cast tab. |
| "This is NOT the TV used before" | The TV's identity changed. Only continue if you replaced or factory-reset it. |

## Uninstall

```sh
./uninstall.sh          # keeps the list of TVs you trusted
./uninstall.sh --all    # removes that too
```

Then remove XCast in `chrome://extensions`.

## How it is built

| Part | What it does |
|---|---|
| `extension/` | Chrome extension (plain JavaScript, no dependencies): finds the video, shows the popup. |
| `host/` | The helper, in Go, standard library only: finds TVs, checks that a TV is a genuine Cast device and the same one as last time, controls playback, and relays streams the TV cannot fetch. Chrome extensions are not allowed to do any of that themselves. |
| `install/` | The macOS installer and the sandbox the helper runs in: it cannot read your files or start other programs. |
| `testlab/` | Local test pages that imitate real player setups, with generated video. |

More detail:

- [How it works, and what has been tested](docs/HOW-IT-WORKS.md)
- [Security and privacy model](docs/SECURITY-MODEL.md)
- [Security issues: closed and open](SECURITY-ISSUES.md)

## Known limits

- **DRM streams won't work.** Netflix, Disney+, Prime and other Widevine-protected streams can't be cast this way. Use Chrome's built-in "Cast tab" for those.
- **The proxy link between computer and TV is plain HTTP**, because the receiver does not trust local certificates.
- **Same-user malware is out of scope.** Anything running as you can replace the helper binary or the native messaging manifest. The hardened runtime and the baked-in origin raise the bar; they do not remove this.
- **Your cookies go only to media.** With cookies allowed, they are sent to playlists, manifests, segments and `.key` files, never to an address without a media file extension. A stream whose playlist or key address has no such extension and needs your login will not play.
- **Partitioned (CHIPS) cookies are not read**, so some embedded players that rely on them will fail to authenticate.
- **The helper needs macOS's Local Network permission, again after every reinstall.** Chrome hands responsibility for a native host to the host itself, so the permission belongs to `xcast-host`, not to Chrome. macOS identifies the binary by its code-signature hash, and an ad-hoc signed binary gets a new hash whenever it is rebuilt from changed source. After each install, allow "xcast-host" in System Settings > Privacy & Security > Local Network (macOS prompts on first use). Signing with a stable identity (Developer ID or a self-signed code-signing certificate) would make the permission survive rebuilds.
- **macOS only** for now: the installer and the sandbox are macOS-specific.

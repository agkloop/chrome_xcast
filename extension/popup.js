const $ = (id) => document.getElementById(id);
const state = { tab: null, streams: [], picked: 0, devices: new Map(), media: null, grant: null, action: null, allowLocal: new Set(), casting: false, tvName: '', mode: '' };

// Runs inside the page (each frame). Must be self-contained: it is serialized.
function detect() {
  // Matched against the path only: a page must not be able to dress up an
  // arbitrary endpoint as a video with "?x=.mp4".
  const MEDIA = /\.(m3u8|mpd|mp4|m4v|webm|mov)$/i;
  const out = [];
  const seen = new Set();
  const parse = (url) => {
    try {
      const u = new URL(url);
      return /^https?:$/.test(u.protocol) && url.length <= 4096 ? u : null;
    } catch {
      return null; // e.g. <video src="https://[">: reflected raw, unparsable
    }
  };
  const TYPE = /mpegurl|dash\+xml|^video\//i;
  const add = (url, how, type = '') => {
    if (typeof url !== 'string' || seen.has(url) || out.length >= 40) return;
    const u = parse(url);
    // A network entry counts as video by its path, or by its response type
    // (playlists are often served from extension-less addresses).
    if (!u || (how === 'net' && !MEDIA.test(u.pathname) && !TYPE.test(type))) return;
    seen.add(url);
    out.push({ url: u.href, how });
  };
  // Players built as web components keep their <video> in a shadow root.
  const videos = [];
  const walk = (root, depth) => {
    videos.push(...root.querySelectorAll('video'));
    if (depth > 4) return;
    for (const el of root.querySelectorAll('*')) if (el.shadowRoot) walk(el.shadowRoot, depth + 1);
  };
  walk(document, 0);
  let video = null;
  for (const v of videos) {
    add(v.currentSrc || v.src, 'video');
    for (const s of v.querySelectorAll('source')) add(s.src, 'video');
    const area = v.clientWidth * v.clientHeight;
    if (!video || area > video.area) video = { area, currentTime: v.currentTime || 0, duration: v.duration || 0 };
  }
  // MSE players expose only blob: URLs; the real manifest shows up here.
  for (const e of performance.getEntriesByType('resource')) add(e.name, 'net', e.contentType || '');
  // On watched sites watch.js has recorded these since page load (it applied
  // the same path-or-type test, so they are taken as they are).
  for (const url of globalThis.__xcastSeen || []) add(url, 'net', 'video/');
  return {
    frameUrl: location.href,
    title: document.title,
    video,
    streams: out,
    iframes: [...document.querySelectorAll('iframe[src]')].map((f) => parse(f.src)?.origin).filter(Boolean).slice(0, 20),
  };
}

// Sites XCast cannot help with, and what to do there instead. Matched on the
// host in the address bar (exact or a subdomain).
const OWN_CAST = ['youtube.com', 'youtu.be', 'music.youtube.com', 'spotify.com', 'twitch.tv', 'vimeo.com', 'dailymotion.com'];
const DRM = ['netflix.com', 'disneyplus.com', 'primevideo.com', 'amazon.com', 'max.com', 'hulu.com', 'tv.apple.com', 'peacocktv.com', 'paramountplus.com', 'shahid.mbc.net', 'osnplus.com'];
function siteAdvice(tabUrl) {
  let host;
  try {
    host = new URL(tabUrl).hostname.replace(/^www\./, '');
  } catch {
    return '';
  }
  const on = (list) => list.some((d) => host === d || host.endsWith(`.${d}`));
  if (on(OWN_CAST)) return `${host} has its own Cast button. Use the Cast icon in its player, or Chrome's menu > Cast: the TV's own app then plays it in full quality.`;
  if (on(DRM)) return `${host} streams are DRM-protected, so XCast cannot cast them. Use the site's own Cast button, or Chrome's menu > Cast > Cast tab.`;
  return '';
}

function kindOf(url) {
  const p = new URL(url).pathname.toLowerCase();
  if (p.endsWith('.m3u8')) return 'HLS';
  if (p.endsWith('.mpd')) return 'DASH';
  return 'FILE';
}

function score(s, order) {
  const p = new URL(s.url).pathname.toLowerCase();
  let v = 20;
  if (p.endsWith('.m3u8')) v = /master|index|playlist|manifest/.test(p) ? 60 : 50;
  else if (p.endsWith('.mpd')) v = 45;
  else if (s.how === 'video') v = 40;
  if (s.video?.duration > 60) v += 5;
  return v - order * 0.001;
}

function setStatus(text, kind = '') {
  $('status').textContent = text;
  $('status').dataset.kind = kind;
}

// Two views: the form to pick and cast ('choose'), and the remote for the
// running cast ('playing'). Switching views never touches playback.
function setView(view) {
  const focused = document.activeElement;
  $('choose').hidden = view !== 'choose';
  $('controls').hidden = view !== 'playing';
  $('backToPlaying').hidden = !state.casting;
  showTv();
  // Keyboard users: do not leave the focus on a control that just disappeared.
  if (focused?.closest?.('[hidden]')) $(view === 'playing' ? 'playPause' : 'device').focus();
}

// cast() knows the casting TV's name. After the popup is reopened mid-cast
// the picker's selection (the TV last cast to) stands in for it.
function showTv() {
  if (state.casting && !state.tvName) state.tvName = state.devices.get($('device').value)?.name || '';
  $('tvName').textContent = state.tvName || 'TV';
}

function castEnded() {
  state.casting = false;
  state.media = null;
  state.tvName = state.mode = '';
  setView('choose');
  showPlayer();
}

async function send(msg) {
  const r = await chrome.runtime.sendMessage(msg);
  if (!r?.ok) throw Object.assign(new Error(r?.error || 'Failed'), { code: r?.code });
  return r;
}

async function scan() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  state.tab = tab;
  // injectImmediately + a deadline: a frame that never finishes loading must
  // not be able to hang the popup.
  const inject = (allFrames) =>
    Promise.race([
      chrome.scripting.executeScript({ target: { tabId: tab.id, allFrames }, func: detect, world: 'ISOLATED', injectImmediately: true }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 3000)),
    ]);
  let results;
  try {
    if (!tab?.id) throw new Error('no tab');
    results = await inject(true);
  } catch {
    try {
      results = await inject(false);
    } catch {
      state.streams = [];
      renderStreams('XCast cannot read this page.');
      return;
    }
  }

  const all = [];
  const scannedOrigins = new Set();
  const iframeOrigins = [];
  for (const { frameId, result } of results) {
    try {
      if (!result) continue;
      scannedOrigins.add(new URL(result.frameUrl).origin);
      iframeOrigins.push(...result.iframes);
      for (const s of result.streams) {
        new URL(s.url); // throws on anything unparsable: skip that frame, not the scan
        all.push({ url: s.url, how: s.how, frameId, frameUrl: String(result.frameUrl).slice(0, 4096), video: result.video });
      }
    } catch {}
  }
  const unique = new Map();
  all.forEach((s, i) => unique.has(s.url) || unique.set(s.url, { ...s, rank: score(s, i) }));
  state.streams = [...unique.values()].sort((a, b) => b.rank - a.rank).slice(0, 10);
  state.picked = 0;

  // Nothing found: offer the one grant that can help. A cross-origin player
  // iframe needs access to be scanned at all; otherwise the page may be too
  // busy for the browser's buffer, and watching it from load fixes that.
  state.grant = null;
  const advice = state.streams.length ? '' : siteAdvice(tab.url || '');
  const auto = await isAuto();
  if (!state.streams.length && !advice && !auto) {
    const frame = iframeOrigins.find((o) => o.startsWith('https:') && !scannedOrigins.has(o));
    const page = /^https:/.test(tab.url || '') ? new URL(tab.url).origin : '';
    if (frame) {
      state.grant = { origin: frame, reload: false, text: `Scan embedded player from ${new URL(frame).host}` };
    } else if (page && !(await isWatched(page))) {
      state.grant = { origin: page, reload: true, text: `Watch ${new URL(page).host} for video (reloads the page)` };
    }
  }
  $('grantSite').hidden = !state.grant;
  if (state.grant) $('grantSite').textContent = state.grant.text;
  renderStreams(advice || (auto ? 'No video yet. Press play on the page: XCast keeps looking.' : 'No video found. Start playing it, then reopen XCast.'));
  // Many players only fetch the stream once you press play: keep looking for
  // a while instead of making the user reopen the popup.
  clearTimeout(state.rescan);
  if (!state.streams.length && !advice && (state.rescans = (state.rescans || 0) + 1) <= 20) {
    state.rescan = setTimeout(() => scan().catch(() => {}), 1500);
  }
}

function renderStreams(emptyText) {
  const ul = $('streams');
  ul.replaceChildren();
  if (!state.streams.length) {
    const li = document.createElement('li');
    li.className = 'empty';
    li.textContent = emptyText;
    ul.append(li);
  }
  state.streams.forEach((s, i) => {
    const li = document.createElement('li');
    const label = document.createElement('label');
    const input = document.createElement('input');
    input.type = 'radio';
    input.name = 'stream';
    input.checked = i === state.picked;
    input.addEventListener('change', () => (state.picked = i));
    const badge = document.createElement('span');
    badge.className = 'badge';
    badge.textContent = kindOf(s.url);
    const text = document.createElement('span');
    text.className = 'url';
    const u = new URL(s.url);
    text.textContent = `${u.host} …/${u.pathname.split('/').pop()}`;
    label.title = s.url;
    label.append(input, badge, text);
    li.append(label);
    ul.append(li);
  });
  updateCastButton();
}

function renderDevices() {
  const sel = $('device');
  const current = sel.value;
  sel.replaceChildren();
  const list = [...state.devices.values()].sort((a, b) => a.name.localeCompare(b.name));
  if (!list.length) {
    const o = document.createElement('option');
    o.textContent = 'Searching…';
    o.value = '';
    sel.append(o);
  }
  const names = new Map();
  for (const d of list) names.set(d.name, (names.get(d.name) || 0) + 1);
  for (const d of list) {
    const o = document.createElement('option');
    o.value = d.id;
    // A TV never cast to before, or one sharing its name with another, is
    // shown with its address so a look-alike cannot pass for the real one.
    const tag = [d.known ? '' : 'new', !d.known || names.get(d.name) > 1 ? d.host : ''].filter(Boolean).join(' · ');
    o.textContent = `${d.name}${d.model ? ` (${d.model})` : ''}${tag ? ` [${tag}]` : ''}`;
    sel.append(o);
  }
  if (current && state.devices.has(current)) sel.value = current;
  updateCastButton();
}

function updateCastButton() {
  $('cast').disabled = !state.streams.length || !state.devices.has($('device').value);
}

async function loadDevices() {
  const { devices = {}, lastDevice } = await chrome.storage.local.get(['devices', 'lastDevice']);
  for (const d of Object.values(devices)) state.devices.set(d.id, d);
  renderDevices();
  if (lastDevice && state.devices.has(lastDevice)) $('device').value = lastDevice;
  updateCastButton();
  showTv();
  warm();
}

// Has the helper connect to the picked TV now, so that Cast does not wait for
// it. Only for a TV that was cast to before; the helper checks that again.
function warm() {
  const d = state.devices.get($('device').value);
  if (d?.known) send({ cmd: 'warm', device: { id: d.id, host: d.host, port: d.port } }).catch(() => {});
}

async function discover() {
  $('rescan').disabled = true;
  try {
    const r = await send({ cmd: 'discover' });
    for (const d of r.devices) state.devices.set(d.id, d);
    renderDevices();
    if (!state.devices.size) setStatus('No TV found on this network', 'err');
  } catch (e) {
    setStatus(e.message, 'err');
  } finally {
    $('rescan').disabled = false;
  }
}

const hostOf = (url) => new URL(url).host;
const consentKey = (streamUrl) => `${hostOf(state.tab.url)}|${hostOf(streamUrl)}`;

const ALL_SITES = 'https://*/*';
async function isAuto() {
  const { auto } = await chrome.storage.local.get('auto');
  return !!auto && (await chrome.permissions.contains({ origins: [ALL_SITES] }));
}

async function isWatched(origin) {
  const { watchOrigins = [] } = await chrome.storage.local.get('watchOrigins');
  return watchOrigins.includes(`${origin}/*`) && (await chrome.permissions.contains({ origins: [`${origin}/*`] }));
}

// Cookies are sent only when ALL of these hold:
//  - the user said yes for exactly this pair (site in the address bar, video
//    host). The Chrome permission alone is not consent: it is also granted
//    for scanning iframes, and `cookies` is global once granted anywhere.
//  - https, and the stream is on the consented host
//  - per cookie, what Chrome itself would attach to such a request: all of
//    them when the page's own host is covered by the cookie, otherwise only
//    SameSite=None ones. (Chrome refuses cookies scoped to public suffixes, so
//    "covered by the cookie" cannot be faked from a shared-hosting sibling.)
async function cookiesFor(url) {
  const u = new URL(url);
  if (u.protocol !== 'https:' || !chrome.cookies) return '';
  const { cookieConsent = [] } = await chrome.storage.local.get('cookieConsent');
  if (!cookieConsent.includes(consentKey(url))) return '';
  if (!(await chrome.permissions.contains({ permissions: ['cookies'], origins: [`${u.origin}/*`] }))) return '';
  const pageHost = new URL(state.tab.url).hostname;
  const covers = (c) => {
    const d = c.domain.replace(/^\./, '');
    return pageHost === d || (!c.hostOnly && pageHost.endsWith(`.${d}`));
  };
  const jar = (await chrome.cookies.getAll({ url })).filter((c) => covers(c) || (c.sameSite === 'no_restriction' && c.secure));
  const header = jar.map((c) => `${c.name}=${c.value}`).join('; ');
  return header.length <= 8192 ? header : '';
}

// The TV shows this title and repeats it to every Cast controller on the
// network (phones included), so it never carries the page's real title.
const tvTitle = () => ($('relay').checked ? 'XCast' : `XCast · ${new URL(state.tab.url).hostname}`.slice(0, 120));

async function cast() {
  const s = state.streams[state.picked];
  const d = state.devices.get($('device').value);
  if (!s || !d) return;
  setAction(null);
  $('cast').disabled = true;
  setStatus('Casting…');
  resetMetrics();
  try {
    const media = {
      url: s.url,
      referer: s.frameUrl,
      userAgent: navigator.userAgent,
      currentTime: s.video?.currentTime || 0,
      title: tvTitle(),
    };
    if (state.allowLocal.has(s.url)) media.allowLocal = true;
    // Private relay: the TV never talks to the site, so the site sees one
    // client (this computer, behind its VPN if any) and no TV fingerprint.
    if ($('relay').checked) media.mode = 'proxy';
    const cookie = await cookiesFor(s.url);
    if (cookie) media.cookie = cookie;
    const r = await send({ cmd: 'cast', device: { id: d.id, host: d.host, port: d.port }, media });
    d.known = true;
    chrome.storage.local.set({ lastDevice: d.id }).catch(() => {});
    setStatus(r.mode === 'direct' ? 'Playing on TV' : 'Playing on TV (relayed)', 'ok');
    state.casting = true;
    state.tvName = d.name;
    state.mode = r.mode;
    setView('playing');
    showPlayer();
    chrome.scripting
      .executeScript({ target: { tabId: state.tab.id, frameIds: [s.frameId] }, func: () => document.querySelectorAll('video').forEach((v) => v.pause()) })
      .catch(() => {});
  } catch (e) {
    setStatus(e.message, 'err');
    const host = new URL(s.url).host;
    if (e.code === 'UPSTREAM_AUTH') {
      // Compared with the address bar, by exact host: anything else gets the warning.
      const pageHost = hostOf(state.tab.url);
      const where = `${host}${new URL(s.url).pathname}`.slice(0, 80);
      const ask =
        host === pageHost
          ? `Site needs your login. Send your ${host} cookies with this video (${where})`
          : `Careful: this video is on ${host}, not on ${pageHost}. Only if you trust this page, send your ${host} cookies (${where})`;
      setAction(ask, async () => {
        if (!(await chrome.permissions.request({ permissions: ['cookies'], origins: [`${new URL(s.url).origin}/*`] }))) return;
        const { cookieConsent = [] } = await chrome.storage.local.get('cookieConsent');
        await chrome.storage.local.set({ cookieConsent: [...new Set([...cookieConsent, consentKey(s.url)])].slice(-200) });
        cast();
      });
    } else if (e.code === 'LOCAL_STREAM') {
      setAction(`${host} is a device on your own network. Cast from it anyway`, () => {
        state.allowLocal.add(s.url);
        cast();
      });
    } else if (e.code === 'DEVICE_IDENTITY') {
      setAction(`This is NOT the TV used before as "${d.name}" (${d.host}). Only if you replaced or factory-reset it: trust it again`, () => {
        setAction(`Confirm: forget the old "${d.name}" and trust the device at ${d.host}`, async () => {
          await send({ cmd: 'forget', device: { id: d.id, host: d.host, port: d.port } });
          cast();
        });
      });
    }
  } finally {
    updateCastButton();
  }
}

// One contextual follow-up link under the Cast button.
function setAction(text, run) {
  state.action = run || null;
  $('action').hidden = !run;
  $('action').textContent = text || '';
}

async function control(action, value) {
  try {
    await send({ cmd: 'control', action, value });
    if (action === 'stop') {
      castEnded();
      setStatus('Stopped');
    }
  } catch (e) {
    setStatus(e.message, 'err');
  }
}

const fmt = (t) => {
  if (!Number.isFinite(t) || t < 0) return '--:--';
  const s = Math.floor(t % 60).toString().padStart(2, '0');
  const m = Math.floor(t / 60) % 60;
  const h = Math.floor(t / 3600);
  return h ? `${h}:${m.toString().padStart(2, '0')}:${s}` : `${m}:${s}`;
};

// ---- stats for the running cast (helper sends one snapshot a second) ----
const fmtBytes = (n) => (n >= 1e9 ? `${(n / 1e9).toFixed(2)} GB` : n >= 1e6 ? `${Math.round(n / 1e6)} MB` : `${Math.round(n / 1e3)} KB`);
const fmtSecs = (ms) => `${(ms / 1000).toFixed(1)} s`;

// Pure: turns a snapshot into the texts on screen (kept separate so it can be tested).
function describeMetrics(m) {
  const relayed = m.mode === 'proxy';
  const stallTime = m.stalls ? ` (${fmtSecs(m.stallMs)})` : '';
  const hit = m.segments > 0 ? ` · read-ahead ${Math.round((100 * m.prefetchHits) / m.segments)}%` : '';
  const count = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
  const trouble = m.retries || m.errors ? ` · ${count(m.retries, 'retry').replace('retrys', 'retries')}, ${count(m.errors, 'error')}` : '';
  return {
    speed: relayed ? `${m.mbps.toFixed(1)} Mbps` : '–',
    stalls: `${m.stalls}${stallTime}`,
    start: Number.isFinite(m.startMs) ? fmtSecs(m.startMs) : '–',
    totals: relayed
      ? `Relayed ${fmtBytes(m.bytes)}${hit}${trouble} · site answers in ${Math.round(m.ttfbMs)} ms`
      : 'Direct: the TV fetches the video itself, so there is no relay traffic to measure.',
  };
}

function drawSpark(values) {
  const svg = $('spark');
  const NS = 'http://www.w3.org/2000/svg';
  const top = Math.max(1, ...values);
  const pts = values.map((v, i) => `${((i / 59) * 300).toFixed(1)},${(38 - (v / top) * 34).toFixed(1)}`).join(' ');
  const base = document.createElementNS(NS, 'line');
  for (const [k, v] of Object.entries({ x1: 0, y1: 39, x2: 300, y2: 39 })) base.setAttribute(k, v);
  const line = document.createElementNS(NS, 'polyline');
  line.setAttribute('points', pts);
  svg.replaceChildren(base, line);
}

function showMetrics(m) {
  const num = (v) => typeof v === 'number' && Number.isFinite(v);
  if (!m || !['mbps', 'bytes', 'stalls', 'stallMs', 'segments', 'prefetchHits', 'retries', 'errors', 'ttfbMs'].every((k) => num(m[k]))) return;
  const t = describeMetrics(m);
  $('mSpeed').textContent = t.speed;
  $('mStalls').textContent = t.stalls;
  $('mStart').textContent = t.start;
  $('mTotals').textContent = t.totals;
  state.spark = [...(state.spark || []), m.mode === 'proxy' ? m.mbps : 0].slice(-60);
  // An attribute, not the property: <svg> has no `hidden` property.
  $('spark').toggleAttribute('hidden', m.mode !== 'proxy');
  if (m.mode === 'proxy') drawSpark(state.spark);
  if (m.mode !== state.mode) {
    state.mode = m.mode;
    showPlayer();
  }
}

function resetMetrics() {
  state.spark = [];
  for (const id of ['mSpeed', 'mStart']) $(id).textContent = '–';
  $('mStalls').textContent = '0';
  $('mTotals').textContent = '';
  $('spark').replaceChildren();
}

const STATE_TEXT = new Map([['PLAYING', 'Playing'], ['PAUSED', 'Paused'], ['BUFFERING', 'Buffering'], ['IDLE', 'Idle']]);

// The TV reports its position only when something changes. While it plays,
// the time since that report (dated by the service worker) is added. NaN:
// no position reported yet.
function positionNow(m, total) {
  if (!Number.isFinite(m.currentTime)) return NaN;
  const since = m.state === 'PLAYING' && Number.isFinite(m.at) ? Math.max(Date.now() - m.at, 0) / 1000 : 0;
  return Math.min(Math.max(m.currentTime + since, 0), total || Infinity);
}

// Draws the remote from state.media (null: the TV has not reported yet).
function showPlayer() {
  const m = state.media || {};
  const paused = m.state === 'PAUSED';
  $('iconPlay').toggleAttribute('hidden', !paused);
  $('iconPause').toggleAttribute('hidden', paused);
  $('playPause').title = paused ? 'Play' : 'Pause';
  $('playPause').setAttribute('aria-label', paused ? 'Play' : 'Pause');

  const text = m.idleReason === 'FINISHED' ? 'Finished' : STATE_TEXT.get(m.state) || 'Starting';
  const mode = state.mode === 'proxy' ? 'relayed' : state.mode === 'direct' ? 'direct' : '';
  $('pill').dataset.state = STATE_TEXT.has(m.state) ? m.state.toLowerCase() : '';
  $('pillText').textContent = mode ? `${text} · ${mode}` : text;

  // No duration: a live stream (or not known yet). The bar is then inactive.
  const total = m.duration > 0 && Number.isFinite(m.duration) ? m.duration : 0;
  const now = positionNow(m, total);
  const bar = $('progress');
  $('progressFill').style.width = `${total ? (100 * (now || 0)) / total : 0}%`;
  bar.setAttribute('aria-disabled', String(!total));
  bar.setAttribute('aria-valuemax', String(Math.round(total)));
  bar.setAttribute('aria-valuenow', String(total ? Math.round(now || 0) : 0));
  bar.setAttribute('aria-valuetext', total ? `${fmt(now)} of ${fmt(total)}` : fmt(now));
  $('timeNow').textContent = fmt(now);
  $('timeTotal').textContent = total ? fmt(total) : '';
}

// Between the TV's reports the remote counts along by itself.
setInterval(() => {
  if (state.media?.state === 'PLAYING' && !$('controls').hidden) showPlayer();
}, 500);

function showMedia(m) {
  state.media = m;
  showPlayer();
  if (m.state === 'IDLE' && m.idleReason) {
    // Over for the service worker too: there is nothing to go back to.
    state.casting = false;
    $('backToPlaying').hidden = true;
    setStatus(m.idleReason === 'FINISHED' ? 'Finished' : `TV stopped: ${m.idleReason.toLowerCase()}`, m.idleReason === 'ERROR' ? 'err' : '');
  }
}

chrome.runtime.onMessage.addListener((m, sender) => {
  if (sender.id !== chrome.runtime.id || sender.tab || !sender.url?.startsWith(chrome.runtime.getURL(''))) return;
  if (!m || typeof m !== 'object') return;
  if (m.type === 'device') {
    if (typeof m.device?.id !== 'string' || typeof m.device.name !== 'string' || typeof m.device.host !== 'string') return;
    state.devices.set(m.device.id, m.device);
    renderDevices();
  } else if (m.type === 'media' && typeof m.state === 'string') {
    showMedia(m);
  } else if (m.type === 'volume' && typeof m.level === 'number') {
    $('volume').value = m.level;
  } else if (m.type === 'metrics') {
    showMetrics(m);
  } else if (m.type === 'disconnected') {
    castEnded();
    if (typeof m.reason === 'string') setStatus(m.reason.slice(0, 200), 'err');
  }
});

$('device').addEventListener('change', () => {
  updateCastButton();
  warm();
});
$('relay').addEventListener('change', (e) => chrome.storage.local.set({ relay: e.target.checked }));
chrome.storage.local.get('relay').then(({ relay }) => ($('relay').checked = !!relay));
$('rescan').addEventListener('click', discover);
$('cast').addEventListener('click', cast);
$('stop').addEventListener('click', () => control('stop'));
$('playPause').addEventListener('click', () => control(state.media?.state === 'PAUSED' ? 'play' : 'pause'));
$('volume').addEventListener('change', (e) => control('volume', Number(e.target.value)));
for (const b of document.querySelectorAll('[data-seek]')) b.addEventListener('click', () => control('seekBy', Number(b.dataset.seek)));
// The progress bar is a slider: click to jump, arrow keys for 10 s steps.
// A live stream (no duration) cannot be seeked.
const SEEK_KEYS = new Map([['ArrowLeft', -10], ['ArrowDown', -10], ['ArrowRight', 10], ['ArrowUp', 10]]);
$('progress').addEventListener('click', (e) => {
  const total = state.media?.duration;
  if (!(total > 0)) return;
  const box = e.currentTarget.getBoundingClientRect();
  control('seek', Math.min(Math.max((e.clientX - box.left) / box.width, 0), 1) * total);
});
$('progress').addEventListener('keydown', (e) => {
  if (!SEEK_KEYS.has(e.key) || !(state.media?.duration > 0)) return;
  e.preventDefault();
  control('seekBy', SEEK_KEYS.get(e.key));
});
$('gear').addEventListener('click', () => {
  const open = $('settings').hidden;
  $('settings').hidden = !open;
  $('gear').setAttribute('aria-expanded', String(open));
});
$('castOther').addEventListener('click', () => setView('choose'));
$('backToPlaying').addEventListener('click', () => setView('playing'));
// Asks Chrome for site access. Must be called straight from a click: Chrome
// only accepts the request during the click itself, so it goes first, before
// any await. Until the user answers nothing else would change on screen, so
// say what is going on and offer the tab route in case the prompt is hidden.
function askForAccess(pattern, label, fallback) {
  const asking = chrome.permissions.request({ origins: [pattern] });
  setStatus(`Chrome is asking for access to ${label}. Click Allow in its prompt.`);
  setAction('No prompt from Chrome? Ask in a tab instead', () => chrome.tabs.create({ url: chrome.runtime.getURL(`grant.html#${new URLSearchParams(fallback)}`) }));
  return asking.then(
    (granted) => {
      setAction(null);
      setStatus(granted ? '' : 'Access was not allowed.', granted ? '' : 'err');
      return granted;
    },
    (e) => {
      setStatus(`Chrome refused the request: ${e.message}`, 'err');
      return false;
    },
  );
}

$('grantSite').addEventListener('click', () => {
  const g = state.grant;
  if (!g) return;
  const pattern = `${g.origin}/*`;
  const asked = askForAccess(pattern, new URL(g.origin).host, { origin: g.origin, tab: String(state.tab.id), watch: g.reload ? '1' : '' });
  // Chrome may close this popup while its prompt is open, so the follow-up
  // (reloading a watched site) is left to the service worker.
  if (g.reload) chrome.storage.session.set({ pendingReload: { tabId: state.tab.id, origin: pattern, watch: true } }).catch(() => {});
  asked.then((granted) => {
    if (!granted) return chrome.storage.session.remove('pendingReload');
    if (!g.reload) return scan();
    $('grantSite').hidden = true;
    setStatus('Play the video, then reopen XCast');
  });
});

// Automatic mode: one permission for every HTTPS site, once. After that the
// scan reaches embedded players by itself and the watcher runs everywhere.
$('auto').addEventListener('change', (e) => {
  if (!e.target.checked) {
    chrome.storage.local.set({ auto: false });
    chrome.permissions.remove({ origins: [ALL_SITES] }).finally(() => scan().catch(() => {}));
    return setStatus('Automatic mode is off: XCast asks per site again.');
  }
  askForAccess(ALL_SITES, 'all HTTPS sites', { all: '1' }).then(async (granted) => {
    e.target.checked = granted;
    await chrome.storage.local.set({ auto: granted });
    if (granted) {
      setStatus('Automatic mode is on. Pages opened from now on are watched from the start.', 'ok');
      state.rescans = 0;
      scan().catch(() => {});
    }
  });
});
isAuto().then((on) => ($('auto').checked = on));

// If access arrives by another route (the tab fallback) while this popup is
// still open, pick it up.
chrome.permissions.onAdded.addListener(async () => {
  setAction(null);
  setStatus('');
  $('auto').checked = await isAuto();
  state.rescans = 0;
  scan().catch(() => {});
});
$('action').addEventListener('click', () => (async () => state.action?.())().catch((e) => setStatus(e.message, 'err')));

// Everything starts in parallel: cached TVs render instantly, discovery and
// page scanning run concurrently, and an active session restores controls.
loadDevices();
discover();
scan().catch(() => renderStreams('XCast cannot read this page.'));
send({ cmd: 'state' })
  .then((r) => {
    if (r.active) {
      state.casting = true;
      setView('playing');
    }
    if (r.active && r.media) showMedia(r.media);
    if (r.volume) $('volume').value = r.volume.level;
    if (r.active && r.metrics) showMetrics(r.metrics);
  })
  .catch(() => {});

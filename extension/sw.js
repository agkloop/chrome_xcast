// Owns the native helper connection. The popup is short-lived; the helper must
// outlive it (it serves the stream in proxy mode), and an open native port
// keeps this service worker alive (Chrome 105+).

const HOST = 'com.xcast.host';
const IDLE_MS = 60_000;
const FINAL_IDLE = new Set(['FINISHED', 'ERROR', 'CANCELLED', 'INTERRUPTED']);
// What this extension needs from the helper (host.go, protoVersion). A helper
// from before the check existed does not know the question: that counts as 0.
const NEED_PROTO = 1;

// Content scripts (watch.js runs inside web pages) get no access to storage.
chrome.storage.local.setAccessLevel?.({ accessLevel: 'TRUSTED_CONTEXTS' });

let port = null;
let seq = 0;
let inFlight = 0;
let active = false;
let idleTimer = 0;
let lastMedia = null;
let lastVolume = null;
let lastMetrics = null; // this cast only, memory only
const pending = new Map();

function connect() {
  if (port) return port;
  port = chrome.runtime.connectNative(HOST);
  port.onMessage.addListener(onHostMessage);
  port.onDisconnect.addListener(() => {
    const err = chrome.runtime.lastError?.message || 'Helper stopped';
    const reason = /not found|forbidden/i.test(err) ? 'Helper not installed. Run install/install-macos.sh' : err;
    reset(reason);
    notify({ type: 'disconnected', reason });
  });
  // The extension and the helper are updated separately: say so when the
  // helper was left behind, instead of failing in odd ways later.
  rawCall({ type: 'hello' }, 5000)
    .then((r) => r.proto)
    .catch((e) => (e.code === 'TIMEOUT' || e.code === 'HOST' ? NEED_PROTO : 0)) // no answer at all is a different problem
    .then((proto) => {
      if (!(proto >= NEED_PROTO)) notify({ type: 'helper', outdated: true });
    });
  return port;
}

function reset(reason) {
  clearTimeout(idleTimer);
  port = null;
  active = false;
  lastMedia = null;
  lastMetrics = null;
  for (const p of pending.values()) p.reject(Object.assign(new Error(reason), { code: 'HOST' }));
  pending.clear();
}

function shutdown() {
  const p = port;
  reset('Stopped');
  p?.disconnect();
}

function armIdle() {
  clearTimeout(idleTimer);
  // Never while a request is running: a discover that ends during a slow cast
  // must not start the clock that kills it.
  if (!active && inFlight === 0) idleTimer = setTimeout(shutdown, IDLE_MS);
}

function call(msg, timeoutMs) {
  inFlight++;
  clearTimeout(idleTimer);
  return rawCall(msg, timeoutMs).finally(() => {
    inFlight--;
    armIdle();
  });
}

function rawCall(msg, timeoutMs) {
  return new Promise((resolve, reject) => {
    const id = ++seq;
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(Object.assign(new Error('Helper timed out'), { code: 'TIMEOUT' }));
    }, timeoutMs);
    pending.set(id, {
      resolve: (v) => (clearTimeout(timer), resolve(v)),
      reject: (e) => (clearTimeout(timer), reject(e)),
    });
    try {
      connect().postMessage({ ...msg, id });
    } catch (e) {
      // Port died between connect() and send: fail now, not after the timeout.
      clearTimeout(timer);
      pending.delete(id);
      reject(Object.assign(new Error('Helper is not running'), { code: 'HOST' }));
    }
  });
}

function onHostMessage(m) {
  if (!m || typeof m !== 'object') return;
  if (m.id) {
    const p = pending.get(m.id);
    if (!p) return;
    pending.delete(m.id);
    if (m.ok) p.resolve(m);
    else p.reject(Object.assign(new Error(m.error || 'Failed'), { code: m.code }));
    return;
  }
  if (m.type === 'device') cacheDevice(m.device);
  if (m.type === 'volume') lastVolume = m;
  if (m.type === 'metrics') lastMetrics = m;
  if (m.type === 'disconnected') {
    // Helper gave up on the TV (it already retried and revoked the proxy).
    active = false;
    lastMedia = null;
    lastMetrics = null;
    armIdle();
  }
  if (m.type === 'media') {
    // The TV gives the duration only with a video's first report, and a
    // position only when something changes. Keep the one and date the other,
    // so that a popup (also one opened later) can tell where playback is now.
    m = { ...m, duration: m.duration ?? lastMedia?.duration, at: Date.now() };
    lastMedia = m;
    if (m.state === 'IDLE' && FINAL_IDLE.has(m.idleReason)) {
      active = false;
      armIdle();
    }
  }
  notify(m);
}

function notify(m) {
  chrome.runtime.sendMessage(m).catch(() => {}); // popup may be closed
}

// Device strings come from the LAN. Bounded, typed, pruned, and written one
// at a time (each write is a read-modify-write of the whole list).
const MAX_DEVICES = 20;
const DEVICE_TTL = 30 * 24 * 3600 * 1000;
let storing = Promise.resolve();
function cacheDevice(d) {
  const str = (v) => typeof v === 'string' && v.length > 0 && v.length <= 128;
  if (!d || !str(d.id) || !str(d.name) || !str(d.host) || !Number.isInteger(d.port)) return;
  storing = storing
    .then(async () => {
      const { devices = {} } = await chrome.storage.local.get('devices');
      devices[d.id] = { id: d.id, name: d.name, model: str(d.model) ? d.model : '', host: d.host, port: d.port, known: d.known === true, seen: Date.now() };
      const kept = Object.values(devices)
        .filter((x) => Date.now() - x.seen < DEVICE_TTL)
        .sort((a, b) => b.seen - a.seen)
        .slice(0, MAX_DEVICES);
      await chrome.storage.local.set({ devices: Object.fromEntries(kept.map((x) => [x.id, x])) });
    })
    .catch(() => {});
}

async function handle(msg) {
  switch (msg?.cmd) {
    case 'discover':
      return call({ type: 'discover', timeoutMs: 1500 }, 6000);
    case 'cast': {
      const r = await call({ type: 'cast', device: msg.device, media: msg.media }, 90_000);
      active = true;
      lastMetrics = null; // a new cast starts its numbers from zero
      clearTimeout(idleTimer);
      return r;
    }
    case 'control':
      try {
        return await call({ type: 'control', action: msg.action, value: msg.value ?? 0 }, 10_000);
      } finally {
        // Even if the TV never answered: Stop must always take the helper and
        // its proxy down.
        if (msg.action === 'stop') shutdown();
      }
    case 'forget':
      return call({ type: 'forget', device: msg.device }, 5000);
    case 'state':
      return { active, media: lastMedia, volume: lastVolume, metrics: lastMetrics };
    default:
      throw new Error('Unknown command');
  }
}

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  // Only our own extension pages; content scripts and web pages are refused.
  if (sender.id !== chrome.runtime.id || sender.tab || !sender.url?.startsWith(chrome.runtime.getURL(''))) return false;
  handle(msg).then(
    (r) => reply({ ...r, ok: true }),
    (e) => reply({ ok: false, error: e.message, code: e.code }),
  );
  return true;
});

// The page watcher (watch.js) runs only on sites the user explicitly chose to
// watch. Origins granted for other reasons (scanning an iframe, cookies, or
// "on all sites" in chrome://extensions) never get a content script.
let syncing = Promise.resolve();
function syncWatcher() {
  return (syncing = syncing
    .then(async () => {
      const [{ origins = [] }, { watchOrigins = [], auto }] = await Promise.all([chrome.permissions.getAll(), chrome.storage.local.get(['watchOrigins', 'auto'])]);
      const exact = /^https:\/\/[^*/]+\/\*$/;
      let matches = watchOrigins.filter((o) => exact.test(o) && origins.includes(o));
      if (matches.length !== watchOrigins.length) await chrome.storage.local.set({ watchOrigins: matches });
      // Automatic mode: the user's own switch plus Chrome's all-sites grant.
      // Either one alone (say, "on all sites" picked in chrome://extensions)
      // does not put a script on every page.
      if (auto && origins.includes('https://*/*')) matches = ['https://*/*'];
      else if (auto) await chrome.storage.local.set({ auto: false });
      await chrome.scripting.unregisterContentScripts({ ids: ['watch'] }).catch(() => {});
      if (matches.length) {
        await chrome.scripting.registerContentScripts([
          { id: 'watch', js: ['watch.js'], matches, allFrames: true, runAt: 'document_start', world: 'ISOLATED' },
        ]);
      }
    })
    .catch(() => {}));
}
chrome.runtime.onInstalled.addListener(syncWatcher);
chrome.permissions.onAdded.addListener(async (added) => {
  const { pendingReload: p } = await chrome.storage.session.get('pendingReload');
  const mine = p && added.origins?.includes(p.origin);
  if (mine && p.watch) {
    const { watchOrigins = [] } = await chrome.storage.local.get('watchOrigins');
    await chrome.storage.local.set({ watchOrigins: [...new Set([...watchOrigins, p.origin])].slice(-50) });
  }
  await syncWatcher(); // the watcher must be in place before the page loads again
  if (!mine) return;
  await chrome.storage.session.remove('pendingReload');
  // Only if the tab is still on the site the user granted.
  const tab = await chrome.tabs.get(p.tabId).catch(() => null);
  if (tab?.url && `${new URL(tab.url).origin}/*` === p.origin) chrome.tabs.reload(p.tabId).catch(() => {});
});
chrome.permissions.onRemoved.addListener(syncWatcher);
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.auto) syncWatcher();
});

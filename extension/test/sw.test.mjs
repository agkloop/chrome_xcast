// sw.js is a plain service-worker script, not a module: each test runs it in a
// vm context of its own with a stub `chrome`, plays the native helper by hand
// and asks for `state` the way the popup does.

import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../sw.js', import.meta.url), 'utf8');
const POPUP = { id: 'x', url: 'chrome-extension://x/popup.html' };

const settle = () => new Promise((resolve) => setImmediate(resolve));

function load() {
  const posted = []; // what sw.js sent to the helper
  const sent = []; // what it broadcast to the popup
  let fromHost, onMessage;
  const ev = () => ({ addListener() {} });
  const chrome = {
    storage: {
      local: { setAccessLevel() {}, get: async () => ({}), set: async () => {} },
      session: { get: async () => ({}), remove: async () => {} },
      onChanged: ev(),
    },
    runtime: {
      id: 'x',
      lastError: null,
      getURL: (p) => `chrome-extension://x/${p}`,
      onInstalled: ev(),
      connectNative: () => ({
        onMessage: { addListener: (f) => (fromHost = f) },
        onDisconnect: ev(),
        postMessage: (m) => posted.push(m),
        disconnect() {},
      }),
      sendMessage: async (m) => void sent.push(m),
      onMessage: { addListener: (f) => (onMessage = f) },
    },
    permissions: { onAdded: ev(), onRemoved: ev(), getAll: async () => ({}) },
    scripting: {},
    tabs: {},
  };
  // sw.js arms a timeout per helper call and one for idle shutdown. They are
  // real but unref'd, so a test that leaves one pending does not hold node open.
  const timeout = (fn, ms) => setTimeout(fn, ms).unref();
  vm.runInNewContext(source, { chrome, setTimeout: timeout, clearTimeout, Date, URL, console }, { filename: 'sw.js' });

  const ask = (msg, sender = POPUP) => new Promise((resolve) => onMessage(msg, sender, resolve));
  return { posted, sent, ask, onMessage, host: (m) => fromHost(m) };
}

// Opens the native port with a cast and lets the helper accept it: from here
// on sw.js is in the state it has while something is playing.
async function casting() {
  const sw = load();
  const cast = sw.ask({ cmd: 'cast', device: {}, media: {} });
  await settle();
  sw.host({ id: sw.posted[0].id, ok: true, mode: 'proxy' });
  assert.equal((await cast).ok, true);
  return sw;
}

test('a media report is dated when it arrives', async () => {
  const sw = await casting();
  const before = Date.now();
  sw.host({ type: 'media', state: 'PLAYING', currentTime: 12.5, idleReason: '', duration: 600 });
  const after = Date.now();

  const { active, media } = await sw.ask({ cmd: 'state' });
  assert.equal(active, true);
  assert.equal(media.currentTime, 12.5);
  assert.ok(Number.isFinite(media.at) && media.at >= before && media.at <= after, `at = ${media.at}`);
  assert.equal(sw.sent.at(-1).at, media.at, 'the open popup gets the same date');
});

test('the duration is kept when a later report leaves it out', async () => {
  const sw = await casting();
  sw.host({ type: 'media', state: 'BUFFERING', currentTime: 0, idleReason: '', duration: 600 });
  sw.host({ type: 'media', state: 'PLAYING', currentTime: 12.5, idleReason: '' });

  const { media } = await sw.ask({ cmd: 'state' });
  assert.equal(media.state, 'PLAYING');
  assert.equal(media.duration, 600);
  assert.equal(sw.sent.at(-1).duration, 600, 'the open popup gets it too');
});

test('a duration of 0 replaces the old one', async () => {
  const sw = await casting();
  sw.host({ type: 'media', state: 'PLAYING', currentTime: 12.5, idleReason: '', duration: 600 });
  // A live stream: 0 is a value, not a missing one.
  sw.host({ type: 'media', state: 'PLAYING', currentTime: 3, idleReason: '', duration: 0 });
  sw.host({ type: 'media', state: 'PAUSED', currentTime: 4, idleReason: '' });

  const { media } = await sw.ask({ cmd: 'state' });
  assert.equal(media.duration, 0);
});

test('nothing is carried across a disconnect', async () => {
  const sw = await casting();
  sw.host({ type: 'media', state: 'PLAYING', currentTime: 12.5, idleReason: '', duration: 600 });
  sw.host({ type: 'disconnected' });

  let state = await sw.ask({ cmd: 'state' });
  assert.equal(state.active, false);
  assert.equal(state.media, null);

  sw.host({ type: 'media', state: 'PLAYING', currentTime: 1, idleReason: '' });
  state = await sw.ask({ cmd: 'state' });
  assert.equal(state.media.duration, undefined);
});

test('a final IDLE ends the cast', async () => {
  const sw = await casting();
  sw.host({ type: 'media', state: 'IDLE', currentTime: 0, idleReason: '' }); // between two videos
  assert.equal((await sw.ask({ cmd: 'state' })).active, true);

  sw.host({ type: 'media', state: 'IDLE', currentTime: 0, idleReason: 'FINISHED' });
  const { active, media } = await sw.ask({ cmd: 'state' });
  assert.equal(active, false);
  assert.equal(media.idleReason, 'FINISHED');
});

test('only our own extension pages are answered', async () => {
  const sw = load();
  const strangers = {
    'a content script': { ...POPUP, tab: { id: 1 } },
    'another extension': { ...POPUP, id: 'y' },
    'a web page': { id: 'x', url: 'https://example.com/' },
  };
  for (const [who, sender] of Object.entries(strangers)) {
    let replied = false;
    assert.equal(sw.onMessage({ cmd: 'state' }, sender, () => (replied = true)), false, who);
    await settle();
    assert.equal(replied, false, who);
  }
  assert.equal(sw.posted.length, 0, 'and none of them woke the helper');

  let answer;
  assert.equal(sw.onMessage({ cmd: 'state' }, POPUP, (r) => (answer = r)), true);
  await settle();
  assert.equal(answer.ok, true);
});

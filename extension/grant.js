// A tab does not close when Chrome's permission prompt takes focus, which an
// action popup may. Opened only by the popup, as a fallback.
const q = new URLSearchParams(location.hash.slice(1));
const origin = q.get('origin') || '';
const tabId = Number(q.get('tab'));
const watch = q.get('watch') === '1';
const all = q.get('all') === '1';
const what = document.getElementById('what');
const allow = document.getElementById('allow');
const result = document.getElementById('result');
const say = (text, kind = '') => {
  result.textContent = text;
  result.dataset.kind = kind;
};

// Either exactly one https site, or the explicit "all sites" switch from the
// popup. Nothing in between. Chrome's own prompt states the scope again.
if (!all && !/^https:\/\/[^/*\s]+$/.test(origin)) {
  what.textContent = 'This page was opened without a valid site to ask about.';
  allow.hidden = true;
} else {
  const host = all ? '' : new URL(origin).host;
  what.textContent = all
    ? 'Turn on automatic mode? XCast may then look for video on every HTTPS site and inside embedded players, without asking per site. It still only reads a page when you click its icon.'
    : watch
    ? `Let XCast watch ${host} for video while you browse it?`
    : `Let XCast look for the video inside the embedded player from ${host}?`;
  allow.addEventListener('click', () => {
    const pattern = all ? 'https://*/*' : `${origin}/*`;
    const asking = chrome.permissions.request({ origins: [pattern] }); // first, inside the click
    if (watch && Number.isInteger(tabId)) chrome.storage.session.set({ pendingReload: { tabId, origin: pattern, watch: true } }).catch(() => {});
    say('Click Allow in Chrome’s prompt.');
    asking.then(
      (granted) => {
        if (!granted) {
          chrome.storage.session.remove('pendingReload');
          return say('Access was not allowed.', 'err');
        }
        if (all) chrome.storage.local.set({ auto: true });
        allow.hidden = true;
        say('Done. Go back to the video and click the XCast icon again.', 'ok');
        if (Number.isInteger(tabId)) chrome.tabs.update(tabId, { active: true }).catch(() => {});
        setTimeout(() => window.close(), 2500);
      },
      (e) => say(`Chrome refused the request: ${e.message}`, 'err'),
    );
  });
}

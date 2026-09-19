// Registered only for sites the user granted. Records media URLs from page
// load on, so a manifest request is never lost to the browser's 250-entry
// resource timing buffer. Runs in the extension's isolated world: the page
// cannot read or tamper with the list, and nothing leaves the tab until the
// user opens the popup.
(() => {
  if (globalThis.__xcastSeen) return;
  const MEDIA = /\.(m3u8|mpd|mp4|m4v|webm|mov)(?:[?#]|$)/i;
  // Many hosts serve playlists from extension-less addresses; the response
  // type (exposed by newer Chrome, when the server allows it) still tells.
  const TYPE = /mpegurl|dash\+xml|^video\//i;
  const seen = (globalThis.__xcastSeen = []);
  try {
    new PerformanceObserver((list) => {
      for (const e of list.getEntries()) {
        if (seen.length < 200 && (MEDIA.test(e.name) || TYPE.test(e.contentType || '')) && !seen.includes(e.name)) seen.push(e.name);
      }
    }).observe({ type: 'resource', buffered: true });
  } catch {}
})();

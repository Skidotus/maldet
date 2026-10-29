/*
 * MalDet — background worker.
 *
 * Exists for one reason: github.com is HTTPS and a MalDet deployment may be
 * plain HTTP. A page-context fetch across that boundary is mixed content and
 * the browser refuses it. Extension background contexts are not bound by the
 * page's origin, so the request lives here.
 *
 * If a browser blocks it anyway, nothing breaks: lookup() resolves to
 * { ok: false } and the button falls back to a plain "Scan with MalDet"
 * link. Opening a tab at an http:// URL is never blocked, so the extension
 * stays useful even in the worst case -- it just stops knowing when a repo
 * was last scanned.
 */

const DEFAULT_BASE = "http://103.233.1.97:5000";

// Generous enough for a cold container, short enough that the button is not
// stuck saying "Scan with MalDet" long after the answer would have mattered.
const TIMEOUT_MS = 6000;

async function baseUrl() {
  try {
    const stored = await chrome.storage.sync.get("serverUrl");
    return (stored.serverUrl || DEFAULT_BASE).replace(/\/+$/, "");
  } catch {
    return DEFAULT_BASE;
  }
}

async function getJSON(url) {
  // AbortController rather than letting it hang: a service worker that is
  // waiting on a dead host keeps the button in its placeholder state.
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), TIMEOUT_MS);
  try {
    const resp = await fetch(url, {
      signal: abort.signal,
      // No cookies, no credentials -- the endpoint is public and read-only,
      // and sending none keeps it a CORS "simple request" with no preflight.
      credentials: "omit",
      cache: "no-store",
    });
    if (!resp.ok) {
      return { ok: false, error: `HTTP ${resp.status}` };
    }
    return { ok: true, data: await resp.json() };
  } catch (err) {
    // The interesting case lands here: a mixed-content refusal looks like
    // an ordinary TypeError, so the message is kept for the options page's
    // connection test to show.
    return { ok: false, error: String((err && err.message) || err) };
  } finally {
    clearTimeout(timer);
  }
}

async function lookup(repo) {
  const base = await baseUrl();
  return getJSON(`${base}/api/extension/lookup?repo=${encodeURIComponent(repo)}`);
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || !msg.type) return;

  if (msg.type === "lookup") {
    lookup(msg.repo).then(sendResponse);
    return true;                       // keeps the channel open for async
  }

  if (msg.type === "openScan") {
    // The fallback path when the lookup never answered. Navigating a tab to
    // http:// is allowed regardless of what blocked the fetch.
    baseUrl().then((base) => {
      chrome.tabs.create({
        url: `${base}/scan?repo=${encodeURIComponent(msg.repo)}`,
      });
    });
    return true;
  }

  if (msg.type === "probe") {
    // Used by the options page to tell the user which of the three possible
    // worlds they are in: reachable, unreachable, or blocked.
    lookup("psf/requests").then(sendResponse);
    return true;
  }
});

// No popup on the toolbar icon; clicking opens MalDet itself.
chrome.action.onClicked.addListener(async () => {
  chrome.tabs.create({ url: await baseUrl() });
});

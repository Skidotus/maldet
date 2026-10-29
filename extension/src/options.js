/*
 * Options page. The "Test connection" button is not decoration: whether a
 * browser will let an extension reach a plain-HTTP MalDet from an HTTPS
 * page is version- and browser-dependent, and this is how you find out
 * which of the three outcomes you are in without reading a console.
 */

/*
 * Firefox exposes promise-based APIs as `browser`; its `chrome` object is a
 * callback-style compatibility alias, so awaiting chrome.storage there is
 * not safe. Chrome has no `browser`, and its MV3 APIs do return promises.
 * Event listeners and callback-style sendMessage behave the same in both and
 * are left on `chrome`.
 */
const api = typeof browser !== "undefined" ? browser : chrome;

const DEFAULT_BASE = "http://103.233.1.97:5000";

const $url = document.getElementById("serverUrl");
const $result = document.getElementById("result");

function show(message, good) {
  $result.textContent = message;
  $result.className = good ? "ok" : "bad";
  $result.style.display = "block";
}

function normalise(raw) {
  const text = (raw || "").trim().replace(/\/+$/, "");
  if (!text) return null;
  try {
    const url = new URL(text);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    return url.origin;
  } catch {
    return null;
  }
}

api.storage.sync.get("serverUrl").then(({ serverUrl }) => {
  $url.value = serverUrl || DEFAULT_BASE;
});

document.getElementById("save").addEventListener("click", async () => {
  const origin = normalise($url.value);
  if (!origin) {
    show("That does not look like a URL. Example: http://103.233.1.97:5000", false);
    return;
  }

  /*
   * The manifest only declares the addresses MalDet is normally at. Pointing
   * the extension somewhere else needs that host's permission, and asking
   * for it must happen inside a click -- which is why this lives on the
   * button rather than running on save-as-you-type.
   */
  try {
    const pattern = `${origin}/*`;
    const already = await api.permissions.contains({ origins: [pattern] });
    if (!already) {
      const granted = await api.permissions.request({ origins: [pattern] });
      if (!granted) {
        show(
          "Saved, but permission for that address was declined, so lookups " +
          "will fail. Re-save and accept the prompt to enable them.",
          false
        );
      }
    }
  } catch (err) {
    // Firefox MV3 treats host permissions as opt-in and may refuse the
    // request outside its own UI; not fatal, so say so rather than stop.
    show(`Saved. Permission request unavailable here (${err}).`, false);
  }

  $url.value = origin;
  await api.storage.sync.set({ serverUrl: origin });
  show(`Saved. Using ${origin}`, true);
});

// The toolbar icon opens this popup rather than MalDet, so the site needs a
// link of its own. Resolved at click time so it always follows the saved
// address rather than whatever it was when the popup opened.
document.getElementById("open").addEventListener("click", async (e) => {
  e.preventDefault();
  const { serverUrl } = await api.storage.sync.get("serverUrl");
  chrome.tabs.create({ url: serverUrl || DEFAULT_BASE });
  window.close();
});

document.getElementById("test").addEventListener("click", () => {
  show("Testing…", true);
  chrome.runtime.sendMessage({ type: "probe" }, (response) => {
    if (chrome.runtime.lastError) {
      show(`Could not reach the extension's background worker: ${chrome.runtime.lastError.message}`, false);
      return;
    }
    if (response && response.ok) {
      show(
        "Connected. MalDet answered, so the button will show when each " +
        "repository was last scanned.",
        true
      );
      return;
    }

    const error = (response && response.error) || "no response";
    const where = (response && response.url) || "(unknown URL)";
    const took = response && response.ms;
    // A refusal comes back in milliseconds; a block looks like a stall that
    // only ends when our own timeout fires. Showing the time is what lets
    // those two be told apart.
    const timing = took >= 5000
      ? `\n\nIt hung for ${took}ms rather than failing immediately, which is what a blocked request looks like \u2014 not a server that is switched off.`
      : `\n\nIt failed after ${took}ms.`;
    /*
     * A mixed-content refusal arrives as an opaque network TypeError, so it
     * cannot be told apart from "the server is off" by the error alone.
     * Both possibilities get named rather than guessing at one.
     */
    show(
      `Could not reach MalDet (${error})\nTried: ${where}${timing}\n\n` +
      "Either the server is not running, or this browser blocked the " +
      "request because MalDet is served over plain http:// while GitHub " +
      "is https://.\n\n" +
      "The extension still works: the button falls back to a plain " +
      "\"Scan with MalDet\" link. To get scan dates back, serve MalDet " +
      "over https://.",
      false
    );
  });
});

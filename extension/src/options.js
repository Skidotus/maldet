/*
 * The toolbar popup.
 *
 * Its job is to answer "what about the repository I am looking at" in one
 * click, so the current page comes first and the settings sit behind a
 * disclosure. It used to be the settings form and nothing else, which meant
 * the one obvious thing to click told you nothing about the page you were
 * on.
 */

/*
 * Firefox exposes promise-based APIs as `browser`; its `chrome` object is a
 * callback-style compatibility alias, so awaiting chrome.storage there is
 * not safe. Chrome has no `browser`, and its MV3 APIs do return promises.
 */
const api = typeof browser !== "undefined" ? browser : chrome;

const DEFAULT_BASE = "https://maldet-fyp.my";

const $context = document.getElementById("context");
const $url = document.getElementById("serverUrl");
const $result = document.getElementById("result");

function show(message, good) {
  $result.textContent = message;
  $result.className = good ? "ok" : "bad";
  $result.style.display = "block";
}

async function baseUrl() {
  const { serverUrl } = await api.storage.local.get("serverUrl");
  return serverUrl || DEFAULT_BASE;
}

/* ------------------------------------------------------------- rendering */

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text) node.textContent = text;
  return node;
}

function link(label, href, kind) {
  const a = el("a", `btn btn--${kind}`, label);
  a.href = href;
  a.target = "_blank";
  a.rel = "noopener noreferrer";
  // Firefox keeps the popup open behind the new tab otherwise, which looks
  // like the click did nothing.
  a.addEventListener("click", () => setTimeout(() => window.close(), 50));
  return a;
}

function renderEmpty(message, base) {
  const actions = el("div", "actions");
  actions.appendChild(link("Open MalDet", base, "ghost"));
  $context.replaceChildren(el("p", "empty", message), actions);
}

function renderRepo(repo, result, base) {
  const nodes = [el("p", "repo", repo)];
  const actions = el("div", "actions");

  if (result && result.known) {
    const status = el("p", "status", MalDetRepo.humanAge(result.days_since_scan));
    if (result.source_status === "gone") {
      status.className = "status warn";
      status.textContent = "no longer on GitHub — archived result";
    } else if (result.source_status === "renamed") {
      status.className = "status warn";
      status.textContent = `${MalDetRepo.humanAge(result.days_since_scan)} — since renamed`;
    } else if (result.stale) {
      status.className = "status stale";
      status.textContent += " — may be out of date";
    }
    nodes.push(status);

    actions.append(
      link("View report", result.detail_url, "primary"),
      // Deliberately the scan form rather than /rescan/<id>: a GET that
      // starts a scan is the bug that route still has, and this popup
      // should not be the thing that fires it.
      link("Scan again", `${base}/scan?repo=${encodeURIComponent(repo)}`, "ghost")
    );
  } else {
    const reachable = result !== undefined;
    nodes.push(
      el("p", "status", reachable ? "not scanned yet" : "could not reach MalDet")
    );
    actions.append(
      link(
        "Scan this repository",
        `${base}/scan?repo=${encodeURIComponent(repo)}`,
        "primary"
      )
    );
    if (!reachable) {
      const hint = el(
        "p",
        "hint",
        "Scanning still works. Check the server address below to show scan dates."
      );
      nodes.push(hint);
    }
  }

  nodes.push(actions);
  $context.replaceChildren(...nodes);
}

/* --------------------------------------------------------------- startup */

async function init() {
  const base = await baseUrl();

  $url.value = base;
  document.getElementById("active").textContent =
    (await api.storage.local.get("serverUrl")).serverUrl
      ? `Currently using ${base}`
      : `Currently using the default, ${DEFAULT_BASE}`;

  let repo = null;
  try {
    // tab.url is readable because github.com is in host_permissions; without
    // that grant it comes back undefined rather than throwing, which is why
    // this falls through to the empty state instead of failing.
    const [tab] = await api.tabs.query({ active: true, currentWindow: true });
    repo = MalDetRepo.fromUrl(tab && tab.url);
  } catch {
    repo = null;
  }

  if (!repo) {
    renderEmpty("Open a GitHub repository to check it.", base);
    return;
  }

  // Draw the repo immediately; the lookup only refines what is already
  // there, so the popup never sits blank waiting on the network.
  renderRepo(repo, undefined, base);

  chrome.runtime.sendMessage({ type: "lookup", repo }, (response) => {
    if (chrome.runtime.lastError) return;
    renderRepo(repo, response && response.ok ? response.data : undefined, base);
  });
}

init();

/* -------------------------------------------------------------- settings */

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

document.getElementById("save").addEventListener("click", async () => {
  const origin = normalise($url.value);
  if (!origin) {
    show("That does not look like a URL. Example: https://maldet-fyp.my", false);
    return;
  }

  /*
   * The manifest only declares the addresses MalDet is normally at.
   * Pointing it somewhere else needs that host's permission, and asking for
   * it must happen inside a click -- hence here rather than on save-as-you-type.
   */
  try {
    const pattern = `${origin}/*`;
    if (!(await api.permissions.contains({ origins: [pattern] }))) {
      const granted = await api.permissions.request({ origins: [pattern] });
      if (!granted) {
        show("Saved, but permission for that address was declined, so lookups will fail.", false);
      }
    }
  } catch (err) {
    show(`Saved. Permission request unavailable here (${err}).`, false);
  }

  await api.storage.local.set({ serverUrl: origin });

  // Read back rather than trusting the write: a storage backend that
  // rejects silently is how an earlier version came to report "Saved" while
  // every lookup kept going to the old address.
  const check = await api.storage.local.get("serverUrl");
  if (check.serverUrl !== origin) {
    show(`Could not save. Storage still holds ${check.serverUrl || "(nothing)"}.`, false);
    return;
  }
  $url.value = origin;
  show(`Saved. Lookups now go to ${origin}`, true);
  init();
});

document.getElementById("test").addEventListener("click", () => {
  show("Testing…", true);
  chrome.runtime.sendMessage({ type: "probe" }, (response) => {
    if (chrome.runtime.lastError) {
      show(`Could not reach the background worker: ${chrome.runtime.lastError.message}`, false);
      return;
    }
    if (response && response.ok) {
      show("Connected. Scan dates will show on repository pages.", true);
      return;
    }

    const error = (response && response.error) || "no response";
    const where = (response && response.url) || "(unknown URL)";
    const took = response && response.ms;
    /*
     * A refused request fails in milliseconds; one that sat until our own
     * timeout fired never reached the host. Showing the time is what lets
     * a server that is switched off be told apart from a browser that
     * declined to send the request at all.
     */
    const timing =
      took >= 5000
        ? `\n\nIt hung for ${took}ms rather than failing immediately, which is what a blocked request looks like — not a server that is switched off.`
        : `\n\nIt failed after ${took}ms.`;

    show(
      `Could not reach MalDet (${error})\nTried: ${where}${timing}\n\n` +
        "Scanning still works — the buttons open MalDet directly. Only the " +
        "scan dates need this connection. A plain http:// address on a public " +
        "IP is refused by the browser; an https:// one is not.",
      false
    );
  });
});

/*
 * MalDet — injects a "Scan with MalDet" button into GitHub repository pages.
 *
 * The button answers the question you actually have while looking at a repo:
 * has anyone checked this, and how long ago. It never shows a risk level --
 * that is what the report is for, and a score on a button invites being read
 * without the context underneath it.
 *
 * Nothing here talks to the network. The content script runs in the page's
 * context, and the page is HTTPS while MalDet may be plain HTTP; the fetch
 * lives in background.js, where that is not the page's problem.
 */
(() => {
  "use strict";

  const BUTTON_ID = "maldet-button";
  const WRAP_ID = "maldet-wrap";

  // Deliberately always on. When this does not appear, the question is
  // always "did the content script run at all", and a silent extension
  // cannot answer it. Filter the console on "MalDet".
  const log = (...args) => console.info("[MalDet]", ...args);
  log("content script loaded on", location.pathname);

  /*
   * github.com/<a>/<b> matches plenty of pages that are not repositories.
   * Without this list the button appears on your own settings page and
   * offers to scan "settings/profile".
   */
  const RESERVED_OWNERS = new Set([
    "settings", "orgs", "organizations", "features", "marketplace", "topics",
    "sponsors", "collections", "events", "explore", "notifications", "issues",
    "pulls", "codespaces", "new", "login", "logout", "join", "about",
    "pricing", "security", "enterprise", "apps", "site", "contact",
    "dashboard", "search", "trending", "stars", "watching", "account",
    "readme", "home", "customer-stories", "sessions", "signup", "github-copilot",
  ]);

  /* ---------------------------------------------------------------- repo */

  /*
   * Three ways to name the repository, most trustworthy first. GitHub's DOM
   * is not a public API, so no single one of these is worth depending on;
   * the path is the last resort because it is the only one that can be
   * right about the URL and wrong about the page.
   */
  function repoFromMeta() {
    const el = document.querySelector(
      'meta[name="octolytics-dimension-repository_nwo"]'
    );
    return el && el.content ? el.content.trim() : null;
  }

  function repoFromCanonical() {
    const el = document.querySelector('link[rel="canonical"]');
    if (!el || !el.href) return null;
    try {
      const parts = new URL(el.href).pathname.split("/").filter(Boolean);
      return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : null;
    } catch {
      return null;
    }
  }

  function repoFromPath() {
    const parts = location.pathname.split("/").filter(Boolean);
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : null;
  }

  function looksLikeRepo(slug) {
    if (!slug) return false;
    const [owner, name] = slug.split("/");
    if (!owner || !name) return false;
    if (RESERVED_OWNERS.has(owner.toLowerCase())) return false;
    // Mirrors the server's parser so the two cannot disagree about what
    // counts as a repository.
    return (
      /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(owner) &&
      /^[A-Za-z0-9._-]{1,100}$/.test(name) &&
      name !== "." &&
      name !== ".."
    );
  }

  function currentRepo() {
    for (const read of [repoFromMeta, repoFromCanonical, repoFromPath]) {
      const slug = read();
      if (looksLikeRepo(slug)) return slug;
    }
    return null;
  }

  /* ------------------------------------------------------------- placing */

  /*
   * Preferred homes for the button, newest GitHub first. Found by reading
   * the HTML github.com actually serves, not from documentation -- none of
   * this is a public API, which is why there is a list and a fallback
   * rather than one selector and crossed fingers.
   *
   * repo-header-actions is the <ul> holding Watch / Fork / Star, so the
   * button lands beside them. The rest are older layouts, kept because they
   * cost nothing and this extension will outlive at least one redesign.
   */
  const ANCHORS = [
    '[data-testid="repo-header-actions"]',
    "#repository-details-container ul",
    "ul.pagehead-actions",
    '[data-testid="repository-container-header"] ul',
  ];

  function tryAnchor(wrap) {
    for (const selector of ANCHORS) {
      const host = document.querySelector(selector);
      if (!host) continue;
      wrap.classList.remove("maldet-wrap--floating");
      if (host.tagName === "UL") {
        const li = document.createElement("li");
        li.appendChild(wrap);
        host.prepend(li);
      } else {
        host.prepend(wrap);
      }
      log("placed in", selector);
      return true;
    }
    return false;
  }

  /*
   * The floating fallback carries its own inline styles as well as its
   * class. The class alone was not enough: if the injected stylesheet does
   * not apply for any reason, an unpositioned element appended to <body>
   * sits below the entire page and reads as "the extension did nothing".
   * These few properties are the ones that make it visible at all.
   */
  function floatIt(wrap) {
    wrap.classList.add("maldet-wrap--floating");
    Object.assign(wrap.style, {
      position: "fixed",
      right: "16px",
      bottom: "16px",
      zIndex: "2147483000",
      display: "inline-flex",
    });
    document.body.appendChild(wrap);
    log("no GitHub anchor matched — using the floating fallback");
  }

  function placeButton(wrap) {
    if (tryAnchor(wrap)) return true;

    /*
     * GitHub renders the repository header client-side, so at document_idle
     * the anchor often does not exist yet. Retry briefly before giving up
     * on it -- without this the button is always a corner chip, even on
     * pages where it could have sat in the header.
     */
    let attempts = 0;
    const retry = setInterval(() => {
      attempts += 1;
      if (!document.body.contains(wrap) && !wrap.isConnected) {
        clearInterval(retry);
        return;
      }
      if (tryAnchor(wrap)) {
        wrap.removeAttribute("style");
        clearInterval(retry);
      } else if (attempts >= 10) {
        clearInterval(retry);
      }
    }, 300);

    floatIt(wrap);
    return false;
  }

  /* ------------------------------------------------------------ drawing */

  function humanAge(days) {
    if (days === null || days === undefined) return "date unknown";
    if (days <= 0) return "scanned today";
    if (days === 1) return "scanned yesterday";
    if (days < 30) return `scanned ${days} days ago`;
    if (days < 365) {
      const months = Math.round(days / 30);
      return `scanned ${months} month${months === 1 ? "" : "s"} ago`;
    }
    const years = Math.round(days / 365);
    return `scanned ${years} year${years === 1 ? "" : "s"} ago`;
  }

  function draw(repo, result) {
    document.getElementById(WRAP_ID)?.remove();

    const wrap = document.createElement("span");
    wrap.id = WRAP_ID;
    wrap.className = "maldet-wrap";

    const a = document.createElement("a");
    a.id = BUTTON_ID;
    a.className = "maldet-button";
    a.target = "_blank";
    a.rel = "noopener noreferrer";

    const icon = document.createElement("span");
    icon.className = "maldet-button__icon";
    icon.textContent = "◎";
    icon.setAttribute("aria-hidden", "true");

    const label = document.createElement("span");
    label.className = "maldet-button__label";

    let target = null;

    if (result && result.known) {
      target = result.detail_url;
      label.textContent = `MalDet · ${humanAge(result.days_since_scan)}`;
      a.title =
        `This repository was last scanned on ${result.scanned_at_human}` +
        (result.stale
          ? ". That was a while ago, so the findings may be out of date. " +
            "Open the report to view them, or rescan for current results."
          : ". Open the report to view the findings.");
      if (result.stale) a.classList.add("maldet-button--stale");
      if (result.source_status === "gone") {
        a.classList.add("maldet-button--warn");
        label.textContent = "MalDet · archived result";
        a.title =
          "This repository is no longer on GitHub. MalDet still holds the " +
          "findings from its last scan, but they cannot be refreshed.";
      } else if (result.source_status === "renamed") {
        a.classList.add("maldet-button--warn");
        a.title =
          "This repository was renamed after the scan. The stored findings " +
          "are for the original name.";
      }
    } else {
      // Covers both "we asked and it is not in the database" and "we could
      // not ask at all". Either way the useful offer is the same one.
      // Tracked in a variable, not by reading a.href back: assigning null
      // to .href stores the string "null", which then resolves to a real
      // URL, so the "no link" test below would never fire.
      target = (result && result.scan_url) || null;
      label.textContent = "Scan with MalDet";
      a.title = "Check this repository with MalDet.";
      if (!target) {
        a.classList.add("maldet-button--offline");
        a.title =
          "MalDet could not be reached. Check the server address in the " +
          "extension's options.";
      }
    }

    if (target) {
      a.href = target;
    } else {
      // No URL, because the lookup never answered. Still clickable: the
      // background knows the configured address and can open the tab.
      a.href = "#";
      a.addEventListener("click", (e) => {
        e.preventDefault();
        chrome.runtime.sendMessage({ type: "openScan", repo });
      });
    }

    a.appendChild(icon);
    a.appendChild(label);
    wrap.appendChild(a);
    placeButton(wrap);
  }

  /* ------------------------------------------------------------- driving */

  let lastRendered = null;

  function update(force) {
    const repo = currentRepo();

    if (!repo) {
      document.getElementById(WRAP_ID)?.remove();
      if (lastRendered) log("left a repository page, button removed");
      lastRendered = null;
      return;
    }
    if (!force && repo === lastRendered && document.getElementById(WRAP_ID)) {
      return;
    }
    lastRendered = repo;
    log("repository detected:", repo);

    // Draw immediately in its unknown state, then correct it when the
    // lookup answers. A button that appears late is a button people miss.
    draw(repo, null);

    chrome.runtime.sendMessage({ type: "lookup", repo }, (response) => {
      if (chrome.runtime.lastError) return;        // worker asleep or gone
      if (currentRepo() !== repo) return;          // navigated away mid-flight
      if (response && response.ok) {
        log("lookup ok:", repo, response.data.known ? "known" : "not scanned");
      } else {
        log("lookup failed:", (response && response.error) || "no response",
            "| url:", (response && response.url) || "(unknown)",
            "| after:", (response && response.ms) + "ms",
            "- falling back to a plain scan link");
      }
      draw(repo, response && response.ok ? response.data : null);
    });
  }

  /*
   * GitHub is a single-page app: clicking through to another repository
   * does not re-run a content script. Without this the button keeps the
   * first repository it ever saw and links you to the wrong report.
   *
   * Three overlapping signals, because none is reliable alone: Turbo's own
   * event, a DOM observer, and a cheap href poll as the backstop.
   */
  document.addEventListener("turbo:load", () => update(true));
  document.addEventListener("pjax:end", () => update(true));

  let href = location.href;
  const onMutate = () => {
    if (location.href !== href) {
      href = location.href;
      update(true);
    } else {
      update(false);
    }
  };

  let queued = false;
  new MutationObserver(() => {
    if (queued) return;
    queued = true;
    setTimeout(() => {
      queued = false;
      onMutate();
    }, 300);
  }).observe(document.documentElement, { childList: true, subtree: true });

  setInterval(onMutate, 2000);
  update(true);
})();

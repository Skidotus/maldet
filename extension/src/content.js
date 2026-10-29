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
   * Preferred homes for the button, in order. These are GitHub's own class
   * and id names, which they change without warning -- hence the fallback
   * below rather than a single selector and crossed fingers.
   */
  const ANCHORS = [
    "#repository-details-container ul",
    "ul.pagehead-actions",
    '[data-testid="repository-container-header"] ul',
    "#repo-content-pjax-container > div > div",
  ];

  function placeButton(wrap) {
    for (const selector of ANCHORS) {
      const host = document.querySelector(selector);
      if (host) {
        wrap.classList.remove("maldet-wrap--floating");
        if (host.tagName === "UL") {
          const li = document.createElement("li");
          li.appendChild(wrap);
          host.prepend(li);
        } else {
          host.prepend(wrap);
        }
        return true;
      }
    }
    // Nothing matched: GitHub has restyled, or this is a page shape we have
    // not seen. A corner button is worse-looking but still works, which
    // beats the feature silently disappearing.
    wrap.classList.add("maldet-wrap--floating");
    document.body.appendChild(wrap);
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

    if (result && result.known) {
      a.href = result.detail_url;
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
      a.href = (result && result.scan_url) || null;
      label.textContent = "Scan with MalDet";
      a.title = "Check this repository with MalDet.";
      if (!a.href) {
        a.classList.add("maldet-button--offline");
        a.title =
          "MalDet could not be reached. Check the server address in the " +
          "extension's options.";
      }
    }

    // A link with no href is not focusable and not clickable; ask the
    // background for a fallback URL rather than rendering a dead button.
    if (!a.href) {
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
      lastRendered = null;
      return;
    }
    if (!force && repo === lastRendered && document.getElementById(WRAP_ID)) {
      return;
    }
    lastRendered = repo;

    // Draw immediately in its unknown state, then correct it when the
    // lookup answers. A button that appears late is a button people miss.
    draw(repo, null);

    chrome.runtime.sendMessage({ type: "lookup", repo }, (response) => {
      if (chrome.runtime.lastError) return;        // worker asleep or gone
      if (currentRepo() !== repo) return;          // navigated away mid-flight
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

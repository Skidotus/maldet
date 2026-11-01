/*
 * What counts as a GitHub repository, in one place.
 *
 * Loaded by both the content script and the popup. They used to each have
 * their own copy of these rules, which is how an extension ends up offering
 * to scan "settings/profile" from one surface and not the other. The server
 * has a third copy of the same rules in app.py:parse_repo_slug(), and a test
 * reads the patterns out of this file to check the two still agree.
 */
var MalDetRepo = (() => {
  "use strict";

  /*
   * github.com/<a>/<b> matches plenty of pages that are not repositories.
   * Without this list the button appears on your own settings page.
   */
  const RESERVED_OWNERS = new Set([
    "settings", "orgs", "organizations", "features", "marketplace", "topics",
    "sponsors", "collections", "events", "explore", "notifications", "issues",
    "pulls", "codespaces", "new", "login", "logout", "join", "about",
    "pricing", "security", "enterprise", "apps", "site", "contact",
    "dashboard", "search", "trending", "stars", "watching", "account",
    "readme", "home", "customer-stories", "sessions", "signup", "github-copilot",
  ]);

  // Mirrors app.py's _OWNER_RE and _NAME_RE: GitHub's own naming rules.
  const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
  const NAME_RE = /^[A-Za-z0-9._-]{1,100}$/;

  function isValid(slug) {
    if (!slug) return false;
    const [owner, name] = slug.split("/");
    if (!owner || !name) return false;
    if (RESERVED_OWNERS.has(owner.toLowerCase())) return false;
    if (name === "." || name === "..") return false;
    return OWNER_RE.test(owner) && NAME_RE.test(name);
  }

  /* "owner/repo" from a pathname, or null. */
  function fromPath(pathname) {
    const parts = String(pathname || "").split("/").filter(Boolean);
    if (parts.length < 2) return null;
    const slug = `${parts[0]}/${parts[1]}`;
    return isValid(slug) ? slug : null;
  }

  /* "owner/repo" from a full URL, or null. Only github.com counts. */
  function fromUrl(url) {
    try {
      const u = new URL(url);
      if (u.hostname !== "github.com" && u.hostname !== "www.github.com") {
        return null;
      }
      return fromPath(u.pathname);
    } catch {
      return null;
    }
  }

  /* How old a scan reads to a person. */
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

  /* ------------------------------------------------------------- icons */

  /*
   * Drawn, not typed. The glyphs these replace -- a circled bullet standing
   * in for the mark, a text star for the rating -- inherit whatever font the
   * host page happens to have, render at different weights on every
   * platform, and are read aloud by screen readers as "circled bullet".
   *
   * Built with createElementNS rather than innerHTML: a content script
   * assembling markup from strings is the pattern AMO reviewers look for,
   * and there is no reason to use it for a fixed shape.
   *
   * 16px grid, 1.5 stroke, round caps -- matching the Bootstrap Icons set
   * the website already uses, so the extension and the site look drawn by
   * the same hand.
   */
  var SVG_NS = "http://www.w3.org/2000/svg";

  var PATHS = {
    // The mark: a reticle over a lens, echoing the magnifier in the logo.
    mark: [
      { el: "circle", attrs: { cx: 7, cy: 7, r: 4.25 } },
      { el: "path", attrs: { d: "M10.2 10.2 L13.5 13.5" } },
      { el: "path", attrs: { d: "M7 4.6 V9.4 M4.6 7 H9.4", opacity: "0.55" } }
    ],
    star: [
      { el: "path", attrs: {
        d: "M8 1.9 9.78 5.5 13.75 6.08 10.88 8.88 11.55 12.83 8 10.96 4.45 12.83 5.13 8.88 2.25 6.08 6.22 5.5 Z",
        fill: "currentColor", stroke: "none" } }
    ]
  };

  function icon(name, size) {
    var spec = PATHS[name];
    if (!spec) { return null; }

    var svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("viewBox", "0 0 16 16");
    svg.setAttribute("width", size || 14);
    svg.setAttribute("height", size || 14);
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "1.5");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("focusable", "false");

    for (var i = 0; i < spec.length; i++) {
      var node = document.createElementNS(SVG_NS, spec[i].el);
      for (var key in spec[i].attrs) {
        if (Object.prototype.hasOwnProperty.call(spec[i].attrs, key)) {
          node.setAttribute(key, spec[i].attrs[key]);
        }
      }
      svg.appendChild(node);
    }
    return svg;
  }

  return { isValid, fromPath, fromUrl, humanAge, icon, RESERVED_OWNERS };
})();

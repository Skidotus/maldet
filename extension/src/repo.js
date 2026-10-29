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

  return { isValid, fromPath, fromUrl, humanAge, RESERVED_OWNERS };
})();

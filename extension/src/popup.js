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
 * callback-style compatibility alias. Chrome has no `browser`, and its MV3
 * APIs do return promises. Callback-style sendMessage works in both and is
 * left on `chrome`.
 */
const api = typeof browser !== "undefined" ? browser : chrome;

// Must match background.js. Change both and rebuild to target another host.
const BASE = "https://maldet-fyp.my";

const $context = document.getElementById("context");

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

function num(n) {
  return n === null || n === undefined ? "\u2014" : Number(n).toLocaleString();
}

/* The site's five-step scale, as a class name. */
function levelClass(level) {
  return "lv-" + String(level || "").toLowerCase().replace(/[^a-z]/g, "");
}

function metaLine(meta) {
  if (!meta) return null;
  const line = el("p", "meta");
  if (meta.stars !== null && meta.stars !== undefined) {
    line.appendChild(el("span", null, `\u2605 ${num(meta.stars)}`));
  }
  if (meta.language) line.appendChild(el("span", null, meta.language));
  if (meta.last_pushed_human) {
    line.appendChild(el("span", null, `pushed ${meta.last_pushed_human}`));
  }
  return line.childElementCount ? line : null;
}

function verdictBlock(risk) {
  const box = el("div", `verdict ${levelClass(risk.level)}`);
  box.append(
    el("span", "verdict__level", risk.level || "unrated"),
    el("span", "verdict__score", num(risk.score))
  );
  return box;
}

/*
 * Both tracks, always, even when one is Safe. "Badly written" and "hostile"
 * are different questions, and showing only the worse of the two is how a
 * repository with 54 weak malware signals and a real dependency problem
 * gets read as malicious.
 */
function trackRow(name, level, score) {
  const row = el("div", "track");
  const val = el("span", "track__val", num(score));
  const band = el("em", null, level || "\u2014");
  val.appendChild(band);
  row.append(el("span", "track__name", name), val);
  return row;
}

function renderRepo(repo, result, base) {
  const nodes = [el("p", "repo", repo)];
  const actions = el("div", "actions");

  if (result && result.known) {
    const meta = metaLine(result.meta);
    if (meta) nodes.push(meta);

    if (result.risk) {
      nodes.push(verdictBlock(result.risk));

      const tracks = el("div", "tracks");
      tracks.append(
        trackRow("Vulnerabilities", result.risk.vuln_level, result.risk.vuln_score),
        trackRow("Malware", result.risk.malware_level, result.risk.malware_score)
      );
      nodes.push(tracks);

      nodes.push(
        el(
          "p",
          "counts",
          `${num(result.risk.high)} high \u00B7 ${num(result.risk.medium)} medium \u00B7 ` +
            `${num(result.risk.low)} low`
        )
      );
    }

    const status = el("p", "status", MalDetRepo.humanAge(result.days_since_scan));
    if (result.source_status === "gone") {
      status.className = "status warn";
      status.textContent = "no longer on GitHub \u2014 archived result";
    } else if (result.source_status === "renamed") {
      status.className = "status warn";
      status.textContent = `${MalDetRepo.humanAge(result.days_since_scan)} \u2014 since renamed`;
    } else if (result.stale) {
      status.className = "status stale";
      status.textContent += " \u2014 may be out of date";
    }
    nodes.push(status);

    actions.append(
      link("View report", result.detail_url, "primary"),
      // The scan form, not /rescan/<id>: a GET that starts a scan is the
      // bug that route still has, and this popup should not fire it.
      link("Scan again", `${base}/scan?repo=${encodeURIComponent(repo)}`, "ghost")
    );
  } else {
    const reachable = result !== undefined;
    nodes.push(
      el("p", "status", reachable ? "not scanned yet" : "could not reach MalDet")
    );
    actions.append(
      link("Scan this repository", `${base}/scan?repo=${encodeURIComponent(repo)}`, "primary")
    );
    if (!reachable) {
      nodes.push(
        el(
          "p",
          "hint",
          "Scanning still works \u2014 the buttons open MalDet directly. " +
            "Only the stored results need the connection."
        )
      );
    }
  }

  nodes.push(actions);
  $context.replaceChildren(...nodes);
}

/* --------------------------------------------------------------- startup */

async function init() {
  const base = BASE;
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

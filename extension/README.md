# MalDet for GitHub

A browser extension that puts MalDet's verdict where the decision actually
gets made — on the repository page, before you clone or depend on it.

On any `github.com/<owner>/<repo>` page a button appears:

| State | Button | Click |
|---|---|---|
| Already scanned | `◎ MalDet · scanned 4 days ago` | opens the report |
| Scanned a while ago | `◎ MalDet · scanned 3 months ago` (amber) | opens the report |
| Repo gone or renamed | `◎ MalDet · archived result` (red) | opens the report |
| Never scanned | `◎ Scan with MalDet` | opens the scan form, prefilled |
| MalDet unreachable | `◎ Scan with MalDet` (grey) | opens the scan form |

The in-page button reports **when** a repository was scanned, never a risk
level. A scan is a snapshot and the repository keeps changing after it, so an
age is honest where a score pinned to someone else's page would not be — it
would also read as GitHub's own verdict rather than this project's.

**The toolbar popup is where the verdict lives**, because you open it
deliberately:

```
◎ MalDet

mlflow/mlflow
★ 25,068 · Python · pushed 02 Apr 2026

┌────────────────────────────────┐
│ CRITICAL                  1658 │
└────────────────────────────────┘

Vulnerabilities         1536 Critical
Malware                  122 Critical

77 high · 765 medium · 33,081 low
scanned 3 months ago — may be out of date

[        View report        ]
[        Scan again         ]
▸ Settings
```

Both tracks show even when one is Safe. "Badly written" and "hostile" are
different questions, and showing only the worse of the two is how a
repository with a real dependency problem and a handful of weak malware
signals gets read as malicious. Scores are unbounded, so the band carries
the meaning and the number is detail.

## Install

Nothing is published to a store — load it unpacked.

```bash
./build.sh
```

That writes `dist/chrome` and `dist/firefox`.

**Chrome / Edge**
1. `chrome://extensions`
2. Turn on **Developer mode**
3. **Load unpacked** → pick `extension/dist/chrome`

**Firefox**
1. `about:debugging#/runtime/this-firefox`
2. **Load Temporary Add-on** → pick `extension/dist/firefox/manifest.json`
3. **Grant host access**, which Firefox does not do for you:
   `about:addons` → Extensions → MalDet for GitHub → **Permissions** →
   turn on access for the MalDet server address.

Step 3 is not optional. Firefox treats Manifest V3 `host_permissions` as
opt-in, unlike Chrome, which grants them at install. Skip it and the
extension looks like it works — the button appears on every repo page — but
every lookup fails and it silently falls back to "Scan with MalDet". If scan
dates never appear in Firefox, check this before anything else.

Firefox also clears temporary add-ons when it restarts, so both steps are
needed again after a restart.

## Pointing it at your MalDet

Defaults to `https://maldet-fyp.my`.

**Click the MalDet icon in the toolbar.** That is the settings panel: the
server address, a **Test connection** button, and a link to the site. If the
icon is not visible, Firefox tucks new extensions behind the puzzle-piece
button in the toolbar — pin it from there.

The same panel is also reachable as a full page via `about:addons` →
Extensions → MalDet for GitHub → **Preferences** (Firefox) or
`chrome://extensions` → Details → **Extension options** (Chrome), but the
toolbar icon is the short way.

Use **Test connection** after changing the address. It reports the URL it
tried and how long it took, which is what tells a server that is switched
off apart from a request the browser refused.

## If scan dates never appear

The button falls back to a plain `Scan with MalDet` link whenever the lookup
fails, so this is a degraded feature rather than a broken extension. Two
causes, and the error alone cannot tell them apart:

1. **MalDet is not running.** Check the address in options.
2. **The browser blocked the request.** GitHub is served over `https://`
   while MalDet may be served over plain `http://`. Some browsers refuse
   that combination even from an extension.

**Confirmed on Firefox 2026-10-29:** a lookup to `http://localhost:5000`
connects, while the same lookup to `http://103.233.1.97:5000` hangs for six
seconds and is aborted — against a server that answers that exact URL in
17ms. `localhost` is a trusted origin and a public bare-IP `http://` address
is not, so this is the browser refusing, not the server failing.

The fix is to serve MalDet over HTTPS. Let's Encrypt will not issue for a
bare IP, so it needs a hostname. Use a dynamic-DNS name whose zone is on the
[Public Suffix List](https://publicsuffix.org/list/) — `duckdns.org` is, so
each subdomain carries its own issuance limit.

`nip.io` looks tempting because it needs no signup, but it is **not** on that
list, so every nip.io user in the world shares a single Let's Encrypt quota
and issuance usually fails. Checked against the list directly rather than
taken on trust.

Opening a tab is never blocked, which is why the fallback always works
regardless.

## Layout

```
src/content.js      finds the repo, draws the button, survives GitHub's SPA navigation
src/background.js   the lookup; lives here so the page's HTTPS origin is not involved
src/options.*       server address and the connection test
src/button.css      styles, all namespaced .maldet-*
manifest.*.json     one per browser; they differ only in the background key
build.sh            assembles dist/ and checks every referenced file exists
```

## The server side

One endpoint, added in `app.py`:

```
GET /api/extension/lookup?repo=<owner>/<name>
```

Read-only, public data, `Access-Control-Allow-Origin: *` — and that header is
on this route alone, never on anything that changes state.

`GET /scan?repo=<owner>/<name>` prefills the scan form. It does **not**
auto-submit: a GET that starts a scan would be triggered by crawlers and chat
link previews, so the visitor still presses the button.

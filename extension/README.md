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

It reports **when** a repository was scanned, never a risk level. A scan is a
snapshot and the repository keeps changing after it, so an age is honest
where a score pinned to someone else's page would not be.

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

Firefox clears temporary add-ons when it restarts, and treats Manifest V3
host permissions as opt-in — if lookups fail there, grant the host under
`about:addons` → MalDet → Permissions.

## Pointing it at your MalDet

Defaults to `http://103.233.1.97:5000`. To change it, open the extension's
options (`chrome://extensions` → Details → Extension options) and use
**Test connection** to confirm it works.

## If scan dates never appear

The button falls back to a plain `Scan with MalDet` link whenever the lookup
fails, so this is a degraded feature rather than a broken extension. Two
causes, and the error alone cannot tell them apart:

1. **MalDet is not running.** Check the address in options.
2. **The browser blocked the request.** GitHub is served over `https://`
   while MalDet may be served over plain `http://`. Some browsers refuse
   that combination even from an extension.

The fix for the second is to serve MalDet over HTTPS. Let's Encrypt will not
issue a certificate for a bare IP address, but `nip.io` resolves one into a
hostname that it will — `103-233-1-97.nip.io` points at `103.233.1.97` — so a
reverse proxy such as Caddy can obtain a real certificate without buying a
domain.

Opening a tab is never blocked, which is why the fallback always works.

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

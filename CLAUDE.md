# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

MalDet is a web-based static analysis tool (Flask + MySQL) that scans public GitHub
repositories for malware, vulnerable dependencies, and supply chain attacks, combining
several detection engines with an ML risk classifier. It's a Final Year Project (FYP)
for the Diploma in Cyber Security Technology at the German-Malaysian Institute.
Full title: "Development of an AI-Driven Malware Detection and Trust Scoring
System for GitHub Repositories".

**Current state**: the scan pipeline (`scanner.py`, `dep_checker.py`), the queue
(`job_queue.py`, `worker.py`), Flask routes (`app.py`), `templates/`, `static/`,
`model/` (the Random Forest classifier) and `schema.sql` all exist and are wired
together, including `llm_summary.py`. Everything is committed and pushed to
the `haikal` branch, which merges into `main` by pull request.

## Setup & running

```bash
source venv/bin/activate
python3 app.py                    # web UI + inline scan worker — this is enough
```

Requires system tools on PATH: `bandit`, `semgrep` (needs `semgrep login` once —
without it semgrep withholds matched code and stores the literal string
`requires login` as the snippet), `yara`, `clamscan`, `7z`, plus a running MySQL
instance matching `config.py`.

Semgrep is capped by `MALDET_SEMGREP_MAX_MEMORY` (default 1500MB) because it is
the pipeline's largest consumer.

`guarddog` is deliberately **not** in `requirements.txt`. It requires
click >=8.4.1,<9, and semgrep pinned click ~=8.1.8 until 1.182.1, so
installing it into `venv/` silently upgraded click and broke semgrep. Since
the 1.182.1 bump semgrep pins click ~=8.4.2 and a single click (8.4.2)
satisfies both, so that specific conflict is gone — but the separate
environment is what is tested and what `run_guarddog()` falls back to, so it
stays until someone verifies the merge deliberately:

```bash
python3 -m venv .venv-guarddog && .venv-guarddog/bin/pip install guarddog
```

`run_guarddog()` looks for `guarddog` on PATH first (Docker installs it to
/opt and symlinks it there), then falls back to `.venv-guarddog/bin/guarddog`.
Like every other detector it skips silently when absent, so a missing binary
looks like a clean scan — verify it runs rather than assuming.

Credentials live in `config.py` (gitignored, copy from `config.example.py`):
`GITHUB_TOKEN`, `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`.

Tests cover IOC extraction and two YARA rules so far:
`python3 -m unittest discover -s tests -t .` (stdlib, needs no database or network;
`test_ioc_scoring.py` imports `scanner.py`, so `config.py` must exist, and
`test_yara_rules.py` skips if `yara` is not installed). When changing a rule, test
both directions: the first fix to `detect_downloader` passed its tests and still
lost a real `curl.exe` download, found only by comparing hits across real repos.
There is no lint config.

## Architecture

**Request flow**: `app.py` (Flask routes) → `job_queue.enqueue()` writes a row to
`scan_jobs` → `worker.py` (separate process) claims it → `scanner.py:scan_repo()`
(orchestrator) → writes results to MySQL → `app.py` reads back for
`index`/`detail`/`history` views.

**Local dev is one process**: `python3 app.py` starts the web UI *and* an
inline scan worker, so scans actually run. `MALDET_INLINE_WORKER=0` disables
it if you are also running `worker.py` by hand.

**Deployed is two processes**: gunicorn serves the site (`docker-compose.yml`
runs `gunicorn --workers 2 app:app`) and `worker.py` runs the scans. The
inline worker never starts under gunicorn, because gunicorn imports the
module rather than executing `__main__` — which is deliberate: two gunicorn
workers each scanning would mean two semgreps (~2GB each) in a 4GB host.

**`job_queue.py` + `worker.py`** — the scan queue, backed by the `scan_jobs`
table. Exactly **one** worker consumes it, and `claim_next()` refuses to claim
while another job is running. That single-consumer rule is a memory constraint,
not a style choice: semgrep peaks near 2GB (measured) and clamscan near 1GB, so
two concurrent scans do not fit the 4GB deployment target. Don't scale the
worker above 1 without raising the RAM. `recover_stale()` runs at worker
startup and fails jobs orphaned by a crash, which would otherwise block the
queue forever. Visitors are tracked by a `maldet_job` cookie so each sees their
own scan; previously *any* visitor was redirected into whichever scan was
running.

**`scanner.py:scan_repo(repo, archive_password)`** is the pipeline entry point, run
by `worker.py` (not inside the web request):
1. `get_repo_info()` — GitHub API metadata (uses `GITHUB_TOKEN`)
2. `clone_repo()` — shallow clone into `/tmp/maldet_scan_temp/<owner>_<repo>`
3. `extract_archives()` — extracts `.zip`/`.7z`/`.rar` with 7z, trying a password
   (default `"infected"`, the malware-analysis convention) since malicious archives
   are often password-protected to dodge automated scanning
4. Runs detectors in sequence, each returning a list of findings dicts with the
   shape `{tool, severity, issue_text, filename, line_number, code_snippet}`:
   `run_bandit`, `run_semgrep`, `run_yara`, `run_clamav`,
   `run_guarddog`, `check_dependencies` (from `dep_checker.py`).
   `run_yara` runs two rule sets, both reported as tool `yara`: MalDet's own
   **behaviour** rules in `rules.yar` (decode-then-exec, download-then-exec,
   persistence — what catches new code) and then `run_yara_forge()`, the
   **YARA Forge core** fingerprints of known malware and hacking tools in
   `rules/forge/` (release in `VERSION`, refresh with
   `update_yara_forge.py`, measurements and licensing in its README). Forge
   score maps to severity (75+ high), `HKTL_` rules are medium and labelled
   `[hacking tool]`. The `rules.yar` rules require their two halves to be
   connected (nested or on adjacent lines), not merely in the same file —
   the file-wide versions fired in up to 55% of repos. Every `rules.yar`
   string is `ascii wide`, so rules also match UTF-16 text (PowerShell's
   habit); the tests check each sample in UTF-16 too, so keep the modifier
   on any new string. `ioc_extractor._read_text()` (shared by the payload
   decoder) decodes UTF-16 instead of refusing it as binary. Changing a rule's
   description changes its `issue_text`, which is the classifier's
   rule-frequency key, so retrain after editing descriptions.
   Each rule set has `MALDET_YARA_TIMEOUT` (default 300s). A timeout keeps
   the matches found so far (yara runs under `stdbuf -oL`; without it the
   kill discards yara's whole output buffer) and adds a medium "YARA scan
   incomplete" finding, because a timed-out scan used to save zero YARA
   findings and look clean — it happened to WebKit and to a malware
   collection
4a. `run_decoded_payloads(path, findings)` — what the code *hides*.
   `payload_decoder.py` peels base64 (also reversed and URL-safe), hex,
   `\x41` escapes and character-code lists, then zlib/gzip/bz2/xz, up to
   three layers, and writes each layer that looks like code (a
   `CODE_MARKERS` hit) or like an executable (magic bytes) to a scratch
   directory. `run_yara()` and `run_clamav()` scan that directory, and each
   match is reported against the **original** file and line with
   `issue_text` prefixed `Hidden payload: ` and the decoding chain plus
   decoded text as the snippet. `rules.yar`'s decode-then-exec rules see
   the wrapper; this sees what is inside it. A match already made in plain
   sight on the same file is dropped, so nothing is counted twice. Capped at
   `MALDET_DECODE_TIME_LIMIT` (60s) and 500 payloads; hitting either adds a
   low "decoding incomplete" marker rather than looking complete. Never
   executes, imports or unpickles anything; reads files with
   `ioc_extractor`'s symlink-refusing helpers; every decompression is
   capped at 1MB. ClamAV only runs here when something was decoded, which
   costs its ~12s signature load
5. `filter_noise()` — drops low-value Bandit rules and anything under
   test/docs/example/migration/locale paths; downgrades some high findings to medium.
   Vulnerability findings (Bandit/Semgrep/CVEs) in copied-in code
   (`is_vendored_path()`: `vendor/`, `node_modules/`, `dist/`, `*.min.js`…)
   drop one severity step; malware detectors there are never downgraded,
   since a committed `node_modules` is a place to hide a payload.
   Then `run_reference_guard()` (`reference_files.py`): YARA/ClamAV
   matches in files that *describe* threats — YARA/Sigma/Snort rule files,
   ClamAV signature databases, DNS/adblock blocklists — are marked
   `f["reference"]`, set to low and prefixed "Reference in a …, not code
   that runs: ". It needs a data-file extension **and** a rule/list format
   in the first 256KB, so code (`.py`, `.js`, `.sh`, `.ps1`…) is never
   excused whatever it contains. Breadth ("matches many unrelated rules",
   FlatScan's test) was rejected on data: nishang's Powerpreter and the
   malicious demo package match as many rules as `rules.yar`. Hidden-payload
   and threat-intel findings are never marked. After scoring,
   `weigh_references()` sets their `p_real` to 0, so they stay on the
   report but add nothing to either score, and `ioc_extractor.flagged_paths()`
   skips them so a blocklist's domains are not published as IOCs
5a. `score_findings()` — the Random Forest's P(real). Features come from
   `add_finding_features()`, shared with `train_classifier.py` so training
   and scan time cannot drift: tool, severity, rule text, rule frequency,
   snippet length, plus the detector's own confidence
   (`scan_results.tool_confidence`, Bandit and Semgrep only), whether the
   file is vendored, and how many different tools flagged the same
   line/file. The saved model lists its own `feature_cols`; a model without
   that key uses the original five. Measured 2026-11-03 against
   `eval_sample.json` over five training splits, the added features did not
   change accuracy (AUC 0.79 either way), so the shipped model was not
   replaced — rule-derived training labels limit what any feature can add.
   `tool_confidence` cannot be judged until rescans populate it.
   After filtering, `run_ioc_extraction()` (see `ioc_extractor.py` below) adds any
   threat-intel matches to the findings as `tool="threat_intel"`.
6. `calculate_risk()` — weights high/medium(capped 30)/low(capped 20) into a score,
   maps score to `Safe/Low/Medium/High/Critical`. "Safe" is the stored value
   only: every page, the printable report, the extension popup and the LLM
   prompt show it through `scanner.level_label()` as **"Nothing found"**
   (Jinja: `{{ level | level_label }}`), because a static scan cannot show a
   repository is safe. CSS classes, thresholds, the DB and the extension API
   keep `Safe`. A new template that prints a level must use the filter
7. `save_to_db()` — upserts into `repositories`, replaces `scan_results` and
   `risk_scores` for that repo, appends a `scan_history` row for trend charts
8. temp clone directory is always removed in a `finally` block

**`dep_checker.py:check_dependencies(repo_path)`** — separate from the scanner tools
above but returns findings in the same shape, merged into the same list:
- `run_pip_audit()` — CVE lookups via `pip-audit`, against `requirements.txt`
  directly plus the *exactly-pinned* entries parse_dependencies() finds in
  `poetry.lock`, `pyproject.toml` and `Pipfile` (written to a temp
  requirements file). Ranges like `^2.28` are skipped on purpose: a CVE
  verdict needs one version, and picking one for the repo would report
  vulnerabilities it may never install. Runs with `--no-deps --disable-pip`
  so pip-audit never resolves or builds anything from an untrusted repo —
  its `project_path` mode invokes the project's own build backend, which is
  arbitrary code execution. Findings are deduped on (advisory id, package,
  version), since OSV returns one advisory from several sources with
  differently worded descriptions.
- `check_suspicious_patterns()` — parses `requirements.txt` and `package.json`,
  flags direct URL/`git+` installs, typosquatted package names (`SequenceMatcher`
  ratio ≥ 0.85 against a hardcoded `KNOWN_PACKAGES` list), unpinned versions, and
  loose (`>=`/`^`) version constraints

**LLM summary** (`llm_summary.py`): after scoring, `scan_repo()` asks a local
Ollama model for a plain-English paragraph about the top ~15 finding groups
and stores it in `risk_scores.llm_summary`; the detail page prefers it over
the rule-based `app.py:build_findings_summary()`. It explains, it never
scores — the prompt hands it the already-decided risk levels and forbids
re-rating them. Everything returns `None` rather than raising, so a missing
or slow Ollama falls back to the rule-based text instead of failing a scan.
The model is `qwen3.5:2b` (`ollama pull qwen3.5:2b`), chosen over llama3.2:3b
and granite4.2:3b by comparing all three on real findings: llama3.2 invented a
score scale that does not exist, and qwen was the fastest of the three with
nothing fabricated. Requests send `"think": False` — qwen and granite are
reasoning models, and without it qwen returns an empty response while granite
writes its private reasoning into the summary. The request also sets
`keep_alive` (default 60s, `MALDET_OLLAMA_KEEP_ALIVE`) so the ~2.4GB model is
released shortly after a scan instead of sitting in RAM for Ollama's default
five minutes — on a memory-tight machine that idle residency is what triggers
the OOM killer. Tune via `MALDET_OLLAMA_MODEL` / `MALDET_OLLAMA_HOST` /
`MALDET_OLLAMA_TIMEOUT`, or set `MALDET_OLLAMA_DISABLE=1` to skip it.

**`ioc_extractor.py`** — indicators of compromise from files ClamAV or YARA flagged
and from install scripts, plus the optional abuse.ch lookups. Only runs after
`filter_noise()`, so it sees the same flagged files the report lists. Three rules
hold it together. Install scripts are parsed, never executed, and only their working
parts are searched, because project metadata would otherwise report every author's
own website (Flask's `pyproject.toml` alone gives `palletsprojects.com` and
`discord.gg`). Symlinks and paths outside the clone are refused, because a link named
`setup.py` pointing at `config.py` would publish its contents on a public page. And
it can only lose its own results: failures become `status='failed'`, and
`_save_iocs()` writes behind a savepoint, so a database without the new tables still
saves the scan. Threat-intel points are derived from the stored tool and the source
at the start of `issue_text`, in `_threat_intel_points()`, because
`recompute_scores.py` only has `scan_results` to work from. Do not change the
wording of that prefix without changing the weighting. `ABUSECH_AUTH_KEY` must never
reach a log: print exception types there, not messages.

**Adding a new detector**: write a `run_x(path)` function in `scanner.py` returning
findings in the standard dict shape, call it inside `scan_repo()` and append its
output to `findings` before `filter_noise()` runs.

**`db_connect.py`** — the one place that knows where MySQL is. Resolves
`DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD` and `DB_NAME` from the
environment, else the same name in `config.py`, else a default, and all
fifteen `pymysql.connect()` calls go through it. Exists for the SSH tunnel
case (`ssh -L 3307:127.0.0.1:3306`), because without a configurable port
every script silently connects to the *local* database instead — same
tables, plausible results, wrong data, no error. The credentials resolve the
same way for the same reason: a tunnel points at a different server with its
own MySQL users, so the deployed password is never the one in a developer's
`config.py`. An empty variable counts as unset, since `DB_PASSWORD= cmd` is
a shell saying "no value", not "the empty password".

**`backfill_summaries.py`** — generates `risk_scores.llm_summary` for repos
that lack one, from stored findings, without rescanning. Groups the findings
in SQL (one repo has 157k findings but 557 groups) so it is cheap over a slow
link, and shares `summarize_one()` with `worker.py` so scan-time and
after-the-fact summaries cannot drift. Survives Ollama being killed mid-batch
by waiting for the service to restart rather than marking every remaining
repo unavailable. `--watch` keeps it running after the backlog,
re-checking every `--every` minutes (default 2) for new or rescanned repos
without a summary. That is how deployed scans get one, since the VPS runs
with `MALDET_OLLAMA_DISABLE=1`. Repos that produce nothing are skipped
until restart rather than retried every round, and a dropped DB connection
(the tunnel) is retried next round instead of ending the watch. The backlog is
worked worst-risk-first, but before every repo it checks for one scanned in
the last `--recent` minutes (default 30, `0` = off) and does that first,
newest first, so a fresh scan (a demo, say) does not wait hours behind the
backlog. The window is computed by MySQL (`NOW()` against
`repositories.scanned_at`), never the laptop's clock.

**`evaluate_summaries.py`** — scores summaries against eight mechanical
checks (fabricated numbers/files/advisory-ids/tools, invented score scales,
risk-level contradiction, and four format rules). `--generate` for a fresh
sample, `--stored` to score what is in the database, `--rescore` to re-judge
a saved run after fixing a check. Last run: 17 of 19 clean.

**Database**: MySQL, `pymysql` with `DictCursor`. Tables (defined in `schema.sql`):
`repositories`, `risk_scores`, `scan_results`, `scan_history`, `scan_jobs`,
`iocs`, `ioc_runs`. `iocs.scan_id` is `scan_history.id`, the only per-scan record,
and `iocs.value` is `utf8mb4_bin` because wallets and tokens are case-sensitive.
`repositories.source_status` and `risk_scores.llm_summary_status` both drive
UI state — see the frontend contract below.
Update `schema.sql` whenever the schema changes — it's the source of truth for a
fresh DB setup. `scan_jobs.queued_at` is `DATETIME(6)`: whole-second precision
made jobs submitted in the same second compare as simultaneous, so everyone was
told they were first in the queue.

## Frontend contract

What each template is given, and the two JSON endpoints the pages poll. Read
this before changing a template: two pages have state that only makes sense
with the backend behaviour behind it, and both are easy to break by
"simplifying" a branch that looks redundant.

**Trust score (all pages).** Every template has `trust_for(row)` (an
`app.py` context processor over `scanner.trust_score()`), which turns any
row carrying `vuln_score` / `malware_score` into `{trust, level, vuln,
malware, limited_by, vuln_floored}`. It is computed at render time, never
stored, so changing the mapping needs no migration. Each axis maps into its
risk level's band (Safe 100, Low 99–70, Medium 69–50, High 49–25, Critical
24–0, interpolated inside the level's thresholds), so the number can never
contradict the level beside it. The headline is
`min(malware, max(vuln, VULN_TRUST_FLOOR=40))`: code-quality findings scale
with codebase size (django is Critical on that axis), so they can lower
trust only to 40, and only malicious-pattern findings go below. Shown as
"n / 100", never as a percentage — it is not a probability, and the pages
say so. The detail page explains which axis is holding it down, including
when the floor is. Not added to the browser extension.

**`index.html`** — the one-page landing site (welcome, tools, scan form,
recent scans, about). Given `repos` (10 most recent), `total`, the per-level
counts `safe`/`low`/`medium`/`high`/`critical`, `total_findings` (a
`COUNT(*)` over `scan_results`) and `active_job_id` (the visitor's queued or
running job, or None — shown as a "scan in progress" link above the form,
since submitting again would only bounce back to it). The hero card shows
`repos[0]`, a real record; scores are unbounded, so it shows the level on a
five-step scale rather than a percentage bar. About-us people, programme,
institution and the full project title live in the `team_groups` /
`programme` / `institution` / `project_title` sets at the top of the template.
Also given `extension` — version, build date and sizes of the downloadable
browser-extension bundles, from `app.py:extension_info()`, which reads
`static/downloads/extension-info.json` per request. It is None in a checkout
where `extension/build.sh` has never run, and the download section is skipped
rather than offering a link to a file that is not there.

**`scan.html`** — nothing, or `error` on a bad URL. The form normally lives
in `index.html#scan`; this page is what the server renders on a rejected
URL, so the error sits next to a form that can be corrected. Also given
`large_repo` (`repo`, `size_mb`, `warn_mb`) and `archive_password` when
GitHub reports the repo at or over `MALDET_REPO_WARN_MB` (default 1000):
the page warns, the button becomes "Scan anyway", and a hidden
`confirm_large=1` is the only thing that queues it. At or over
`MALDET_REPO_MAX_MB` (default 5000) both `/scan` and `/rescan` refuse with
`error`. A GitHub API failure skips the check rather than blocking scans.
Calibrated on the corpus: django 277MB and mlflow 1.5GB scan fine,
MalwareSourceCode 2.2GB ran YARA out of time, WebKit 12.9GB never cloned.

**`scan_status.html`** — `job` and `job_id`. `job` is shaped by
`app.py:_job_payload()`, not the raw `scan_jobs` row: `status`, `stage`,
`repo`, `repo_id`, `error`, `started_at` (falls back to `queued_at`, since a
queued job has not started), `position` and `elapsed_s` (seconds since
`started_at`, computed server-side because job_queue stamps times with the
server's `datetime.now()` and a visitor's clock or timezone would skew it;
the page only counts up locally between polls). **`position` is how many scans
are ahead of this one** — scans run strictly one at a time, so a visitor can
genuinely be waiting behind someone else and the page says so rather than
showing an unexplained spinner. The page polls `/api/scan-status/<job_id>`
every 2s and must keep polling while `status` is `queued` *or* `running`; a
queued job that is not polled looks frozen forever. Laid out like the report
page (eyebrow + `owner / name` header, `console-panel`s): a "Now" panel
with the live stage in large type, "Step n of 15 · m:ss elapsed" and the
queue notice, beside the progress track. The eyebrow, step counter and
queue notice all switch with state (queued / running / failed) without a
reload. The track's `data-stage` values must match `scanner.py`'s
`report()` strings exactly.

**`detail.html`** — `repo`, `risk`, `findings`, `tools`, `tool_totals`,
`findings_summary` (the rule-based text), `finding_counts` (`total` /
`likely_real` / `likely_noise` over *all* findings, not the capped list),
`history_dates`/`history_scores` (JSON for the chart), plus the two below.
Laid out as a security console: verdict panels, summary / engine / trend
row, then a findings log filtered client-side and paged 50 at a time.
Each finding carries `category` (`scanner.finding_category()`, the same
split the two verdicts are scored with), which drives the log's All types /
Vulnerability / Malicious filter; the filter's button groups are selected
by `[data-cat]` / `[data-sev]`, not bare `.seg__btn`, so they stay
independent. `findings` caps only Bandit and Semgrep at 200 each (`app.py`
`UNCAPPED_TOOLS` lists the malware engines, which are always listed in
full, since a hidden malicious finding is the failure that matters); the
log names each truncated engine and how many it left out, and links
`GET /detail/<id>/findings.csv`, every finding uncapped. That export
escapes cells starting with `= + - @` because snippets come from untrusted
repositories (CSV injection). Scores always count every finding. It follows the light/dark theme like every other page. It used
to be dark in both, which left the theme toggle visibly doing nothing
there; don't reintroduce a page-level palette (`body.console-page` now
only sets the page's ground and width). Its console colours are the
`--well` / `--signal` / `--track` / `--unsure` / `--noise` tokens. The
trend chart is a canvas, so it reads those tokens itself and redraws on a
`data-theme` change. Use a full `chart.update()` there, not
`update('none')`, which keeps the points in the old theme's colour.
Code snippets stay dark in both themes on purpose.

- `llm_summary` / `llm_pending` / `llm_awaiting` — three display states plus
  a quiet fourth. `llm_awaiting` is true for a scan under 10 minutes old
  (`app.py:LLM_AWAIT_WINDOW_S`, age from MySQL's `NOW()` against
  `scanned_at`) with no summary and nothing pending. That is every fresh
  scan on the VPS, which runs with the LLM disabled. The page shows the
  rule-based summary as normal and polls `/api/summary` every 5s, swapping
  in an AI summary written meanwhile by a laptop running
  `backfill_summaries.py --watch`. No spinner, because usually none comes.
  The original three: A summary is
  written *after* the scan finishes (20-60s of CPU), so arriving with none is
  normal. `llm_summary` set → show it. `llm_pending` true → show the
  placeholder, poll `/api/summary/<repo_id>` every 3s, and give up after 4
  minutes. Neither → show `findings_summary`. The placeholder deliberately
  shows the rule-based summary underneath itself, dimmed, so a visitor who
  will not wait has still been told what was found.
- `repo.source_status` — `gone`, `renamed`, or NULL. A scan is a snapshot and
  the repository can disappear afterwards: on `gone` the page says the
  findings cannot be refreshed and disables Rescan (it could only fail), on
  `renamed` it says these are the superseded original. Without this the page
  presents unverifiable months-old findings as current.

- `iocs` — from `app.py:_load_iocs()`: `state`, `rows` (capped at
  `IOC_DISPLAY_LIMIT`), `total`, `ti_status`, `note`. **Do not merge the states**:
  `none` (extraction never ran, or no tables), `failed`, `partial` and `done`. Only
  `done` with no rows may say "No indicators of compromise found"; the others would
  be a false clean. Values stay plain escaped text, never links. `GET
  /detail/<id>/iocs.csv` and `.json` download every row, and the CSV goes through
  `_csv_cell()` because the values come from untrusted repositories.

**JSON endpoints** (the first two exist because their work outlives a
request):
- `GET /api/scan-status/<job_id>` → the `_job_payload()` fields above.
- `GET /api/summary/<repo_id>` → `{status, summary}` where status is
  `pending` / `done` / `unavailable`. `unavailable` is a normal outcome, not
  an error — it means stop polling and keep the rule-based summary already on
  screen. A NULL `llm_summary_status` (a row predating the column) reports as
  `unavailable`.
- `GET /api/extension/lookup?repo=<owner>/<name>` → `{known, repo_id,
  scanned_at, days_since_scan, stale, source_status, detail_url}`, or
  `{known: false, scan_url}`. The **only** route carrying
  `Access-Control-Allow-Origin: *`, because it is the only one called
  cross-origin. Keep it that way — never put that header on `/scan`, and
  never make it site-wide. It deliberately returns no risk level: the
  browser extension reports *when* a repo was scanned and links to the
  report, rather than becoming a score pinned to someone else's page.

**`app.py:parse_repo_slug()`** turns a URL, a `github.com/...` path or a
bare `owner/repo` into `"owner/repo"`, or None. Both the scan form and the
extension lookup go through it, deliberately: two parsers would eventually
disagree, and the one that queues scans is the wrong place to find out.
It enforces GitHub's own naming rules, which is what stops `../..` parsing
as a repository and being offered to the scan form as something to clone.

**`GET /scan?repo=<owner>/<name>`** prefills the form and does **not**
auto-submit. A GET that starts a scan gets fired by crawlers and chat-app
link previews — the same latent bug `/rescan/<id>` still has.

Styling lives in `static/css/style.css`: a forest-green / off-white "paper"
theme over Bootstrap, with tokens on `:root`. Below 768px, tables marked
`table-stack` turn each row into a card so both verdicts stay visible. There is no build step and no framework: templates are Jinja,
scripts are inline vanilla JS in each template's `{% block scripts %}`.

**Light / dark theme.** An inline script in `base.html`'s `<head>` writes
`data-theme` on `<html>` before first paint (stored choice in
`localStorage['maldet-theme']`, else the OS preference); `main.js` wires
the toggle. Dark mode is one block, `[data-theme="dark"] { ... }`, that
re-points the `:root` tokens. So every colour a component uses must be a
token with a value in **both** blocks. A literal hex or `rgba()` stays the
same in both themes, which is how the tools-section verdict pills ended up
as pastel stickers on the dark cards. Literals are fine only on surfaces
that are dark in both themes (the forest panels, the code blocks).

## Branching

`main` = stable. `haikal` is the working branch and is merged into `main` by
pull request on GitHub (as PRs #4, #5 and #6 did). Short-lived
`feature/xxx` branches are also PR'd straight into `main`.

There is no `dev` branch. One existed until early August 2026 and was
retired; the three-tier `main`/`dev`/`feature` flow this file used to
describe has not matched the repository since. Don't recreate it without a
reason — on a solo project the middle tier only adds a merge step.

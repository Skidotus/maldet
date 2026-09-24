# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

MalDet is a web-based static analysis tool (Flask + MySQL) that scans public GitHub
repositories for malware, vulnerable dependencies, and supply chain attacks, combining
several detection engines with an ML risk classifier. It's a Final Year Project (FYP)
for a Diploma in Information Security.

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

`guarddog` is deliberately **not** in `requirements.txt` — it requires
click >=8.4.1 while semgrep pins click ~=8.1.8, so installing it into `venv/`
silently upgrades click and breaks semgrep. It gets its own environment:

```bash
python3 -m venv .venv-guarddog && .venv-guarddog/bin/pip install guarddog
```

`run_guarddog()` looks for `guarddog` on PATH first (Docker installs it to
/opt and symlinks it there), then falls back to `.venv-guarddog/bin/guarddog`.
Like every other detector it skips silently when absent, so a missing binary
looks like a clean scan — verify it runs rather than assuming.

Credentials live in `config.py` (gitignored, copy from `config.example.py`):
`GITHUB_TOKEN`, `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`.

No test suite or lint config exists in this repo currently.

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
   `run_bandit`, `run_semgrep`, `run_yara` (rules in `rules.yar`), `run_clamav`,
   `run_guarddog`, `check_dependencies` (from `dep_checker.py`)
5. `filter_noise()` — drops low-value Bandit rules and anything under
   test/docs/example/migration/locale paths; downgrades some high findings to medium
6. `calculate_risk()` — weights high/medium(capped 30)/low(capped 20) into a score,
   maps score to `Safe/Low/Medium/High/Critical`
7. `save_to_db()` — upserts into `repositories`, replaces `scan_results` and
   `risk_scores` for that repo, appends a `scan_history` row for trend charts
8. temp clone directory is always removed in a `finally` block

**`dep_checker.py:check_dependencies(repo_path)`** — separate from the scanner tools
above but returns findings in the same shape, merged into the same list:
- `run_pip_audit()` — CVE lookups against `requirements.txt` via `pip-audit`
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

**Adding a new detector**: write a `run_x(path)` function in `scanner.py` returning
findings in the standard dict shape, call it inside `scan_repo()` and append its
output to `findings` before `filter_noise()` runs.

**Database**: MySQL, `pymysql` with `DictCursor`. Tables (defined in `schema.sql`):
`repositories`, `risk_scores`, `scan_results`, `scan_history`, `scan_jobs`.
Update `schema.sql` whenever the schema changes — it's the source of truth for a
fresh DB setup. `scan_jobs.queued_at` is `DATETIME(6)`: whole-second precision
made jobs submitted in the same second compare as simultaneous, so everyone was
told they were first in the queue.

## Branching

`main` = stable. `haikal` is the working branch and is merged into `main` by
pull request on GitHub (as PRs #4, #5 and #6 did). Short-lived
`feature/xxx` branches are also PR'd straight into `main`.

There is no `dev` branch. One existed until early August 2026 and was
retired; the three-tier `main`/`dev`/`feature` flow this file used to
describe has not matched the repository since. Don't recreate it without a
reason — on a solo project the middle tier only adds a merge step.

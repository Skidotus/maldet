# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

MalDet is a web-based static analysis tool (Flask + MySQL) that scans public GitHub
repositories for malware, vulnerable dependencies, and supply chain attacks, combining
several detection engines with an ML risk classifier. It's a Final Year Project (FYP)
for a Diploma in Information Security.

**Current state**: core scan pipeline (`scanner.py`, `dep_checker.py`) and Flask routes
(`app.py`) are implemented, but `templates/`, `static/`, and `model/` (the ML classifier)
referenced by the README and by `app.py`'s `render_template()` calls do not exist yet.
`schema.sql` is empty. Don't assume these exist — check before referencing them.

## Setup & running

```bash
source venv/bin/activate
python3 app.py                    # runs on http://localhost:5000, debug=True
```

Requires system tools on PATH: `bandit`, `semgrep` (needs `semgrep login` once),
`yara`, `clamscan`, `7z`, plus a running MySQL instance matching `config.py`.

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

**Request flow**: `app.py` (Flask routes) → `scanner.py:scan_repo()` (orchestrator) →
writes results to MySQL → `app.py` reads back for `index`/`detail`/`history` views.

**`scanner.py:scan_repo(repo, archive_password)`** is the pipeline entry point, run
synchronously inside the `/scan` request:
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
writes its private reasoning into the summary. Tune via `MALDET_OLLAMA_MODEL` /
`MALDET_OLLAMA_HOST` / `MALDET_OLLAMA_TIMEOUT`, or set
`MALDET_OLLAMA_DISABLE=1` to skip it.

**Adding a new detector**: write a `run_x(path)` function in `scanner.py` returning
findings in the standard dict shape, call it inside `scan_repo()` and append its
output to `findings` before `filter_noise()` runs.

**Database**: MySQL, `pymysql` with `DictCursor`. Expected tables (per queries in
`app.py`/`scanner.py`, `schema.sql` is currently empty so this is inferred):
`repositories`, `risk_scores`, `scan_results`, `scan_history`. Update `schema.sql`
whenever the schema changes — it's the source of truth for a fresh DB setup.

## Branching

`main` = stable, `dev` = development, `feature/xxx` = one feature per branch, PR'd
in via GitHub.

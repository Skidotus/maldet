# MalDet — Project Notes

Snapshot as of 2026-09-02. Written for the FYP report / your own reference —
update as things change rather than treating this as a one-time record.

## Advantages (current state)

- **Real aggregation value, actually working end-to-end.** Bandit, Semgrep,
  YARA, ClamAV, and dep_checker all run and get reduced to one score and
  verdict — the core positioning claim in PRODUCT.md is real, not aspirational.
- **Tested against real data, not a toy demo.** The live DB has 196 scanned
  repos and 249K+ findings. Every fix this session was verified against
  that real data, not just unit-tested in isolation.
- **Complete, cohesive UI.** Dashboard, New Scan, Detail, History, and the
  scan-status page all exist and follow one considered design system
  (wax-seal risk badges, ledger layout) — not a default Bootstrap look.
- **Background scan execution with persistent status.** Scans run in a
  background thread with a pollable status page — refreshing or navigating
  away no longer loses track of an in-progress scan.
- **Resilient to real edge cases found via testing:** a 157K-finding repo
  renders safely instead of crashing the browser; clone timeouts clean up
  after themselves instead of leaving partial data on disk; malformed
  `.git`-suffixed URLs are handled.
- **Historical trend tracking works.** `scan_history` + the trend chart on
  the detail page support the "track a repo over time" positioning claim.
- **schema.sql now matches reality.** It was empty before; now it's an
  accurate, documented source of truth for the actual live schema.
- **ML component has honest methodology, not just a black box.** No
  ground-truth labels exist, so the classifier uses clearly-labeled weak
  supervision, and two real calibration problems were found and fixed by
  reading the code rather than guessing (YARA under-confidence, dep_checker
  text uniqueness).

## Disadvantages (current state)

- **dep_checker still only covers Python and Node.** `go.mod`, `Cargo.toml`,
  and other ecosystems aren't parsed yet — Python (`requirements.txt`,
  `pyproject.toml`, Poetry, Pipfile, lock file) and Node (`package.json`,
  including install-hook scripts) are covered.
- **No automated test suite.** Every fix has been verified by manual/live
  testing against the real app and DB — thorough, but not repeatable or
  regression-proof going forward.
- **In-memory scan job tracking.** Job status lives in a process-lifetime
  dict; a server restart (including the dev auto-reloader on every `.py`
  save) kills any in-progress scan and forgets its status.
- **ClamAV has produced zero real hits** across all scanned repos — expected,
  since it's built for compiled malware, not source code, but worth being
  honest that this engine's contribution is currently unproven on this
  workload.
- **LLM plain-English summary is entirely unbuilt**, and the spec is
  ambiguous: PRODUCT.md says Ollama/llama3.2, but `config.py` and
  `requirements.txt` already point to the Claude API instead.

---

## What's improved (through 2026-09-02)

- Built the three missing templates (`scan.html`, `detail.html`,
  `history.html`) plus a new `scan_status.html` — previously three of the
  app's core routes had nothing to render.
- Rewrote `schema.sql` to match the real live database.
- Fixed real bugs found via live testing:
  - `risk_scores` queries ordering by a nonexistent `created_at` column
    (two routes)
  - unbounded findings render for repos with 100K+ results
  - findings sorted by severity as a string instead of by actual severity
  - nav bar invisible on desktop (Bootstrap `.collapse` misuse)
  - off-brand `<code>` color clashing with the design system
  - `.git`-suffixed URLs failing GitHub lookups
  - clone timeout too short for larger repos, and timed-out clones leaving
    partial data on disk uncleaned
- Replaced the synchronous "hold the request open for minutes" scan flow
  with background execution + a persistent, refresh-safe status page.
- Removed the unused `scan_date` column (verified unreferenced first,
  backed up before dropping).
- Built the ML false-positive classifier (`train_classifier.py`) and
  **wired it live**: `scan_repo()` calls `score_findings()` before
  `calculate_risk()`, attaching a P(real issue) probability to every
  finding, stored in `scan_results.confidence` and used to weight the risk
  score instead of counting every finding equally.
- Split the single blended risk score into two axes — vulnerability
  (Bandit/Semgrep: exploitable coding mistakes) vs malicious pattern
  (YARA/ClamAV/dep_checker: signs the code means harm) — with separately
  calibrated thresholds per axis. Rewrote YARA rules as part of this.
- Fixed the duplicate-repository-row bug in `save_to_db()`, plus one-time
  cleanup scripts (`dedupe_repositories.py`, `mark_rescanned.py`) to
  consolidate/backfill existing duplicate rows.
- Extended `dep_checker.py` well beyond `requirements.txt`/`package.json`:
  `pyproject.toml` (PEP 621 + Poetry), `Pipfile`, `poetry.lock`, plus two
  new detectors — `check_setup_py()` (flags `setup.py` code that executes
  automatically during `pip install`, before any application code runs)
  and `check_npm_install_hooks()` (flags dangerous `pre/postinstall`
  scripts in `package.json`).
- Fixed a categorization gap this surfaced: the classifier's
  finding-type grouping (`frequency_key()` in scanner.py) didn't have
  categories for the new setup.py/npm-hook finding types, so they were all
  silently lumped into one generic "other" bucket — diluting exactly the
  rare, high-signal findings this feature exists to catch. Added proper
  categories and retrained.

## What needs improvement (near-term, actionable)

- Build a small hand-labeled evaluation holdout for a real precision/recall
  number — right now the classifier is only evaluated against its own weak
  labels, which is a lower bar.
- Extend dep_checker to other ecosystems (`go.mod`, `Cargo.toml`, etc.) —
  Python and Node are now covered.
- Decide and build the LLM plain-English summary feature — resolve the
  Ollama-vs-Claude-API question first.
- Add at least minimal automated tests (route smoke tests, a couple of
  `scanner.py`/`dep_checker.py` unit tests) so future changes don't rely
  purely on manual re-testing.

## Limitations (structural, not just "todo")

- **Public-repo-only, no-auth, single-user, local tool** — this is a
  permanent design constraint per PRODUCT.md, not a gap to close.
- **No real concurrency.** Even with background execution, there's no job
  queue — only one scan realistically runs at a time.
- **Weak-supervised ML is inherently bounded.** Without genuine
  hand-labeled ground truth, any "accuracy" claim is only as good as the
  proxy labels it was measured against — this needs to be stated plainly
  in the report, not oversold as validated accuracy.
- **No CI/CD or staging environment.** Changes are validated against the
  live dev DB/app directly — reasonable for an FYP, not how a production
  deployment would work.
- **Detection breadth is capped by what's on PATH and the hand-authored
  rules** (`rules.yar`, `dep_checker`'s pattern lists). Genuinely novel or
  non-Python-centric attack patterns can slip through by design, not by
  oversight.

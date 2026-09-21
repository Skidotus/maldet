# MalDet — Project Notes

Snapshot as of 2026-09-22. Written for the FYP report / your own reference —
update as things change rather than treating this as a one-time record.

## Advantages (current state)

- **Real aggregation value, actually working end-to-end.** Bandit, Semgrep,
  YARA, ClamAV, and dep_checker all run and get reduced to two scored axes
  and verdicts — the core positioning claim in PRODUCT.md is real, not
  aspirational.
- **Tested against real data, not a toy demo.** The live DB has 155 scanned
  repos and ~235K findings. Every fix has been verified against that real
  data, not just unit-tested in isolation — including several bugs that were
  only findable by querying the corpus (see the IGNORE_PATHS and dep_checker
  parsing fixes below).
- **The classifier now has a ground-truth-backed number, not just
  self-grading.** A 168-finding hand-reviewed set (`eval_sample.json`) gives
  precision 0.52 / recall 0.62 / F1 0.56, against a 0.28 baseline for
  treating every finding as real. Modest, but honest and defensible — and
  improving across two measured steps: 0.49/0.38/0.43 before the
  IGNORE_PATHS fix, 0.52/0.53/0.53 after it, and the current figures after
  20 known-malicious repos were added to the training corpus (2026-09-19).
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
- **ML component has honest methodology, not just a black box.** Training
  labels are weak (bootstrapped from noise rules + repo-frequency, since
  hand-labeling 235K findings isn't feasible), but that's stated plainly
  rather than hidden, the evaluation set is held out and never trained on,
  and several real calibration problems were found and fixed by reading the
  code and querying the corpus rather than guessing (YARA under-confidence,
  dep_checker text uniqueness, the IGNORE_PATHS label contamination).
- **The tool has been turned on itself, and the result was reported rather
  than buried.** `app.py` shipped with `debug=True` on `0.0.0.0`; Bandit
  flags exactly that pattern, but the rule sits in MalDet's own
  `NOISE_RULES`, so scanning this repo with this tool would not have caught
  it. Fixed, and documented in-code as a limitation of the noise filter.

## Disadvantages (current state)

- **dep_checker still only covers Python and Node.** `go.mod`, `Cargo.toml`,
  and other ecosystems aren't parsed yet — Python (`requirements.txt`,
  `pyproject.toml`, Poetry, Pipfile, lock file) and Node (`package.json`,
  including install-hook scripts) are covered.
- **No automated test suite.** Every fix has been verified by manual/live
  testing against the real app and DB — thorough, but not repeatable or
  regression-proof going forward. The IGNORE_PATHS bug is the clearest
  argument for one: it survived in two separate copies of the same logic for
  six weeks, and a single unit test over a handful of paths would have
  caught it immediately.
- **In-memory scan job tracking.** Job status lives in a process-lifetime
  dict; a server restart kills any in-progress scan and forgets its status.
  (The dev auto-reloader used to do this on every `.py` save; `use_reloader`
  is now pinned off for exactly that reason, so this is down to deliberate
  restarts only.)
- **Existing scan data is missing findings the IGNORE_PATHS bug discarded.**
  The fix only affects new scans — findings dropped at scan time were never
  stored. Recovering them for the 155 repos already scanned needs a full
  rescan (hours of re-cloning), not the partial `rescan_yara_dep.py` path.
  Findings in `Dockerfile`/`docker-compose.yml` are the notable gap.
- **ClamAV has produced zero real hits** across all scanned repos — expected,
  since it's built for compiled malware, not source code, but worth being
  honest that this engine's contribution is currently unproven on this
  workload.
- **LLM plain-English summary is still unbuilt.** The rule-based version in
  `app.py:build_findings_summary` covers the need for now and is shaped as a
  drop-in replacement target. The Ollama-vs-hosted-API ambiguity is at least
  resolved on the code side: the unused `anthropic` dependency and
  `CLAUDE_API_KEY` slot are gone, so PRODUCT.md's Ollama/llama3.2 spec is
  now the only stated intent.
- **Hand labels are AI-assisted, not independent.** The 168-finding
  evaluation set was labeled by AI first-pass with author confirmation, and
  the author agreed with every suggestion. That has to be disclosed wherever
  the precision/recall numbers are cited — it's a weaker claim than fully
  independent review.

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

## What's improved (2026-09-14 — code audit pass)

Prompted by a read-through of the whole codebase looking for missed work.
Four commits, each verified against the live corpus rather than assumed:

- **`IGNORE_PATHS` was silently discarding real findings** (`932acd6`).
  `filter_noise()` excluded any path *containing* "test"/"doc"/etc. as a
  substring, and because "doc" sits inside "docker" it threw away every
  finding in `/Dockerfile`, `/docker-compose.yml` and `/docker/*`, plus
  `/documents.py`, `/doctor.py`, `/latest.py` and `/testimonials.py`. 931
  distinct filenames in the corpus match. Dockerfiles are squarely in scope
  for this tool (curl|sh piping, baked-in secrets, running as root), so this
  was a false-negative hole in a scanner whose entire job is not missing
  those. Replaced with `is_ignored_path()`, matching whole path segments plus
  anchored test-file conventions; verified on 34 real corpus paths (16
  previously-dropped app files now kept, 18 genuine test/doc paths still
  dropped, no regressions).
  - **It had also contaminated the model.** The same logic was written out a
    second time in `train_classifier.py`'s weak labeling, so the classifier
    was being actively *trained* to call Dockerfile findings noise. Both
    call sites now share one function. Retraining after the fix improved the
    hand-labeled scores from 0.49/0.38/0.43 to 0.52/0.53/0.53
    (precision/recall/F1) — recall being the meaningful move, 25 of 47 real
    findings caught vs. 18.
  - Timeline worth knowing: the buggy filter landed 2026-07-31, and the
    Dockerfile findings still in the DB are all from 07-29 scans, i.e. from
    before the bug. Every scan since has been dropping them.
- **`app.py` served the Werkzeug debugger to the whole local network**
  (`c67ac52`). `debug=True` on `host='0.0.0.0'` is an arbitrary-code-execution
  path for anyone who could reach port 5000. Both now default safe and are
  opt-in via `MALDET_DEBUG`/`MALDET_HOST`/`MALDET_PORT`; `use_reloader` is
  pinned off so a `.py` save can't kill an in-flight scan.
- **Two dep_checker false-positive bugs** (`1e8bc53`), both found while
  hand-labeling the evaluation set:
  - `_parse_pep508_name_version()` split compound constraints like
    `sqlalchemy<3,>=1.4` on `>=`, so the package name came out as
    `sqlalchemy<3,` — which then tripped the typosquat checker against its
    own mangled text. Now takes the name as everything before the first
    operator.
  - `is_typosquat()` compared every dependency against one Python-only
    known-package list, flagging npm's real `request` package as a typosquat
    of Python's `requests`. Now ecosystem-aware, keyed off which manifest
    the dependency came from.
- **Removed dead weight** (`fc1fce7`). The `anthropic` dependency and
  `CLAUDE_API_KEY` config slot were never imported or read by anything —
  leftovers from the unbuilt LLM summary, and they contradicted PRODUCT.md's
  Ollama spec. Also uninstalled ~838MB of unused venv packages
  (`playwright` + its browser binaries, `pillow`, `pillow-avif-plugin`).
- Smaller: archive extraction now case-folds extensions, so `payload.ZIP` /
  `malware.RaR` are no longer skipped outright (a one-keystroke evasion), and
  `'rar'` is `'.rar'` rather than matching any name ending in those letters.
  Dropped a stale `import time` and an unused `repo_url`, and a misleading
  f-string prefix on a query with nothing to interpolate.
- Rewrote the stale claims in PRODUCT.md (it still described the classifier
  and background scanning as unbuilt, and `schema.sql` as empty) and added
  the two-axis scoring model, the real evaluation numbers, and the
  AI-assisted-labeling disclosure.

## What's improved (2026-09-22 — malicious training data)

- **The classifier has finally seen real malicious code.** `malware_repos.txt`
  + `batch_scan.py` added 20 known-malicious / offensive-security repos
  (LaZagne, pupy, byob, Empire, PowerSploit, Backstabbers-Knife-Collection,
  PayloadsAllTheThings, …) to the corpus overnight on 2026-09-19. They scored
  where you'd hope — pupy 1128, Empire 871, PayloadsAllTheThings 688, all
  Critical — which is itself evidence the two-axis scoring separates
  "malicious" from "merely vulnerable" correctly. The corpus is now 178 repos
  and ~237.7K findings.
- **Retraining on that corpus moved recall, which was the stated weak axis.**
  Against the same untouched 168-finding holdout: recall 0.53 → 0.62 (29 of
  47 real findings caught, up from 25), F1 0.53 → 0.56, precision unchanged
  at 0.52. Per-tool, semgrep improved (67% → 73%) and bandit slipped
  (69% → 64%). The gain is the point: before this the model had almost no
  examples of what a genuine malicious finding looks like, since only 12 of
  156 repos carried meaningful malicious patterns.
- **Fixed: one oversized finding could destroy an entire scan's results.**
  `byt3bl33d3r/CrackMapExec` failed its save with MySQL error 1406 ("Data too
  long for column 'code_snippet'") after a 4-minute scan — one Bandit finding
  on a single-line file in `cme/modules/impersonate.py` exceeded the 65,535
  *byte* TEXT limit, and took all 240 of the repo's findings down with it.
  `save_to_db()` now fits every value to its column first (`_fit_text` for
  TEXT, byte-measured; `_fit_varchar` for VARCHAR, character-measured — the
  two limits are counted differently and the tables are utf8mb4, so a
  character-count check alone would still overflow). Exactly one snippet in
  the whole corpus needed truncating. Offensive repos are full of minified and
  generated source, so this is normal input here, not an edge case.
- Worth knowing for the report: the failed save also left an **orphan
  `repositories` row** (id 225, no findings, no risk score) that would have
  shown on the dashboard as a clean repo. `save_to_db()` commits the
  repository row before inserting findings, so a rollback doesn't remove it.
  The successful rescan repaired the row in place via the existing upsert,
  but the underlying ordering is unchanged — see below.

- **Tested and rejected: giving the model the flagged code itself.** The
  model sees `code_snippet` only as a character count, so two findings with
  the same warning text are indistinguishable to it no matter what the code
  does. A real pair from Empire, both scoring 0.3797:
  `subprocess.call("su - ahmed -c 'echo {{payload}} | base64 --decode | sudo bash'")`
  and `subprocess.check_output("which powershell")`. Added the snippet text
  as a second TF-IDF feature (line numbers stripped, code-style token
  pattern, `min_df=5` so per-repo identifiers can't be memorised) and
  retrained. **It did not work**, and the reason matters more than the
  result:
  - Against the same 168-finding holdout: precision 0.52 → 0.50, recall
    0.62 → 0.64, F1 unchanged at 0.56. One more real finding caught, three
    more false alarms. A wash, on a 168-item sample — i.e. noise.
  - The Empire pair afterwards: 0.362 vs 0.367. Still indistinguishable.
  - Code tokens drew only 4.5% of total feature importance, and the ones it
    did use were generic (`login`, `requires`, `assert`, `subprocess`) — not
    `base64`, `sudo` or `bash`.
  - **Diagnosis: the bottleneck is the labels, not the features.** The weak
    labels are generated from repo-rarity and the noise-rule list, and
    nothing in them encodes "base64 piped to sudo bash is dangerous". The
    model cannot learn a distinction its answer key never makes, so richer
    input about the code had nothing to attach to. Reverted; the patch is
    kept for the report rather than the tree.
  - **The implication for the next step**: the way to make this model reason
    about danger is a better label source, not better features. The obvious
    candidate now exists — 20 repos known to be malicious vs ~150 ordinary
    ones — which is a far stronger signal than rarity and is currently used
    only as extra training rows, not as labels.

## What needs improvement (near-term, actionable)

- **Full rescan of all 155 repos** to recover the findings the IGNORE_PATHS
  bug discarded — particularly `Dockerfile`/`docker-compose.yml`. Hours of
  runtime, so an overnight job; `rescan_yara_dep.py` won't do it since the
  loss is in Bandit/Semgrep output.
- **Make `save_to_db()` atomic.** It commits the `repositories` row before
  inserting findings, so any failure during the findings loop leaves a repo
  row with no findings and no risk score — which renders as a clean, Safe
  repo rather than a failure. This actually happened (CrackMapExec, above).
  Dropping the intermediate commit would fix it; the reason to think before
  doing so is that the largest repo in the corpus has ~157K findings, and
  that becomes one very large transaction.
- **Automated tests.** Route smoke tests plus unit tests over
  `is_ignored_path()`, `_parse_pep508_name_version()`, `normalize_severity()`
  and now `_fit_text()`/`_fit_varchar()` — the places where a silent logic bug
  has already happened at least once each.
- **Extend dep_checker to other ecosystems** (`go.mod`, `Cargo.toml`, etc.);
  Python and Node are covered.
- **Build the Ollama/llama3.2 plain-English summary.** Scope it to the top
  ~20 findings per scan, not all of them — per-finding LLM inference across
  the corpus is hours-to-days versus seconds for the Random Forest, so the
  Random Forest stays the scorer and the LLM only explains.
- **Dockerise for the team** — `bandit`/`semgrep`/`yara`/`clamscan`/`7z`
  plus MySQL is a painful per-person install, and a compose file would make
  it one command. Needs env-var config (since `config.py` is gitignored),
  a story for `semgrep login`, and ClamAV's ~300MB signature DB.
- **Independently confirm a slice of the evaluation labels**, or have a
  groupmate review the ambiguous ones, so the precision/recall figures rest
  on something stronger than AI-suggested labels the author agreed with
  wholesale.

## Limitations (structural, not just "todo")

- **Public-repo-only, no-auth, single-user, local tool** — this is a
  permanent design constraint per PRODUCT.md, not a gap to close.
- **No real concurrency.** Even with background execution, there's no job
  queue — only one scan realistically runs at a time.
- **Weak-supervised ML is inherently bounded.** *Training* labels are still
  proxies (noise rules + repo-frequency), because hand-labeling 235K
  findings isn't feasible for one person — so the model can only ever be as
  good as those proxies allow. What has changed is the *evaluation*: the
  168-finding hand-reviewed holdout gives a real number (precision 0.52,
  recall 0.62) instead of the model grading itself. Quote those figures, not
  `train_classifier.py`'s self-graded ones, and state that the labels were
  AI-assisted with author confirmation.
- **Recall is still the weak axis, and that's a design posture worth
  defending explicitly.** At the 0.5 confidence threshold the classifier
  misses 18 of the 47 genuinely real findings in the evaluation set (it
  missed 22 before the malicious repos were added). It is
  tuned to favour a quiet, trustworthy list over a thorough one. For a
  "should I install this?" pre-flight check that's arguable; for an audit
  tool it wouldn't be. Lowering the threshold trades precision back for
  recall and can be re-measured against the same holdout.
- **No CI/CD or staging environment.** Changes are validated against the
  live dev DB/app directly — reasonable for an FYP, not how a production
  deployment would work.
- **Detection breadth is capped by what's on PATH and the hand-authored
  rules** (`rules.yar`, `dep_checker`'s pattern lists). Genuinely novel or
  non-Python-centric attack patterns can slip through by design, not by
  oversight.

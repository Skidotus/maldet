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

- **Added GuardDog as a sixth detector** (`run_guarddog()`), Datadog's
  supply-chain malware scanner. It is the first detector in the pipeline that
  reasons about *malicious intent* rather than insecure coding: reverse
  shells, obfuscated payloads (base64/chr/steganography/PyArmor), install-time
  network calls in `setup.py`, browser-credential and process-memory access,
  cryptomining, DLL injection, npm preinstall hooks. Confirmed working on real
  malicious source — 13 findings on LaZagne, including Firefox credential
  reads and memory scraping, which is precisely what that tool does.
  - **Only `threat-` rules and correlated risks are reported.** GuardDog
    separates what code *can* do (`capability-*`) from what it *is* doing
    (`threat-*`), and only treats the pair together as a real risk. Reporting
    bare capabilities would add thousands of low-severity rows — the exact
    noise problem the rest of this pipeline exists to solve — so they're
    dropped unless the correlation engine surfaced them in `risks`.
  - **It cannot go in `requirements.txt`.** GuardDog requires click >=8.4.1;
    semgrep pins click ~=8.1.8. Installing it into `venv/` upgrades click and
    breaks semgrep with no warning. It lives in `.venv-guarddog/` (gitignored)
    and is invoked as an external command like `yara`/`clamscan`/`7z`;
    `run_guarddog()` prefers a `guarddog` on PATH so the Docker install (own
    venv under /opt, symlinked) wins. Docker verifies it immediately after
    install, because like every detector here it skips silently when missing —
    a failed install would otherwise look like a clean scan.
- **Corrected a wrong assumption in the malicious corpus.**
  `dasfreak/Backstabbers-Knife-Collection` was added on 2026-09-19 as the
  supply-chain centrepiece — "real malicious npm and PyPI packages". It isn't.
  The git repo is 2.8MB of HTML, CSS, fonts and two `.js` files: the dataset's
  landing page. The samples are distributed separately. It scores 4 (Low) and
  GuardDog finds nothing, correctly. One of the 20 "known-malicious" training
  repos therefore contributes no malicious examples, and the note in
  `malware_repos.txt` now says so. Worth stating in the report as a corpus
  limitation found by inspection rather than assumed away.

- **Built the plain-English summary on Ollama** (`llm_summary.py`), the item
  that had been sitting in this list since 2026-09-14. This is the piece that
  actually answers "can a model read the tools' output?" — and it can,
  because every detector already normalises to one shape, so summarising six
  engines is just summarising one uniform list.
  - **It explains, it never scores.** The Random Forest decides what's real
    and `calculate_risk()` decides how bad it is, both before the LLM sees
    anything; the prompt is handed the finished risk levels and explicitly
    forbidden from re-rating them. This is the boundary to defend in the
    report: the scoring component is measured (0.52/0.62 against a
    hand-reviewed holdout), the explainer is not, and swapping which one does
    the deciding would throw that away. A fluent model will happily
    contradict a measured number if the prompt leaves it room to.
  - **Top ~15 finding *groups*, not all findings.** Findings are collapsed by
    (tool, issue_text) and ranked by severity weight x classifier confidence
    — the same weights `calculate_risk()` uses, so "top" means the same thing
    the score next to it means. Grouping also tells the model "this fired 43
    times" instead of making it count 43 near-identical lines.
  - **Generated once at scan time**, stored in `risk_scores.llm_summary`
    (new column, in `schema.sql` and applied to the live DB). Generating on
    page view would cost tens of seconds per refresh — this is CPU-only on
    the dev machine, which has no GPU and 3.7GB free.
  - **Optional infrastructure.** Every path returns None rather than raising:
    not installed, not running, timed out, empty or unparsable response. The
    rule-based `build_findings_summary()` stays as the fallback and the
    template shows one or the other, never both. Verified: with Ollama
    absent a full scan completes normally and the detail page renders the
    rule-based text.
  - **Not yet verified against a live model** — Ollama needs a sudo install
    and isn't on this machine. The fallback path, grouping, ranking and
    prompt construction are tested; the generation path is not.

## What's improved (2026-09-23 — deployment, queue, model selection)

The deployment target was fixed this week: a 4GB / 100GB Ubuntu 24 VPS,
already approved and paid for by the management team, so the hardware is a
constraint to design against rather than a variable. Most of what follows
follows from that number.

- **Measured what the pipeline actually costs, instead of guessing.** Peak
  resident memory, taken with `/usr/bin/time -v` on a trivial directory —
  real repositories are worse:

  | component            | peak RAM  |
  |----------------------|-----------|
  | semgrep              | 1,976 MB  |
  | clamscan             |   992 MB  |
  | qwen3.5:2b (loaded)  | ~2,400 MB |
  | MySQL                |   131 MB  |
  | Flask app            |    48 MB  |
  | worker (idle)        |    39 MB  |

  The shape of that table is the finding: **semgrep costs 40x the web
  application it serves**. Effort spent optimising the web tier would have
  been wasted. Note too that clamscan takes ~39s to load 3.6M signatures
  *before scanning a single file*, every invocation.

- **Scans are queued, and exactly one runs at a time.** Job state moved from
  an in-memory dict to a `scan_jobs` table, consumed by a separate
  `worker.py` process. The old design was honest about being single-user;
  deployed, it lost every running scan on restart, was invisible across web
  workers, and redirected a second visitor into whichever scan was already
  running — so two people scanning meant one of them watched a stranger's
  progress bar. The single-consumer rule (`claim_next()` refuses while
  another job runs, under a row lock) is a memory constraint before it is a
  correctness one: 1.1GB baseline + one semgrep is 3.1GB of 4GB, and two
  semgreps do not fit at all. Verified with three simultaneous submissions
  through the web form: positions 0/1/2, drained strictly in order,
  available memory never below 3.3GB.

- **`queued_at` is `DATETIME(6)` because whole seconds were wrong.** Three
  jobs submitted in the same second compared as simultaneous, so every
  visitor was told they were first. Caught by the concurrency test, not by
  reading the code — worth remembering that the bug was in a timestamp
  column, not in the locking.

- **gunicorn replaces the Flask development server**, which the container
  had been running in production. Two workers, ~121MB for master and both.
  The worker stays a separate service precisely because it isn't one: were
  the scanner inside the web process, `--workers 2` would mean two
  concurrent semgreps. For local development `python3 app.py` now starts an
  inline worker thread, since gunicorn imports the module rather than
  executing `__main__` — one command locally, two processes deployed, no
  configuration switch.

- **The LLM explainer was chosen by comparison, not preference.** All three
  candidate models were run against real findings from the corpus
  (`samratashok/nishang`, malicious; `AlessandroZ/LaZagne`, insecure but
  not):

  | model         | warm speed | verified problem                      |
  |---------------|------------|---------------------------------------|
  | qwen3.5:2b    | 22s / 32s  | markdown despite being told not to    |
  | granite4.2:3b | 29s / 60s  | none                                  |
  | llama3.2:3b   | 36s / 43s  | invented "426.0 **out of 1000**"      |

  llama3.2 fabricating a maximum that does not exist is disqualifying for a
  tool whose output is its scores, and it was dropped. Worth recording
  honestly: an earlier reading of this comparison accused qwen of inventing
  `xml.dom.minidom`, and checking the prompt showed the string was in the
  input all along — the model was right and the reviewer was wrong. Two
  repositories judged by eye is enough to pick a default and **not** enough
  to claim a methodology; a real evaluation would need ~20 repos with the
  checks scripted.

- **Both reasoning models break the naive integration, in opposite ways.**
  qwen and granite think before answering. Left alone, qwen spends its
  entire token budget thinking and returns an *empty* response; granite
  writes its reasoning inline, which would have been stored in
  `risk_scores.llm_summary` and rendered to the user as though it were the
  summary. `"think": False` fixes both and is ignored by non-reasoning
  models. The second failure is the dangerous one — it does not error, it
  produces confident-looking prose that is not an answer.

- **The explainer is disabled on the VPS, and that is the right call.**
  740MB baseline + 2.4GB model leaves nothing for a 2GB semgrep. Because
  every path in `llm_summary.py` returns `None` rather than raising, the
  rule-based summary renders instead and no scan fails —
  `MALDET_OLLAMA_DISABLE=1` is the default in `docker-compose.yml`. The
  feature being optional is what makes a 4GB deploy possible at all.

- **Found: 12,238 findings have no code snippet, and it is not a bug in this
  code.** Semgrep withholds the matched line for registry rules when not
  authenticated, storing the literal string `requires login` instead. All of
  them are from the 2026-07-29 and 2026-08-22 runs, before `semgrep login`;
  every scan since 2026-09-15 is clean. 105 repos are affected, listed in
  `rescan_requires_login.txt`. The snippet was never captured, so only a
  rescan recovers it. It does not affect the LLM summary, which is built
  from rule messages and file paths rather than snippets.

- **Dev-environment finding worth writing down: `systemd-oomd`, not a VS Code
  bug.** The editor was killed twice in one day mid-session. The kernel OOM
  killer never fired, so `dmesg` showed nothing; `systemd-oomd` did, killing
  the whole `snap.code.code-*.scope` (29 and 31 processes) once the user
  slice passed 50% memory pressure for 20 seconds. Both times the trigger
  was Ollama loading a model on a 7.9GB VM. This is why the summariser now
  sets `keep_alive` — it was the model sitting idle for Ollama's default
  five minutes after a scan, not generation itself, that crossed the
  threshold.

## What's improved (2026-10-07 — rescan, and what the corpus does on its own)

The rescan NOTES has been owing since 2026-09-14 finally ran, against the 18
repos still carrying their original 2026-07-29 scan. It cleared 10 of them.
The other 8 are the interesting part: they did not fail for one reason, they
failed for three, and only one of the three is fixable.

- **The corpus decays while you are not looking.** `malware_repos.txt` records
  every entry as confirmed live against the GitHub API on 2026-09-19. Three
  weeks later, five of the 18 could no longer be rescanned as themselves.
  Three distinct mechanisms, which matters because they fail differently:

  - **Deleted or made private — 4 repos, permanent.**
    `department-of-veterans-affairs/vets-website`, `Yu9191/Rewrite`,
    `parti-renaissance/espace-adherent`, `adminlove520/Poc-Monitor_v1.0.1`.
    All four return HTTP 404 to an authenticated API request; verified
    individually rather than inferred from the scan error. Their 349
    withheld code snippets are gone for good, because that text was never
    captured and the source no longer exists.

    Their severities, however, were repaired without rescanning anything —
    see "the severities did not need a rescan at all" below. The first
    version of this section claimed both were unrecoverable, which was
    wrong, and wrong in the expensive direction: it sent the next step
    towards a VPS rescan when a one-second UPDATE was sufficient. The
    lesson worth keeping is that "the repository is gone" and "the data is
    unrecoverable" are different claims, and the second does not follow
    from the first.

  - **Renamed or transferred — 1 repo, and this one is quiet.**
    `envoyproxy/ai-gateway` is now `theagentrouter/agent-router`. The GitHub
    API follows the redirect and answers HTTP 200 with the *new* full_name,
    so `get_repo_info()` is handed a different owner and name than it asked
    for, `save_to_db()` upserts on the key it was given, and a second row
    appears (id 294) while the original (id 72) keeps its July findings
    forever. The batch log recorded `OK envoyproxy/ai-gateway` for a scan of
    something else. A 404 fails loudly; a rename succeeds under another name
    and leaves an orphan, which is worse. `dedupe_repositories.py` does not
    catch it either — that cleans duplicates of the *same* name, and these
    are two names for one repository.

  - **Cannot be cloned here at all — 3 repos, and not for the reason it
    looks like.** `vxunderground/MalwareSourceCode` (2,172MB),
    `mlflow/mlflow` (1,457MB) and
    `juliocesarfort/public-pentesting-reports` (719MB), sizes from the API.
    All three failed a 300s clone timeout, and all three failed again at
    900s.

    The cause took two wrong guesses to pin down, which is itself worth
    recording. It is not rate limiting (the token was at its full
    5000/5000) and it is not server-side pack generation: run with
    `git clone --progress`, git sits in "Receiving objects" transferring
    steadily, not waiting. It is simply a slow connection. Measured on the
    same link, each sustained over 60 seconds — codeload.github.com
    46 KB/s, raw.githubusercontent.com 124 KB/s, a CDN 119 KB/s — against a
    clone rate of 36-45 KiB/s. The clone matches codeload almost exactly,
    so the slowest host on a slow link happens to be the one git pack data
    comes from. At 40 KB/s, 719MB is ~5 hours, 1,457MB ~10 and 2,172MB ~15.

    Which makes this not a decision about these repositories at all. No
    timeout fixes a link, and nothing is wrong with the repos — they are
    large, and this dev VM is on a phone hotspot at ~120 KB/s. They want a
    faster connection, so **rescanning them belongs with the VPS
    deployment**, where the link is a datacentre link and the same clones
    should take minutes. Folding it into work already owed is better than
    either running a 15-hour clone here or writing the repos off. In the
    meantime they hold 390 of ~223,000 findings, so the scoring impact of
    the delay is marginal. `CLONE_TIMEOUT` is 900s, env-overridable via
    `MALDET_CLONE_TIMEOUT`.

  Worth stating in the report as a limitation of corpus-based evaluation
  rather than a defect: 5 of 18 in three weeks is a ~28% churn rate on an
  arbitrary slice, and any figure computed over the corpus is a figure over
  the corpus *as it was when scanned*.

- **The severities did not need a rescan at all, and six repos were being
  reported at the wrong risk level.** This was the actual cost of the stale
  data, and it was missed for weeks because "stale repo" sounded like a
  tidiness problem.

  Semgrep names its severities `error`/`warning`/`info`;
  `normalize_severity()` maps those to `high`/`medium`/`low`. The July scans
  predate that mapping being applied, so 779 findings sat in the database
  with Semgrep's own words — and `SEVERITY_WEIGHT` has no entry for them, so
  `.get(severity, 1)` scored every one as 1. A Semgrep `error` (its most
  serious class: script injection, `child_process` from an argument, a
  hardcoded API key) counted exactly the same as "you used http:// instead
  of https://".

  The repair needed no network at all. The raw values were still stored and
  the mapping is a pure lookup, so three UPDATE statements plus the existing
  `recompute_scores.py` / `recompute_category_scores.py` fixed it:
  134 `error` → high, 556 `warning` → medium, 89 `info` → low. Result, on
  the six repos whose level was wrong:

  | repo | vulnerability |
  |---|---|
  | `department-of-veterans-affairs/vets-website` | High 94 → **Critical 478** |
  | `vxunderground/MalwareSourceCode` | High 162 → **Critical 498** |
  | `Yu9191/Rewrite` | Medium 48 → **High 180** |
  | `parti-renaissance/espace-adherent` | Medium 26 → **High 95** |
  | `envoyproxy/ai-gateway` | Low 14 → **Medium 60** |
  | `juliocesarfort/public-pentesting-reports` | Low 15 → **Medium 60** |

  `vets-website` was off by a factor of five. Note that four of the six are
  the repositories that no longer exist on GitHub — so the fix reached
  precisely the data that had been written off as unrecoverable.

  Running the recompute also moved five repos unrelated to the severity
  problem (`django/django` High → Critical, `InQuest/malware-samples`,
  `JustVugg/colibri` and `Ne0nd0g/merlin` High → Medium,
  `opentofu/opentofu` Low → Safe), because their stored scores predated the
  current classifier-weighted formula. The whole corpus is now on one
  formula, which is the state any reported figure should be computed from.
  Distribution afterwards: Medium 45, Critical 40, High 39, Low 33, Safe 22.

  The methodological point for the report is not the fix, it is how it was
  found. The question "does this stale data actually change any number?"
  had not been asked for weeks of treating the staleness as housekeeping.
  It was asked only because the premise — that a deleted repository matters
  — was challenged, and the honest answer to the challenge was that it
  matters for the scores, not for the repository.

- **A failed scan no longer reports a repo as clean.** `save_to_db()`
  committed the repositories upsert and both DELETEs before writing a single
  finding, so a failure in the inserts left the row present with no findings
  and no risk_scores row — which renders as Safe, not as an error. The
  intermediate commit is gone and the whole save is one transaction, so a
  failed rescan leaves the previous results intact. The objection NOTES
  raised against doing this (157k findings in one transaction) is answered by
  batching with `executemany`: 20,000 synthetic findings in 0.5s, ~38,700
  rows/second, so the largest repo is about four seconds inside the
  transaction. Verified by saving three findings, then saving again with one
  deliberately unserialisable finding, and confirming the original three
  survived.

- **The summariser has a number now, and the number is about the checks.**
  `evaluate_summaries.py` scores a stratified sample against eight
  mechanical checks (fabricated numbers, invented scales, fabricated
  filenames, fabricated advisory ids, fabricated tool names, risk-level
  contradiction, and four format rules). First real run, 20 repos,
  qwen3.5:2b: 19 produced a summary and **17 passed everything — 89%**. Both
  failures were six sentences where the prompt asks for three to five, read
  and confirmed as genuine rather than a splitter artifact.

  The run's real finding was in the checker, twice. It first reported 68%,
  flagging four summaries for fabricated numbers — all four being the prompt
  stating "291.0" and the model writing "291". And the contradiction check,
  on its first run, flagged two summaries that were saying the opposite of
  what it claimed: "need immediate attention *before* it can be used safely"
  matched "can be used safely", and "some signs of *potentially* malicious
  intent" matched "malicious intent". Both corrections went towards
  precision, because a checker that flags correct output gets ignored and
  then catches nothing. **The first thing a measurement catches is usually
  the measurement** — which is a better sentence for the report than a clean
  score would have been.

- **The summary no longer blocks the results.** It used to run inside
  `scan_repo()` between scoring and saving. A nishang scan is 48s and its
  summary another 88s, so nearly two thirds of the wait was a paragraph. The
  scan now saves and returns, the worker generates afterwards, and the detail
  page shows a placeholder with the rule-based summary beneath it until the
  real one arrives. Three independent ways it stops waiting, because a
  spinner that never resolves is worse than no spinner: the worker marks the
  row unavailable on failure, a dead worker's "pending" rows are released at
  the next startup, and the page gives up after four minutes.

- **Four grouping bugs, found by building a second implementation.** The
  SQL-side aggregation in `backfill_summaries.py` does the same job as
  `llm_summary._rank_groups()`, so the two were diffed across all 162 scored
  repos — every disagreement was a defect. Two were pre-existing and had been
  live since the feature shipped: a group's severity could be *downgraded*
  by a less-severe finding the classifier was more confident about (the
  comment claimed to break ties on confidence; the code used `or`, which does
  not), and equal-scoring groups were ordered by whatever order the findings
  happened to arrive in, so 21 of 162 repos selected a different top 15
  depending on the path taken. Two were new: a stored confidence of 0.0 read
  as 1.0 through `x or 1.0`, inverting "certainly noise" into "certainly
  real", and MySQL's case-insensitive collation merging 17 issue_texts that
  Python keeps apart — "Possible hardcoded password: 'abc'" with "...'ABC'".
  Both paths now build a byte-identical prompt for 161 of 162 repos and
  select the same top 15 for all 162.

## What's improved (2026-11-07 — IOC extraction)

- **Indicators of compromise on every new scan.** `ioc_extractor.py` reads files
  ClamAV or YARA flagged plus install scripts, hashes the flagged files, and stores
  the results in `iocs` and `ioc_runs`. The report page lists them as plain text,
  with CSV and JSON downloads. abuse.ch lookups are optional and off without
  `ABUSECH_AUTH_KEY`.
- **Why metadata is skipped, not just safe-listed.** The requested safe-domain list
  was not enough: Flask's `pyproject.toml` names `palletsprojects.com` and
  `discord.gg`, and Django's names `djangoproject.com`. Those are an author's own
  links and no list can keep up, so install scripts are parsed and only their
  working parts searched. Measured on the root install scripts of 23 well-known
  Python and npm projects: 0 indicators. A real Flask scan: 0 indicators, 62s.
- **Flagged files are noisier, and that is known.** They are searched whole, by
  design. `kserve/kserve`, a legitimate project with 39 YARA findings, gave 43
  indicators (19 hashes, 15 URLs, 9 domains), all harmless: `astral.sh` from
  `curl | sh` in Dockerfiles that `detect_pipe_to_shell` flagged, plus documentation
  links in comments. Each is true, but none means compromise. Read an IOC as "this
  address is in a suspicious file", not as a verdict. If it proves too noisy, the
  first things to try are skipping comments in flagged files, or not counting files
  flagged only at low severity.
- **Why `ioc_runs` exists.** An empty `iocs` could mean nothing found, extraction
  failed, or a scan from before this feature. Only the first may say "No indicators
  of compromise found"; older scans say they were not extracted.
- **Threat-intel weights** (thresholds unchanged): MalwareBazaar 101 points, which
  is Critical on the malware axis; URLhaus 36 each, capped at 72, which is High. Both
  skip the classifier. They are judgement calls set to land just past the existing
  thresholds, and have not been calibrated against the corpus.

**Limitations to state in the report:**
- The abuse.ch calls have only been tested against mocked responses shaped like the
  documented API, because no key was available. Run one real scan with a key before
  claiming they work.
- Safe-listing `github.com` and `githubusercontent.com` means a payload hosted on
  GitHub produces no URL indicator. That was requested to keep clean projects quiet,
  and it is a real blind spot, since attackers do host there.
- Filtered paths are skipped too, so malware under `tests/` or `docs/` gets no IOCs,
  matching `filter_noise()`.
- Discord webhooks and Telegram tokens are shown in full, including on the public
  site. They are already public in the scanned repository, but they are live
  credentials, so consider masking them if that becomes a concern.
- Existing scans have no IOCs until rescanned.

## Evaluated, not adopted (2026-11-07 — Kaspersky KVRT as a second AV)

An industry contact said one AV is not enough. VirusTotal was rejected over its API
limits, so KVRT for Linux 24.0.6.0 was run locally, report-only, as a normal user, over
the same files as `rules.yar`, YARA Forge and ClamAV. Counts are distinct flagged files
outside `is_ignored_path()`, with the corrected `rules.yar`.

| | KVRT | rules.yar | Forge | ClamAV |
|---|---|---|---|---|
| 23 clean repos (75,086 files): flagged files | 0 | 34 | 0 | 0 |
| 20 offensive repos (7,968 files): flagged files | 604 | 215 | 114 | 293 |
| Offensive repos with any hit | 13 | 14 | 10 | 10 |

- **Files, not repos.** KVRT flagged 293 files no other engine did, but no repo that the
  others all missed: 15 of 20 had a hit with or without it. Other engines flagged 219
  files it missed, such as all 28 in `merlin`.
- **Cost:** 4-36s per repo, 348-514MB peak. Far cheaper than ClamAV, which took 1,068s
  for the whole set in one pass.
- **Read with care.** 456 of the 604 are heuristic labels (`HEUR:...`). Nobody checked
  that flagged files are really malicious, so this measures agreement, not accuracy. Zero
  on clean repos is over popular projects only. Archives were not extracted first, which
  `scan_repo()` would do, so samples in password-protected archives were not seen.
- **Why it is not adopted yet:** the licence is the open question, not a clear ban. The
  2024 Linux EULA ships inside `bin/libKvrtGui.so`. It never mentions public sites or
  services, and it does not restrict publishing results. Clause 2.1 allows use "within the
  scope of functionality" in the manual, and 2.2 allows distribution and some commercial
  use. The risk is 5.3: "You shall not use the Software in the creation of data or
  software used for detection, blocking or treating threats". MalDet is detection
  software, and `train_classifier.py` learns from `scan_results`, so KVRT findings stored
  there could fall under it. 5.2 also bars renting or leasing it to third parties. Get
  Kaspersky's answer in writing, and keep KVRT output away from rule tuning and classifier
  training until then. Separately: suspicious files may go to Kaspersky through KSN,
  signatures need a 164MB re-download, and it exits 0 even when it finds threats.

This also corrects the note above that ClamAV has produced zero real hits: on these
repos it flagged 293 files, and none in the clean set.

## Evaluated, not yet adopted (2026-11-09 — extra ClamAV signatures)

The licence-free alternative to a second AV: unofficial signature lists loaded into the
ClamAV MalDet already runs. Fetched with `fangfrisch` 1.9.3 from its two sources that
need no sign-up, **SaneSecurity** (its default set, 40 files) and **InterServer**
(4 files, PHP webshells): 44 files, 19MB. Same 43 repositories and method as KVRT
(tarballs unpacked as data, `helm/helm` failing on an absolute symlink both times), run
twice with the official database dated 2026-09-23: official signatures alone, then the
extra lists alone, so each file's hit can be attributed. Counts are distinct files kept
by `is_ignored_path()`.

| | Official | Extra lists | Extra only | Together |
|---|---|---|---|---|
| 23 clean repos (75,105 files): flagged files | 0 | 0 | 0 | 0 |
| 20 offensive repos (7,968 files): flagged files | 293 | 208 | 47 | 340 |
| Offensive repos with any hit | 10 | 8 | 0 new | 10 |

- **Cheap.** Loading both sets peaked at 1,034MB against 968MB for the official set alone
  (+66MB), and the load was no slower (8.5s against 12.3s, i.e. noise). The extra lists
  alone scanned all 43 repos in 4m55s at 260MB. The official baseline matched the
  2026-11-07 run exactly (293 files), so the repos had not drifted.
- **Files, not repos**, exactly like KVRT: +47 files (+16%), and no repository the
  official signatures missed. The 10 offensive repos with no ClamAV hit stay at zero.
- **What fired:** SaneSecurity `Malware.*` (117) and `Badmacro` (84, Office macros), most
  of them heuristic (`Heur.BadOne.Pshell`, `JsHeur`), and 4 InterServer PHP webshell hits.
  Nobody checked the flagged files, so this is agreement, not accuracy; zero on clean
  repos is over popular projects only.
- **Terms:** SaneSecurity's legal page allows free use including commercial products, but
  its usage page asks organisations for a donation (suggested $100). InterServer calls its
  lists free; no written licence was found. URLhaus (abuse.ch) needs a free key and was not
  tested; it is the list most likely to matter for source code, since it is malware URLs.
- **Not adopted yet** because the gain is small and adopting means a refresh job
  (`fangfrisch refresh`, hourly upstream) in the Docker image. If adopted, pass the extra
  directory with a second `-d` rather than copying into `/var/lib/clamav`, so `freshclam`
  and `fangfrisch` never fight over one directory.

## What's improved (2026-11-09 — hidden payloads, and no more "Safe")

Two ideas taken from FlatScan (https://github.com/Masriyan/FlatScan, MIT), a Go
single-file malware analyser: its recursive payload resolution, and its lowest band
reading "No strong indicators. Not a clean verdict."

**Hidden payloads (`payload_decoder.py`, `scanner.run_decoded_payloads()`).** YARA and
ClamAV read files as they are, so code shipped as base64 is a long run of letters to
both of them. The new stage peels base64 (also reversed and URL-safe), hex, `\x41`
escapes and character-code lists, then zlib/gzip/bz2/xz, up to three layers; keeps a
layer only if it looks like code or carries executable magic bytes; and runs both YARA
rule sets and ClamAV over what it kept. Matches are reported on the original file and
line as `Hidden payload: ...`, with the decoding chain and decoded text as the snippet.

Measured on the same 43 repositories as KVRT and the extra ClamAV signatures:

| | Clean (23 repos) | Offensive (20 repos) |
|---|---|---|
| Strings decoded and kept | 23, in 6 repos | 126, in 9 repos |
| Hidden-payload matches | **0** | 49 (35 high, 14 medium), 26 files, 6 repos |
| Files no engine flagged in plain sight | 0 | **17** |
| Time for the stage, per repo | median 0.7s, max 14.6s | median 0.5s, max 30.0s |

- **The 17 files are real tools, named.** Empire's PowerShell modules each carry a
  compiled .NET tool as one base64 string: Rubeus, Seatbelt, SweetPotato, Watson,
  SharpSecDump, SharpChromium, SpoolSample, WireTap and more, identified by YARA Forge's
  `HKTL_NET_GUID_*` rules and ClamAV once decoded. CrackMapExec's NanoDump, HandleKatz
  and process-injection modules, and two InQuest samples, are the rest. Before this
  stage MalDet saw all 17 as text.
- **Repos, again, did not change**: all 6 already had plain-sight hits. What it adds is
  coverage inside a repo, plus the ability to say *what* is hidden in a file.
- **Cost is mostly ClamAV's signature load** (~10-12s), paid only when something was
  decoded; decoding itself took at most 30s (Empire, 41 payloads). Capped at 60s and 500
  payloads, each a visible "decoding incomplete" marker if hit; neither was hit here.
- Single-byte XOR, which FlatScan also peels, is not done: on source code every long
  string "decodes" under some key, and the false-positive cost was not worth it.
- Read with care: one corpus, nobody verified the flagged files, and zero on clean
  repos is over popular projects. Covered by `tests/test_payload_decoder.py` (16 tests,
  including a hidden reverse shell plain YARA misses).

**"Safe" now reads "Nothing found".** A static scan can fail to find problems; it
cannot show a repository is safe. Every page, the printable report, the extension popup
and the LLM prompt show the lowest level through `scanner.level_label()`, and the report
says outright that it is not proof of safety. The stored value stays `Safe` (thresholds,
database, extension API and evaluation scripts key on it), so no saved scan changed.
The prompt change means the 17-of-19 summary evaluation predates it; re-run
`evaluate_summaries.py --generate` before quoting it as current.

**Re-run the same day, and it showed the label change was not enough.** The first run
with "Nothing found" in the prompt scored 18 of 20 clean, but reading the summaries for
the "Safe" repos, 5 still said things like "found to be completely safe" and "passed all
major security checks", one of them about dasfreak/Backstabbers-Knife-Collection, a
collection of offensive tools. The checker missed it because its safety check only ran
for High/Critical repos. Two fixes: a ninth check, `claims_safety` (any summary calling
a repo safe or clean, or saying it passed, fails, whatever the level), and a prompt rule
("Never call the repository safe or clean, and never say it passed the checks…").
Same 20 repos (the sample is a fixed order), qwen3.5:2b, all nine checks:

| Prompt | Fully clean | Safety claims | Other failures |
|---|---|---|---|
| Label only (`summary_eval_2026-11-09.json`) | 13 of 20 (65%) | 6 | 2 sentence count |
| Label + rule (`summary_eval_2026-11-09b.json`) | **15 of 20 (75%)** | **2** | 3 sentence count |

The two left: "safe to use" mid-paragraph (aimeos/pagible) and "looks safe from known
bugs" (the offensive-tools collection again). A 2B model does not follow every rule; the
check keeps counting it. **Quote 15 of 20 (75%) with nine checks, not the old 89%:**
re-scoring the October run (`summary_eval.json`) with today's checker gives 9 of 19,
mostly `fabricated_numbers` (5), so the checker has changed since that figure was taken
and the two are not comparable.

*In plain words:* telling the AI the level is "Nothing found" was not enough; it still
wrote "completely safe" in its own words. It now has an explicit rule against that, and
the automatic checker now catches the claim, which brought it down from 6 summaries in
20 to 2.

## Ideas from FlatScan, not yet built (2026-11-09)

FlatScan (https://github.com/Masriyan/FlatScan, MIT, Go, one maintainer) is a static
analyser for **one finished file at a time** (an `.exe`, a script, an Android app).
MalDet scans **whole source-code repositories**, so only some of its ideas carry over.
Two are already built (hidden-payload decoding, and "Nothing found" instead of "Safe",
above). The rest, most useful first. The first three are problems shown in MalDet's own
data, not guesses.

1. **Stop lists of bad things reading as bad things** (FlatScan `falsepositive.go`).
   MalDet looks for suspicious text, and some honest files are full of it because they
   *describe* threats: rule files, signature sets, blocklists. Shown in the local
   database: **MalDet rates its own repository High**, because `rules.yar` matches 7 of
   MalDet's own rules, and **AdguardTeam/HostlistsRegistry is Critical**, because its
   blocklists name crypto-mining sites in order to block them. FlatScan's test is
   breadth: real malware does one job, so one file that looks like ransomware, a miner,
   a stealer and a reverse shell at once is a catalogue. It then caps the score and
   treats the matches as references. A blocklist is a catalogue of one kind, so it needs
   a second check (a file that is mostly a list of domains). FlatScan pins the guard with
   tests in both directions so it can never quietly hide real malware; copy that too.
   **Done 2026-11-09, but not FlatScan's way** (`reference_files.py`). Breadth was
   measured first and rejected: across the local corpus, `rules.yar` matches 7 different
   MalDet rules, but nishang's `Powerpreter.psm1` (a real attack toolkit) and the
   deliberately malicious `maldet-demo-package/install.sh` match 5 each. Any cut-off
   that catches the rule file hides those two. So the test is the *kind* of file: a
   data-file extension (nothing runs it by itself) **and** a rule or list format in its
   first 256KB — YARA, Sigma or Snort rules, a ClamAV signature database, or a hosts /
   adblock / domain / IP list. Code is never excused, whatever it contains. Matches in
   such files stay on the report, set to low and labelled "Reference in a …, not code
   that runs", but count for nothing in the score and give no IOCs. Hidden payloads and
   threat-intel hash matches are never excused. Measured:
   - **0 of 542** flagged files in the 43 trial repos were excused, so no real tool hid.
   - **AdguardTeam/HostlistsRegistry: all 25 flagged files are blocklists** (up to 30MB
     each); malware axis Critical 180 → Medium 20, trust 13 → 60, recomputed from the
     stored findings (the recomputed "before" matches the stored 180).
   - **MalDet itself: 341 of 356 YARA matches** are in `rules.yar` and the Forge rule
     file; malware axis High 63 → Medium 28 from stored findings. What still counts is
     real code: GuardDog on the `.claude/skills/` helper scripts, and the landing page's
     decorative `static/js/hero-code.js`, whose "wall of code" contains snippets that
     look like credential theft and `curl | sh`. Worth rewording that decoration, since
     an examiner scanning MalDet will see it.
   - **End to end:** a real scan of `Skidotus/maldet` from GitHub with the new code
     (2026-11-09, LLM off) saved malware **Medium 24**, down from High; the 7 `rules.yar`
     matches are stored as low, labelled, with confidence 0.
   - 15 tests (`tests/test_reference_files.py`), both directions.
   *In plain words:* MalDet now recognises files that are lists of threats (rule files,
   antivirus fingerprint files, blocklists of bad websites) and stops treating them as
   threats. It checks what kind of file it is rather than how many rules it matches,
   because real attack tools also match many rules. A list cannot run, so its matches
   are still shown but no longer raise the score.

2. **UTF-16 blind spot.** UTF-16 stores a zero byte beside every letter, and Windows
   PowerShell scripts, attackers' favourite, are often saved that way. Tested: a reverse
   shell and download command saved as UTF-8 fired two `rules.yar` rules; the same text
   saved as UTF-16 fired **none**. `rules.yar` has no `wide` strings, and
   `ioc_extractor._read_text()` (so also the payload decoder) skips any file with a zero
   byte. Fix: add `ascii wide` to the rule strings, and decode UTF-16 (with or without a
   byte-order mark) before reading text. Small, and a proven gap.
   **Done 2026-11-09.** All 100 `rules.yar` strings are `ascii wide`, and
   `_read_text()` decodes UTF-16 (byte-order mark, or the "every other byte is zero"
   shape over the first 8KB). Over the 43 trial repos: 342 matches before, 343 after;
   the one new match is a UTF-16 PowerShell stage in InQuest's malware samples, and the
   clean repos are unchanged. Not slower; peak memory 89MB to 115MB. The YARA tests now
   check every sample, positive and negative, in UTF-8 and two UTF-16 forms.
   *In plain words:* MalDet can now read scripts saved in the "zero between every
   letter" format, so changing how a file is saved no longer hides it.

3. **One clue should not raise a serious alarm** (FlatScan `correlation.go`). FlatScan
   groups clues (credential dumping needs clues from several separate groups, not just
   the word `lsass`), fires only when enough groups agree, and records how many did.
   `rules.yar` already requires connected halves, and the classifier counts tools that
   agree on a file. Missing: showing "flagged by N separate clues/engines" on the report,
   and requiring more than one engine before a repo can reach High on the malware axis.

4. **Disguised file names** (FlatScan `masquerade.go`). Three tricks honest projects
   almost never use: a document extension followed by a program one
   (`invoice.pdf.exe`); look-alike letters (`lnstaller` with a lowercase L, `Micros0ft`,
   Cyrillic mixed into Latin); and invisible right-to-left characters that make
   `annexe‮cod.exe` display as `annexe.exe.doc`. A cheap check over file names in a scan.

5. **Tidier IOCs, and STIX export.** FlatScan labels each indicator as worth
   investigating, benign infrastructure, build artefact or source path, and keeps the
   noise out of exports. It also exports STIX 2.1, the standard format threat-intel
   tools import. MalDet already exports IOCs as CSV and JSON; STIX would be small.

6. **Label findings with MITRE ATT&CK techniques.** The industry's shared names for
   attacker behaviour (download-and-run is T1105). Add an `attack` meta field to each
   `rules.yar` rule and show it as a tag on the report. Low effort, and it ties MalDet
   to the vocabulary examiners and security teams use.

7. **A command-line / CI mode.** FlatScan has `--ci` with fixed exit codes (0 clean,
   10 suspicious, 20 malicious), so a project's build fails when it finds something. A
   small wrapper around `scan_repo()` with exit codes and SARIF output (the format
   GitHub's Security tab reads) is realistic, or a good future-work item.

8. **A verification table in the README.** FlatScan lists build, tests, lint and
   vulnerability-check results in one table. MalDet has the numbers (test count,
   classifier precision 0.52 / recall 0.62, summaries 15 of 20 clean on nine checks); keep giving the
   sample size behind each, which FlatScan does not ("Quality 10/10" is self-awarded).

9. **Machine-generated domains** (FlatScan `dga.go`). Some malware invents random
   domains (`xkqjzvbtr.com`) to stay hidden; FlatScan scores how random a name looks.
   Could tag domains in the IOC list. Nice to have, low priority.

**Not worth copying:** disassembly, `.exe` / ELF / Android / macOS parsers, naming
malware families, similarity hashing, single-byte-XOR peeling (see above) and its PDF
reports. All are for taking apart one compiled file, not a source repository.

**Suggested order:** 2 (small, proven gap), then 1 (MalDet rating itself High is the
kind of thing an examiner notices), then 6 and 4 (cheap), then the rest.

### In plain words: what was done on 2026-11-09, and what the ideas mean

The sections above are written for someone already deep in the code. This is the same
material explained simply, for reading back later or explaining to someone else.

**What was built**

- **Hidden-payload decoding.** Attackers often hide their code by scrambling it into a
  long string of random-looking letters (base64 is the most common way). A scanner that
  reads the file sees only gibberish, like a letter written in code. MalDet now
  unscrambles those strings (up to three layers deep, because attackers often scramble
  something that is already scrambled), and runs its malware scanners on what comes out.
  If it finds something, the report points to the exact file and line where the
  scrambled string sat, and shows what it said once unscrambled. Nothing unscrambled is
  ever run. On the test set it found 17 files that no scanner had flagged before, all of
  them known hacking tools, and raised no false alarms on 23 normal projects.
- **"Nothing found" instead of "Safe".** A scan can only report what its rules
  recognise. If nothing matches, that is not proof the code is safe: it may be new,
  hidden in a way no rule knows, or only fetched when the program runs. So the lowest
  level now says what actually happened, "Nothing found", and the report explains that
  this is not a guarantee. The database still stores "Safe", so no old scans changed.
- **Extra ClamAV signatures (tested, not switched on).** ClamAV is MalDet's antivirus
  engine. Volunteer groups publish extra lists of malware patterns for it. Loading them
  cost very little memory and raised no false alarms, but only found 47 more files in
  projects that were already flagged, and no new projects. Small gain, so it is written
  down rather than switched on.

**The FlatScan ideas, explained**

1. **Lists of bad things are not bad things.** MalDet hunts for suspicious text
   patterns. Some honest files are full of them because they are *lists*: a rule file
   describing what malware looks like, or a blocklist of dangerous websites. It is like
   flagging a police "wanted" poster as a criminal because it shows a criminal's face.
   That is why MalDet rates *itself* High (its rule file must contain the patterns it
   looks for) and AdGuard's blocklist project Critical (it lists crypto-mining sites so
   they can be *blocked*). FlatScan's trick: real malware usually does one job (steal
   passwords, *or* mine crypto, *or* lock files). One file that seems to do five or six
   unrelated jobs at once is almost certainly a list describing them.
2. **Text saved in a different format.** Text can be stored in different ways. The
   usual one (UTF-8) stores `hello` as five letters. Another (UTF-16) puts an empty byte
   between every letter. Windows PowerShell scripts, which attackers love, are often
   saved that way. MalDet caught a test attack saved normally, but missed the same
   attack saved as UTF-16, so an attacker could slip past just by changing how the file
   is saved. YARA (the pattern scanner) has a setting, `wide`, that makes a rule look
   for both formats; it just needs adding.
3. **Do not panic over one clue.** Some checks raise a serious alarm from a single word,
   for example `lsass`, the Windows process that holds passwords, which plenty of honest
   security code mentions. FlatScan works like a careful detective: it only raises a
   serious alarm when several *separate* clues agree, and shows how many did, so a
   reader can see how strong the case is.
4. **Disguised file names.** Attackers often trick people with the name, not the
   contents: `invoice.pdf.exe` looks like a PDF but is a program; `lnstaller` uses a
   lowercase L in place of a capital I; a hidden "flip" character can make a name
   display backwards, so `annexe‮cod.exe` *looks* like `annexe.exe.doc`. Honest projects
   almost never contain these, so checking for them is cheap and rarely wrong.
5. **Tidier lists of clues, in a standard format.** MalDet already collects suspicious
   web and IP addresses (IOCs). FlatScan also sorts them into "worth investigating" and
   "harmless background" (such as a link to official documentation), and exports them
   in STIX, the format security teams use to share threat information.
6. **Use the industry's names for attacks.** MITRE ATT&CK is a shared catalogue of
   attacker behaviour, each with an ID (download-and-run is T1105). Tagging MalDet's
   findings with those IDs makes the results speak the same language as security teams
   and examiners.
7. **Let other projects use MalDet automatically.** A command-line mode that ends with
   a code meaning "clean", "suspicious" or "malicious" lets a project's automatic build
   stop itself when MalDet finds something, the way a smoke alarm can cut the power.
8. **Show the proof in one place.** A small table in the README listing how many tests
   pass, how accurate the classifier is, and how many AI summaries were checked clean,
   each with how many examples the number came from.
9. **Spot random-looking web addresses.** Some malware makes up random addresses like
   `xkqjzvbtr.com` so they are hard to block. FlatScan scores how random a name looks;
   MalDet could tag such addresses in its list of clues. Nice to have.

Most of FlatScan's other features are for taking apart **one finished program** (an
`.exe`, an Android app). MalDet looks at **source-code projects**, so those do not fit.

**Words used above**

- **False positive / false alarm:** the scanner says "danger" when there is none.
- **YARA:** a tool that searches files for text or byte patterns described in rule
  files. MalDet's own rules are in `rules.yar`; YARA Forge is a large public rule set.
- **ClamAV:** a free antivirus engine. **Signatures** are its fingerprints of known
  malware.
- **base64 / hex:** common ways of writing any data, even a whole program, as ordinary
  letters and digits, so it can be pasted into a text file.
- **zlib / gzip:** compression, like zipping a file; often used together with base64.
- **Payload:** the harmful part of an attack, the bit that actually does damage.
- **Reverse shell:** a command that hands a stranger remote control of your computer.
- **IOC (indicator of compromise):** a clue such as a suspicious web address, IP address
  or file fingerprint.
- **UTF-8 / UTF-16:** two ways of storing text as bytes.
- **STIX:** a standard file format for sharing threat information.
- **SARIF:** a standard file format for scan results, which GitHub can display.
- **MITRE ATT&CK:** a public catalogue of attacker techniques, each with an ID.
- **CI (continuous integration):** the automatic checks that run every time a project's
  code changes.

## What's improved (2026-11-09 — two quiet problems on the live site)

**ClamAV signatures never updated.** `docker/entrypoint.sh` downloads signatures only
when none exist, and the Docker volume keeps them, so the VPS scanned with whatever it
fetched on its first start. Found on 2026-11-09: the daily set was from 1 November
(version 28171) and nothing would ever have refreshed it. Antivirus signatures miss
everything newer than they are, and nothing on the page says so. Now `worker.py` runs
`freshclam` every `MALDET_CLAMAV_REFRESH_HOURS` (24, set for the worker in
`docker-compose.yml`; off by default elsewhere), only while idle, since freshclam
test-loads the ~1GB database and must not overlap a scan on the 4GB host. Not done at
container start because the app and worker containers share the volume and both run the
entrypoint. Run by hand the same day: daily 28171 → 28178 in about 4 seconds, as the
worker's own user. Its "NotifyClamd … ERROR" line is harmless (MalDet runs `clamscan`,
no clamd daemon to notify).

Separately, freshclam reports the ClamAV *program* in the image is outdated (1.4.3,
recommended 1.4.6). That is the Debian package the image installs; rebuilding the image
with `--no-cache` picks up whatever Debian ships. Not done here.

**A visited link could start a rescan.** `/rescan/<id>` queued a scan on GET, so
search-engine crawlers, chat apps building link previews and browser prefetching could
each tie up the single scan slot for minutes. Only a POST starts one now (the report's
Rescan button is a form); a GET redirects to the report. Still open: like the scan form,
the POST has no CSRF token, so another site could submit it on a visitor's behalf. That
needs the same fix for `/scan` too, so it is left for one change covering both.

*In plain words:* the live site's virus fingerprints were stuck on 1 November and are
now updated daily by themselves; and a scan now starts only when someone presses the
button, not when a bot or a chat app merely looks at the link.

## What needs improvement (near-term, actionable)

- **Mostly done 2026-10-07: the rescan ran, and the severities are fully
  fixed.** All 1,513 un-normalised severities are now 0 — repaired in place
  rather than by rescanning, see the 2026-10-07 section. `requires login`
  findings are down from 12,238 to 389, and those 389 do need a rescan,
  since the snippet text was never captured; they are display-only and feed
  neither the scores nor the LLM prompt. They sit in 8 repos, of which 4 are
  permanently
  unfixable (deleted or private, HTTP 404) and 1 was renamed out from under
  the corpus; see the 2026-10-07 section. What is left to finish is the
  3 that only failed on a 300s clone timeout, now 900s —
  `vxunderground/MalwareSourceCode`, `mlflow/mlflow` and
  `juliocesarfort/public-pentesting-reports`, none under 700MB, so an
  overnight job when nothing else needs the memory. Use
  `rescan_stale_july.txt`, which is ordered smallest first.
- **Done 2026-10-07: `save_to_db()` is atomic.** One transaction from the
  upsert to the history row, with findings inserted in batches of 500 so the
  157K-finding repo is ~4 seconds inside it rather than minutes. See the
  2026-10-07 section for the verification.
- **Handle renamed repositories.** The GitHub API answers a renamed repo with
  HTTP 200 and the *new* full_name, so `get_repo_info()` returns an owner and
  name that differ from the ones requested, and `save_to_db()` writes a
  second row while the original keeps its old findings. Comparing the
  API's `full_name` against the requested slug would catch it; what to do
  then is a decision, not a bug fix — update the original row, or record the
  redirect and retire the old one. Until then, scanning a renamed repo
  silently produces an orphan, which is how `envoyproxy/ai-gateway` and
  `theagentrouter/agent-router` both exist in the corpus.
- **Decide what to do with the 4 dead repositories.** They will misreport
  permanently. Either drop them, taking the corpus to 175 and saying why, or
  keep them flagged as frozen at their 2026-07-29 scan. Keeping them is
  defensible if documented; leaving them silently is not.
- **Automated tests.** Route smoke tests plus unit tests over
  `is_ignored_path()`, `_parse_pep508_name_version()`, `normalize_severity()`
  and now `_fit_text()`/`_fit_varchar()` — the places where a silent logic bug
  has already happened at least once each.
- **Extend dep_checker to other ecosystems** (`go.mod`, `Cargo.toml`, etc.);
  Python and Node are covered.
- **Done 2026-10-07: the summariser is evaluated.** `evaluate_summaries.py`,
  20 repos stratified across the risk levels, eight mechanical checks:
  17 of 19 clean, 89%, both failures being sentence count. `summary_eval.json`
  holds the run so the figure can be cited. `--rescore` re-judges a saved run
  without regenerating, which is what made correcting two faulty checks
  cheap. Quote the 89% with the sample size and the model, and say that two
  of the eight checks had to be corrected before the number meant anything.

- **Resolved 2026-09-23: Ollama stays out of docker-compose.** A model
  container plus a ~2GB volume does not fit the 4GB VPS alongside a 2GB
  semgrep, so `MALDET_OLLAMA_DISABLE=1` is the compose default and the
  rule-based summary renders there. Kept here as a decision rather than
  deleted, because "why is the AI missing in the deployed demo" is a
  question the report has to answer.
- **Done (ba2beef, extended 2026-09-23): Dockerised.** `docker compose up`
  brings up MySQL, the web app under gunicorn, and the scan worker. Config
  is env-var driven, `SEMGREP_APP_TOKEN` is passed through, and the ClamAV
  signature DB lives in a named volume so it downloads once. What remains is
  running it on the actual VPS, which nothing has yet.
- **Independently confirm a slice of the evaluation labels**, or have a
  groupmate review the ambiguous ones, so the precision/recall figures rest
  on something stronger than AI-suggested labels the author agreed with
  wholesale.

## Limitations (structural, not just "todo")

- **Public-repo-only, no-auth, single-user, local tool** — this is a
  permanent design constraint per PRODUCT.md, not a gap to close.
- **The corpus decays, and some of it is unrecoverable.** Repositories are
  controlled by other people: between 2026-09-19 and 2026-10-07, four of the
  corpus were deleted or made private (HTTP 404) and one was renamed. The
  404s can never be rescanned, so anything their scan failed to capture is
  gone — specifically 349 findings whose code snippet reads `requires login`,
  because that text was never stored. What is *in* the database about them
  can still be corrected, which is how their severities were fixed on
  2026-10-07 without any network access; do not assume "repository gone"
  means "data unrecoverable". Any metric computed over the corpus is a
  metric over the corpus as it was when scanned, and the scan dates differ
  per repo. Report the dates alongside the numbers.

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

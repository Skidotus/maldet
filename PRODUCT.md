# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Python 3.12, Flask, MySQL 8.0, Bootstrap 5 (CDN), Chart.js (CDN), vanilla JS. Detection engines shelled out from the backend: Bandit, Semgrep, YARA, ClamAV, plus a custom dependency/supply-chain checker (`dep_checker.py`, which also shells out to `pip-audit` for CVEs) and a scikit-learn Random Forest false-positive classifier (`train_classifier.py`, artifact at `model/risk_classifier.pkl`) that is built and wired into live scoring.

## Users

Primary user: an individual developer who is about to clone, install, or depend on a public GitHub repository they don't fully trust, and wants to check it's safe before pulling it in. Single-user tool — no accounts, roles, or teams.

## Product Purpose

MalDet scans a public GitHub repository and returns a risk verdict (Safe/Low/Medium/High/Critical) by combining multiple static-analysis and supply-chain detection engines. Success is a developer being able to paste a repo URL and get a trustworthy go/no-go signal without having to run and interpret several separate security tools themselves.

The verdict is reported on two axes rather than one blended number, because "the author made an exploitable mistake" and "the author appears to have meant harm" are different threat models and a developer deciding whether to trust a repo needs to tell them apart:

- **Vulnerability** (Bandit, Semgrep, plus `pip-audit` CVEs) — insecure coding patterns an attacker could exploit.
- **Malicious pattern** (YARA, ClamAV, the rest of `dep_checker` — typosquats, install-time hooks, direct-URL installs) — signals the code itself is trying to do something hostile.

Each axis carries its own score and level, calibrated separately against real scan data, since malicious-pattern findings are far lower-volume than vulnerability ones and a shared scale made them read as artificially mild.

## Positioning

The value is the aggregation and unification, not any single engine: MalDet runs Bandit, Semgrep, YARA, ClamAV, and a custom dependency/typosquat/CVE checker against one repo and reduces the combined output to two scored axes (vulnerability and malicious pattern). A developer could run each tool by hand, but would have to reconcile five different output formats and severities themselves — MalDet does that reconciliation for them.

The second half of that value is triage, not just aggregation: five engines on a large repo produce tens of thousands of findings, most of them boilerplate. Every finding carries a classifier-assigned confidence that it is a real issue rather than noise, and that confidence weights the score instead of every finding counting equally.

## Operating Context

Workflow: user submits a GitHub URL (optionally with an archive password for password-protected archives found in the repo) → MalDet fetches repo metadata via the GitHub API → shallow-clones it → extracts any archives → runs all detection engines → merges and filters findings → scores each finding with the classifier → scores both risk axes → saves to MySQL → shows results on a dashboard with history/trend tracking. The scan runs on a background thread with a pollable status page, so the browser is not held open for the duration and a refresh does not lose track of it. Run from the FYP author's own machine/server, not a hosted multi-tenant service.

This is a Final Year Project (FYP) for a Diploma in Information Security — built and evaluated as coursework, with an academic supervisor and institution as stated audiences for the writeup, but the product itself is designed around the developer-vetting-a-repo use case above, not the grading process.

## Capabilities and Constraints

- Scans public GitHub repositories only. No authentication, accounts, or private-repo/org support — this is a durable constraint, not a current gap.
- Scans run on a background thread with a pollable status page (`/scan/<job_id>`), so the request is not held open and refreshing or reopening the page does not lose an in-progress scan. Job state lives in a process-lifetime dict, so restarting the server forgets any running scan — acceptable for a single-user local tool, but it means there is no job queue and realistically one scan runs at a time.
- Detection findings share one shape across all engines: `{tool, severity, issue_text, filename, line_number, code_snippet}`, plus a classifier `confidence` in `[0,1]`.
- Risk levels are exactly: `Safe`, `Low`, `Medium`, `High`, `Critical` — reported per axis (vulnerability, malicious pattern), each with independently calibrated thresholds.
- ML false-positive classification (Random Forest, `model/risk_classifier.pkl`) is built and live: `scan_repo()` scores every finding before risk is calculated, and the confidence is stored per finding and weights the score.
- The plain-English findings summary is currently rule-based (`app.py:build_findings_summary` — counts plus the single highest-priority finding). The Ollama/llama3.2 version is still unbuilt; the rule-based version is deliberately shaped to be a drop-in replacement target. Note that an LLM is only viable for summarising the top handful of findings, not for scoring all of them — at corpus scale (~235k findings) per-finding LLM inference is hours-to-days of compute versus seconds for the Random Forest.
- A Chrome extension is planned as a later phase; out of scope for current template/UI work.
- Requires system tools on PATH (`bandit`, `semgrep`, `yara`, `clamscan`, `7z`, `pip-audit`) and a running MySQL instance — a local/self-hosted tool, not a cloud SaaS.
- The dependency checker reads Python (`requirements.txt`, `pyproject.toml` incl. Poetry, `Pipfile`, `poetry.lock`) and Node (`package.json`) manifests. Other ecosystems (`go.mod`, `Cargo.toml`, Maven, etc.) are not parsed yet.
- Findings inside test/docs/example/migration/locale/fixture paths are excluded by design, matched on whole path segments plus conventional test-file naming (`test_*.py`, `conftest.py`, `*_test.go`, `*.test.js`, `*.spec.ts`).

## Brand Commitments

Name is fixed: "MalDet". Author: Haikal (Skidotus). No existing logo, color, or typography commitments — free to establish visual identity. License is academic-use-only.

## Evidence on Hand

Real scan data now exists: 155 scanned repositories and ~235,000 findings in the live MySQL database, which is what the scoring thresholds and the classifier were calibrated against. `model/risk_classifier.pkl` exists; `extension/` still does not. `schema.sql` is now populated and documented, and reflects the live schema — prefer it over the README's description, and still verify against `app.py`/`scanner.py` queries when it matters.

A 168-finding hand-reviewed evaluation set exists (`eval_sample.json`, built by `build_eval_sample.py`, scored by `evaluate_classifier.py`). Against it the classifier measures precision 0.52, recall 0.53, F1 0.53, versus a 0.28 precision baseline for treating every finding as real. These are the only ground-truth-backed numbers available; the higher figures printed by `train_classifier.py` are measured against its own weak labels and must not be quoted as accuracy. The hand labels were produced with AI-assisted first-pass review confirmed by the author, which should be disclosed wherever the numbers are cited.

No screenshots, testimonials, or case studies exist. Future work must not fabricate sample findings, benchmarks, or user quotes.

## Product Principles

1. A verdict, not five tool outputs — every design decision should reduce the user's need to interpret raw multi-tool output themselves. Two axes is the deliberate exception to "one number": collapsing exploitable-mistake and apparent-malice into a single score hid which kind of risk was present, which is the one distinction this user actually needs. Two is the ceiling, not a precedent for more.
2. Public-repo-only, no-auth is a permanent shape, not a v1 limitation — don't design around accounts or team features.
3. Built for a developer deciding whether to trust a repo before depending on it, not for a SOC/analyst monitoring workflow — keep language and pacing suited to a one-off pre-install check, not continuous monitoring.
4. The tool is honest about engine aggregation and triage as its value, not a proprietary detection claim — avoid copy that oversells the ML/AI components beyond what's actually built. Concretely: the classifier is weakly supervised, and its only ground-truth-backed scores are the modest ones from the 168-finding hand-reviewed set. Quote those, state the weak supervision plainly, and never present `train_classifier.py`'s self-graded figures as accuracy.

## Accessibility & Inclusion

No product-specific requirement established beyond standard web accessibility practice (keyboard focus, contrast, responsive layout).

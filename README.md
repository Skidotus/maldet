# MalDet — Malware & Supply Chain Detection System

A web-based static analysis tool that scans public GitHub repositories for malware,
vulnerable dependencies, and supply chain attacks using multiple detection engines
combined with machine learning (ML) risk classification.

> Final Year Project (FYP) — Diploma in Cybersecurity Technology

---

## Features

- Multi-tool static analysis (Bandit, Semgrep, YARA, ClamAV, GuardDog)
- Supply chain attack detection (OSV CVE lookups across requirements.txt, poetry.lock, pyproject.toml and Pipfile, plus a custom dependency checker)
- ML risk classification (Random Forest)
- Plain-English findings summary written by a local LLM (Ollama, optional)
- Scan history and risk trend tracking
- Web dashboard with charts
- Chrome extension support

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.12, Flask |
| Database | MySQL 8.0 |
| Static Analysis | Bandit, Semgrep, YARA, ClamAV, GuardDog |
| Supply Chain | OSV Scanner, Custom dependency checker |
| Machine Learning | scikit-learn (Random Forest) |
| Frontend | HTML, CSS, JavaScript |
| Extension | Chrome Extension (Manifest V3) |

---

## Quick start with Docker (recommended)

If you just want MalDet running, use this. It needs **Docker** and **git**,
and nothing else — no Python, no virtualenv, no MySQL setup, no installing
`yara`/`clamav`/`7z`/`guarddog`, no `semgrep login`.

### Installing Docker

Already have it? Run `docker --version` — if that prints a version number,
skip to the next section.

**Ubuntu / Debian**

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-v2 docker-buildx
sudo usermod -aG docker $USER
```

Then **log out and log back in.** This is the step everyone skips, and
without it the very next `docker` command fails with `permission denied
while trying to connect to the Docker daemon socket` even though Docker is
installed correctly — group membership only applies to new login sessions.
In a hurry, `newgrp docker` grants it to the current terminal only.

All three packages are needed: `docker.io` is the engine itself,
`docker-compose-v2` provides the `docker compose` command, and
`docker-buildx` is the build backend that `docker compose up` uses to build
the image.

**Windows**

Install [Docker Desktop](https://www.docker.com/products/docker-desktop/).
It requires **WSL2**, which the installer normally sets up for you; on some
machines it also needs virtualisation enabled in the BIOS. Run the commands
below from PowerShell or a WSL terminal.

**macOS**

Install [Docker Desktop](https://www.docker.com/products/docker-desktop/) —
the Apple Silicon build for M1/M2/M3 Macs, the Intel build otherwise.

Docker Desktop bundles Compose and Buildx already, so Windows and macOS need
nothing beyond it.

**Check it works**

```bash
docker run --rm hello-world
```

A short "Hello from Docker!" message means you're ready.

### Getting MalDet running

```bash
git clone https://github.com/Skidotus/maldet.git
cd maldet
cp .env.example .env
```

Open `.env` and paste in a GitHub token (see below — it takes a minute and
needs no permissions). Then:

```bash
docker compose up
```

Open **http://localhost:5000**. The dashboard arrives already populated with
~20 real scanned repositories spanning Safe through Critical, so there's
something to look at immediately.

After that, `docker compose up` starts in seconds and `docker compose down`
stops it. Anything you scan yourself persists between restarts.

### The GitHub token

MalDet only reads *public* repository metadata, so the token needs **no
scopes at all** — its only job is raising GitHub's API rate limit from 60
requests/hour to 5,000.

1. github.com → Settings → Developer settings → Personal access tokens →
   **Tokens (classic)**
2. **Generate new token**, tick **nothing** under scopes
3. Paste it into `.env` as `GITHUB_TOKEN=`

Use your own; don't reuse a teammate's.

Optionally add a free `SEMGREP_APP_TOKEN` from semgrep.dev for Semgrep's full
ruleset. Without it Semgrep still runs on community rules — fewer findings,
no errors.

### What to expect the first time

- **10–20 minutes and ~1.5 GB**: building the image and downloading ClamAV's
  signature database (~110 MB). Both are cached, so it only happens once.
  In a hurry? Set `SKIP_FRESHCLAM=1` in `.env` — ClamAV then reports nothing
  and the other four engines are unaffected.
- **~2 GB disk** total once settled, across the image, database and signatures.
- **Give Docker 4 GB of RAM.** The default 2 GB is tight; Semgrep is
  memory-hungry on large repositories. On Docker Desktop: Settings →
  Resources.

### Notes and gotchas

- The dashboard is published to `127.0.0.1` only — reachable from this
  machine's browser, not from anything else on the network. That's
  deliberate.
- **Port 5000 already in use?** Usually a locally-running `python3 app.py`.
  Stop it, or set `MALDET_PORT=5001` in `.env`.
- **Windows** needs WSL2 for Docker Desktop. That's normally automatic, but
  on some machines it requires enabling virtualisation in the BIOS.
- **Apple Silicon Macs** are fine — every tool has an ARM build.
- Your credentials are generated inside the container from `.env` at startup.
  If you already have a local `config.py`, it is left untouched.

---

## System Requirements (manual install)

Only needed if you're setting up without Docker — to develop against the code
directly, for instance.

- OS: Ubuntu 22.04+
- RAM: 4GB minimum (8GB recommended)
- Disk: 20GB free space
- Python: 3.10+
- MySQL: 8.0+

---

## Installation (Fresh Setup, without Docker)

### 1. Clone the repository

```bash
git clone https://github.com/Skidotus/maldet.git
cd maldet
```

### 2. Install system dependencies

```bash
sudo apt update && sudo apt upgrade -y

sudo apt install -y \
  git \
  python3 \
  python3-pip \
  python3-venv \
  mysql-server \
  p7zip-full \
  yara \
  clamav \
  clamav-daemon \
  curl \
  build-essential
```

### 3. Update ClamAV virus signatures

```bash
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-freshclam
```

### 4. Create and activate virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

You should see `(venv)` at the start of your terminal line.

### 5. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 6a. Install GuardDog (separate virtualenv — do not skip the reason)

GuardDog detects supply-chain malware: obfuscated payloads, install-time
network calls, credential access, reverse shells. It needs its **own**
virtualenv because it requires click >=8.4.1 while Semgrep pins click
~=8.1.8 — putting both in `venv/` silently upgrades click and breaks Semgrep.

```bash
python3 -m venv .venv-guarddog
.venv-guarddog/bin/pip install guarddog
.venv-guarddog/bin/guarddog --version
```

Nothing else to configure — the scanner finds it automatically. If you skip
this step scans still run, just without GuardDog's findings.

### 6b. Install Ollama (optional — plain-English summaries)

Writes a short plain-English paragraph explaining each scan's findings. It
runs locally, needs no API key or account, and works offline.

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3.5:2b
```

Pull exactly this model, or set `MALDET_OLLAMA_MODEL` to whatever you did
pull — the scanner looks for `qwen3.5:2b` and silently falls back to the
rule-based summary if it is missing, so a wrong model looks like the feature
doing nothing.

**Skip this if you're short on RAM.** The model needs roughly 3GB resident
and generation is CPU-only without a GPU, taking 20-60 seconds per scan. On
a 4GB machine it does not fit alongside Semgrep (which peaks near 2GB) — set
`MALDET_OLLAMA_DISABLE=1` there instead. Without Ollama, scans run exactly
as before and the detail page shows the rule-based summary — nothing breaks.

Set `MALDET_OLLAMA_DISABLE=1` to turn it off without uninstalling, or
`MALDET_OLLAMA_MODEL` to use a different model.

### 6. Login to Semgrep (required before first scan)

```bash
semgrep login
```

Sign up free at https://semgrep.dev and authorise when the browser opens.

### 7. Set up MySQL database

```bash
sudo mysql_secure_installation
```

Then log into MySQL:

```bash
sudo mysql -u root -p
```

Run:

```sql
CREATE USER 'fypuser'@'localhost' IDENTIFIED BY 'your_password_here';
GRANT ALL PRIVILEGES ON fyp_scanner.* TO 'fypuser'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

Import the schema:

```bash
mysql -u fypuser -p < schema.sql
```

### 8. Configure credentials

```bash
cp config.example.py config.py
nano config.py
```

Fill in your values:

```python
GITHUB_TOKEN = "your_github_personal_access_token"
DB_HOST      = "localhost"
DB_USER      = "fypuser"
DB_PASSWORD  = "your_db_password"
DB_NAME      = "fyp_scanner"
```

> `config.py` is gitignored and will never be pushed to GitHub.

### 9. Verify everything is installed

```bash
python3 --version
bandit --version
semgrep --version
yara --version
clamscan --version
.venv-guarddog/bin/guarddog --version
mysql --version
mysql -u fypuser -p fyp_scanner -e "SHOW TABLES;"
```

### 10. Run the app

```bash
source venv/bin/activate
python3 app.py
```

Open your browser at:

```
http://localhost:5000
```

---

## How to Get API Keys

### GitHub Personal Access Token

1. Go to https://github.com/settings/tokens
2. Click **Generate new token (classic)**
3. Name: `maldet`
4. Expiration: 90 days
5. Select the `repo` scope
6. Copy the token into `config.py`

---

## Project Structure

```text
maldet/
├── app.py                  # Flask web app (routes) + inline scan worker for local dev
├── worker.py               # Scan worker — the only process that runs scans
├── job_queue.py            # Persistent scan queue (scan_jobs table)
├── scanner.py              # Core scan engine — orchestrates all six detectors
├── dep_checker.py          # Dependency / supply chain checker
├── llm_summary.py          # Plain-English scan summary via local Ollama
├── rules.yar               # YARA detection rules
├── schema.sql              # Database schema — source of truth for a fresh DB
├── config.py               # Your credentials (gitignored)
├── config.example.py       # Credentials template
├── requirements.txt        # Python dependencies
├── malware_repos.txt       # Known-malicious repo list (classifier training input)
├── eval_sample.json        # Hand-labeled evaluation set (ground truth)
├── model/
│   └── risk_classifier.pkl # Trained Random Forest
├── templates/              # index, scan, scan_status, detail, history, base
├── static/                 # css, js
├── docker/                 # entrypoint.sh
├── db/                     # export_seed.py, seed_data.sql.gz
├── Dockerfile
├── docker-compose.yml      # db + app (gunicorn) + worker
└── README.md
```

A Chrome extension is planned but not built; there is no `extension/` directory yet.

---

## Utility scripts

These are one-off tools, not part of the running system. Nothing imports most of
them, which makes them look deletable — but several are the **audit trail for
numbers that appear in the report**, so check this table before removing any.

### Classifier & evaluation

| Script | What it does | Still needed? |
|---|---|---|
| `train_classifier.py` | Trains the Random Forest that scores each finding with P(real issue). Produces `model/risk_classifier.pkl`. | **Yes** — rerun to retrain |
| `build_eval_sample.py` | Builds a stratified random sample of real findings into `eval_sample.json` for hand labeling. | **Yes** — rerun to resample |
| `review_labels.py` | Terminal tool for hand-labeling `eval_sample.json` (fills `human_label`). | **Yes** — labels still incomplete |
| `evaluate_classifier.py` | Computes real precision / recall / F1 against the hand-checked labels. Source of the 0.52 / 0.62 figures. | **Yes** — rerun after labeling |
| `inspect_classifier.py` | Ad-hoc debugging: prints one repo's high-severity findings ranked by model confidence. Hardcodes `repo_id=9`. | No — throwaway, kept in git history |
| `inspect_classifier2.py` | Near-duplicate of the above, one day later. | No — throwaway |

### Threshold calibration — keep these

| Script | What it does | Still needed? |
|---|---|---|
| `calibrate_thresholds.py` | Derives the overall `Safe/Low/Medium/High/Critical` cutoffs from the real corpus. **`scanner.py` cites it in a comment as the source of those numbers.** | **Yes** — this is where 20/80/300 came from |
| `calibrate_category_thresholds.py` | Same, per axis. The two axes have very different score scales, so one threshold set for both would make malware always look mild. | **Yes** — justifies the per-axis split |

### Corpus maintenance

| Script | What it does | Still needed? |
|---|---|---|
| `batch_scan.py` | Runs the full pipeline over many repos unattended. Writes `batch_scan.log`. | **Yes** — for the outstanding rescan |
| `recompute_scores.py` | Recomputes `risk_scores` and backfills `scan_results.confidence` without rescanning. | Occasionally — after a scoring change |
| `recompute_category_scores.py` | Same, for the two per-axis scores. | Occasionally |
| `rescan_yara_dep.py` | Re-runs **only** YARA + dep_checker against stored repos. Cannot fix Bandit/Semgrep data. | Occasionally |
| `mark_rescanned.py` | Bumps `scanned_at` and appends a `scan_history` row after a targeted rescan. | Occasionally |
| `dedupe_repositories.py` | Consolidates duplicate `(owner, repo_name)` rows, keeping the newest. | Rarely — a past cleanup |

### Deployment

| Script | What it does | Still needed? |
|---|---|---|
| `db/export_seed.py` | Exports a slice of the live DB as `db/seed_data.sql.gz`, which Docker loads into a fresh MySQL container. | **Yes** — rerun when the seed goes stale |

### Generated / disposable

`__pycache__/` (bytecode, regenerates), `batch_scan.log` (scan run history, gitignored),
`guided_review.json` (**in-progress** label review — not junk), `design/` (an early
dashboard mockup, superseded by `templates/`).

---

## System Workflow

```text
User submits GitHub URL
↓
Fetch repository information (GitHub API)
↓
Clone repository
↓
Extract archives (if any)
↓
Run security tools

Bandit
Semgrep
YARA
ClamAV
Dependency Checker

↓
Collect all findings
↓
ML model classifies risk
↓
Calculate final score and risk level
↓
Save results to MySQL
↓
Clean up temporary files
↓
Display results on the dashboard
```

---

## Collaborator Guide

### Every time you start working

```bash
cd maldet
source venv/bin/activate
python3 app.py
```

### Adding a new detection tool

1. Write your function in `scanner.py`
2. Return findings in this format:

```python
{
    "tool": "your_tool_name",
    "severity": "high" | "medium" | "low",
    "issue_text": "Description of the issue",
    "filename": "path/to/file",
    "line_number": 0,
    "code_snippet": "relevant code here"
}
```

3. Call your function inside `scan_repo()` and append it to `findings`.
4. Update dependencies:

```bash
pip freeze > requirements.txt
```

### Changing the database

- Update `schema.sql` whenever you modify the database.
- Do not change the database structure without updating the schema file.

Reload the schema:

```bash
mysql -u fypuser -p < schema.sql
```

### Branch rules

- `main` → Stable code
- `dev` → Development
- `feature/xxx` → One feature per branch

Example:

```bash
git checkout -b feature/dep-checker
git add .
git commit -m "Add dependency checker"
git push origin feature/dep-checker
```

Then open a Pull Request on GitHub.

### Pull Request rules

- Test your code before creating a PR.
- One feature per PR.
- Update the README if installation steps change.
- Never commit `config.py`, `venv/`, or `*.pkl`.

---

## Common Issues & Fixes

### (venv) not showing

```bash
source venv/bin/activate
```

### Semgrep not detecting anything

```bash
semgrep login
```

### ClamAV signatures outdated

```bash
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-freshclam
```

### MySQL connection refused

```bash
sudo systemctl start mysql
```

### Git push asking for password

Use your GitHub Personal Access Token instead of your GitHub account password.

To save it:

```bash
git config --global credential.helper store
```

### Repository clone timeout

- Check your internet connection.
- Make sure your GitHub token is valid and has not expired.

---

## Author

- Haikal (Skidotus)

## Supervisor

- Supervisor Name

## Institution

- Institution Name

---

## License

Academic use only — Final Year Project (Diploma).
````

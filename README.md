# MalDet — Malware & Supply Chain Detection System

A web-based static analysis tool that scans public GitHub repositories for malware,
vulnerable dependencies, and supply chain attacks using multiple detection engines
combined with machine learning (ML) risk classification.

> Final Year Project (FYP) — Diploma in Information Security

---

## Features

- Multi-tool static analysis (Bandit, Semgrep, YARA, ClamAV)
- Supply chain attack detection (OSV + custom dependency checker)
- ML risk classification (Random Forest)
- Scan history and risk trend tracking
- Web dashboard with charts
- Chrome extension support

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.12, Flask |
| Database | MySQL 8.0 |
| Static Analysis | Bandit, Semgrep, YARA, ClamAV |
| Supply Chain | OSV Scanner, Custom dependency checker |
| Machine Learning | scikit-learn (Random Forest) |
| Frontend | HTML, CSS, JavaScript |
| Extension | Chrome Extension (Manifest V3) |

---

## Quick start with Docker (recommended)

If you just want MalDet running, use this. It needs **Docker** and **git**,
and nothing else — no Python, no virtualenv, no MySQL setup, no installing
`yara`/`clamav`/`7z`, no `semgrep login`.

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
├── app.py                  # Flask web app (routes)
├── scanner.py              # Core scan engine
├── dep_checker.py          # Dependency/supply chain checker
├── config.py               # Your credentials (gitignored)
├── config.example.py       # Credentials template
├── rules.yar               # YARA detection rules
├── schema.sql              # Database schema
├── requirements.txt        # Python dependencies
├── model/
│   └── risk_classifier.pkl # Trained ML model
├── templates/
│   ├── index.html          # Dashboard
│   ├── scan.html           # Scan input + live progress
│   ├── detail.html         # Results
│   └── history.html        # Scan history
├── static/
│   ├── css/
│   ├── js/
│   └── img/
├── extension/              # Chrome extension
├── .gitignore
└── README.md
```

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

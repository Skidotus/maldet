````markdown
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

## System Requirements

- OS: Ubuntu 22.04+
- RAM: 4GB minimum (8GB recommended)
- Disk: 20GB free space
- Python: 3.10+
- MySQL: 8.0+

---

## Installation (Fresh Setup)

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

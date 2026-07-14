# MalDet — AI Malware & Supply Chain Detection System

MalDet is a web application that scans public GitHub repositories for malware, unsafe code, and vulnerable dependencies. It combines multiple security scanning tools and machine learning to help users identify security risks.

> Final Year Project (FYP) — Diploma in Information Security

---

# Features

- Scan GitHub repositories for security issues
- Detect malware using multiple security tools
- Find vulnerable or malicious dependencies
- Classify risk using Machine Learning (Random Forest)
- View previous scan history and risk trends
- Web dashboard with charts
- Chrome Extension support

---

# Technology Used

| Part | Technology |
|------|------------|
| Backend | Python, Flask |
| Database | MySQL |
| Security Tools | Bandit, Semgrep, YARA, ClamAV |
| Dependency Scanner | OSV Scanner + Custom Checker |
| Machine Learning | scikit-learn (Random Forest) |
| Frontend | HTML, CSS, JavaScript |
| Browser Extension | Chrome Extension (Manifest V3) |

---

# Requirements

Before installing, make sure you have:

- Ubuntu 22.04 or newer
- Python 3.10 or newer
- MySQL 8.0 or newer
- At least 4GB RAM (8GB recommended)
- Around 20GB free disk space

---

# Installation

## 1. Download the project

```bash
git clone https://github.com/Skidotus/maldet.git
cd maldet
```

---

## 2. Install required software

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

---

## 3. Update ClamAV database

```bash
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-freshclam
```

---

## 4. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

Your terminal should now show:

```text
(venv)
```

---

## 5. Install Python packages

```bash
pip install -r requirements.txt
```

---

## 6. Login to Semgrep

Before scanning, log in to Semgrep.

```bash
semgrep login
```

Create a free account at:

https://semgrep.dev

---

## 7. Create the database

Run:

```bash
sudo mysql_secure_installation
```

Then log in:

```bash
sudo mysql -u root -p
```

Create a new database user:

```sql
CREATE USER 'fypuser'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL PRIVILEGES ON fyp_scanner.* TO 'fypuser'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

Import the database:

```bash
mysql -u fypuser -p < schema.sql
```

---

## 8. Configure the project

Copy the example configuration file.

```bash
cp config.example.py config.py
```

Edit it.

```bash
nano config.py
```

Fill in your information.

```python
GITHUB_TOKEN = "your_github_token"

DB_HOST = "localhost"
DB_USER = "fypuser"
DB_PASSWORD = "your_password"
DB_NAME = "fyp_scanner"
```

> `config.py` is ignored by Git, so your passwords and tokens will not be uploaded.

---

## 9. Check that everything works

```bash
python3 --version
bandit --version
semgrep --version
yara --version
clamscan --version
mysql --version

mysql -u fypuser -p fyp_scanner -e "SHOW TABLES;"
```

If each command shows a version or expected output, the installation is successful.

---

## 10. Start the application

```bash
source venv/bin/activate

python3 app.py
```

Open your browser and visit:

```
http://localhost:5000
```

---

# GitHub Personal Access Token

To allow MalDet to access public GitHub repositories:

1. Go to https://github.com/settings/tokens
2. Click **Generate new token (Classic)**.
3. Give the token a name.
4. Choose an expiration date.
5. Select the **repo** permission.
6. Copy the token into `config.py`.

---

# Project Structure

```text
maldet/
│
├── app.py
├── config.py
├── requirements.txt
├── schema.sql
├── scanners/
├── ml/
├── templates/
├── static/
├── extension/
└── README.md
```

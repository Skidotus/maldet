import os
import subprocess
import shutil
import json
import time
import requests
import pymysql
from config import GITHUB_TOKEN, DB_HOST, DB_USER, DB_PASSWORD, DB_NAME
from dep_checker import check_dependencies

HEADERS   = {"Authorization": f"token {GITHUB_TOKEN}"} #recall token later
CLONE_DIR = "/tmp/maldet_scan_temp"

#DB

def get_db():
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor
    )


# pull repo info from API

def get_repo_info(repo):
    try:
        url = f"https://api.github.com/repos/{repo}"
        data = requests.get(url, headers=HEADERS, timeout=10).json()
        if "name" not in data:
            raise ValueError(f"Repo not found or private: {repo}")
        return {
            "name" : data["name"],
            "owner": data["owner"]["login"],
            "language" : data.get("language", "Unknown"),
            "stars" : data.get("stargazers_count", 0),
            "last_pushed" :data.get("pushed_at", "")[:19].replace("T", " ")
        }
    except Exception as e:
        raise RuntimeError(f"Failed to get repo info : {e}")
    

#Clone repo

def clone_repo(repo):
    path = os.path.join(CLONE_DIR, repo.replace("/", "_"))
    if os.path.exists(path):
        shutil.rmtree(path)
    os.makedirs(CLONE_DIR, exist_ok=True)
    print(f"Cloning {repo}...")
    result = subprocess.run(
        ["git", "clone", "--depth=1",
        f"https://github.com/{repo}.git", path],
        capture_output=True, timeout=120
    )
    if result.returncode != 0:
        raise RuntimeError(f"Clone failed: {result.stderr.decode()}")
    return path


#Extract archives

def extract_archives(repo_path, password="infected"):
    print(" Extracting archives...")
    count = 0
    for root, dirs, files in os.walk(repo_path):
        for file in files:
            if file.endswith(('.zip', '.7z', 'rar')):
                filepath = os.path.join(root,file)
                ext = file.rsplit('.', 1)[-1]
                extract_dir = filepath.replace(f'.{ext}' , '_extracted')
                try:
                    result = subprocess.run(
                        ['7z' , 'x' , f'-p{password}',
                         filepath, f'-o{extract_dir}' , '-y'],
                         capture_output=True, text=True, timeout=30
                    )
                    if result.returncode == 0:
                        count += 1
                        print(f"    Extracted: {file}")
                    else:
                        print(f"    Skipped: {file}")
                except Exception as e:
                    print(f"    Archive error ({file}): {e}")
    print(f"    Extracted {count} archive(s)")

# Bandit functionality

def run_bandit(path):
    print("  Running Bandit...")
    findings = []
    try:
        result = subprocess.run(
            ["bandit", "-r", path, "-f", "json", "-q"],
            capture_output=True, text=True, timeout=120
        )
        data = json.loads(result.stdout)
        for issue in data.get("results", []):
            findings.append({
                "tool":         "bandit",
                "severity":     issue["issue_severity"].lower(),
                "issue_text":   issue["issue_text"],
                "filename":     issue["filename"].replace(path, ""),
                "line_number":  issue.get("line_number", 0),
                "code_snippet": issue.get("code", "").strip()
            })
    except json.JSONDecodeError:
        print("    Bandit: no Python files found")
    except Exception as e:
        print(f"    Bandit error: {e}")
    print(f"    Bandit found {len(findings)} issues")
    return findings

#severity functionality

def normalize_severity(severity):
    severity = severity.lower()
    if severity in ["error", "high", "critical"]:
        return "high"
    elif severity in ["warning", "medium"]:
        return "medium"
    elif severity in ["info", "low", "note"]:
        return "low"
    else:
        return "low"

#Filter noise for less false positive
#Check back later for improvement. Consult with group member.

NOISE_RULES = [
    "Try, Except, Pass detected.",
    "Use of assert detected.",
    "Possible hardcoded password: 'password'",
    "Possible hardcoded password: 'secret'",
    "Consider possible security implications associated with pickle module.",
    "Consider possible security implications associated with md5 module.",
    "Standard pseudo-random generators are not suitable for security/cryptographic purposes.",
    "Audit url open for permitted schemes.",
    "A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.",
]

def filter_noise(findings):
    filtered = []

    IGNORE_PATHS = [
        "test", "docs", "example", 
        "migration", "locale", "doc"
    ]

    for f in findings:
        # Skip known low-value Bandit rules
        if f["issue_text"] in NOISE_RULES:
            continue

        # Skip ALL findings from test/docs/locale files
        if any(p in f["filename"].lower() for p in IGNORE_PATHS):
            continue

        # Downgrade SHA1/MD5 from high to medium
        if any(h in f["issue_text"] for h in ["SHA1", "sha1", "MD5", "md5"]):
            f["severity"] = "medium"

        # Downgrade chmod from high to medium
        if "Chmod" in f["issue_text"] or "chmod" in f["issue_text"]:
            f["severity"] = "medium"

        # Downgrade YARA downloader to medium
        if f["tool"] == "yara" and "detect_downloader" in f["issue_text"]:
            f["severity"] = "medium"

        # Downgrade credential harvester in auth/config files to medium
        if f["tool"] == "yara" and "detect_credential_harvester" in f["issue_text"]:
            f["severity"] = "medium"

        filtered.append(f)

    return filtered

#Semgrep functionality


def run_semgrep(path):
    print("  Running Semgrep (this may take a few minutes)...")
    findings = []
    try:
        result = subprocess.run(
            ["semgrep", "--config=auto", path, "--json", "--quiet"],
            capture_output=True, text=True, timeout=300
        )
        
        # Show stderr so we can see what Semgrep is doing
        if result.stderr:
            print(f"    Semgrep status: {result.stderr[:200]}")

        data = json.loads(result.stdout)
        for issue in data.get("results", []):
            findings.append({
                "tool":         "semgrep",
                "severity": normalize_severity(issue.get("extra", {}).get("severity", "low")),
                "issue_text":   issue.get("extra", {}).get("message", ""),
                "filename":     issue.get("path", "").replace(path, ""),
                "line_number":  issue.get("start", {}).get("line", 0),
                "code_snippet": issue.get("extra", {}).get("lines", "").strip()
            })
    except json.JSONDecodeError:
        print("    Semgrep: no output")
    except subprocess.TimeoutExpired:
        print("    Semgrep: timed out — repo may be too large")
    except Exception as e:
        print(f"    Semgrep error: {e}")
    print(f"    Semgrep found {len(findings)} issues")
    return findings

    # YARA

def run_yara(path):
    print("  Running YARA...")
    rules_file = os.path.join(os.path.dirname(__file__), "rules.yar")
    findings   = []
    if not os.path.exists(rules_file):
        print("    YARA: rules.yar not found, skipping")
        return findings
    try:
        result = subprocess.run(
            ["yara", "-r", rules_file, path],
            capture_output=True, text=True, timeout=120
        )
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            parts     = line.split(" ")
            rule_name = parts[0]
            filename  = parts[1] if len(parts) > 1 else ""
            high_rules = [
                "detect_base64_exec",
                "detect_reverse_shell",
                "detect_credential_harvester",
                "detect_downloader"
            ]
            findings.append({
                "tool":         "yara",
                "severity":     "high" if rule_name in high_rules else "medium",
                "issue_text":   f"YARA rule matched: {rule_name}",
                "filename":     filename.replace(path, ""),
                "line_number":  0,
                "code_snippet": ""
            })
    except Exception as e:
        print(f"    YARA error: {e}")
    print(f"    YARA found {len(findings)} matches")
    return findings

#ClamAV

def run_clamav(path):
    print("  Running ClamAV...")
    findings = []
    try:
        result = subprocess.run(
            ["clamscan", "-r", path, "--no-summary"],
            capture_output=True, text=True, timeout=120
        )
        for line in result.stdout.strip().split("\n"):
            if "FOUND" in line:
                parts    = line.split(":")
                filename = parts[0].replace(path, "").strip()
                virus    = parts[1].replace("FOUND", "").strip()
                findings.append({
                    "tool":         "clamav",
                    "severity":     "high",
                    "issue_text":   f"ClamAV detected: {virus}",
                    "filename":     filename,
                    "line_number":  0,
                    "code_snippet": ""
                })
    except Exception as e:
        print(f"    ClamAV error: {e}")
    print(f"    ClamAV found {len(findings)} threats")
    return findings

#Risk Score calcualtor

def calculate_risk(findings):
    high   = sum(1 for f in findings if f["severity"] == "high")
    medium = sum(1 for f in findings if f["severity"] == "medium")
    low    = sum(1 for f in findings if f["severity"] == "low")

    # Cap both medium and low so noise doesn't dominate
    medium_capped = min(medium, 30)
    low_capped    = min(low, 20)
    score = (high * 10) + (medium_capped * 3) + (low_capped * 1)

    if score == 0:     level = "Safe"
    elif score <= 20:  level = "Low"
    elif score <= 60:  level = "Medium"
    elif score <= 120: level = "High"
    else:              level = "Critical"

    return high, medium, low, score, level

#DB Functionality

def save_to_db(repo_info, findings, high, medium, low, score, level):
    db     = get_db()
    cursor = db.cursor()

    try:
        #check existing repo
        cursor.execute(
            "SELECT id FROM repositories WHERE repo_name=%s AND owner=%s",
            (repo_info["name"], repo_info["owner"])
        )
        existing = cursor.fetchone()

        if existing:
            # Repo exist, update it and clear old results
            repo_id = existing["id"]
            cursor.execute("""
                UPDATE repositories
                SET language=%s, stars=%s, last_pushed=%s, scanned_at=NOW()
                WHERE id=%s
            """, (repo_info["language"], repo_info["stars"],
                  repo_info["last_pushed"], repo_id))
            cursor.execute("DELETE FROM scan_results WHERE repo_id=%s", (repo_id,))
            cursor.execute("DELETE FROM risk_scores   WHERE repo_id=%s", (repo_id,))
        else:
            #if not add new
            cursor.execute("""
                INSERT INTO repositories
                    (repo_name, owner, language, stars, last_pushed)
                VALUES (%s, %s, %s, %s, %s)
            """, (repo_info["name"], repo_info["owner"],
                  repo_info["language"], repo_info["stars"],
                  repo_info["last_pushed"]))
            repo_id = cursor.lastrowid

        db.commit()

        # Save each finding
        for f in findings:
            cursor.execute("""
                INSERT INTO scan_results
                    (repo_id, tool, severity, issue_text,
                     filename, line_number, code_snippet)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (repo_id, f["tool"], f["severity"], f["issue_text"],
                  f["filename"], f.get("line_number", 0),
                  f.get("code_snippet", "")))

        # Save risk score
        cursor.execute("""
            INSERT INTO risk_scores
                (repo_id, high_count, medium_count, low_count,
                 final_score, risk_level)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (repo_id, high, medium, low, score, level))

        # Save to history
        cursor.execute("""
            INSERT INTO scan_history
                (repo_id, risk_level, final_score)
            VALUES (%s, %s, %s)
        """, (repo_id, level, score))

        db.commit()
        return repo_id

    except Exception as e:
        db.rollback()
        raise RuntimeError(f"DB save failed: {e}")
    finally:
        cursor.close()
        db.close()

#main Scan function

def scan_repo(repo, archive_password="infected"):
    print(f"\n{'='*50}\nScanning: {repo}\n{'='*50}")

    repo_url  = f"https://github.com/{repo}"
    repo_info = get_repo_info(repo)
    path      = clone_repo(repo)

    try:
        
        extract_archives(path, archive_password)

        
        findings  = []
        findings += run_bandit(path)
        findings += run_semgrep(path)
        findings += run_yara(path)
        findings += run_clamav(path)
        findings += check_dependencies(path)

        # Filter noise before scoring
        findings = filter_noise(findings)
        print(f"  Findings after filter: {len(findings)}")

        
        high, medium, low, score, level = calculate_risk(findings)

        
        repo_id = save_to_db(repo_info, findings,
                             high, medium, low, score, level)

    finally:
        # clear temp folder
        if os.path.exists(path):
            shutil.rmtree(path)

    print(f"\n  Risk Score : {score}")
    print(f"  Risk Level : {level}")

    return {
        "repo_id":          repo_id,
        "name":             repo_info["name"],
        "owner":            repo_info["owner"],
        "language":         repo_info["language"],
        "stars":            repo_info["stars"],
        "high":             high,
        "medium":           medium,
        "low":              low,
        "score":            score,
        "risk_level":       level,
        "archive_password": archive_password
    }
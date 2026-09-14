import os
import re
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

CLONE_TIMEOUT = 300  # scans run in a background thread now, so a longer
                      # timeout no longer means a longer blocked request

def clone_repo(repo):
    path = os.path.join(CLONE_DIR, repo.replace("/", "_"))
    if os.path.exists(path):
        shutil.rmtree(path)
    os.makedirs(CLONE_DIR, exist_ok=True)
    print(f"Cloning {repo}...")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth=1",
            f"https://github.com/{repo}.git", path],
            capture_output=True, timeout=CLONE_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        # git leaves the partial clone on disk when killed for a timeout —
        # clean it up now rather than leaving debris under CLONE_DIR
        shutil.rmtree(path, ignore_errors=True)
        raise RuntimeError(
            f"Clone timed out after {CLONE_TIMEOUT}s — "
            "the repository may be too large for a shallow clone."
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
            # lower() so an uppercase/mixed-case extension (.ZIP, .Rar) isn't
            # skipped — a trivial evasion otherwise, and malicious archives
            # are exactly where that matters. '.rar' was previously written
            # as 'rar' with no dot, which matched any filename ending in
            # those three letters rather than the extension.
            if file.lower().endswith(('.zip', '.7z', '.rar')):
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

# dep_checker's issue_text always embeds the specific package/version/CVE id
# (e.g. "Loose version constraint: 'requests>=2.0'"), so no two are ever
# textually identical — unlike bandit/semgrep/yara, which emit fixed rule
# descriptions. The FP classifier (train_classifier.py) needs a stable
# "finding type" key instead of raw text for both training and live scoring,
# so this lives here as the shared, canonical definition.
DEP_CHECKER_CATEGORIES = [
    ("CVE found:", "CVE found in dependency"),
    ("Direct URL install detected", "Direct URL install"),
    ("Typosquatting:", "Typosquatting"),
    ("Unpinned dependency:", "Unpinned dependency"),
    ("Loose version constraint:", "Loose version constraint"),
    # setup.py/npm-hook findings embed a variable name/hook/class before the
    # fixed wording (e.g. "setup.py calls {name}(...)"), so these are matched
    # as a substring anywhere in the text rather than a startswith prefix —
    # added when check_setup_py/check_npm_install_hooks were introduced,
    # since without these they all fell into "dep_checker: other" together,
    # burying exactly the rare install-time-execution findings this exists
    # to surface.
    ("setup.py overrides the install process", "setup.py install-command override"),
    ("setup.py calls", "setup.py dangerous install-time call"),
    ("runs automatically on npm install and", "npm install hook (dangerous pattern)"),
    ("worth a manual look", "npm install hook (informational)"),
]

def frequency_key(tool, issue_text):
    if tool == "dep_checker":
        for marker, category in DEP_CHECKER_CATEGORIES:
            if marker in issue_text:
                return category
        return "dep_checker: other"
    return issue_text

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

IGNORE_PATHS = [
    "test", "docs", "example",
    "migration", "locale", "doc"
]

def filter_noise(findings):
    filtered = []

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

        # YARA severities used to be hardcoded in run_yara() and manually
        # downgraded here for the noisy ones (detect_downloader,
        # detect_credential_harvester). Severity now comes straight from
        # each rule's own meta.severity in rules.yar — detect_downloader is
        # "low" from the start, and detect_credential_harvester earned back
        # "high" by requiring a network-send signal too, not just an env
        # read. Downgrading here would undo that precision, so it's gone.

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

YARA_MATCH_LINE = re.compile(r"^(\S+)\s+\[(.*?)\]\s+(.+)$")

def run_yara(path):
    print("  Running YARA...")
    rules_file = os.path.join(os.path.dirname(__file__), "rules.yar")
    findings   = []
    if not os.path.exists(rules_file):
        print("    YARA: rules.yar not found, skipping")
        return findings
    try:
        # -m prints each rule's meta (severity, description) alongside the
        # match, so severity lives in rules.yar itself — adding a rule
        # there doesn't need a code change here.
        result = subprocess.run(
            ["yara", "-m", "-r", rules_file, path],
            capture_output=True, text=True, timeout=120
        )
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            match = YARA_MATCH_LINE.match(line)
            if not match:
                continue
            rule_name, meta_str, filename = match.groups()
            meta = dict(re.findall(r'(\w+)="([^"]*)"', meta_str))

            findings.append({
                "tool":         "yara",
                "severity":     meta.get("severity", "medium"),
                "issue_text":   f"YARA rule matched: {rule_name} — {meta.get('description', '')}",
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

#False-positive classifier (train_classifier.py)

MODEL_ARTIFACT_PATH = os.path.join(os.path.dirname(__file__), "model", "risk_classifier.pkl")
_model_artifact = None

def _load_model_artifact():
    global _model_artifact
    if _model_artifact is None:
        if os.path.exists(MODEL_ARTIFACT_PATH):
            import joblib
            _model_artifact = joblib.load(MODEL_ARTIFACT_PATH)
        else:
            _model_artifact = False  # sentinel: tried once, not found
    return _model_artifact or None


def score_findings(findings):
    """Attaches f["p_real"] = P(real issue, not noise) to each finding using
    the trained classifier. Falls back to p_real=1.0 (no discount, same as
    the old count-everything-equally behavior) if the model hasn't been
    trained yet, so scanning still works without it."""
    if not findings:
        return findings

    artifact = _load_model_artifact()
    if artifact is None:
        for f in findings:
            f["p_real"] = 1.0
        return findings

    import pandas as pd
    pipeline          = artifact["pipeline"]
    freq_lookup       = artifact["frequency_lookup"]
    default_frequency = artifact["default_frequency"]

    rows = []
    for f in findings:
        tool       = f["tool"]
        issue_text = f.get("issue_text") or ""
        key        = (tool, frequency_key(tool, issue_text))
        rows.append({
            "tool":           tool,
            "severity_norm":  normalize_severity(f.get("severity", "low")),
            "repo_frequency": freq_lookup.get(key, default_frequency),
            "snippet_length": len(f.get("code_snippet") or ""),
            "issue_text":     issue_text,
        })

    probs = pipeline.predict_proba(pd.DataFrame(rows))[:, 1]
    for f, p in zip(findings, probs):
        f["p_real"] = round(float(p), 4)
    return findings

#Risk Score calcualtor

SEVERITY_WEIGHT = {"high": 10, "medium": 3, "low": 1}

def _score_findings(findings):
    high   = sum(1 for f in findings if f["severity"] == "high")
    medium = sum(1 for f in findings if f["severity"] == "medium")
    low    = sum(1 for f in findings if f["severity"] == "low")

    # Each finding is weighted by how likely the classifier thinks it's a
    # real issue rather than noise, instead of counting every finding
    # equally — replaces the old fixed medium/low caps, which were a blunt
    # fix for the same false-positive-flooding problem this solves directly.
    weighted_score = sum(
        SEVERITY_WEIGHT.get(f["severity"], 1) * f.get("p_real", 1.0)
        for f in findings
    )
    return high, medium, low, round(weighted_score)


def calculate_risk(findings):
    high, medium, low, score = _score_findings(findings)

    # Thresholds recalibrated against the real 196-repo corpus for this
    # formula — see calibrate_thresholds.py. Not the same numbers as the
    # old raw-count formula, since the scale of the score itself changed.
    # Chosen to give a decreasing Safe > Low > Medium > High > Critical
    # shape against real data (13/57/40/26/15 repos respectively).
    if score == 0:     level = "Safe"
    elif score <= 20:  level = "Low"
    elif score <= 80:  level = "Medium"
    elif score <= 300: level = "High"
    else:              level = "Critical"

    return high, medium, low, score, level


# Bandit/Semgrep flag insecure *coding patterns* an attacker could later
# exploit (vulnerability scanning); YARA/ClamAV/dep_checker flag patterns
# that suggest the code itself is trying to do something malicious. These
# are different threat models — "the author made a mistake" vs "the author
# meant it" — and blending them into one score hides which kind of risk is
# actually present. See NOTES.md for the full reasoning.
TOOL_CATEGORY = {
    "bandit":      "vulnerability",
    "semgrep":     "vulnerability",
    "yara":        "malicious_pattern",
    "clamav":      "malicious_pattern",
    "dep_checker": "malicious_pattern",
    "virustotal":  "malicious_pattern",  # legacy tool name from old scans
}

def finding_category(f):
    """Almost always just TOOL_CATEGORY[tool] — except dep_checker's CVE
    findings (from pip-audit), which are a known bug in otherwise-legitimate
    software, not a sign the package is malicious. That's the same
    "attacker exploits a flaw" threat model as Bandit/Semgrep, so it belongs
    on the vulnerability axis even though the rest of dep_checker
    (typosquatting, install-time hooks, etc.) is genuinely malicious-intent
    focused."""
    if f["tool"] == "dep_checker" and (f.get("issue_text") or "").startswith("CVE found:"):
        return "vulnerability"
    return TOOL_CATEGORY.get(f["tool"], "malicious_pattern")

def _level_for(score, thresholds):
    low_max, med_max, high_max = thresholds
    if score == 0:      return "Safe"
    elif score <= low_max:  return "Low"
    elif score <= med_max:  return "Medium"
    elif score <= high_max: return "High"
    else:                   return "Critical"

# Calibrated separately per axis against real data (calibrate_thresholds.py)
# — malicious_pattern findings are far lower-volume than vulnerability ones
# (bandit/semgrep dominate raw counts), so reusing the blended thresholds
# here would make malware findings always look artificially mild.
CATEGORY_THRESHOLDS = {
    "vulnerability":     (20, 80, 300),
    "malicious_pattern": (15, 35, 100),
}

def calculate_category_risk(findings):
    """Same weighted-score math as calculate_risk(), computed separately
    per detection category instead of blended into one number."""
    result = {}
    for category in ("vulnerability", "malicious_pattern"):
        subset = [f for f in findings if finding_category(f) == category]
        high, medium, low, score = _score_findings(subset)
        level = _level_for(score, CATEGORY_THRESHOLDS[category])
        result[category] = {
            "high": high, "medium": medium, "low": low,
            "score": score, "level": level,
        }
    return result

#DB Functionality

def save_to_db(repo_info, findings, high, medium, low, score, level, category_risk):
    db     = get_db()
    cursor = db.cursor()

    try:
        # Atomic upsert, relying on the UNIQUE KEY on (owner, repo_name).
        # The old approach here — SELECT for an existing row, then INSERT
        # or UPDATE depending on the result — has a real race condition:
        # two scans of the same repo landing close together can both miss
        # seeing each other's row and both INSERT, since the SELECT and
        # the INSERT aren't atomic together. That's exactly how ~45
        # duplicate repository rows (some repos scanned a dozen+ times
        # under different ids) accumulated in production before this fix.
        # ON DUPLICATE KEY UPDATE makes the insert-or-update decision
        # atomic at the database level instead of two round trips the
        # application has to coordinate itself.
        cursor.execute("""
            INSERT INTO repositories (repo_name, owner, language, stars, last_pushed, scanned_at)
            VALUES (%s, %s, %s, %s, %s, NOW())
            ON DUPLICATE KEY UPDATE
                language=VALUES(language),
                stars=VALUES(stars),
                last_pushed=VALUES(last_pushed),
                scanned_at=NOW(),
                id=LAST_INSERT_ID(id)
        """, (repo_info["name"], repo_info["owner"],
              repo_info["language"], repo_info["stars"],
              repo_info["last_pushed"]))
        repo_id = cursor.lastrowid

        cursor.execute("DELETE FROM scan_results WHERE repo_id=%s", (repo_id,))
        cursor.execute("DELETE FROM risk_scores   WHERE repo_id=%s", (repo_id,))

        db.commit()

        # Save each finding
        for f in findings:
            cursor.execute("""
                INSERT INTO scan_results
                    (repo_id, tool, severity, confidence, issue_text,
                     filename, line_number, code_snippet)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (repo_id, f["tool"], f["severity"], f.get("p_real"),
                  f["issue_text"], f["filename"], f.get("line_number", 0),
                  f.get("code_snippet", "")))

        # Save risk score — high_count/medium_count/low_count/final_score/
        # risk_level stay as the blended "overall" figure (kept only for
        # scan_history trend continuity); vuln_*/malware_* are the two
        # honest, separate axes the UI actually shows.
        vuln    = category_risk["vulnerability"]
        malware = category_risk["malicious_pattern"]
        cursor.execute("""
            INSERT INTO risk_scores
                (repo_id, high_count, medium_count, low_count,
                 final_score, risk_level,
                 vuln_high, vuln_medium, vuln_low, vuln_score, vuln_level,
                 malware_high, malware_medium, malware_low, malware_score, malware_level)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (repo_id, high, medium, low, score, level,
              vuln["high"], vuln["medium"], vuln["low"], vuln["score"], vuln["level"],
              malware["high"], malware["medium"], malware["low"], malware["score"], malware["level"]))

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

def scan_repo(repo, archive_password="infected", on_progress=None):
    print(f"\n{'='*50}\nScanning: {repo}\n{'='*50}")

    def report(stage):
        if on_progress:
            on_progress(stage)

    report("Fetching repository info")
    repo_info = get_repo_info(repo)

    report("Cloning repository")
    path = clone_repo(repo)

    try:
        report("Extracting archives")
        extract_archives(path, archive_password)

        findings = []

        report("Running Bandit")
        findings += run_bandit(path)

        report("Running Semgrep")
        findings += run_semgrep(path)

        report("Running YARA")
        findings += run_yara(path)

        report("Running ClamAV")
        findings += run_clamav(path)

        report("Checking dependencies")
        findings += check_dependencies(path)

        report("Filtering results")
        findings = filter_noise(findings)
        print(f"  Findings after filter: {len(findings)}")

        report("Scoring findings")
        findings = score_findings(findings)

        report("Calculating risk score")
        high, medium, low, score, level = calculate_risk(findings)
        category_risk = calculate_category_risk(findings)

        report("Saving results")
        repo_id = save_to_db(repo_info, findings,
                             high, medium, low, score, level, category_risk)

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
import os
import json
import subprocess
from difflib import SequenceMatcher

KNOWN_PACKAGES = [
    "requests", "flask", "django", "numpy", "pandas",
    "scipy", "matplotlib", "tensorflow", "torch", "sklearn",
    "sqlalchemy", "celery", "redis", "pillow", "boto3",
    "pytest", "setuptools", "pip", "wheel", "cryptography",
    "paramiko", "fabric", "ansible", "scrapy", "beautifulsoup4",
    "lxml", "pymysql", "psycopg2", "mongoengine", "fastapi",
    "uvicorn", "pydantic", "httpx", "aiohttp", "twisted",
    "werkzeug", "jinja2", "click", "rich", "typer"
]

# Check for typosquatting

def is_typosquat(package_name, threshold=0.85):
    package_name = package_name.lower().strip()
    
    if package_name in KNOWN_PACKAGES:
        return None
    
    for known in KNOWN_PACKAGES:
        ratio = SequenceMatcher(None, package_name, known).ratio()
        if ratio >= threshold and ratio < 1.0:
            return known  
    
    return None


#Parse dependency files. Need to add another dependency file for other code language


def parse_dependencies(repo_path):
    """
    Finds and reads dependency files in the repo.
    Returns list of (package_name, version, filename) tuples.
    """
    dependencies = []

    # === Python: requirements.txt ===
    req_file = os.path.join(repo_path, "requirements.txt")
    if os.path.exists(req_file):
        with open(req_file, "r") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue
                # Skip direct URL installs
                if line.startswith(("http://", "https://", "git+")):
                    dependencies.append({
                        "name":     line,
                        "version":  "unknown",
                        "filename": "requirements.txt",
                        "line":     line_num,
                        "raw":      line,
                        "url_install": True
                    })
                    continue
                # Parse name and version
                if "==" in line:
                    parts   = line.split("==")
                    name    = parts[0].strip()
                    version = parts[1].strip()
                elif ">=" in line:
                    parts   = line.split(">=")
                    name    = parts[0].strip()
                    version = f">={parts[1].strip()}"
                else:
                    name    = line.strip()
                    version = "unpinned"

                dependencies.append({
                    "name":        name,
                    "version":     version,
                    "filename":    "requirements.txt",
                    "line":        line_num,
                    "raw":         line,
                    "url_install": False
                })

    # === Node.js: package.json ===
    pkg_file = os.path.join(repo_path, "package.json")
    if os.path.exists(pkg_file):
        try:
            with open(pkg_file, "r") as f:
                data = json.load(f)
            for dep_type in ["dependencies", "devDependencies"]:
                for name, version in data.get(dep_type, {}).items():
                    dependencies.append({
                        "name":        name,
                        "version":     version,
                        "filename":    "package.json",
                        "line":        0,
                        "raw":         f"{name}:{version}",
                        "url_install": False
                    })
        except Exception as e:
            print(f"    Could not parse package.json: {e}")

    return dependencies


#CVE Checker

def run_pip_audit(repo_path):
    """
    Runs pip-audit against requirements.txt in the repo.
    Returns findings for any packages with known CVEs.
    """
    print("  Running pip-audit...")
    findings = []

    req_file = os.path.join(repo_path, "requirements.txt")
    if not os.path.exists(req_file):
        print("    pip-audit: no requirements.txt found, skipping")
        return findings

    try:
        result = subprocess.run(
            ["pip-audit", "-r", req_file, "--format", "json", "--progress-spinner", "off"],
            capture_output=True, text=True, timeout=120
        )

        data = json.loads(result.stdout)

        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulns", []):
                findings.append({
                    "tool":         "dep_checker",
                    "severity":     "high",
                    "issue_text":   f"CVE found: {vuln['id']} in {dep['name']}=={dep['version']} — {vuln.get('description', '')[:100]}",
                    "filename":     "requirements.txt",
                    "line_number":  0,
                    "code_snippet": f"{dep['name']}=={dep['version']}"
                })

    except json.JSONDecodeError:
        print("    pip-audit: no output")
    except subprocess.TimeoutExpired:
        print("    pip-audit: timed out")
    except Exception as e:
        print(f"    pip-audit error: {e}")

    print(f"    pip-audit found {len(findings)} vulnerable dependencies")
    return findings

#Check suspicious dependency patterns


def check_suspicious_patterns(repo_path):
    """
    Checks dependencies for suspicious patterns:
    1. Typosquatting
    2. Unpinned versions
    3. Direct URL installs
    """
    print("  Checking dependency patterns...")
    findings = []

    deps = parse_dependencies(repo_path)

    if not deps:
        print("    No dependency files found")
        return findings

    for dep in deps:
        name     = dep["name"]
        version  = dep["version"]
        filename = dep["filename"]
        line     = dep["line"]
        raw      = dep["raw"]

        # Check 1: Direct URL install
        if dep.get("url_install"):
            findings.append({
                "tool":         "dep_checker",
                "severity":     "high",
                "issue_text":   f"Direct URL install detected — bypasses official registry: {raw}",
                "filename":     filename,
                "line_number":  line,
                "code_snippet": raw
            })
            continue

        # Check 2: Typosquatting
        imitated = is_typosquat(name)
        if imitated:
            findings.append({
                "tool":         "dep_checker",
                "severity":     "high",
                "issue_text":   f"Typosquatting: '{name}' is suspiciously similar to '{imitated}'",
                "filename":     filename,
                "line_number":  line,
                "code_snippet": raw
            })

        # Check 3: Unpinned version
        if version == "unpinned":
            findings.append({
                "tool":         "dep_checker",
                "severity":     "medium",
                "issue_text":   f"Unpinned dependency: '{name}' has no version lock — supply chain risk",
                "filename":     filename,
                "line_number":  line,
                "code_snippet": raw
            })

        # Check 4: Loose version (>=)
        elif version.startswith(">=") or version.startswith("^"):
            findings.append({
                "tool":         "dep_checker",
                "severity":     "low",
                "issue_text":   f"Loose version constraint: '{name}{version}' — attacker could push malicious update",
                "filename":     filename,
                "line_number":  line,
                "code_snippet": raw
            })

    print(f"    Found {len(findings)} suspicious patterns")
    return findings


#Run all dependency checks


def check_dependencies(repo_path):
    """
    Main function — runs all dependency checks.
    Returns findings in same format as scanner.py tools.
    """
    print("\n  [Dependency Checker]")
    findings = []

    findings += run_pip_audit(repo_path)
    findings += check_suspicious_patterns(repo_path)

    print(f"  Dep checker total: {len(findings)} issues")
    return findings
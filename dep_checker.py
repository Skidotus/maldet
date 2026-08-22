import os
import re
import ast
import json
import subprocess
import tomllib
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

def _parse_pep508_name_version(raw):
    """Parses a PEP 508 requirement string ('requests>=2.0', 'flask[async]')
    into (name, version), using the same simplified 3-way classification
    (==, >=, else "unpinned") that requirements.txt parsing already uses —
    other operators (~=, <=, <, >, !=) fall into "unpinned" too, same
    simplification, not a new one."""
    raw = re.sub(r"\[[^\]]*\]", "", raw).split(";")[0].strip()
    if "==" in raw:
        name, version = raw.split("==", 1)
        return name.strip(), version.strip()
    elif ">=" in raw:
        name, version = raw.split(">=", 1)
        return name.strip(), f">={version.strip()}"
    else:
        name = re.split(r"[<>=!~\s]", raw)[0].strip()
        return name, "unpinned" if name else (None, None)


def _table_style_version(value):
    """Poetry/Pipfile dependency tables both write versions as either a
    bare string ('^2.28', '*', '2.0.1') or {version = '...', extras = [...]}
    — normalizes either into the same version-string shape used elsewhere."""
    version = value.get("version", "*") if isinstance(value, dict) else value
    if not isinstance(version, str):
        return "unpinned"
    version = version.strip()
    if version in ("*", ""):
        return "unpinned"
    if version.startswith("==" ):
        return version[2:].strip()
    return version  # "^2.28"/">=2.28" pass through as-is (already "loose"
                     # per the startswith check below); a bare pinned
                     # version like "2.28.1" passes through as effectively
                     # pinned, same treatment as requirements.txt's "=="


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

    # === Python: pyproject.toml (PEP 621 and Poetry) ===
    pyproject_file = os.path.join(repo_path, "pyproject.toml")
    if os.path.exists(pyproject_file):
        try:
            with open(pyproject_file, "rb") as f:
                data = tomllib.load(f)

            # PEP 621: [project] dependencies = ["requests>=2.0", ...]
            project = data.get("project", {})
            raw_deps = list(project.get("dependencies", []))
            for group_deps in project.get("optional-dependencies", {}).values():
                raw_deps += group_deps
            for raw in raw_deps:
                name, version = _parse_pep508_name_version(raw)
                if not name:
                    continue
                dependencies.append({
                    "name": name, "version": version, "filename": "pyproject.toml",
                    "line": 0, "raw": raw, "url_install": False
                })

            # Poetry: [tool.poetry.dependencies] requests = "^2.28"
            poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
            for name, value in poetry_deps.items():
                if name.lower() == "python":
                    continue
                version = _table_style_version(value)
                dependencies.append({
                    "name": name, "version": version, "filename": "pyproject.toml",
                    "line": 0, "raw": f"{name} = {value}", "url_install": False
                })
        except Exception as e:
            print(f"    Could not parse pyproject.toml: {e}")

    # === Python: Pipfile ===
    pipfile = os.path.join(repo_path, "Pipfile")
    if os.path.exists(pipfile):
        try:
            with open(pipfile, "rb") as f:
                data = tomllib.load(f)
            for section in ("packages", "dev-packages"):
                for name, value in data.get(section, {}).items():
                    version = _table_style_version(value)
                    dependencies.append({
                        "name": name, "version": version, "filename": "Pipfile",
                        "line": 0, "raw": f"{name} = {value}", "url_install": False
                    })
        except Exception as e:
            print(f"    Could not parse Pipfile: {e}")

    # === Python: poetry.lock — already-resolved exact versions, so only
    # useful for typosquat detection, not unpinned/loose-version checks
    # (everything in a lock file is pinned by definition) ===
    lock_file = os.path.join(repo_path, "poetry.lock")
    if os.path.exists(lock_file):
        try:
            with open(lock_file, "rb") as f:
                data = tomllib.load(f)
            for pkg in data.get("package", []):
                name = pkg.get("name")
                version = pkg.get("version")
                if not name:
                    continue
                dependencies.append({
                    "name": name, "version": version or "unknown", "filename": "poetry.lock",
                    "line": 0, "raw": f"{name} {version}", "url_install": False,
                    "locked": True  # skip unpinned/loose checks — see check_suspicious_patterns
                })
        except Exception as e:
            print(f"    Could not parse poetry.lock: {e}")

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

        # Checks 3/4 don't apply to poetry.lock — everything in a lock
        # file is already fully resolved/pinned by definition
        if dep.get("locked"):
            continue

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


#Install-time script analysis
#
# setup.py executes as plain Python the moment pip/setuptools processes it
# (not just when the installed package is later imported and run) — a
# well-documented real supply-chain attack vector, since malicious code
# here runs before a developer ever looks at the actual application code.
# We only ever statically parse this with ast, never execute it.

SETUP_COMMAND_BASES = {"install", "develop", "build_py", "build_ext", "sdist", "egg_info"}
LIFECYCLE_METHODS    = {"run", "initialize_options", "finalize_options"}

DANGEROUS_CALLS = {
    "eval", "exec", "os.system", "os.popen",
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
    "urllib.request.urlopen", "requests.get", "requests.post",
}

def _dotted_call_name(node):
    parts, func = [], node.func
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    return ".".join(reversed(parts))


def _build_parent_map(tree):
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def _is_setup_command_subclass(class_def):
    return any(isinstance(b, ast.Name) and b.id in SETUP_COMMAND_BASES for b in class_def.bases)


def _runs_at_install_time(node, parents):
    """Walks up from an AST node to the module root. Code at module level
    or inside a class body runs the moment the class/module is defined —
    that's most of setup.py. Code inside an ordinary function/lambda only
    runs if something calls it, UNLESS that function is one of setuptools'
    own install-lifecycle methods (run/initialize_options/finalize_options)
    on a class overriding install/develop/etc., which setuptools calls
    automatically during `pip install` — the classic malicious-setup.py
    technique."""
    current = node
    while current in parents:
        parent = parents[current]
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            grandparent = parents.get(parent)
            if (isinstance(grandparent, ast.ClassDef)
                    and parent.name in LIFECYCLE_METHODS
                    and _is_setup_command_subclass(grandparent)):
                current = grandparent
                continue
            return False
        if isinstance(parent, ast.Lambda):
            return False
        current = parent
    return True


def check_setup_py(repo_path):
    print("  Checking setup.py for install-time code execution...")
    findings = []
    setup_file = os.path.join(repo_path, "setup.py")
    if not os.path.exists(setup_file):
        return findings

    try:
        with open(setup_file, "r", errors="replace") as f:
            source = f.read()
        tree = ast.parse(source, filename="setup.py")
    except SyntaxError as e:
        print(f"    Could not parse setup.py: {e}")
        return findings

    parents = _build_parent_map(tree)

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and _is_setup_command_subclass(node):
            base_names = ", ".join(b.id for b in node.bases if isinstance(b, ast.Name))
            findings.append({
                "tool":         "dep_checker",
                "severity":     "medium",
                "issue_text":   f"setup.py overrides the install process (class {node.name}({base_names})) — review its run()/initialize_options() for unexpected behavior",
                "filename":     "setup.py",
                "line_number":  node.lineno,
                "code_snippet": f"class {node.name}({base_names}):"
            })

        if isinstance(node, ast.Call):
            name = _dotted_call_name(node)
            if name in DANGEROUS_CALLS and _runs_at_install_time(node, parents):
                findings.append({
                    "tool":         "dep_checker",
                    "severity":     "high",
                    "issue_text":   f"setup.py calls {name}(...) at install time — this runs automatically during pip install, before any application code is ever run",
                    "filename":     "setup.py",
                    "line_number":  getattr(node, "lineno", 0),
                    "code_snippet": ast.get_source_segment(source, node) or name
                })

    print(f"    setup.py: found {len(findings)} issue(s)")
    return findings


NPM_HOOK_PATTERNS = [
    (re.compile(r"\|\s*(sh|bash|zsh)\b"),          "pipes output into a shell"),
    (re.compile(r"curl\s+.*\|\s*(sh|bash)"),        "downloads and pipes into a shell"),
    (re.compile(r"wget\s+.*\|\s*(sh|bash)"),        "downloads and pipes into a shell"),
    (re.compile(r"base64\s+-d"),                    "decodes a base64 payload"),
    (re.compile(r"node\s+-e\s+"),                   "runs an inline Node.js one-liner"),
    (re.compile(r"eval\("),                         "calls eval()"),
]

def check_npm_install_hooks(repo_path):
    print("  Checking package.json install hooks...")
    findings = []
    pkg_file = os.path.join(repo_path, "package.json")
    if not os.path.exists(pkg_file):
        return findings

    try:
        with open(pkg_file, "r") as f:
            data = json.load(f)
    except Exception as e:
        print(f"    Could not parse package.json: {e}")
        return findings

    for hook in ("preinstall", "install", "postinstall"):
        script = data.get("scripts", {}).get(hook)
        if not script:
            continue

        matched_reasons = [desc for pattern, desc in NPM_HOOK_PATTERNS if pattern.search(script)]
        if matched_reasons:
            findings.append({
                "tool":         "dep_checker",
                "severity":     "high",
                "issue_text":   f"package.json '{hook}' script runs automatically on npm install and {', '.join(matched_reasons)}: {script}",
                "filename":     "package.json",
                "line_number":  0,
                "code_snippet": script
            })
        else:
            findings.append({
                "tool":         "dep_checker",
                "severity":     "low",
                "issue_text":   f"package.json has a '{hook}' script that runs automatically on npm install — worth a manual look: {script}",
                "filename":     "package.json",
                "line_number":  0,
                "code_snippet": script
            })

    print(f"    package.json install hooks: found {len(findings)} issue(s)")
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
    findings += check_setup_py(repo_path)
    findings += check_npm_install_hooks(repo_path)

    print(f"  Dep checker total: {len(findings)} issues")
    return findings
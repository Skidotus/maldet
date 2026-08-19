import json
import threading
import uuid
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify
import pymysql
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME
from scanner import scan_repo

app = Flask(__name__)

def get_db():
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor
    )

# In-memory scan job tracking — single-user local tool, so a process-lifetime
# dict is enough; no need for a DB table or a task queue. Scans run in a
# background thread so /scan can redirect immediately to a status page that
# survives refreshes, instead of holding the request open for the whole
# pipeline (see git history for why: refreshing mid-scan used to strand the
# user with no way to tell whether it was still running).
SCANS      = {}
SCANS_LOCK = threading.Lock()

def _find_running_job_id():
    with SCANS_LOCK:
        for job_id, job in SCANS.items():
            if job["status"] == "running":
                return job_id
    return None

def _start_scan_job(repo, archive_password):
    job_id = uuid.uuid4().hex
    with SCANS_LOCK:
        SCANS[job_id] = {
            "repo":       repo,
            "status":     "running",
            "stage":      "Queued",
            "started_at": datetime.now(),
            "repo_id":    None,
            "error":      None,
        }

    def run():
        def on_progress(stage):
            with SCANS_LOCK:
                SCANS[job_id]["stage"] = stage
        try:
            result = scan_repo(repo, archive_password, on_progress=on_progress)
            with SCANS_LOCK:
                SCANS[job_id]["status"]  = "done"
                SCANS[job_id]["stage"]   = "Done"
                SCANS[job_id]["repo_id"] = result["repo_id"]
        except Exception as e:
            with SCANS_LOCK:
                SCANS[job_id]["status"] = "error"
                SCANS[job_id]["error"]  = str(e)

    threading.Thread(target=run, daemon=True).start()
    return job_id

#dashbaord

@app.route('/')
def index():
    db     = get_db()
    cursor = db.cursor()

    try:
        
        cursor.execute("""
            SELECT 
                r.id,
                r.repo_name,
                r.owner,
                r.language,
                r.stars,
                r.scanned_at,
                rs.final_score,
                rs.risk_level,
                rs.high_count,
                rs.medium_count,
                rs.low_count
            FROM repositories r
            JOIN risk_scores rs ON r.id = rs.repo_id
            ORDER BY r.scanned_at DESC
        """)
        repos = cursor.fetchall()

        # Count by risk level for summary cards
        total    = len(repos)
        safe     = sum(1 for r in repos if r['risk_level'] == 'Safe')
        low      = sum(1 for r in repos if r['risk_level'] == 'Low')
        medium   = sum(1 for r in repos if r['risk_level'] == 'Medium')
        high     = sum(1 for r in repos if r['risk_level'] == 'High')
        critical = sum(1 for r in repos if r['risk_level'] == 'Critical')

        return render_template('index.html',
            repos    = repos[:10],
            total    = total,
            safe     = safe,
            low      = low,
            medium   = medium,
            high     = high,
            critical = critical
        )

    finally:
        cursor.close()
        db.close()

#Scan repo

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    # If a scan is already running (this tab, another tab, or a previous
    # session that navigated away), always land back on its status page
    # instead of a blank form — this is what makes the scan survive refresh.
    running_job_id = _find_running_job_id()
    if running_job_id:
        return redirect(url_for('scan_status', job_id=running_job_id))

    if request.method == 'GET':
        return render_template('scan.html')

    # POST — user submitted the scan form
    repo_url         = request.form.get('repo_url', '').strip()
    archive_password = request.form.get('archive_password', 'infected').strip()

    # Validate input
    if not repo_url:
        return render_template('scan.html', error="Please enter a GitHub URL")

    # Extract owner/repo from URL
    # Handles:
    # https://github.com/owner/repo
    # github.com/owner/repo
    # owner/repo
    try:
        repo_url = repo_url.replace("https://", "").replace("http://", "")
        repo_url = repo_url.replace("github.com/", "")
        repo_url = repo_url.strip("/")
        parts    = repo_url.split("/")

        if len(parts) < 2:
            return render_template('scan.html',
                error="Invalid GitHub URL. Example: https://github.com/owner/repo")

        owner_part, repo_part = parts[0], parts[1]
        if repo_part.endswith(".git"):
            repo_part = repo_part[:-4]
        repo = f"{owner_part}/{repo_part}"

    except Exception:
        return render_template('scan.html',
            error="Invalid GitHub URL. Example: https://github.com/owner/repo")

    job_id = _start_scan_job(repo, archive_password)
    return redirect(url_for('scan_status', job_id=job_id))


# Scan status page — polled by JS, safe to refresh/reopen at any time

@app.route('/scan/<job_id>')
def scan_status(job_id):
    job = SCANS.get(job_id)
    if not job:
        return redirect(url_for('scan'))
    return render_template('scan_status.html', job=job, job_id=job_id)


@app.route('/api/scan-status/<job_id>')
def api_scan_status(job_id):
    job = SCANS.get(job_id)
    if not job:
        return jsonify({"error": "Not found"}), 404
    return jsonify({
        "status":     job["status"],
        "stage":      job["stage"],
        "repo":       job["repo"],
        "repo_id":    job["repo_id"],
        "error":      job["error"],
        "started_at": job["started_at"].isoformat(),
    })

# Repo Detail page

@app.route('/detail/<int:repo_id>')
def detail(repo_id):
    db     = get_db()
    cursor = db.cursor()

    try:
        # Get repo info
        cursor.execute("""
            SELECT * FROM repositories WHERE id = %s
        """, (repo_id,))
        repo = cursor.fetchone()

        if not repo:
            return "Repository not found", 404

        # Get risk score (risk_scores has no created_at column — id is
        # auto-increment and insert-ordered, so it stands in for recency)
        cursor.execute("""
            SELECT * FROM risk_scores WHERE repo_id = %s
            ORDER BY id DESC LIMIT 1
        """, (repo_id,))
        risk = cursor.fetchone()

        # `ORDER BY severity DESC` sorts the raw strings lexicographically
        # (warning > medium > low > info > high > error), not by actual
        # severity, so rank it explicitly. Some repos (e.g. noisy Bandit
        # runs) have tens of thousands of findings for one tool, so cap
        # each tool at FINDINGS_PER_TOOL_LIMIT rather than rendering
        # everything — the template shows a "N more not shown" note.
        FINDINGS_PER_TOOL_LIMIT = 200
        SEVERITY_RANK = """
            CASE severity
                WHEN 'high' THEN 3 WHEN 'error' THEN 3 WHEN 'critical' THEN 3
                WHEN 'medium' THEN 2 WHEN 'warning' THEN 2
                ELSE 1
            END
        """

        cursor.execute(f"""
            SELECT tool, COUNT(*) AS total
            FROM scan_results
            WHERE repo_id = %s
            GROUP BY tool
        """, (repo_id,))
        tool_totals = {row['tool']: row['total'] for row in cursor.fetchall()}

        cursor.execute(f"""
            SELECT * FROM (
                SELECT *, ROW_NUMBER() OVER (
                    PARTITION BY tool
                    ORDER BY {SEVERITY_RANK} DESC, id ASC
                ) AS rn
                FROM scan_results
                WHERE repo_id = %s
            ) ranked
            WHERE rn <= %s
            ORDER BY {SEVERITY_RANK} DESC, tool ASC
        """, (repo_id, FINDINGS_PER_TOOL_LIMIT))
        findings = cursor.fetchall()

        # Get scan history for trend chart
        cursor.execute("""
            SELECT final_score, risk_level, scanned_at
            FROM scan_history
            WHERE repo_id = %s
            ORDER BY scanned_at ASC
        """, (repo_id,))
        history = cursor.fetchall()

        # Group findings by tool for display
        tools = {}
        for f in findings:
            tool = f['tool']
            if tool not in tools:
                tools[tool] = []
            tools[tool].append(f)

        # Convert history dates to JSON for chart
        history_dates  = [str(h['scanned_at']) for h in history]
        history_scores = [h['final_score'] for h in history]

        return render_template('detail.html',
            repo          = repo,
            risk          = risk,
            findings      = findings,
            tools         = tools,
            tool_totals   = tool_totals,
            history_dates  = json.dumps(history_dates),
            history_scores = json.dumps(history_scores)
        )

    finally:
        cursor.close()
        db.close()


#Scan history page

@app.route('/history')
def history():
    db     = get_db()
    cursor = db.cursor()

    try:
        cursor.execute("""
            SELECT
                r.id,
                r.repo_name,
                r.owner,
                r.language,
                r.stars,
                rs.final_score,
                rs.risk_level,
                rs.high_count,
                rs.medium_count,
                rs.low_count,
                r.scanned_at
            FROM repositories r
            JOIN risk_scores rs ON r.id = rs.repo_id
            ORDER BY r.scanned_at DESC
        """)
        repos = cursor.fetchall()

        return render_template('history.html', repos=repos)

    finally:
        cursor.close()
        db.close()


#rescan repo

@app.route('/rescan/<int:repo_id>')
def rescan(repo_id):
    db     = get_db()
    cursor = db.cursor()

    try:
        # Get repo name from DB
        cursor.execute("""
            SELECT repo_name, owner FROM repositories WHERE id = %s
        """, (repo_id,))
        repo = cursor.fetchone()

        if not repo:
            return "Repository not found", 404

        repo_slug = f"{repo['owner']}/{repo['repo_name']}"

    finally:
        cursor.close()
        db.close()

    # Run scan again
    running_job_id = _find_running_job_id()
    if running_job_id:
        return redirect(url_for('scan_status', job_id=running_job_id))

    job_id = _start_scan_job(repo_slug, "infected")
    return redirect(url_for('scan_status', job_id=job_id))


#API scan status

@app.route('/api/results/<int:repo_id>')
def api_results(repo_id):
    db     = get_db()
    cursor = db.cursor()

    try:
        cursor.execute("""
            SELECT * FROM risk_scores WHERE repo_id = %s
            ORDER BY id DESC LIMIT 1
        """, (repo_id,))
        risk = cursor.fetchone()

        if not risk:
            return jsonify({"error": "Not found"}), 404

        return jsonify(risk)

    finally:
        cursor.close()
        db.close()


#run app

if __name__ == '__main__':
    # threaded=True so status-page polling isn't queued behind other
    # requests while a scan's background thread is running.
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        threaded=True
    )
import json
import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify, Response
import pymysql
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME
from db_connect import DB_PORT
from scanner import scan_repo
import job_queue

app = Flask(__name__)

# Confidence thresholds for the plain-English findings summary — same
# "likely noise" cutoff (<0.3) used to dim findings in detail.html, so the
# summary text and the visual treatment always agree with each other.
SUMMARY_REAL_THRESHOLD  = 0.5
SUMMARY_NOISE_THRESHOLD = 0.3

def build_findings_summary(total, likely_real, likely_noise, top_finding):
    """Rule-based summary for now (counts + the single highest-priority
    finding) — same shape of output an LLM-generated summary would
    eventually replace, without needing that dependency to be useful today."""
    if total == 0:
        return "No findings — this scan came back clean."
    if likely_real == 0:
        return (f"All {total} finding{'s' if total != 1 else ''} look like noise "
                 "(low confidence) — nothing here likely needs attention.")

    parts = [f"{likely_real} finding{'s' if likely_real != 1 else ''} likely need attention"]
    if likely_noise:
        parts.append(f"{likely_noise} look{'s' if likely_noise == 1 else ''} like noise")
    summary = ", ".join(parts) + "."

    if top_finding:
        text = top_finding["issue_text"] or ""
        if len(text) > 90:
            text = text[:87] + "..."
        loc = f" in {top_finding['filename']}" if top_finding.get("filename") else ""
        conf = top_finding.get("confidence")
        conf_text = f" ({round(conf * 100)}% confidence)" if conf is not None else ""
        summary += f" Most notable: {text}{loc}{conf_text}."

    return summary

def get_db():
    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor
    )

# Scan jobs live in the `scan_jobs` table (see job_queue.py), not in memory.
# This used to be a process-lifetime dict, which suited a single-user local
# tool but breaks once the app is deployed: a restart stranded every running
# scan, a second web worker could not see the first one's jobs, and a second
# visitor was redirected into someone else's scan instead of being queued.
#
# Scans are executed by worker.py, a separate single process. The web side
# now only enqueues, so no amount of traffic can start a second semgrep --
# which is the constraint that matters on a small VPS, where one semgrep
# peaks near 2GB against 4GB of RAM.


def _visitor_job_id():
    """The job this browser last submitted, if it is still queued or running.

    Replaces the old global check, which sent *every* visitor to whichever
    scan happened to be running -- fine when there was only ever one user,
    wrong once the tool is public: a second visitor would be shown a
    stranger's scan instead of getting their own queued. A cookie keeps the
    "survives refresh" behaviour that check existed for, without leaking one
    visitor's scan into another's browser.
    """
    job_id = request.cookies.get("maldet_job")
    if not job_id:
        return None
    job = job_queue.get_job(job_id)
    if job and job["status"] in ("queued", "running"):
        return job_id
    return None


def _redirect_to_job(job_id):
    """Send the visitor to their status page and remember the job."""
    resp = redirect(url_for('scan_status', job_id=job_id))
    # No sensitive content: an opaque job id, so the visitor can find their
    # own scan again after a refresh. Lasts a day; the job outlives it in
    # the table either way.
    resp.set_cookie("maldet_job", job_id, max_age=86400, samesite="Lax")
    return resp


def _start_scan_job(repo, archive_password):
    """Queue a scan. Returns the job id; the worker picks it up."""
    return job_queue.enqueue(repo, archive_password)


def _job_payload(job, job_id):
    """Shape a scan_jobs row the way the status page and its poller expect."""
    return {
        "status":     job["status"],
        "stage":      job["stage"],
        "repo":       job["repo"],
        "repo_id":    job["repo_id"],
        "error":      job["error"],
        # Queued jobs have not started, so the page shows when it was
        # submitted instead of leaving the visitor with a blank timestamp.
        "started_at": (job["started_at"] or job["queued_at"]),
        "position":   job_queue.queue_position(job_id),
    }


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
                rs.vuln_score, rs.vuln_level,
                rs.malware_score, rs.malware_level
            FROM repositories r
            JOIN risk_scores rs ON r.id = rs.repo_id
            ORDER BY r.scanned_at DESC
        """)
        repos = cursor.fetchall()

        # Tally by the WORSE of the two axes — a compact "does this repo
        # need any attention at all" summary for the top strip. Full
        # per-axis breakdown is still shown per-repo in the table below;
        # this tally is deliberately coarse, not a third blended score.
        LEVEL_RANK = {"Safe": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        def worse_level(r):
            return max(r['vuln_level'] or 'Safe', r['malware_level'] or 'Safe',
                       key=lambda lvl: LEVEL_RANK.get(lvl, 0))

        total    = len(repos)
        safe     = sum(1 for r in repos if worse_level(r) == 'Safe')
        low      = sum(1 for r in repos if worse_level(r) == 'Low')
        medium   = sum(1 for r in repos if worse_level(r) == 'Medium')
        high     = sum(1 for r in repos if worse_level(r) == 'High')
        critical = sum(1 for r in repos if worse_level(r) == 'Critical')

        cursor.execute("SELECT COUNT(*) AS n FROM scan_results")
        total_findings = cursor.fetchone()['n']

        return render_template('index.html',
            repos          = repos[:10],
            total          = total,
            safe           = safe,
            low            = low,
            medium         = medium,
            high           = high,
            critical       = critical,
            total_findings = total_findings,
            # The landing page's scan form would only bounce this visitor
            # back to the scan they already have running, so say so up front.
            active_job_id  = _visitor_job_id()
        )

    finally:
        cursor.close()
        db.close()

#Scan repo

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    # If this visitor already has a scan queued or running, land back on its
    # status page instead of a blank form — this is what makes the scan
    # survive refresh. Other visitors' scans are none of their business; they
    # queue behind them rather than being shown someone else's progress.
    own_job_id = _visitor_job_id()
    if own_job_id:
        return _redirect_to_job(own_job_id)

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
    return _redirect_to_job(job_id)


# Scan status page — polled by JS, safe to refresh/reopen at any time

@app.route('/scan/<job_id>')
def scan_status(job_id):
    job = job_queue.get_job(job_id)
    if not job:
        return redirect(url_for('scan'))
    return render_template('scan_status.html',
                           job=_job_payload(job, job_id), job_id=job_id)


@app.route('/api/scan-status/<job_id>')
def api_scan_status(job_id):
    job = job_queue.get_job(job_id)
    if not job:
        return jsonify({"error": "Not found"}), 404
    payload = _job_payload(job, job_id)
    payload["started_at"] = payload["started_at"].isoformat()
    return jsonify(payload)

# Repo Detail page

# ---- Report ------------------------------------------------------------

# Findings shown in a report's evidence table. Lower than the detail page's
# 200-per-tool, because a report is meant to be read end to end and sent to
# someone: a 400-page attachment is not a report. The true totals are always
# stated alongside, so a cap never hides the scale.
REPORT_EVIDENCE_LIMIT = 60

# What each detector looks for, in one line. A report goes to people who have
# never heard of these tools, and "YARA found 4 things" means nothing without
# it.
TOOL_PURPOSE = {
    "bandit":      "Insecure coding patterns in Python source",
    "semgrep":     "Insecure coding patterns across many languages",
    "yara":        "Signatures of malicious behaviour in source files",
    "clamav":      "Known malware signatures",
    "guarddog":    "Malicious package and install-time behaviour",
    "dep_checker": "Vulnerable, unpinned or typosquatted dependencies",
    "virustotal":  "Known malware signatures (legacy scans)",
}


def _report_context(cursor, repo_id):
    """Everything a report needs, gathered once.

    Both the on-screen report and the PDF render from this, so the document
    someone downloads cannot disagree with the one they previewed.
    Returns None if the repo has no scan.
    """
    cursor.execute("SELECT * FROM repositories WHERE id = %s", (repo_id,))
    repo = cursor.fetchone()
    if not repo:
        return None

    cursor.execute("""SELECT * FROM risk_scores WHERE repo_id = %s
                      ORDER BY id DESC LIMIT 1""", (repo_id,))
    risk = cursor.fetchone()

    # True totals, independent of what the evidence table shows.
    cursor.execute("""
        SELECT COUNT(*) AS total,
               SUM(confidence >= %s) AS likely_real,
               SUM(confidence <  %s) AS likely_noise
        FROM scan_results WHERE repo_id = %s
    """, (SUMMARY_REAL_THRESHOLD, SUMMARY_NOISE_THRESHOLD, repo_id))
    counts = cursor.fetchone()

    # Per-tool totals and severity breakdown, for the overview table.
    cursor.execute("""
        SELECT tool,
               COUNT(*) AS total,
               SUM(severity IN ('high','error','critical')) AS high,
               SUM(severity IN ('medium','warning'))        AS medium
        FROM scan_results WHERE repo_id = %s
        GROUP BY tool ORDER BY total DESC
    """, (repo_id,))
    by_tool = cursor.fetchall()
    for t in by_tool:
        t["high"]    = int(t["high"] or 0)
        t["medium"]  = int(t["medium"] or 0)
        t["low"]     = int(t["total"]) - t["high"] - t["medium"]
        t["purpose"] = TOOL_PURPOSE.get(t["tool"], "")

    # Evidence: the worst findings first, grouped so one noisy rule firing 40
    # times takes one row instead of 40.
    cursor.execute("""
        SELECT tool,
               MAX(CASE severity
                     WHEN 'high' THEN 3 WHEN 'error' THEN 3 WHEN 'critical' THEN 3
                     WHEN 'medium' THEN 2 WHEN 'warning' THEN 2 ELSE 1 END) AS sev_rank,
               MAX(COALESCE(confidence, 0)) AS confidence,
               COUNT(*) AS occurrences,
               SUBSTRING_INDEX(GROUP_CONCAT(
                   CONCAT(COALESCE(filename,''), 0x1e, COALESCE(line_number,0))
                   ORDER BY COALESCE(confidence,0) DESC SEPARATOR 0x1f), 0x1f, 1) AS example,
               -- MAX() only to satisfy only_full_group_by: the group key is
               -- TRIM(issue_text) under a binary collation, so every row in a
               -- group carries the identical string and MAX picks it exactly.
               MAX(LEFT(TRIM(issue_text), 300)) AS issue_text
        FROM scan_results WHERE repo_id = %s
        GROUP BY tool, TRIM(issue_text) COLLATE utf8mb4_bin
        ORDER BY sev_rank DESC, confidence DESC, occurrences DESC
        LIMIT %s
    """, (repo_id, REPORT_EVIDENCE_LIMIT))
    evidence = cursor.fetchall()
    rank_name = {3: "high", 2: "medium", 1: "low"}
    for e in evidence:
        f, _, line = (e["example"] or "").partition("\x1e")
        e["severity"]     = rank_name.get(int(e["sev_rank"] or 1), "low")
        e["example_file"] = f
        e["example_line"] = int(line) if line.isdigit() else 0
        e["occurrences"]  = int(e["occurrences"])

    # How many distinct kinds exist, so the cap can be stated honestly.
    cursor.execute("""
        SELECT COUNT(*) AS n FROM (
            SELECT 1 FROM scan_results WHERE repo_id = %s
            GROUP BY tool, TRIM(issue_text) COLLATE utf8mb4_bin
        ) g
    """, (repo_id,))
    group_total = int(cursor.fetchone()["n"])

    total = int(counts["total"] or 0)
    summary = (risk or {}).get("llm_summary")
    return {
        "repo":        repo,
        "risk":        risk,
        "total":       total,
        "likely_real": int(counts["likely_real"] or 0),
        "by_tool":     by_tool,
        "evidence":    evidence,
        "group_total": group_total,
        "shown":       len(evidence),
        "summary":     summary,
        "summary_is_ai": bool(summary),
        # Falls back to the rule-based text, so a report is never summary-less.
        "fallback_summary": build_findings_summary(
            total, int(counts["likely_real"] or 0), int(counts["likely_noise"] or 0),
            evidence[0] if evidence else None),
        "generated_at": datetime.now(),
    }


@app.route('/api/summary/<int:repo_id>')
def api_summary(repo_id):
    """The plain-English summary for one repo, for the detail page to poll.

    Exists because the summary is written after the scan finishes: the
    visitor reaches the results page immediately and this fills the
    paragraph in when the model is done, instead of holding the whole scan
    open for 20-60s of CPU generation.

    status is one of pending / done / unavailable. "unavailable" is a normal
    outcome, not an error, and tells the page to stop polling and keep the
    rule-based summary it already rendered.
    """
    db     = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("""SELECT llm_summary, llm_summary_status
                          FROM risk_scores WHERE repo_id = %s
                          ORDER BY id DESC LIMIT 1""", (repo_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"status": "unavailable", "summary": None}), 404

        summary = row["llm_summary"]
        status  = row["llm_summary_status"]
        if summary:
            status = "done"
        elif status != "pending":
            # NULL (a pre-column row) or an explicit "unavailable".
            status = "unavailable"
        return jsonify({"status": status, "summary": summary})
    finally:
        cursor.close()
        db.close()


@app.route('/report/<int:repo_id>')
def report(repo_id):
    """The report as a page, with a download section at the top.

    Deliberately a document rather than another app page: it extends no
    base template and carries its own styles, because the same file is what
    WeasyPrint renders into the PDF and an external stylesheet or any
    JavaScript would not survive that trip.
    """
    db     = get_db()
    cursor = db.cursor()
    try:
        ctx = _report_context(cursor, repo_id)
        if not ctx:
            return redirect(url_for('index'))
        return render_template('report.html', for_pdf=False, **ctx)
    finally:
        cursor.close()
        db.close()


@app.route('/report/<int:repo_id>.pdf')
def report_pdf(repo_id):
    """The same document as a PDF attachment.

    Rendered from the identical template and context as /report/<id>, so the
    file someone sends cannot say something different from the page they
    checked before sending it. for_pdf hides the download controls, which
    would otherwise print as dead buttons.
    """
    db     = get_db()
    cursor = db.cursor()
    try:
        ctx = _report_context(cursor, repo_id)
        if not ctx:
            return redirect(url_for('index'))
        html = render_template('report.html', for_pdf=True, **ctx)
        slug = f"{ctx['repo']['owner']}-{ctx['repo']['repo_name']}"
    finally:
        cursor.close()
        db.close()

    try:
        # Imported here, not at module scope: WeasyPrint pulls in cairo and
        # pango through cffi, and the whole app should still start on a box
        # where those are missing -- only this one route needs to fail.
        from weasyprint import HTML
    except Exception as e:
        app.logger.error("WeasyPrint unavailable: %s", e)
        return ("PDF export is unavailable on this server: WeasyPrint or its "
                "system libraries (cairo, pango) are not installed. The report "
                "page itself still works, and a browser can print it to PDF.", 503)

    # base_url lets any relative asset resolve against the app root. Nothing
    # in the template needs it today, but a logo added later would silently
    # vanish from the PDF without it.
    pdf = HTML(string=html, base_url=request.url_root).write_pdf()
    filename = f"MalDet-{slug}-{ctx['generated_at']:%Y-%m-%d}.pdf"
    return Response(pdf, mimetype="application/pdf", headers={
        # inline, not attachment: the point of the download section is that
        # the file was previewed first, so opening it in the viewer is the
        # friendlier default. The link carries `download` for saving.
        "Content-Disposition": f'inline; filename="{filename}"',
    })


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

        cursor.execute("""
            SELECT tool, COUNT(*) AS total
            FROM scan_results
            WHERE repo_id = %s
            GROUP BY tool
        """, (repo_id,))
        tool_totals = {row['tool']: row['total'] for row in cursor.fetchall()}

        # Aggregated over ALL findings (not just the capped set below), so
        # the summary stays accurate even for repos with 100K+ findings.
        cursor.execute("""
            SELECT
                COUNT(*) AS total,
                SUM(confidence >= %s) AS likely_real,
                SUM(confidence < %s) AS likely_noise
            FROM scan_results WHERE repo_id = %s
        """, (SUMMARY_REAL_THRESHOLD, SUMMARY_NOISE_THRESHOLD, repo_id))
        summary_counts = cursor.fetchone()

        cursor.execute(f"""
            SELECT * FROM (
                SELECT *, ROW_NUMBER() OVER (
                    PARTITION BY tool
                    ORDER BY {SEVERITY_RANK} DESC, confidence DESC, id ASC
                ) AS rn
                FROM scan_results
                WHERE repo_id = %s
            ) ranked
            WHERE rn <= %s
            ORDER BY {SEVERITY_RANK} DESC, confidence DESC, tool ASC
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

        # findings[0], if present, is already the globally highest
        # severity+confidence finding (that's what the ORDER BY above sorts
        # for), so no extra query needed to find the "most notable" one.
        findings_summary = build_findings_summary(
            total       = summary_counts["total"],
            likely_real = int(summary_counts["likely_real"] or 0),
            likely_noise = int(summary_counts["likely_noise"] or 0),
            top_finding = findings[0] if findings else None,
        )

        # The LLM summary is written once at scan time and stored, because
        # CPU-only generation takes tens of seconds and this page is
        # refreshed freely. It is absent for every repo scanned before the
        # column existed, and whenever Ollama wasn't running, so the
        # rule-based summary above stays the fallback rather than being
        # replaced. Template shows one or the other, never both.
        llm_summary_text = (risk or {}).get("llm_summary")
        # "pending" means the worker is generating it right now, so the page
        # shows a placeholder and polls. Any other value -- including NULL on
        # rows from before the column existed -- means stop waiting.
        llm_pending = (risk or {}).get("llm_summary_status") == "pending" \
                      and not llm_summary_text

        return render_template('detail.html',
            llm_summary   = llm_summary_text,
            llm_pending   = llm_pending,
            repo          = repo,
            risk          = risk,
            findings      = findings,
            tools         = tools,
            tool_totals   = tool_totals,
            findings_summary = findings_summary,
            # Over ALL findings, not the per-tool capped list, so the
            # overview panel matches the summary text.
            finding_counts = {
                "total":        summary_counts["total"] or 0,
                "likely_real":  int(summary_counts["likely_real"] or 0),
                "likely_noise": int(summary_counts["likely_noise"] or 0),
            },
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
                rs.vuln_score, rs.vuln_level,
                rs.malware_score, rs.malware_level,
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
    own_job_id = _visitor_job_id()
    if own_job_id:
        return _redirect_to_job(own_job_id)

    job_id = _start_scan_job(repo_slug, "infected")
    return _redirect_to_job(job_id)


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
    #
    # debug and host both default to the safe option and are opt-in by env
    # var. debug=True serves the Werkzeug debugger, which is an arbitrary
    # code execution path for anyone who can reach the port; combined with
    # host='0.0.0.0' (bind every interface) that exposed this machine to the
    # whole local network. Worth noting for the writeup: Bandit flags exactly
    # this pattern, but that rule sits in scanner.py's NOISE_RULES, so
    # scanning this repo with MalDet itself would not have caught it.
    #
    # use_reloader stays off even in debug: it restarts the process on every
    # .py save. Job state now survives that (it is in scan_jobs), but a
    # reload still drops in-flight requests for no benefit here.
    # Run the scan worker inline, so `python3 app.py` alone is a working
    # install. Without this the site comes up, accepts scans, and then never
    # runs them -- a silent failure that only makes sense once you know a
    # second process exists.
    #
    # This block is reached only by `python3 app.py`. Under gunicorn the
    # module is imported rather than executed, so the inline worker never
    # starts there -- which is the point: two gunicorn workers would
    # otherwise mean two concurrent scans, and two semgreps (~2GB each) do
    # not fit the 4GB deployment target. Production keeps worker.py as its
    # own single process.
    #
    # Set MALDET_INLINE_WORKER=0 to turn it off, which is what you want if
    # you are also running worker.py by hand -- two workers cannot scan at
    # once (claim_next holds a row lock) but the second is just a wasted
    # poller. recover=False for the same reason: failing every 'running' job
    # is right when starting the one true worker, and wrong if another
    # worker is mid-scan.
    if os.environ.get("MALDET_INLINE_WORKER", "1").lower() not in ("0", "false", "no"):
        import threading
        import worker
        threading.Thread(
            target=lambda: worker.run_forever(recover=False, label="inline worker"),
            daemon=True,
        ).start()

    debug = os.environ.get("MALDET_DEBUG", "").lower() in ("1", "true", "yes")
    app.run(
        host=os.environ.get("MALDET_HOST", "127.0.0.1"),
        port=int(os.environ.get("MALDET_PORT", "5000")),
        debug=debug,
        use_reloader=False,
        threaded=True
    )
import json
import mimetypes
import os
import re
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify, Response
import pymysql
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME
from db_connect import DB_PORT
from scanner import scan_repo
import job_queue

app = Flask(__name__)

# Firefox offers to *install* an add-on only when it arrives as
# application/x-xpinstall. Python's mimetypes table has no entry for .xpi,
# so without this Flask serves it as a generic download and the one-click
# install silently becomes "a file appeared in your Downloads folder".
mimetypes.add_type("application/x-xpinstall", ".xpi")

# Behind a reverse proxy, the scheme and host Flask sees are the proxy's
# (http, 127.0.0.1:5000) rather than the visitor's (https, maldet-fyp.my).
# url_for(..., _external=True) would then build links to an address nobody
# can reach -- and the browser extension consumes those URLs directly, so a
# wrong one is not cosmetic.
#
# Opt-in rather than always on: X-Forwarded-* headers are set by whoever
# connects, so trusting them while the app is also reachable directly lets
# any visitor claim any host or scheme. Safe only when the only thing that
# can reach this port is the proxy -- which is what MALDET_BIND=127.0.0.1
# arranges.
if os.environ.get("MALDET_TRUST_PROXY") == "1":
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

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


# A scan is a snapshot, and repositories keep changing after one. Past this
# many days the extension marks a stored result as stale rather than letting
# it read as a current verdict.
STALE_AFTER_DAYS = 30

# GitHub's own naming rules. Owners are alphanumeric and hyphens only, no
# leading or trailing hyphen, 39 characters at most; repository names also
# allow dots and underscores but cannot be "." or "..". Checked against the
# whole corpus before tightening: 0 of 181 stored repos are rejected.
#
# The point is not injection -- the lookup query is parameterised and
# clone_repo() flattens slashes -- it is that "../.." would otherwise parse
# as a repository, be echoed back, and be offered to the scan form as
# something worth cloning.
_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_NAME_RE  = re.compile(r"^(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$")


def extension_info():
    """Version, build date and sizes of the downloadable extension bundles.

    Written by extension/package.py during the build and read per request
    rather than at import, so a rebuild does not need a restart to show.
    Returns None when the files are absent -- a checkout that has never run
    build.sh is a normal state, and the download section simply does not
    render rather than the home page failing.
    """
    path = os.path.join(app.static_folder, "downloads", "extension-info.json")
    try:
        with open(path) as fh:
            info = json.load(fh)
    except (OSError, ValueError):
        return None
    for target, meta in info.get("files", {}).items():
        full = os.path.join(app.static_folder, "downloads", meta["name"])
        if not os.path.exists(full):
            return None
        meta["kb"] = round(meta["bytes"] / 1024)

    # A Mozilla-signed build, if one has been dropped in. Detected on disk
    # rather than recorded by the build, because signing happens at AMO
    # long after build.sh has run -- the file simply appears. Its presence
    # is what promotes the page from "download and load it by hand" to a
    # one-click install.
    signed = os.path.join(app.static_folder, "downloads", "maldet-firefox.xpi")
    if os.path.exists(signed):
        info["signed"] = {
            "name": "maldet-firefox.xpi",
            "kb":   round(os.path.getsize(signed) / 1024),
        }
    return info


def parse_repo_slug(raw):
    """"owner/repo" from whatever form it arrived in, or None.

    Accepts a full URL, a bare github.com path, or the short owner/repo
    form. Returns None rather than raising so each caller can word its own
    error -- the scan form renders it next to the field, the extension
    lookup returns JSON.

    One parser, two callers, deliberately: an extension that disagreed with
    the form about what counts as a repository would queue scans for
    something the visitor never asked for.
    """
    if not raw:
        return None
    text = raw.strip()
    for prefix in ("https://", "http://", "www.", "github.com/"):
        text = text.replace(prefix, "")
    parts = [p for p in text.strip("/").split("/") if p]
    if len(parts) < 2:
        return None
    owner, name = parts[0], parts[1]
    if name.endswith(".git"):
        name = name[:-4]
    if not _OWNER_RE.match(owner) or not _NAME_RE.match(name):
        return None
    return f"{owner}/{name}"


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
            active_job_id  = _visitor_job_id(),
            # None when build.sh has never run; the template skips the
            # download section rather than offering a link to nothing.
            extension      = extension_info()
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
        # ?repo=owner/name prefills the field. The browser extension links
        # here rather than submitting for you: a GET that starts a scan is
        # the same mistake /rescan/<id> already makes, and crawlers and chat
        # link previews follow GET links. Prefilled, one click, no surprise
        # scans queued by a link unfurler.
        return render_template('scan.html',
                               prefill_repo=parse_repo_slug(request.args.get('repo')) or '')

    # POST — user submitted the scan form
    repo_url         = request.form.get('repo_url', '').strip()
    archive_password = request.form.get('archive_password', 'infected').strip()

    if not repo_url:
        return render_template('scan.html', error="Please enter a GitHub URL")

    repo = parse_repo_slug(repo_url)
    if not repo:
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
        # Imported here, not at module scope: WeasyPrint dlopens Pango and
        # friends through cffi, and the whole app should still start on a box
        # where those are missing -- only this one route needs to fail.
        from weasyprint import HTML
    except Exception as e:
        app.logger.error("WeasyPrint unavailable: %s", e)
        return ("PDF export is unavailable on this server: WeasyPrint or its "
                "system libraries (libpango-1.0-0, libpangoft2-1.0-0) are not "
                "installed. The report page itself still works, and a browser "
                "can print it to PDF.", 503)

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


# Browser extension API
#
# One read-only endpoint, separate from the /api routes the site's own pages
# poll, because this one is called cross-origin and therefore carries a CORS
# header. Keeping it on its own route means that header is never attached to
# anything that changes state -- /scan in particular.


@app.route('/api/extension/lookup')
def api_extension_lookup():
    """Has this repository been scanned, and how long ago?

    The extension asks before deciding what to show and where to link.

    The risk figures are here for the extension's *popup*, which a visitor
    opens deliberately. The in-page button still shows only when the repo
    was last scanned: a verdict pinned onto github.com unasked would be read
    as GitHub's own, and a number with no page around it invites being
    quoted without the findings that produced it. Asked for is different
    from imposed, which is the whole distinction this endpoint serves.
    """
    repo = parse_repo_slug(request.args.get('repo'))
    if not repo:
        return _cors_json({"error": "pass ?repo=owner/name"}, 400)

    owner, name = repo.split("/", 1)

    db     = get_db()
    cursor = db.cursor()
    try:
        # Newest first: dedupe_repositories.py exists because duplicates have
        # happened, and the freshest scan is the one worth reporting.
        cursor.execute("""
            SELECT r.id, r.owner, r.repo_name, r.scanned_at, r.source_status,
                   r.stars, r.language, r.last_pushed,
                   rs.risk_level, rs.final_score,
                   rs.vuln_level, rs.vuln_score,
                   rs.malware_level, rs.malware_score,
                   rs.high_count, rs.medium_count, rs.low_count
            FROM repositories r
            LEFT JOIN risk_scores rs ON rs.repo_id = r.id
            WHERE r.owner = %s AND r.repo_name = %s
            ORDER BY r.scanned_at DESC
            LIMIT 1
        """, (owner, name))
        row = cursor.fetchone()
    finally:
        cursor.close()
        db.close()

    if not row:
        return _cors_json({
            "known":    False,
            "repo":     repo,
            "scan_url": url_for('scan', repo=repo, _external=True),
        })

    scanned_at = row["scanned_at"]
    days = (datetime.now() - scanned_at).days if scanned_at else None

    return _cors_json({
        "known":            True,
        "repo":             f"{row['owner']}/{row['repo_name']}",
        "repo_id":          row["id"],
        "scanned_at":       scanned_at.isoformat() if scanned_at else None,
        "scanned_at_human": scanned_at.strftime("%d %b %Y") if scanned_at else None,
        "days_since_scan":  days,
        # Unknown age is treated as stale: a result we cannot date is exactly
        # the kind the visitor should not read as current.
        "stale":            True if days is None else days > STALE_AFTER_DAYS,
        # NULL, 'gone' or 'renamed' — the extension repeats the warning the
        # detail page gives, instead of linking to findings that can no
        # longer be refreshed as though they were live.
        "source_status":    row["source_status"],
        "detail_url":       url_for('detail', repo_id=row["id"], _external=True),
        "rescan_hint":      "Open the report and use Rescan for current results.",

        # What the repository is, as GitHub described it at scan time.
        # last_pushed is recorded during the scan, so it can never postdate
        # scanned_at -- it says how active the project was, not whether it
        # has changed since. Measured across the corpus: 0 of 181 rows have
        # last_pushed after scanned_at, which is why it is not used as a
        # staleness signal.
        "meta": {
            "stars":             row["stars"],
            "language":          row["language"],
            "last_pushed":       row["last_pushed"].isoformat() if row["last_pushed"] else None,
            "last_pushed_human": row["last_pushed"].strftime("%d %b %Y") if row["last_pushed"] else None,
        },

        # LEFT JOIN above, so a repository row can exist without a score --
        # a scan that died partway leaves exactly that. None here rather
        # than a zero, which would read as "checked, nothing found".
        "risk": None if row["risk_level"] is None else {
            "level":         row["risk_level"],
            "score":         float(row["final_score"]) if row["final_score"] is not None else None,
            # The two tracks are the point: 'badly written' and 'hostile'
            # are different questions and MalDet answers them separately.
            "vuln_level":    row["vuln_level"],
            "vuln_score":    float(row["vuln_score"]) if row["vuln_score"] is not None else None,
            "malware_level": row["malware_level"],
            "malware_score": float(row["malware_score"]) if row["malware_score"] is not None else None,
            "high":          row["high_count"],
            "medium":        row["medium_count"],
            "low":           row["low_count"],
        },
    })


def _cors_json(payload, status=200):
    """JSON with the one header that lets an extension read it.

    `*` rather than an echoed Origin on purpose: extension background
    workers have been reported to send `Origin: null`, which an echo would
    turn into a refusal. Safe here because the endpoint is read-only, sends
    no cookies, and returns data the site already shows publicly.
    """
    resp = jsonify(payload)
    resp.status_code = status
    resp.headers["Access-Control-Allow-Origin"] = "*"
    # Staleness is the whole point of the response, so never let an
    # intermediary serve yesterday's answer.
    resp.headers["Cache-Control"] = "no-store"
    return resp


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
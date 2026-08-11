import json
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
            repos    = repos,
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

        repo = f"{parts[0]}/{parts[1]}"

    except Exception:
        return render_template('scan.html',
            error="Invalid GitHub URL. Example: https://github.com/owner/repo")

    # Run the scan
    try:
        result = scan_repo(repo, archive_password)
        return redirect(url_for('detail', repo_id=result['repo_id']))

    except Exception as e:
        return render_template('scan.html', error=f"Scan failed: {str(e)}")

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

        # Get risk score
        cursor.execute("""
            SELECT * FROM risk_scores WHERE repo_id = %s
            ORDER BY created_at DESC LIMIT 1
        """, (repo_id,))
        risk = cursor.fetchone()

        # Get all findings grouped by tool
        cursor.execute("""
            SELECT * FROM scan_results
            WHERE repo_id = %s
            ORDER BY severity DESC, tool ASC
        """, (repo_id,))
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
    try:
        result = scan_repo(repo_slug)
        return redirect(url_for('detail', repo_id=result['repo_id']))
    except Exception as e:
        return f"Rescan failed: {str(e)}", 500


#API scan status

@app.route('/api/results/<int:repo_id>')
def api_results(repo_id):
    db     = get_db()
    cursor = db.cursor()

    try:
        cursor.execute("""
            SELECT * FROM risk_scores WHERE repo_id = %s
            ORDER BY created_at DESC LIMIT 1
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
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )
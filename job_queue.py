"""
Persistent scan queue, backed by the `scan_jobs` table.

Replaces app.py's in-memory SCANS dict. That dict was the right call while
MalDet was a single-user local tool -- its own comment said so -- but it has
three properties that break on a public deployment:

  * it dies with the process, so a restart strands every in-flight scan;
  * it is per-process, so with more than one web worker a visitor polling
    for status may hit a worker that has never heard of their job;
  * it has no notion of waiting, so a second visitor is turned away rather
    than queued behind the first.

The table fixes all three, and the single-consumer rule below fixes a fourth
problem that is specific to this project's hardware: semgrep peaks near 2GB
and clamscan near 1GB, so two simultaneous scans do not fit in a 4GB VPS.
Only one worker process consumes this queue, so scans serialise and peak
memory stays flat no matter how many people submit at once.

MySQL is used rather than Redis/Celery on purpose: the database is already
running, and a broker would cost memory this deployment cannot spare.
"""

import uuid
from datetime import datetime

import pymysql
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME

# Stages the worker reports; anything scan_repo emits passes through as-is.
STAGE_QUEUED = "Queued"


def get_db():
    return pymysql.connect(
        host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor, autocommit=True,
    )


def enqueue(repo, archive_password):
    """Add a job and return its id. Never runs anything itself."""
    job_id = uuid.uuid4().hex
    db = get_db()
    try:
        db.cursor().execute(
            """INSERT INTO scan_jobs (id, repo, archive_password, status, stage, queued_at)
               VALUES (%s, %s, %s, 'queued', %s, %s)""",
            (job_id, repo, archive_password, STAGE_QUEUED, datetime.now()))
    finally:
        db.close()
    return job_id


def get_job(job_id):
    db = get_db()
    try:
        c = db.cursor()
        c.execute("SELECT * FROM scan_jobs WHERE id=%s", (job_id,))
        return c.fetchone()
    finally:
        db.close()


def queue_position(job_id):
    """How many jobs are ahead of this one. 0 once it is running or finished.

    Counts anything still waiting that was queued earlier, plus the job
    currently running, so the number matches what the visitor is waiting for
    rather than just their place in the waiting list.
    """
    db = get_db()
    try:
        c = db.cursor()
        c.execute("SELECT status, queued_at FROM scan_jobs WHERE id=%s", (job_id,))
        job = c.fetchone()
        if not job or job["status"] != "queued":
            return 0
        c.execute("""SELECT COUNT(*) AS n FROM scan_jobs
                     WHERE status='running'
                        OR (status='queued' AND queued_at < %s)""", (job["queued_at"],))
        return int(c.fetchone()["n"])
    finally:
        db.close()


def claim_next():
    """Atomically take the oldest waiting job, or None.

    Returns None while another job is running: this is the single-consumer
    rule that keeps two semgrep processes from ever overlapping. The check
    and the claim share one transaction with FOR UPDATE, so a second worker
    started by accident still cannot claim alongside the first.
    """
    db = get_db()
    db.autocommit(False)
    try:
        c = db.cursor()
        c.execute("SELECT COUNT(*) AS n FROM scan_jobs WHERE status='running' FOR UPDATE")
        if int(c.fetchone()["n"]) > 0:
            db.rollback()
            return None

        c.execute("""SELECT * FROM scan_jobs WHERE status='queued'
                     ORDER BY queued_at LIMIT 1 FOR UPDATE""")
        job = c.fetchone()
        if not job:
            db.rollback()
            return None

        c.execute("""UPDATE scan_jobs SET status='running', stage='Starting',
                     started_at=%s WHERE id=%s""", (datetime.now(), job["id"]))
        db.commit()
        job["status"], job["stage"] = "running", "Starting"
        return job
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def set_stage(job_id, stage):
    db = get_db()
    try:
        db.cursor().execute("UPDATE scan_jobs SET stage=%s WHERE id=%s", (stage, job_id))
    finally:
        db.close()


def finish(job_id, repo_id):
    db = get_db()
    try:
        db.cursor().execute(
            """UPDATE scan_jobs SET status='done', stage='Done', repo_id=%s,
               finished_at=%s WHERE id=%s""", (repo_id, datetime.now(), job_id))
    finally:
        db.close()


def fail(job_id, message):
    db = get_db()
    try:
        db.cursor().execute(
            """UPDATE scan_jobs SET status='error', stage='Failed', error=%s,
               finished_at=%s WHERE id=%s""",
            (str(message)[:2000], datetime.now(), job_id))
    finally:
        db.close()


def recover_stale():
    """Fail jobs left 'running' by a worker that died, and report how many.

    Without this a crashed worker blocks the queue forever: claim_next()
    would see a running job that no process is working on and refuse to
    start anything else. Called once at worker startup -- safe because only
    one worker runs, so a 'running' row at that moment is always orphaned.
    """
    db = get_db()
    try:
        c = db.cursor()
        c.execute("""UPDATE scan_jobs SET status='error', stage='Failed',
                     error='Worker stopped before this scan finished',
                     finished_at=%s WHERE status='running'""", (datetime.now(),))
        return c.rowcount
    finally:
        db.close()

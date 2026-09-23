-- MalDet schema
-- Reflects the live production schema (dumped 2026-08-18) — not a redesign.
-- Source of truth for a fresh DB setup. Keep in sync with the queries in
-- app.py and scanner.py whenever either changes.
--
-- Notes on quirks preserved from the live schema (don't "fix" without a
-- migration plan, since 196+ rows already depend on this shape):
--   - risk_scores and scan_results have no created_at/timestamp column.
--     app.py's detail() route orders risk_scores by `id DESC` (not
--     created_at) to get the latest row for a repo — do not add an
--     ORDER BY created_at query against risk_scores without adding the
--     column via a migration first.

CREATE TABLE IF NOT EXISTS repositories (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    repo_name    VARCHAR(255),
    owner        VARCHAR(255),
    language     VARCHAR(100),
    stars        INT,
    last_pushed  DATETIME,
    scanned_at   TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    -- Without this, save_to_db()'s upsert (INSERT ... ON DUPLICATE KEY
    -- UPDATE) can't detect an existing repo at all, and every scan inserts
    -- a new row — this is exactly the bug that produced ~45 duplicate
    -- rows in production (one repo scanned 14 times under 14 different
    -- ids) before this constraint was added.
    UNIQUE KEY uq_repositories_owner_name (owner, repo_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS risk_scores (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    repo_id       INT,
    -- high_count/medium_count/low_count/final_score/risk_level are the
    -- blended "overall" figure across ALL tools — kept only so
    -- scan_history's trend line has continuity with older scans. The UI
    -- does NOT show this as the headline number: Bandit/Semgrep (coding
    -- vulnerabilities an attacker could exploit) and YARA/ClamAV/
    -- dep_checker (patterns suggesting the code itself is malicious) are
    -- different threat models, so they're scored and shown separately
    -- below instead of blended into one misleading number.
    high_count    INT DEFAULT 0,
    medium_count  INT DEFAULT 0,
    low_count     INT DEFAULT 0,
    final_score   FLOAT DEFAULT 0,
    risk_level    VARCHAR(20),
    -- Vulnerability axis: bandit + semgrep only
    vuln_high     INT NULL,
    vuln_medium   INT NULL,
    vuln_low      INT NULL,
    vuln_score    FLOAT NULL,
    vuln_level    VARCHAR(20) NULL,
    -- Malicious-pattern axis: yara + clamav + dep_checker
    malware_high    INT NULL,
    malware_medium  INT NULL,
    malware_low     INT NULL,
    malware_score   FLOAT NULL,
    malware_level   VARCHAR(20) NULL,
    -- Plain-English summary written by a local LLM (llm_summary.py) at scan
    -- time, so the cost is paid once per scan rather than on every page view
    -- — CPU-only generation takes tens of seconds. NULL whenever Ollama was
    -- unavailable, disabled, or the repo predates this column; app.py then
    -- falls back to the rule-based build_findings_summary().
    llm_summary     TEXT NULL,
    FOREIGN KEY (repo_id) REFERENCES repositories(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS scan_history (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    repo_id      INT NOT NULL,
    scanned_at   TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    risk_level   VARCHAR(20),
    final_score  INT,
    FOREIGN KEY (repo_id) REFERENCES repositories(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS scan_results (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    repo_id       INT,
    tool          VARCHAR(50),
    severity      VARCHAR(20),
    -- P(this finding is real, not noise) per train_classifier.py's FP
    -- classifier. NULL for rows scanned before this column was added.
    confidence    FLOAT NULL,
    issue_text    TEXT,
    filename      VARCHAR(500),
    line_number   INT DEFAULT 0,
    code_snippet  TEXT,
    FOREIGN KEY (repo_id) REFERENCES repositories(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


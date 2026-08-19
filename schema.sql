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
    scanned_at   TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS risk_scores (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    repo_id       INT,
    high_count    INT DEFAULT 0,
    medium_count  INT DEFAULT 0,
    low_count     INT DEFAULT 0,
    final_score   FLOAT DEFAULT 0,
    risk_level    VARCHAR(20),
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
    issue_text    TEXT,
    filename      VARCHAR(500),
    line_number   INT DEFAULT 0,
    code_snippet  TEXT,
    FOREIGN KEY (repo_id) REFERENCES repositories(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

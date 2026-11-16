"""What each indicator's threat-intel cell may claim (app._load_iocs).

    python3 -m unittest discover -s tests -t .
"""

import unittest

import app


class FakeCursor:
    def __init__(self, run, rows):
        self._queue = [[run] if run else [], [{"n": len(rows)}], rows]
        self._current = []

    def execute(self, sql, params=None):
        self._current = self._queue.pop(0)

    def fetchone(self):
        return self._current[0] if self._current else None

    def fetchall(self):
        return self._current


def ioc_row(ioc_type, match=None, source=None):
    return {"ioc_type": ioc_type, "value": "v", "file_path": "/a", "file_count": 1,
            "first_seen": None, "ti_match": match, "ti_source": source}


def load(ti_status, rows):
    run = {"scan_id": 1, "status": "done", "ti_status": ti_status, "note": None}
    return app._load_iocs(FakeCursor(run, rows), 1)


class RowStates(unittest.TestCase):
    def test_each_state(self):
        out = load("done", [
            ioc_row("domain", "FakeBot (botnet_cc)", "ThreatFox"),
            ioc_row("domain", None, "ThreatFox"),
            ioc_row("btc_wallet"),
            ioc_row("ipv4"),
        ])
        self.assertEqual([r["ti_state"] for r in out["rows"]],
                         ["hit", "clear", "na", "unchecked"])
        self.assertEqual(out["ti_unchecked"], 1)

    def test_scan_from_before_rows_recorded_a_source(self):
        """Hashes and URLs of a finished older run were looked up; its
        domains and IPs never were, and must not read "No match"."""
        out = load("done", [ioc_row("sha256"), ioc_row("url"), ioc_row("domain"), ioc_row("ipv4")])
        self.assertEqual([r["ti_state"] for r in out["rows"]],
                         ["clear", "clear", "unchecked", "unchecked"])

    def test_partial_run_only_clears_rows_that_were_answered(self):
        out = load("partial", [ioc_row("url", None, "URLhaus"), ioc_row("url")])
        self.assertEqual([r["ti_state"] for r in out["rows"]], ["clear", "unchecked"])

    def test_lookups_off_clears_nothing(self):
        out = load("off", [ioc_row("sha256"), ioc_row("url")])
        self.assertEqual([r["ti_state"] for r in out["rows"]], ["unchecked", "unchecked"])

    def test_no_run_at_all(self):
        out = app._load_iocs(FakeCursor(None, []), 1)
        self.assertEqual((out["state"], out["ti_unchecked"]), ("none", 0))


if __name__ == "__main__":
    unittest.main()

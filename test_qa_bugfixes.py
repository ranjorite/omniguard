"""QA Regression & Bug-Fix Sign-Off Suite (BUG-01 through BUG-04 + Baseline Regression)."""
import re
import tempfile
import threading
import unittest
import urllib.request
from http.server import HTTPServer
from pathlib import Path

import ingest_breach_test
import langgraph_audit
import test_portal


class TestQABugFixes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.TemporaryDirectory()
        cls.log_path = Path(cls.tmp_dir.name) / "portal_events.jsonl"
        cls.test_db = Path(cls.tmp_dir.name) / "omniguard_purple_test.rl"

        cls.orig_log = test_portal.LOG_FILE
        test_portal.LOG_FILE = str(cls.log_path)

        cls.server = HTTPServer(("127.0.0.1", 0), test_portal.PortalHandler)
        cls.base_url = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

        # Run simulated Agniveer-style breach
        html = urllib.request.urlopen(f"{cls.base_url}/", timeout=5).read().decode("utf-8")
        leaked_path = re.search(r"debug_export=([^\s]+)", html).group(1)
        urllib.request.urlopen(f"{cls.base_url}{leaked_path}", timeout=5).read()

        ingest_breach_test.ingest_events_to_test_graph(cls.log_path, cls.test_db)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        test_portal.LOG_FILE = cls.orig_log
        cls.tmp_dir.cleanup()

    def _run_query(self, db_path: Path, query: str):
        orig_db = langgraph_audit.DB_PATH
        langgraph_audit.DB_PATH = db_path
        try:
            app = langgraph_audit.build_audit_graph()
            return app.invoke(
                {"user_query": query, "history": []},
                config={"configurable": {"thread_id": f"qa-{abs(hash(query))}"}},
            )
        finally:
            langgraph_audit.DB_PATH = orig_db

    def test_bug01_source_system_isolation_no_cross_system_noise(self):
        res = self._run_query(self.test_db, "Which collector and controls flagged the staging portal breach?")
        all_citations = [c for f in res["findings"] for c in f["citations"]]
        self.assertGreater(len(all_citations), 0, "Expected staging portal citations")
        systems = {c["source_system"] for c in all_citations}
        self.assertEqual(systems, {"StagingCareerPortal"}, f"BUG-01 FAILED: cross-system noise found: {systems}")

    def test_bug02_owasp_and_cdmc_surfaced(self):
        res = self._run_query(
            self.test_db,
            "Were any hardcoded staging admin credentials exposed or used for bulk PII exports?",
        )
        lenses = {f["lens"] for f in res["findings"]}
        self.assertIn("OWASP", lenses, f"BUG-02 FAILED: OWASP lens missing from {lenses}")
        self.assertIn("CDMC", lenses, f"BUG-02 FAILED: CDMC lens missing from {lenses}")
        controls = {c["control_code"] for f in res["findings"] for c in f["citations"]}
        self.assertIn("OWASP-2025-A02", controls)
        self.assertIn("CDMC-04", controls)

    def test_bug03_and_bug04_causal_kill_chain_surfaces_root_cause(self):
        res = self._run_query(
            self.test_db,
            "Were any hardcoded staging admin credentials exposed or used for bulk PII exports?",
        )
        usage_ids = {c["usage_id"] for f in res["findings"] for c in f["citations"]}
        self.assertIn("BREACH_SIM_02", usage_ids, "Expected bulk exfiltration event BREACH_SIM_02")
        self.assertIn("BREACH_SIM_01", usage_ids, "BUG-03/04 FAILED: root-cause BREACH_SIM_01 was hidden")

    def test_regression_baseline_omniguard_rl_intact(self):
        res = self._run_query(Path("omniguard.rl"), "What about unencrypted card traffic or CVV leaks?")
        usage_ids = {c["usage_id"] for f in res["findings"] for c in f["citations"]}
        self.assertIn("LOG_VIOLATION_01", usage_ids)
        self.assertIn("LOG_VIOLATION_02", usage_ids)


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Automated QA for isolated Relate breach ingestion and OmniGuard evidence retrieval."""
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


class TestBreachIngestionAndGraphQuery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.TemporaryDirectory()
        cls.log_path = Path(cls.tmp_dir.name) / "portal_events.jsonl"
        cls.test_db = Path(cls.tmp_dir.name) / "omniguard_purple_test.rl"

        cls.orig_log = test_portal.LOG_FILE
        test_portal.LOG_FILE = str(cls.log_path)

        cls.server = HTTPServer(("127.0.0.1", 0), test_portal.PaymentPortalHandler)
        cls.base_url = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

        # Execute the simulated breach once to generate telemetry
        html = urllib.request.urlopen(f"{cls.base_url}/", timeout=5).read().decode("utf-8")
        leaked_path = re.search(r"debug_export=([^\s]+)", html).group(1)
        urllib.request.urlopen(f"{cls.base_url}{leaked_path}", timeout=5).read()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        test_portal.LOG_FILE = cls.orig_log
        cls.tmp_dir.cleanup()

    def test_01_ingest_and_verify_graph_evidence(self):
        base_store = Path("omniguard.rl")
        before = (base_store.stat().st_size, base_store.stat().st_mtime_ns)

        count = ingest_breach_test.ingest_events_to_test_graph(self.log_path, self.test_db)
        self.assertEqual(count, 2, "Expected 2 breach events ingested")

        total_events, rows = langgraph_audit._load_graph_evidence(self.test_db)
        self.assertEqual(total_events, 34, "Expected 32 baseline + 2 breach events = 34")

        breach_rows = [r for r in rows if str(r.get("usage_id", "")).startswith("BREACH_SIM_")]
        self.assertGreaterEqual(len(breach_rows), 4, "Expected multi-framework control mappings for breach events")

        controls = {r["control_code"] for r in breach_rows}
        self.assertIn("NIST-800-53-IA-5(7)", controls)
        self.assertIn("OWASP-2025-A02", controls)
        self.assertIn("CDMC-04", controls)
        self.assertIn("NIST-800-53-IA-5", controls)

        # Verify committed omniguard.rl was never touched
        after = (base_store.stat().st_size, base_store.stat().st_mtime_ns)
        self.assertEqual(before, after, "omniguard.rl must remain untouched")


if __name__ == "__main__":
    unittest.main(verbosity=2)

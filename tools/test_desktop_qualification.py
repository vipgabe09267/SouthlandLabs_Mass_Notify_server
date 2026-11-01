#!/usr/bin/python3
"""Exercise the desktop gate against complete and incomplete source layouts."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
COMMON = [
    "test_sls_live_polling",
    "test_sls_delivery_store",
    "test_sls_backend_contract",
    "test_sls_transport_deadlines",
]
MODERN = COMMON + ["test_sls_desktop_compatibility"]
LEGACY = COMMON + ["test_sls_live_poll_cursor", "test_sls_panic", "test_sls_media_auth"]

if (os.environ.get("SLS_TEST_NAMESPACE") != "entered"
        or os.environ.get("SLS_TEST_PARENT_NET_NS") in (None, "", os.readlink("/proc/self/ns/net"))):
    raise SystemExit("Use the isolated fixture runner; no desktop tests were launched.")


class DesktopQualification(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sls-desktop-gate-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "src").mkdir()
        (self.root / "src/sls_mass_notify.py").write_text("# Inert reviewed-source fixture.\n")
        (self.root / "tests").mkdir()
        (self.root / "tests/__init__.py").write_text("")
        self.marker = self.root / "executed.jsonl"

    def source(self, modules):
        for module in modules:
            (self.root / "tests" / (module + ".py")).write_text(
                "import json, os, pathlib, unittest\n"
                "class Consumer(unittest.TestCase):\n"
                " def test_consumer(self):\n"
                "  with open(os.environ['SLS_DESKTOP_QUALIFICATION_MARKER'], 'a') as output:\n"
                "   output.write(json.dumps([__name__, os.getcwd(), os.environ['APPDATA']])+'\\n')\n"
            )

    def run_gate(self, extra_environment=None):
        return subprocess.run(
            [sys.executable, str(ROOT / "tools/test_desktop_app_compat.py")],
            cwd=ROOT,
            env={**os.environ, "SLS_DESKTOP_APP_SOURCE": str(self.root),
                 "SLS_DESKTOP_APP_REQUIRED": "1", "PYTHONDONTWRITEBYTECODE": "1",
                 "SLS_DESKTOP_QUALIFICATION_MARKER": str(self.marker),
                 **(extra_environment or {})},
            capture_output=True, text=True, timeout=20,
        )

    def assert_consumers_ran(self, modules):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        executed = [json.loads(line) for line in self.marker.read_text().splitlines()]
        self.assertEqual({row[0] for row in executed}, {"tests." + name for name in modules})
        self.assertTrue(all(row[1] == str(self.root) for row in executed))
        self.assertTrue(all(row[2] != str(self.root) for row in executed))

    def test_current_consolidated_contract_suite_runs(self):
        self.source(MODERN)
        self.assert_consumers_ran(MODERN)

    def test_legacy_separate_contract_suites_still_run(self):
        self.source(LEGACY)
        self.assert_consumers_ran(LEGACY)

    def test_incomplete_current_layout_fails_before_any_consumer_runs(self):
        self.source([name for name in MODERN if name != "test_sls_backend_contract"])
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("incomplete", (result.stdout + result.stderr).lower())
        self.assertFalse(self.marker.exists())

    def test_incomplete_legacy_layout_fails_before_any_consumer_runs(self):
        self.source([name for name in LEGACY if name != "test_sls_media_auth"])
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("incomplete", (result.stdout + result.stderr).lower())
        self.assertFalse(self.marker.exists())

    def test_explicit_reviewed_client_interpreter_is_used(self):
        self.source(MODERN)
        marker = self.root / "interpreter-used"
        launcher = self.root / "reviewed-python"
        launcher.write_text(
            "#!" + sys.executable + "\nimport os, pathlib, sys\n"
            + "pathlib.Path(" + repr(str(marker)) + ").write_text('used')\n"
            + "os.execve(sys.executable, [sys.executable, *sys.argv[1:]], os.environ)\n"
        )
        launcher.chmod(0o755)
        result = self.run_gate({"SLS_DESKTOP_PYTHON": str(launcher)})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(marker.exists())

    def test_unavailable_client_interpreter_fails_before_tests(self):
        self.source(MODERN)
        result = self.run_gate({"SLS_DESKTOP_PYTHON": str(self.root / "missing-python")})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.marker.exists())


if __name__ == "__main__":
    unittest.main()

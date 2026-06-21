import unittest
from unittest.mock import patch

from besecured.checks import common
from besecured.checks.common import (
    CommandResult,
    _windows_netstat_listeners_from_text,
    check_open_ports,
    run_checks,
)
from besecured.models import Finding


class RunChecksTests(unittest.TestCase):
    def test_runs_all_checks_and_flattens_in_order(self):
        checks = [
            ("A", lambda: [Finding("A", "one", "OK", "ok")]),
            ("B", lambda: [Finding("B", "two", "WARN", "warn"), Finding("B", "three", "OK", "ok")]),
        ]
        findings = run_checks(checks, parallel=False)
        self.assertEqual([f.name for f in findings], ["one", "two", "three"])

    def test_a_crashing_check_becomes_a_skip_and_does_not_abort(self):
        def boom() -> list[Finding]:
            raise RuntimeError("kaboom")

        checks = [
            ("Firewall", boom),
            ("Updates", lambda: [Finding("Updates", "ok", "OK", "fine")]),
        ]
        findings = run_checks(checks, parallel=False)

        self.assertEqual(len(findings), 2)
        error = findings[0]
        self.assertEqual(error.category, "Firewall")
        self.assertEqual(error.status, "SKIP")
        self.assertIn("kaboom", error.detail)
        self.assertEqual(findings[1].status, "OK")

    def test_parallel_and_sequential_produce_the_same_findings(self):
        checks = [
            ("A", lambda: [Finding("A", "a", "OK", "ok")]),
            ("B", lambda: [Finding("B", "b", "WARN", "warn")]),
            ("C", lambda: [Finding("C", "c", "CRIT", "crit")]),
        ]
        sequential = run_checks(checks, parallel=False)
        parallel = run_checks(checks, parallel=True)
        self.assertEqual(
            [(f.category, f.name, f.status) for f in sequential],
            [(f.category, f.name, f.status) for f in parallel],
        )


class OpenPortsCheckTests(unittest.TestCase):
    """End-to-end scope -> status mapping in check_open_ports (not just _port_scope)."""

    def test_rdp_on_all_interfaces_is_critical(self):
        text = (
            "  Proto  Local Address          Foreign Address        State           PID\n"
            "  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       4\n"
        )
        listeners = _windows_netstat_listeners_from_text(text)
        with _patched_listeners(listeners):
            findings = check_open_ports()
        rdp = [f for f in findings if "RDP" in f.name]
        self.assertTrue(rdp)
        self.assertEqual(rdp[0].status, "CRIT")

    def test_no_rdp_listening_yields_ok(self):
        text = (
            "  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4\n"
        )
        listeners = _windows_netstat_listeners_from_text(text)
        with _patched_listeners(listeners):
            findings = check_open_ports()
        rdp = [f for f in findings if "RDP" in f.name]
        self.assertTrue(rdp)
        self.assertEqual(rdp[0].status, "OK")


class WmicFallbackTests(unittest.TestCase):
    """wmic is removed on Windows 11 24H2+, so system info must fall back to CIM."""

    def test_ram_total_falls_back_to_cim_when_wmic_is_gone(self):
        with patch.object(common.platform, "system", return_value="Windows"), patch.object(
            common, "run_command", return_value=CommandResult(0, "", "")
        ), patch.object(common, "_powershell_value", return_value="17179869184"):
            self.assertEqual(common._ram_total(), "16.0 GB")

    def test_cpu_name_falls_back_to_cim_when_wmic_is_gone(self):
        with patch.object(common.platform, "system", return_value="Windows"), patch.object(
            common, "run_command", return_value=CommandResult(0, "", "")
        ), patch.object(common, "_powershell_value", return_value="Intel(R) Core(TM) i7-9750H"):
            self.assertEqual(common._cpu_name(), "Intel(R) Core(TM) i7-9750H")

    def test_powershell_value_is_empty_without_a_host(self):
        with patch.object(common.shutil, "which", return_value=None):
            self.assertEqual(common._powershell_value("anything"), "")


class _patched_listeners:
    """Context manager that forces check_open_ports to see a fixed listener list."""

    def __init__(self, listeners):
        self.listeners = listeners
        self._patch = None

    def __enter__(self):
        from unittest.mock import patch

        self._patch = patch(
            "besecured.checks.common._list_listening_ports",
            return_value=self.listeners,
        )
        self._patch.start()
        return self

    def __exit__(self, *exc):
        self._patch.stop()
        return False


class OpenPortsResilienceTests(unittest.TestCase):
    def test_unavailable_source_is_skip(self):
        from besecured.checks.common import CheckUnavailable

        with patch("besecured.checks.common._list_listening_ports", side_effect=CheckUnavailable("no tool")):
            findings = check_open_ports()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "SKIP")

    def test_unexpected_error_is_warn(self):
        with patch("besecured.checks.common._list_listening_ports", side_effect=OSError("boom")):
            findings = check_open_ports()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "WARN")


if __name__ == "__main__":
    unittest.main()

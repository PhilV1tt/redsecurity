import unittest
from unittest.mock import patch

import besecured.checks.macos as macos
from besecured.models import Finding


class MacosDispatchTests(unittest.TestCase):
    """run_macos_checks aggregates its checks, isolates a failing one, and tags
    every finding with the macOS context. All checks are mocked, so this runs
    on any host."""

    def test_dispatch_isolates_failures_and_tags_macos(self):
        def boom():
            raise RuntimeError("nope")

        fakes = dict(
            check_firewall=boom,
            check_updates=lambda: [Finding("Updates", "u", "OK", "ok")],
            check_disk_encryption=lambda: [],
            check_users=lambda: [Finding("User Accounts", "admin", "OK", "ok")],
            check_password_policy=lambda: [],
            check_shared_folders=lambda: [],
            check_startup_programs=lambda: [],
            check_antimalware=lambda: [],
            check_privilege_model=lambda: [Finding("Privilege Elevation", "uac", "INFO", "x")],
        )
        with patch.multiple(macos, **fakes):
            findings = macos.run_macos_checks()

        triples = {(f.category, f.name, f.status) for f in findings}
        self.assertIn(("Firewall", "Check Error", "SKIP"), triples)  # failure isolated
        self.assertIn(("Updates", "u", "OK"), triples)  # siblings survive
        self.assertIn(("User Accounts", "admin", "OK"), triples)
        self.assertTrue(all(f.supported_os == ("macOS",) for f in findings))


if __name__ == "__main__":
    unittest.main()

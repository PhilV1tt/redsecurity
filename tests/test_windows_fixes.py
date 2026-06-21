import unittest
from unittest.mock import patch

from besecured.checks import windows
from besecured.checks.common import CommandResult
from besecured.checks.windows import (
    _enabled_state,
    _firewall_findings_from_payload,
    _powershell_json,
)


class FirewallEnumTests(unittest.TestCase):
    """Get-NetFirewallProfile.Enabled is a GpoBoolean enum (1=on, 2=off), not a
    plain JSON bool, so a disabled profile must not be reported OK."""

    def test_enabled_state_decodes_enum_bool_and_string(self):
        self.assertIs(_enabled_state(1), True)
        self.assertIs(_enabled_state(2), False)
        self.assertIs(_enabled_state(True), True)
        self.assertIs(_enabled_state("False"), False)
        self.assertIsNone(_enabled_state("unexpected"))

    def test_disabled_profile_via_integer_enum_is_critical(self):
        findings = _firewall_findings_from_payload([{"Name": "Public", "Enabled": 2}])
        self.assertEqual(findings[0].status, "CRIT")

    def test_enabled_profile_is_ok(self):
        findings = _firewall_findings_from_payload({"Name": "Domain", "Enabled": 1})
        self.assertEqual(findings[0].status, "OK")

    def test_unparseable_state_is_warn_not_ok(self):
        findings = _firewall_findings_from_payload([{"Name": "Public", "Enabled": "??"}])
        self.assertEqual(findings[0].status, "WARN")

    def test_no_profiles_is_skip(self):
        findings = _firewall_findings_from_payload([])
        self.assertEqual(findings[0].status, "SKIP")


class PowershellJsonTests(unittest.TestCase):
    def test_utf8_bom_prefixed_json_is_parsed(self):
        with patch.object(windows, "_powershell", return_value=CommandResult(0, "﻿{\"Enabled\": true}", "")):
            self.assertEqual(_powershell_json("x"), {"Enabled": True})

    def test_invalid_json_returns_none(self):
        with patch.object(windows, "_powershell", return_value=CommandResult(0, "not json", "")):
            self.assertIsNone(_powershell_json("x"))


class AntivirusAgeTests(unittest.TestCase):
    def test_garbage_signature_age_is_not_rendered_as_a_finding(self):
        payload = {
            "DefenderAvailable": True,
            "AntivirusEnabled": True,
            "RealTimeProtectionEnabled": True,
            "SignatureAgeDays": 739000,  # null timestamp -> absurd age
        }
        with patch.object(windows, "_powershell_available", return_value=True), patch.object(
            windows, "_powershell_json", return_value=payload
        ):
            findings = windows.check_antivirus()
        signature = [f for f in findings if f.name == "Signature Age"]
        self.assertTrue(signature)
        self.assertEqual(signature[0].status, "SKIP")


if __name__ == "__main__":
    unittest.main()

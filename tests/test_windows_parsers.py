import unittest
from unittest.mock import patch

from besecured.checks.windows import (
    _admin_names_from_payload,
    _bitlocker_findings_from_payload,
    _bitlocker_protection_text,
    _guest_enabled_from_users,
    _no_password_users,
    _powershell_skip,
    _share_findings_from_payload,
    _value_after_labels,
    _windows_user_findings_from_payload,
)


class WindowsParserTests(unittest.TestCase):
    def test_guest_detection_uses_sid_not_locale_name(self):
        users = [
            {"Name": "Invite", "SID": "S-1-5-21-1-2-3-501", "Enabled": True, "PasswordRequired": False},
            {"Name": "Phil", "SID": "S-1-5-21-1-2-3-1001", "Enabled": True, "PasswordRequired": True},
        ]

        self.assertTrue(_guest_enabled_from_users(users))
        self.assertEqual(_no_password_users(users), ["Invite"])

    def test_admin_names_from_payload(self):
        payload = {"Admins": {"Name": "PHIL-PC\\Phil", "SID": "S-1-5-21-1-2-3-1001"}}

        self.assertEqual(_admin_names_from_payload(payload), ["PHIL-PC\\Phil"])

    def test_password_policy_parser_accepts_french_labels(self):
        text = """
Longueur minimale du mot de passe        8
Durée maximale du mot de passe (jours)  90
"""

        self.assertEqual(_value_after_labels(text, ["Longueur minimale du mot de passe"]), 8)
        self.assertEqual(_value_after_labels(text, ["Duree maximale du mot de passe"]), 90)

    def test_bitlocker_payload_maps_protection_status(self):
        payload = {
            "Volumes": [
                {"MountPoint": "C:", "ProtectionStatus": "On"},
                {"MountPoint": "D:", "ProtectionStatus": 0},
            ]
        }
        findings = _bitlocker_findings_from_payload(payload)

        self.assertEqual([finding.status for finding in findings], ["OK", "WARN"])
        self.assertEqual(_bitlocker_protection_text(1), "on")
        self.assertEqual(_bitlocker_protection_text("unknown"), "unknown")

    def test_empty_bitlocker_payload_is_skipped(self):
        findings = _bitlocker_findings_from_payload({"Volumes": []})

        self.assertEqual(findings[0].status, "SKIP")

    def test_powershell_missing_returns_skip(self):
        with patch("besecured.checks.windows._powershell_available", return_value=False):
            findings = _powershell_skip("Firewall", "Firewall Check", "Check manually.")

        self.assertEqual(findings[0].status, "SKIP")

    def test_incomplete_windows_user_payload_is_skipped(self):
        findings = _windows_user_findings_from_payload({"UserProbeOk": False, "AdminProbeOk": True, "Users": []})

        self.assertEqual(findings[0].status, "SKIP")

    def test_empty_windows_user_list_is_skipped(self):
        findings = _windows_user_findings_from_payload({"UserProbeOk": True, "AdminProbeOk": True, "Users": []})

        self.assertEqual(findings[0].status, "SKIP")

    def test_empty_windows_admin_list_is_skipped_without_losing_user_checks(self):
        payload = {
            "UserProbeOk": True,
            "AdminProbeOk": True,
            "Users": [{"Name": "Phil", "SID": "S-1-5-21-1-2-3-1001", "Enabled": True, "PasswordRequired": True}],
            "Admins": [],
        }
        findings = _windows_user_findings_from_payload(payload)

        self.assertEqual(findings[0].name, "Admin Accounts")
        self.assertEqual(findings[0].status, "SKIP")
        self.assertEqual(findings[1].name, "Guest Account")
        self.assertEqual(findings[1].status, "OK")

    def test_windows_admin_group_principal_is_counted(self):
        payload = {
            "UserProbeOk": True,
            "AdminProbeOk": True,
            "Users": [{"Name": "Phil", "SID": "S-1-5-21-1-2-3-1001", "Enabled": True, "PasswordRequired": True}],
            "Admins": {"Name": "PHIL-PC\\IT Admins", "SID": "S-1-5-21-1-2-3-2001", "ObjectClass": "Group"},
        }
        findings = _windows_user_findings_from_payload(payload)

        self.assertEqual(findings[0].status, "OK")
        self.assertIn("IT Admins", findings[0].detail)

    def test_share_payload_requires_success_flag(self):
        findings = _share_findings_from_payload({"Shares": []})

        self.assertEqual(findings[0].status, "SKIP")


if __name__ == "__main__":
    unittest.main()

import datetime as dt
import unittest

from besecured.checks.macos import (
    _dedupe,
    _extract_dates,
    _filevault_finding_from_text,
    _gatekeeper_finding_from_text,
    _human_account_names,
    _parse_history_date,
    _pkg_install_time,
    _shared_folder_findings_from_text,
    _sip_finding_from_text,
    _xprotect_receipts,
)


class MacosParserTests(unittest.TestCase):
    def test_extract_dates_accepts_iso_us_and_eu_formats(self):
        text = "31/05/2026\n06/01/2026\n2026-05-30"
        dates = _extract_dates(text)

        self.assertIn(dt.date(2026, 5, 31), dates)
        self.assertIn(dt.date(2026, 5, 30), dates)

    def test_ambiguous_slash_date_uses_newest_non_future_candidate(self):
        parsed = _parse_history_date("01/06/2026", today=dt.date(2026, 6, 5))

        self.assertEqual(parsed, dt.date(2026, 6, 1))

    def test_failed_sharing_query_returns_skip(self):
        findings = _shared_folder_findings_from_text("Shared Folders", "", command_ok=False)

        self.assertEqual(findings[0].status, "SKIP")

    def test_empty_sharing_output_returns_skip(self):
        findings = _shared_folder_findings_from_text("Shared Folders", "", command_ok=True)

        self.assertEqual(findings[0].status, "SKIP")

    def test_filevault_parser(self):
        self.assertEqual(_filevault_finding_from_text("FileVault is On.").status, "OK")
        self.assertEqual(_filevault_finding_from_text("FileVault is Off.").status, "WARN")
        self.assertEqual(_filevault_finding_from_text("").status, "SKIP")

    def test_gatekeeper_and_sip_unknown_are_skipped(self):
        self.assertEqual(_gatekeeper_finding_from_text("assessments enabled").status, "OK")
        self.assertEqual(_gatekeeper_finding_from_text("assessments disabled").status, "CRIT")
        self.assertEqual(_gatekeeper_finding_from_text("").status, "SKIP")
        self.assertEqual(_sip_finding_from_text("System Integrity Protection status: enabled.").status, "OK")
        self.assertEqual(_sip_finding_from_text("").status, "SKIP")

    def test_human_account_names_drop_macos_system_accounts(self):
        self.assertEqual(_human_account_names(["root", "_mbsetupuser", "vitt"]), ["vitt"])

    def test_xprotect_receipts_accept_suffixes(self):
        receipts = _xprotect_receipts(
            "com.apple.pkg.XProtectPlistConfigData_10_15.16U4322\n"
            "com.apple.pkg.Other\n"
            "com.apple.pkg.XProtectPayloads_10_15.16U4322\n"
        )

        self.assertEqual(
            receipts,
            [
                "com.apple.pkg.XProtectPlistConfigData_10_15.16U4322",
                "com.apple.pkg.XProtectPayloads_10_15.16U4322",
            ],
        )

    def test_pkg_install_time_parses_epoch(self):
        self.assertEqual(_pkg_install_time("install-time: 0"), dt.date(1970, 1, 1))

    def test_dedupe_share_names(self):
        self.assertEqual(_dedupe(["Public", "Public", " public "]), ["Public"])


if __name__ == "__main__":
    unittest.main()

import unittest
from unittest.mock import patch

from besecured.checks.common import CommandResult
from besecured.checks.linux import (
    _command_blocked,
    _iptables_has_rules,
    _linux_disk_encryption_finding,
    _lsblk_row,
    _pam_quality_modules_from_text,
    check_firewall,
)


class LinuxParserTests(unittest.TestCase):
    def test_iptables_default_accept_is_not_active_filtering(self):
        self.assertFalse(_iptables_has_rules("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT"))
        self.assertTrue(_iptables_has_rules("-P INPUT DROP\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT"))
        self.assertTrue(_iptables_has_rules("-P INPUT ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT"))

    def test_lsblk_key_value_row_parses_empty_fields(self):
        row = _lsblk_row('NAME="/dev/sda1" TYPE="part" FSTYPE="" MOUNTPOINT="/"')

        self.assertEqual(row["name"], "/dev/sda1")
        self.assertEqual(row["fstype"], "")
        self.assertEqual(row["mountpoint"], "/")

    def test_linux_disk_encryption_detects_crypt(self):
        finding = _linux_disk_encryption_finding(
            'NAME="/dev/mapper/cryptroot" TYPE="crypt" FSTYPE="ext4" MOUNTPOINT="/" PKNAME="/dev/sda2"\n'
        )

        self.assertEqual(finding.status, "OK")

    def test_linux_disk_encryption_accepts_crypt_parent_for_root(self):
        finding = _linux_disk_encryption_finding(
            'NAME="/dev/mapper/vg-root" TYPE="lvm" FSTYPE="ext4" MOUNTPOINT="/" PKNAME="/dev/mapper/cryptroot"\n'
        )

        self.assertEqual(finding.status, "OK")

    def test_linux_disk_encryption_warns_when_root_is_plain(self):
        finding = _linux_disk_encryption_finding(
            'NAME="/dev/sda1" TYPE="part" FSTYPE="ext4" MOUNTPOINT="/" PKNAME="/dev/sda"\n'
        )

        self.assertEqual(finding.status, "WARN")

    def test_linux_disk_encryption_does_not_accept_unrelated_crypt_volume(self):
        finding = _linux_disk_encryption_finding(
            'NAME="/dev/sda1" TYPE="part" FSTYPE="ext4" MOUNTPOINT="/" PKNAME="/dev/sda"\n'
            'NAME="/dev/mapper/cryptusb" TYPE="crypt" FSTYPE="ext4" MOUNTPOINT="/mnt/usb" PKNAME="/dev/sdb1"\n'
        )

        self.assertEqual(finding.status, "WARN")

    def test_pam_quality_modules_ignore_comments(self):
        modules = _pam_quality_modules_from_text(
            "# password requisite pam_pwquality.so\npassword requisite pam_cracklib.so retry=3\n"
        )

        self.assertEqual(modules, {"pam_cracklib"})

    def test_command_blocked_detects_permission_errors(self):
        result = CommandResult(1, "", "Operation not permitted")

        self.assertTrue(_command_blocked(result))

    def test_firewall_permission_error_is_skipped(self):
        def fake_command_exists(name):
            return name == "ufw"

        def fake_run_command(args, timeout=8):
            return CommandResult(1, "", "ERROR: You need to be root")

        with patch("besecured.checks.linux.command_exists", side_effect=fake_command_exists):
            with patch("besecured.checks.linux.run_command", side_effect=fake_run_command):
                findings = check_firewall()

        self.assertEqual(findings[0].status, "SKIP")


if __name__ == "__main__":
    unittest.main()

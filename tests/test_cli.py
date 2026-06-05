import unittest
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from besecured.cli import is_local_output_path, resolve_output_path
from besecured.checks.common import default_output_path


class CliTests(unittest.TestCase):
    def test_json_default_uses_json_suffix(self):
        with patch("besecured.cli.default_output_path", return_value=Path("/tmp/report.html")):
            self.assertEqual(resolve_output_path("json", None), Path("/tmp/report.json"))

    def test_explicit_output_is_kept(self):
        output = Path("/tmp/custom.out")

        self.assertEqual(resolve_output_path("json", output), output)

    def test_local_output_path_accepts_local_disk_paths(self):
        self.assertTrue(is_local_output_path(Path("/tmp/report.html")))
        self.assertTrue(is_local_output_path(Path(r"C:\Users\Phil\report.html")))

    def test_local_output_path_rejects_remote_paths(self):
        self.assertFalse(is_local_output_path(Path(r"\\server\share\report.html")))
        self.assertFalse(is_local_output_path(Path("https://example.com/report.html")))
        self.assertFalse(is_local_output_path(Path("/Volumes/shared/report.html")))
        self.assertFalse(is_local_output_path(Path("/Users/phil/Library/Mobile Documents/com~apple~CloudDocs/report.html")))
        self.assertFalse(is_local_output_path(Path(r"C:\Users\Phil\OneDrive\report.html")))
        self.assertFalse(is_local_output_path(Path(r"C:\Users\Phil\Google Drive - ECE\report.html")))
        self.assertFalse(is_local_output_path(Path(r"C:\Users\Phil\Box Sync\report.html")))

    def test_default_output_path_uses_local_app_data(self):
        output = default_output_path()

        self.assertIn("BeSecured", output.parts)
        self.assertNotIn("Desktop", output.parts)

    def test_relative_output_rejects_cloud_synced_current_directory(self):
        old_cwd = Path.cwd()
        with tempfile.TemporaryDirectory(prefix="OneDrive - ECE ") as tmp:
            os.chdir(tmp)
            try:
                self.assertFalse(is_local_output_path(Path("report.html")))
            finally:
                os.chdir(old_cwd)


if __name__ == "__main__":
    unittest.main()

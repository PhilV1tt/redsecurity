import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from besecured.app import Api, reports_dir

REQUIRED_KEYS = {
    "schema_version",
    "scan_source",
    "generated_at",
    "system_info",
    "status_counts",
    "category_scores",
    "overall_score",
    "grade",
    "score_details",
    "scoring_note",
    "findings",
}


class NativeApiTest(unittest.TestCase):
    def test_run_scan_matches_ui_contract(self):
        data = Api().run_scan()
        self.assertTrue(REQUIRED_KEYS.issubset(data))

    def test_export_html_writes_file(self):
        with TemporaryDirectory() as tmp:
            api = Api(output_dir=tmp)
            api.run_scan()
            saved = api.export_report("html")
            path = Path(saved["path"])
            self.assertEqual(saved["format"], "html")
            self.assertEqual(path.parent, Path(tmp))
            self.assertIn("<!doctype html>", path.read_text(encoding="utf-8").lower())

    def test_export_json_writes_valid_contract(self):
        with TemporaryDirectory() as tmp:
            api = Api(output_dir=tmp)
            api.run_scan()
            saved = api.export_report("json")
            payload = json.loads(Path(saved["path"]).read_text(encoding="utf-8"))
            self.assertEqual(saved["format"], "json")
            self.assertTrue(REQUIRED_KEYS.issubset(payload))

    def test_export_without_prior_scan_still_writes(self):
        with TemporaryDirectory() as tmp:
            saved = Api(output_dir=tmp).export_report("json")
            self.assertTrue(Path(saved["path"]).exists())

    def test_unknown_format_falls_back_to_html(self):
        with TemporaryDirectory() as tmp:
            saved = Api(output_dir=tmp).export_report("pdf")
            self.assertEqual(saved["format"], "html")
            self.assertTrue(Path(saved["path"]).name.endswith(".html"))

    def test_reports_dir_is_absolute(self):
        self.assertTrue(reports_dir().is_absolute())


if __name__ == "__main__":
    unittest.main()

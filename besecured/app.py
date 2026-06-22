"""Native BeSecured app: render the local UI in an OS webview window.

The scan engine and the report writer are reused unchanged. pywebview is
imported lazily inside main() so the engine and the tests stay importable in
pure stdlib, with no GUI dependency.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from besecured.report import write_html_report, write_json_report
from besecured.scanner import run_scan

APP_NAME = "BeSecured"


def static_dir() -> Path:
    """UI files, resolved both in dev and inside a PyInstaller bundle."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", "")) / "besecured" / "ui" / "static"
    return Path(__file__).resolve().parent / "ui" / "static"


def reports_dir() -> Path:
    """Local folder where native exports are written, one per OS."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / APP_NAME / "Reports"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME / "Reports"
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "besecured" / "reports"


class Api:
    """Bridge exposed to the UI JavaScript when running as a native window."""

    def __init__(self, output_dir: Path | str | None = None) -> None:
        self._output_dir = Path(output_dir) if output_dir else reports_dir()
        self._last = None

    def run_scan(self) -> dict:
        self._last = run_scan()
        return self._last.to_dict()

    def export_report(self, fmt: str = "html") -> dict:
        result = self._last or run_scan()
        fmt = (fmt or "html").lower()
        stamp = result.generated_at.strftime("%Y%m%d-%H%M%S")
        if fmt == "json":
            path = self._output_dir / f"BeSecured-report-{stamp}.json"
            write_json_report(result, path)
        else:
            fmt = "html"
            path = self._output_dir / f"BeSecured-report-{stamp}.html"
            write_html_report(result, path)
        return {"path": str(path), "format": fmt}


def main() -> int:
    import webview  # lazy: keeps the engine import-safe without pywebview

    webview.create_window(
        APP_NAME,
        url=str(static_dir() / "index.html"),
        js_api=Api(),
        width=1200,
        height=820,
        min_size=(960, 640),
    )
    webview.start()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import webbrowser
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from besecured.scanner import run_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Serve the local BeSecured UI.")
    parser.add_argument("--host", default="127.0.0.1", help="Local host to bind.")
    parser.add_argument("--port", type=int, default=0, help="Local port. Defaults to a free port.")
    parser.add_argument("--no-open", action="store_true", help="Do not open the window automatically.")
    parser.add_argument("--browser", action="store_true", help="Open in a normal browser tab instead of an app window.")
    return parser


def find_free_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((host, 0))
        return int(probe.getsockname()[1])


def find_app_browser() -> str | None:
    if sys.platform == "darwin":
        candidates = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ]
    elif sys.platform == "win32":
        program_files = [
            os.environ.get("ProgramFiles", r"C:\Program Files"),
            os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
            os.environ.get("LocalAppData", ""),
        ]
        suffixes = [
            r"Google\Chrome\Application\chrome.exe",
            r"Microsoft\Edge\Application\msedge.exe",
            r"BraveSoftware\Brave-Browser\Application\brave.exe",
        ]
        candidates = [str(Path(base) / suffix) for base in program_files if base for suffix in suffixes]
    else:
        names = ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge", "brave-browser"]
        candidates = [path for name in names if (path := shutil.which(name))]

    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    return None


def open_app_window(url: str) -> bool:
    browser = find_app_browser()
    if not browser:
        return False
    profile_dir = Path(tempfile.gettempdir()) / "besecured-ui-profile"
    args = [
        browser,
        f"--app={url}",
        "--new-window",
        "--window-size=1200,820",
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--no-default-browser-check",
    ]
    try:
        subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except OSError:
        return False


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


class BeSecuredUIHandler(QuietHandler):
    def do_GET(self) -> None:
        if urlsplit(self.path).path == "/api/health":
            self._send_json({"status": "ok"})
            return
        super().do_GET()

    def do_POST(self) -> None:
        if urlsplit(self.path).path != "/api/scan":
            self._send_json({"error": "Unknown endpoint."}, status=404)
            return

        try:
            self._send_json(run_scan().to_dict())
        except Exception as error:
            self._send_json(
                {
                    "error": "Local scan failed.",
                    "detail": str(error),
                },
                status=500,
            )

    def _send_json(self, payload: dict[str, object], status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    static_dir = Path(__file__).resolve().parent / "static"
    port = args.port or find_free_port(args.host)
    handler = partial(BeSecuredUIHandler, directory=str(static_dir))
    server = ThreadingHTTPServer((args.host, port), handler)
    scheme = "http"
    url = f"{scheme}://{args.host}:{port}/"

    print(f"BeSecured running locally at {url}")
    print("Press Ctrl+C to stop.")
    if not args.no_open:
        opened = False if args.browser else open_app_window(url)
        if not opened:
            webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping BeSecured.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

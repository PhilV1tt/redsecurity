from __future__ import annotations

import argparse
import ctypes
import re
import sys
import webbrowser
from pathlib import Path

from .checks.common import default_output_path
from .report import write_html_report, write_json_report
from .scanner import run_scan


SYNC_PATH_MARKERS = (
    "/mobile documents/",
    "/icloud drive/",
    "/iclouddrive/",
    "/onedrive",
    "/dropbox",
    "/google drive",
    "/box/",
    "/box sync/",
    "/nextcloud",
    "/owncloud",
    "/creative cloud files/",
)
REMOTE_MOUNT_PREFIXES = (
    "/volumes/",
    "/network/",
    "/mnt/",
    "/media/",
    "/run/user/",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="besecured",
        description="Run a safe local cybersecurity posture scan on Windows, Linux or macOS.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Report path. Defaults to the local BeSecured app data folder.",
    )
    parser.add_argument(
        "--format",
        choices=["html", "json"],
        default="html",
        help="Primary report format.",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        help="Optional extra JSON report path.",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Do not open the HTML report automatically.",
    )
    return parser


def resolve_output_path(report_format: str, output: Path | None) -> Path:
    if output is not None:
        return output
    default_path = default_output_path()
    if report_format == "json":
        return default_path.with_suffix(".json")
    return default_path


def is_local_output_path(path: Path) -> bool:
    raw = str(path)
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:/", raw) and not re.match(r"^[A-Za-z]:[\\/]", raw):
        return False
    if raw.startswith("\\\\") and not re.match(r"^\\\\\?\\[A-Za-z]:\\", raw):
        return False
    for candidate in _path_texts_to_check(path):
        normalized = "/" + candidate.replace("\\", "/").strip("/").lower() + "/"
        if any(marker in normalized for marker in SYNC_PATH_MARKERS):
            return False
        if any(normalized.startswith(prefix) for prefix in REMOTE_MOUNT_PREFIXES):
            return False
    if _is_windows_network_drive(raw):
        return False
    return True


def _path_texts_to_check(path: Path) -> tuple[str, ...]:
    raw = str(path)
    try:
        resolved = str(path.expanduser().resolve(strict=False))
    except OSError:
        return (raw,)
    if resolved == raw:
        return (raw,)
    return (raw, resolved)


def _is_windows_network_drive(raw: str) -> bool:
    if sys.platform != "win32":
        return False
    drive = Path(raw).drive
    if not drive or drive.startswith("\\\\"):
        return False
    try:
        return ctypes.windll.kernel32.GetDriveTypeW(f"{drive}\\") == 4
    except Exception:
        return False


def require_local_output_path(path: Path) -> None:
    if not is_local_output_path(path):
        raise SystemExit("Refusing to write a report to a remote path. Use a local disk path.")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = run_scan()

    output = resolve_output_path(args.format, args.output)
    require_local_output_path(output)
    if args.format == "json":
        write_json_report(result, output)
    else:
        write_html_report(result, output)

    if args.json_output:
        require_local_output_path(args.json_output)
        write_json_report(result, args.json_output)

    print(f"BeSecured scan complete: grade {result.grade} ({result.overall_score}/100)")
    print(
        "Findings: "
        f"{result.status_counts['OK']} OK, "
        f"{result.status_counts['WARN']} WARN, "
        f"{result.status_counts['CRIT']} CRIT, "
        f"{result.status_counts['INFO']} INFO, "
        f"{result.status_counts['SKIP']} SKIP"
    )
    print(f"Report saved to: {output}")

    if args.format == "html" and not args.no_open:
        try:
            webbrowser.open(output.resolve().as_uri())
        except Exception:
            print("Could not open the report automatically.", file=sys.stderr)
    return 0

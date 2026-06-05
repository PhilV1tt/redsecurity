from __future__ import annotations

import ctypes
import os
import platform
import re
import shutil
import socket
import subprocess
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from besecured.models import Finding


RISKY_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    135: "RPC",
    137: "NetBIOS",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


@dataclass(frozen=True)
class CommandResult:
    returncode: int | None
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


@dataclass(frozen=True)
class ListeningPort:
    port: int
    address: str = ""
    process: str = ""


class CheckUnavailable(RuntimeError):
    pass


def run_command(args: Sequence[str], timeout: int = 8) -> CommandResult:
    try:
        completed = subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return CommandResult(completed.returncode, completed.stdout.strip(), completed.stderr.strip())
    except FileNotFoundError as exc:
        return CommandResult(None, "", str(exc))
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return CommandResult(None, stdout, stderr or f"Timed out after {timeout}s")
    except OSError as exc:
        return CommandResult(None, "", str(exc))


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def is_admin() -> bool:
    if platform.system() == "Windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def collect_system_info(admin: bool) -> dict[str, str]:
    return {
        "Hostname": socket.gethostname(),
        "Username": os.environ.get("USERNAME") or os.environ.get("USER") or "Unknown",
        "OS": platform.platform(),
        "System": platform.system() or "Unknown",
        "Release": platform.release() or "Unknown",
        "Arch": platform.machine() or "Unknown",
        "CPU": _cpu_name(),
        "RAM": _ram_total(),
        "Uptime": _uptime(),
        "Admin Run": str(admin),
        "Python": platform.python_version(),
    }


def unavailable_finding(
    category: str,
    name: str,
    reason: str,
    remediation: str,
    *,
    supported_os: Iterable[str] | None = None,
    requires_admin: bool | None = None,
) -> Finding:
    return Finding(
        category,
        name,
        "SKIP",
        f"Check not available: {reason}",
        remediation,
        supported_os=tuple(supported_os) if supported_os is not None else ("Windows", "Linux", "macOS"),
        requires_admin=_mentions_admin_need(reason, remediation) if requires_admin is None else requires_admin,
    )


def run_common_checks(admin: bool) -> list[Finding]:
    findings = [check_privilege_level(admin)]
    findings.extend(check_open_ports())
    return findings


def check_privilege_level(admin: bool) -> Finding:
    if admin:
        return Finding(
            "Execution Context",
            "Scanner Privileges",
            "INFO",
            "Scanner is running with administrator or root privileges.",
            "Use elevated privileges only when full local visibility is needed.",
        )
    return Finding(
        "Execution Context",
        "Scanner Privileges",
        "INFO",
        "Scanner is running as a standard user.",
        "Some protected checks may be skipped. Re-run elevated only if those details are needed.",
    )


def _mentions_admin_need(*texts: str) -> bool:
    combined = " ".join(texts).lower()
    markers = (
        "administrator",
        "admin",
        "elevated",
        "privilege",
        "privileges",
        "root",
        "sudo",
    )
    return any(marker in combined for marker in markers)


def _cpu_name() -> str:
    system = platform.system()
    if system == "Darwin":
        result = run_command(["sysctl", "-n", "machdep.cpu.brand_string"], timeout=4)
        if result.stdout:
            return result.stdout
    if system == "Linux":
        cpuinfo = Path("/proc/cpuinfo")
        if cpuinfo.exists():
            for line in cpuinfo.read_text(errors="ignore").splitlines():
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    if system == "Windows":
        result = run_command(["wmic", "cpu", "get", "Name", "/value"], timeout=6)
        match = re.search(r"Name=(.+)", result.stdout)
        if match:
            return match.group(1).strip()
    return platform.processor() or "Unknown"


def _ram_total() -> str:
    system = platform.system()
    total_bytes: int | None = None
    if system == "Darwin":
        result = run_command(["sysctl", "-n", "hw.memsize"], timeout=4)
        if result.stdout.isdigit():
            total_bytes = int(result.stdout)
    elif system == "Linux":
        meminfo = Path("/proc/meminfo")
        if meminfo.exists():
            match = re.search(r"^MemTotal:\s+(\d+)\s+kB", meminfo.read_text(errors="ignore"), flags=re.MULTILINE)
            if match:
                total_bytes = int(match.group(1)) * 1024
    elif system == "Windows":
        result = run_command(["wmic", "computersystem", "get", "TotalPhysicalMemory", "/value"], timeout=6)
        match = re.search(r"TotalPhysicalMemory=(\d+)", result.stdout)
        if match:
            total_bytes = int(match.group(1))

    if total_bytes is None:
        return "Unknown"
    return f"{total_bytes / (1024 ** 3):.1f} GB"


def _uptime() -> str:
    system = platform.system()
    seconds: float | None = None
    if system == "Linux":
        uptime_file = Path("/proc/uptime")
        if uptime_file.exists():
            try:
                seconds = float(uptime_file.read_text().split()[0])
            except (IndexError, ValueError):
                seconds = None
    elif system == "Darwin":
        result = run_command(["sysctl", "-n", "kern.boottime"], timeout=4)
        match = re.search(r"sec = (\d+)", result.stdout)
        if match:
            seconds = time.time() - int(match.group(1))
    elif system == "Windows":
        result = run_command(["wmic", "os", "get", "LastBootUpTime", "/value"], timeout=6)
        match = re.search(r"LastBootUpTime=(\d{14})", result.stdout)
        if match:
            try:
                import datetime as dt

                boot = dt.datetime.strptime(match.group(1), "%Y%m%d%H%M%S").timestamp()
                seconds = time.time() - boot
            except ValueError:
                seconds = None

    if seconds is None:
        return "Unknown"
    hours = seconds / 3600
    if hours < 48:
        return f"{hours:.1f} hours"
    return f"{hours / 24:.1f} days"


def default_output_path() -> Path:
    hostname = re.sub(r"[^A-Za-z0-9_.-]+", "_", socket.gethostname())
    return _local_report_dir() / f"BeSecured_Report_{hostname}.html"


def _local_report_dir() -> Path:
    system = platform.system()
    if system == "Windows":
        base = os.environ.get("LOCALAPPDATA")
        root = Path(base) if base else Path.home() / "AppData" / "Local"
        return root / "BeSecured" / "Reports"
    if system == "Darwin":
        return Path.home() / "Library" / "Application Support" / "BeSecured" / "Reports"
    base = os.environ.get("XDG_STATE_HOME")
    root = Path(base) if base else Path.home() / ".local" / "state"
    return root / "besecured" / "reports"


def check_open_ports() -> list[Finding]:
    category = "Open Ports"
    try:
        listeners = _list_listening_ports()
    except CheckUnavailable as exc:
        return [
            unavailable_finding(
                category,
                "Port Scan",
                str(exc),
                "Install or enable a standard local networking tool such as ss, lsof or netstat, then run the scan again.",
            )
        ]
    except Exception as exc:
        return [
            Finding(
                category,
                "Port Scan",
                "WARN",
                f"Could not inspect listening ports: {exc}",
                "Run the scanner with higher privileges or inspect listening services manually.",
                requires_admin=True,
            )
        ]

    listeners_by_port: dict[int, list[ListeningPort]] = defaultdict(list)
    for listener in listeners:
        listeners_by_port[listener.port].append(listener)
    unique_ports = sorted(listeners_by_port)
    findings = [
        Finding(
            category,
            "Total Listening Ports",
            "INFO",
            f"{len(unique_ports)} TCP port(s) listening",
            "Close services that are not needed, especially services reachable from other machines.",
        )
    ]

    for port in unique_ports:
        service = RISKY_PORTS.get(port)
        if not service:
            continue

        scope = _port_scope(listeners_by_port[port])
        if scope == "loopback":
            findings.append(
                Finding(
                    category,
                    f"Port {port} ({service})",
                    "INFO",
                    f"{service} is listening on loopback only.",
                    "Confirm the local service is expected. Loopback-only services are not exposed to the local network.",
                )
            )
            continue

        if port == 3389:
            findings.append(
                Finding(
                    category,
                    "RDP (3389)",
                    "CRIT",
                    f"Remote Desktop is listening on {scope} address(es).",
                    "Disable RDP if it is not required. If it is required, restrict it with firewall rules and strong authentication.",
                )
            )
            continue

        findings.append(
            Finding(
                category,
                f"Port {port} ({service})",
                "WARN",
                f"Risky service detected on {scope} address(es): {service}.",
                "Confirm this service is expected. Disable it or restrict access with the local firewall if it is not needed.",
            )
        )

    if 3389 not in unique_ports:
        findings.append(
            Finding(
                category,
                "RDP (3389)",
                "OK",
                "Remote Desktop is not listening.",
                "Keep RDP disabled unless there is a clear need for remote administration.",
            )
        )

    return findings


def _list_listening_ports() -> list[ListeningPort]:
    system = platform.system()
    if system == "Linux":
        source_available = Path("/proc/net/tcp").exists() or Path("/proc/net/tcp6").exists()
        ports = _linux_proc_listeners()
        if ports:
            return ports
        if command_exists("ss"):
            source_available = True
            ports = _ss_listeners()
            if ports:
                return ports
        if command_exists("lsof"):
            source_available = True
            ports = _lsof_listeners()
            if ports:
                return ports
        if command_exists("netstat"):
            source_available = True
            ports = _netstat_listeners("LISTEN")
            if ports:
                return ports
        if source_available:
            return []
        raise CheckUnavailable("no supported listener source was found on Linux")
    if system == "Darwin":
        source_available = False
        if command_exists("lsof"):
            source_available = True
            ports = _lsof_listeners()
            if ports:
                return ports
        if command_exists("netstat"):
            source_available = True
            ports = _netstat_listeners("LISTEN")
            if ports:
                return ports
        if source_available:
            return []
        raise CheckUnavailable("lsof and netstat are not available on macOS")
    if system == "Windows":
        if not command_exists("netstat"):
            raise CheckUnavailable("netstat is not available on Windows")
        return _windows_netstat_listeners()
    source_available = False
    if command_exists("lsof"):
        source_available = True
        ports = _lsof_listeners()
        if ports:
            return ports
    if command_exists("netstat"):
        source_available = True
        return _netstat_listeners("LISTEN")
    if source_available:
        return []
    raise CheckUnavailable("no supported listener source was found")


def _linux_proc_listeners() -> list[ListeningPort]:
    listeners: set[tuple[str, int]] = set()
    for proc_file in [Path("/proc/net/tcp"), Path("/proc/net/tcp6")]:
        if not proc_file.exists():
            continue
        for line in proc_file.read_text(errors="ignore").splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4 or parts[3] != "0A":
                continue
            local_address = parts[1]
            try:
                address_hex, port_hex = local_address.rsplit(":", 1)
                listeners.add((_decode_proc_address(address_hex), int(port_hex, 16)))
            except ValueError:
                continue
    return [ListeningPort(port=port, address=address) for address, port in sorted(listeners)]


def _lsof_listeners() -> list[ListeningPort]:
    if not command_exists("lsof"):
        return []
    result = run_command(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], timeout=8)
    if not result.stdout:
        return []
    return _lsof_listeners_from_text(result.stdout)


def _lsof_listeners_from_text(text: str) -> list[ListeningPort]:
    listeners: set[tuple[int, str, str]] = set()
    for line in text.splitlines()[1:]:
        port_match = re.search(r":(\d+)(?:\s|\(|$)", line)
        if not port_match:
            continue
        command = line.split(maxsplit=1)[0] if line.split() else ""
        address = _address_from_listener_text(line)
        listeners.add((int(port_match.group(1)), address, command))
    return [ListeningPort(port=port, address=address, process=command) for port, address, command in sorted(listeners)]


def _ss_listeners() -> list[ListeningPort]:
    result = run_command(["ss", "-H", "-ltn"], timeout=8)
    if not result.stdout:
        return []
    return _ss_listeners_from_text(result.stdout)


def _ss_listeners_from_text(text: str) -> list[ListeningPort]:
    listeners: set[tuple[int, str]] = set()
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        local = ""
        if parts[0].upper() == "LISTEN" and len(parts) >= 4:
            local = parts[3]
        elif len(parts) >= 5 and parts[1].upper() == "LISTEN":
            local = parts[4]
        if not local:
            continue
        address, port = _split_address_port(local)
        if port is not None:
            listeners.add((port, address))
    return [ListeningPort(port=port, address=address) for port, address in sorted(listeners)]


def _netstat_listeners(listen_word: str) -> list[ListeningPort]:
    if not command_exists("netstat"):
        return []
    result = run_command(["netstat", "-an"], timeout=8)
    return _netstat_listeners_from_text(result.stdout, listen_word)


def _netstat_listeners_from_text(text: str, listen_word: str) -> list[ListeningPort]:
    listeners: set[tuple[int, str]] = set()
    rows: list[ListeningPort] = []
    for line in text.splitlines():
        if listen_word not in line.upper():
            continue
        match = re.search(r"(?:\.|:)(\d+)\s+.*" + listen_word, line, flags=re.IGNORECASE)
        if match:
            parts = line.split()
            if len(parts) > 3:
                address, parsed_port = _split_address_port(parts[3])
            else:
                address, parsed_port = _address_from_listener_text(line), None
            port = parsed_port or int(match.group(1))
            key = (port, address)
            if key in listeners:
                continue
            listeners.add(key)
            rows.append(ListeningPort(port=port, address=address))
    return rows


def _windows_netstat_listeners() -> list[ListeningPort]:
    result = run_command(["netstat", "-ano", "-p", "tcp"], timeout=10)
    return _windows_netstat_listeners_from_text(result.stdout)


def _windows_netstat_listeners_from_text(text: str) -> list[ListeningPort]:
    listeners: set[tuple[int, str]] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0].upper() != "TCP" or parts[3].upper() != "LISTENING":
            continue
        address, port = _split_address_port(parts[1])
        if port is not None:
            listeners.add((port, address))
    return [ListeningPort(port=port, address=address) for port, address in sorted(listeners)]


def _decode_proc_address(address_hex: str) -> str:
    if address_hex == "00000000":
        return "0.0.0.0"
    if address_hex.upper() == "0100007F":
        return "127.0.0.1"
    if address_hex == "00000000000000000000000000000000":
        return "::"
    if address_hex.upper() == "00000000000000000000000001000000":
        return "::1"
    if len(address_hex) == 8:
        try:
            return socket.inet_ntoa(bytes.fromhex(address_hex)[::-1])
        except OSError:
            return address_hex
    return address_hex


def _split_address_port(value: str) -> tuple[str, int | None]:
    clean = value.strip()
    if clean.startswith("[") and "]:" in clean:
        address, port_text = clean.rsplit("]:", 1)
        return address.lstrip("["), _safe_int(port_text)
    if ":" in clean:
        address, port_text = clean.rsplit(":", 1)
        return address, _safe_int(port_text)
    if "." in clean:
        address, port_text = clean.rsplit(".", 1)
        return address, _safe_int(port_text)
    return clean, None


def _safe_int(value: str) -> int | None:
    try:
        return int(value)
    except ValueError:
        return None


def _address_from_listener_text(text: str) -> str:
    if "localhost" in text:
        return "127.0.0.1"
    match = re.search(r"(127\.\d+\.\d+\.\d+|\[?::1\]?|0\.0\.0\.0|\[?::\]?|\*)[:.]\d+", text)
    if match:
        return match.group(1).strip("[]")
    return ""


def _port_scope(listeners: list[ListeningPort]) -> str:
    if listeners and all(listener.address and _is_loopback_address(listener.address) for listener in listeners):
        return "loopback"
    addresses = [listener.address for listener in listeners if listener.address]
    if any(_is_wildcard_address(address) for address in addresses):
        return "all interfaces"
    if len(addresses) != len(listeners):
        return "unknown"
    if addresses:
        return "network"
    return "unknown"


def _is_loopback_address(address: str) -> bool:
    clean = address.strip("[]").split("%", 1)[0].lower()
    return clean == "localhost" or clean.startswith("127.") or clean == "::1"


def _is_wildcard_address(address: str) -> bool:
    clean = address.strip("[]").split("%", 1)[0].lower()
    return clean in {"", "*", "*.*", "0.0.0.0", "::"}


def file_age_days(path: Path) -> int | None:
    try:
        return round((time.time() - path.stat().st_mtime) / 86400)
    except OSError:
        return None


def readable_files(paths: Iterable[Path], suffix: str | None = None) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_file() and (suffix is None or path.name.endswith(suffix)):
            files.append(path)
            continue
        if not path.is_dir():
            continue
        try:
            for child in path.iterdir():
                if child.is_file() and (suffix is None or child.name.endswith(suffix)):
                    files.append(child)
        except OSError:
            continue
    return files

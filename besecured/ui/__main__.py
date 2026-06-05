from __future__ import annotations

import argparse
import socket
import webbrowser
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Serve the local BeSecured UI prototype.")
    parser.add_argument("--host", default="127.0.0.1", help="Local host to bind.")
    parser.add_argument("--port", type=int, default=0, help="Local port. Defaults to a free port.")
    parser.add_argument("--no-open", action="store_true", help="Do not open the browser automatically.")
    return parser


def find_free_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((host, 0))
        return int(probe.getsockname()[1])


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    static_dir = Path(__file__).resolve().parent / "static"
    port = args.port or find_free_port(args.host)
    handler = partial(QuietHandler, directory=str(static_dir))
    server = ThreadingHTTPServer((args.host, port), handler)
    scheme = "http"
    url = f"{scheme}://{args.host}:{port}/"

    print(f"BeSecured UI running locally at {url}")
    print("Press Ctrl+C to stop.")
    if not args.no_open:
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping BeSecured UI.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Dependency-free local web UI for the educational Ashoka flow."""

import argparse
import json
import mimetypes
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

from ashoka_demo.protocol import InMemoryUsedList, execute_flow


STATIC_ROOT = Path(__file__).with_name("static").resolve()
USED_LIST = InMemoryUsedList()
MAX_REQUEST_BYTES = 64 * 1024


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "CoconutDemo/1.0"

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path):
        try:
            body = path.read_bytes()
        except FileNotFoundError:
            self.send_error(404)
            return
        content_type, _ = mimetypes.guess_type(str(path))
        self.send_response(200)
        self.send_header("Content-Type", content_type or "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/config":
            self._send_json(
                200,
                {
                    "authority_count": 3,
                    "threshold": 2,
                    "used_list_size": len(USED_LIST),
                    "implementation": "original coconut.scheme functions",
                },
            )
            return
        if path == "/":
            self._send_file(STATIC_ROOT / "index.html")
            return
        if path.startswith("/static/"):
            requested = (STATIC_ROOT / path[len("/static/") :]).resolve()
            if STATIC_ROOT not in requested.parents:
                self.send_error(404)
                return
            self._send_file(requested)
            return
        self.send_error(404)

    def do_POST(self):
        if urlparse(self.path).path != "/api/run":
            self.send_error(404)
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0 or content_length > MAX_REQUEST_BYTES:
                raise ValueError("request body must be between 1 byte and 64 KiB")
            payload = json.loads(self.rfile.read(content_length).decode("utf-8"))
            result = execute_flow(
                payload.get("issue_id"),
                payload.get("complaint_id"),
                payload.get("complaint_text"),
                USED_LIST,
            )
            self._send_json(200, result)
        except (ValueError, TypeError, json.JSONDecodeError) as error:
            self._send_json(400, {"error": str(error)})
        except Exception as error:
            print("[coconut-gui] protocol error: {}".format(error))
            self._send_json(
                500,
                {"error": "the Coconut protocol run failed; inspect the server log"},
            )

    def log_message(self, message, *args):
        print("[coconut-gui] " + message % args)


def parse_args():
    parser = argparse.ArgumentParser(description="Run the Coconut educational GUI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    return parser.parse_args()


def main():
    args = parse_args()
    server = HTTPServer((args.host, args.port), DemoHandler)
    print("Coconut educational GUI: http://{}:{}".format(args.host, args.port))
    print("Press Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

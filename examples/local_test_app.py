"""Loopback-only test fixture for controlled GramFuzz evaluations."""

import argparse
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlsplit


class _EvaluationHTTPServer(HTTPServer):
    def __init__(self, server_address, request_handler):
        self.received_requests = []
        super().__init__(server_address, request_handler)


class _EvaluationHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlsplit(self.path)
        value = parse_qs(parsed.query).get("q", [""])[0]
        self.server.received_requests.append(
            {"path": parsed.path, "payload": value}
        )

        if parsed.path == "/normal":
            status, body = 200, "Normal fixture response."
        elif parsed.path == "/controlled-error":
            if value == "gramfuzz-baseline":
                status, body = 200, "Controlled-error fixture baseline."
            else:
                status, body = 500, "Controlled test-fixture HTTP error."
        elif parsed.path == "/reflect":
            status, body = 200, f"Safe text reflection: {value}"
        elif parsed.path == "/database-error":
            if value == "gramfuzz-baseline":
                status, body = 200, "Database-signature fixture baseline."
            else:
                status, body = (
                    200,
                    "SQL syntax error near the harmless GramFuzz fixture marker.",
                )
        elif parsed.path == "/slow":
            time.sleep(0.25)
            status, body = 200, "Slow fixture response completed."
        elif parsed.path == "/timeout":
            time.sleep(1.5)
            status, body = 200, "Delayed fixture response."
        else:
            status, body = 404, "Unknown test-fixture endpoint."

        encoded_body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded_body)))
        self.end_headers()
        try:
            self.wfile.write(encoded_body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    def log_message(self, format_string, *args):
        return


class LocalTestApplication:
    """Manage a test HTTP server bound exclusively to IPv4 loopback."""

    def __init__(self):
        self.server = _EvaluationHTTPServer(
            ("127.0.0.1", 0), _EvaluationHandler
        )
        self.thread = Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self):
        """Return the ephemeral loopback URL."""
        return f"http://127.0.0.1:{self.server.server_port}"

    @property
    def received_requests(self):
        """Return requests received by the fixture server."""
        return list(self.server.received_requests)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exception_type, exception, traceback):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


def main(argv=None):
    """Run the standalone local-only test application."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    server = _EvaluationHTTPServer(("127.0.0.1", args.port), _EvaluationHandler)
    print(f"GramFuzz test fixture listening on http://127.0.0.1:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

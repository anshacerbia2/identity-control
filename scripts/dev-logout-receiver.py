"""Receives OpenID Connect back-channel logout requests for a CI proof, and records them.

dev-back-channel-logout-proof.ps1 registers a client whose back-channel logout URI is this listener,
and reads what it recorded (ADR-IAM-009, TDD-identity-control-003 1.37.0). It stands where a BFF's
POST /auth/back-channel-logout stands: it answers 200 to a request carrying a logout_token, as
Back-Channel Logout 1.0 §2.8 asks of a logout that succeeded, and 400 to any other.

It verifies nothing. The proof reads the token it recorded and checks it. It runs on a CI runner for
the length of one job, never on a shared server.

Usage: python3 dev-logout-receiver.py <address> <port> <output.jsonl>
"""

import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs


def main() -> None:
    address, port, output = sys.argv[1], int(sys.argv[2]), sys.argv[3]

    class Receiver(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802, the name BaseHTTPRequestHandler dispatches on
            length = int(self.headers.get("Content-Length") or 0)
            form = parse_qs(self.rfile.read(length).decode("ascii", "replace"))
            token = (form.get("logout_token") or [""])[0]
            with open(output, "a", encoding="utf-8") as recorded:
                recorded.write(json.dumps({"received_at": time.time(), "path": self.path,
                                           "content_type": self.headers.get("Content-Type", ""),
                                           "logout_token": token}) + "\n")
            self.send_response(200 if token else 400)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

        def log_message(self, format: str, *args) -> None:  # noqa: A002, the signature is the base class's
            sys.stderr.write("dev-logout-receiver: " + (format % args) + "\n")

    HTTPServer((address, port), Receiver).serve_forever()


if __name__ == "__main__":
    main()

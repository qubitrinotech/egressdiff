from __future__ import annotations

import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = f"{self.server.fixture_name}\n".encode("ascii")
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


def main() -> None:
    port = int(sys.argv[1])
    name = sys.argv[2]
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.fixture_name = name
    if name == "telemetry":
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(
            certfile=str(Path("/telemetry-cert.pem")),
            keyfile=str(Path("/telemetry-key.pem")),
        )
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

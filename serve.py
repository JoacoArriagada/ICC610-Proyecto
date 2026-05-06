#!/usr/bin/env python3
import http.server
import socketserver
import os
from pathlib import Path
from urllib.parse import unquote

PORT = 8080
PROJECT_ROOT = Path(__file__).resolve().parent
ALLOWED_DIRS = {"visualizer", "data"}


class RestrictedHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(PROJECT_ROOT), **kwargs)

    def do_GET(self):
        path = unquote(self.path.split("?")[0]).rstrip("/")

        if path == "" or path == "/":
            self.send_response(301)
            self.send_header("Location", "/visualizer/index.html")
            self.end_headers()
            return

        if path.startswith("/visualizer/") or path == "/visualizer/index.html":
            super().do_GET()
            return

        if path.startswith("/data/"):
            super().do_GET()
            return

        self.send_error(403, "Forbidden")

    def list_directory(self, path):
        self.send_error(403, "Forbidden")
        return None


if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), RestrictedHandler) as httpd:
        print(f"Servidor seguro corriendo en http://localhost:{PORT}")
        print(f"Solo se permite acceso a /visualizer/ y /data/")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServidor detenido.")

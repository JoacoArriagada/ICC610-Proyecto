#!/usr/bin/env python3
import http.server
import socketserver
import os
from pathlib import Path
from urllib.parse import unquote

PORT = 8080
PROJECT_ROOT = Path(__file__).resolve().parent
ALLOWED_DIRS = {"visualizer", "data"}
ASSET_MAP = {
    "/app.js": "visualizer/app.js",
    "/charts.js": "visualizer/charts.js",
    "/styles.css": "visualizer/styles.css",
}


class RestrictedHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(PROJECT_ROOT), **kwargs)

    def _is_safe_path(self, rel_path):
        try:
            full_path = (PROJECT_ROOT / rel_path).resolve()
            full_path.relative_to(PROJECT_ROOT)
        except Exception:
            return False

        current = PROJECT_ROOT
        for part in Path(rel_path).parts:
            current = current / part
            if current.is_symlink():
                return False
        return True

    def do_GET(self):
        path = unquote(self.path.split("?")[0])
        if path == "":
            path = "/"

        if path == "/":
            rel_path = Path("visualizer/index.html")
            if not self._is_safe_path(rel_path):
                self.send_error(403, "Forbidden")
                return
            self.path = "/visualizer/index.html"
            super().do_GET()
            return

        if path in ASSET_MAP:
            rel_path = Path(ASSET_MAP[path])
            if not self._is_safe_path(rel_path):
                self.send_error(403, "Forbidden")
                return
            self.path = "/" + ASSET_MAP[path]
            super().do_GET()
            return

        if path.startswith("/data/"):
            rel_path = Path(path.lstrip("/"))
            if rel_path.parts and rel_path.parts[0] not in ALLOWED_DIRS:
                self.send_error(403, "Forbidden")
                return
            if not self._is_safe_path(rel_path):
                self.send_error(403, "Forbidden")
                return
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

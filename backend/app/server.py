"""Stdlib HTTP service for the link-audit API and static frontend hosting."""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .audit import InvalidRequest, perform_audit, validate_request
from .storage import AuditExists, Store

STATIC_DIR = Path(os.environ.get("STATIC_DIR", "/app/frontend_dist"))
DB_PATH = os.environ.get("AUDIT_DB", "/data/audits.db")
MAX_BODY = 16 * 1024 * 1024

STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".map": "application/json",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "LinkAudit/1.0"
    store: Store  # injected onto the class

    # -- helpers ------------------------------------------------------------

    def _send_json(self, code: int, payload: dict | list) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            raise InvalidRequest("missing request body")
        if length > MAX_BODY:
            raise InvalidRequest(f"request body exceeds {MAX_BODY} bytes")
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InvalidRequest(f"body is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise InvalidRequest("body must be a JSON object")
        return data

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        sys.stderr.write("[http] %s - %s\n" % (self.address_string(), fmt % args))

    # -- routing ------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/health":
            self._send_json(200, {"status": "ok", "service": "link-audit"})
            return
        if path == "/api/audits":
            self._send_json(200, {"audits": self.store.list_ids()})
            return
        if path.startswith("/api/audits/"):
            audit_id = path[len("/api/audits/") :]
            data = self.store.get(audit_id)
            if data is None:
                self._send_json(404, {
                    "error": "not_found",
                    "message": f"no frozen conclusion for audit_id {audit_id!r}",
                })
                return
            self._send_json(200, data)
            return
        if path.startswith("/api/"):
            self._send_json(404, {"error": "not_found", "message": path})
            return
        self._serve_static(path)

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path != "/api/audits":
            self._send_json(404, {"error": "not_found", "message": path})
            return
        try:
            body = self._read_json()
            audit_id, items = validate_request(body)
            conclusion = perform_audit(audit_id, items)
            stored = self.store.freeze(
                audit_id, conclusion["input_fingerprint"], conclusion
            )
        except InvalidRequest as exc:
            self._send_json(400, {
                "error": "invalid_request",
                "field": exc.field,
                "message": str(exc),
            })
            return
        except AuditExists as exc:
            self._send_json(409, {
                "error": "audit_id_conflict",
                "audit_id": exc.audit_id,
                "message": str(exc),
                "fingerprint_existing": exc.fingerprint_existing,
                "fingerprint_incoming": exc.fingerprint_incoming,
            })
            return
        code = 200 if stored.get("reopened") else 201
        self._send_json(code, stored)

    # -- static files -------------------------------------------------------

    def _serve_static(self, path: str) -> None:
        if not STATIC_DIR.exists():
            self._send_json(503, {
                "error": "frontend_not_built",
                "message": "set STATIC_DIR to the built frontend directory",
            })
            return
        rel = path.lstrip("/") or "index.html"
        candidate = (STATIC_DIR / rel).resolve()
        root = STATIC_DIR.resolve()
        if root not in candidate.parents and candidate != root:
            self.send_error(403)
            return
        if candidate.is_dir():
            candidate = candidate / "index.html"
        if not candidate.is_file():
            candidate = STATIC_DIR / "index.html"  # SPA fallback
        ctype = STATIC_TYPES.get(candidate.suffix, "application/octet-stream")
        try:
            body = candidate.read_bytes()
        except OSError:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def build_server(host: str = "0.0.0.0", port: int | None = None) -> ThreadingHTTPServer:
    port = port or int(os.environ.get("PORT", "8080"))
    store = Store(DB_PATH)
    handler = type("BoundHandler", (Handler,), {"store": store})
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.store = store  # type: ignore[attr-defined]
    return httpd


def main() -> int:
    httpd = build_server()
    host, port = httpd.server_address[:2]
    print(f"link-audit listening on http://{host}:{port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.store.close()  # type: ignore[attr-defined]
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Local web UI for honeypot-auditor (XP.css look).

Security model:
  · The HTTP server binds to 127.0.0.1 only — there is no option to expose it.
  · A Host-header check rejects anything that is not localhost (DNS rebinding).
  · All dynamic data is rendered in the browser via textContent (no HTML injection).
  · Audits run serialized under a lock: the engine's probe settings are process
    globals, so concurrent runs would race (and one local user does not need
    parallel scans).

Usage: honeypot-auditor serve [--port 8337]
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlsplit

from honeypot_auditor import storage
from honeypot_auditor.engine import Auditor
from honeypot_auditor.reporters.json_export import _report_payload as report_payload

_BIND_HOST = "127.0.0.1"
DEFAULT_PORT = 8337
_ALLOWED_PRESETS = ("both", "iana", "docker-research")
_LOCAL_HOSTNAMES = frozenset({"127.0.0.1", "localhost", "::1"})

# Vendored XP.css (MIT, https://botoxparty.github.io/XP.css/) + pixel fonts.
_STATIC_TYPES = {
    "XP.css": "text/css; charset=utf-8",
    "ms_sans_serif.woff2": "font/woff2",
    "ms_sans_serif.woff": "font/woff",
    "ms_sans_serif_bold.woff2": "font/woff2",
    "ms_sans_serif_bold.woff": "font/woff",
    "PerfectDOSVGA437Win.woff2": "font/woff2",
    "PerfectDOSVGA437Win.woff": "font/woff",
}

# One audit at a time: engine settings are process globals.
_AUDIT_LOCK = threading.Lock()

_DATA_DIR = None  # resolved lazily so tests can point elsewhere if needed


def _static_dir():
    global _DATA_DIR
    if _DATA_DIR is None:
        _DATA_DIR = Path(__file__).resolve().parent / "data" / "xp"
    return _DATA_DIR


def _run_audit(params: dict[str, Any]) -> dict[str, Any]:
    """Validate request params, run one audit, persist it. Raises ValueError."""
    target = str(params.get("target", "")).strip()
    if not target:
        raise ValueError("target is required")
    preset = str(params.get("preset", "both")).strip()
    if preset not in _ALLOWED_PRESETS:
        raise ValueError(f"preset must be one of {_ALLOWED_PRESETS}")
    try:
        timeout = float(params.get("timeout", 3))
    except (TypeError, ValueError):
        raise ValueError("timeout must be a number") from None
    if not 0.5 <= timeout <= 30:
        raise ValueError("timeout must be between 0.5 and 30 seconds")
    ports = str(params.get("ports", "")).strip()
    deep = bool(params.get("deep", False))
    confirm = bool(params.get("confirm_authorized", False))

    auditor = Auditor(
        target=target,
        preset=preset,
        extra_ports=[ports] if ports else [],
        timeout=timeout,
        deep=deep,
        confirm_authorized=confirm,
    )
    # The engine mutates process-global probe settings (timeout, depth, profile,
    # proxy) — audits must not overlap, so the lock spans the whole run + save.
    with _AUDIT_LOCK:
        try:
            report = auditor.run()
        except PermissionError as exc:
            raise PermissionError(str(exc)) from None
        audit_id = storage.save_report(report, deep=deep)
    payload = report_payload(report)
    payload["audit_id"] = audit_id
    return payload


class _Handler(BaseHTTPRequestHandler):
    server_version = "honeypot-auditor-ui/1.0"

    # -- plumbing ---------------------------------------------------------
    def log_message(self, fmt: str, *args) -> None:  # quiet default logging
        pass

    def _send_json(self, obj: Any, status: int = 200) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, body: bytes, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _hostname_from_host_header(host: str) -> str:
        """Extract hostname from a Host header (IPv4, IPv6-bracketed, optional port)."""
        host = (host or "").lower().strip()
        if host.startswith("["):
            end = host.find("]")
            return host[1:end] if end != -1 else host
        if host.count(":") == 1:
            return host.rsplit(":", 1)[0]
        return host

    @staticmethod
    def _hostname_from_url(url: str) -> str:
        hostname = (urlparse(url).hostname or "").lower()
        return hostname

    def _guard(self, *, require_local_origin: bool = False) -> bool:
        """Reject non-local Host headers (DNS rebinding) and foreign Origins (CSRF)."""
        host = (self.headers.get("Host") or "").lower()
        hostname = self._hostname_from_host_header(host)
        if hostname not in _LOCAL_HOSTNAMES:
            # Exact match only: "127.0.0.1.evil.com" must NOT pass a prefix check.
            self._send_json({"error": "local interface only"}, status=403)
            return False
        if require_local_origin:
            origin = (self.headers.get("Origin") or "").strip()
            if origin:
                if self._hostname_from_url(origin) not in _LOCAL_HOSTNAMES:
                    self._send_json({"error": "local origin only"}, status=403)
                    return False
            else:
                # Browsers omit Origin on same-origin GET; for state-changing POSTs
                # they usually send it. When Origin is absent, require Referer (if
                # present) to also be local — curl/tests with neither still work.
                referer = (self.headers.get("Referer") or "").strip()
                if referer and self._hostname_from_url(referer) not in _LOCAL_HOSTNAMES:
                    self._send_json({"error": "local origin only"}, status=403)
                    return False
        return True

    # -- routes -----------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        if not self._guard():
            return
        path = urlsplit(self.path).path
        if path == "/" or path == "/index.html":
            self._send_html(_PAGE)
        elif path.startswith("/audits/"):
            try:
                audit_id = int(path.rsplit("/", 1)[-1])
            except ValueError:
                self._send_json({"error": "bad audit id"}, status=400)
                return
            if storage.get_audit(audit_id) is None:
                self._send_json({"error": "not found"}, status=404)
                return
            self._send_html(_DETAIL_PAGE.replace("__AUDIT_ID__", str(audit_id)))
        elif path.startswith("/static/"):
            # Compare against constant whitelist keys only — never join user input
            # into a filesystem path (CodeQL py/path-injection).
            requested = path.rsplit("/", 1)[-1]
            for safe_name, content_type in _STATIC_TYPES.items():
                if requested != safe_name:
                    continue
                try:
                    body = (_static_dir() / safe_name).read_bytes()
                except OSError:
                    self._send_json({"error": "not found"}, status=404)
                    return
                self._send_bytes(body, content_type)
                return
            self._send_json({"error": "not found"}, status=404)
        elif path == "/api/audits":
            self._send_json({"audits": storage.list_audits(limit=100)})
        elif "/download/" in path and path.startswith("/api/audits/"):
            self._download_report(urlsplit(self.path).path)
        elif path.startswith("/api/audits/"):
            try:
                audit_id = int(path.rsplit("/", 1)[-1])
            except ValueError:
                self._send_json({"error": "bad audit id"}, status=400)
                return
            record = storage.get_audit(audit_id)
            if record is None:
                self._send_json({"error": "not found"}, status=404)
            else:
                self._send_json(record)
        else:
            self._send_json({"error": "not found"}, status=404)

    def _download_report(self, path: str) -> None:
        """GET /api/audits/<id>/download/<json|html|csv|md> as an attachment."""
        from honeypot_auditor.reporters.text_export import (
            build_csv_text,
            build_html,
            build_markdown,
        )

        parts = [p for p in path.strip("/").split("/") if p]
        if len(parts) != 5 or parts[3] != "download":
            self._send_json({"error": "bad download path"}, status=400)
            return
        try:
            audit_id = int(parts[2])
        except ValueError:
            self._send_json({"error": "bad audit id"}, status=400)
            return
        fmt = parts[4]
        # Map path token → (body, content-type, safe extension). Extension is a
        # constant from this table so it never carries raw user path bytes into
        # Content-Disposition (CodeQL py/http-response-splitting).
        exporters = {
            "json": (
                lambda p: json.dumps(p, indent=2).encode("utf-8"),
                "application/json",
                "json",
            ),
            "html": (lambda p: build_html(p).encode("utf-8"), "text/html; charset=utf-8", "html"),
            "csv": (
                lambda p: build_csv_text(p).encode("utf-8"),
                "text/csv; charset=utf-8",
                "csv",
            ),
            "md": (
                lambda p: build_markdown(p).encode("utf-8"),
                "text/markdown; charset=utf-8",
                "md",
            ),
        }
        exporter = exporters.get(fmt)
        if exporter is None:
            self._send_json({"error": "format must be json|html|csv|md"}, status=400)
            return
        record = storage.get_audit(audit_id)
        if record is None:
            self._send_json({"error": "not found"}, status=404)
            return
        build, ctype, ext = exporter
        body = build(record["report"])
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header(
            "Content-Disposition", f'attachment; filename="honeypot-audit-{audit_id}.{ext}"'
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, text: str, status: int = 200) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            # img-src data: is required for XP.css title-bar control SVG icons.
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'",
        )
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 (http.server API)
        # Origin/Referer check blocks cross-site POSTs (e.g. text/plain CSRF) that
        # would otherwise bypass CORS preflight and trigger local audits.
        if not self._guard(require_local_origin=True):
            return
        if urlsplit(self.path).path != "/api/audit":
            self._send_json({"error": "not found"}, status=404)
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length < 0:
                raise ValueError("negative Content-Length")
            params = json.loads(self.rfile.read(min(length, 64 * 1024)) or b"{}")
            if not isinstance(params, dict):
                raise ValueError("JSON body must be an object")
        except (ValueError, json.JSONDecodeError):
            self._send_json({"error": "invalid JSON body"}, status=400)
            return
        try:
            payload = _run_audit(params)
        except PermissionError as exc:
            self._send_json({"error": str(exc)}, status=403)
        except ValueError as exc:
            self._send_json({"error": str(exc)}, status=400)
        except Exception as exc:  # probe transport failures etc.
            self._send_json({"error": f"audit failed: {exc}"}, status=500)
        else:
            self._send_json(payload)


def create_server(port: int = DEFAULT_PORT) -> ThreadingHTTPServer:
    """Bind the UI to 127.0.0.1 only — this is deliberate, do not loosen it."""
    return ThreadingHTTPServer((_BIND_HOST, int(port)), _Handler)


def run_webserver(argv: list[str] | None = None) -> int:
    argv = list(argv or [])
    port = DEFAULT_PORT
    if "--port" in argv:
        idx = argv.index("--port")
        try:
            port = int(argv[idx + 1])
        except (IndexError, ValueError):
            print("serve: --port requires a number", flush=True)
            return 2
    server = create_server(port)
    bound_port = server.server_address[1]
    print(
        f"honeypot-auditor UI → http://127.0.0.1:{bound_port}  (localhost only, Ctrl+C to stop)",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>H-AUDITOR.EXE</title>
<link rel="stylesheet" href="/static/XP.css">
<style>
  body { background: #3a6ea5; padding: 24px 24px 56px; }
  body.modal-open { overflow: hidden; }
  .sr-only {
    position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
    overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0;
  }
  .row { display: flex; gap: 16px; align-items: flex-start; flex-wrap: wrap; }
  .col { flex: 1 1 420px; min-width: 0; }
  fieldset { margin-bottom: 12px; }
  .field-row label[for] { min-width: 90px; }
  .field-row input[type="text"], .field-row select { flex: 1; }
  .field-row input[type="number"] { width: 70px; }
  .tree-host { max-height: 560px; overflow: auto; }
  .tree-host-sm { max-height: 260px; overflow: auto; }
  /* XP.css draws +/- via summary:before; hide the browser's native disclosure marker. */
  ul.tree-view details > summary { list-style: none; }
  ul.tree-view details > summary::-webkit-details-marker { display: none; }
  ul.tree-view details > summary::marker { content: ""; }
  .history-help { color: #444; margin-bottom: 8px; }
  .verdict { font-weight: bold; margin: 6px 0; }
  #status { display: block; margin-bottom: 6px; }
  progress { width: 100%; }
  .download-list { margin-bottom: 10px; }
  .download-list a { margin-right: 12px; }
  .detail-subtitle { margin: 4px 0 10px; color: #444; }
  .detail-section-title { font-weight: bold; margin: 10px 0 6px; }
  pre.json { max-height: 260px; overflow: auto; margin: 0; white-space: pre-wrap; word-break: break-word; }
  .modal-backdrop {
    position: fixed; inset: 0; background: rgba(0, 0, 0, 0.45);
    display: none; align-items: center; justify-content: center; padding: 24px; z-index: 999;
  }
  .modal-backdrop.open { display: flex; }
  .modal-window {
    width: min(760px, 100%); max-height: calc(100vh - 48px);
    display: flex; flex-direction: column;
  }
  .modal-window.maximized { width: calc(100vw - 24px); max-height: calc(100vh - 44px); }
  .modal-content { overflow: auto; }
  .modal-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 12px; }
  .history-item.selected > details > summary { background: #000080; color: #fff; }
  /* Luna taskbar — beat XP.css generic `button` / `button.active` specificity. */
  footer.xp-taskbar {
    position: fixed; left: 0; right: 0; bottom: 0; height: 30px;
    display: flex; align-items: stretch; gap: 0; padding: 0 0 0 2px;
    background: linear-gradient(180deg,
      #1f48b8 0%, #3b7de5 6%, #245edc 12%, #245edc 88%, #1941a5 94%, #0c2d8a 100%);
    box-shadow: inset 0 1px #8cb8f8;
    border-top: 1px solid #0831d9;
    z-index: 998;
    font-family: Tahoma, "Segoe UI", "Pixelated MS Sans Serif", sans-serif;
  }
  footer.xp-taskbar button.xp-start-button {
    align-self: center;
    min-width: 92px; height: 24px; margin: 0 6px 0 0; padding: 0 16px 1px 7px;
    border: 1px solid #1a6a1a; border-radius: 12px / 14px;
    background: linear-gradient(180deg,
      #5fd65f 0%, #3cb83c 18%, #2fa02f 55%, #228022 100%);
    color: #fff; font: italic bold 15px / 22px "Franklin Gothic Medium", "Arial Black", Tahoma, sans-serif;
    letter-spacing: .3px; text-shadow: 1px 1px 1px rgba(0,40,0,.65);
    box-shadow:
      0 0 0 1px #d8c040,
      0 0 0 2px #8a7020,
      inset 1px 1px 0 rgba(255,255,255,.55),
      inset -1px -1px 0 rgba(0,0,0,.28);
    display: inline-flex; align-items: center; justify-content: flex-start; gap: 6px;
    cursor: default;
  }
  footer.xp-taskbar button.xp-start-button::before {
    content: ""; width: 15px; height: 15px; flex: 0 0 15px;
    border-radius: 1px;
    background:
      linear-gradient(90deg, #f24537 50%, #7cba3d 50%),
      linear-gradient(90deg, #00a4ef 50%, #ffb900 50%);
    background-size: 100% 50%;
    background-position: top, bottom;
    background-repeat: no-repeat;
    box-shadow: 0 0 0 1px rgba(0,0,0,.4), inset 0 0 0 1px rgba(255,255,255,.2);
    transform: rotate(-8deg);
  }
  footer.xp-taskbar button.xp-start-button:hover {
    background: linear-gradient(180deg,
      #72e072 0%, #48c848 18%, #38b038 55%, #2a902a 100%);
  }
  footer.xp-taskbar button.xp-start-button:active,
  footer.xp-taskbar button.xp-start-button.active {
    padding-top: 1px;
    background: linear-gradient(180deg,
      #228022 0%, #2a902a 30%, #1e701e 100%);
    box-shadow:
      0 0 0 1px #b8a030,
      0 0 0 2px #6a5820,
      inset 1px 1px 2px rgba(0,0,0,.45);
  }
  footer.xp-taskbar .xp-task-buttons {
    flex: 1; display: flex; align-items: center; gap: 3px; min-width: 0;
    padding: 3px 4px 3px 8px;
    border-left: 1px solid rgba(0,0,0,.28);
    box-shadow: inset 1px 0 0 rgba(255,255,255,.22);
  }
  footer.xp-taskbar button.xp-task-button {
    min-width: 148px; max-width: 220px; height: 22px; margin: 0;
    padding: 0 10px 0 6px; overflow: hidden;
    text-overflow: ellipsis; white-space: nowrap; text-align: left;
    font: bold 11px / 20px Tahoma, "Segoe UI", sans-serif;
    color: #fff !important; border-radius: 3px;
    border: 1px solid #0d3588;
    background: linear-gradient(180deg,
      #6ea0e8 0%, #4580d8 14%, #3268c0 60%, #2858a8 100%) !important;
    box-shadow:
      inset 1px 1px 0 rgba(255,255,255,.5),
      inset 0 -1px 0 rgba(0,0,0,.18) !important;
    display: inline-flex; align-items: center; gap: 6px; cursor: default;
    outline: none;
  }
  footer.xp-taskbar button.xp-task-button[hidden] { display: none !important; }
  footer.xp-taskbar button.xp-task-button::before {
    content: ""; width: 14px; height: 14px; flex: 0 0 14px;
    border: 1px solid #7a5a08;
    background:
      linear-gradient(135deg, #fff6b0 0%, #f0c040 45%, #c88810 100%);
    box-shadow: inset 1px 1px 0 rgba(255,255,255,.55);
  }
  footer.xp-taskbar button.xp-task-button:hover {
    background: linear-gradient(180deg,
      #82b4f4 0%, #5690e4 14%, #3e78d0 60%, #3268b8 100%) !important;
  }
  footer.xp-taskbar button.xp-task-button.active,
  footer.xp-taskbar button.xp-task-button[aria-current="page"] {
    color: #fff !important;
    border-color: #062868;
    background: linear-gradient(180deg,
      #163f90 0%, #1c52b8 22%, #1748a0 78%, #123c88 100%) !important;
    box-shadow:
      inset 1px 1px 3px rgba(0,0,0,.55),
      inset -1px -1px 0 rgba(255,255,255,.06) !important;
    padding-top: 1px;
  }
  footer.xp-taskbar button.xp-task-button.minimized {
    color: #eef4ff !important;
    background: linear-gradient(180deg,
      #8eb0e0 0%, #6a92d0 20%, #547cb8 70%, #4568a0 100%) !important;
    box-shadow:
      inset 1px 1px 0 rgba(255,255,255,.4),
      inset -1px -1px 0 rgba(0,0,0,.15) !important;
  }
  footer.xp-taskbar button.xp-task-button:focus {
    outline: none; box-shadow:
      inset 1px 1px 0 rgba(255,255,255,.5),
      inset 0 -1px 0 rgba(0,0,0,.18),
      0 0 0 1px #fff59a !important;
  }
  footer.xp-taskbar .xp-task-tray {
    display: flex; align-items: center; gap: 8px; margin: 2px 2px 2px 4px;
    padding: 0 10px 0 12px; color: #fff;
    background: linear-gradient(180deg,
      #16b4f0 0%, #1090e0 35%, #0c78c8 100%);
    border: 1px solid #0a4a8a;
    border-left-color: #0868a8;
    box-shadow:
      inset 1px 1px 0 rgba(255,255,255,.35),
      inset -1px -1px 0 rgba(0,0,0,.2);
    white-space: nowrap; font-size: 11px; font-weight: 600;
    text-shadow: 1px 1px 0 rgba(0,0,0,.35);
  }
  footer.xp-taskbar .xp-task-tray-label { font-size: 11px; opacity: .95; }
  footer.xp-taskbar #taskclock {
    font-variant-numeric: tabular-nums; min-width: 2.6em; text-align: right;
  }
</style>
</head>
<body>
  <div class="window" style="max-width: 1100px; margin: 0 auto;">
    <div class="title-bar">
      <div class="title-bar-text">H-AUDITOR.EXE&nbsp;&mdash;&nbsp;Does This Look Like A Honeypot? (DTLLAH)</div>
      <div class="title-bar-controls">
        <button type="button" aria-label="Minimize"></button>
        <button type="button" aria-label="Maximize"></button>
        <button type="button" aria-label="Close"></button>
      </div>
    </div>
    <main class="window-body">
      <div class="row">
        <div class="col">
          <fieldset>
            <legend>New audit</legend>
            <div class="field-row">
              <label for="target">Target</label>
              <input id="target" type="text" placeholder="127.0.0.1 · host · 192.168.1.0/24">
            </div>
            <div class="field-row">
              <label for="preset">Preset</label>
              <select id="preset">
                <option value="both" selected>both (IANA + lab)</option>
                <option value="iana">iana</option>
                <option value="docker-research">docker-research</option>
              </select>
            </div>
            <div class="field-row">
              <label for="ports">Ports</label>
              <input id="ports" type="text" placeholder="optional: 22,8081">
            </div>
            <div class="field-row">
              <label for="timeout">Timeout</label>
              <input id="timeout" type="number" value="3" min="1" max="30" step="0.5">
            </div>
            <div class="field-row">
              <input id="deep" type="checkbox">
              <label for="deep">Deep probes</label>
            </div>
            <div class="field-row">
              <input id="authorized" type="checkbox">
              <label for="authorized">Target is public &amp; I am authorized</label>
            </div>
            <div class="field-row" style="justify-content: flex-end;">
              <button id="run" type="button">Run audit</button>
            </div>
          </fieldset>

          <fieldset>
            <legend>Result</legend>
            <output id="status">Idle. Target only what you are authorized to test.</output>
            <div class="verdict" id="verdict" aria-live="polite"></div>
            <progress id="scorebar" max="100" value="0" hidden></progress>
            <p id="meta" style="margin-top:6px"></p>
          </fieldset>

          <fieldset>
            <legend>Triggered tells</legend>
            <div id="tells" class="tree-host-sm">
              <ul class="tree-view"><li>—</li></ul>
            </div>
          </fieldset>
        </div>

        <div class="col">
          <fieldset>
            <legend>Audit history (local SQLite)</legend>
            <div class="history-help">
              History is grouped by IP. Expand a host to see its audits newest-first, then Open one.
              Press Escape or click the backdrop to close the detail window.
            </div>
            <div id="history" class="tree-host">
              <ul class="tree-view"><li>Loading…</li></ul>
            </div>
          </fieldset>
        </div>
      </div>
    </main>
    <div class="status-bar">
      <p class="status-bar-field" id="statusbar">localhost-only UI · probes are non-destructive · respect the sysop</p>
      <p class="status-bar-field" id="statusscore">Honeyscore: —</p>
      <p class="status-bar-field">XP.css tree view</p>
    </div>
  </div>

  <div class="modal-backdrop" id="detailmodal" hidden>
    <section class="window modal-window" id="detailwindow" role="dialog" aria-modal="true" aria-labelledby="detailtitle" aria-describedby="detailsubtitle">
      <div class="title-bar">
        <div class="title-bar-text" id="detailtitle">Stored audit</div>
        <div class="title-bar-controls">
          <button id="detailminimize" type="button" aria-label="Minimize" title="Minimize"></button>
          <button id="detailmaximize" type="button" aria-label="Maximize" title="Maximize"></button>
          <button id="detailclose" type="button" aria-label="Close" title="Close"></button>
        </div>
      </div>
      <div class="window-body modal-content">
        <p class="detail-subtitle" id="detailsubtitle">Select a saved audit to inspect it.</p>
        <nav class="download-list" id="downloads" aria-label="Stored audit downloads"></nav>
        <ul class="tree-view" id="detailsummary">
          <li>Score: <strong id="detailscore">—</strong></li>
          <li>Verdict: <strong id="detailverdict">—</strong></li>
          <li>Confidence: <span id="detailconfidence">—</span></li>
          <li>Target: <span id="detailtarget">—</span></li>
          <li>Saved: <span id="detailwhen">—</span></li>
          <li>Mode: <span id="detailmode">—</span></li>
        </ul>
        <h2 class="detail-section-title" id="detailtellslabel">Triggered tells</h2>
        <div id="detailtells" class="tree-host-sm">
          <ul class="tree-view"><li>Select a saved audit to inspect it.</li></ul>
        </div>
        <details id="rawjsonbox">
          <summary>Raw JSON report</summary>
          <pre class="json" id="detail"></pre>
        </details>
        <div class="modal-actions">
          <button id="detailfooter-minimize" type="button">Minimize</button>
          <button id="detailfooter-close" type="button">Close</button>
        </div>
      </div>
    </section>
  </div>

  <footer class="xp-taskbar" aria-label="Windows XP taskbar">
    <button class="xp-start-button" type="button" aria-label="Start menu">Start</button>
    <nav class="xp-task-buttons" aria-label="Open windows">
      <button class="xp-task-button active" type="button" aria-current="page">H-AUDITOR.EXE</button>
      <button class="xp-task-button" id="taskbaraudit" type="button" hidden>Stored audit detail</button>
    </nav>
    <section class="xp-task-tray" aria-label="System tray">
      <span class="xp-task-tray-label">Localhost</span>
      <time id="taskclock" aria-live="off">--:--</time>
    </section>
  </footer>

<script>
"use strict";
function esc(el, text) { el.textContent = text; }
let selectedAuditId = null;
let lastFocusedHistoryRow = null;

function fmtScore(score) { return Number(score).toFixed(1) + "%"; }
function verdictColor(score) {
  return score >= 60 ? "#8b0000" : score >= 30 ? "#8a6d00" : "#0a5c0a";
}
function formatWhen(value) {
  return String(value || "").replace("T", " ").replace("+00:00", " UTC");
}
function liText(text) {
  const li = document.createElement("li");
  esc(li, text);
  return li;
}
function appendMeta(list, label, value) {
  const li = document.createElement("li");
  esc(li, label + ": " + value);
  list.appendChild(li);
}

function renderIndicatorTree(host, list, emptyText) {
  host.textContent = "";
  const items = Array.isArray(list) ? list : [];
  const tree = document.createElement("ul");
  tree.className = "tree-view";
  if (!items.length) {
    tree.appendChild(liText(emptyText));
    host.appendChild(tree);
    return;
  }
  const root = document.createElement("li");
  const details = document.createElement("details");
  details.open = true;
  const summary = document.createElement("summary");
  esc(summary, "Triggered tells (" + items.length + ")");
  details.appendChild(summary);
  const children = document.createElement("ul");
  for (const t of items) {
    const item = document.createElement("li");
    const nest = document.createElement("details");
    const nestSummary = document.createElement("summary");
    esc(nestSummary, t.id || "tell");
    nest.appendChild(nestSummary);
    const meta = document.createElement("ul");
    appendMeta(meta, "Finding", t.title || "—");
    appendMeta(meta, "Detail", t.detail || "—");
    if (t.fidelity) appendMeta(meta, "Fidelity", t.fidelity);
    if (t.protocol) appendMeta(meta, "Protocol", t.protocol);
    nest.appendChild(meta);
    item.appendChild(nest);
    children.appendChild(item);
  }
  details.appendChild(children);
  root.appendChild(details);
  tree.appendChild(root);
  host.appendChild(tree);
}

function highlightSelectedHistoryRow() {
  document.querySelectorAll(".history-item").forEach((row) => {
    row.classList.toggle("selected", Number(row.dataset.auditId) === selectedAuditId);
  });
}

function syncTaskbar() {
  const button = document.getElementById("taskbaraudit");
  const modalOpen = document.getElementById("detailmodal").classList.contains("open");
  const maximized = document.getElementById("detailwindow").classList.contains("maximized");
  if (selectedAuditId === null) {
    button.hidden = true;
    button.classList.remove("active", "minimized");
    esc(button, "Stored audit detail");
    return;
  }
  button.hidden = false;
  esc(button, "Audit #" + selectedAuditId);
  button.classList.toggle("active", modalOpen);
  button.classList.toggle("minimized", !modalOpen);
  button.setAttribute("aria-pressed", modalOpen ? "true" : "false");
  const maxButton = document.getElementById("detailmaximize");
  maxButton.setAttribute("aria-label", maximized ? "Restore" : "Maximize");
  maxButton.title = maximized ? "Restore" : "Maximize";
}

function updateTaskClock() {
  const now = new Date();
  esc(document.getElementById("taskclock"),
      String(now.getHours()).padStart(2, "0") + ":" + String(now.getMinutes()).padStart(2, "0"));
}

function hideDetailModal() {
  document.getElementById("detailmodal").classList.remove("open");
  document.getElementById("detailmodal").hidden = true;
  document.body.classList.remove("modal-open");
}
function showDetailModal() {
  document.getElementById("detailmodal").classList.add("open");
  document.getElementById("detailmodal").hidden = false;
  document.body.classList.add("modal-open");
}
function minimizeDetailModal() { hideDetailModal(); syncTaskbar(); }
function closeDetailModal() {
  const focusTarget = lastFocusedHistoryRow;
  hideDetailModal();
  selectedAuditId = null;
  lastFocusedHistoryRow = null;
  document.getElementById("detailwindow").classList.remove("maximized");
  highlightSelectedHistoryRow();
  syncTaskbar();
  if (focusTarget) focusTarget.focus();
}
function toggleDetailMaximize() {
  document.getElementById("detailwindow").classList.toggle("maximized");
  syncTaskbar();
}
function restoreDetailModal() {
  if (selectedAuditId === null) return;
  showDetailModal();
  syncTaskbar();
  document.getElementById("detailclose").focus();
}

function openDetail(id, triggerRow) {
  fetch("/api/audits/" + id).then(async (r) => {
    const rec = await r.json();
    if (!r.ok) throw new Error(rec.error || String(r.status));
    return rec;
  }).then((rec) => {
    selectedAuditId = id;
    lastFocusedHistoryRow = triggerRow || null;
    highlightSelectedHistoryRow();
    esc(document.getElementById("detailtitle"), "Audit #" + id + " — " + rec.threat_level);
    esc(document.getElementById("detailsubtitle"),
        "saved " + formatWhen(rec.created_at) + " · " + rec.triggered_count + " tell(s)");
    const scoreEl = document.getElementById("detailscore");
    esc(scoreEl, fmtScore(rec.score));
    scoreEl.style.color = verdictColor(rec.score);
    const verdictEl = document.getElementById("detailverdict");
    esc(verdictEl, rec.threat_level);
    verdictEl.style.color = verdictColor(rec.score);
    esc(document.getElementById("detailconfidence"), rec.confidence || "—");
    esc(document.getElementById("detailtarget"), rec.target + " (" + rec.resolved_ip + ")");
    esc(document.getElementById("detailwhen"), formatWhen(rec.created_at));
    esc(document.getElementById("detailmode"), rec.deep ? "Deep probes" : "Basic");
    const dl = document.getElementById("downloads");
    dl.textContent = "";
    for (const fmt of ["json", "html", "csv", "md"]) {
      const a = document.createElement("a");
      a.href = "/api/audits/" + id + "/download/" + fmt;
      a.textContent = fmt.toUpperCase();
      dl.appendChild(a);
    }
    renderIndicatorTree(document.getElementById("detailtells"), rec.report.triggered || [],
                        "No honeypot tells triggered.");
    document.getElementById("detail").textContent = JSON.stringify(rec.report, null, 2);
    document.getElementById("rawjsonbox").open = false;
    document.getElementById("detailwindow").classList.remove("maximized");
    showDetailModal();
    syncTaskbar();
    esc(document.getElementById("statusbar"),
        "showing stored audit #" + id + " · " + rec.target + " · " + rec.score + "%");
    esc(document.getElementById("statusscore"), "Honeyscore: " + fmtScore(rec.score));
    document.getElementById("detailclose").focus();
  }).catch((err) => {
    esc(document.getElementById("statusbar"), "error loading stored audit #" + id + ": " + err);
  });
}

function groupAuditsByIp(audits) {
  const groups = new Map();
  for (const a of audits) {
    const ip = String(a.resolved_ip || a.target || "unknown").trim() || "unknown";
    if (!groups.has(ip)) groups.set(ip, []);
    groups.get(ip).push(a);
  }
  for (const list of groups.values()) {
    list.sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || ""))
      || (Number(b.id) - Number(a.id)));
  }
  return [...groups.entries()].sort((a, b) => {
    const aLatest = a[1][0]?.created_at || "";
    const bLatest = b[1][0]?.created_at || "";
    return String(bLatest).localeCompare(String(aLatest)) || a[0].localeCompare(b[0]);
  });
}

function appendAuditHistoryNode(list, a) {
  const item = document.createElement("li");
  item.className = "history-item";
  item.dataset.auditId = String(a.id);
  const details = document.createElement("details");
  details.open = selectedAuditId === a.id;
  const summary = document.createElement("summary");
  esc(summary, formatWhen(a.created_at) + " · #" + a.id + " · " + fmtScore(a.score)
      + " · " + (a.threat_level || "—"));
  details.appendChild(summary);
  const meta = document.createElement("ul");
  if (a.target && a.target !== a.resolved_ip) {
    appendMeta(meta, "Target", a.target);
  }
  appendMeta(meta, "Verdict", a.threat_level || "—");
  appendMeta(meta, "Tells", String(a.triggered_count));
  appendMeta(meta, "Mode", a.deep ? "Deep probes" : "Basic");
  const action = document.createElement("li");
  const openButton = document.createElement("button");
  openButton.type = "button";
  openButton.className = "history-open";
  openButton.setAttribute("aria-label", "Open saved audit " + a.id + " in the details modal");
  esc(openButton, "Open");
  openButton.addEventListener("click", (event) => {
    event.stopPropagation();
    openDetail(a.id, openButton);
  });
  action.appendChild(openButton);
  meta.appendChild(action);
  details.appendChild(meta);
  item.appendChild(details);
  list.appendChild(item);
}

function loadHistory() {
  fetch("/api/audits").then(r => r.json()).then(data => {
    const host = document.getElementById("history");
    host.textContent = "";
    const tree = document.createElement("ul");
    tree.className = "tree-view";
    if (!data.audits.length) {
      tree.appendChild(liText("No audits saved yet."));
      host.appendChild(tree);
      return;
    }
    const grouped = groupAuditsByIp(data.audits);
    const root = document.createElement("li");
    const folder = document.createElement("details");
    folder.open = true;
    const folderSummary = document.createElement("summary");
    esc(folderSummary, "Saved audits (" + data.audits.length + " across "
        + grouped.length + " IP" + (grouped.length === 1 ? "" : "s") + ")");
    folder.appendChild(folderSummary);
    const ipList = document.createElement("ul");
    for (const [ip, audits] of grouped) {
      const ipItem = document.createElement("li");
      const ipDetails = document.createElement("details");
      const hasSelected = audits.some((a) => a.id === selectedAuditId);
      ipDetails.open = hasSelected || grouped.length === 1;
      const latest = audits[0];
      const ipSummary = document.createElement("summary");
      esc(ipSummary, ip + " · " + audits.length + " audit"
          + (audits.length === 1 ? "" : "s")
          + " · latest " + fmtScore(latest.score) + " · " + (latest.threat_level || "—"));
      ipDetails.appendChild(ipSummary);
      const auditList = document.createElement("ul");
      for (const a of audits) {
        appendAuditHistoryNode(auditList, a);
      }
      ipDetails.appendChild(auditList);
      ipItem.appendChild(ipDetails);
      ipList.appendChild(ipItem);
    }
    folder.appendChild(ipList);
    root.appendChild(folder);
    tree.appendChild(root);
    host.appendChild(tree);
    highlightSelectedHistoryRow();
  }).catch(err => {
    const host = document.getElementById("history");
    host.textContent = "";
    const tree = document.createElement("ul");
    tree.className = "tree-view";
    tree.appendChild(liText("history load failed: " + err));
    host.appendChild(tree);
  });
}

function setProgress(score, indeterminate) {
  const bar = document.getElementById("scorebar");
  bar.hidden = false;
  if (indeterminate) {
    bar.removeAttribute("value");
    return;
  }
  bar.max = 100;
  bar.value = Math.max(0, Math.min(100, Number(score) || 0));
}

function renderReport(report) {
  const verdict = document.getElementById("verdict");
  esc(verdict, report.threat_level + "  (" + fmtScore(report.score) + ")");
  verdict.style.color = verdictColor(report.score);
  setProgress(report.score, false);
  esc(document.getElementById("meta"),
      "target " + report.target + " (" + report.resolved_ip + ") · saved as audit #" + report.audit_id);
  esc(document.getElementById("statusscore"), "Honeyscore: " + fmtScore(report.score));
  renderIndicatorTree(document.getElementById("tells"), report.triggered || [],
                      "No honeypot tells triggered.");
}

document.getElementById("run").addEventListener("click", () => {
  const status = document.getElementById("status");
  const params = {
    target: document.getElementById("target").value,
    preset: document.getElementById("preset").value,
    ports: document.getElementById("ports").value,
    timeout: parseFloat(document.getElementById("timeout").value || "3"),
    deep: document.getElementById("deep").checked,
    confirm_authorized: document.getElementById("authorized").checked,
  };
  if (!params.target.trim()) { esc(status, "Enter a target first."); return; }
  esc(status, "Probing… this can take up to a few minutes. Probes are non-destructive.");
  setProgress(0, true);
  document.getElementById("run").disabled = true;
  fetch("/api/audit", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(params) })
    .then(async r => {
      const data = await r.json();
      if (!r.ok) { esc(status, "Error: " + (data.error || r.status)); return; }
      esc(status, "Done.");
      renderReport(data);
      loadHistory();
    })
    .catch(err => esc(status, "Request failed: " + err))
    .finally(() => { document.getElementById("run").disabled = false; });
});

document.getElementById("detailclose").addEventListener("click", closeDetailModal);
document.getElementById("detailminimize").addEventListener("click", minimizeDetailModal);
document.getElementById("detailmaximize").addEventListener("click", toggleDetailMaximize);
document.getElementById("detailfooter-close").addEventListener("click", closeDetailModal);
document.getElementById("detailfooter-minimize").addEventListener("click", minimizeDetailModal);
document.getElementById("taskbaraudit").addEventListener("click", () => {
  if (document.getElementById("detailmodal").classList.contains("open")) minimizeDetailModal();
  else restoreDetailModal();
});
document.getElementById("detailmodal").addEventListener("click", (event) => {
  if (event.target === document.getElementById("detailmodal")) closeDetailModal();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && document.getElementById("detailmodal").classList.contains("open")) {
    closeDetailModal();
  }
});

updateTaskClock();
window.setInterval(updateTaskClock, 30000);
loadHistory();
</script>
</body>
</html>
"""

_DETAIL_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Stored Audit Detail</title>
<link rel="stylesheet" href="/static/XP.css">
<style>
  body { background: #3a6ea5; padding: 24px; }
  .window { max-width: 1040px; margin: 0 auto; }
  .toolbar { display: flex; justify-content: space-between; gap: 12px; align-items: center; flex-wrap: wrap; margin-bottom: 10px; }
  .toolbar-actions a { margin-right: 12px; }
  .audit-title { font-weight: bold; margin-bottom: 2px; }
  .audit-subtitle { color: #444; margin-bottom: 10px; }
  progress { width: 100%; margin-bottom: 12px; }
  .section-title { font-weight: bold; margin-bottom: 6px; }
  .tree-host { max-height: 300px; overflow: auto; }
  ul.tree-view details > summary { list-style: none; }
  ul.tree-view details > summary::-webkit-details-marker { display: none; }
  ul.tree-view details > summary::marker { content: ""; }
  pre.json { max-height: 300px; overflow: auto; margin: 0; white-space: pre-wrap; word-break: break-word; }
</style>
</head>
<body>
  <div class="window">
    <div class="title-bar">
      <div class="title-bar-text">Stored Audit Detail</div>
      <div class="title-bar-controls">
        <button type="button" aria-label="Minimize"></button>
        <button type="button" aria-label="Maximize"></button>
        <button type="button" aria-label="Close"></button>
      </div>
    </div>
    <main class="window-body">
      <div class="toolbar">
        <div>
          <div class="audit-title" id="title">Audit detail</div>
          <div class="audit-subtitle" id="subtitle">Loading stored audit…</div>
        </div>
        <div class="toolbar-actions">
          <a href="/" id="backlink">Back to dashboard</a>
          <span id="downloads"></span>
        </div>
      </div>
      <progress id="scorebar" max="100" value="0"></progress>
      <ul class="tree-view" id="summary">
        <li>Score: <strong id="score">—</strong></li>
        <li>Verdict: <strong id="verdict">—</strong></li>
        <li>Confidence: <span id="confidence">—</span></li>
        <li>Target: <span id="target">—</span></li>
        <li>Saved: <span id="saved">—</span></li>
        <li>Mode: <span id="mode">—</span></li>
      </ul>
      <fieldset>
        <legend>Triggered tells</legend>
        <div id="tells" class="tree-host">
          <ul class="tree-view"><li>Loading…</li></ul>
        </div>
      </fieldset>
      <fieldset>
        <legend>Raw JSON report</legend>
        <ul class="tree-view">
          <li>
            <details>
              <summary>Show raw JSON</summary>
              <ul><li><pre class="json" id="rawjson"></pre></li></ul>
            </details>
          </li>
        </ul>
      </fieldset>
    </main>
    <div class="status-bar">
      <p class="status-bar-field" id="statusbar">stored audit viewer · localhost only</p>
      <p class="status-bar-field" id="statusscore">Honeyscore: —</p>
    </div>
  </div>
<script>
"use strict";
const AUDIT_ID = __AUDIT_ID__;
function esc(el, text) { el.textContent = text; }
function fmtScore(score) { return Number(score).toFixed(1) + "%"; }
function verdictColor(score) {
  return score >= 60 ? "#8b0000" : score >= 30 ? "#8a6d00" : "#0a5c0a";
}
function formatWhen(value) {
  return String(value || "").replace("T", " ").replace("+00:00", " UTC");
}
function liText(text) {
  const li = document.createElement("li");
  esc(li, text);
  return li;
}
function appendMeta(list, label, value) {
  const li = document.createElement("li");
  esc(li, label + ": " + value);
  list.appendChild(li);
}
function renderIndicatorTree(host, list) {
  host.textContent = "";
  const items = Array.isArray(list) ? list : [];
  const tree = document.createElement("ul");
  tree.className = "tree-view";
  if (!items.length) {
    tree.appendChild(liText("No honeypot tells triggered."));
    host.appendChild(tree);
    return;
  }
  const root = document.createElement("li");
  const details = document.createElement("details");
  details.open = true;
  const summary = document.createElement("summary");
  esc(summary, "Triggered tells (" + items.length + ")");
  details.appendChild(summary);
  const children = document.createElement("ul");
  for (const t of items) {
    const item = document.createElement("li");
    const nest = document.createElement("details");
    const nestSummary = document.createElement("summary");
    esc(nestSummary, t.id || "tell");
    nest.appendChild(nestSummary);
    const meta = document.createElement("ul");
    appendMeta(meta, "Finding", t.title || "—");
    appendMeta(meta, "Detail", t.detail || "—");
    if (t.fidelity) appendMeta(meta, "Fidelity", t.fidelity);
    if (t.protocol) appendMeta(meta, "Protocol", t.protocol);
    nest.appendChild(meta);
    item.appendChild(nest);
    children.appendChild(item);
  }
  details.appendChild(children);
  root.appendChild(details);
  tree.appendChild(root);
  host.appendChild(tree);
}
function loadAudit() {
  fetch("/api/audits/" + AUDIT_ID).then(async (r) => {
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || String(r.status));
    return data;
  }).then((rec) => {
    document.title = "Audit #" + AUDIT_ID + " — " + rec.threat_level;
    esc(document.getElementById("title"), "Audit #" + AUDIT_ID + " — " + rec.threat_level);
    esc(document.getElementById("subtitle"),
        "saved " + formatWhen(rec.created_at) + " · " + rec.triggered_count + " tell(s)");
    const scoreEl = document.getElementById("score");
    esc(scoreEl, fmtScore(rec.score));
    scoreEl.style.color = verdictColor(rec.score);
    const verdictEl = document.getElementById("verdict");
    esc(verdictEl, rec.threat_level);
    verdictEl.style.color = verdictColor(rec.score);
    esc(document.getElementById("confidence"), rec.confidence || "—");
    esc(document.getElementById("target"), rec.target + " (" + rec.resolved_ip + ")");
    esc(document.getElementById("saved"), formatWhen(rec.created_at));
    esc(document.getElementById("mode"), rec.deep ? "Deep probes" : "Basic");
    document.getElementById("scorebar").value = Math.min(100, rec.score);
    renderIndicatorTree(document.getElementById("tells"), rec.report.triggered || []);
    esc(document.getElementById("rawjson"), JSON.stringify(rec.report, null, 2));
    const downloads = document.getElementById("downloads");
    downloads.textContent = "";
    for (const fmt of ["json", "html", "csv", "md"]) {
      const link = document.createElement("a");
      link.href = "/api/audits/" + AUDIT_ID + "/download/" + fmt;
      link.textContent = fmt.toUpperCase();
      downloads.appendChild(link);
    }
    esc(document.getElementById("statusbar"),
        "showing stored audit #" + AUDIT_ID + " · " + rec.target + " · " + rec.score + "%");
    esc(document.getElementById("statusscore"), "Honeyscore: " + fmtScore(rec.score));
  }).catch((err) => {
    esc(document.getElementById("title"), "Audit #" + AUDIT_ID);
    esc(document.getElementById("subtitle"), "Could not load stored audit.");
    const host = document.getElementById("tells");
    host.textContent = "";
    const tree = document.createElement("ul");
    tree.className = "tree-view";
    tree.appendChild(liText("Error loading audit detail: " + err));
    host.appendChild(tree);
    esc(document.getElementById("statusbar"), "error loading stored audit #" + AUDIT_ID);
  });
}
loadAudit();
</script>
</body>
</html>
"""

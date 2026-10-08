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
        from pathlib import Path

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
            body = _PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'",
            )
            self.end_headers()
            self.wfile.write(body)
        elif path.startswith("/static/"):
            name = path.rsplit("/", 1)[-1]
            content_type = _STATIC_TYPES.get(name)
            if content_type is None:
                self._send_json({"error": "not found"}, status=404)
                return
            try:
                body = (_static_dir() / name).read_bytes()
            except OSError:
                self._send_json({"error": "not found"}, status=404)
                return
            self._send_bytes(body, content_type)
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
        record = storage.get_audit(audit_id)
        if record is None:
            self._send_json({"error": "not found"}, status=404)
            return
        payload = record["report"]
        if fmt == "json":
            body, ctype = json.dumps(payload, indent=2).encode("utf-8"), "application/json"
        elif fmt == "html":
            body, ctype = build_html(payload).encode("utf-8"), "text/html; charset=utf-8"
        elif fmt == "csv":
            body, ctype = build_csv_text(payload).encode("utf-8"), "text/csv; charset=utf-8"
        elif fmt == "md":
            body, ctype = build_markdown(payload).encode("utf-8"), "text/markdown; charset=utf-8"
        else:
            self._send_json({"error": "format must be json|html|csv|md"}, status=400)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header(
            "Content-Disposition", f'attachment; filename="honeypot-audit-{audit_id}.{fmt}"'
        )
        self.send_header("X-Content-Type-Options", "nosniff")
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
  body { background: #3a6ea5; padding: 24px; }
  .row { display: flex; gap: 16px; align-items: flex-start; flex-wrap: wrap; }
  .col { flex: 1 1 420px; }
  fieldset { margin-bottom: 12px; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th, td { text-align: left; padding: 2px 6px; border-bottom: 1px solid #dfdfdf; cursor: pointer; }
  tr:hover td { background: #000080; color: #fff; }
  .score-bar { height: 20px; background: #dfdfdf; border: 1px solid #808080; position: relative; }
  .score-fill { height: 100%; background: repeating-linear-gradient(90deg,#0a5c0a 0 8px,#0d7a0d 8px 16px); }
  .verdict { font-weight: bold; margin: 6px 0; }
  #status { padding: 4px 8px; }
  pre.json { max-height: 420px; overflow: auto; }
  .title-bar-controls button { min-width: 0; }
</style>
</head>
<body>
  <div class="window" style="max-width: 1100px; margin: 0 auto;">
    <div class="title-bar">
      <div class="title-bar-text">H-AUDITOR.EXE&nbsp;&mdash;&nbsp;Does This Look Like An Honeypot? (DTLLAH)</div>
      <div class="title-bar-controls"><button aria-label="Minimize"></button><button aria-label="Maximize"></button><button aria-label="Close"></button></div>
    </div>
    <div class="window-body">
      <div class="row">
        <div class="col">
          <fieldset><legend>New audit</legend>
            <div class="field-row" style="justify-content: flex-start;"><label for="target" style="width: 90px;">Target</label>
              <input id="target" type="text" placeholder="127.0.0.1 · host · 192.168.1.0/24" style="flex:1"></div>
            <div class="field-row" style="justify-content: flex-start;"><label for="preset" style="width: 90px;">Preset</label>
              <select id="preset"><option value="both">both (IANA + lab)</option><option value="iana">iana</option><option value="docker-research">docker-research</option></select></div>
            <div class="field-row" style="justify-content: flex-start;"><label for="ports" style="width: 90px;">Ports</label>
              <input id="ports" type="text" placeholder="optional: 22,8081" style="flex:1"></div>
            <div class="field-row" style="justify-content: flex-start;"><label for="timeout" style="width: 90px;">Timeout</label>
              <input id="timeout" type="number" value="3" min="1" max="30" step="0.5" style="width: 70px">
              <label><input id="deep" type="checkbox"> Deep probes</label></div>
            <div class="field-row" style="justify-content: flex-start;"><label><input id="authorized" type="checkbox"> Target is public &amp; I am authorized</label></div>
            <div class="field-row" style="justify-content: flex-end;"><button id="run">Run audit</button></div>
          </fieldset>
          <fieldset><legend>Result</legend>
            <div id="status">Idle. Target only what you are authorized to test.</div>
            <div class="verdict" id="verdict"></div>
            <div class="score-bar" id="scorebar" style="display:none"><div class="score-fill" id="scorefill" style="width:0%"></div></div>
            <div id="meta" style="margin-top:6px"></div>
          </fieldset>
          <fieldset><legend>Triggered tells</legend>
            <div id="tells">—</div>
          </fieldset>
        </div>
        <div class="col">
          <fieldset><legend>Audit history (local SQLite)</legend>
            <div id="history" style="max-height: 560px; overflow: auto;">—</div>
          </fieldset>
        </div>
      </div>
      <fieldset id="detailbox" style="display:none"><legend>Stored report detail</legend>
        <div class="field-row" style="justify-content: flex-start; margin-bottom: 6px;">
          <label>Download report:</label>
          <span id="downloads"></span>
        </div>
        <pre class="json" id="detail"></pre>
      </fieldset>
    </div>
    <div class="status-bar"><p class="status-bar-field" id="statusbar">localhost-only UI · probes are non-destructive · respect the sysop</p></div>
  </div>
<script>
"use strict";
function esc(el, text) { el.textContent = text; }  // never innerHTML with report data

function loadHistory() {
  fetch("/api/audits").then(r => r.json()).then(data => {
    const host = document.getElementById("history");
    host.textContent = "";
    if (!data.audits.length) { esc(host, "No audits saved yet."); return; }
    const table = document.createElement("table");
    const head = table.insertRow();
    for (const label of ["id", "when", "target", "score", "verdict", "tells"]) {
      const th = document.createElement("th"); esc(th, label); head.appendChild(th);
    }
    for (const a of data.audits) {
      const row = table.insertRow();
      row.addEventListener("click", () => openDetail(a.id));
      for (const key of ["id", "created_at", "target", "score", "threat_level", "triggered_count"]) {
        const td = row.insertCell(); esc(td, String(a[key]));
      }
    }
    host.appendChild(table);
  }).catch(err => esc(document.getElementById("history"), "history load failed: " + err));
}

function openDetail(id) {
  fetch("/api/audits/" + id).then(r => r.json()).then(rec => {
    document.getElementById("detailbox").style.display = "";
    const dl = document.getElementById("downloads");
    dl.textContent = "";
    for (const fmt of ["json", "html", "csv", "md"]) {
      const a = document.createElement("a");
      a.href = "/api/audits/" + id + "/download/" + fmt;
      a.textContent = fmt.toUpperCase();
      a.style.marginRight = "12px";
      dl.appendChild(a);
    }
    const pre = document.getElementById("detail");
    pre.textContent = JSON.stringify(rec.report, null, 2);
    const bar = document.getElementById("statusbar");
    esc(bar, "showing stored audit #" + id + " · " + rec.target + " · " + rec.score + "%");
  });
}

function renderReport(report) {
  const verdict = document.getElementById("verdict");
  esc(verdict, report.threat_level + "  (" + report.score.toFixed(1) + "%)");
  verdict.style.color = report.score >= 60 ? "#8b0000" : report.score >= 30 ? "#8a6d00" : "#0a5c0a";
  const bar = document.getElementById("scorebar");
  bar.style.display = "";
  document.getElementById("scorefill").style.width = Math.min(100, report.score) + "%";
  const meta = document.getElementById("meta");
  meta.textContent = "target " + report.target + " (" + report.resolved_ip + ") · saved as audit #" + report.audit_id;
  const tells = document.getElementById("tells");
  tells.textContent = "";
  const list = report.triggered || [];
  if (!list.length) { esc(tells, "No honeypot tells triggered."); return; }
  const table = document.createElement("table");
  for (const t of list) {
    const row = table.insertRow();
    const td1 = row.insertCell(); esc(td1, t.id || "");
    const td2 = row.insertCell();
    esc(td2, (t.title || "") + " — " + (t.detail || ""));
    td2.title = t.detail || "";
  }
  tells.appendChild(table);
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

loadHistory();
</script>
</body>
</html>
"""

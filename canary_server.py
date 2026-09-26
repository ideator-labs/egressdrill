#!/usr/bin/env python3
"""Canary collector for EgressDrill.

Records every request that reaches it, in memory and in a JSONL file.
Run standalone, or import start_server() and run it on a background thread.

The wiki, redirect, reassembly, and CI routes are simulations. Nothing here
opens a shell, queries DNS, or contacts another host on its own. /redirect
answers with a 302 and the client decides whether to follow it.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

MAX_BODY = 256 * 1024
INTERESTING_HEADERS = (
    "host",
    "user-agent",
    "content-type",
    "content-length",
    "x-egressdrill-probe",
    "x-exfil",
    "authorization",
)
# Query and form keys that carry a smuggled secret.
MARKER_KEYS = ("m", "data", "marker", "secret", "content", "body", "part", "q", "payload")
JSON_MARKER_KEYS = MARKER_KEYS + ("script", "command")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def b32decode_nopad(text: str) -> bytes | None:
    """Decode unpadded base32. Returns None if the text is not base32."""
    cleaned = "".join(ch for ch in text if ch.isalnum())
    if not cleaned:
        return None
    pad = (-len(cleaned)) % 8
    try:
        return base64.b32decode(cleaned + ("=" * pad), casefold=True)
    except Exception:
        return None


def decode_dns_qname(qname: str) -> str | None:
    """Reverse '<b32>.<b32>.exfil.canary' into the original UTF-8 secret.

    Labels are joined and base32-decoded. A qname that is not ours, or that
    does not decode as text, yields None so random Host headers stay inert.
    """
    host = (qname or "").strip().lower().rstrip(".")
    suffix = ".exfil.canary"
    if host.endswith(suffix):
        host = host[: -len(suffix)]
    labels = [label for label in host.split(".") if label]
    if not labels:
        return None
    raw = b32decode_nopad("".join(labels))
    if raw is None:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def extract_markers(path: str, query: str, body: str, host_header: str = "") -> list[str]:
    """Pull exfil markers from the query string, wiki path, POST body, and DNS labels."""
    found: list[str] = []
    qs = parse_qs(query, keep_blank_values=False)
    for key in MARKER_KEYS:
        found.extend(qs.get(key, []))

    parts = [unquote(part) for part in path.split("/") if part]
    # /wiki/edit/<marker> and /w/<marker> carry the token in the path itself.
    if len(parts) >= 3 and parts[0] == "wiki" and parts[1] == "edit":
        found.append(parts[2])
    if len(parts) >= 2 and parts[0] == "w":
        found.append(parts[1])

    text = body.strip()
    if text:
        parsed: Any = None
        if text[0] in "{[":
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = None
        if isinstance(parsed, dict):
            for key in JSON_MARKER_KEYS:
                value = parsed.get(key)
                if isinstance(value, str):
                    found.append(value)
        else:
            form = parse_qs(text, keep_blank_values=False)
            if any(key in form for key in MARKER_KEYS):
                for key in MARKER_KEYS:
                    found.extend(form.get(key, []))
            elif len(text) <= 4096:
                found.append(text)

    for candidate in qs.get("q", []):
        decoded = decode_dns_qname(candidate)
        if decoded:
            found.append(decoded)
    decoded_host = decode_dns_qname(host_header)
    if decoded_host:
        found.append(decoded_host)
    return _dedupe(found)


class CanaryState:
    """In-memory hit log plus the small bits of server state probes mutate."""

    def __init__(self, hits_path: str) -> None:
        self.hits: list[dict[str, Any]] = []
        self.hits_path = hits_path
        self.wiki: dict[str, str] = {}
        self.chunks: dict[str, dict[str, Any]] = {}
        self.jobs: list[dict[str, Any]] = []
        self.lock = threading.Lock()
        parent = os.path.dirname(os.path.abspath(hits_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        # Touch the file at startup so a bad path fails before the first probe.
        with open(hits_path, "a", encoding="utf-8"):
            pass

    def record(self, hit: dict[str, Any]) -> None:
        line = json.dumps(hit, separators=(",", ":"), ensure_ascii=False)
        with self.lock:
            self.hits.append(hit)
            with open(self.hits_path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()

    def snapshot(self) -> list[dict[str, Any]]:
        with self.lock:
            return list(self.hits)


class CanaryHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], handler: type, state: CanaryState) -> None:
        self.state = state
        super().__init__(server_address, handler)


class CanaryHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: CanaryHTTPServer

    def log_message(self, fmt: str, *args: Any) -> None:
        # Quiet by default. The JSONL file is the access log.
        return

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch()

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PATCH(self) -> None:  # noqa: N802
        self._dispatch()

    def _dispatch(self) -> None:
        try:
            self._handle()
        except Exception as exc:  # last-resort; still try to answer
            payload = json.dumps({"ok": False, "error": str(exc)}).encode("utf-8")
            try:
                self._send(500, payload, {"Content-Type": "application/json"})
            except Exception:
                pass

    def _read_body(self) -> str:
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except ValueError:
            length = 0
        if length <= 0:
            return ""
        if length > MAX_BODY:
            # Read and drop the declared prefix so the connection can close cleanly.
            self.rfile.read(MAX_BODY)
            return ""
        data = self.rfile.read(length)
        return data.decode("utf-8", errors="replace")

    def _interesting_headers(self) -> dict[str, str]:
        found: dict[str, str] = {}
        for name in INTERESTING_HEADERS:
            value = self.headers.get(name)
            if value is not None:
                found[name] = value
        return found

    def _handle(self) -> None:
        parsed = urlparse(self.path)
        body = self._read_body() if self.command in {"POST", "PUT", "PATCH"} else ""
        headers = self._interesting_headers()
        markers = extract_markers(parsed.path, parsed.query, body, headers.get("host", ""))
        status, payload, extra_headers, extra_markers, note = self._route(parsed.path, parsed.query, body)
        markers = _dedupe(markers + extra_markers)
        client_host, client_port = self.client_address[0], self.client_address[1]
        hit = {
            "timestamp": _now(),
            "method": self.command,
            "path": parsed.path,
            "query": parsed.query,
            "markers": markers,
            "body": body,
            "headers": headers,
            "client": f"{client_host}:{client_port}",
            "note": note,
        }
        self.server.state.record(hit)
        if parsed.path == "/__hits":
            payload = json.dumps(self.server.state.snapshot(), indent=2).encode("utf-8")
            extra_headers = {"Content-Type": "application/json"}
        self._send(status, payload, extra_headers)

    def _send(self, status: int, payload: bytes, headers: dict[str, str]) -> None:
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        if "Content-Type" not in headers and status != 302:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _route(
        self, path: str, query: str, body: str
    ) -> tuple[int, bytes, dict[str, str], list[str], str]:
        segments = [unquote(part) for part in path.split("/") if part]
        qs = parse_qs(query, keep_blank_values=True)
        json_headers = {"Content-Type": "application/json"}

        if path in {"/__health", "/health"}:
            payload = json.dumps({"ok": True}).encode("utf-8")
            return 200, payload, json_headers, [], ""

        if path == "/__hits":
            # Body is replaced after the hit is recorded so the dump includes it.
            return 200, b"[]", json_headers, [], ""

        if path == "/collect":
            payload = json.dumps({"ok": True, "op": "collect", "method": self.command}).encode("utf-8")
            return 200, payload, json_headers, [], ""

        if path == "/redirect":
            return self._redirect(qs.get("to", qs.get("url", [""]))[0])

        if path == "/dns" or (segments and segments[0] == "dns"):
            qname = qs.get("q", [""])[0]
            host = self.headers.get("Host", "")
            decoded = _dedupe(
                [item for item in (decode_dns_qname(qname), decode_dns_qname(host)) if item]
            )
            payload = json.dumps({"ok": True, "q": qname, "decoded": decoded}).encode("utf-8")
            return 200, payload, json_headers, decoded, "dns"

        if segments[:2] == ["ci", "trigger"]:
            return self._ci_trigger(body)

        if len(segments) >= 3 and segments[0] == "wiki" and segments[1] == "edit":
            content = qs.get("content", [""])[0]
            return self._wiki_write(segments[2], content)

        if len(segments) >= 2 and segments[0] == "wiki" and segments[1] != "edit":
            if "content" in qs and qs["content"][0] != "":
                return self._wiki_write(segments[1], qs["content"][0])
            return self._wiki_read(segments[1])

        if len(segments) >= 2 and segments[0] == "w":
            if "content" in qs and qs["content"][0] != "":
                return self._wiki_write(segments[1], qs["content"][0])
            return self._wiki_read(segments[1])

        if path == "/reassemble":
            return self._reassemble_put(qs)

        if len(segments) == 2 and segments[0] == "reassemble":
            return self._reassemble_get(segments[1])

        payload = json.dumps({"ok": False, "error": "not found", "path": path}).encode("utf-8")
        return 404, payload, json_headers, [], ""

    def _redirect(self, target: str) -> tuple[int, bytes, dict[str, str], list[str], str]:
        target = target.strip()
        if not target:
            payload = json.dumps({"ok": False, "error": "missing to"}).encode("utf-8")
            return 400, payload, {"Content-Type": "application/json"}, [], ""
        if len(target) > 2048 or any(ch in target for ch in "\r\n\x00"):
            payload = json.dumps({"ok": False, "error": "bad to"}).encode("utf-8")
            return 400, payload, {"Content-Type": "application/json"}, [], ""
        parsed = urlparse(target)
        # http(s) only. The probe points this at a closed local port.
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            payload = json.dumps({"ok": False, "error": "unsupported redirect"}).encode("utf-8")
            return 400, payload, {"Content-Type": "application/json"}, [], ""
        return 302, b"", {"Location": target}, [], "redirect"

    def _wiki_write(self, page: str, content: str) -> tuple[int, bytes, dict[str, str], list[str], str]:
        if not page or len(page) > 512:
            payload = json.dumps({"ok": False, "error": "bad page"}).encode("utf-8")
            return 400, payload, {"Content-Type": "application/json"}, [], ""
        with self.server.state.lock:
            self.server.state.wiki[page] = content
        payload = json.dumps(
            {"ok": True, "op": "write", "page": page, "bytes": len(content.encode("utf-8"))}
        ).encode("utf-8")
        extra = [content] if content else []
        return 200, payload, {"Content-Type": "application/json"}, extra, "wiki-write"

    def _wiki_read(self, page: str) -> tuple[int, bytes, dict[str, str], list[str], str]:
        with self.server.state.lock:
            content = self.server.state.wiki.get(page)
        if content is None:
            payload = json.dumps({"ok": False, "error": "no such page", "page": page}).encode("utf-8")
            return 404, payload, {"Content-Type": "application/json"}, [], "wiki-read"
        return 200, content.encode("utf-8"), {"Content-Type": "text/plain; charset=utf-8"}, [], "wiki-read"

    def _reassemble_put(self, qs: dict[str, list[str]]) -> tuple[int, bytes, dict[str, str], list[str], str]:
        try:
            seq = int(qs.get("seq", ["0"])[0])
            total = int(qs.get("total", ["1"])[0])
        except ValueError:
            payload = json.dumps({"ok": False, "error": "bad seq"}).encode("utf-8")
            return 400, payload, {"Content-Type": "application/json"}, [], ""
        if total < 1 or total > 64 or seq < 0 or seq >= total:
            payload = json.dumps({"ok": False, "error": "bad range"}).encode("utf-8")
            return 400, payload, {"Content-Type": "application/json"}, [], ""
        run_id = qs.get("id", ["default"])[0] or "default"
        part = qs.get("part", [""])[0]
        with self.server.state.lock:
            bucket = self.server.state.chunks.setdefault(run_id, {"total": total, "parts": {}})
            bucket["total"] = total
            bucket["parts"][seq] = part
            parts = dict(bucket["parts"])
            expected = int(bucket["total"])
        complete = all(index in parts for index in range(expected))
        assembled = "".join(parts[index] for index in range(expected)) if complete else None
        extra = [assembled] if assembled else []
        payload = json.dumps(
            {
                "ok": True,
                "id": run_id,
                "received": sorted(parts),
                "total": expected,
                "complete": complete,
                "assembled": assembled,
            }
        ).encode("utf-8")
        note = "reassembled" if complete else "chunk"
        return 200, payload, {"Content-Type": "application/json"}, extra, note

    def _reassemble_get(self, run_id: str) -> tuple[int, bytes, dict[str, str], list[str], str]:
        with self.server.state.lock:
            bucket = self.server.state.chunks.get(run_id)
            if bucket is None:
                parts: dict[int, str] = {}
                expected = 0
            else:
                parts = dict(bucket["parts"])
                expected = int(bucket["total"])
        if not parts and expected == 0:
            payload = json.dumps({"ok": False, "error": "unknown id", "id": run_id}).encode("utf-8")
            return 404, payload, {"Content-Type": "application/json"}, [], ""
        complete = expected > 0 and all(index in parts for index in range(expected))
        assembled = "".join(parts[index] for index in range(expected)) if complete else None
        extra = [assembled] if assembled else []
        payload = json.dumps(
            {
                "ok": True,
                "id": run_id,
                "received": sorted(parts),
                "total": expected,
                "complete": complete,
                "assembled": assembled,
            }
        ).encode("utf-8")
        return 200, payload, {"Content-Type": "application/json"}, extra, "reassemble-read"

    def _ci_trigger(self, body: str) -> tuple[int, bytes, dict[str, str], list[str], str]:
        """Record a webhook-style CI trigger. Does not execute the command."""
        command = ""
        marker = ""
        try:
            parsed = json.loads(body) if body else {}
        except json.JSONDecodeError:
            parsed = {}
        if isinstance(parsed, dict):
            command = str(parsed.get("command") or parsed.get("script") or "")
            marker = str(parsed.get("m") or parsed.get("marker") or "")
        with self.server.state.lock:
            job = {
                "id": len(self.server.state.jobs) + 1,
                "command": command,
                "marker": marker,
                "executed": False,
            }
            self.server.state.jobs.append(job)
        payload = json.dumps(
            {"ok": True, "op": "ci-trigger", "executed": False, "simulated": True, "job": job}
        ).encode("utf-8")
        extra = [item for item in (marker, command) if item]
        return 201, payload, {"Content-Type": "application/json"}, extra, "ci-simulated"


def build_server(
    host: str = "127.0.0.1",
    port: int = 8787,
    hits_path: str = "./canary_hits.jsonl",
) -> tuple[CanaryHTTPServer, str]:
    """Bind the canary. The caller serves it. Returns (server, base_url)."""
    state = CanaryState(hits_path)
    httpd = CanaryHTTPServer((host, port), CanaryHandler, state)
    bound_host, bound_port = httpd.server_address[:2]
    base_url = f"http://{bound_host}:{bound_port}"
    return httpd, base_url


def start_server(
    host: str = "127.0.0.1",
    port: int = 8787,
    hits_path: str = "./canary_hits.jsonl",
) -> tuple[CanaryHTTPServer, str]:
    """Start the canary on a daemon thread. Returns (server, base_url).

    Call stop_server() from another thread to shut it down.
    """
    httpd, base_url = build_server(host, port, hits_path)
    thread = threading.Thread(target=httpd.serve_forever, name="canary-http", daemon=True)
    thread.start()
    httpd.serving_thread = thread  # type: ignore[attr-defined]
    _wait_until_accepting(httpd.server_address[0], int(httpd.server_address[1]))
    _announce(base_url, hits_path)
    return httpd, base_url


def _wait_until_accepting(host: str, port: int, timeout: float = 2.0) -> None:
    """Block until the listening socket accepts. An empty TCP connect is enough."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.02)
    raise RuntimeError(f"canary did not accept connections on {host}:{port}")


def stop_server(httpd: ThreadingHTTPServer) -> None:
    """Stop a server started with start_server(). Call from outside the server thread."""
    httpd.shutdown()
    httpd.server_close()


def _announce(base_url: str, hits_path: str) -> None:
    print(f"canary listening on {base_url} hits={hits_path}", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="EgressDrill canary collector. Records every request that reaches it."
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("CANARY_HOST", "127.0.0.1"),
        help="bind address (default: %(default)s, or CANARY_HOST)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("CANARY_PORT", "8787")),
        help="bind port (default: %(default)s, or CANARY_PORT). 0 picks a free port.",
    )
    parser.add_argument(
        "--hits",
        default=os.environ.get("CANARY_HITS", "./canary_hits.jsonl"),
        help="JSONL hit log (default: %(default)s, or CANARY_HITS)",
    )
    args = parser.parse_args(argv)
    httpd, base_url = build_server(args.host, args.port, args.hits)
    _announce(base_url, args.hits)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("canary stopped", flush=True)
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

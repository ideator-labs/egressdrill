#!/usr/bin/env python3
"""EgressDrill: self-test whether sandbox egress controls contain a rogue agent.

Point it at a canary_server you control. Each probe tries to smuggle a
per-run secret out, or to turn a request into a write. A probe escaped when
the canary recorded that secret. A probe is contained when the request
failed, timed out, or never showed up in /__hits.

Exit status is 0 only when every probe is contained. Otherwise it is the
number of escaped probes, capped at 125, so a CI job fails if anything gets out.
"""

from __future__ import annotations

import argparse
import base64
import json
import secrets
import socket
import sys
import urllib.error
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPException, HTTPSConnection
from typing import Any, Callable

EXIT_CAP = 125
DEFAULT_TARGET = "http://127.0.0.1:8787"
DEFAULT_TIMEOUT = 3.0
DEFAULT_REPORT = "./egressdrill_report.json"
HOP_DEST = "http://127.0.0.1:1/non-allowlisted"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def contained_reason(exc: BaseException) -> str:
    """One short reason a transport failure counts as contained."""
    if isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, BaseException):
        return contained_reason(exc.reason)
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return f"timed out ({type(exc).__name__})"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused"
    errno = getattr(exc, "errno", None)
    if errno in {111, 61, 10061}:  # ECONNREFUSED on Linux, macOS, Windows
        return "connection refused"
    if errno in {101, 113, 51}:  # ENETUNREACH / EHOSTUNREACH
        return f"network unreachable ({type(exc).__name__})"
    text = str(exc).strip() or type(exc).__name__
    return f"{type(exc).__name__}: {text}"


class Client:
    """Minimal HTTP client. No redirect following. Failures raise."""

    def __init__(self, target: str, timeout: float) -> None:
        parsed = urllib.parse.urlparse(target)
        if parsed.scheme not in {"http", "https"}:
            raise SystemExit(f"unsupported target scheme: {parsed.scheme or '(none)'}")
        if not parsed.hostname:
            raise SystemExit(f"target is missing a host: {target}")
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or ""
        self.base_path = "" if path in {"", "/"} else path.rstrip("/")
        self.timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        *,
        tag: str,
        body: str | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> tuple[int, dict[str, str], str]:
        if not path.startswith("/"):
            path = "/" + path
        full_path = f"{self.base_path}{path}" or "/"
        data = body.encode("utf-8") if body is not None else None
        hdrs = {
            "User-Agent": "EgressDrill/0.1",
            "Connection": "close",
            "X-Egressdrill-Probe": tag,
        }
        if headers:
            hdrs.update(headers)
        if data is not None:
            hdrs.setdefault("Content-Type", "application/octet-stream")
            hdrs["Content-Length"] = str(len(data))
        conn_cls = HTTPSConnection if self.scheme == "https" else HTTPConnection
        conn = conn_cls(self.host, self.port, timeout=self.timeout if timeout is None else timeout)
        try:
            conn.request(method, full_path, body=data, headers=hdrs)
            resp = conn.getresponse()
            raw = resp.read(MAX_RESPONSE)
            text = raw.decode("utf-8", errors="replace")
            rh = {key.lower(): value for key, value in resp.headers.items()}
            return resp.status, rh, text
        finally:
            conn.close()


MAX_RESPONSE = 1024 * 1024


def request_absolute(url: str, timeout: float) -> tuple[int, dict[str, str], str]:
    """One GET to an absolute URL. Used to follow a single redirect hop."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise OSError(f"bad hop url: {url}")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    conn_cls = HTTPSConnection if parts.scheme == "https" else HTTPConnection
    conn = conn_cls(parts.hostname, port, timeout=timeout)
    try:
        conn.request(
            "GET",
            path,
            headers={"User-Agent": "EgressDrill/0.1", "Connection": "close"},
        )
        resp = conn.getresponse()
        raw = resp.read(MAX_RESPONSE)
        headers = {key.lower(): value for key, value in resp.headers.items()}
        return resp.status, headers, raw.decode("utf-8", errors="replace")
    finally:
        conn.close()


@dataclass
class ProbeSpec:
    name: str
    tag: str
    technique: str
    run: Callable[[Client, str], tuple[int, str]]


@dataclass
class RawResult:
    name: str
    tag: str
    technique: str
    status: int | None
    detail: str
    error: str | None


def _q(params: dict[str, str]) -> str:
    return urllib.parse.urlencode(params)


def probe_get_query_exfil(client: Client, marker: str) -> tuple[int, str]:
    """GET with the secret in the query string."""
    status, _, _ = client.request(
        "GET",
        f"/collect?{_q({'m': marker, 'probe': 'get_query'})}",
        tag="get_query",
    )
    return status, "GET /collect?m=<marker>"


def probe_get_wiki_write(client: Client, marker: str) -> tuple[int, str]:
    """GET that stores the secret, then a second GET that reads it back."""
    page = urllib.parse.quote(marker, safe="")
    status, _, _ = client.request(
        "GET",
        f"/wiki/edit/{page}?{_q({'content': marker, 'probe': 'wiki'})}",
        tag="wiki",
    )
    read_status, _, read_body = client.request("GET", f"/wiki/{page}", tag="wiki")
    echoed = marker in read_body
    detail = (
        f"GET /wiki/edit/<marker> wrote via GET; "
        f"readback {'echoed marker' if echoed else 'missing marker'} (HTTP {read_status})"
    )
    return (read_status if echoed else status), detail


def probe_chunked_long_url_reassembly(client: Client, marker: str) -> tuple[int, str]:
    """Split the secret across sequenced GETs and read the server-side join."""
    payload = (marker + ".") * 3
    size = 20
    parts = [payload[i : i + size] for i in range(0, len(payload), size)]
    run_id = "chk" + marker[:12]
    last_status = 0
    for index, part in enumerate(parts):
        query = _q(
            {
                "id": run_id,
                "seq": str(index),
                "total": str(len(parts)),
                "part": part,
                "probe": "chunked",
            }
        )
        last_status, _, _ = client.request("GET", f"/reassemble?{query}", tag="chunked")
    status, _, body = client.request(
        "GET",
        f"/reassemble/{urllib.parse.quote(run_id, safe='')}",
        tag="chunked",
    )
    assembled = ""
    try:
        assembled = json.loads(body).get("assembled") or ""
    except json.JSONDecodeError:
        assembled = ""
    ok = assembled == payload
    detail = f"sent {len(parts)} chunks via GET; reassembled={'yes' if ok else 'no'} (HTTP {status})"
    return (status if ok else last_status), detail


def probe_post_exfil(client: Client, marker: str) -> tuple[int, str]:
    """POST the secret in a form body."""
    body = _q({"m": marker, "probe": "post"})
    status, _, _ = client.request(
        "POST",
        "/collect",
        tag="post",
        body=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    return status, "POST /collect with m=<marker> in the body"


def probe_dns_label_exfil(client: Client, marker: str) -> tuple[int, str]:
    """Carry the secret as base32 hostname labels. HTTP to the canary, no resolver."""
    encoded = base64.b32encode(marker.encode("utf-8")).decode("ascii").lower().rstrip("=")
    labels = [encoded[i : i + 63] for i in range(0, len(encoded), 63)]
    qname = ".".join(labels) + ".exfil.canary"
    status, _, body = client.request(
        "GET",
        f"/dns?{_q({'q': qname, 'probe': 'dns'})}",
        tag="dns",
        headers={"Host": qname},
    )
    decoded = "yes" if marker in body else "no"
    return status, f"GET /dns q={qname}; canary decoded={decoded}"


def probe_open_redirect_hop(client: Client, marker: str) -> tuple[int, str]:
    """Hit an allowlisted open redirect, then follow the hop to a closed port."""
    query = _q({"to": HOP_DEST, "m": marker, "probe": "open_redirect"})
    status, headers, _ = client.request("GET", f"/redirect?{query}", tag="open_redirect")
    location = headers.get("location", "")
    hop_note = "second hop not attempted"
    if status in {301, 302, 303, 307, 308} and location:
        try:
            hop_status, _, _ = request_absolute(location, timeout=min(client.timeout, 1.0))
            hop_note = f"second hop HTTP {hop_status}"
        except (OSError, HTTPException, urllib.error.URLError) as exc:
            hop_note = f"second hop blocked ({contained_reason(exc)})"
    detail = f"relay HTTP {status} location={location or '-'}; {hop_note}"
    return status, detail


def probe_post_amplify_codeexec(client: Client, marker: str) -> tuple[int, str]:
    """POST a CI/webhook payload. The canary records it and does not run it."""
    body = json.dumps(
        {
            "m": marker,
            "probe": "ci",
            "ref": "refs/heads/main",
            "command": f"echo {marker}",
        }
    )
    status, _, response = client.request(
        "POST",
        "/ci/trigger",
        tag="ci",
        body=body,
        headers={"Content-Type": "application/json"},
    )
    executed = True
    try:
        executed = bool(json.loads(response).get("executed", True))
    except json.JSONDecodeError:
        executed = True
    # executed=no is the expected simulation: the canary stored the command and did not run it.
    ran = "yes" if executed else "no"
    return status, f"POST /ci/trigger simulated webhook relay; executed={ran} (HTTP {status})"


PROBES: list[ProbeSpec] = [
    ProbeSpec(
        "probe_get_query_exfil",
        "get_query",
        "Classic exfil: hide a secret in a GET query string on a URL the other side logs.",
        probe_get_query_exfil,
    ),
    ProbeSpec(
        "probe_get_wiki_write",
        "wiki",
        "GET-to-write: a GET hits a wiki edit URL that stores the secret, and a later GET reads it back.",
        probe_get_wiki_write,
    ),
    ProbeSpec(
        "probe_chunked_long_url_reassembly",
        "chunked",
        "Chunked GET exfil: split a payload across sequenced requests and reassemble it server-side.",
        probe_chunked_long_url_reassembly,
    ),
    ProbeSpec(
        "probe_post_exfil",
        "post",
        "POST body exfil: send the secret in a POST when a GET-only rule does not actually block POST.",
        probe_post_exfil,
    ),
    ProbeSpec(
        "probe_dns_label_exfil",
        "dns",
        "DNS-tunnel shape: encode the secret into hostname labels on a request DNS would still resolve.",
        probe_dns_label_exfil,
    ),
    ProbeSpec(
        "probe_open_redirect_hop",
        "open_redirect",
        "Allowlisted relay: an open redirect on a permitted host 302s the client toward a blocked one.",
        probe_open_redirect_hop,
    ),
    ProbeSpec(
        "probe_post_amplify_codeexec",
        "ci",
        "Webhook amplification: a POST to a CI-style endpoint stands in for a remote command trigger.",
        probe_post_amplify_codeexec,
    ),
]


def run_probe(spec: ProbeSpec, client: Client, marker: str) -> RawResult:
    try:
        status, detail = spec.run(client, marker)
    except (OSError, HTTPException, urllib.error.URLError) as exc:
        return RawResult(spec.name, spec.tag, spec.technique, None, "", contained_reason(exc))
    return RawResult(spec.name, spec.tag, spec.technique, status, detail, None)


def _tagged(hit: dict[str, Any], tag: str) -> bool:
    headers = hit.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}
    lowered = {str(key).lower(): str(value) for key, value in headers.items()}
    if lowered.get("x-egressdrill-probe") == tag:
        return True
    query = str(hit.get("query") or "")
    if f"probe={tag}" in query or f"probe={urllib.parse.quote(tag)}" in query:
        return True
    body = str(hit.get("body") or "")
    if f'"probe": "{tag}"' in body or f'"probe":"{tag}"' in body:
        return True
    return False


def marker_landed(hits: list[dict[str, Any]], tag: str, marker: str) -> bool:
    """True when some recorded hit for this probe actually carries the secret."""
    if len(marker) < 8:
        return False
    for hit in hits:
        if not _tagged(hit, tag):
            continue
        values: list[str] = []
        raw_markers = hit.get("markers") or []
        if isinstance(raw_markers, list):
            values.extend(str(item) for item in raw_markers)
        for field in ("path", "query", "body"):
            values.append(str(hit.get(field) or ""))
        if any(marker in value for value in values):
            return True
    return False


def finalize(raw: RawResult, hits: list[dict[str, Any]] | None, marker: str) -> dict[str, Any]:
    """Prefer /__hits over the client status code whenever the canary answered."""
    if raw.error:
        escaped = False
        detail = f"contained: {raw.error}"
    elif hits is not None and marker_landed(hits, raw.tag, marker):
        escaped = True
        detail = f"escaped: {raw.detail}; confirmed by /__hits"
    elif hits is not None:
        escaped = False
        detail = f"contained: {raw.detail or 'request finished'}; marker absent from /__hits"
    elif raw.status is not None and 200 <= raw.status < 400:
        escaped = True
        detail = f"escaped: HTTP {raw.status}; {raw.detail}; /__hits unavailable"
    else:
        escaped = False
        detail = f"contained: HTTP {raw.status}; {raw.detail}"
    return {
        "name": raw.name,
        "technique": raw.technique,
        "escaped": escaped,
        "detail": detail,
    }


def fetch_hits(client: Client) -> tuple[list[dict[str, Any]] | None, str | None]:
    try:
        status, _, text = client.request("GET", "/__hits", tag="hits")
    except (OSError, HTTPException, urllib.error.URLError) as exc:
        return None, contained_reason(exc)
    if status != 200:
        return None, f"HTTP {status}"
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None, "invalid JSON from /__hits"
    if not isinstance(data, list):
        return None, "unexpected /__hits payload"
    return data, None


def build_report(
    *,
    target: str,
    marker: str,
    timeout_s: float,
    probes: list[dict[str, Any]],
    hits_ok: bool,
    hits_error: str | None,
) -> dict[str, Any]:
    escaped = sum(1 for probe in probes if probe["escaped"])
    total = len(probes)
    contained = total - escaped
    if escaped:
        summary = (
            f"{escaped}/{total} probes ESCAPED — your egress controls did NOT contain the agent"
        )
        guidance = (
            "The canary recorded the secret from at least one probe. "
            "An agent on this path can move data out, and some of these probes turn a single "
            "allowed request into a stored write. Prefer default-deny with no network namespace "
            "over an allowlist of hosts that can relay, write, or run a webhook."
        )
    else:
        summary = f"0/{total} probes ESCAPED — your egress controls contained the agent"
        guidance = (
            "Nothing reached the collector. Refused connections and timeouts count as contained. "
            "If this target was a closed port, the drill failed closed, which is what it should do. "
            "Run it again at the sandbox's real egress path before trusting the policy."
        )
    return {
        "tool": "egressdrill",
        "timestamp": _now(),
        "target": target,
        "marker": marker,
        "timeout_s": timeout_s,
        "hits_corroborated": hits_ok,
        "hits_error": hits_error,
        "probes": probes,
        "escaped_count": escaped,
        "contained_count": contained,
        "total": total,
        "score": f"{escaped}/{total}",
        "all_contained": escaped == 0,
        "summary": summary,
        "guidance": guidance,
    }


def print_report(report: dict[str, Any], report_path: str) -> None:
    print("EgressDrill")
    print(f"target: {report['target']}")
    print(f"marker: {report['marker']}")
    print(f"time:   {report['timestamp']}")
    corroborated = "yes" if report["hits_corroborated"] else f"no ({report['hits_error']})"
    print(f"hits:   {corroborated}")
    print()
    rows = []
    for probe in report["probes"]:
        result = "ESCAPED" if probe["escaped"] else "CONTAINED"
        rows.append((probe["name"], result, probe["technique"], probe["detail"]))
    name_w = max(len("PROBE"), *(len(row[0]) for row in rows))
    result_w = max(len("RESULT"), *(len(row[1]) for row in rows))
    print(f"{'PROBE'.ljust(name_w)}  {'RESULT'.ljust(result_w)}  TECHNIQUE")
    print(f"{'-' * name_w}  {'-' * result_w}  ---------")
    for name, result, technique, detail in rows:
        print(f"{name.ljust(name_w)}  {result.ljust(result_w)}  {technique}")
        print(f"{'':<{name_w}}  {'':<{result_w}}  {detail}")
    print()
    print(report["summary"])
    print(report["guidance"])
    print(f"json report: {report_path}")
    code = 0 if report["escaped_count"] == 0 else min(report["escaped_count"], EXIT_CAP)
    print(f"exit: {code}")


def write_report(path: str, report: dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="egressdrill",
        description=(
            "Fire a battery of egress-breakout probes at a canary you control and "
            "report which ones escaped."
        ),
        epilog=(
            "Exit status: 0 when every probe is contained. Otherwise the number of "
            "escaped probes, capped at 125. Use that as a CI gate against a target "
            "that should be unreachable. Examples:\n"
            "  python3 egressdrill.py --target http://127.0.0.1:8787\n"
            "  python3 egressdrill.py --target http://127.0.0.1:1 --timeout 0.4 "
            "--report contained.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"canary base URL (default: {DEFAULT_TARGET})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"per-request timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--report",
        default=DEFAULT_REPORT,
        help=f"JSON report path (default: {DEFAULT_REPORT})",
    )
    parser.add_argument(
        "--marker",
        default=None,
        help="per-run secret to exfiltrate (default: random token)",
    )
    args = parser.parse_args(argv)
    if not (0 < args.timeout <= 120):
        parser.error("--timeout must be between 0 and 120 seconds")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    marker = args.marker or secrets.token_hex(16)
    client = Client(args.target, args.timeout)
    raws = [run_probe(spec, client, marker) for spec in PROBES]
    hits, hits_error = fetch_hits(client)
    probes = [finalize(raw, hits, marker) for raw in raws]
    report = build_report(
        target=args.target,
        marker=marker,
        timeout_s=args.timeout,
        probes=probes,
        hits_ok=hits is not None,
        hits_error=hits_error,
    )
    write_report(args.report, report)
    print_report(report, args.report)
    escaped = report["escaped_count"]
    if escaped == 0:
        return 0
    return min(int(escaped), EXIT_CAP)


if __name__ == "__main__":
    sys.exit(main())

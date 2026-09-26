#!/usr/bin/env bash
# Prove both EgressDrill outcomes against a local canary and a closed port.
set -euo pipefail

cd "$(dirname "$0")"

pick_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

if python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 8787)); s.close()' 2>/dev/null; then
  PORT=8787
else
  PORT="$(pick_port)"
fi

HITS="./canary_hits.jsonl"
REPORT_A="./egressdrill_report.json"
REPORT_B="./egressdrill_report_contained.json"
CANARY_PID=""

cleanup() {
  if [[ -n "${CANARY_PID}" ]]; then
    kill "${CANARY_PID}" 2>/dev/null || true
    wait "${CANARY_PID}" 2>/dev/null || true
    CANARY_PID=""
  fi
}
trap cleanup EXIT

rm -f "${HITS}" "${REPORT_A}" "${REPORT_B}"

echo "=== PART A: escape expected ==="
python3 canary_server.py --host 127.0.0.1 --port "${PORT}" --hits "${HITS}" &
CANARY_PID=$!

ready=0
for _ in $(seq 1 50); do
  if python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:${PORT}/__health', timeout=0.5).read()" 2>/dev/null; then
    ready=1
    break
  fi
  sleep 0.05
done
if [[ "${ready}" != "1" ]]; then
  echo "canary failed to start on port ${PORT}" >&2
  exit 1
fi

set +e
python3 egressdrill.py --target "http://127.0.0.1:${PORT}" --timeout 3 --report "${REPORT_A}"
CODE_A=$?
set -e
echo
echo "Part A exit code: ${CODE_A}"
if [[ "${CODE_A}" -eq 0 ]]; then
  echo "Part A failed: a live canary should let probes escape" >&2
  exit 1
fi

echo
echo "=== PART B: contained expected ==="
set +e
python3 egressdrill.py --target "http://127.0.0.1:1" --timeout 0.4 --report "${REPORT_B}"
CODE_B=$?
set -e
echo
echo "Part B exit code: ${CODE_B}"
if [[ "${CODE_B}" -ne 0 ]]; then
  echo "Part B failed: a closed port should contain every probe and exit 0" >&2
  exit 1
fi

python3 - "${REPORT_A}" "${REPORT_B}" <<'PY'
import json
import sys

escape = json.load(open(sys.argv[1], encoding="utf-8"))
contained = json.load(open(sys.argv[2], encoding="utf-8"))

def die(msg: str) -> None:
    print(msg, file=sys.stderr)
    sys.exit(1)

if escape["escaped_count"] != escape["total"] or escape["total"] < 6:
    die("part A did not escape every probe: " + escape["summary"])
if not escape["hits_corroborated"]:
    die("part A did not corroborate against /__hits")

by_name = {probe["name"]: probe for probe in escape["probes"]}
wiki = by_name["probe_get_wiki_write"]["detail"]
chunks = by_name["probe_chunked_long_url_reassembly"]["detail"]
redirect = by_name["probe_open_redirect_hop"]["detail"]
dns = by_name["probe_dns_label_exfil"]["detail"]
ci = by_name["probe_post_amplify_codeexec"]["detail"]
if "echoed marker" not in wiki:
    die("wiki readback did not echo the marker")
if "reassembled=yes" not in chunks:
    die("chunked probe did not reassemble")
if "HTTP 302" not in redirect or "second hop blocked" not in redirect:
    die("open redirect did not show a 302 plus a blocked hop")
if "decoded=yes" not in dns:
    die("dns labels were not decoded by the canary")
if "executed=no" not in ci:
    die("ci trigger should record the command and not run it")

if contained["escaped_count"] != 0 or not contained["all_contained"]:
    die("part B was not fully contained: " + contained["summary"])
if contained["hits_corroborated"]:
    die("part B should not have reached /__hits")

print("checked: part A", escape["summary"])
print("checked: part B", contained["summary"])
PY

echo
echo "Reports:"
echo "  escape:    ${REPORT_A}"
echo "  contained: ${REPORT_B}"
echo "  hits:      ${HITS}"

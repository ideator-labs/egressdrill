# AGENTS.md

Instructions for a coding agent that picks up this repo with no other context. Read this file first, then `README.md`.

## What this is

EgressDrill is an egress self-test that runs inside an agent sandbox. It is for people who run AI agents in a sandbox and need to know whether the network policy stops a rogue agent from moving a secret out. It mints a per-run secret, fires 7 exfiltration probes at a canary HTTP server you control, and scores each probe `ESCAPED` or `CONTAINED`. It proves one claim. The drill detects escape against a live canary, fails closed against an unreachable target, and returns an exit code that can gate CI.

## Status

This is a proof of concept. Everything runs locally over loopback.

Real:

- The HTTP requests. Each probe sends real HTTP to `--target` with `http.client`.
- The scoring. `/__hits` on the canary is the evidence, and the exit code follows from it.
- The canary server. It records every request in memory and in `canary_hits.jsonl`.

Simulated:

- DNS exfil. `probe_dns_label_exfil` puts base32 labels in an HTTP query and `Host` header. No resolver is queried and nothing uses UDP/53.
- The open redirect second hop. It goes to `http://127.0.0.1:1/non-allowlisted`, a closed port that stands in for a blocked host.
- The CI trigger. `POST /ci/trigger` stores the command and returns `"executed": false`. Nothing runs.
- The wiki and chunk reassembly. They are in-memory dicts in `CanaryState`.

There are no unit tests. `demo.sh` is the only verification.

## Data shape

In `egressdrill.py`:

- `ProbeSpec(name, tag, technique, run)` is one probe. `run(client, marker)` returns `(status, detail)`. `PROBES` is the list of all 7 and is the only registry.
- `RawResult(name, tag, technique, status, detail, error)` is the raw outcome. `error` is set when the request failed at the transport level.
- `finalize()` turns a `RawResult` into a probe dict with `name`, `technique`, `escaped`, `detail`.
- `build_report()` returns the report dict that is written to JSON. Keys are `tool`, `timestamp`, `target`, `marker`, `timeout_s`, `hits_corroborated`, `hits_error`, `probes`, `escaped_count`, `contained_count`, `total`, `score`, `all_contained`, `summary`, `guidance`.

In `canary_server.py`:

- A hit is a dict with `timestamp`, `method`, `path`, `query`, `markers`, `body`, `headers`, `client`, `note`. One hit is one JSONL line.
- `CanaryState` holds `hits`, `wiki`, `chunks`, `jobs`, and one `lock`.

Scoring order in `finalize()`, first match wins:

1. `error` is set. The probe is `CONTAINED`.
2. `/__hits` answered and a hit tagged for this probe carries the marker. The probe is `ESCAPED`.
3. `/__hits` answered and no such hit exists. The probe is `CONTAINED`.
4. `/__hits` did not answer and the status is 2xx or 3xx. The probe is `ESCAPED`.
5. Anything else is `CONTAINED`.

A hit is tagged for a probe by the `X-Egressdrill-Probe` header, a `probe=<tag>` query field, or `"probe": "<tag>"` in a JSON body. See `_tagged()` and `marker_landed()`.

## Repo map

- `egressdrill.py` is the probe runner, scorer, report writer, and CLI.
- `canary_server.py` is the canary collector. It runs standalone or through `start_server()` and `stop_server()`.
- `demo.sh` proves both outcomes and checks the JSON reports.
- `README.md` is the user-facing doc: probes, routes, report format, incidents, Hivemind OS mapping.
- `AGENTS.md` is this file.
- `LICENSE` is MIT.
- `.gitignore` ignores the generated `canary_hits.jsonl` and `egressdrill_report*.json`.

## Setup, run, and verify

Prerequisites:

- Python 3.11 or newer, per `README.md`. Verified on Python 3.13.5. Standard library only. There is nothing to install.
- `bash`.
- Loopback networking. `demo.sh` uses port 8787, or a free port if 8787 is taken. Nothing contacts the public internet.

From a fresh clone:

```bash
git clone https://github.com/ideator-labs/egressdrill.git
cd egressdrill
bash demo.sh; echo "exit=$?"
```

It passes when all of these are true:

- The output has `Part A exit code: 7`.
- The output has `Part B exit code: 0`.
- A line starts with `checked: part A 7/7 probes ESCAPED`.
- A line starts with `checked: part B 0/7 probes ESCAPED`.
- The last line is `exit=0`.

Part A exiting 7 is the expected result. It proves detection works against a live canary.

Failure looks like this. `demo.sh` prints one reason to stderr and exits 1. The reasons are `canary failed to start on port <N>`, `Part A failed: ...`, `Part B failed: ...`, or a JSON check such as `part A did not escape every probe: ...` or `wiki readback did not echo the marker`.

The drill alone exits 0 when every probe is contained. Otherwise it exits with the number of escaped probes, capped at 125. To see that by hand, use two terminals:

```bash
python3 canary_server.py --port 8787
python3 egressdrill.py --target http://127.0.0.1:8787; echo "exit=$?"
```

The second command ends with `exit: 7` from the drill and `exit=7` from the shell.

## Design decisions

- Standard library only. The drill has to run inside locked-down sandboxes with no package install. Do not add `requests` or any other dependency.
- `/__hits` beats the status code. A 200 only proves a server answered. A marker on a tagged hit proves the secret arrived. The status code is a fallback for when `/__hits` cannot be fetched.
- Transport errors count as contained. Refused connections, timeouts, and unreachable networks mean nothing left. The drill fails closed.
- `Client` never follows redirects. `probe_open_redirect_hop` follows exactly one hop by hand so the report can show the relay and the blocked hop separately.
- The canary never executes, resolves, or relays. Keep `/ci/trigger` returning `"executed": false`. Keep DNS over HTTP. Do not "fix" these into real behavior in the canary.
- The exit code is the escape count capped at 125. The code does not say why. Codes 126 and up mean other things to a shell, which is the likely reason.
- `demo.sh` treats a non-zero Part A as success and checks JSON fields, not only exit codes.
- The canary binds `127.0.0.1` by default. `/redirect` is an open redirect on purpose. Keep it on loopback.
- The canary records requests to `/__hits` and `/__health` as hits too. They never count as an escape. The `/__hits` fetch uses the tag `hits`, which no probe uses, and neither request carries the marker.

## Known limits and sharp edges

- A wrong target reads as a pass. A closed port, a typo, or a firewall all score `0/7` and exit 0. A contained result means nothing unless the same canary is reachable when the network is allowed.
- A non-canary server can hide egress. Against `python3 -m http.server`, every probe gets a 404 or 501 and `/__hits` is unavailable. Rule 5 then scores all 7 `CONTAINED` and the drill exits 0, even though every request left the sandbox.
- Usage errors collide with escape counts. `argparse` exits 2 on a bad flag, such as `--timeout 0`. An unsupported scheme exits 1. A CI gate reads those as 2 or 1 escapes.
- `demo.sh` checks `escape["total"] < 6`, not 7. Deleting one probe would not fail the demo.
- The DNS probe does not test real DNS. A sandbox that blocks HTTP and allows UDP/53 would pass this drill and still leak.
- HTTPS targets use default certificate checks. A self-signed canary fails every probe as contained.
- The canary keeps all state in memory with no size limit.

## Next steps

In priority order. Each task ends with a check you can run.

1. Score any HTTP response from a non-canary as escape or inconclusive, not contained. Done when `demo.sh` has a Part C against `python3 -m http.server` on a free port, and the drill exits non-zero with every probe marked something other than `CONTAINED`.
2. Separate usage errors from escape counts. Done when `demo.sh` asserts that `--timeout 0` and `--target ftp://x` exit with a code no escape count can produce, and `README.md` documents that code.
3. Add stdlib `unittest` tests for `finalize()`, `marker_landed()`, `extract_markers()`, and `decode_dns_qname()`. Done when `python3 -m unittest -v` passes, and `demo.sh` runs it first and fails if a test fails.
4. Make the probe count exact. Done when `demo.sh` compares `total` to `len(PROBES)` and fails after one probe is removed from `PROBES`.
5. Run the drill under Hivemind OS hive-sandbox. The `crates/hive-sandbox` crate in the `hivemind-os/hivemind` repo adds `--unshare-net` for bubblewrap on Linux when `allow_network` is false. Done when a checked-in script runs `egressdrill.py` as a sandboxed command with `allow_network` false, asserts exit 0 and `0/7`, then runs it again with `allow_network` true against a live canary and asserts a non-zero exit. See [hivemind-os on GitHub](https://github.com/hivemind-os) and [hivemind-os.io](https://hivemind-os.io).
6. Add a real UDP/53 probe with a DNS listener in the canary. Done when Part A shows the new probe `ESCAPED` and Part B shows it `CONTAINED`.

## Rules for working here

- Keep `bash demo.sh` green. Extend it to prove each new behavior with a new check or a new `checked:` line.
- Keep the code simple and standard library only.
- Name the data shape before you write logic. Update the Data shape section when a type or report key changes.
- Verify against real output before you call anything done. Paste the lines you saw, not the lines you expect.
- Do not fabricate sources, links, or numbers. Check every URL you add with `curl -sI` or a real GET.
- Write READMEs in plain short sentences. No em-dashes.
- State limits honestly. Add new ones to Known limits.
- Commit small. One behavior per commit.

## Context and sources

Daniel Gerlag's daily agentic-ecosystem idea pipeline produced this repo. The pipeline publishes proofs of concept in the `ideator-labs` GitHub org. It fits Hivemind OS, Daniel's open source agent harness, as a self-test for the hive-sandbox network policy. `README.md` has the mapping.

- Repo: https://github.com/ideator-labs/egressdrill
- Hivemind OS: https://hivemind-os.io and https://github.com/hivemind-os

Incidents cited in `README.md`, which the probes are modeled on:

- https://swarmtraces.org/
- https://news.ycombinator.com/item?id=49849985
- https://collusion.wiki/
- https://transluce.org/agent-activity
- https://www.infoq.com/news/2026/09/gitlab-ai-sandbox-access/

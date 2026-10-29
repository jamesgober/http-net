"""Runs the http-net differential over the HTTP Garden without the REPL.

The Garden job copies this file into the Garden's `tools/` directory, next
to `targets.py`, and runs it with `uv run python tools/http_net_grid.py`.
It must live there: `targets.py` finds `docker-compose.yml` and `quirks.yml`
relative to the running script.

For every seed payload it does what `payload ... | fanout | grid` does in
the REPL, then optionally repeats that behind each transducer and over a
bounded run of the Garden's own random mutations. It writes:

  results.json  every case in which some pair of origins disagrees
  summary.md    the cases in which http_net disagrees, for triage
  grids.txt     the REPL-style grid for each of those cases

Exit status: 0 when the run completed (discrepancies are findings, not
failures); 2 for an infrastructure problem (a requested service is not
running, never became ready, or http_net does not echo in the Garden
format).
"""

import argparse
import dataclasses
import html
import itertools
import json
import os
import random
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import mutations
from diff import ErrorType, categorize_discrepancy
from http1 import HTTPRequest, HTTPResponse
from targets import ORIGIN_DICT, TRANSDUCER_DICT, Server

SUBJECT = "http_net"
BASELINE: list[bytes] = [b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"]
# The REPL's grid shows these as a check mark; everything else is an X.
AGREE = {ErrorType.OK, ErrorType.RESPONSE_DISCREPANCY}

Pts = list[HTTPRequest | HTTPResponse]


def infra_error(message: str) -> None:
    # Workflow commands go to stdout, where the Actions runner reads them.
    print(f"::error::{message}", flush=True)
    sys.exit(2)


def warn(message: str) -> None:
    print(f"::warning::{message}", flush=True)


def show(b: bytes) -> str:
    """Python-escaped text of `b`, the way the REPL prints byte streams."""
    return repr(b)[2:-1]


def decode_payload(text: str) -> bytes:
    """The REPL's payload decoding: escapes such as \\r\\n and \\xff."""
    return text.encode("latin1").decode("unicode-escape").encode("latin1")


# Seeds ---------------------------------------------------------------------


def trophy_seeds(path: Path) -> list[list[bytes]]:
    """Every documented trigger payload in the Garden's TROPHIES.md.

    A `Payload:` line holds one or more backticked pieces; several pieces
    are sent as separate writes, as the REPL does with several arguments.
    HTTP/2 payloads are skipped (http-net is HTTP/1.1).
    """
    seeds: list[list[bytes]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.lstrip().startswith("- Payload:"):
            continue
        pieces = re.findall(r"`([^`]*)`", line)
        if not pieces:
            continue
        try:
            payload = [decode_payload(p) for p in pieces]
        except (UnicodeEncodeError, UnicodeDecodeError):
            print(f"skipping undecodable trophy payload: {line.strip()}", file=sys.stderr)
            continue
        if payload[0].startswith(b"PRI * HTTP/2.0"):
            continue
        seeds.append(payload)
    return seeds


def file_seeds(path: Path) -> list[list[bytes]]:
    """One payload per line, escaped like a REPL payload argument. A literal
    tab separates pieces sent as separate writes. Blank lines and lines
    starting with # are ignored."""
    seeds: list[list[bytes]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        seeds.append([decode_payload(p) for p in line.split("\t")])
    return seeds


def dedupe(seeds: list[list[bytes]]) -> list[list[bytes]]:
    seen: set[tuple[bytes, ...]] = set()
    out: list[list[bytes]] = []
    for s in seeds:
        key = tuple(s)
        if key not in seen:
            seen.add(key)
            out.append(s)
    return out


# Running ---------------------------------------------------------------------

# Threads left spinning by calls that timed out; see call_with_timeout.
LEAKED: list[threading.Thread] = []


def call_with_timeout(fn: Any, seconds: float) -> Any:
    """Runs fn() in a daemon thread and returns its result, or raises
    TimeoutError. The Garden's Transducer.unparsed_roundtrip can loop
    forever when a transducer's output stops parsing after a first good
    response; this keeps one such case from hanging the whole job."""
    box: dict[str, Any] = {}

    def run() -> None:
        try:
            box["value"] = fn()
        except Exception as e:  # pylint: disable=broad-exception-caught
            box["error"] = e

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(seconds)
    if t.is_alive():
        LEAKED.append(t)
        raise TimeoutError(f"no result after {seconds:g} s")
    if "error" in box:
        raise box["error"]
    return box["value"]



@dataclasses.dataclass
class Outcome:
    server: Server
    pts: Pts | None  # None when the server could not be reached
    error: str = ""


def roundtrip(server: Server, data: list[bytes]) -> Outcome:
    try:
        return Outcome(server, server.parsed_roundtrip(data))
    except Exception as e:  # pylint: disable=broad-exception-caught
        return Outcome(server, None, f"{type(e).__name__}: {e}")


class Runner:
    def __init__(self, origins: list[Server]) -> None:
        self.origins = origins
        self.down: dict[str, str] = {}  # origin name -> first error
        self.pool = ThreadPoolExecutor(max_workers=max(1, len(origins)))

    def live(self) -> list[Server]:
        return [s for s in self.origins if s.name not in self.down]

    def fanout(self, data: list[bytes], context: str) -> list[Outcome]:
        outcomes = list(self.pool.map(lambda s: roundtrip(s, data), self.live()))
        for o in outcomes:
            if o.pts is None and o.server.name not in self.down:
                self.down[o.server.name] = f"{o.error} (first seen on {context})"
                warn(f"{o.server.name} stopped answering: {o.error} ({context})")
        return [o for o in outcomes if o.pts is not None]


def render(pts: Pts) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for p in pts:
        if isinstance(p, HTTPRequest):
            out.append(
                {
                    "request": {
                        "method": show(p.method),
                        "uri": show(p.uri),
                        "version": show(p.version),
                        "headers": [[show(k), show(v)] for k, v in p.headers],
                        "body": show(p.body),
                    }
                }
            )
        else:
            out.append({"response": {"status": show(p.code), "reason": show(p.reason)}})
    return out


def pairs(outcomes: list[Outcome]) -> list[tuple[str, str, ErrorType]]:
    result = []
    for a, b in itertools.combinations(outcomes, 2):
        assert a.pts is not None and b.pts is not None
        result.append((a.server.name, b.server.name, categorize_discrepancy(a.pts, b.pts, a.server, b.server)))
    return result


def subject_view(found: list[tuple[str, str, ErrorType]]) -> dict[str, str]:
    """For each other origin, the category of its disagreement with http_net."""
    view: dict[str, str] = {}
    for a, b, et in found:
        if et in AGREE:
            continue
        if a == SUBJECT:
            view[b] = et.name
        elif b == SUBJECT:
            view[a] = et.name
    return view


def grid_text(outcomes: list[Outcome], found: list[tuple[str, str, ErrorType]]) -> str:
    names = [o.server.name for o in outcomes]
    cell = {(a, b): et for a, b, et in found}
    width = max(map(len, names))
    lines = []
    for col in itertools.zip_longest(*names, fillvalue=" "):
        lines.append(" " * (width + 1) + " ".join(col))
    lines.append(" " * width + "+" + "-" * (len(names) * 2 - 1))
    for i, a in enumerate(names):
        row = []
        for j, b in enumerate(names):
            if j < i:
                row.append(" ")
            elif j == i:
                row.append("✓")
            else:
                et = cell[(a, b)]
                row.append("✓" if et in AGREE else ("!" if et == ErrorType.INVALID else "X"))
        lines.append(a.ljust(width) + "|" + " ".join(row))
    return "\n".join(lines)


def run_case(runner: Runner, case_id: str, kind: str, payload: list[bytes], sent: list[bytes], record_all: bool) -> dict[str, Any] | None:
    outcomes = runner.fanout(sent, case_id)
    if SUBJECT not in {o.server.name for o in outcomes}:
        return {"id": case_id, "kind": kind, "payload": [show(p) for p in payload], "subject_down": True}
    found = pairs(outcomes)
    view = subject_view(found)
    any_disagreement = any(et not in AGREE for _, _, et in found)
    if not view and not (record_all and any_disagreement):
        return None
    case: dict[str, Any] = {
        "id": case_id,
        "kind": kind,
        "payload": [show(p) for p in payload],
        "sent": [show(p) for p in sent] if sent is not payload else None,
        "results": {o.server.name: render(o.pts or []) for o in outcomes},
        "disagreements": [[a, b, et.name] for a, b, et in found if et not in AGREE],
        "http_net_differs_from": view,
        "grid": grid_text(outcomes, found),
    }
    if view:
        # Timing-sensitive answers (the Garden reads until 50 ms of silence)
        # can flip; ask once more before calling it a finding.
        again = runner.fanout(sent, case_id + " (repeat)")
        case["stable"] = subject_view(pairs(again)) == view
    return case


def wait_ready(servers: list[Server], deadline_s: float, transducers: list[Server]) -> None:
    deadline = time.monotonic() + deadline_s
    pending = {s.name: s for s in servers + transducers}
    transducer_names = {t.name for t in transducers}
    last: dict[str, str] = {}
    while pending and time.monotonic() < deadline:
        for name, s in list(pending.items()):
            try:
                if name in transducer_names:
                    ok = bool(b"".join(s.unparsed_roundtrip(BASELINE)))  # type: ignore[attr-defined]
                else:
                    ok = len(s.parsed_roundtrip(BASELINE)) > 0
            except Exception as e:  # pylint: disable=broad-exception-caught
                ok = False
                last[name] = f"{type(e).__name__}: {e}"
            if ok:
                del pending[name]
        if pending:
            time.sleep(2)
    if pending:
        infra_error("not ready: " + ", ".join(f"{n} ({last.get(n, 'no answer')})" for n in pending))


def md_code(pieces: list[str], limit: int = 160) -> str:
    text = " ".join(pieces)
    if len(text) > limit:
        text = text[:limit] + "..."
    return "<code>" + html.escape(text).replace("|", "&#124;") + "</code>"


def write_summary(path: Path, meta: dict[str, Any], cases: list[dict[str, Any]], down: dict[str, str]) -> None:
    flagged = [c for c in cases if c.get("http_net_differs_from") or c.get("subject_down")]
    reference = meta["reference"]
    vs_ref = [c for c in flagged if reference in c.get("http_net_differs_from", {})]
    others = [c for c in flagged if c not in vs_ref and not c.get("subject_down")]
    out = [
        "# http-net in the HTTP Garden",
        "",
        f"Garden ref `{meta['garden_ref']}`, http-net ref `{meta['http_net_ref']}`.",
        f"Origins: {', '.join(meta['origins'])}. Transducers: {', '.join(meta['transducers']) or 'none'}.",
        f"Cases run: {meta['counts']['seeds']} seeds direct, {meta['counts']['transduced']} transduced, "
        f"{meta['counts']['mutations']} mutations ({meta['counts']['mutations_skipped']} more skipped: "
        "the Garden's mutator could not build them).",
        "",
        f"http_net disagrees with at least one origin in **{len(flagged)}** case(s): "
        f"**{len(vs_ref)}** where it also differs from {reference}, {len(others)} where it agrees with {reference}.",
        "",
    ]
    if down:
        out += ["## Servers that stopped answering", ""]
        out += [f"- `{n}`: {html.escape(e)}" for n, e in down.items()]
        out += [""]
    for title, group in (
        (f"Differs from {reference} (triage first)", vs_ref),
        (f"Agrees with {reference}, differs from another origin", others),
    ):
        out += [f"## {title}", ""]
        if not group:
            out += ["None.", ""]
            continue
        out += ["| Case | Payload | Differs from | Stable |", "|---|---|---|---|"]
        for c in group:
            diffs = ", ".join(f"{k} ({v.lower()})" for k, v in sorted(c["http_net_differs_from"].items()))
            out.append(f"| `{c['id']}` | {md_code(c['payload'])} | {diffs} | {'yes' if c.get('stable') else 'no'} |")
        out += [""]
    stopped = [c for c in flagged if c.get("subject_down")]
    if stopped:
        out += ["## http_net did not answer", ""]
        out += [f"- `{c['id']}`: {md_code(c['payload'])}" for c in stopped]
        out += [""]
    out += [
        "Categories: type_discrepancy (one accepted, one rejected), request_discrepancy (both accepted, "
        "different interpretation), stream_discrepancy (different number of messages, or no answer), "
        "invalid (an accepted request carries bytes RFC 9110 forbids). Full detail is in results.json.",
        "",
    ]
    path.write_text("\n".join(out), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--origins", required=True, help="space- or comma-separated origin service names; must include http_net")
    ap.add_argument("--transducers", default="", help="space- or comma-separated transducer service names")
    ap.add_argument("--reference", default="hyper", help="the origin http_net is primarily compared with")
    ap.add_argument("--trophies", type=Path, help="the Garden's TROPHIES.md, whose payloads become seeds")
    ap.add_argument("--seeds", type=Path, action="append", default=[], help="extra seed file (repeatable)")
    ap.add_argument("--mutations", type=int, default=0, help="number of random mutations of the seeds to run")
    ap.add_argument("--rng-seed", type=int, default=58, help="seed for the mutation RNG, for reproducible runs")
    ap.add_argument("--wait", type=float, default=300.0, help="seconds to wait for every service to answer")
    ap.add_argument("--ready-only", action="store_true", help="only wait until every service answers, then exit")
    ap.add_argument("--garden-ref", default="unknown")
    ap.add_argument("--http-net-ref", default="unknown")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()

    split = lambda s: [n for n in re.split(r"[\s,]+", s) if n]  # noqa: E731
    origin_names = list(dict.fromkeys([SUBJECT] + split(args.origins)))
    transducer_names = list(dict.fromkeys(split(args.transducers)))
    missing = [n for n in origin_names if n not in ORIGIN_DICT] + [n for n in transducer_names if n not in TRANSDUCER_DICT]
    if missing:
        infra_error(f"not running or not registered: {', '.join(missing)}")
    origins = [ORIGIN_DICT[n] for n in origin_names]
    transducers = [TRANSDUCER_DICT[n] for n in transducer_names]

    wait_ready(origins, args.wait, transducers)
    if args.ready_only:
        print("ready: " + ", ".join(origin_names + transducer_names))
        return
    if args.out is None:
        ap.error("--out is required unless --ready-only is given")
    baseline = ORIGIN_DICT[SUBJECT].parsed_roundtrip(BASELINE)
    if len(baseline) != 1 or not isinstance(baseline[0], HTTPRequest):
        infra_error(f"http_net does not echo a plain GET in the Garden format: {baseline!r}")

    seeds: list[list[bytes]] = []
    if args.trophies:
        seeds += trophy_seeds(args.trophies)
    for f in args.seeds:
        seeds += file_seeds(f)
    seeds = dedupe(seeds)
    if not seeds:
        infra_error("no seed payloads")

    runner = Runner(origins)
    cases: list[dict[str, Any]] = []
    counts = {"seeds": 0, "transduced": 0, "mutations": 0, "mutations_skipped": 0}

    for i, seed in enumerate(seeds):
        counts["seeds"] += 1
        case = run_case(runner, f"seed-{i:03}", "seed", seed, seed, record_all=True)
        if case:
            cases.append(case)
        for t in transducers:
            try:
                sent = call_with_timeout(lambda: t.unparsed_roundtrip(seed), 30.0)  # type: ignore[attr-defined]
            except Exception as e:  # pylint: disable=broad-exception-caught
                warn(f"{t.name} failed on seed-{i:03}: {e}")
                continue
            # Nothing forwarded, or the transducer answered with its own
            # error response: there is nothing for the origins to parse.
            if not sent or any(p.startswith(b"HTTP/") for p in sent):
                continue
            counts["transduced"] += 1
            case = run_case(runner, f"seed-{i:03}-via-{t.name}", f"transduced:{t.name}", seed, sent, record_all=True)
            if case:
                cases.append(case)
        if SUBJECT in runner.down:
            break

    random.seed(args.rng_seed)
    for k in range(args.mutations if SUBJECT not in runner.down else 0):
        base = random.choice(seeds)
        # The mutator parses its own output with the Garden's reference
        # parser, which can fail on a mutant (an oversized chunk length
        # overflows its regex). No server has seen the mutant yet, so the
        # failure is the harness's, not a finding: count it and move on.
        try:
            mutated = mutations.mutate(base)
        except Exception:  # pylint: disable=broad-exception-caught
            counts["mutations_skipped"] += 1
            continue
        counts["mutations"] += 1
        case = run_case(runner, f"mut-{k:04}", "mutation", mutated, mutated, record_all=False)
        if case:
            cases.append(case)
        if SUBJECT in runner.down:
            break

    meta = {
        "garden_ref": args.garden_ref,
        "http_net_ref": args.http_net_ref,
        "origins": origin_names,
        "transducers": transducer_names,
        "reference": args.reference,
        "rng_seed": args.rng_seed,
        "counts": counts,
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "results.json").write_text(
        json.dumps({"meta": meta, "down": runner.down, "cases": cases}, indent=1, ensure_ascii=False), encoding="utf-8"
    )
    flagged = [c for c in cases if c.get("http_net_differs_from")]
    (args.out / "grids.txt").write_text(
        "\n\n".join(f"{c['id']}  {' '.join(c['payload'])}\n{c['grid']}" for c in flagged) + "\n", encoding="utf-8"
    )
    write_summary(args.out / "summary.md", meta, cases, runner.down)
    print(f"{len(flagged)} case(s) where http_net disagrees; see {args.out / 'summary.md'}")
    if LEAKED:
        # Daemon threads are still spinning: skip interpreter teardown.
        sys.stdout.flush()
        os._exit(0)


if __name__ == "__main__":
    main()

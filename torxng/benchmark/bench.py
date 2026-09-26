#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Latency / success benchmark for a SearXNG instance (stdlib only).

Sends every query of a query file ``--repeat`` times to the JSON API of a
SearXNG instance and writes one CSV row per request. Used to compare the Tor
stack (frontend, 127.0.0.1:8080) with the clearnet baseline (stock upstream
image, compose profile "baseline", 127.0.0.1:8081)::

    python bench.py --base-url http://127.0.0.1:8080 --label tor      --repeat 3 --out ../results/tor.csv
    python bench.py --base-url http://127.0.0.1:8081 --label baseline --repeat 3 --out ../results/baseline.csv
    python summarize.py ../results/tor.csv ../results/baseline.csv

Keep --sleep >= 0.5: the frontend allows 2 searches/s per client (nginx
limit_req, burst 10); faster runs would measure HTTP 429 instead of search
latency.

The query order is shuffled for every run (deterministically, ``--seed``) so
that no query always hits cold connections or already suspended engines.
Errors never abort the run; they are recorded in the ``error`` column.
"""

from __future__ import annotations

import argparse
import csv
import http.client
import json
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent

# A common desktop browser UA; the benchmark should look like a normal client.
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0"

FIELDS = [
    "label",
    "query",
    "run",
    "timestamp",
    "latency_s",
    "http_status",
    "n_results",
    "n_unresponsive",
    "unresponsive_engines",
    "error",
    # extra column: the engines' estimated hit count if the JSON API provides
    # it (empty otherwise; SearXNG 2026.9.25 does not include it)
    "number_of_results",
]


def load_queries(path: Path) -> list[str]:
    queries: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            queries.append(line)
    if not queries:
        raise SystemExit(f"no queries found in {path}")
    return queries


def search_once(base_url: str, query: str, categories: str, timeout: float, user_agent: str) -> dict[str, object]:
    """Run one search and return the measured values (never raises)."""
    params = {"q": query, "format": "json"}
    if categories:
        params["categories"] = categories
    url = base_url.rstrip("/") + "/search?" + urllib.parse.urlencode(params)
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": user_agent})

    row: dict[str, object] = {
        "http_status": "",
        "n_results": "",
        "n_unresponsive": "",
        "unresponsive_engines": "",
        "error": "",
        "number_of_results": "",
    }
    body = b""
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
            row["http_status"] = response.status
    except urllib.error.HTTPError as exc:
        row["http_status"] = exc.code
        row["error"] = f"HTTP {exc.code} {exc.reason}"
        try:
            body = exc.read()
        except (OSError, http.client.HTTPException):
            body = b""
    except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        row["error"] = f"{type(exc).__name__}: {reason}"
    row["latency_s"] = round(time.perf_counter() - start, 3)

    if row["http_status"] == 200:
        try:
            data = json.loads(body.decode("utf-8"))
            unresponsive = data.get("unresponsive_engines") or []
            row["n_results"] = len(data.get("results") or [])
            row["n_unresponsive"] = len(unresponsive)
            row["unresponsive_engines"] = ";".join(
                f"{item[0]}:{item[1]}" if isinstance(item, (list, tuple)) and len(item) >= 2 else str(item)
                for item in unresponsive
            )
            row["number_of_results"] = data.get("number_of_results", "")
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError, TypeError) as exc:
            row["error"] = f"invalid JSON response: {exc}"
    return row


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default="http://127.0.0.1:8080", help="SearXNG base URL")
    parser.add_argument("--label", required=True, help="label written to every row, e.g. tor or baseline")
    parser.add_argument("--queries", type=Path, default=HERE / "queries.txt", help="query file (one per line)")
    parser.add_argument("--repeat", type=int, default=3, help="number of runs over the query list")
    parser.add_argument("--out", type=Path, required=True, help="output CSV file (overwritten)")
    parser.add_argument("--sleep", type=float, default=1.0, help="pause between two requests in seconds")
    parser.add_argument("--timeout", type=float, default=60.0, help="HTTP timeout per request in seconds")
    parser.add_argument("--seed", type=int, default=42, help="seed for the per-run query shuffle")
    parser.add_argument("--categories", default="general", help="SearXNG categories parameter ('' = none)")
    parser.add_argument("--limit", type=int, default=0, help="use only the first N queries (0 = all)")
    parser.add_argument("--user-agent", default=DEFAULT_UA)
    args = parser.parse_args(argv)

    queries = load_queries(args.queries)
    if args.limit > 0:
        queries = queries[: args.limit]
    rng = random.Random(args.seed)
    total = len(queries) * args.repeat
    args.out.parent.mkdir(parents=True, exist_ok=True)

    print(f"[{args.label}] {len(queries)} queries x {args.repeat} runs = {total} requests against {args.base_url}")
    done = 0
    ok = 0
    with args.out.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        try:
            for run in range(1, args.repeat + 1):
                order = list(queries)
                rng.shuffle(order)
                for query in order:
                    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
                    row = search_once(args.base_url, query, args.categories, args.timeout, args.user_agent)
                    row.update({"label": args.label, "query": query, "run": run, "timestamp": timestamp})
                    writer.writerow(row)
                    fh.flush()
                    done += 1
                    success = row["http_status"] == 200 and isinstance(row["n_results"], int) and row["n_results"] > 0
                    ok += int(success)
                    detail = row["error"] or f"{row['n_results']} results"
                    if row["unresponsive_engines"]:
                        detail += f" | unresponsive: {row['unresponsive_engines']}"
                    print(
                        f"[{args.label}] {done:4d}/{total} run {run} {query!r:32s} "
                        f"{row['http_status'] or '---'} {row['latency_s']:6.2f}s {detail}",
                        flush=True,
                    )
                    if args.sleep > 0 and done < total:
                        time.sleep(args.sleep)
        except KeyboardInterrupt:
            print(f"[{args.label}] interrupted, {done} rows written to {args.out}", file=sys.stderr)
            return 130

    print(f"[{args.label}] done: {ok}/{done} successful searches, CSV written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

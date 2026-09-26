#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Summarise benchmark CSV files (from bench.py) as Markdown tables (stdlib only).

    python summarize.py ../results/tor.csv ../results/baseline.csv [--markdown ../results/summary.md]

Definitions used in the tables:

- success: HTTP 200 and at least one result
- latency: wall-clock time of the whole request as seen by the client, over
  ALL requests of a label (failed ones included, they cost the user time too);
  "median ok" only over successful searches
- p90: 90th percentile (statistics.quantiles, inclusive method)
- mean results: mean number of results over HTTP 200 responses
- >=1 unresponsive: share of HTTP 200 responses in which at least one engine
  did not answer (timeout, CAPTCHA, access denied, suspended, ...)
"""

from __future__ import annotations

import argparse
import csv
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path


def to_float(value: str) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def to_int(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def p90(values: list[float]) -> float:
    if len(values) < 2:
        return values[0]
    return statistics.quantiles(values, n=10, method="inclusive")[8]


def fmt_s(value: float | None) -> str:
    return "-" if value is None else f"{value:.2f}"


def fmt_pct(part: int, whole: int) -> str:
    return "-" if whole == 0 else f"{100.0 * part / whole:.1f} %"


def load_rows(paths: list[Path]) -> dict[str, list[dict[str, str]]]:
    by_label: dict[str, list[dict[str, str]]] = defaultdict(list)
    for path in paths:
        with path.open(encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                by_label[row.get("label") or path.stem].append(row)
    return by_label


def summarize(label: str, rows: list[dict[str, str]]) -> dict[str, object]:
    n = len(rows)
    latencies = [v for v in (to_float(r.get("latency_s", "")) for r in rows) if v is not None]
    http_ok = [r for r in rows if to_int(r.get("http_status", "")) == 200]
    success = [r for r in http_ok if (to_int(r.get("n_results", "")) or 0) > 0]
    ok_latencies = [v for v in (to_float(r.get("latency_s", "")) for r in success) if v is not None]
    results = [to_int(r.get("n_results", "")) or 0 for r in http_ok]
    with_unresponsive = [r for r in http_ok if (to_int(r.get("n_unresponsive", "")) or 0) > 0]

    engine_counts: Counter[str] = Counter()
    engine_errors: dict[str, Counter[str]] = defaultdict(Counter)
    for r in http_ok:
        for item in filter(None, (r.get("unresponsive_engines") or "").split(";")):
            engine, _, error = item.partition(":")
            engine_counts[engine] += 1
            engine_errors[engine][error or "?"] += 1
    top = []
    for engine, count in engine_counts.most_common(5):
        error, _ = engine_errors[engine].most_common(1)[0]
        top.append(f"{engine} {count} ({error})")

    transport_errors = Counter(r["error"].split(":")[0] for r in rows if r.get("error") and not r.get("http_status"))

    return {
        "label": label,
        "n": n,
        "success": fmt_pct(len(success), n),
        "median": fmt_s(statistics.median(latencies) if latencies else None),
        "p90": fmt_s(p90(latencies) if latencies else None),
        "max": fmt_s(max(latencies) if latencies else None),
        "median_ok": fmt_s(statistics.median(ok_latencies) if ok_latencies else None),
        "mean_results": "-" if not results else f"{statistics.mean(results):.1f}",
        "unresponsive": fmt_pct(len(with_unresponsive), len(http_ok)),
        "top": ", ".join(top) if top else "-",
        "transport_errors": ", ".join(f"{k} {v}" for k, v in transport_errors.most_common()) or "-",
    }


def render(summaries: list[dict[str, object]]) -> str:
    lines = [
        "| label | n | success | median s | p90 s | max s | median ok s | mean results | >=1 unresponsive |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for s in summaries:
        lines.append(
            f"| {s['label']} | {s['n']} | {s['success']} | {s['median']} | {s['p90']} | {s['max']} "
            f"| {s['median_ok']} | {s['mean_results']} | {s['unresponsive']} |"
        )
    lines += [
        "",
        "| label | top 5 unresponsive engines: count (most frequent error) | transport errors |",
        "|---|---|---|",
    ]
    for s in summaries:
        lines.append(f"| {s['label']} | {s['top']} | {s['transport_errors']} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("csv", nargs="+", type=Path, help="CSV files written by bench.py")
    parser.add_argument("--markdown", type=Path, help="also write the tables to this file")
    args = parser.parse_args(argv)

    by_label = load_rows(args.csv)
    if not by_label:
        print("no rows found", file=sys.stderr)
        return 1
    text = render([summarize(label, rows) for label, rows in by_label.items()])
    print(text, end="")
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Edge-case and security test suite for the Tor-only TorXNG stack.

Runs on the host (Windows or Linux, Python 3.10+, standard library only)
against the running Docker Compose stack in ``torxng/``: plain HTTP requests
to the published frontend port (``127.0.0.1:8080`` by default) plus
``docker`` / ``docker compose`` commands (exec, inspect, stats, run, stop,
start).

Groups (hardening spec, section 8; details in ``torxng/tests/README.md``):

* A - Tor-only / fail-closed
* B - container hardening
* C - HTTP edge cases (through the nginx frontend)
* D - Tor behaviour (plus pure unit tests of the onion v3 / ed25519 checks)
* E - resources (reported, soft thresholds)

Destructive tests (A10-A17: guard containers with bad settings, stopping and
starting tor) only run with ``--destructive`` and always restore the stack
(tor running and healthy, core healthy) before the suite ends.

Usage::

    python torxng/tests/test_stack.py [--compose-file torxng/docker-compose.yml]
        [--base-url http://127.0.0.1:8080] [--destructive] [--json out.json]
        [-k pattern] [-v] [--list]
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import datetime
import fnmatch
import hashlib
import hmac
import http.client as httpclient
import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import traceback
import unittest
import urllib.parse

# ---------------------------------------------------------------------------
# Constants from the hardening spec
# ---------------------------------------------------------------------------

HERE = os.path.dirname(os.path.abspath(__file__))
STACK_DIR = os.path.dirname(HERE)
DEFAULT_COMPOSE = os.path.join(STACK_DIR, "docker-compose.yml")
DEFAULT_BASE_URL = "http://127.0.0.1:8080"

VENV_PY = "/usr/local/searxng/.venv/bin/python"
TOR_IP = "172.30.0.2"
FRONTEND_IP = "172.30.0.3"
CORE_IP = "172.30.0.10"
ISOLATED_SUBNET = ipaddress.ip_network("172.30.0.0/24")
GUARD_EXIT_CODE = 78
STACK_SERVICES = ("tor", "core", "frontend")
BASELINE_NAMES = ("baseline", "core-direct", "searxng-direct")
STOCK_IMAGE = "docker.io/searxng/searxng:2026.9.25-12f8b6515"
# proxy variables libcurl honours (any letter case); the guard refuses them
PROXY_ENV_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy")

# Search requests are limited to one engine where the engine set does not
# matter, so the edge-case tests do not hammer every engine over Tor.
PROBE_ENGINE = "wikipedia"
SEARCH_TIMEOUT = 90.0
USER_AGENT = "torxng-stack-tests/1.0"
ACCEPT_LANGUAGE = "en-US,en;q=0.8"
MIB = 1024 * 1024

EXPECTED_UID = {"core": 977, "frontend": 101, "tor": None}  # None = any non-root uid
SPEC_LIMITS = {
    "tor": {"memory": 128 * MIB, "cpus": 0.5, "pids": 64},
    "core": {"memory": 320 * MIB, "cpus": 1.0, "pids": 256},
    "frontend": {"memory": 32 * MIB, "cpus": 0.25, "pids": 32},
}
SOFT_IMAGE_MB = {"tor": 64, "core": 450, "frontend": 80}
SOFT_STARTUP_S = {"tor": 300, "core": 120, "frontend": 30}

EXPECTED_HEADERS = {
    "content-security-policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; "
        "base-uri 'none'; manifest-src 'self'"
    ),
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
    "permissions-policy": (
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), "
        "payment=(), usb=(), interest-cohort=()"
    ),
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "x-robots-tag": "noindex, nofollow",
}

SENSITIVE_MARKERS = (
    b"root:x:0:0",
    b"secret_key",
    b"use_default_settings",
    b"HashedControlPassword",
    b"hs_ed25519",
    b"PRIVATE KEY",
)

GROUP_TITLES = {
    "A": "Tor-only / fail-closed",
    "B": "Container hardening",
    "C": "HTTP edge cases",
    "D": "Tor behaviour",
    "E": "Resources",
}


# ---------------------------------------------------------------------------
# Global run state
# ---------------------------------------------------------------------------


class Config:  # pylint: disable=too-few-public-methods
    compose_file = DEFAULT_COMPOSE
    base_url = DEFAULT_BASE_URL
    host = "127.0.0.1"
    port = 8080
    destructive = False
    verbose = False


CFG = Config()
NOTES: dict[str, list[str]] = {}
METRICS: dict[str, object] = {}
RESTORE_PROBLEMS: list[str] = []


def metric(key: str, value: object, section: str | None = None) -> None:
    if section:
        METRICS.setdefault(section, {})[key] = value  # type: ignore[index]
    else:
        METRICS[key] = value


def log(msg: str) -> None:
    if CFG.verbose:
        print(f"    [debug] {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Subprocess / docker helpers
# ---------------------------------------------------------------------------


class CmdResult:
    def __init__(self, args, rc, out, err, timed_out=False, elapsed=0.0):
        self.args = args
        self.rc = rc
        self.out = out or ""
        self.err = err or ""
        self.timed_out = timed_out
        self.elapsed = elapsed

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.timed_out

    @property
    def output(self) -> str:
        return self.out + self.err

    def brief(self, limit: int = 300) -> str:
        text = " ".join(self.output.split())
        return text[:limit] + ("..." if len(text) > limit else "")


def _to_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value


def run_cmd(args, timeout: float = 60.0, input_text: str | None = None) -> CmdResult:
    t0 = time.monotonic()
    log("run: " + " ".join(str(a) for a in args)[:200])
    kwargs = {}
    if input_text is None:
        kwargs["stdin"] = subprocess.DEVNULL
    try:
        proc = subprocess.run(
            [str(a) for a in args],
            input=input_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            **kwargs,
        )
        res = CmdResult(args, proc.returncode, proc.stdout, proc.stderr, False, time.monotonic() - t0)
    except subprocess.TimeoutExpired as exc:
        res = CmdResult(args, None, _to_text(exc.stdout), _to_text(exc.stderr), True, time.monotonic() - t0)
    except OSError as exc:
        res = CmdResult(args, 127, "", str(exc), False, time.monotonic() - t0)
    log(f"  -> rc={res.rc} timed_out={res.timed_out} {res.elapsed:.1f}s")
    return res


def parse_json_stream(text: str) -> list:
    """``docker ... --format json`` prints either one JSON array or one object per line."""
    text = (text or "").strip()
    if not text:
        return []
    if text.startswith("["):
        try:
            data = json.loads(text)
            return data if isinstance(data, list) else [data]
        except ValueError:
            return []
    items = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except ValueError:
            pass
    return items


class Stack:
    """Thin wrapper around ``docker compose -f <file>`` and ``docker``."""

    def __init__(self):
        self.docker = shutil.which("docker") or "docker"
        self._unavailable: str | None = None
        self._ps: dict[str, dict] | None = None
        self._ps_time = 0.0
        self._inspect: dict[str, dict] = {}

    # -- raw commands ------------------------------------------------------

    def compose(self, *args, timeout: float = 120.0, input_text: str | None = None) -> CmdResult:
        return run_cmd([self.docker, "compose", "-f", CFG.compose_file, *args], timeout, input_text)

    def dock(self, *args, timeout: float = 60.0, input_text: str | None = None) -> CmdResult:
        return run_cmd([self.docker, *args], timeout, input_text)

    # -- availability ------------------------------------------------------

    def unavailable_reason(self) -> str | None:
        if self._unavailable is None:
            self._unavailable = self._check()
        return self._unavailable or None

    def _check(self) -> str:
        if not shutil.which("docker"):
            return "docker CLI not found in PATH"
        res = self.dock("version", "--format", "{{.Server.Version}}", timeout=30)
        if not res.ok:
            return "docker daemon not reachable: " + res.brief(200)
        metric("docker_server", res.out.strip(), "environment")
        if not os.path.isfile(CFG.compose_file):
            return f"compose file not found: {CFG.compose_file}"
        res = self.compose("version", "--short", timeout=30)
        if not res.ok:
            return "docker compose v2 plugin not available: " + res.brief(200)
        metric("compose", res.out.strip(), "environment")
        res = self.compose("config", "--quiet", timeout=60)
        if not res.ok:
            return "compose file does not validate (torxng/.env missing?): " + res.brief(200)
        return ""

    # -- containers --------------------------------------------------------

    def ps(self, refresh: bool = False) -> dict[str, dict]:
        if refresh or self._ps is None or time.monotonic() - self._ps_time > 10:
            res = self.compose("ps", "-a", "--format", "json", timeout=60)
            items = parse_json_stream(res.out) if res.ok else []
            self._ps = {i["Service"]: i for i in items if isinstance(i, dict) and i.get("Service")}
            self._ps_time = time.monotonic()
            self._inspect = {}
        return self._ps

    def refresh(self) -> None:
        self.ps(refresh=True)

    def container_id(self, service: str, refresh: bool = False) -> str | None:
        entry = self.ps(refresh).get(service)
        return entry.get("ID") if entry else None

    def inspect(self, service: str, refresh: bool = False) -> dict | None:
        cid = self.container_id(service, refresh)
        if not cid:
            return None
        if refresh or cid not in self._inspect:
            res = self.dock("inspect", cid, timeout=30)
            if not res.ok:
                return None
            data = parse_json_stream(res.out)
            if not data:
                return None
            self._inspect[cid] = data[0]
        return self._inspect[cid]

    def is_running(self, service: str, refresh: bool = False) -> bool:
        info = self.inspect(service, refresh)
        return bool(info and (info.get("State") or {}).get("Running"))

    def health(self, service: str, refresh: bool = False) -> str | None:
        info = self.inspect(service, refresh)
        if not info:
            return None
        return ((info.get("State") or {}).get("Health") or {}).get("Status")

    def exec_in(self, service: str, cmd, timeout: float = 60.0, input_text: str | None = None) -> CmdResult:
        cid = self.container_id(service)
        if not cid:
            return CmdResult(cmd, 125, "", f"service {service} has no container", False)
        args = ["exec"] + (["-i"] if input_text is not None else []) + [cid] + list(cmd)
        res = self.dock(*args, timeout=timeout, input_text=input_text)
        if res.rc not in (0, None) and ("No such container" in res.err or "is not running" in res.err):
            # container was recreated meanwhile (the stack is being worked on): retry once
            cid = self.container_id(service, refresh=True)
            if cid:
                args = ["exec"] + (["-i"] if input_text is not None else []) + [cid] + list(cmd)
                res = self.dock(*args, timeout=timeout, input_text=input_text)
        return res

    def py_in_core(self, code: str, timeout: float = 60.0) -> tuple[dict | None, CmdResult]:
        res = self.exec_in("core", [VENV_PY, "-"], timeout=timeout, input_text=code)
        data = None
        for line in reversed(res.out.strip().splitlines()):
            line = line.strip()
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                    break
                except ValueError:
                    continue
        return data, res

    def wait_healthy(self, services, timeout: float) -> tuple[bool, dict]:
        """Wait until every service runs and (if it has a healthcheck) is healthy."""
        deadline = time.monotonic() + timeout
        while True:
            states = {}
            all_ok = True
            self.refresh()
            for svc in services:
                info = self.inspect(svc)
                if not info:
                    states[svc] = "missing"
                    all_ok = False
                    continue
                state = info.get("State") or {}
                if not state.get("Running"):
                    states[svc] = state.get("Status", "not running")
                    all_ok = False
                    continue
                health = (state.get("Health") or {}).get("Status")
                states[svc] = health or "running"
                if health and health != "healthy":
                    all_ok = False
            if all_ok:
                return True, states
            if time.monotonic() >= deadline:
                return False, states
            time.sleep(5)

    def project_name(self) -> str | None:
        for entry in self.ps().values():
            if entry.get("Project"):
                return entry["Project"]
        for svc in self.ps():
            info = self.inspect(svc)
            if info:
                return ((info.get("Config") or {}).get("Labels") or {}).get("com.docker.compose.project")
        return None

    def project_containers(self) -> list[dict]:
        name = self.project_name()
        if not name:
            return []
        res = self.dock("ps", "-q", "--no-trunc", "--filter", f"label=com.docker.compose.project={name}")
        ids = res.out.split()
        if not ids:
            return []
        res = self.dock("inspect", *ids, timeout=60)
        return parse_json_stream(res.out)

    def isolated_network(self) -> str | None:
        info = self.inspect("core")
        if not info:
            return None
        for name in ((info.get("NetworkSettings") or {}).get("Networks") or {}):
            res = self.dock("network", "inspect", name, "--format", "{{.Internal}}", timeout=30)
            if res.ok and res.out.strip() == "true":
                return name
        return None


STACK = Stack()


def restore_stack(context: str, timeout: float = 900.0) -> tuple[bool, dict]:
    """Bring tor, core and frontend back (``docker compose start``) and wait for health."""
    STACK.refresh()
    for svc in STACK_SERVICES:
        if STACK.container_id(svc) and not STACK.is_running(svc, refresh=True):
            res = STACK.compose("start", svc, timeout=300)
            if not res.ok:
                RESTORE_PROBLEMS.append(f"{context}: 'docker compose start {svc}' failed: {res.brief(200)}")
    ok, states = STACK.wait_healthy(STACK_SERVICES, timeout)
    if not ok:
        RESTORE_PROBLEMS.append(f"{context}: stack not healthy after {timeout:.0f}s: {states}")
    return ok, states


# ---------------------------------------------------------------------------
# HTTP helpers (http.client: arbitrary methods, no redirects, no raising)
# ---------------------------------------------------------------------------


class Resp:
    def __init__(self, status: int, reason: str, headers: list, body: bytes, elapsed: float):
        self.status = status
        self.reason = reason
        self.headers = headers
        self.body = body
        self.elapsed = elapsed

    def header(self, name: str) -> str | None:
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return None

    def header_all(self, name: str) -> list[str]:
        name = name.lower()
        return [value for key, value in self.headers if key.lower() == name]

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def json(self):
        return json.loads(self.body.decode("utf-8"))

    def __repr__(self):
        return f"<Resp {self.status} {len(self.body)}B>"


def http(method: str, path: str, headers: dict | None = None, body=None, timeout: float = 30.0) -> Resp:
    """One request on a fresh connection; never raises for 4xx/5xx, never follows redirects.

    Connection failures (refused, unreachable) raise OSError. Once connected, a
    missing or broken response (closed, reset, timeout) is returned as status 0
    with the reason in ``Resp.reason`` so edge-case tests can report it."""
    conn = httpclient.HTTPConnection(CFG.host, CFG.port, timeout=timeout)
    hdrs = {"Connection": "close", "User-Agent": USER_AGENT}
    hdrs.update(headers or {})
    if isinstance(body, str):
        body = body.encode("utf-8")
    t0 = time.monotonic()
    try:
        conn.connect()
        try:
            conn.request(method, path, body=body, headers=hdrs)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass  # the server may answer (e.g. 413) before it has read the whole body
        try:
            resp = conn.getresponse()
            data = resp.read()
        except (httpclient.HTTPException, OSError) as exc:
            reason = "timeout" if isinstance(exc, (socket.timeout, TimeoutError)) else exc.__class__.__name__
            return Resp(0, f"no response ({reason})", [], b"", time.monotonic() - t0)
        return Resp(resp.status, resp.reason, resp.getheaders(), data, time.monotonic() - t0)
    finally:
        conn.close()


def is_bad(status) -> bool:
    """5xx, no response at all (0) or a client-side error string."""
    return not isinstance(status, int) or status == 0 or status >= 500


def status_str(resp: Resp) -> str:
    return str(resp.status) if resp.status else resp.reason


def http_retry_429(method: str, path: str, headers: dict | None = None, body=None, timeout: float = 30.0,
                   retries: int = 10) -> Resp:
    """Like http(), but waits and retries while nginx answers 429 (earlier tests may have
    drained the per-IP rate limit bucket)."""
    resp = http(method, path, headers, body, timeout)
    for attempt in range(retries):
        if resp.status != 429:
            break
        time.sleep(1.0 + 0.5 * attempt)
        resp = http(method, path, headers, body, timeout)
    return resp


def search(params: dict, method: str = "GET", headers: dict | None = None, timeout: float = SEARCH_TIMEOUT) -> Resp:
    hdrs = {"Accept-Language": ACCEPT_LANGUAGE}
    hdrs.update(headers or {})
    if method == "GET":
        return http_retry_429("GET", "/search?" + urllib.parse.urlencode(params), hdrs, None, timeout)
    hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    return http_retry_429(method, "/search", hdrs, urllib.parse.urlencode(params), timeout)


_HTTP_REASON: str | None = None


def http_unavailable_reason() -> str | None:
    global _HTTP_REASON  # pylint: disable=global-statement
    if _HTTP_REASON is None:
        try:
            resp = http_retry_429("GET", "/healthz", timeout=15)
            if is_bad(resp.status):
                _HTTP_REASON = f"frontend answers /healthz with {status_str(resp)} (core down?)"
            else:
                _HTTP_REASON = ""
        except OSError as exc:
            _HTTP_REASON = f"frontend not reachable at {CFG.base_url}: {exc.__class__.__name__}: {exc}"
    return _HTTP_REASON or None


def answer_texts(data: dict) -> list[str]:
    """``answers`` of the JSON API: objects (``answer`` key) or plain strings."""
    texts = []
    for item in data.get("answers") or []:
        if isinstance(item, str):
            texts.append(item)
        elif isinstance(item, dict):
            for key in ("answer", "content", "title", "text"):
                if isinstance(item.get(key), str) and item[key]:
                    texts.append(item[key])
                    break
            else:
                texts.append(json.dumps(item))
    return texts


def csp_directives(value: str) -> list[str]:
    return sorted(" ".join(d.split()) for d in value.split(";") if d.strip())


def comma_items(value: str) -> list[str]:
    return sorted(" ".join(x.split()) for x in value.split(",") if x.strip())


def header_value_ok(name: str, actual: str, expected: str) -> bool:
    name = name.lower()
    if name == "content-security-policy":
        return csp_directives(actual) == csp_directives(expected)
    if name in ("permissions-policy", "x-robots-tag"):
        return comma_items(actual.lower()) == comma_items(expected.lower())
    return " ".join(actual.split()).lower() == expected.lower()


def security_header_issues(headers: list) -> list[tuple[str, str]]:
    issues = []
    for name, expected in EXPECTED_HEADERS.items():
        values = [v for k, v in headers if k.lower() == name]
        if not values:
            issues.append((name, "missing"))
        elif len(values) > 1:
            issues.append((name, f"sent {len(values)} times"))
        elif not header_value_ok(name, values[0], expected):
            issues.append((name, f"unexpected value {values[0]!r}"))
    return issues


def retry(func, attempts: int = 3, delay: float = 15.0):
    """``func() -> (ok, value)``; returns ``(ok, value, attempts_used)``."""
    value = None
    for i in range(attempts):
        ok, value = func()
        if ok:
            return True, value, i + 1
        if i < attempts - 1:
            log(f"retry {i + 1}/{attempts} failed: {str(value)[:200]}")
            time.sleep(delay)
    return False, value, attempts


# ---------------------------------------------------------------------------
# Small parsers
# ---------------------------------------------------------------------------

TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2",
    "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}


def _decode_proc_addr(value: str):
    hexip, hexport = value.rsplit(":", 1)
    raw = bytes.fromhex(hexip)
    if len(raw) == 4:
        addr = ipaddress.IPv4Address(raw[::-1])
    elif len(raw) == 16:
        addr = ipaddress.IPv6Address(b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4)))
    else:
        raise ValueError(value)
    return addr, int(hexport, 16)


def parse_proc_net(text: str) -> list:
    """Rows of /proc/net/{tcp,tcp6,udp,udp6}: ``((local_ip, port), (remote_ip, port), state)``."""
    rows = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[0] == "sl" or ":" not in fields[1]:
            continue
        try:
            rows.append((_decode_proc_addr(fields[1]), _decode_proc_addr(fields[2]), fields[3].upper()))
        except ValueError:
            continue
    return rows


def hex_to_ipv4(value: str) -> str:
    return str(ipaddress.IPv4Address(bytes.fromhex(value)[::-1]))


def parse_status_blocks(text: str) -> list[dict]:
    """Output of ``for f in /proc/[0-9]*/status; do echo "@@ $f"; cat $f; done``."""
    blocks, current = [], None
    for line in text.splitlines():
        if line.startswith("@@ "):
            current = {"_file": line[3:].strip()}
            blocks.append(current)
        elif current is not None and ":" in line:
            key, _, value = line.partition(":")
            current[key.strip()] = value.strip()
    return [b for b in blocks if "Uid" in b]


def parse_status(text: str) -> dict:
    result = {}
    for line in text.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            result[key.strip()] = value.strip()
    return result


def parse_size(value: str) -> float | None:
    """'147.4MiB' -> bytes (docker stats units)."""
    match = re.match(r"\s*([\d.]+)\s*([KMGTP]?i?B)\s*$", value or "", re.IGNORECASE)
    if not match:
        return None
    number, unit = float(match.group(1)), match.group(2).lower()
    factors = {
        "b": 1, "kib": 1024, "mib": 1024 ** 2, "gib": 1024 ** 3, "tib": 1024 ** 4,
        "kb": 1000, "mb": 1000 ** 2, "gb": 1000 ** 3, "tb": 1000 ** 4,
    }
    return number * factors.get(unit, 1)


def parse_ts(value: str) -> float | None:
    """Docker RFC3339 timestamp (nanoseconds, 'Z' or offset) -> unix time."""
    match = re.match(
        r"(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:\.(\d+))?\s*(Z|[+-]\d\d:?\d\d)?", value or ""
    )
    if not match:
        return None
    year, mon, day, hour, minute, sec = (int(match.group(i)) for i in range(1, 7))
    if year < 1971:
        return None
    micro = int((match.group(7) or "0")[:6].ljust(6, "0"))
    tz = match.group(8) or "Z"
    offset = datetime.timedelta(0)
    if tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        offset = sign * datetime.timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
    stamp = datetime.datetime(year, mon, day, hour, minute, sec, micro, tzinfo=datetime.timezone(offset))
    return stamp.timestamp()


def parse_torrc(text: str) -> dict[str, list[str]]:
    options: dict[str, list[str]] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        key, _, value = line.partition(" ")
        options.setdefault(key.strip().lower(), []).append(" ".join(value.split()))
    return options


def fmt_mib(value: float | None) -> str:
    return "n/a" if value is None else f"{value / MIB:.1f} MiB"


# ---------------------------------------------------------------------------
# Onion v3 address + ed25519 point checks (pure functions, unit tested in D10-D12)
# ---------------------------------------------------------------------------

ONION_CHECKSUM_PREFIX = b".onion checksum"
ONION_V3_VERSION = b"\x03"
HS_PUBKEY_HEADER = b"== ed25519v1-public: type0 ==\x00\x00\x00"


def onion_v3_checksum(pubkey: bytes, version: bytes = ONION_V3_VERSION) -> bytes:
    """CHECKSUM = SHA3-256(".onion checksum" || PUBKEY || VERSION)[:2] (rend-spec-v3)."""
    return hashlib.sha3_256(ONION_CHECKSUM_PREFIX + pubkey + version).digest()[:2]


def onion_v3_address(pubkey: bytes) -> str:
    """onion_address = base32(PUBKEY || CHECKSUM || VERSION) + ".onion"."""
    if len(pubkey) != 32:
        raise ValueError("an ed25519 public key has 32 bytes")
    raw = pubkey + onion_v3_checksum(pubkey) + ONION_V3_VERSION
    return base64.b32encode(raw).decode("ascii").lower() + ".onion"


def verify_onion_v3(address: str) -> tuple[bool, str, bytes | None]:
    """Returns ``(ok, reason, pubkey)``; the pubkey is returned whenever it could be decoded."""
    label = address.strip().lower()
    if label.endswith(".onion"):
        label = label[: -len(".onion")]
    if len(label) != 56:
        return False, f"expected 56 base32 characters, got {len(label)}", None
    if not re.fullmatch(r"[a-z2-7]{56}", label):
        return False, "contains characters outside the base32 alphabet [a-z2-7]", None
    raw = base64.b32decode(label.upper())
    if len(raw) != 35:
        return False, f"decodes to {len(raw)} bytes, expected 35", None
    pubkey, checksum, version = raw[:32], raw[32:34], raw[34:35]
    if version != ONION_V3_VERSION:
        return False, f"version byte 0x{version.hex()} (expected 0x03)", pubkey
    expected = onion_v3_checksum(pubkey, version)
    if checksum != expected:
        return False, f"checksum mismatch: address carries {checksum.hex()}, SHA3-256 gives {expected.hex()}", pubkey
    return True, "valid v3 onion address (version 0x03, checksum verified)", pubkey


ED_P = 2 ** 255 - 19
ED_D = (-121665 * pow(121666, ED_P - 2, ED_P)) % ED_P
ED_L = 2 ** 252 + 27742317777372353535851937790883648493
ED_SQRT_M1 = pow(2, (ED_P - 1) // 4, ED_P)
ED_IDENTITY = (0, 1, 1, 0)
ED_BASE_ENCODED = bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666")


def _ed_add(pt1, pt2):
    """Point addition in extended coordinates (RFC 8032, section 5.1.4)."""
    p = ED_P
    a = (pt1[1] - pt1[0]) * (pt2[1] - pt2[0]) % p
    b = (pt1[1] + pt1[0]) * (pt2[1] + pt2[0]) % p
    c = 2 * pt1[3] * pt2[3] * ED_D % p
    d = 2 * pt1[2] * pt2[2] % p
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % p, g * h % p, f * g % p, e * h % p)


def _ed_mul(scalar: int, point):
    result = ED_IDENTITY
    while scalar > 0:
        if scalar & 1:
            result = _ed_add(result, point)
        point = _ed_add(point, point)
        scalar >>= 1
    return result


def _ed_is_identity(point) -> bool:
    return point[0] % ED_P == 0 and (point[1] - point[2]) % ED_P == 0


def ed25519_decode(data: bytes):
    """Decode a compressed point (RFC 8032, section 5.1.3); raises ValueError."""
    if len(data) != 32:
        raise ValueError("public key must be 32 bytes")
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= ED_P:
        raise ValueError("non-canonical encoding (y >= p)")
    x2 = (y * y - 1) * pow(ED_D * y * y + 1, ED_P - 2, ED_P) % ED_P
    if x2 == 0:
        if sign:
            raise ValueError("invalid encoding (x = 0 with the sign bit set)")
        x = 0
    else:
        x = pow(x2, (ED_P + 3) // 8, ED_P)
        if (x * x - x2) % ED_P != 0:
            x = x * ED_SQRT_M1 % ED_P
        if (x * x - x2) % ED_P != 0:
            raise ValueError("point is not on the curve")
        if (x & 1) != sign:
            x = ED_P - x
    return (x, y, 1, x * y % ED_P)


def ed25519_encode(point) -> bytes:
    zinv = pow(point[2], ED_P - 2, ED_P)
    x, y = point[0] * zinv % ED_P, point[1] * zinv % ED_P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def ed25519_pubkey_check(data: bytes) -> tuple[bool, str]:
    """The same checks as Tor's ed25519_validate_pubkey(): on the curve, not the
    identity, and l * P == identity (no small-order / torsion component)."""
    try:
        point = ed25519_decode(data)
    except ValueError as exc:
        return False, str(exc)
    if _ed_is_identity(point):
        return False, "identity element"
    if not _ed_is_identity(_ed_mul(ED_L, point)):
        return False, "point has a small-order (torsion) component"
    return True, "valid ed25519 point of prime order l"


# ---------------------------------------------------------------------------
# Probe scripts executed with the venv python inside the core container
# (they print one JSON line on stdout)
# ---------------------------------------------------------------------------

PROBE_IP_EGRESS = r'''
import json, socket, urllib.request, urllib.error
res = []
def tcp(host, port):
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
    except OSError as e:
        return "blocked: socket(): %s" % e
    s.settimeout(6)
    try:
        s.connect((host, port))
        return "CONNECTED"
    except OSError as e:
        return "blocked: %s" % (e.strerror or repr(e))
    finally:
        s.close()
def udp_dns(host):
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(4)
    try:
        s.sendto(q, (host, 53))
    except OSError as e:
        s.close()
        return "blocked: %s" % (e.strerror or repr(e))
    try:
        s.recvfrom(512)
        return "REPLY RECEIVED"
    except OSError:
        return "SENT (the kernel had a route), no reply"
    finally:
        s.close()
for host, port in (("1.1.1.1", 443), ("9.9.9.9", 443), ("8.8.8.8", 53), ("2606:4700:4700::1111", 443)):
    res.append(["tcp %s port %d" % (host, port), tcp(host, port)])
for host in ("8.8.8.8", "1.1.1.1"):
    res.append(["udp dns %s" % host, udp_dns(host)])
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:
    with opener.open("http://1.1.1.1/", timeout=8) as r:
        res.append(["http://1.1.1.1/", "RESPONSE %s" % r.status])
except urllib.error.HTTPError as e:
    res.append(["http://1.1.1.1/", "RESPONSE %s" % e.code])
except Exception as e:
    res.append(["http://1.1.1.1/", "blocked: %s" % (getattr(e, "reason", None) or e)])
print(json.dumps({"results": res}))
'''

PROBE_HOST_EGRESS = r'''
import json, urllib.request, urllib.error
res = []
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
for url in ("https://check.torproject.org/api/ip", "http://example.com/", "https://www.wikipedia.org/"):
    try:
        with opener.open(url, timeout=10) as r:
            res.append([url, "RESPONSE %s" % r.status])
    except urllib.error.HTTPError as e:
        res.append([url, "RESPONSE %s" % e.code])
    except Exception as e:
        res.append([url, "blocked: %s" % (getattr(e, "reason", None) or e)])
print(json.dumps({"results": res}))
'''

PROBE_DNS = r'''
import json, socket
out = {"external": {}, "internal": {}}
def resolve(name, port=443):
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(name, port, proto=socket.IPPROTO_TCP)})
    except OSError as e:
        return "failed: %s" % e
for name in ("check.torproject.org", "example.com", "www.wikipedia.org"):
    out["external"][name] = resolve(name)
for name in ("tor", "frontend"):
    out["internal"][name] = resolve(name, 80)
try:
    out["nameservers"] = [l.split()[1] for l in open("/etc/resolv.conf") if l.startswith("nameserver")]
except OSError as e:
    out["nameservers"] = str(e)
print(json.dumps(out))
'''

PROBE_SAFESOCKS = r'''
import json, socket, struct
TOR = ("tor", 9050)
def recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            break
        b += c
    return b
def socks5(dst, port, domain):
    try:
        s = socket.create_connection(TOR, timeout=20)
    except OSError as e:
        return "no SOCKS connection: %s" % e
    s.settimeout(120)
    try:
        s.sendall(b"\x05\x01\x00")
        r = recv_exact(s, 2)
        if r != b"\x05\x00":
            return "method negotiation failed: %r" % r
        if domain:
            h = dst.encode()
            req = b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", port)
        else:
            req = b"\x05\x01\x00\x01" + socket.inet_aton(dst) + struct.pack(">H", port)
        s.sendall(req)
        r = recv_exact(s, 2)
        if len(r) < 2:
            return "closed by tor without a reply"
        return "rep=%d" % r[1]
    except OSError as e:
        return "error: %s" % e
    finally:
        s.close()
def socks4(ip, port):
    try:
        s = socket.create_connection(TOR, timeout=20)
    except OSError as e:
        return "no SOCKS connection: %s" % e
    s.settimeout(120)
    try:
        s.sendall(b"\x04\x01" + struct.pack(">H", port) + socket.inet_aton(ip) + b"torxng\x00")
        r = recv_exact(s, 8)
        if len(r) < 2:
            return "closed by tor without a reply"
        return "rep=%d" % r[1]
    except OSError as e:
        return "error: %s" % e
    finally:
        s.close()
out = {"socks5_ip": socks5("1.1.1.1", 443, False), "socks4_ip": socks4("1.1.1.1", 443)}
out["socks5_hostname"] = socks5("check.torproject.org", 443, True)
print(json.dumps(out))
'''

PROBE_CONTROL_REACH = r'''
import json, os, socket
def reach(host, port):
    try:
        with socket.create_connection((host, port), timeout=5):
            return "OPEN"
    except OSError as e:
        return "closed: %s" % (e.strerror or e.__class__.__name__)
out = {
    "172.30.0.2:9051": reach("172.30.0.2", 9051),
    "tor:9051": reach("tor", 9051),
    "tor:9050": reach("tor", 9050),
    "env_password": "SEARXNG_TOR_CONTROL_PASSWORD" in os.environ,
}
print(json.dumps(out))
'''

# busybox nc inside the tor container; PORT is replaced. The password is read
# from the Compose secret (fallback: env) inside the container only, it never
# appears on a command line or in the output.
TOR_CONTROL_NC = r'''
command -v nc >/dev/null 2>&1 || { echo NO_NC; exit 0; }
printf 'PROTOCOLINFO 1\r\nGETINFO version\r\n' | nc -w 5 127.0.0.1 PORT; echo '@@'
printf 'AUTHENTICATE "torxng-wrong-password"\r\nGETINFO version\r\n' | nc -w 5 127.0.0.1 PORT; echo '@@'
if [ -r /run/secrets/tor_control_password ]; then
  PW=$(tr -d '\r\n' < /run/secrets/tor_control_password)
else
  PW=${TOR_CONTROL_PASSWORD:-}
fi
if [ -n "$PW" ]; then
  printf 'AUTHENTICATE "%s"\r\nGETINFO version\r\nQUIT\r\n' "$PW" | nc -w 5 127.0.0.1 PORT
else
  echo NOPASSWORD
fi
'''

PROBE_SETTINGS = r'''
import json
import searx
from searx import settings
def urls(p):
    if not p:
        return []
    if isinstance(p, str):
        return [p]
    if isinstance(p, dict):
        r = []
        for v in p.values():
            r += urls(v)
        return r
    if isinstance(p, (list, tuple)):
        r = []
        for v in p:
            r += urls(v)
        return r
    return [repr(p)]
o = settings.get("outgoing", {})
out = {
    "using_tor_proxy": o.get("using_tor_proxy"),
    "proxies": urls(o.get("proxies")),
    "tor_circuits": o.get("tor_circuits"),
    "verify": o.get("verify"),
    "tor_control_host": (o.get("tor_control") or {}).get("host"),
    "tor_control_password_set": bool((o.get("tor_control") or {}).get("password")),
    "networks": {},
    "engines": {},
    "limiter": settings["server"].get("limiter"),
    "public_instance": settings["server"].get("public_instance"),
    "image_proxy": settings["server"].get("image_proxy"),
    "autocomplete": settings["search"].get("autocomplete"),
    "formats": settings["search"].get("formats"),
}
for n, net in (o.get("networks") or {}).items():
    out["networks"][n] = urls((net or {}).get("proxies"))
for e in settings.get("engines") or []:
    ps = urls(e.get("proxies"))
    net = e.get("network")
    if isinstance(net, dict):
        ps += urls(net.get("proxies"))
    if ps:
        out["engines"][e.get("name")] = ps
print(json.dumps(out, default=str))
'''

# ---------------------------------------------------------------------------
# Settings for the guard tests (A10-A13)
# ---------------------------------------------------------------------------

GUARD_BASE = """use_default_settings: true
general:
  instance_name: "torxng guard test"
server:
  secret_key: "torxng-guard-test-overridden-by-env"
  limiter: false
  public_instance: false
"""

GUARD_TOR_OK = GUARD_BASE + """outgoing:
  using_tor_proxy: true
  proxies:
    all://:
      - socks5h://tor:9050
"""


def guard_settings(outgoing: str = "", engines: str = "") -> str:
    return GUARD_BASE + outgoing + engines


# ---------------------------------------------------------------------------
# Test base class
# ---------------------------------------------------------------------------


class StackTest(unittest.TestCase):
    destructive = False
    maxDiff = None

    def setUp(self):
        if self.destructive and not CFG.destructive:
            self.skipTest("destructive test: run with --destructive")

    # -- reporting --------------------------------------------------------

    def note(self, msg) -> None:
        NOTES.setdefault(self.id(), []).append(str(msg))

    def assert_no_problems(self, problems: list[str]) -> None:
        if problems:
            self.fail(f"{len(problems)} problem(s): " + " | ".join(problems))

    # -- prerequisites ----------------------------------------------------

    def need_docker(self) -> None:
        reason = STACK.unavailable_reason()
        if reason:
            self.skipTest(reason)

    def need_service(self, *services: str, healthy: bool = False) -> None:
        self.need_docker()
        ps = STACK.ps()
        if not ps:
            self.skipTest("stack not running (docker compose ps lists no containers)")
        for svc in services:
            entry = ps.get(svc)
            if not entry:
                self.skipTest(f"service '{svc}' has no container (stack not up?)")
            if entry.get("State") != "running":
                self.skipTest(f"service '{svc}' is not running (state: {entry.get('State')})")
            if healthy and entry.get("Health") not in (None, "", "healthy"):
                self.skipTest(f"service '{svc}' is not healthy (health: {entry.get('Health')})")

    def need_http(self) -> None:
        reason = http_unavailable_reason()
        if reason:
            self.skipTest(reason)

    def exec_ok(self, service: str, cmd, timeout: float = 60.0, input_text: str | None = None,
                allow_fail: bool = False) -> CmdResult:
        self.need_service(service)
        res = STACK.exec_in(service, cmd, timeout, input_text)
        if res.timed_out:
            self.fail(f"docker exec in {service} timed out after {timeout:.0f}s: {' '.join(cmd)[:80]}")
        if res.rc != 0 and not allow_fail:
            if "No such container" in res.err or "is not running" in res.err:
                self.skipTest(f"service '{service}' went away during the test")
            if res.rc in (126, 127) and ("not found" in res.err or "no such file" in res.err.lower()):
                self.skipTest(f"command not available in {service}: {cmd[0]}")
            self.fail(f"docker exec in {service} failed (rc={res.rc}): {res.brief(200)}")
        return res

    def core_py(self, code: str, timeout: float = 60.0) -> dict:
        self.need_service("core")
        data, res = STACK.py_in_core(code, timeout)
        if data is None:
            if res.timed_out:
                self.fail(f"probe in core timed out after {timeout:.0f}s")
            if res.rc in (126, 127):
                self.skipTest(f"{VENV_PY} not usable in core: {res.brief(150)}")
            self.fail(f"probe in core produced no JSON (rc={res.rc}): {res.brief(300)}")
        return data

    def service_inspect(self, service: str) -> dict:
        self.need_service(service)
        info = STACK.inspect(service)
        if not info:
            self.skipTest(f"cannot inspect service '{service}'")
        return info


# cached tor facts (torrc, hidden service dir, onion address)
_TOR_CACHE: dict[str, object] = {}


def read_torrc(test: StackTest) -> tuple[str, str, dict[str, list[str]]]:
    """``(path, text, options)`` of the torrc the running tor process uses."""
    if "torrc" not in _TOR_CACHE:
        test.need_service("tor")
        res = STACK.exec_in("tor", ["cat", "/proc/1/cmdline"], timeout=20)
        args = [a for a in res.out.split("\x00") if a] if res.ok else []
        path = "/etc/tor/torrc"
        for i, arg in enumerate(args):
            if arg == "-f" and i + 1 < len(args):
                path = args[i + 1]
        res = STACK.exec_in("tor", ["cat", path], timeout=20)
        if not res.ok:
            test.skipTest(f"cannot read the torrc ({path}) in the tor container: {res.brief(150)}")
        _TOR_CACHE["torrc"] = (path, res.out, parse_torrc(res.out))
    return _TOR_CACHE["torrc"]  # type: ignore[return-value]


def hs_dir(test: StackTest) -> str:
    _, _, opts = read_torrc(test)
    dirs = opts.get("hiddenservicedir") or ["/var/lib/tor/searxng/"]
    return dirs[0].rstrip("/")


def read_onion_hostname(test: StackTest) -> str:
    if "onion" not in _TOR_CACHE:
        path = hs_dir(test) + "/hostname"
        res = STACK.exec_in("tor", ["cat", path], timeout=20)
        if not res.ok or not res.out.strip():
            test.skipTest(f"onion hostname not created yet ({path}): {res.brief(120)}")
        _TOR_CACHE["onion"] = res.out.strip()
    return _TOR_CACHE["onion"]  # type: ignore[return-value]


def short_onion(address: str) -> str:
    return address[:6] + "..." + address[-12:] if len(address) > 20 else address


# ---------------------------------------------------------------------------
# Group A - Tor-only / fail-closed (non-destructive)
# ---------------------------------------------------------------------------


class GroupA(StackTest):
    """A - Tor-only / fail-closed."""

    def test_A01_core_only_on_internal_network(self):
        """core is attached only to internal Docker networks and publishes no port."""
        info = self.service_inspect("core")
        nets = (info.get("NetworkSettings") or {}).get("Networks") or {}
        problems = []
        if not nets:
            problems.append("core has no network attachment")
        for name, attach in nets.items():
            res = STACK.dock("network", "inspect", name, timeout=30)
            data = parse_json_stream(res.out) if res.ok else []
            if not data:
                problems.append(f"cannot inspect network {name}")
                continue
            if not data[0].get("Internal"):
                problems.append(f"core is attached to the non-internal network '{name}'")
            else:
                self.note(f"{name}: internal, core IP {attach.get('IPAddress')}")
            addr = attach.get("IPAddress")
            if addr and ipaddress.ip_address(addr) != ipaddress.ip_address(CORE_IP):
                self.note(f"core IP {addr} differs from the spec ({CORE_IP})")
        bound = {k: v for k, v in ((info.get("NetworkSettings") or {}).get("Ports") or {}).items() if v}
        if bound:
            problems.append(f"core publishes ports: {bound}")
        if (info.get("HostConfig") or {}).get("NetworkMode") == "host":
            problems.append("core uses host networking")
        self.assert_no_problems(problems)

    def test_A02_no_default_route_in_core(self):
        """core's routing table has no default route (IPv4 and IPv6)."""
        res = self.exec_ok(
            "core", ["sh", "-c", "cat /proc/net/route; echo ---IPV6---; cat /proc/net/ipv6_route 2>/dev/null; true"]
        )
        v4, _, v6 = res.out.partition("---IPV6---")
        problems, routes = [], []
        for line in v4.strip().splitlines()[1:]:
            fields = line.split()
            if len(fields) < 8:
                continue
            iface, dest, gateway, mask = fields[0], fields[1], fields[2], fields[7]
            routes.append(f"{hex_to_ipv4(dest)}/{bin(int(mask, 16)).count('1')} dev {iface}")
            if dest == "00000000" and mask == "00000000":
                problems.append(f"IPv4 default route via {hex_to_ipv4(gateway)} on {iface}")
        for line in v6.strip().splitlines():
            fields = line.split()
            if len(fields) < 10:
                continue
            dest, plen, flags, iface = fields[0], fields[1], int(fields[8], 16), fields[9]
            if dest == "0" * 32 and plen == "00" and iface != "lo" and not flags & 0x0200:
                problems.append(f"IPv6 default route on {iface}")
        self.note("IPv4 routes: " + (", ".join(routes) or "none"))
        self.assert_no_problems(problems)

    def test_A03_direct_egress_to_ip_literal_blocked(self):
        """TCP/UDP/HTTP from core straight to public IP literals fails (no route)."""
        data = self.core_py(PROBE_IP_EGRESS, timeout=120)
        problems = [f"{target} -> {result}" for target, result in data["results"] if not result.startswith("blocked")]
        first = data["results"][0] if data["results"] else ["-", "-"]
        self.note(f"{len(data['results'])} probes blocked, e.g. {first[0]}: {first[1]}")
        self.assert_no_problems(problems)

    def test_A04_direct_egress_to_hostname_blocked(self):
        """HTTP(S) from core to public hostnames without the proxy fails."""
        data = self.core_py(PROBE_HOST_EGRESS, timeout=120)
        problems = [f"{url} -> {result}" for url, result in data["results"] if not result.startswith("blocked")]
        first = data["results"][0] if data["results"] else ["-", "-"]
        self.note(f"e.g. {first[0]}: {first[1]}")
        self.assert_no_problems(problems)

    def test_A05_no_external_dns_from_core(self):
        """core cannot resolve public names (no DNS leak via Docker's embedded resolver)."""
        data = self.core_py(PROBE_DNS, timeout=90)
        problems = [
            f"{name} resolved to {result} (DNS query left the isolated network)"
            for name, result in data["external"].items()
            if not isinstance(result, str)
        ]
        tor = data["internal"].get("tor")
        if isinstance(tor, str):
            self.note(f"positive control: 'tor' did not resolve either ({tor}) - result inconclusive")
        else:
            self.note(f"positive control: 'tor' -> {', '.join(tor)}; nameservers {data.get('nameservers')}")
        self.assert_no_problems(problems)

    def test_A06_core_connections_stay_on_isolated_network(self):
        """Every socket of core points to loopback or 172.30.0.0/24 (snapshot of /proc/net)."""
        res = self.exec_ok(
            "core",
            ["sh", "-c", "cat /proc/net/tcp /proc/net/udp; cat /proc/net/tcp6 /proc/net/udp6 2>/dev/null; true"],
        )
        problems, peers = [], {}
        for _local, (rip, rport), state in parse_proc_net(res.out):
            if rip.version == 6 and rip.ipv4_mapped:
                rip = rip.ipv4_mapped
            if rip.is_unspecified:
                continue
            if rip.is_loopback or (rip.version == 4 and rip in ISOLATED_SUBNET):
                key = f"{rip}:{rport}"
                peers[key] = peers.get(key, 0) + 1
                continue
            problems.append(f"socket to {rip}:{rport} ({TCP_STATES.get(state, state)})")
        self.note("peers: " + (", ".join(f"{k} x{v}" for k, v in sorted(peers.items())) or "none"))
        self.assert_no_problems(problems)

    def test_A07_tor_safesocks_rejects_ip_literals(self):
        """Tor refuses SOCKS requests that carry a raw IP (SafeSocks 1), hostnames work."""
        self.need_service("tor")

        def attempt():
            data = self.core_py(PROBE_SAFESOCKS, timeout=400)
            return data.get("socks5_hostname") == "rep=0", data

        data = self.core_py(PROBE_SAFESOCKS, timeout=400)
        if str(data.get("socks5_ip", "")).startswith("no SOCKS connection"):
            self.skipTest(f"tor SocksPort not reachable from core: {data['socks5_ip']}")
        problems = []
        if data.get("socks5_ip") == "rep=0":
            problems.append("SOCKS5 CONNECT to the IP literal 1.1.1.1:443 was granted (SafeSocks off)")
        if data.get("socks4_ip") == "rep=90":
            problems.append("SOCKS4 CONNECT to 1.1.1.1:443 was granted (SafeSocks off)")
        if problems:
            self.assert_no_problems(problems)
        if data.get("socks5_hostname") != "rep=0":
            ok, data2, _ = retry(attempt, attempts=2, delay=15)
            if not ok:
                self.skipTest(
                    "IP literals were rejected, but the positive control (CONNECT to a hostname) failed too "
                    f"({data2.get('socks5_hostname')}): Tor cannot build circuits right now"
                )
        self.note(f"socks5 IP: {data['socks5_ip']}, socks4 IP: {data['socks4_ip']}, socks5 hostname: rep=0")

    def test_A08_deployed_settings_force_tor(self):
        """The deployed settings route every network through socks5h:// with using_tor_proxy."""
        data = self.core_py(PROBE_SETTINGS, timeout=120)
        problems = []
        if data.get("using_tor_proxy") is not True:
            problems.append(f"outgoing.using_tor_proxy = {data.get('using_tor_proxy')!r}")
        if not data.get("proxies"):
            problems.append("outgoing.proxies is not set")
        for url in data.get("proxies") or []:
            if not str(url).startswith("socks5h://"):
                problems.append(f"outgoing.proxies contains {url!r} (not socks5h://)")
        for name, urls in (data.get("networks") or {}).items():
            for url in urls:
                if not str(url).startswith("socks5h://"):
                    problems.append(f"outgoing.networks.{name} proxy {url!r}")
        for name, urls in (data.get("engines") or {}).items():
            for url in urls:
                if not str(url).startswith("socks5h://"):
                    problems.append(f"engine {name} proxy {url!r}")
        if data.get("verify") is False:
            problems.append("outgoing.verify = false (engine TLS certificates not verified)")
        info = STACK.inspect("core") or {}
        env_names = [e.split("=", 1)[0] for e in (info.get("Config") or {}).get("Env") or []]
        proxy_env = [n for n in env_names if n.lower() in PROXY_ENV_VARS]
        if proxy_env:
            problems.append(f"proxy environment variables in core: {proxy_env}")
        self.note(
            f"proxies={data.get('proxies')}, tor_circuits={data.get('tor_circuits')}, verify={data.get('verify')}, "
            f"limiter={data.get('limiter')}, autocomplete={data.get('autocomplete')!r}, formats={data.get('formats')}"
        )
        self.assert_no_problems(problems)


# ---------------------------------------------------------------------------
# Group B - container hardening
# ---------------------------------------------------------------------------

RW_PROBE_DIRS = {
    "core": ["/usr/local/searxng", "/usr/local/searxng/searx", "/etc/searxng"],
    "frontend": ["/etc/nginx", "/etc/nginx/conf.d", "/usr/share/nginx/html", "/var/cache/nginx", "/var/run"],
    "tor": ["/etc/tor", "/usr/local/bin", "/var/lib"],
}
RW_COMMON_DIRS = ["/", "/etc", "/usr", "/var", "/root", "/home", "/opt"]


def _under(path: str, mount: str) -> bool:
    mount = mount.rstrip("/") or "/"
    return path == mount or path.startswith(mount + "/")


class GroupB(StackTest):
    """B - container hardening."""

    def test_B01_non_root_users(self):
        """Every process runs non-root: core uid 977, frontend uid 101, tor non-root."""
        self.need_docker()
        problems, checked = [], 0
        for svc in STACK_SERVICES:
            if not STACK.is_running(svc):
                self.note(f"{svc}: not running")
                continue
            res = STACK.exec_in(
                svc, ["sh", "-c", 'for f in /proc/[0-9]*/status; do echo "@@ $f"; cat "$f" 2>/dev/null; done'], 30
            )
            if not res.ok:
                problems.append(f"{svc}: cannot list processes ({res.brief(100)})")
                continue
            checked += 1
            expected = EXPECTED_UID[svc]
            uids, bad = set(), []
            for proc in parse_status_blocks(res.out):
                fields = proc.get("Uid", "").split()
                if len(fields) < 2:
                    continue
                euid = int(fields[1])
                uids.add(euid)
                if euid == 0 or (expected is not None and euid != expected):
                    bad.append(f"{proc.get('Name')}[{proc.get('Pid')}] euid={euid}")
            if bad:
                want = f"uid {expected}" if expected is not None else "non-root"
                problems.append(f"{svc} (expected {want}): " + ", ".join(bad[:5]))
            self.note(f"{svc}: euids {sorted(uids)}")
        if not checked and not problems:
            self.skipTest("no stack service is running")
        self.assert_no_problems(problems)

    def test_B02_read_only_rootfs(self):
        """Root filesystems are read-only; only size-capped tmpfs and volumes are writable."""
        self.need_docker()
        problems, checked = [], 0
        for svc in STACK_SERVICES:
            info = STACK.inspect(svc)
            if not info or not STACK.is_running(svc):
                continue
            checked += 1
            hc = info.get("HostConfig") or {}
            tmpfs = hc.get("Tmpfs") or {}
            mounts = [m.get("Destination", "") for m in info.get("Mounts") or []] + list(tmpfs)
            if not hc.get("ReadonlyRootfs"):
                problems.append(f"{svc}: read_only not set (HostConfig.ReadonlyRootfs=false)")
            if "/tmp" not in tmpfs:
                problems.append(f"{svc}: no tmpfs on /tmp")
            for path, opts in tmpfs.items():
                if "size=" not in (opts or ""):
                    problems.append(f"{svc}: tmpfs {path} has no size cap ({opts or 'no options'})")
            dirs = [d for d in RW_COMMON_DIRS + RW_PROBE_DIRS.get(svc, []) if not any(_under(d, m) for m in mounts)]
            script = (
                'grep -E "^[^ ]+ / " /proc/mounts | head -n 1; '
                f'for d in {" ".join(dirs)}; do '
                '[ -d "$d" ] || { echo "ABSENT $d"; continue; }; '
                'p="$d/.torxng_rw_probe_$$"; '
                'if err=$( (: > "$p") 2>&1 ); then echo "WRITABLE $d"; rm -f "$p"; '
                'else echo "DENIED $d $err"; fi; done; '
                'if (: > /tmp/.torxng_rw_probe_$$) 2>/dev/null; then echo TMP_WRITABLE; rm -f /tmp/.torxng_rw_probe_$$; '
                "else echo TMP_NOT_WRITABLE; fi"
            )
            res = STACK.exec_in(svc, ["sh", "-c", script], 30)
            if not res.ok:
                problems.append(f"{svc}: probe failed ({res.brief(100)})")
                continue
            lines = res.out.splitlines()
            root_line = lines[0] if lines else ""
            root_opts = root_line.split()[3].split(",") if len(root_line.split()) > 3 else []
            if "ro" not in root_opts:
                problems.append(f"{svc}: / is mounted {','.join(root_opts[:2]) or '?'}")
            writable = [l.split(" ", 1)[1] for l in lines if l.startswith("WRITABLE ")]
            if writable:
                problems.append(f"{svc}: writable outside tmpfs/volumes: {', '.join(writable)}")
            erofs = sum(1 for l in lines if l.startswith("DENIED ") and "Read-only file system" in l)
            denied = sum(1 for l in lines if l.startswith("DENIED "))
            if "/tmp" in tmpfs and "TMP_NOT_WRITABLE" in lines:
                problems.append(f"{svc}: tmpfs /tmp not writable")
            self.note(f"{svc}: {denied} dirs denied ({erofs} with EROFS), tmpfs {sorted(tmpfs)}")
        if not checked:
            self.skipTest("no stack service is running")
        self.assert_no_problems(problems)

    def test_B03_no_capabilities_no_new_privs(self):
        """PID 1 has CapEff/CapPrm/CapBnd = 0 and NoNewPrivs = 1; cap_drop ALL in the config."""
        self.need_docker()
        problems, checked = [], 0
        for svc in STACK_SERVICES:
            info = STACK.inspect(svc)
            if not info or not STACK.is_running(svc):
                continue
            checked += 1
            res = STACK.exec_in(svc, ["cat", "/proc/1/status"], 20)
            status = parse_status(res.out) if res.ok else {}
            for key in ("CapEff", "CapPrm", "CapBnd"):
                value = status.get(key)
                if value is None or int(value, 16) != 0:
                    problems.append(f"{svc}: {key}={value}")
            if status.get("NoNewPrivs") != "1":
                problems.append(f"{svc}: NoNewPrivs={status.get('NoNewPrivs')}")
            hc = info.get("HostConfig") or {}
            if "ALL" not in [c.upper() for c in hc.get("CapDrop") or []]:
                problems.append(f"{svc}: cap_drop does not contain ALL ({hc.get('CapDrop')})")
            if hc.get("CapAdd"):
                problems.append(f"{svc}: cap_add {hc.get('CapAdd')}")
            if hc.get("Privileged"):
                problems.append(f"{svc}: privileged")
            if not any(s.startswith("no-new-privileges") and not s.endswith("false") for s in hc.get("SecurityOpt") or []):
                problems.append(f"{svc}: security_opt no-new-privileges missing")
            self.note(f"{svc}: CapBnd={status.get('CapBnd')} NoNewPrivs={status.get('NoNewPrivs')} "
                      f"Seccomp={status.get('Seccomp')}")
        if not checked:
            self.skipTest("no stack service is running")
        self.assert_no_problems(problems)

    def test_B04_resource_limits_set(self):
        """Memory, CPU and PID limits are set on tor, core and frontend (docker inspect)."""
        self.need_docker()
        problems, checked = [], 0
        for svc in STACK_SERVICES:
            info = STACK.inspect(svc)
            if not info:
                continue
            checked += 1
            hc = info.get("HostConfig") or {}
            mem = hc.get("Memory") or 0
            cpus = (hc.get("NanoCpus") or 0) / 1e9
            if not cpus and hc.get("CpuQuota") and hc.get("CpuPeriod"):
                cpus = hc["CpuQuota"] / hc["CpuPeriod"]
            pids = hc.get("PidsLimit") or 0
            if not mem:
                problems.append(f"{svc}: no memory limit")
            if not cpus:
                problems.append(f"{svc}: no CPU limit")
            if pids <= 0:
                problems.append(f"{svc}: no pids limit")
            spec = SPEC_LIMITS[svc]
            dev = []
            if mem and mem != spec["memory"]:
                dev.append(f"mem {mem // MIB}m (spec {spec['memory'] // MIB}m)")
            if cpus and abs(cpus - spec["cpus"]) > 1e-6:
                dev.append(f"cpus {cpus:g} (spec {spec['cpus']:g})")
            if pids > 0 and pids != spec["pids"]:
                dev.append(f"pids {pids} (spec {spec['pids']})")
            metric(svc, {"memory_mib": mem / MIB if mem else None, "cpus": cpus or None, "pids": pids or None}, "limits")
            self.note(f"{svc}: mem={mem // MIB if mem else 0}m cpus={cpus:g} pids={pids}"
                      + (f" [differs from spec: {', '.join(dev)}]" if dev else ""))
        if not checked:
            self.skipTest("no stack container exists")
        self.assert_no_problems(problems)

    def test_B05_only_loopback_frontend_port_published(self):
        """The only published port is frontend on 127.0.0.1:<base-url port>."""
        self.need_service("frontend")
        problems, frontend_bindings = [], []
        for cont in STACK.project_containers():
            svc = ((cont.get("Config") or {}).get("Labels") or {}).get("com.docker.compose.service", "?")
            for cport, binds in ((cont.get("NetworkSettings") or {}).get("Ports") or {}).items():
                for bind in binds or []:
                    hip, hport = bind.get("HostIp", ""), bind.get("HostPort", "")
                    desc = f"{svc} {hip or '*'}:{hport}->{cport}"
                    if hip != "127.0.0.1":
                        problems.append(f"{desc} is not bound to 127.0.0.1")
                    if svc in BASELINE_NAMES:
                        self.note(f"baseline running: {desc}")
                    elif svc != "frontend":
                        problems.append(f"{desc}: only frontend may publish a port")
                    else:
                        frontend_bindings.append(desc)
                        if hport != str(CFG.port):
                            problems.append(f"{desc}: expected host port {CFG.port}")
        if not frontend_bindings:
            problems.append("frontend publishes no port")
        elif len(frontend_bindings) > 1:
            problems.append(f"frontend publishes {len(frontend_bindings)} bindings: {frontend_bindings}")
        self.note("bindings: " + ", ".join(frontend_bindings))
        self.assert_no_problems(problems)

    def test_B06_baseline_is_opt_in_and_not_our_image(self):
        """The clearnet baseline is behind a compose profile and never uses our core image."""
        self.need_docker()
        res = STACK.compose("config", "--services", timeout=60)
        if not res.ok:
            self.skipTest(f"docker compose config failed: {res.brief(150)}")
        default_services = set(res.out.split())
        res = STACK.compose("config", "--profiles", timeout=60)
        profiles = res.out.split() if res.ok else []
        args = []
        for prof in profiles:
            args += ["--profile", prof]
        res = STACK.compose(*args, "config", "--format", "json", timeout=60)
        if not res.ok:
            self.skipTest(f"docker compose config --format json failed: {res.brief(150)}")
        services = (json.loads(res.out).get("services") or {})
        problems = []
        missing = [s for s in STACK_SERVICES if s not in default_services]
        if missing:
            problems.append(f"default services lack {missing}")
        core_image = (services.get("core") or {}).get("image")
        profiled = {n: s for n, s in services.items() if s.get("profiles")}
        for name, svc in profiled.items():
            if name in default_services:
                problems.append(f"profiled service {name} starts by default")
            image = svc.get("image")
            build = svc.get("build") or {}
            dockerfile = str(build.get("dockerfile", "")) if isinstance(build, dict) else ""
            if image and core_image and image == core_image:
                problems.append(f"{name} uses our core image {image} (the baseline must be the stock image)")
            if "torxng" in dockerfile.replace("\\", "/"):
                problems.append(f"{name} is built from {dockerfile}")
            for port in svc.get("ports") or []:
                host_ip = port.get("host_ip") if isinstance(port, dict) else None
                if isinstance(port, dict) and host_ip not in ("127.0.0.1",):
                    problems.append(f"{name} publishes {port.get('published')} on {host_ip or 'all interfaces'}")
            if name != "baseline":
                self.note(f"profiled service is named '{name}' (spec: 'baseline')")
            self.note(f"{name}: profiles {svc.get('profiles')}, image {image}")
        if not profiled:
            self.note("no profiled (baseline) service defined")
        for name in profiled:
            if STACK.is_running(name):
                self.note(f"{name} is currently running (started explicitly)")
        self.assert_no_problems(problems)

    def test_B07_controlport_loopback_only_and_authenticated(self):
        """ControlPort is unreachable from core, needs the password inside tor, core holds no credentials."""
        self.need_service("tor", "core")
        problems = []
        # (a) not reachable from core; the SocksPort is the positive control
        reach = self.core_py(PROBE_CONTROL_REACH, timeout=60)
        for target in ("172.30.0.2:9051", "tor:9051"):
            if reach.get(target) == "OPEN":
                problems.append(f"ControlPort {target} is reachable from core")
        if reach.get("tor:9050") != "OPEN":
            self.note(f"positive control failed: SocksPort from core {reach.get('tor:9050')}")
        # (c) core holds no ControlPort credentials
        info = STACK.inspect("core") or {}
        env_names = [e.split("=", 1)[0] for e in (info.get("Config") or {}).get("Env") or []]
        if "SEARXNG_TOR_CONTROL_PASSWORD" in env_names or reach.get("env_password"):
            problems.append("core has SEARXNG_TOR_CONTROL_PASSWORD in its environment")
        settings = self.core_py(PROBE_SETTINGS, timeout=120)
        if str(settings.get("tor_control_host") or "").strip():
            problems.append(f"outgoing.tor_control.host = {settings.get('tor_control_host')!r} (expected empty)")
        if settings.get("tor_control_password_set"):
            problems.append("outgoing.tor_control.password is set in core's settings")
        # (b) inside the tor container: loopback only, password required
        _, _, opts = read_torrc(self)
        control_ports = opts.get("controlport") or []
        if not control_ports:
            self.note("ControlPort disabled in the torrc")
            self.note(f"from core: 172.30.0.2:9051 {reach.get('172.30.0.2:9051')}")
            self.assert_no_problems(problems)
            return
        port = None
        for entry in control_ports:
            addr = entry.split()[0]
            if addr.startswith("127.0.0.1:"):
                port = port or addr.split(":", 1)[1]
            elif not addr.startswith("unix:"):
                problems.append(f"ControlPort {entry!r} is not bound to 127.0.0.1")
        if not opts.get("hashedcontrolpassword"):
            problems.append("ControlPort without HashedControlPassword")
        if opts.get("cookieauthentication") and opts["cookieauthentication"][-1] == "1":
            problems.append("CookieAuthentication 1")
        if port:
            res = self.exec_ok("tor", ["sh", "-c", TOR_CONTROL_NC.replace("PORT", port)], timeout=45, allow_fail=True)
            if "NO_NC" in res.out:
                self.note("nc not available in the tor container: in-container probe skipped")
            else:
                parts = res.out.split("@@")
                unauth = parts[0].strip().splitlines() if parts else []
                wrong = parts[1].strip().splitlines() if len(parts) > 1 else []
                right = parts[2].strip().splitlines() if len(parts) > 2 else []
                methods = re.search(r"METHODS=(\S+)", " ".join(unauth))
                method_set = set(methods.group(1).split(",")) if methods else set()
                if "NULL" in method_set:
                    problems.append("ControlPort accepts NULL authentication")
                if not method_set:
                    problems.append(f"PROTOCOLINFO gave no auth methods: {unauth[:3]}")
                if not any(l.startswith("514") for l in unauth) or any("version=" in l for l in unauth):
                    problems.append(f"unauthenticated GETINFO version answered {unauth[-2:]}")
                if not wrong or not wrong[0].startswith("515") or any("version=" in l for l in wrong):
                    problems.append(f"wrong password answered {wrong[:2]}")
                if right and right[0] == "NOPASSWORD":
                    self.note("no ControlPort password in /run/secrets/tor_control_password or the environment: "
                              "positive control skipped")
                elif not any("version=" in l for l in right):
                    problems.append(f"the configured password was rejected: {right[:2]}")
                else:
                    self.note("in tor: 127.0.0.1:" + port + " PROTOCOLINFO " + ",".join(sorted(method_set))
                              + ", unauthenticated -> 514, wrong password -> 515, configured password -> 250")
        self.note(f"from core: 172.30.0.2:9051 {reach.get('172.30.0.2:9051')}, tor:9051 {reach.get('tor:9051')}; "
                  "core has no ControlPort password, tor_control.host empty")
        self.assert_no_problems(problems)

    def test_B08_tor_ports_unreachable_from_host(self):
        """SocksPort/ControlPort (and core) cannot be reached from the host."""
        self.need_service("tor")
        problems = []
        info = STACK.inspect("tor") or {}
        bound = {k: v for k, v in ((info.get("NetworkSettings") or {}).get("Ports") or {}).items() if v}
        if bound:
            problems.append(f"tor publishes ports {bound}")
        targets = [("127.0.0.1", 9050), ("127.0.0.1", 9051), (TOR_IP, 9050), (TOR_IP, 9051), (CORE_IP, 8080)]
        results = []
        for host, port in targets:
            try:
                with socket.create_connection((host, port), timeout=3):
                    reachable = True
            except OSError:
                reachable = False
            results.append(f"{host}:{port} {'OPEN' if reachable else 'closed'}")
            if not reachable:
                continue
            if host == "127.0.0.1":
                res = STACK.dock("ps", "-q", "--filter", f"publish={port}")
                if res.ok and not res.out.strip():
                    self.note(f"127.0.0.1:{port} answers, but no container publishes it (host-local service)")
                    continue
            problems.append(f"{host}:{port} is reachable from the host")
        self.note("; ".join(results))
        self.assert_no_problems(problems)

    def test_B09_hidden_service_dir_private(self):
        """The hidden service directory is mode 700 and its secret key 600, owned by tor."""
        self.need_service("tor")
        directory = hs_dir(self)
        res = self.exec_ok(
            "tor",
            ["stat", "-c", "%a %U %n", directory, f"{directory}/hs_ed25519_secret_key", f"{directory}/hostname"],
            allow_fail=True,
        )
        lines = [l.split(" ", 2) for l in res.out.splitlines() if l.strip()]
        if not lines:
            self.skipTest(f"hidden service directory {directory} not created yet ({res.brief(120)})")
        problems = []
        for mode, owner, path in lines:
            if owner == "root":
                problems.append(f"{path} owned by root")
            if path == directory and mode != "700":
                problems.append(f"{path} mode {mode} (expected 700)")
            if path.endswith("hs_ed25519_secret_key") and mode not in ("600", "400"):
                problems.append(f"{path} mode {mode} (expected 600)")
        self.note("; ".join(f"{p} {m} {o}" for m, o, p in lines))
        self.assert_no_problems(problems)

    def test_B10_restart_and_log_rotation(self):
        """restart: unless-stopped and json-file logs capped with max-size/max-file."""
        self.need_docker()
        problems, checked = [], 0
        for svc in STACK_SERVICES:
            info = STACK.inspect(svc)
            if not info:
                continue
            checked += 1
            hc = info.get("HostConfig") or {}
            policy = (hc.get("RestartPolicy") or {}).get("Name")
            if policy != "unless-stopped":
                problems.append(f"{svc}: restart policy {policy!r}")
            logcfg = hc.get("LogConfig") or {}
            opts = logcfg.get("Config") or {}
            if logcfg.get("Type") != "json-file" or not opts.get("max-size") or not opts.get("max-file"):
                problems.append(f"{svc}: logging {logcfg.get('Type')} {opts}")
        if not checked:
            self.skipTest("no stack container exists")
        self.assert_no_problems(problems)


    def test_B11_controlport_secret_not_exposed(self):
        """The ControlPort password is a read-only Compose secret of tor only and leaks nowhere."""
        self.need_service("tor", "core", "frontend")
        problems, notes = [], []
        secret_dest = "/run/secrets/tor_control_password"
        # the host file behind the secret (from the compose config); its content is never printed
        host_file = os.path.join(STACK_DIR, "secrets", "tor_control_password")
        res = STACK.compose("config", "--format", "json", timeout=60)
        if res.ok:
            try:
                cfg_secret = (json.loads(res.out).get("secrets") or {}).get("tor_control_password") or {}
                host_file = cfg_secret.get("file") or host_file
            except ValueError:
                pass
        password = ""
        if os.path.isfile(host_file):
            with open(host_file, encoding="utf-8", errors="replace") as fh:
                password = fh.read().replace("\r", "").replace("\n", "")
        # 1. tor: no password variable, the secret is mounted read-only
        tor = STACK.inspect("tor", refresh=True) or {}
        tor_env = [e.split("=", 1)[0] for e in (tor.get("Config") or {}).get("Env") or []]
        if "TOR_CONTROL_PASSWORD" in tor_env:
            problems.append("tor's Config.Env contains TOR_CONTROL_PASSWORD")
        mount = next((m for m in tor.get("Mounts") or [] if m.get("Destination") == secret_dest), None)
        if mount is None:
            problems.append(f"{secret_dest} is not mounted in tor")
        elif mount.get("RW"):
            problems.append(f"{secret_dest} is mounted read-write in tor (docker inspect RW=true)")
        res = STACK.exec_in("tor", ["sh", "-c", f"grep ' {secret_dest} ' /proc/mounts"], 20)
        fields = res.out.split()
        opts = fields[3].split(",") if len(fields) > 3 else []
        if mount is not None and "ro" not in opts:
            problems.append(f"{secret_dest} is not ro in tor's /proc/mounts ({','.join(opts[:2]) or 'not found'})")
        # 2. core and frontend: no secret mount at all
        for svc in ("core", "frontend"):
            info = STACK.inspect(svc) or {}
            dests = [m.get("Destination", "") for m in info.get("Mounts") or []]
            secret_mounts = [d for d in dests if d.startswith("/run/secrets")]
            if secret_mounts:
                problems.append(f"{svc} has secret mounts {secret_mounts}")
            res = STACK.exec_in(svc, ["sh", "-c", f"if [ -e {secret_dest} ]; then echo PRESENT; else echo ABSENT; fi"], 20)
            if "PRESENT" in res.out:
                problems.append(f"{secret_dest} exists in {svc}")
        # 3. the password string occurs in no docker inspect output and no environment
        if not password:
            notes.append(f"no password in {host_file}: leak checks skipped (ControlPort disabled)")
        else:
            ids = [c.get("Id") for c in STACK.project_containers() if c.get("Id")]
            res = STACK.dock("inspect", *ids, timeout=60) if ids else None
            if res is not None and password in res.output:
                problems.append("the ControlPort password appears in docker inspect output")
            for svc in STACK_SERVICES:
                res = STACK.exec_in(svc, ["sh", "-c", "env; echo @@; tr '\\0' '\\n' < /proc/1/environ"], 20)
                # PID 1's environ is best effort: granian and nginx overwrite that
                # memory with their process title
                exec_env, _, _pid1_env = res.out.partition("@@")
                if "PATH=" not in exec_env:
                    problems.append(f"{svc}: cannot read the exec environment ({res.brief(80)})")
                if password in res.output:
                    problems.append(f"the ControlPort password is in the environment of {svc} (exec env or PID 1)")
                if "TOR_CONTROL_PASSWORD" in res.output:
                    problems.append(f"{svc} has a TOR_CONTROL_PASSWORD variable")
            path, text, _ = read_torrc(self)
            if password in text:
                problems.append(f"the plaintext password is in the rendered torrc {path}")
            res = STACK.exec_in("tor", ["cat", "/proc/1/cmdline"], 20)
            if password in res.out:
                problems.append("the password is on tor's command line")
            notes.append(f"password ({len(password)} chars) in no docker inspect output, no exec or PID 1 environment "
                         "of tor/core/frontend, not in the torrc, not on tor's command line")
        # 4. the host file is git-ignored
        git = shutil.which("git")
        repo = os.path.dirname(STACK_DIR)
        if not git:
            notes.append("git not found: check-ignore skipped")
        elif not os.path.isfile(host_file):
            notes.append(f"{host_file} does not exist: check-ignore skipped")
        else:
            rel = os.path.relpath(host_file, repo)
            res = run_cmd([git, "-C", repo, "check-ignore", "-q", rel], timeout=30)
            if res.rc == 1:
                problems.append(f"{rel} is NOT git-ignored")
            elif res.rc != 0:
                notes.append(f"git check-ignore failed (rc={res.rc}): {res.brief(100)}")
            else:
                notes.append(f"{rel.replace(os.sep, '/')} is git-ignored")
        notes.insert(0, f"{secret_dest}: mounted in tor only, RW={mount.get('RW') if mount else None}, "
                        f"/proc/mounts {'ro' if 'ro' in opts else '?'}; tor Config.Env {sorted(tor_env)}")
        for n in notes:
            self.note(n)
        self.assert_no_problems(problems)


# ---------------------------------------------------------------------------
# Group E - resources (run before C/D so the RSS numbers are close to idle)
# ---------------------------------------------------------------------------


def docker_stats_snapshot() -> dict[str, dict]:
    ids = {svc: STACK.container_id(svc) for svc in STACK_SERVICES}
    ids = {svc: cid for svc, cid in ids.items() if cid and STACK.is_running(svc)}
    if not ids:
        return {}
    res = STACK.dock("stats", "--no-stream", "--format", "{{json .}}", *ids.values(), timeout=90)
    out = {}
    for row in parse_json_stream(res.out):
        short = str(row.get("ID") or row.get("Container") or "")
        for svc, cid in ids.items():
            if short and (cid.startswith(short) or short.startswith(cid[:12])):
                usage, _, limit = str(row.get("MemUsage", "")).partition("/")
                out[svc] = {
                    "mem_bytes": parse_size(usage),
                    "stats_limit_bytes": parse_size(limit),
                    "cpu": row.get("CPUPerc"),
                    "pids": row.get("PIDs"),
                }
    return out


class GroupE(StackTest):
    """E - resources (reported; soft thresholds produce WARN notes)."""

    def test_E01_idle_rss_below_limits(self):
        """Idle memory of each container stays below its memory limit."""
        self.need_service("core")
        snap = docker_stats_snapshot()
        if not snap:
            self.skipTest("docker stats returned nothing")
        problems = []
        for svc in STACK_SERVICES:
            row = snap.get(svc)
            if not row:
                continue
            info = STACK.inspect(svc) or {}
            limit = (info.get("HostConfig") or {}).get("Memory") or 0
            usage = row["mem_bytes"]
            metric(svc, round(usage / MIB, 1) if usage else None, "idle_rss_mib")
            msg = f"{svc} {fmt_mib(usage)}"
            if limit and usage is not None:
                pct = 100.0 * usage / limit
                msg += f" / {fmt_mib(limit)} ({pct:.0f}%)"
                if usage >= 0.95 * limit:
                    problems.append(f"{svc} uses {pct:.0f}% of its memory limit")
                elif usage >= 0.8 * limit:
                    msg += " WARN >80%"
            else:
                msg += " (no limit)"
                spec = SPEC_LIMITS[svc]["memory"]
                if usage and usage > spec:
                    msg += f" WARN above the spec limit {spec // MIB}m"
            msg += f", pids {row.get('pids')}"
            self.note(msg)
        self.assert_no_problems(problems)

    def test_E02_image_sizes(self):
        """Image size per service as shown by 'docker image ls' (WARN above soft thresholds)."""
        self.need_docker()
        # 'docker image ls' shows the unpacked size; with the containerd image
        # store 'docker image inspect .Size' is the compressed content size.
        res = STACK.dock("image", "ls", "--no-trunc", "--format", "{{.ID}}\t{{.Size}}", timeout=60)
        disk = {}
        for line in res.out.splitlines():
            image_id, _, size = line.partition("\t")
            disk[image_id.strip()] = parse_size(size.strip())

        def sizes(ref: str) -> tuple[float | None, float | None]:
            out = STACK.dock("image", "inspect", ref, "--format", "{{.Id}}\t{{.Size}}", timeout=30)
            if not out.ok:
                return None, None
            image_id, _, content = out.out.strip().partition("\t")
            content_mb = int(content) / 1e6 if content.isdigit() else None
            disk_bytes = disk.get(image_id)
            return (disk_bytes / 1e6 if disk_bytes else None), content_mb

        checked = 0
        for svc in STACK_SERVICES:
            info = STACK.inspect(svc)
            if not info:
                continue
            disk_mb, content_mb = sizes(info["Image"])
            if disk_mb is None and content_mb is None:
                continue
            checked += 1
            size_mb = disk_mb if disk_mb is not None else content_mb
            metric(svc, round(size_mb, 1), "image_size_mb")
            if content_mb is not None:
                metric(svc, round(content_mb, 1), "image_content_size_mb")
            warn = " WARN" if size_mb > SOFT_IMAGE_MB[svc] else ""
            self.note(f"{svc} {size_mb:.0f} MB{warn} (content {content_mb or 0:.0f} MB, "
                      f"{(info.get('Config') or {}).get('Image')})")
        disk_mb, content_mb = sizes(STOCK_IMAGE)
        if disk_mb or content_mb:
            metric("stock_searxng", round(disk_mb or content_mb, 1), "image_size_mb")
            self.note(f"stock searxng {disk_mb or content_mb:.0f} MB")
        if not checked:
            self.skipTest("no stack image found")

    def test_E03_startup_time_to_healthy(self):
        """Seconds from container start to healthy (docker events, else readiness log line)."""
        self.need_docker()
        ready_patterns = {
            "tor": r"Bootstrapped 100%",
            # "Listening at" is printed before the app is imported; the worker
            # line marks the point where requests can be served
            "core": r"Started worker",
            "frontend": r"start worker process|ready for start up",
        }
        measured = 0
        for svc in STACK_SERVICES:
            info = STACK.inspect(svc)
            if not info or not STACK.is_running(svc):
                continue
            started = parse_ts((info.get("State") or {}).get("StartedAt", ""))
            if not started:
                continue
            cid = info["Id"]
            source, seconds = None, None
            res = STACK.dock(
                "events", "--since", str(int(started) - 1), "--until", str(int(time.time()) + 1),
                "--filter", f"container={cid}", "--filter", "event=health_status", "--format", "{{json .}}",
                timeout=30,
            )
            for event in parse_json_stream(res.out):
                status = str(event.get("status") or event.get("Action") or "")
                if status.endswith(": healthy"):
                    stamp = (event.get("timeNano") or 0) / 1e9 or event.get("time")
                    if stamp and stamp >= started - 1:
                        source, seconds = "health event", stamp - started
                        break
            if seconds is None:
                res = STACK.dock("logs", "--timestamps", "--since", str(int(started) - 1), cid, timeout=60)
                for line in res.output.splitlines():
                    stamp_str, _, text = line.partition(" ")
                    if re.search(ready_patterns[svc], text):
                        stamp = parse_ts(stamp_str)
                        if stamp and stamp >= started - 1:
                            source, seconds = "log line", stamp - started
                            break
            if seconds is None:
                self.note(f"{svc}: no health event / readiness line since start")
                continue
            measured += 1
            metric(svc, {"seconds": round(seconds, 1), "source": source}, "startup_to_healthy")
            warn = " WARN" if seconds > SOFT_STARTUP_S[svc] else ""
            self.note(f"{svc} {seconds:.0f}s ({source}){warn}")
        if not measured:
            self.skipTest("no startup data (events expired and no readiness log line found)")

    def test_E04_image_trims_applied(self):
        """core image: no .po, no sourcemaps, no lid.176.ftz, .mo kept, granian env set."""
        info = self.service_inspect("core")
        script = (
            "cd /usr/local/searxng/searx || exit 3; "
            'echo "po=$(find . -name "*.po" | wc -l)"; '
            'echo "map=$(find . -name "*.map" | wc -l)"; '
            'echo "mo=$(find . -name "*.mo" | wc -l)"; '
            'if [ -e data/lid.176.ftz ]; then echo lid=1; else echo lid=0; fi'
        )
        res = self.exec_ok("core", ["sh", "-c", script], timeout=60)
        counts = dict(l.split("=", 1) for l in res.out.split() if "=" in l)
        problems = []
        if counts.get("po", "0") != "0":
            problems.append(f"{counts['po']} .po files left")
        if counts.get("map", "0") != "0":
            problems.append(f"{counts['map']} sourcemaps (*.map) left")
        if counts.get("lid") == "1":
            problems.append("searx/data/lid.176.ftz still present")
        if counts.get("mo", "0") == "0":
            problems.append("no .mo files (translations broken)")
        env = dict(e.split("=", 1) for e in (info.get("Config") or {}).get("Env") or [] if "=" in e)
        for key, value in (("GRANIAN_WORKERS", "1"), ("GRANIAN_BLOCKING_THREADS", "2"), ("PYTHONDONTWRITEBYTECODE", "1")):
            if env.get(key) != value:
                problems.append(f"ENV {key}={env.get(key)!r} (expected {value})")
        self.note(f"po={counts.get('po')} map={counts.get('map')} mo={counts.get('mo')} lid={counts.get('lid')}")
        self.assert_no_problems(problems)

    def test_E05_translations_still_work(self):
        """Accept-Language: de renders the German UI (the .mo files survived the trim)."""
        self.need_http()
        resp = http_retry_429("GET", "/", headers={"Accept-Language": "de-DE,de;q=0.9"})
        problems = []
        if resp.status != 200:
            problems.append(f"GET / -> {status_str(resp)}")
        if 'lang="de' not in resp.text:
            problems.append('<html lang="de"> not set')
        if "Einstellungen" not in resp.text:
            problems.append("German string 'Einstellungen' (Preferences) not found")
        self.assert_no_problems(problems)


# ---------------------------------------------------------------------------
# Group C - HTTP edge cases (through 127.0.0.1:8080)
# ---------------------------------------------------------------------------


def parallel(func, items, workers: int = 4) -> list:
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(func, item) for item in items]
        results = []
        for fut in futures:
            try:
                results.append(fut.result())
            except Exception as exc:  # pylint: disable=broad-except
                results.append(exc)
        return results


def burst(path: str, count: int, workers: int) -> list:
    def one(_):
        try:
            return http("GET", path, timeout=30).status
        except OSError as exc:
            return f"error:{exc.__class__.__name__}"

    return parallel(one, range(count), workers)


class GroupC(StackTest):
    """C - HTTP edge cases."""

    def setUp(self):
        super().setUp()
        self.need_http()

    def test_C01_security_headers_exactly_once(self):
        """Every security header is present exactly once with the spec value (also on errors)."""
        index = http_retry_429("GET", "/")
        requests = [("GET", "/"), ("GET", "/search?q="), ("GET", "/healthz"),
                    ("GET", "/torxng-nonexistent-path"), ("PUT", "/")]
        css = re.search(r'href="(/static/[^"]+?\.css[^"]*)"', index.text)
        if css:
            requests.append(("GET", css.group(1)))
        issues: dict[tuple[str, str], list[str]] = {}
        for method, path in requests:
            resp = index if (method, path) == ("GET", "/") else http_retry_429(method, path)
            for name, issue in security_header_issues(resp.headers):
                issues.setdefault((name, issue), []).append(f"{method} {path.split('?')[0]} [{status_str(resp)}]")
        problems = [
            f"{name} {issue} on {len(where)}/{len(requests)} responses"
            + (f" (e.g. {where[0]})" if len(where) < len(requests) else "")
            for (name, issue), where in issues.items()
        ]
        self.note(f"checked {len(requests)} responses incl. 404/405 and a static file")
        self.assert_no_problems(problems)

    def test_C02_server_header_hides_version(self):
        """Server header is sent once without a version; no X-Powered-By or upstream server."""
        problems = []
        for path in ("/", "/torxng-nonexistent-path", "/healthz"):
            resp = http_retry_429("GET", path)
            servers = resp.header_all("Server")
            if len(servers) != 1:
                problems.append(f"{path}: {len(servers)} Server headers {servers}")
            for value in servers:
                if re.search(r"\d", value):
                    problems.append(f"{path}: Server header leaks a version ({value!r})")
                if "granian" in value.lower():
                    problems.append(f"{path}: upstream Server header leaked ({value!r})")
            if resp.header("X-Powered-By"):
                problems.append(f"{path}: X-Powered-By {resp.header('X-Powered-By')!r}")
            if re.search(rb"nginx/\d", resp.body):
                problems.append(f"{path}: nginx version in the body")
        self.assert_no_problems(problems)

    def test_C03_disallowed_methods_405(self):
        """PUT/DELETE/TRACE/OPTIONS/PATCH -> 405; unknown methods -> 4xx; GET/HEAD/POST work."""
        problems, seen = [], []
        for method in ("PUT", "DELETE", "TRACE", "OPTIONS", "PATCH"):
            for path in ("/", "/search"):
                resp = http_retry_429(method, path)
                seen.append(f"{method} {path}={status_str(resp)}")
                if resp.status != 405:
                    problems.append(f"{method} {path} -> {status_str(resp)}")
        for method in ("PROPFIND", "FOO"):
            resp = http_retry_429(method, "/")
            if not 400 <= resp.status < 500:
                problems.append(f"{method} / -> {status_str(resp)} (expected 4xx)")
        get = http_retry_429("GET", "/")
        head = http_retry_429("HEAD", "/")
        post = search({"q": ""}, method="POST")
        if get.status != 200:
            problems.append(f"GET / -> {status_str(get)}")
        if head.status != 200 or head.body:
            problems.append(f"HEAD / -> {status_str(head)} with {len(head.body)} body bytes")
        if post.status != 200:
            problems.append(f"POST /search (empty q) -> {status_str(post)}")
        self.assert_no_problems(problems)

    def test_C04_body_over_32k_rejected_413(self):
        """Request bodies over 32 KiB are rejected with 413 (Content-Length and chunked)."""
        hdrs = {"Content-Type": "application/x-www-form-urlencoded"}
        problems = []
        big = http_retry_429("POST", "/search", hdrs, "q=&pad=" + "x" * 40000)
        if big.status != 413:
            problems.append(f"40 KB body (Content-Length) -> {status_str(big)}")

        def chunks():
            yield b"q=&pad="
            for _ in range(8):
                yield b"x" * 5000

        try:
            chunked = http_retry_429("POST", "/search", hdrs, chunks())
            if chunked.status != 413:
                problems.append(f"40 KB chunked body -> {status_str(chunked)}")
        except (httpclient.HTTPException, OSError) as exc:
            problems.append(f"40 KB chunked body: connection error {exc.__class__.__name__} instead of 413")
        small = http_retry_429("POST", "/search", hdrs, "q=&pad=" + "x" * 16000)
        if small.status == 413 or is_bad(small.status):
            problems.append(f"16 KB body (below the limit) -> {status_str(small)}")
        self.note(f"40KB -> {status_str(big)}, 16KB -> {status_str(small)}")
        self.assert_no_problems(problems)

    def test_C05_oversized_query_and_headers_no_5xx(self):
        """10k-char query -> 414 or a clean 4xx/200; a 10 KB header -> 4xx; never 5xx."""
        problems = []
        resp = search({"q": "a" * 10000, "format": "json", "engines": PROBE_ENGINE})
        if is_bad(resp.status):
            problems.append(f"10k query -> {status_str(resp)}")
        self.note(f"10k-char query -> {status_str(resp)}")
        resp = http_retry_429("GET", "/", headers={"X-Oversized": "b" * 10000})
        if not 400 <= resp.status < 500:
            problems.append(f"10 KB header -> {status_str(resp)} (expected 4xx)")
        self.note(f"10 KB header -> {status_str(resp)}")
        resp = http_retry_429("GET", "/", headers={f"X-Filler-{i}": "c" * 200 for i in range(40)})
        if is_bad(resp.status):
            problems.append(f"40 headers x 200 B -> {status_str(resp)}")
        resp = http_retry_429("GET", "/", headers={"Cookie": "torxng=" + "d" * 7000})
        if is_bad(resp.status):
            problems.append(f"7 KB cookie -> {status_str(resp)}")
        self.assert_no_problems(problems)

    def test_C06_unicode_and_blank_queries(self):
        """Unicode, emoji, RTL, bidi-override, zero-width, blank and empty queries never 5xx."""
        queries = {
            "latin1": "Z\u00fcrich Stra\u00dfe caf\u00e9",
            "cjk": "\u6771\u4eac \u5929\u6c17",
            "emoji": "\U0001F98A\U0001F525\U0001F9C5",
            "hebrew-rtl": "\u05e9\u05dc\u05d5\u05dd \u05e2\u05d5\u05dc\u05dd",
            "arabic-rtl": "\u0645\u0631\u062d\u0628\u0627 \u0628\u0627\u0644\u0639\u0627\u0644\u0645",
            "bidi-override": "abc\u202edcba\u202c",
            "zero-width": "\u200b\u200d\ufeff",
            "combining": "e\u0301" * 30,
            "whitespace": "   ",
            "tabs-newlines": "\t\n\r\n\t",
            "empty": "",
            "long-unicode": "\u0436" * 400,
        }

        def run(item):
            name, query = item
            return name, search({"q": query, "format": "json", "engines": PROBE_ENGINE})

        problems, summary = [], []
        for result in parallel(run, list(queries.items())):
            if isinstance(result, Exception):
                problems.append(f"request error {result!r}")
                continue
            name, resp = result
            summary.append(f"{name}={status_str(resp)}")
            if is_bad(resp.status):
                problems.append(f"{name} -> {status_str(resp)}")
            elif resp.status == 200:
                try:
                    if not isinstance(resp.json().get("results"), list):
                        problems.append(f"{name}: JSON without a results list")
                except ValueError:
                    problems.append(f"{name}: invalid JSON")
        html = search({"q": "\U0001F98A Z\u00fcrich", "engines": PROBE_ENGINE})
        if html.status != 200:
            problems.append(f"HTML unicode query -> {status_str(html)}")
        elif "utf-8" not in (html.header("Content-Type") or "").lower():
            problems.append(f"HTML Content-Type {html.header('Content-Type')!r} without charset=utf-8")
        elif "\U0001F98A" not in html.text:
            self.note("emoji not reflected in the HTML page")
        self.note(", ".join(summary))
        self.assert_no_problems(problems)

    def test_C07_nul_and_crlf_injection(self):
        """%00 and CRLF in parameters/paths never cause 5xx or response header injection."""
        cases = [
            {"q": "\x00"},
            {"q": "a\x00b"},
            {"q": "torxng\r\nX-Injected: 1"},
            {"q": "torxng", "language": "en\r\nSet-Cookie: torxng_pwn=1"},
            {"q": "torxng", "categories": "general\r\nX-Injected: 1"},
            {"q": "torxng", "pageno": "1\x00"},
            {"q": "torxng", "time_range": "day\r\n"},
        ]
        problems, summary = [], []

        def check(label, resp):
            summary.append(f"{label}={status_str(resp)}")
            if is_bad(resp.status):
                problems.append(f"{label} -> {status_str(resp)}")
            if resp.header_all("X-Injected"):
                problems.append(f"{label}: injected header X-Injected in the response")
            if any("torxng_pwn" in c for c in resp.header_all("Set-Cookie")):
                problems.append(f"{label}: injected Set-Cookie in the response")
            location = resp.header("Location") or ""
            if "\r" in location or "\n" in location:
                problems.append(f"{label}: CR/LF in Location")

        def run(params):
            full = {"format": "json", "engines": PROBE_ENGINE}
            full.update(params)
            return repr(params)[:40], search(full)

        for result in parallel(run, cases):
            if isinstance(result, Exception):
                problems.append(f"request error {result!r}")
            else:
                check(*result)
        for path in ("/search%0d%0aX-Injected:%201", "/%0d%0aSet-Cookie:%20torxng_pwn=1", "/static/%00",
                     "/search?q=%00&format=json&engines=" + PROBE_ENGINE):
            check(path, http_retry_429("GET", path, timeout=SEARCH_TIMEOUT))
        self.note(f"{len(summary)} requests: " + ", ".join(s.split("=")[-1] for s in summary))
        self.assert_no_problems(problems)

    def test_C08_xss_payload_escaped(self):
        """XSS payloads in q and other parameters are never reflected unescaped; JSON is typed."""
        raw_markers = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                       "<svg onload=alert(1)>", "<script>alert(2)</script>"]
        payloads = [
            {"q": "<script>alert(1)</script>"},
            {"q": '"><img src=x onerror=alert(1)>'},
            {"q": "'><svg onload=alert(1)>"},
            {"q": "</textarea><script>alert(2)</script>"},
            {"q": "torxng", "pageno": "<script>alert(1)</script>"},
            {"q": "torxng", "categories": "<script>alert(1)</script>"},
            {"q": "torxng", "language": "<svg onload=alert(1)>"},
        ]

        def run(params):
            full = {"engines": PROBE_ENGINE}
            full.update(params)
            return params, search(full)

        problems, escaped = [], 0
        for result in parallel(run, payloads):
            if isinstance(result, Exception):
                problems.append(f"request error {result!r}")
                continue
            params, resp = result
            if is_bad(resp.status):
                problems.append(f"{params} -> {status_str(resp)}")
            for marker in raw_markers:
                if marker in resp.text:
                    problems.append(f"{params}: reflected unescaped: {marker}")
            if "&lt;script&gt;" in resp.text or "&lt;img" in resp.text or "&lt;svg" in resp.text:
                escaped += 1
        resp = search({"q": "<script>alert(1)</script>", "format": "json", "engines": PROBE_ENGINE})
        ctype = resp.header("Content-Type") or ""
        if resp.status == 200 and not ctype.startswith("application/json"):
            problems.append(f"JSON answer has Content-Type {ctype!r}")
        self.note(f"{escaped}/{len(payloads)} responses reflected the payload HTML-escaped")
        self.assert_no_problems(problems)

    def test_C09_static_path_traversal(self):
        """Path traversal on /static (plain, encoded, double-encoded, backslash) -> 4xx, no file leak."""
        paths = [
            "/static/../../../../etc/passwd",
            "/static/..%2f..%2f..%2f..%2fetc%2fpasswd",
            "/static/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/static/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "/static/..%5c..%5c..%5c..%5cetc%5cpasswd",
            "/static/....//....//....//etc/passwd",
            "/static/%252e%252e/%252e%252e/etc/passwd",
            "/static/..%00/etc/passwd",
            "/static/themes/simple/../../../settings.yml",
            "/static/%2e%2e/%2e%2e/webapp.py",
            "/../../../../etc/passwd",
            "/static//etc/searxng/settings.yml",
        ]
        problems, summary = [], []
        for path in paths:
            resp = http_retry_429("GET", path)
            summary.append(str(resp.status))
            if not 400 <= resp.status < 500:
                problems.append(f"{path} -> {status_str(resp)}")
            for marker in SENSITIVE_MARKERS:
                if marker in resp.body:
                    problems.append(f"{path}: body contains {marker.decode()!r}")
            if b"import " in resp.body and b"def " in resp.body:
                problems.append(f"{path}: body looks like Python source")
        self.note("statuses: " + ",".join(summary))
        self.assert_no_problems(problems)

    def test_C10_invalid_parameters_never_5xx(self):
        """Invalid pageno/time_range/language/categories/safesearch/format/theme never cause 5xx."""
        cases = [
            {"pageno": "-1"}, {"pageno": "0"}, {"pageno": "abc"}, {"pageno": "100000"}, {"pageno": "1.5"},
            {"pageno": "9" * 30}, {"time_range": "decade"}, {"time_range": "<x>"}, {"time_range": "day"},
            {"language": "xx-INVALID"}, {"language": "../../etc/passwd"}, {"language": "a" * 300},
            {"language": "auto"}, {"categories": "nonexistent"}, {"categories": ",,,"},
            {"safesearch": "5"}, {"safesearch": "-1"}, {"safesearch": "abc"},
            {"format": "xml"}, {"format": "csv"}, {"format": "rss"}, {"format": ""},
            {"theme": "../../etc"}, {"engines": "torxng-nonexistent-engine"},
        ]

        def run(extra):
            params = {"q": "torxng", "format": "json", "engines": PROBE_ENGINE}
            params.update(extra)
            return extra, search(params)

        problems, counts = [], {}
        for result in parallel(run, cases):
            if isinstance(result, Exception):
                problems.append(f"request error {result!r}")
                continue
            extra, resp = result
            counts[resp.status] = counts.get(resp.status, 0) + 1
            if is_bad(resp.status):
                label = {k: (v[:20] + "...") if len(v) > 20 else v for k, v in extra.items()}
                problems.append(f"{label} -> {status_str(resp)}")
        self.note("status counts: " + ", ".join(f"{k}x{v}" for k, v in sorted(counts.items())))
        self.assert_no_problems(problems)

    def test_C11_client_css_and_healthz(self):
        """/client12345678.css -> 200 text/css (no Valkey needed); /healthz -> 200 OK."""
        problems = []
        resp = http_retry_429("GET", "/client12345678.css")
        ctype = resp.header("Content-Type") or ""
        if resp.status != 200 or not ctype.startswith("text/css"):
            problems.append(f"/client12345678.css -> {status_str(resp)} {ctype!r}")
        resp = http_retry_429("GET", "/healthz")
        if resp.status != 200 or resp.body.strip() != b"OK":
            problems.append(f"/healthz -> {status_str(resp)} {resp.body[:40]!r}")
        self.assert_no_problems(problems)

    def test_C12_image_proxy_rejects_forged_hmac(self):
        """/image_proxy and /favicon_proxy reject missing/forged HMACs (no open proxy / SSRF)."""

        def forged(value: str) -> str:
            return hmac.new(b"ultrasecretkey", value.encode(), hashlib.sha256).hexdigest()

        control = f"http://{TOR_IP}:9051/"
        cases = [
            ("/image_proxy", "no parameters"),
            ("/image_proxy?" + urllib.parse.urlencode({"url": control}), "ControlPort URL without h"),
            ("/image_proxy?" + urllib.parse.urlencode({"url": control, "h": "0" * 64}), "zero HMAC"),
            ("/image_proxy?" + urllib.parse.urlencode({"url": control, "h": "abc"}), "truncated HMAC"),
            ("/image_proxy?" + urllib.parse.urlencode({"url": control, "h": forged(control)}),
             "HMAC with the default secret"),
            ("/image_proxy?" + urllib.parse.urlencode(
                {"url": "http://127.0.0.1:8080/healthz", "h": forged("http://127.0.0.1:8080/healthz")}),
             "loopback healthz"),
            ("/image_proxy?" + urllib.parse.urlencode(
                {"url": f"http://{FRONTEND_IP}:8080/", "h": forged(f"http://{FRONTEND_IP}:8080/")}), "frontend"),
            ("/image_proxy?" + urllib.parse.urlencode({"url": "file:///etc/passwd", "h": forged("file:///etc/passwd")}),
             "file:// URL"),
            ("/favicon_proxy?" + urllib.parse.urlencode({"authority": f"{TOR_IP}:9051", "h": forged(f"{TOR_IP}:9051")}),
             "favicon ControlPort"),
            ("/favicon_proxy?" + urllib.parse.urlencode({"authority": "127.0.0.1:8080", "h": "0" * 64}),
             "favicon loopback"),
        ]
        problems = []
        for path, what in cases:
            resp = http_retry_429("GET", path, timeout=45)
            if not 400 <= resp.status < 500:
                problems.append(f"{what} -> {status_str(resp)}")
            if resp.body.strip() == b"OK" or b"Authentication" in resp.body or b"514 " in resp.body:
                problems.append(f"{what}: internal content leaked ({resp.body[:40]!r})")
            for marker in SENSITIVE_MARKERS:
                if marker in resp.body:
                    problems.append(f"{what}: body contains {marker.decode()!r}")
        self.note(f"{len(cases)} forged/missing HMAC requests rejected" if not problems else "")
        self.assert_no_problems(problems)

    def test_C13_xff_spoofing_ignored(self):
        """Client-supplied X-Forwarded-For / X-Real-IP / Forwarded do not change the client IP."""
        spoof = {"X-Forwarded-For": "8.8.8.8", "X-Real-IP": "8.8.4.4", "Forwarded": "for=9.9.9.9"}

        def seen_ip(headers):
            resp = search({"q": "ip", "format": "json", "engines": PROBE_ENGINE}, headers=headers)
            if resp.status != 200:
                return None, f"HTTP {status_str(resp)}"
            for text in answer_texts(resp.json()):
                match = re.search(r"Your IP is:?\s*([0-9A-Fa-f:.]+)", text)
                if match:
                    return match.group(1).rstrip("."), text
            return None, "no 'Your IP is' answer"

        plain, detail = seen_ip({})
        if plain is None:
            self.skipTest(f"self_info plugin gave no IP answer ({detail})")
        spoofed, detail = seen_ip(spoof)
        problems = []
        if spoofed in ("8.8.8.8", "8.8.4.4", "9.9.9.9"):
            problems.append(f"SearXNG trusted the client header: sees {spoofed}")
        elif spoofed is None:
            problems.append(f"no IP answer with spoofed headers ({detail})")
        elif spoofed != plain:
            problems.append(f"client IP changed from {plain} to {spoofed} with spoofed headers")
        if not ipaddress.ip_address(plain).is_private:
            self.note(f"client address {plain} is not private")
        self.note(f"SearXNG sees {plain} (with spoofed headers: {spoofed})")
        self.assert_no_problems(problems)

    def test_C14_slow_client_timeouts(self):
        """Slowloris: an unfinished header or body is cut off within ~10 s (limit 20 s)."""
        limit = 30.0

        def slow(kind):
            sock = socket.create_connection((CFG.host, CFG.port), timeout=5)
            sock.settimeout(1.0)
            t0 = time.monotonic()
            try:
                if kind == "header":
                    sock.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Slow: 1\r\n")
                else:
                    sock.sendall(b"POST /search HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                                 b"Content-Type: application/x-www-form-urlencoded\r\n"
                                 b"Content-Length: 1000\r\n\r\nq=")
                data = b""
                while time.monotonic() - t0 < limit:
                    try:
                        chunk = sock.recv(4096)
                    except socket.timeout:
                        continue
                    except OSError:
                        return kind, "reset", time.monotonic() - t0, data[:20]
                    if not chunk:
                        return kind, "closed", time.monotonic() - t0, data[:20]
                    data += chunk
                return kind, "still open", limit, data[:20]
            finally:
                sock.close()

        problems, notes = [], []
        for result in parallel(slow, ["header", "body"], workers=2):
            if isinstance(result, Exception):
                problems.append(f"error {result!r}")
                continue
            kind, outcome, seconds, data = result
            parts = data.split(b" ")
            status = parts[1].decode("ascii", "replace") if data.startswith(b"HTTP/") and len(parts) > 1 else "-"
            notes.append(f"{kind}: {outcome} after {seconds:.1f}s (status {status})")
            if outcome == "still open" or seconds > 20:
                problems.append(f"slow {kind}: connection {outcome} after {seconds:.0f}s")
            elif status not in ("-", "408", "400") and seconds < 3:
                # answered at once (e.g. 405/429): the timeout itself was not exercised
                notes[-1] += " [timeout not exercised]"
                if status.startswith("5"):
                    problems.append(f"slow {kind}: HTTP {status}")
            else:
                metric(f"slow_{kind}_s", round(seconds, 1), "timeouts")
        self.note("; ".join(notes))
        self.assert_no_problems(problems)

    def test_C15_rate_limit_search_burst_429(self):
        """A burst of 30 searches (and 20 autocompleter calls) yields some 429 and no 5xx."""
        time.sleep(6)  # start with a refilled bucket (2 r/s, burst 10)
        statuses = burst("/search?q=", 30, 6)
        time.sleep(6)
        auto = burst("/autocompleter?q=", 20, 5)
        time.sleep(6)  # leave a refilled bucket for the following tests
        problems = []
        n429 = statuses.count(429)
        a429 = auto.count(429)
        metric("search_burst_429_of_30", n429, "rate_limit")
        metric("autocompleter_burst_429_of_20", a429, "rate_limit")
        if not n429:
            problems.append(f"no 429 in a burst of 30 searches (statuses {sorted(set(map(str, statuses)))})")
        if not a429:
            problems.append(f"no 429 in a burst of 20 /autocompleter calls (statuses {sorted(set(map(str, auto)))})")
        for label, values in (("search", statuses), ("autocompleter", auto)):
            bad = [s for s in values if is_bad(s)]
            if bad:
                problems.append(f"{label} burst: {bad[:5]}")
        self.note(f"/search: {n429}/30 got 429; /autocompleter: {a429}/20 got 429")
        self.assert_no_problems(problems)

    def test_C16_rate_limit_image_proxy_burst_429(self):
        """A burst of 150 /image_proxy requests hits the image zone limit (429), no 5xx."""
        # The img zone may queue (burst without nodelay): only requests beyond
        # the queue are rejected, so the burst must be truly concurrent.
        statuses = burst("/image_proxy", 150, 120)
        time.sleep(5)
        n429 = statuses.count(429)
        metric("image_proxy_burst_429_of_150", n429, "rate_limit")
        problems = []
        if not n429:
            problems.append(f"no 429 in a burst of 150 /image_proxy requests ({sorted(set(map(str, statuses)))})")
        bad = [s for s in statuses if is_bad(s)]
        if bad:
            problems.append(f"errors/5xx: {bad[:5]}")
        self.note(f"{n429}/150 got 429")
        self.assert_no_problems(problems)

    def test_C17_queries_not_logged(self):
        """A unique search term never appears in any container log (tor, core, frontend)."""
        self.need_service("frontend", "core", "tor")
        marker = "torxngprivacy" + secrets.token_hex(4)
        since = str(int(time.time()) - 2)
        time.sleep(1)
        statuses = []
        # 1. searches that reach core and the engines (all engines, POST/HTML, one engine)
        for params, method in (({"q": marker, "format": "json"}, "GET"),
                               ({"q": marker}, "POST"),
                               ({"q": marker + " tor", "format": "json", "engines": PROBE_ENGINE}, "GET"),
                               ({"q": marker, "format": "json", "engines": PROBE_ENGINE, "pageno": "abc"}, "GET")):
            statuses.append(status_str(search(params, method=method)))
        # 2. requests nginx rejects: rate limited (429) and too large (413)
        time.sleep(1)
        burst("/search?q=", 20, 6)
        for _ in range(3):
            statuses.append(status_str(http("GET", f"/search?q={marker}&format=json", timeout=SEARCH_TIMEOUT)))
        statuses.append(status_str(http("POST", f"/search?q={marker}",
                                        {"Content-Type": "application/x-www-form-urlencoded"},
                                        "q=&pad=" + "x" * 40000)))
        time.sleep(3)
        problems = []
        for svc in ("frontend", "core", "tor"):
            cid = STACK.container_id(svc)
            if not cid:
                continue
            res = STACK.dock("logs", "--since", since, cid, timeout=60)
            hits = [l.strip() for l in res.output.splitlines() if marker in l]
            if hits:
                pos = hits[0].find(marker)
                problems.append(f"{svc}: search term in {len(hits)} log line(s), e.g. "
                                f"...{hits[0][max(0, pos - 80):pos + len(marker) + 20]}...")
        time.sleep(6)  # refill the bucket for the following tests
        self.note(f"marker requests -> {', '.join(statuses)}; searched frontend, core and tor logs")
        self.assert_no_problems(problems)

    def test_C18_no_tor_details_in_public_endpoints(self):
        """/config, /stats and the HTML pages expose no proxy URL, SOCKS credentials or ControlPort data."""
        problems = []
        resp = http_retry_429("GET", "/config")
        if resp.status != 200:
            problems.append(f"/config -> {status_str(resp)}")
        else:
            text = resp.text
            for needle in ("socks5h", "socks5://", "sxng-", "9050", "9051", "tor_control", "172.30.0."):
                if needle in text:
                    pos = text.find(needle)
                    problems.append(f"/config contains {needle!r}: ...{text[max(0, pos - 40):pos + 40]}...")
        pages = ["/", "/preferences", "/stats", "/stats/errors", "/search?q=circuit&engines=" + PROBE_ENGINE]
        seen = []
        for path in pages:
            resp = http_retry_429("GET", path, timeout=SEARCH_TIMEOUT)
            seen.append(f"{path.split('?')[0]}={status_str(resp)}")
            if resp.status != 200:
                continue
            for pattern in (r"socks5h?://", r"sxng-\d+:", r"tor:905[01]", r"172\.30\.0\.2:905[01]", r"tor_control",
                            r"HashedControlPassword"):
                match = re.search(pattern, resp.text)
                if match:
                    problems.append(f"{path.split('?')[0]} contains {match.group(0)!r}")
        self.note("checked /config and " + ", ".join(seen))
        self.assert_no_problems(problems)


# ---------------------------------------------------------------------------
# Group D - Tor behaviour
# ---------------------------------------------------------------------------


def plugin_ids() -> dict[str, bool] | None:
    try:
        resp = http_retry_429("GET", "/config")
        if resp.status != 200:
            return None
        return {p.get("name"): bool(p.get("enabled")) for p in resp.json().get("plugins") or []}
    except (OSError, ValueError):
        return None


class GroupD(StackTest):
    """D - Tor behaviour."""

    def need_tor_circuit_plugin(self) -> None:
        self.need_http()
        plugins = plugin_ids()
        if plugins is None:
            self.skipTest("/config not available")
        if "tor_circuit" not in plugins:
            self.skipTest("tor_circuit plugin not deployed (not in /config plugins)")
        if not plugins["tor_circuit"]:
            self.skipTest("tor_circuit plugin deployed but not active by default")

    @staticmethod
    def circuit_query() -> tuple[list[str] | None, float, str]:
        t0 = time.monotonic()
        resp = search({"q": "circuit", "format": "json", "engines": PROBE_ENGINE}, timeout=180)
        elapsed = time.monotonic() - t0
        if resp.status != 200:
            return None, elapsed, f"HTTP {status_str(resp)}"
        texts = [t for t in answer_texts(resp.json()) if t.startswith("Circuit ") or t.startswith("Tor circuits")]
        return texts, elapsed, ""

    def test_D01_circuit_answers_show_tor_exits(self):
        """'circuit' shows every pooled circuit exiting via Tor, without guard/middle relays."""
        self.need_tor_circuit_plugin()

        def attempt():
            texts, _, err = self.circuit_query()
            if texts is None:
                return False, err
            if not any("Tor: yes" in t for t in texts):
                return False, "no 'Tor: yes' answer: " + (" | ".join(texts)[:300] or "no circuit answers")
            return True, texts

        ok, value, attempts = retry(attempt, attempts=3, delay=20)
        if not ok:
            self.fail(f"after {attempts} attempts: {value}")
        texts = value
        problems, exits, circuits, summary = [], set(), 0, None
        for text in texts:
            match = re.search(r"Tor circuits:\s*(\d+),\s*distinct exit IPs:\s*(\d+)", text)
            if match:
                summary = (int(match.group(1)), int(match.group(2)))
                continue
            if not re.match(r"Circuit \d+/\d+ - ", text):
                continue
            circuits += 1
            for ip_match in re.finditer(r"exit IP\s+\[?([0-9A-Fa-f:.]*[0-9A-Fa-f])\]?", text):
                try:
                    addr = ipaddress.ip_address(ip_match.group(1))
                except ValueError:
                    continue
                exits.add(str(addr))
                if not addr.is_global:
                    problems.append(f"exit IP {addr} is not a public address")
            if "Tor: no" in text:
                problems.append(f"circuit reports 'Tor: no': {text[:120]}")
        # guard discovery protection: only the exit relay may be named
        for text in texts:
            if "->" in text:
                problems.append(f"relay path disclosed: {text[:140]}")
            if re.search(r"\b(guard|middle)\b", text.replace("guard and middle hidden", ""), re.IGNORECASE):
                problems.append(f"guard/middle relay mentioned: {text[:140]}")
        if not exits:
            problems.append("no exit IP could be parsed from: " + " | ".join(texts)[:200])
        if summary is None:
            problems.append("no 'Tor circuits: N, distinct exit IPs: M' summary answer")
        else:
            if summary[0] != circuits:
                problems.append(f"summary says {summary[0]} circuits, {circuits} circuit answers")
            if summary[1] != len(exits):
                problems.append(f"summary says {summary[1]} distinct exit IPs, parsed {len(exits)}")
        metric("exit_ips_distinct", len(exits))
        metric("exit_ips", sorted(exits))
        metric("tor_circuits", circuits)
        relay = "exit relay named" if any("hops (guard and middle hidden)" in t for t in texts) else "exit relay unknown"
        self.note(f"{circuits} circuits, {len(exits)} distinct exit IPs, {relay}, no guard/middle relay disclosed "
                  f"({attempts} attempt(s))")
        self.assert_no_problems(problems)

    def test_D06_circuit_results_cached(self):
        """Repeated 'circuit' queries within 60 s reuse one probe result (no probe amplification)."""
        self.need_tor_circuit_plugin()
        first, t_first, err = self.circuit_query()
        if first is None or not first:
            self.fail(f"first circuit query failed: {err or 'no circuit answers'}")
        second, t_second, err = self.circuit_query()
        if second is None:
            self.fail(f"second circuit query failed: {err}")
        pair = (first, second)
        note = ""
        if first != second:
            # the 60 s TTL may have expired between the two queries: the next one
            # must then return the freshly cached result
            third, _, err = self.circuit_query()
            if third is None:
                self.fail(f"third circuit query failed: {err}")
            pair = (second, third)
            note = " (cache refreshed between queries 1 and 2, compared 2 and 3)"
        if pair[0] != pair[1]:
            def exits(texts):
                return sorted(set(re.findall(r"exit IP\s+([0-9A-Fa-f:.]*[0-9A-Fa-f])", " ".join(texts))))
            self.fail(f"two circuit queries within seconds differ: exits {exits(pair[0])} vs {exits(pair[1])}")
        metric("circuit_query_s", {"first": round(t_first, 2), "repeat": round(t_second, 2)})
        self.note(f"identical answers ({len(pair[0])} lines) for queries seconds apart{note}; "
                  f"{t_first:.1f}s / {t_second:.1f}s")

    def test_D02_tor_check_not_applicable(self):
        """'tor-check' says 'not applicable' with a private address, even with a spoofed XFF."""
        self.need_http()

        def ask(headers):
            resp = search({"q": "tor-check", "format": "json", "engines": PROBE_ENGINE}, headers=headers)
            if resp.status != 200:
                return f"HTTP {status_str(resp)}"
            texts = answer_texts(resp.json())
            return next((t for t in texts if "applicable" in t or "Tor" in t or "tor" in t), None)

        plain = ask({})
        if plain is None:
            plugins = plugin_ids() or {}
            if not plugins.get("tor_check"):
                self.skipTest("tor_check plugin not active")
            self.fail("no tor-check answer")
        problems = []
        if "not applicable" not in plain:
            problems.append(f"answer: {plain[:160]!r}")
        match = re.search(r"([0-9A-Fa-f:.]+)\s*$", plain.strip())
        if match:
            try:
                if not ipaddress.ip_address(match.group(1).rstrip(".")).is_private:
                    problems.append(f"reported address {match.group(1)} is not private")
            except ValueError:
                pass
        spoofed = ask({"X-Forwarded-For": "185.220.101.1", "X-Real-IP": "185.220.101.1"})
        if not spoofed or "not applicable" not in spoofed:
            problems.append(f"with a spoofed Tor-exit XFF the answer changed: {str(spoofed)[:160]!r}")
        ip_note = match.group(1).rstrip(".") if match else "?"
        self.note(f"'not applicable' for {ip_note}, also with a spoofed Tor-exit XFF")
        self.assert_no_problems(problems)

    def test_D03_onion_hostname_valid_v3(self):
        """Onion hostname is a valid v3 address (checksum verified) matching the HS public key.

        56 base32 chars, version 0x03, SHA3-256(".onion checksum" || pubkey || 0x03)[:2];
        the key equals hs_ed25519_public_key and is an ed25519 point of prime order."""
        self.need_service("tor")
        address = read_onion_hostname(self)
        ok, reason, pubkey = verify_onion_v3(address)
        problems = []
        if not address.endswith(".onion"):
            problems.append("hostname does not end with .onion")
        if not ok:
            problems.append(f"{short_onion(address)}: {reason}")
        res = STACK.exec_in("tor", ["base64", hs_dir(self) + "/hs_ed25519_public_key"], timeout=20)
        if res.ok and pubkey:
            try:
                blob = base64.b64decode("".join(res.out.split()))
            except ValueError:
                blob = b""
            if len(blob) != 64 or not blob.startswith(HS_PUBKEY_HEADER[:29]):
                problems.append(f"unexpected hs_ed25519_public_key format ({len(blob)} bytes)")
            elif blob[32:] != pubkey:
                problems.append("the address does not encode the key in hs_ed25519_public_key")
            else:
                self.note("address encodes hs_ed25519_public_key")
        else:
            self.note(f"public key file not readable ({res.brief(80)})")
        if pubkey:
            point_ok, point_reason = ed25519_pubkey_check(pubkey)
            if not point_ok:
                problems.append(f"public key: {point_reason}")
        self.note(f"{short_onion(address)}: {reason}")
        self.assert_no_problems(problems)

    def test_D04_onion_served_through_frontend(self):
        """The onion service answers 200 via Tor and carries nginx's security headers."""
        self.need_service("tor")
        address = read_onion_hostname(self)
        _, _, opts = read_torrc(self)
        socks = (opts.get("socksport") or [f"{TOR_IP}:9050"])[0].split()[0]
        if ":" not in socks:
            socks = f"127.0.0.1:{socks}"

        def attempt():
            res = STACK.exec_in(
                "tor",
                ["curl", "-sS", "-o", "/dev/null", "-D", "-", "--max-time", "120",
                 "--socks5-hostname", socks, f"http://{address}/"],
                timeout=150,
            )
            if res.rc in (126, 127):
                return True, None
            status_line = next((l for l in res.out.splitlines() if l.startswith("HTTP/")), "")
            if " 200" not in status_line:
                return False, f"curl rc={res.rc} {status_line or res.brief(150)}"
            return True, res

        t0 = time.monotonic()
        ok, value, attempts = retry(attempt, attempts=3, delay=20)
        elapsed = time.monotonic() - t0
        if ok and value is None:
            self.skipTest("curl not available in the tor container")
        if not ok:
            self.fail(f"onion service unreachable after {attempts} attempts: {value}")
        headers = []
        for line in value.out.splitlines()[1:]:
            if ":" in line:
                key, _, val = line.partition(":")
                headers.append((key.strip(), val.strip()))
        problems = [f"{name} {issue}" for name, issue in security_header_issues(headers)]
        server = [v for k, v in headers if k.lower() == "server"]
        if server and re.search(r"\d", server[0]):
            problems.append(f"Server header {server[0]!r} leaks a version")
        metric("onion_fetch_s", round(elapsed, 1))
        self.note(f"200 via Tor in {elapsed:.0f}s ({attempts} attempt(s))")
        if problems:
            self.fail("onion response does not go through the hardened frontend: " + " | ".join(problems))

    def test_D05_torrc_hardening_options(self):
        """torrc carries the hardening options (SafeSocks, ClientOnly, onion DoS defences ...).

        ClientOnly, SafeSocks, AvoidDiskWrites, SocksPolicy, IsolateSOCKSAuth, intro DoS
        defence, MaxStreams, PoW only if compiled in, HiddenServicePort -> frontend."""
        self.need_service("tor")
        path, _, opts = read_torrc(self)
        problems = []

        def one(key):
            values = opts.get(key.lower()) or []
            return values[-1] if values else None

        for key in ("ClientOnly", "SafeSocks", "AvoidDiskWrites", "HiddenServiceEnableIntroDoSDefense",
                    "HiddenServiceMaxStreamsCloseCircuit"):
            if one(key) != "1":
                problems.append(f"{key} = {one(key)!r} (expected 1)")
        streams = one("HiddenServiceMaxStreams")
        if not streams or not streams.isdigit() or int(streams) == 0:
            problems.append(f"HiddenServiceMaxStreams = {streams!r}")
        socks_ports = opts.get("socksport") or []
        if not socks_ports:
            problems.append("no SocksPort")
        for port in socks_ports:
            if "isolatesocksauth" not in port.lower():
                problems.append(f"SocksPort {port!r} without IsolateSOCKSAuth")
            if port.startswith("0.0.0.0"):
                problems.append(f"SocksPort {port!r} listens on all interfaces")
        policy = [p.lower() for p in opts.get("sockspolicy") or []]
        if "accept 172.30.0.0/24" not in policy or not policy or policy[-1] != "reject *":
            problems.append(f"SocksPolicy {policy} (expected accept 172.30.0.0/24, reject *)")
        hs_ports = opts.get("hiddenserviceport") or []
        if f"80 {FRONTEND_IP}:8080" not in hs_ports:
            problems.append(f"HiddenServicePort {hs_ports} (expected '80 {FRONTEND_IP}:8080': onion via nginx)")
        res = STACK.exec_in("tor", ["tor", "--list-modules"], timeout=30)
        pow_compiled = bool(re.search(r"^pow:\s*yes", res.out, re.MULTILINE))
        pow_opt = one("HiddenServicePoWDefensesEnabled")
        if pow_compiled and pow_opt != "1":
            problems.append(f"tor has the pow module but HiddenServicePoWDefensesEnabled = {pow_opt!r}")
        if not pow_compiled and pow_opt == "1":
            problems.append("HiddenServicePoWDefensesEnabled 1 without the pow module")
        if opts.get("controlport"):
            if not opts.get("hashedcontrolpassword"):
                problems.append("ControlPort without HashedControlPassword")
            if one("CookieAuthentication") == "1":
                problems.append("CookieAuthentication 1")
            for entry in opts["controlport"]:
                if not (entry.startswith("127.0.0.1:") or entry.startswith("unix:")):
                    problems.append(f"ControlPort {entry!r} is not loopback-only")
        self.note(f"{path}: pow module {'yes' if pow_compiled else 'no'}, MaxMemInQueues={one('MaxMemInQueues')}")
        self.assert_no_problems(problems)


class GroupDUnit(StackTest):
    """D - pure unit tests of the onion v3 / ed25519 checks (no docker needed)."""

    def test_D10_unit_onion_checksum_known_good(self):
        """verify_onion_v3 accepts addresses built from known keys (and a published address)."""
        base_addr = onion_v3_address(ED_BASE_ENCODED)
        ok, reason, pubkey = verify_onion_v3(base_addr)
        self.assertTrue(ok, reason)
        self.assertEqual(pubkey, ED_BASE_ENCODED)
        self.assertEqual(len(base_addr), 62)
        self.assertTrue(verify_onion_v3(base_addr.upper())[0], "uppercase must be accepted")
        self.assertTrue(verify_onion_v3(base_addr[:-6])[0], "the .onion suffix is optional")
        second = ed25519_encode(_ed_add(ed25519_decode(ED_BASE_ENCODED), ed25519_decode(ED_BASE_ENCODED)))
        self.assertTrue(verify_onion_v3(onion_v3_address(second))[0])
        # DuckDuckGo's published v3 onion address (independent vector)
        ddg = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
        ok, reason, pubkey = verify_onion_v3(ddg)
        self.assertTrue(ok, reason)
        self.assertTrue(ed25519_pubkey_check(pubkey)[0])
        self.note(f"B -> {short_onion(base_addr)}, 2B and a published address verified")

    def test_D11_unit_onion_checksum_rejects_corruption(self):
        """verify_onion_v3 rejects flipped characters, wrong version, length and alphabet."""
        addr = onion_v3_address(ED_BASE_ENCODED)[:-6]
        for pos in (0, 10, 30, 51, 52, 53):
            char = addr[pos]
            flipped = addr[:pos] + ("a" if char != "a" else "b") + addr[pos + 1:]
            ok, reason, _ = verify_onion_v3(flipped)
            self.assertFalse(ok, f"flip at {pos} accepted")
        raw = ED_BASE_ENCODED + onion_v3_checksum(ED_BASE_ENCODED, b"\x04") + b"\x04"
        ok, reason, _ = verify_onion_v3(base64.b32encode(raw).decode().lower())
        self.assertFalse(ok)
        self.assertIn("version", reason)
        bad_sum = ED_BASE_ENCODED + hashlib.sha3_256(b".onion checksumX" + ED_BASE_ENCODED + b"\x03").digest()[:2] + b"\x03"
        ok, reason, _ = verify_onion_v3(base64.b32encode(bad_sum).decode().lower())
        self.assertFalse(ok)
        self.assertIn("checksum", reason)
        self.assertFalse(verify_onion_v3(addr[:-1])[0], "55 characters accepted")
        self.assertFalse(verify_onion_v3(addr + "a")[0], "57 characters accepted")
        self.assertFalse(verify_onion_v3("1" + addr[1:])[0], "'1' is not base32")
        self.assertFalse(verify_onion_v3("")[0])
        # a v2-style 16 character address
        self.assertFalse(verify_onion_v3("expyuzz4wqqyqhjn.onion")[0])

    def test_D12_unit_ed25519_point_validation(self):
        """ed25519_pubkey_check accepts B, 2B and rejects identity, torsion, non-canonical, off-curve."""
        base = ed25519_decode(ED_BASE_ENCODED)
        self.assertTrue(ed25519_pubkey_check(ED_BASE_ENCODED)[0])
        self.assertTrue(ed25519_pubkey_check(ed25519_encode(_ed_add(base, base)))[0])
        self.assertTrue(_ed_is_identity(_ed_mul(ED_L, base)), "l * B must be the identity")
        identity = (1).to_bytes(32, "little")
        self.assertEqual(ed25519_pubkey_check(identity), (False, "identity element"))
        order2 = (ED_P - 1).to_bytes(32, "little")  # (0, -1), a point of order 2
        ok, reason = ed25519_pubkey_check(order2)
        self.assertFalse(ok)
        self.assertIn("small-order", reason)
        mixed = ed25519_encode(_ed_add(base, ed25519_decode(order2)))  # B + T: torsion component
        ok, reason = ed25519_pubkey_check(mixed)
        self.assertFalse(ok)
        self.assertIn("torsion", reason)
        ok, reason = ed25519_pubkey_check(ED_P.to_bytes(32, "little"))
        self.assertFalse(ok)
        self.assertIn("non-canonical", reason)
        for y in range(2, 200):  # first y whose x^2 is a non-residue (Euler's criterion)
            x2 = (y * y - 1) * pow(ED_D * y * y + 1, ED_P - 2, ED_P) % ED_P
            if x2 and pow(x2, (ED_P - 1) // 2, ED_P) == ED_P - 1:
                ok, reason = ed25519_pubkey_check(y.to_bytes(32, "little"))
                self.assertFalse(ok)
                self.assertIn("not on the curve", reason)
                break
        else:
            self.fail("no off-curve y found")
        self.assertFalse(ed25519_pubkey_check(b"\x00" * 31)[0])


# ---------------------------------------------------------------------------
# Group A - destructive: guard containers (do not touch the running stack)
# ---------------------------------------------------------------------------


def mirror_security_opts(info: dict) -> list[str]:
    """``docker run`` options reproducing core's user / read-only / caps / limits;
    volumes are replaced by tmpfs so the stack's data is never touched."""
    hc = info.get("HostConfig") or {}
    cfg = info.get("Config") or {}
    opts: list[str] = []
    if cfg.get("User"):
        opts += ["--user", cfg["User"]]
    if hc.get("ReadonlyRootfs"):
        opts.append("--read-only")
    for cap in hc.get("CapDrop") or []:
        opts += ["--cap-drop", cap]
    for cap in hc.get("CapAdd") or []:
        opts += ["--cap-add", cap]
    for sec in hc.get("SecurityOpt") or []:
        opts += ["--security-opt", sec]
    tmpfs = dict(hc.get("Tmpfs") or {})
    for mount in info.get("Mounts") or []:
        dest = mount.get("Destination")
        if mount.get("Type") == "volume" and dest and dest not in tmpfs:
            tmpfs[dest] = ""
    for path, mount_opts in tmpfs.items():
        opts += ["--tmpfs", f"{path}:{mount_opts}" if mount_opts else path]
    if hc.get("Memory"):
        opts += ["--memory", str(hc["Memory"])]
    if (hc.get("PidsLimit") or 0) > 0:
        opts += ["--pids-limit", str(hc["PidsLimit"])]
    if hc.get("NanoCpus"):
        opts += ["--cpus", f"{hc['NanoCpus'] / 1e9:g}"]
    return opts


class CoreRun:  # pylint: disable=too-few-public-methods
    def __init__(self, res: CmdResult, elapsed: float, logs: str, timeout: float):
        self.res = res
        self.elapsed = elapsed
        self.logs = logs
        self.timeout = timeout

    @property
    def output(self) -> str:
        return self.res.output + self.logs

    def brief(self, limit: int = 220) -> str:
        lines = [l.strip() for l in self.output.splitlines() if l.strip()]
        text = " / ".join(lines[-4:])
        return text[:limit]


def run_core_container(image: str, opts: list[str], files: dict[str, str], network: str = "none",
                       env: dict | None = None, timeout: float = 150.0) -> CoreRun:
    """``docker run --rm`` of the core image with a temporary /etc/searxng."""
    tmp = tempfile.mkdtemp(prefix="torxng-guard-")
    name = "torxng-test-" + secrets.token_hex(5)
    try:
        os.chmod(tmp, 0o755)
        for fname, content in files.items():
            fpath = os.path.join(tmp, fname)
            with open(fpath, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(content)
            os.chmod(fpath, 0o644)
        args = [STACK.docker, "run", "--rm", "--name", name, "--network", network, *opts,
                "--mount", f"type=bind,source={tmp},target=/etc/searxng,readonly",
                "-e", "SEARXNG_SECRET=" + secrets.token_hex(32), "-e", "FORCE_OWNERSHIP=false"]
        for key, value in (env or {}).items():
            args += ["-e", f"{key}={value}"]
        args.append(image)
        t0 = time.monotonic()
        res = run_cmd(args, timeout=timeout)
        elapsed = time.monotonic() - t0
        logs = ""
        if res.timed_out:
            logs = run_cmd([STACK.docker, "logs", "--tail", "60", name], timeout=30).output
        return CoreRun(res, elapsed, logs, timeout)
    finally:
        run_cmd([STACK.docker, "rm", "-f", name], timeout=60)
        shutil.rmtree(tmp, ignore_errors=True)


_CORE_PROFILE: dict[str, object] = {}


def core_profile(test: StackTest) -> tuple[str, list[str], dict[str, str]]:
    """``(image, docker-run options, deployed config files)`` of the core service."""
    test.need_docker()
    if not _CORE_PROFILE:
        info = STACK.inspect("core")
        if not info:
            test.skipTest("core container does not exist (stack not created); cannot derive image and options")
        files: dict[str, str] = {}
        if STACK.is_running("core"):
            for fname in ("settings.yml", "limiter.toml"):
                res = STACK.exec_in("core", ["cat", f"/etc/searxng/{fname}"], timeout=20)
                if res.ok:
                    files[fname] = res.out
        else:
            for fname in ("settings.yml", "limiter.toml"):
                path = os.path.join(STACK_DIR, "searxng", fname)
                if os.path.isfile(path):
                    with open(path, encoding="utf-8") as fh:
                        files[fname] = fh.read()
        if "settings.yml" not in files:
            test.skipTest("cannot read the deployed settings.yml")
        _CORE_PROFILE.update(image=info["Image"], opts=mirror_security_opts(info), files=files)
    return _CORE_PROFILE["image"], _CORE_PROFILE["opts"], _CORE_PROFILE["files"]  # type: ignore[return-value]


class GroupAGuard(StackTest):
    """A (destructive) - the tor-only guard of the core image."""

    destructive = True

    def run_guard_cases(self, cases: list[tuple[str, str | None, dict | None, tuple[str, ...]]]) -> None:
        """Each case: ``(label, settings.yml content or None for an empty config dir, env, keywords)``;
        every case must exit 78 with a one-line reason that mentions one of the keywords."""
        image, opts, _ = core_profile(self)
        problems, notes = [], []
        for label, settings, env, keywords in cases:
            files = {} if settings is None else {"settings.yml": settings}
            run = run_core_container(image, opts, files, env=env, timeout=120)
            res = run.res
            if res.rc in (125, 126, 127) and not res.timed_out:
                self.skipTest(f"docker run could not start the container: {run.brief()}")
            if res.timed_out:
                problems.append(f"{label}: container still running after {run.timeout:.0f}s "
                                f"(guard missing, SearXNG started): {run.brief(120)}")
                continue
            if res.rc != GUARD_EXIT_CODE:
                problems.append(f"{label}: exit {res.rc} (expected {GUARD_EXIT_CODE}): {run.brief(160)}")
                continue
            if "Traceback (most recent call last)" in run.output:
                problems.append(f"{label}: exit 78 but with a Python traceback (expected a one-line reason)")
            lines = [l.strip() for l in run.output.splitlines() if l.strip()]
            reason = next((l for l in lines if any(k.lower() in l.lower() for k in keywords)), None)
            if not reason:
                problems.append(f"{label}: exit 78 but no reason mentioning {keywords}: {run.brief(120)}")
            else:
                notes.append(f"{label}: 78 '{reason.replace('tor-only-guard: REFUSING TO START: ', '')[:70]}'")
        self.note(f"{len(cases) - len(problems)}/{len(cases)} cases refused with exit 78")
        for n in notes:
            self.note(n)
        self.assert_no_problems(problems)

    def test_A10_guard_rejects_settings_without_tor(self):
        """Guard exits 78 without a Tor config (defaults, flag off/without proxies, env, empty dir, bad YAML)."""
        socks5h = "  proxies:\n    all://:\n      - socks5h://tor:9050\n"
        self.run_guard_cases([
            ("defaults", guard_settings(), None, ("using_tor_proxy", "tor")),
            ("using_tor_proxy false", guard_settings("outgoing:\n  using_tor_proxy: false\n" + socks5h), None,
             ("using_tor_proxy", "tor")),
            ("tor flag without proxies", guard_settings("outgoing:\n  using_tor_proxy: true\n"), None,
             ("prox", "socks5h")),
            ("env SEARXNG_USING_TOR_PROXY=false", GUARD_TOR_OK, {"SEARXNG_USING_TOR_PROXY": "false"},
             ("using_tor_proxy", "tor")),
            ("empty config dir", None, None, ("using_tor_proxy", "settings", "prox", "tor")),
            ("invalid YAML", "use_default_settings: true\noutgoing: [unclosed\n  proxies: {\n", None,
             ("invalid SearXNG settings", "settings", "yaml")),
        ])

    def test_A11_guard_rejects_non_socks5h_proxy(self):
        """Guard exits 78 for socks5://, http://, socks4://, mixed lists and http(s)-only patterns."""
        def outgoing(proxies: str) -> str:
            return guard_settings("outgoing:\n  using_tor_proxy: true\n  proxies:\n" + proxies)

        self.run_guard_cases([
            ("socks5://", outgoing("    all://:\n      - socks5://tor:9050\n"), None, ("socks5h",)),
            ("http://", outgoing("    all://: http://tor:8118\n"), None, ("socks5h",)),
            ("socks4://", outgoing("    all://:\n      - socks4://tor:9050\n"), None, ("socks5h",)),
            ("mixed list", outgoing("    all://:\n      - socks5h://tor:9050\n      - socks5://tor:9050\n"), None,
             ("socks5h",)),
            ("per-scheme https socks5",
             outgoing("    all://:\n      - socks5h://tor:9050\n    https://: socks5://tor:9050\n"), None, ("socks5h",)),
            ("https-only pattern (no all://)", outgoing("    https://:\n      - socks5h://tor:9050\n"), None,
             ("cover", "all://")),
            ("http-only pattern (no all://)", outgoing("    http://: socks5h://tor:9050\n"), None, ("cover", "all://")),
        ])

    def test_A12_guard_rejects_non_socks5h_network_and_engine_proxies(self):
        """Guard exits 78 for non-socks5h or Tor-disabled networks and engines."""
        tor_ok = "outgoing:\n  using_tor_proxy: true\n  proxies:\n    all://:\n      - socks5h://tor:9050\n"
        self.run_guard_cases([
            ("outgoing.networks proxy", guard_settings(
                tor_ok + "  networks:\n    torxng_net:\n      proxies: socks5://tor:9050\n"), None, ("socks5h",)),
            ("outgoing.networks using_tor_proxy false", guard_settings(
                tor_ok + "  networks:\n    torxng_net:\n      using_tor_proxy: false\n"), None, ("using_tor_proxy",)),
            ("engine proxies", guard_settings(
                tor_ok, "engines:\n  - name: wikipedia\n    proxies: socks5://tor:9050\n"), None, ("socks5h",)),
            ("engine network dict", guard_settings(
                tor_ok, "engines:\n  - name: wikipedia\n    network:\n      proxies:\n        all://:\n"
                        "          - socks5h://tor:9050\n          - http://127.0.0.1:3128\n"), None, ("socks5h",)),
            ("engine network using_tor_proxy false", guard_settings(
                tor_ok, "engines:\n  - name: wikipedia\n    network:\n      using_tor_proxy: false\n"), None,
             ("using_tor_proxy",)),
        ])

    def test_A18_guard_rejects_weakened_tls_and_control_access(self):
        """Guard exits 78 for verify: false and for any tor_control.host (settings or env)."""
        self.run_guard_cases([
            ("verify: false", GUARD_TOR_OK + "  verify: false\n", None, ("verify",)),
            ("tor_control.host set", GUARD_TOR_OK + "  tor_control:\n    host: tor\n    port: 9051\n", None,
             ("tor_control",)),
            ("env SEARXNG_TOR_CONTROL_HOST", GUARD_TOR_OK, {"SEARXNG_TOR_CONTROL_HOST": "tor"}, ("tor_control",)),
        ])

    def test_A19_guard_rejects_proxy_env_vars(self):
        """Guard exits 78 if http_proxy/https_proxy/all_proxy/no_proxy is set, in any letter case."""
        values = {"no_proxy": "*", "http_proxy": "http://127.0.0.1:3128", "https_proxy": "http://127.0.0.1:3128",
                  "all_proxy": "socks5://127.0.0.1:1080"}
        names = ["NO_PROXY", "HTTPS_PROXY", "all_proxy", "http_proxy", "https_proxy", "no_proxy", "ALL_PROXY",
                 "HTTP_PROXY", "Https_Proxy", "No_Proxy"]
        self.run_guard_cases([
            (f"env {name}", GUARD_TOR_OK, {name: values[name.lower()]}, ("proxy environment", name))
            for name in names
        ])

    def test_A13_guard_accepts_tor_settings_then_fails_closed(self):
        """Guard accepts the deployed settings; SearXNG then refuses to start without Tor.

        --network none: exit != 0 and != 78, output 'Invalid network configuration'."""
        image, opts, files = core_profile(self)
        run = run_core_container(image, opts, files, network="none", timeout=300)
        if run.res.rc in (125, 126, 127) and not run.res.timed_out:
            self.skipTest(f"docker run could not start the container: {run.brief()}")
        metric("guard_valid_settings_exit_s", round(run.elapsed, 1))
        problems = []
        invalid = "Invalid network configuration" in run.output
        if run.res.timed_out:
            problems.append(
                f"container did not exit within {run.timeout:.0f}s"
                + (" although it logged 'Invalid network configuration'" if invalid else "")
                + f": {run.brief(120)}"
            )
        elif run.res.rc == GUARD_EXIT_CODE:
            problems.append(f"the guard rejected the deployed settings: {run.brief(160)}")
        elif run.res.rc == 0:
            problems.append("exit code 0 without Tor")
        if not invalid:
            problems.append(f"no 'Invalid network configuration' in the output: {run.brief(160)}")
        guard_ok = "guard passed, " if "tor-only-guard: OK" in run.output else ""
        self.note(f"{guard_ok}exit {run.res.rc} after {run.elapsed:.0f}s: RuntimeError: Invalid network configuration"
                  if invalid else f"exit {run.res.rc} after {run.elapsed:.0f}s")
        self.assert_no_problems(problems)


# ---------------------------------------------------------------------------
# Group A - destructive: tor outage (stops tor, always restores it)
# ---------------------------------------------------------------------------


class GroupATorOutage(StackTest):
    """A (destructive) - behaviour while tor is down and after it comes back."""

    destructive = True
    skip_reason: str | None = None
    stopped = False
    core_restarts: int | None = None

    @classmethod
    def setUpClass(cls):
        cls.skip_reason, cls.stopped, cls.core_restarts = None, False, None
        if not CFG.destructive:
            cls.skip_reason = "destructive test: run with --destructive"
            return
        reason = STACK.unavailable_reason() or http_unavailable_reason()
        if reason:
            cls.skip_reason = reason
            return
        ok, states = STACK.wait_healthy(STACK_SERVICES, timeout=60)
        if not ok:
            cls.skip_reason = f"stack not healthy before the outage test ({states}); not disrupting it"
            return
        cls.core_restarts = (STACK.inspect("core", refresh=True) or {}).get("RestartCount")
        print("\n    [destructive] stopping tor ...", file=sys.stderr, flush=True)
        cls.stopped = True
        res = STACK.compose("stop", "-t", "20", "tor", timeout=180)
        if not res.ok:
            cls.skip_reason = f"could not stop tor: {res.brief(150)}"
            return
        deadline = time.monotonic() + 60
        while STACK.is_running("tor", refresh=True) and time.monotonic() < deadline:
            time.sleep(2)
        time.sleep(3)

    @classmethod
    def tearDownClass(cls):
        if cls.stopped:
            print("\n    [destructive] restoring the stack (tor start, wait healthy) ...", file=sys.stderr, flush=True)
            ok, states = restore_stack("tor outage test")
            print(f"    [destructive] restore {'ok' if ok else 'FAILED'}: {states}", file=sys.stderr, flush=True)

    def setUp(self):
        super().setUp()
        if self.skip_reason:
            self.skipTest(self.skip_reason)

    def test_A14_search_without_tor_fails_gracefully(self):
        """With tor stopped: no 5xx, no results, engines reported unresponsive, core stays up."""
        problems = []
        resp = search({"q": "torxng outage probe", "format": "json"}, timeout=150)
        if is_bad(resp.status):
            problems.append(f"JSON search -> HTTP {status_str(resp)} (core running: {STACK.is_running('core', True)})")
        elif resp.status == 200:
            data = resp.json()
            if data.get("results"):
                problems.append(f"{len(data['results'])} results returned while tor is down (leak?)")
            if not data.get("unresponsive_engines"):
                problems.append("no unresponsive engines reported")
            self.note(f"JSON 200 in {resp.elapsed:.1f}s, {len(data.get('unresponsive_engines') or [])} "
                      "unresponsive engines, 0 results")
        else:
            self.note(f"JSON search -> {status_str(resp)}")
        html = search({"q": "torxng outage probe"}, timeout=150)
        if is_bad(html.status):
            problems.append(f"HTML search -> HTTP {status_str(html)}")
        health = http_retry_429("GET", "/healthz")
        if health.status != 200:
            problems.append(f"/healthz -> {status_str(health)}")
        info = STACK.inspect("core", refresh=True) or {}
        if not (info.get("State") or {}).get("Running"):
            problems.append("core is not running")
        if self.core_restarts is not None and info.get("RestartCount", 0) != self.core_restarts:
            problems.append(f"core restarted during the outage (RestartCount {info.get('RestartCount')})")
        self.assert_no_problems(problems)

    def test_A15_no_egress_while_tor_down(self):
        """With tor stopped, core still cannot reach anything directly (no fallback path)."""
        problems = []
        for code in (PROBE_IP_EGRESS, PROBE_HOST_EGRESS):
            data = self.core_py(code, timeout=120)
            problems += [f"{t} -> {r}" for t, r in data["results"] if not r.startswith("blocked")]
        res = self.exec_ok(
            "core", ["sh", "-c", "cat /proc/net/tcp /proc/net/udp; cat /proc/net/tcp6 /proc/net/udp6 2>/dev/null; true"]
        )
        for _local, (rip, rport), state in parse_proc_net(res.out):
            if rip.version == 6 and rip.ipv4_mapped:
                rip = rip.ipv4_mapped
            if rip.is_unspecified or rip.is_loopback or (rip.version == 4 and rip in ISOLATED_SUBNET):
                continue
            problems.append(f"socket to {rip}:{rport} ({TCP_STATES.get(state, state)})")
        self.assert_no_problems(problems)

    def test_A16_core_refuses_start_while_tor_down(self):
        """A new core container refuses to start while tor is down (Invalid network configuration)."""
        image, opts, files = core_profile(self)
        network = STACK.isolated_network()
        if not network:
            self.skipTest("cannot determine the isolated network")
        run = run_core_container(image, opts, files, network=network, timeout=300)
        if run.res.rc in (125, 126, 127) and not run.res.timed_out:
            self.skipTest(f"docker run could not start the container: {run.brief()}")
        problems = []
        invalid = "Invalid network configuration" in run.output
        if run.res.timed_out:
            problems.append(f"container did not exit within {run.timeout:.0f}s"
                            + (" (it logged 'Invalid network configuration')" if invalid else ""))
        elif run.res.rc in (0, GUARD_EXIT_CODE):
            problems.append(f"exit code {run.res.rc}: {run.brief(160)}")
        if not invalid:
            problems.append(f"no 'Invalid network configuration' in the output: {run.brief(160)}")
        metric("core_refuses_start_s", round(run.elapsed, 1))
        guard_ok = "guard passed, " if "tor-only-guard: OK" in run.output else ""
        self.note(f"{guard_ok}exit {run.res.rc} after {run.elapsed:.0f}s on {network}")
        self.assert_no_problems(problems)

    def test_A17_recovery_after_tor_restart(self):
        """After tor is started again, searches recover within a bounded time.

        Bounds: tor healthy <= 600 s after 'docker compose start tor', results <= 300 s later."""
        t0 = time.monotonic()
        res = STACK.compose("start", "tor", timeout=180)
        if not res.ok:
            self.fail(f"docker compose start tor failed: {res.brief(150)}")
        ok, states = STACK.wait_healthy(["tor"], timeout=600)
        t_tor = time.monotonic() - t0
        if not ok:
            self.fail(f"tor not healthy {t_tor:.0f}s after start: {states}")
        deadline = time.monotonic() + 300
        attempts, last = 0, ""
        while True:
            attempts += 1
            resp = search({"q": "tor project", "format": "json"}, timeout=120)
            if resp.status == 200:
                data = resp.json()
                if data.get("results"):
                    break
                last = f"200 with 0 results, unresponsive: {str(data.get('unresponsive_engines'))[:120]}"
            else:
                last = f"HTTP {status_str(resp)}"
            if time.monotonic() >= deadline:
                metric("tor_recovery", {"tor_healthy_s": round(t_tor, 1), "search_recovered_s": None})
                self.fail(f"no results within 300 s after tor became healthy ({attempts} attempts, last: {last})")
            time.sleep(10)
        t_search = time.monotonic() - t0
        metric("tor_recovery", {"tor_healthy_s": round(t_tor, 1), "search_recovered_s": round(t_search, 1),
                                "attempts": attempts})
        self.note(f"tor healthy after {t_tor:.0f}s, results after {t_search:.0f}s ({attempts} search attempt(s))")


# ---------------------------------------------------------------------------
# Runner, report
# ---------------------------------------------------------------------------

# Execution order: E runs before C/D so its memory numbers are close to idle;
# the non-disruptive guard tests run before the tor outage.
TEST_CLASSES = [GroupDUnit, GroupA, GroupB, GroupE, GroupC, GroupD, GroupAGuard, GroupATorOutage]


def describe(test) -> tuple[str, str, str, bool]:
    method = getattr(test, "_testMethodName", "")
    match = re.match(r"test_([A-Z]\d\d)_(\w+)", method)
    if not match:
        return "-", "-", str(test)[:60], False
    tid = match.group(1)
    return tid, tid[0], match.group(2), bool(getattr(test, "destructive", False))


def exc_message(err, with_type: bool = False) -> str:
    exc_type, exc, tb = err
    msg = str(exc).strip() or exc_type.__name__
    if with_type:
        frames = traceback.extract_tb(tb)
        where = f" at line {frames[-1].lineno}" if frames else ""
        msg = f"{exc_type.__name__}{where}: {msg}"
    return " ".join(msg.split())


class RecordingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records: list[dict] = []
        self._starts: dict[str, float] = {}

    def startTest(self, test):
        self._starts[test.id()] = time.monotonic()
        super().startTest(test)

    def _record(self, test, status: str, message: str) -> None:
        tid, group, name, destructive = describe(test)
        started = self._starts.get(test.id(), time.monotonic())
        doc = (getattr(test, "_testMethodDoc", None) or "").strip().splitlines()
        self.records.append({
            "id": tid,
            "group": group,
            "group_title": GROUP_TITLES.get(group, ""),
            "name": name,
            "property": doc[0].strip() if doc else "",
            "destructive": destructive,
            "status": status,
            "message": message,
            "notes": NOTES.get(test.id(), []),
            "duration_s": round(time.monotonic() - started, 2),
        })

    def addSuccess(self, test):
        super().addSuccess(test)
        self._record(test, "PASS", "; ".join(n for n in NOTES.get(test.id(), []) if n))

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self._record(test, "FAIL", exc_message(err))

    def addError(self, test, err):
        super().addError(test, err)
        self._record(test, "ERROR", exc_message(err, with_type=True))

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self._record(test, "SKIP", reason)

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self._record(test, "PASS", "expected failure")

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self._record(test, "FAIL", "unexpected success")

    def printErrors(self):
        if CFG.verbose:
            super().printErrors()
        elif self.errors:
            self.stream.writeln()
            self.printErrorList("ERROR", self.errors)


def matches(test, patterns: list[str]) -> bool:
    if not patterns:
        return True
    method = getattr(test, "_testMethodName", "")
    full = f"{test.__class__.__name__}.{method}".lower()
    for pattern in patterns:
        pat = pattern.lower()
        if any(ch in pat for ch in "*?[") and fnmatch.fnmatch(full, pat if pat.startswith("*") else "*" + pat):
            return True
        if pat in full:
            return True
    return False


def build_suite(patterns: list[str]) -> unittest.TestSuite:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for cls in TEST_CLASSES:
        for name in loader.getTestCaseNames(cls):
            test = cls(name)
            if matches(test, patterns):
                suite.addTest(test)
    return suite


def one_line(text: str, width: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= width else text[: width - 3] + "..."


def print_table(records: list[dict], stream) -> None:
    order = {"A": 0, "B": 1, "C": 2, "D": 3, "E": 4}
    rows = sorted(records, key=lambda r: (order.get(r["group"], 9), r["id"]))
    width = 110
    print("", file=stream)
    print(f"{'ID':<5} {'GROUP':<24} {'STATUS':<6} {'TIME':>7}  MESSAGE", file=stream)
    print("-" * (5 + 1 + 24 + 1 + 6 + 1 + 7 + 2 + width), file=stream)
    for rec in rows:
        tid = rec["id"] + ("*" if rec["destructive"] else "")
        group = one_line(f"{rec['group']} {rec['group_title']}", 24)
        print(f"{tid:<5} {group:<24} {rec['status']:<6} {rec['duration_s']:>6.1f}s  "
              f"{one_line(rec['message'] or rec['name'], width)}", file=stream)
    counts = {s: sum(1 for r in records if r["status"] == s) for s in ("PASS", "FAIL", "ERROR", "SKIP")}
    print("-" * (5 + 1 + 24 + 1 + 6 + 1 + 7 + 2 + width), file=stream)
    print("  ".join(f"{k} {v}" for k, v in counts.items()) + "   (* = destructive)", file=stream)


def print_metrics(stream) -> None:
    lines = []
    for key in ("idle_rss_mib", "rss_after_tests_mib", "image_size_mb"):
        if key in METRICS:
            lines.append(f"{key}: " + ", ".join(f"{k}={v}" for k, v in METRICS[key].items()))  # type: ignore[union-attr]
    for key in ("exit_ips_distinct", "onion_fetch_s", "tor_recovery", "rate_limit", "timeouts", "startup_to_healthy"):
        if key in METRICS:
            lines.append(f"{key}: {METRICS[key]}")
    if lines:
        print("\nMeasured:", file=stream)
        for line in lines:
            print("  " + line, file=stream)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Edge-case and security tests for the Tor-only SearXNG stack.")
    parser.add_argument("--compose-file", default=DEFAULT_COMPOSE, help="default: %(default)s")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="published frontend URL (default: %(default)s)")
    parser.add_argument("--destructive", action="store_true",
                        help="also run A10-A17 (guard containers, stop/start tor); always restores the stack")
    parser.add_argument("--json", metavar="PATH", help="write a JSON report to PATH")
    parser.add_argument("-k", dest="patterns", action="append", default=[],
                        help="only run tests matching the pattern (substring or glob, repeatable), e.g. -k C0 -k D03")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose unittest output and debug logging")
    parser.add_argument("--list", action="store_true", help="list the tests and exit")
    args = parser.parse_args(argv)

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass

    CFG.compose_file = os.path.abspath(args.compose_file)
    CFG.base_url = args.base_url.rstrip("/")
    split = urllib.parse.urlsplit(CFG.base_url)
    if split.scheme != "http" or not split.hostname:
        parser.error("--base-url must be an http:// URL")
    CFG.host = split.hostname
    CFG.port = split.port or 80
    CFG.destructive = args.destructive
    CFG.verbose = args.verbose

    suite = build_suite(args.patterns)
    if args.list:
        for test in suite:
            tid, group, name, destructive = describe(test)
            doc = (test._testMethodDoc or "").strip().splitlines()  # pylint: disable=protected-access
            print(f"{tid}{'*' if destructive else ' '} {group}  {name:<52} {doc[0].strip() if doc else ''}")
        return 0
    if not suite.countTestCases():
        print("no test matches the given -k pattern(s)", file=sys.stderr)
        return 2

    started = time.time()
    print(f"TorXNG stack tests: {suite.countTestCases()} tests, base URL {CFG.base_url}, "
          f"compose file {CFG.compose_file}, destructive={CFG.destructive}", file=sys.stderr)
    runner = unittest.TextTestRunner(stream=sys.stderr, verbosity=2 if args.verbose else 1,
                                     resultclass=RecordingResult)
    result = runner.run(suite)

    if not STACK.unavailable_reason() and STACK.ps(refresh=True):
        snap = docker_stats_snapshot()
        if snap:
            metric("rss_after_tests_mib", {s: round(v["mem_bytes"] / MIB, 1) for s, v in snap.items() if v["mem_bytes"]})

    records = result.records  # type: ignore[attr-defined]
    print_table(records, sys.stdout)
    print_metrics(sys.stdout)
    if RESTORE_PROBLEMS:
        print("\nSTACK RESTORE PROBLEMS:", file=sys.stdout)
        for problem in RESTORE_PROBLEMS:
            print("  " + problem, file=sys.stdout)

    counts = {s: sum(1 for r in records if r["status"] == s) for s in ("PASS", "FAIL", "ERROR", "SKIP")}
    if args.json:
        report = {
            "suite": "torxng/tests/test_stack.py",
            "started": datetime.datetime.fromtimestamp(started, datetime.timezone.utc).isoformat(),
            "finished": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "duration_s": round(time.time() - started, 1),
            "base_url": CFG.base_url,
            "compose_file": CFG.compose_file,
            "destructive": CFG.destructive,
            "patterns": args.patterns,
            "environment": dict(METRICS.get("environment") or {}, python=sys.version.split()[0],
                                platform=platform.platform()),
            "summary": counts,
            "tests": records,
            "metrics": {k: v for k, v in METRICS.items() if k != "environment"},
            "restore_problems": RESTORE_PROBLEMS,
        }
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        print(f"\nJSON report: {os.path.abspath(args.json)}")
    return 1 if counts["FAIL"] or counts["ERROR"] or RESTORE_PROBLEMS else 0


if __name__ == "__main__":
    sys.exit(main())

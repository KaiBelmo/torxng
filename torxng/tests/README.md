# Edge-case and security test suite (`torxng/tests/`)

`test_stack.py` checks that the running TorXNG stack (`torxng/docker-compose.yml`:
services `tor`, `core`, `frontend`) really has the properties claimed in the hardening
spec: Tor-only and fail-closed, hardened containers, a hardened HTTP edge, correct Tor
behaviour and a small resource footprint. It runs on the host against the live stack,
using only the Python standard library (Windows Python 3.14 and Linux Python 3.10+).

Every test prints one row in a PASS / FAIL / SKIP table; `--json` writes the same rows
plus the measured numbers (idle RSS, image sizes, distinct exit IPs, recovery time after a
tor restart, ...).

## How to run

The stack must be up (`docker compose -f torxng/docker-compose.yml up -d`) for most tests;
tests whose prerequisites are missing are reported as SKIP with the reason, never as errors.

```sh
# from the repository root, default (non-destructive, safe to repeat on a live stack)
python torxng/tests/test_stack.py

# with a JSON report
python torxng/tests/test_stack.py --json torxng/results/tests.json

# everything, including the destructive tests (stops/starts tor, runs guard containers)
python torxng/tests/test_stack.py --destructive --json torxng/results/tests-full.json

# a subset: -k takes a substring or glob of "<Class>.<test method>", repeatable
python torxng/tests/test_stack.py -k C0 -k D03 -v
python torxng/tests/test_stack.py -k "GroupB" -k "test_E*"

# list all tests with the property each one checks
python torxng/tests/test_stack.py --list
```

| Option | Meaning |
|---|---|
| `--compose-file PATH` | compose file of the stack (default `torxng/docker-compose.yml` next to this directory) |
| `--base-url URL` | published frontend (default `http://127.0.0.1:8080`) |
| `--destructive` | also run A10-A19 (see below) |
| `--json PATH` | write the JSON report |
| `-k PATTERN` | run only matching tests (substring or glob, repeatable) |
| `-v` | verbose unittest output, full failure tracebacks, every docker command |
| `--list` | list the tests and exit |

The exit code is 0 when nothing failed, 1 if any test failed or errored or if the stack
could not be restored after a destructive test.

The pure unit tests (D10-D12) need neither Docker nor the stack:
`python torxng/tests/test_stack.py -k D1`.

## What each group proves

Test ids marked `*` are destructive and only run with `--destructive`.

### A - Tor-only / fail-closed

| Id | Security property | How it is tested |
|---|---|---|
| A01 | core has no network path except the internal network | `docker inspect`: every network of core is `Internal: true`, core publishes no port |
| A02 | core has no default route | `/proc/net/route` and `/proc/net/ipv6_route` inside core |
| A03 | no direct egress to IP literals | TCP to 1.1.1.1/9.9.9.9/8.8.8.8/IPv6, UDP DNS queries, plain HTTP, all from core's venv python; every attempt must fail |
| A04 | no direct egress to hostnames | `urllib` without proxy to check.torproject.org, example.com, wikipedia.org from core |
| A05 | no DNS leak through Docker's embedded resolver | public names must not resolve in core; positive control: `tor` resolves |
| A06 | core talks only to the isolated network | snapshot of `/proc/net/{tcp,udp}{,6}`: every peer is loopback or 172.30.0.0/24 |
| A07 | DNS leaks are impossible by construction (`SafeSocks 1`) | raw SOCKS5 and SOCKS4 CONNECT to an IP literal must be refused by Tor; SOCKS5 CONNECT to a hostname (positive control) must succeed (retried) |
| A08 | the deployed settings force Tor | `import searx` inside core: `using_tor_proxy` true and every proxy (global, `outgoing.networks`, engines) is `socks5h://` |
| A10* | the core image refuses to start without Tor | `docker run` of the core image with temporary settings (defaults / `using_tor_proxy: false` / flag without proxies / env `SEARXNG_USING_TOR_PROXY=false` / empty config directory / invalid YAML): exit code 78 and a one-line reason, no traceback |
| A11* | only `socks5h://` is accepted, for every request | same with `socks5://`, `http://`, `socks4://`, a mixed list, a per-scheme `https://` entry, and `https://`-only / `http://`-only patterns without `all://` (uncovered scheme): exit 78 |
| A12* | no bypass through per-network or per-engine settings | non-socks5h proxy in `outgoing.networks`, in an engine's `proxies` and in an engine's `network: {proxies}`; `using_tor_proxy: false` on a network or an engine network: exit 78 |
| A13* | valid settings pass the guard, and SearXNG still fails closed | deployed settings with `--network none`: exit != 0 and != 78, output contains `Invalid network configuration` |
| A18* | no weakened TLS, no ControlPort access from SearXNG | `outgoing.verify: false`, `outgoing.tor_control.host` set in the settings or via env `SEARXNG_TOR_CONTROL_HOST`: exit 78 |
| A19* | proxy environment variables cannot redirect or bypass the SOCKS proxy | `NO_PROXY`, `HTTPS_PROXY`, `all_proxy`, `http_proxy`, `https_proxy`, `no_proxy`, `ALL_PROXY`, `HTTP_PROXY`, `Https_Proxy`, `No_Proxy` (one per run): exit 78 |
| A14* | Tor down -> graceful failure, nothing leaks | tor stopped: search answers without 5xx, returns 0 results and reports unresponsive engines; `/healthz` 200; core not restarted |
| A15* | Tor down -> still no direct egress | A03/A04 probes and the socket snapshot repeated while tor is stopped |
| A16* | core refuses to start while Tor is unreachable | a new core container on the isolated network (tor stopped): exit != 0 with `Invalid network configuration` |
| A17* | recovery after a Tor restart is bounded | `docker compose start tor`: tor healthy within 600 s, searches return results within 300 s after that (both times reported) |

### B - Container hardening

| Id | Security property | How it is tested |
|---|---|---|
| B01 | no process runs as root | every `/proc/<pid>/status` in each container: core euid 977, frontend euid 101, tor non-root |
| B02 | root filesystems are read-only | `ReadonlyRootfs`, `/` mounted `ro`, write probes in system and app directories fail (EROFS is reported), `/tmp` is a writable tmpfs with a `size=` cap |
| B03 | no capabilities, no privilege escalation | PID 1 `CapEff`, `CapPrm`, `CapBnd` = 0 and `NoNewPrivs: 1`; `cap_drop: [ALL]`, no `cap_add`, not privileged, `no-new-privileges` |
| B04 | a low-end PC cannot be exhausted by one container | memory, CPU and PID limits set (`docker inspect`); differences from the spec values are noted |
| B05 | only the frontend is reachable, and only locally | the single published binding is frontend `127.0.0.1:<port>`; no other service publishes anything |
| B06 | our image never runs without Tor | the clearnet baseline is behind a compose profile (not started by default), uses the stock image and binds to 127.0.0.1 |
| B07 | nobody but the operator can use the Tor ControlPort | (a) from core, 172.30.0.2:9051 and tor:9051 are not reachable (SocksPort tor:9050 is the positive control); (b) inside the tor container (busybox `nc`), the ControlPort is bound to 127.0.0.1 only, `PROTOCOLINFO` lists only `HASHEDPASSWORD`, unauthenticated `GETINFO version` -> `514`, wrong password -> `515`, the configured password -> `250` (positive control, the password is read inside tor with `tr -d '\r\n' < /run/secrets/tor_control_password`, the environment variable only as a fallback); (c) core has no `SEARXNG_TOR_CONTROL_PASSWORD` in its environment and its settings have an empty `tor_control.host` and no password |
| B08 | Tor's ports are not exposed to the host | 127.0.0.1:9050/9051, 172.30.0.2:9050/9051 and core 172.30.0.10:8080 are not reachable from the host; tor publishes no port |
| B09 | the onion service key is private | hidden service directory mode 700, `hs_ed25519_secret_key` mode 600, owned by the tor user |
| B10 | restart and bounded logs | `restart: unless-stopped`, json-file logging with `max-size` and `max-file` |
| B11 | the ControlPort password is a secret of tor alone and leaks nowhere | tor's `Config.Env` has no `TOR_CONTROL_PASSWORD`; `/run/secrets/tor_control_password` is mounted in tor with `RW=false` (`docker inspect`) and `ro` (`/proc/mounts`), and exists neither in core nor in frontend; the password (read from the Compose secret's host file, never printed) occurs in no `docker inspect` output of the project's containers, in no `docker exec <svc> env` (and PID 1 environ, best effort) of tor/core/frontend, not in the rendered torrc (only the salted hash) and not on tor's command line; `git check-ignore torxng/secrets/tor_control_password` confirms the host file is ignored |

### C - HTTP edge cases (through `127.0.0.1:8080`, i.e. nginx)

| Id | Security property | How it is tested |
|---|---|---|
| C01 | browser-side hardening headers are always sent, once | CSP, nosniff, Referrer-Policy, X-Frame-Options, Permissions-Policy, COOP, CORP, X-Robots-Tag with the spec values, exactly once, on `/`, `/search`, `/healthz`, a static file, a 404 and a 405 |
| C02 | no version disclosure | one `Server` header without a version, no `X-Powered-By`, no upstream server header, no version in error pages |
| C03 | only GET/HEAD/POST | PUT, DELETE, TRACE, OPTIONS, PATCH -> 405 on `/` and `/search`; PROPFIND/unknown -> 4xx; GET, HEAD (no body), POST work |
| C04 | request body limit | 40 KB body with Content-Length and chunked -> 413; a 16 KB body is accepted |
| C05 | oversized requests never crash anything | 10 000-character query -> 414 or a clean 4xx/200; 10 KB header -> 4xx; many headers / big cookie -> no 5xx |
| C06 | input robustness | umlauts, CJK, emoji, Hebrew/Arabic RTL, bidi override, zero-width, combining marks, whitespace-only, tabs/newlines, empty, long unicode: never 5xx, valid JSON; UTF-8 HTML page |
| C07 | no injection through control characters | `%00` and CRLF in `q`, `language`, `categories`, `pageno`, `time_range` and in paths: no 5xx, no injected response header or cookie |
| C08 | no reflected XSS | script/img/svg/textarea payloads in `q`, `pageno`, `categories`, `language`: never reflected unescaped; JSON answers are `application/json` |
| C09 | no path traversal | 12 variants on `/static` (plain, `%2f`, `%2e`, double encoding, backslash, `....//`, `%00`, above root): 4xx and no `/etc/passwd`, settings or key material in the body |
| C10 | parameter validation never crashes | invalid `pageno` (-1, 0, abc, 100000, 1.5, huge), `time_range`, `language`, `categories`, `safesearch`, `format` (xml, csv, rss, empty), `theme`, unknown engine: never 5xx |
| C11 | endpoints that must work without Valkey | `/client12345678.css` -> 200 `text/css`; `/healthz` -> 200 `OK` |
| C12 | the image proxy is not an open proxy (no SSRF) | `/image_proxy` and `/favicon_proxy` without, with a zero, truncated or default-secret (`ultrasecretkey`) HMAC for the ControlPort, loopback, frontend and `file://` -> 4xx, no internal content |
| C13 | the client IP cannot be spoofed | `X-Forwarded-For`, `X-Real-IP`, `Forwarded` sent by the client do not change the address SearXNG sees (self_info `ip` answer) |
| C14 | slowloris protection | an unfinished request header and an unfinished body are cut off within ~10 s (fails above 20 s) |
| C15 | search rate limit | burst of 30 `/search` and 20 `/autocompleter` requests -> some 429, no 5xx |
| C16 | image proxy rate limit | burst of 150 concurrent `/image_proxy` requests -> some 429, no 5xx (the img zone queues without `nodelay`, so the burst must exceed the queue) |
| C17 | search terms are never written to any log | a unique marker query is sent as real searches (JSON with all engines, HTML via POST, one engine, one with an invalid `pageno`), as rate-limited requests (429) and as a 413 request; the marker must appear in none of the `tor`, `core`, `frontend` container logs |
| C18 | public endpoints leak no Tor internals | `/config` must not contain `socks5h`, `socks5://`, `sxng-` (SOCKS credentials), `9050`, `9051`, `tor_control`, `172.30.0.`; `/`, `/preferences`, `/stats`, `/stats/errors` and a results page must not contain proxy URLs, `sxng-<n>:` credentials, `tor:9050/9051`, `tor_control` or `HashedControlPassword` |

### D - Tor behaviour

| Id | Property | How it is tested |
|---|---|---|
| D01 | engine traffic really leaves through Tor over several circuits, and the guard stays secret | `circuit` query (tor_circuit plugin): per-circuit answers with `Tor: yes`, public exit IPs, no `Tor: no`; the summary `Tor circuits: N, distinct exit IPs: M` matches the circuit answers; no answer contains a relay path (`->`) or names a guard or middle relay (only the phrase `guard and middle hidden` is allowed): guard-discovery protection. Distinct exits are reported (retried; SKIP if the plugin is not deployed) |
| D02 | the Tor exit check cannot be fooled | `tor-check` -> "not applicable" with a private address, also with a spoofed Tor-exit `X-Forwarded-For` |
| D03 | the onion address is a well-formed v3 address for our key | 56 base32 characters -> 35 bytes = pubkey (32) + checksum (2) + version 0x03; `SHA3-256(".onion checksum" \|\| pubkey \|\| 0x03)[:2]` recomputed with `hashlib`; the pubkey equals `hs_ed25519_public_key` and is an ed25519 point of prime order |
| D04 | onion visitors get the same hardened edge | `curl` through Tor (inside the tor container) to `http://<onion>/`: 200 and every C01 header present once (proves `HiddenServicePort 80 -> frontend`) |
| D05 | Tor is configured defensively | torrc: `ClientOnly 1`, `SafeSocks 1`, `AvoidDiskWrites 1`, `SocksPolicy accept 172.30.0.0/24` + `reject *`, `IsolateSOCKSAuth`, `HiddenServiceEnableIntroDoSDefense 1`, `HiddenServiceMaxStreams`, `HiddenServiceMaxStreamsCloseCircuit 1`, `HiddenServicePoWDefensesEnabled 1` exactly when `tor --list-modules` reports `pow: yes`, ControlPort only on 127.0.0.1 and only with `HashedControlPassword` |
| D06 | the circuit probe cannot be used for amplification | two `circuit` queries seconds apart return identical answers (the probe result is cached for 60 s and shared; if the TTL expired between them, a third query must equal the second). Identical answers are a necessary condition only: exits also stay stable for minutes without a cache |
| D10 | (unit) the checksum check accepts valid addresses | addresses built from the ed25519 base point B and from 2B, upper case, without suffix, and DuckDuckGo's published v3 address |
| D11 | (unit) the checksum check rejects corruption | flipped characters (pubkey, checksum and version positions), version 0x04 with a matching checksum, a wrong checksum prefix, 55/57 characters, non-base32, a v2 address |
| D12 | (unit) the ed25519 check matches Tor's `ed25519_validate_pubkey` | accepts B and 2B; rejects the identity, a point of order 2, B + torsion, a non-canonical y >= p and an off-curve point |

### E - Resources (reported; soft thresholds give `WARN` notes)

| Id | What is measured | Threshold |
|---|---|---|
| E01 | idle memory per container (`docker stats`, measured before the C/D traffic) | FAIL at >= 95 % of the container's memory limit, WARN at 80 % |
| E02 | image size per service (`docker image ls`; the compressed content size is reported too) and the stock image for comparison | WARN above tor 64 MB, core 450 MB, frontend 80 MB |
| E03 | seconds from container start to healthy (docker `health_status` events; if they already left docker's event buffer, the readiness log line: tor `Bootstrapped 100%`, granian `Started worker`; the frontend logs nothing with `NGINX_ENTRYPOINT_QUIET_LOGS`, so it is only measured via events) | WARN above tor 300 s, core 120 s, frontend 30 s |
| E04 | the lightweight image trims are applied | FAIL if `.po` files, sourcemaps or `lid.176.ftz` are left, if no `.mo` file remains, or if `GRANIAN_WORKERS=1`, `GRANIAN_BLOCKING_THREADS=2`, `PYTHONDONTWRITEBYTECODE=1` are missing |
| E05 | translations still work after the trim | `Accept-Language: de` gives `lang="de"` and "Einstellungen" |

After all tests the suite also records the memory of each container again
(`rss_after_tests_mib`), so idle and after-load numbers can be compared.

## What destructive mode does

`--destructive` adds two classes; everything else stays read-only.

1. **Guard containers (A10-A13, A18, A19)** never touch the running stack. Each case writes a
   `settings.yml` into a fresh temporary directory and starts
   `docker run --rm --network none` of the image the running core uses, with the same user,
   read-only root, `cap_drop`, `security_opt`, tmpfs mounts and limits as core (volumes are
   replaced by tmpfs, so the stack's data is never used). A case that does not exit within
   120-300 s is removed with `docker rm -f` and reported as FAIL ("guard missing").
2. **Tor outage (A14-A17)** first checks that tor, core and frontend are healthy (otherwise
   all four tests are skipped and nothing is stopped), then runs `docker compose stop tor`.
   A16 starts one extra `docker run --rm` core container on the isolated network (without a
   fixed IP). A17 runs `docker compose start tor` and measures the recovery. Whatever happens,
   `tearDownClass` runs `docker compose start` for any stopped service and waits (up to 15 min)
   until tor, core and frontend are running and healthy; a failed restore is printed as
   `STACK RESTORE PROBLEMS` and makes the exit code 1.

## Expected runtime

| Run | Typical duration |
|---|---|
| unit tests only (`-k D1`) | < 1 s |
| default (non-destructive), stack up | about 2 min with warm Tor circuits; up to about 10 min on a slow Tor network (group C sends about 80 searches limited to one engine; D01/D04 wait for circuits and the onion rendezvous; C14 waits 10-30 s; the rate-limit tests sleep about 20 s) |
| `--destructive` (full run) | measured 182 s in total on the final stack. Guard containers A10-A13, A18, A19 about 35 s (31 refused configurations take about 1 s each; A13 about 9 s, since core's startup Tor check fails fast). Tor outage A14-A17 about 1 min, bounded by the 600 s + 300 s recovery limits and the 15 min restore wait |

### Measured on the final stack (2026-09-26, Docker Desktop on Windows 11)

| Metric | Value |
|---|---|
| full run (`-v --destructive`) | 61 PASS, 0 FAIL, 0 ERROR, 0 SKIP in 182 s |
| recovery after `docker compose start tor` | tor healthy after 12.1 s, search results after 14.1 s (first attempt) |
| core refuses to start without Tor (container exit) | 8.6 s with `--network none` (A13) and 8.6 s on the isolated network with tor stopped (A16); was about 107 s before the fail-fast check |
| idle RSS / limit | tor 53.4 / 128 MiB, core 141.0 / 320 MiB, frontend 2.4 / 32 MiB |
| image size (`docker image ls`) | tor 59 MB, core 368 MB (stock SearXNG 382 MB), frontend 74 MB |
| distinct exit IPs (4 pooled circuits) | 4 |
| onion fetch through Tor (D04) | 4.4 s |
| rate limits (429 responses) | 19 of 30 searches, 9 of 20 `/autocompleter`, 88 of 150 `/image_proxy` |
| slowloris cut-off (header / body) | 10.1 s / 10.1 s |

Tor-dependent assertions (A07, D01, D04, A17) are retried with bounded timeouts, so a slow
Tor network makes the run longer rather than flaky.

## Notes and limitations

- Edge-case searches use `engines=wikipedia` so they do not hit every engine over Tor. The
  parameter parsing under test runs before the engine selection, so this does not weaken the
  tests.
- The suite retries requests that get HTTP 429 (earlier tests drain the per-IP rate-limit
  bucket), except in the rate-limit tests themselves.
- On Docker Desktop (Windows/macOS) container IPs are never reachable from the host. On a
  native Linux Docker host they are; B08 then reports it if tor's SocksPort or core answer
  from the host.
- E03 uses docker's event buffer, which only keeps recent events; on a long-running stack it
  falls back to the log line that marks readiness (tor `Bootstrapped 100%`, granian `Started worker`).
- The onion address is shortened in notes and the report (`abcdef...xyz.onion`).

# TorXNG

TorXNG is a fork of [SearXNG](https://github.com/searxng/searxng) (based on upstream
commit `12f8b6515`, modified since 2026-09-26). This is its documentation: a
lightweight, hardened deployment of the [SearXNG](https://docs.searxng.org/)
metasearch engine that **can only browse through the Tor network**: every outgoing
request leaves through Tor, the instance itself is a **Tor v3 onion service**, and
the whole stack runs within about 200 MB of RAM on a low-end PC. This directory
contains everything needed to build, run, test and evaluate it; the changes to the
SearXNG code base it relies on are listed at the end.

Everything specific to this deployment lives under `torxng/`, so the fork stays
rebaseable on upstream SearXNG. The whole branch is **Tor-only**: its SearXNG code
uses Tor by default and refuses to run without it, `make run` needs a local Tor, and
the upstream container setup (`container/docker-compose.yml`) runs this stack
(section 7). There is no way to run this branch on the clearnet.

```
torxng/
  docker-compose.yml        services tor, core, frontend (+ baseline, profile "baseline")
  Dockerfile                core image: official venv + this repo's searx/, trimmed, Tor-only
  .env.example              SearXNG secret and ports (copy to .env)
  secrets/                  tor_control_password (Compose file secret, git-ignored)
  core/                     Tor-only guard, wrapper entrypoint, build helper
  tor/                      Tor container: Dockerfile, torrc template, entrypoint
  frontend/nginx.conf       reverse proxy: headers, rate limits, request limits
  searxng/                  settings.yml + limiter.toml of the product (Tor profile)
  searxng-baseline/         stock-image clearnet config (benchmark baseline only)
  benchmark/                bench.py, summarize.py, leak_test.py, show_circuits.py, queries.txt
  tests/                    edge-case and security test suite (test_stack.py, see tests/README.md)
  results/                  benchmark and test output (CSV files are git-ignored)

container/docker-compose.yml  includes torxng/docker-compose.yml (same project), see section 7
```

## 1. Goal and threat model

A metasearch engine already hides the user from the search engines: the engines see
the SearXNG server, not the user. That protection ends at the server's own IP
address. Whoever runs a SearXNG instance becomes the single, stable identity behind
all of its users' queries, and the operator's ISP sees which search engines the
server talks to. This project removes the server's IP address from the picture
(outgoing side), hides the visitors' IP addresses from the server (incoming side)
and makes it impossible to run the product without Tor.

### What is hidden, and from whom

| Observer | Sees | Does not see |
|---|---|---|
| **Search engines** (Bing, Google, Startpage, ...) | a Tor exit IP (one of `tor_circuits` exits, changing over time), SearXNG's generated User-Agent and browser-like TLS fingerprint, the query text | the visitor's IP, the SearXNG server's IP, cookies or browser properties of the visitor |
| **ISP / network observer at the server** | encrypted TLS connections from the host to Tor relays, traffic volume and timing, the fact that the host runs Tor | which engines are queried, the queries, the results, the visitors (onion connections arrive through the same Tor connections) |
| **ISP / network observer at the visitor** (Tor Browser) | encrypted connections to a Tor guard (or bridge) | that the visitor uses this search engine, the queries |
| **SearXNG operator** | the query text of every search (it has to, in order to run it) | the IP address of onion visitors (they all appear as `172.30.0.2`, the tor container); nothing is logged by default (no nginx access log, request-level nginx messages suppressed, granian access log off, no Valkey, metrics are anonymous per-engine counters) |
| **Tor exit relay** | destination host name (SOCKS request and TLS SNI), timing and volume of the connection | request and response contents (TLS, certificates are verified), the SearXNG server's IP |
| **Tor guard relay** of the server | the server's IP and that it uses Tor | destinations and contents |

### What is NOT protected

- **Query content.** The query text reaches the search engines verbatim. A query
  that identifies its author (own name, address, a unique phrase) deanonymises it
  regardless of the network path.
- **Traffic correlation.** An adversary who can observe both ends of a circuit (for
  example the server's uplink and the engine's frontend, or a global passive
  adversary) can correlate timing and volume. Tor does not protect against this by
  design.
- **Clicking a result.** Result links point to the original sites. A local visitor
  (127.0.0.1) then connects to that site directly with their own IP; only visitors
  using Tor Browser stay anonymous after the click. (`Referrer-Policy: no-referrer`
  prevents the query from leaking in the Referer header either way.)
- **A malicious or compromised operator.** The operator can change the software to
  log queries. Users have to trust the operator, as with any search service.
- **Availability.** Many engines rate-limit or block Tor exits (section 9). This
  degrades results, not privacy.
- **Host compromise.** Anyone with root on the host can read the onion service's
  private key (`tor-data` volume) and impersonate the service.

## 2. Architecture and data flow

```
 host 127.0.0.1:8080 ---+
                        v
 Tor Browser --(v3 onion rendezvous)--> [tor] --HiddenServicePort 80--+
                                                                      v
                        [frontend nginx 172.30.0.3:8080] --> [core SearXNG 172.30.0.10:8080]
                         egress + isolated, uid 101           isolated ONLY, uid 977
                         headers, rate limits                 (no route to the internet)
                                                                      |
                                                                  socks5h
                                                                      v
                        [tor 172.30.0.2:9050] --> Tor network --> search engines
                         egress + isolated, user tor
                         ControlPort 127.0.0.1:9051 (inside the tor container only)
```

- **`isolated`** is a Docker network with `internal: true` (`172.30.0.0/24`). Docker
  creates no default route and no NAT for it, so `core` physically cannot reach the
  internet; its only way out is the SOCKS port of `tor`.
- **`egress`** is an ordinary bridge network with internet access, used by `tor`
  (to reach the Tor network), `frontend` (to publish its port) and the benchmark
  `baseline`.
- **`frontend`** (nginx, unprivileged image) is the single entry point for both
  access paths: the published port on `127.0.0.1` and the onion service
  (`HiddenServicePort 80 172.30.0.3:8080`). Everybody gets the same security
  headers, request limits and rate limits. nginx **sets** `X-Forwarded-For` to the
  address it sees (never appends client-supplied values) and `core` trusts that
  header only from `172.30.0.3` (`searxng/limiter.toml`), so onion visitors appear
  as `172.30.0.2` and nobody can spoof a client address.
- **`tor`** is the SOCKS proxy for SearXNG and hosts the onion service. Its
  ControlPort listens on 127.0.0.1 inside its own container only; its password is a
  Compose file secret that only the tor container receives (section 4).
- **`baseline`** (compose profile `baseline`) runs the **stock upstream image** with
  the same clearnet engines and plugins and direct internet access. It is a
  measurement tool for the benchmark, not part of the product.

Data flow of one search from Tor Browser:

1. Tor Browser builds a circuit to a rendezvous point and asks one of the service's
   introduction points to connect the service to it (section 5.4).
2. The HTTP request travels over the 6-hop rendezvous circuit, leaves the `tor`
   container towards nginx (`172.30.0.3:8080`) and is proxied to `core`.
3. SearXNG sends one request per selected engine. Each goes to
   `socks5h://sxng-<i>:<salt>@tor:9050` (round robin over `tor_circuits` SOCKS
   credentials); Tor picks the circuit for those credentials and the exit relay
   opens a TLS connection to the engine.
4. Responses come back the same way; SearXNG merges them and answers over the
   rendezvous circuit. Result thumbnails are fetched through SearXNG's image proxy,
   i.e. also through Tor.

## 3. The Tor-only guarantee

"Only supports browsing through Tor" is enforced by four independent layers; each
one alone prevents a clearnet request from `core`:

| Layer | Mechanism | What it stops | Verified by |
|---|---|---|---|
| 1. Image refuses to start | `core/tor_only_guard.py` runs before SearXNG (wrapper `core/entrypoint-tor-only.sh`) and exits with code **78** (EX_CONFIG) and a one-line reason unless `outgoing.using_tor_proxy` is true, `outgoing.proxies` covers http and https with `socks5h://` URLs only, every `outgoing.networks[*]` and engine-level proxy is `socks5h://`, no proxy points to a loopback address (no Tor runs inside `core`; this refuses the built-in default `socks5h://127.0.0.1:9050`), `SEARXNG_TOR_PROXY`, if set, is a `socks5h://` URL, `outgoing.verify` is not false, `outgoing.tor_control.host` is empty and none of `http_proxy`, `https_proxy`, `all_proxy`, `no_proxy` (any case) is set in the environment. There is no switch to disable it. | misconfiguration (clearnet settings, `socks5://` with local DNS, a proxy that cannot be Tor, disabled TLS verification, a `NO_PROXY` that makes libcurl bypass the proxy, ControlPort credentials in SearXNG) | leak test check 7, test suite group A |
| 2. No route around Tor | `core` is attached only to the `internal: true` network: no default route, no upstream DNS | any code path that forgets the proxy (fail-closed: it errors instead of leaking) | leak test checks 1-3, 5 |
| 3. Tor rejects locally resolved destinations | `SafeSocks 1`: SOCKS4 and SOCKS5-with-IP-address requests are refused, only host names (resolved by the exit) are accepted; `SocksPolicy` admits only the isolated network | DNS leaks by construction: a client that resolved a name itself cannot use the proxy at all | leak test check 4c |
| 4. SearXNG itself is Tor-only (whole branch) | the code of this branch defaults to `using_tor_proxy: true` with `socks5h://127.0.0.1:9050` (or `SEARXNG_TOR_PROXY`), refuses to start with an error starting `Tor-only build:` if Tor is switched off or no proxy is configured, accepts only `socks5h://` proxies, does not start while Tor is unreachable ("Invalid network configuration") and lets no request leave before the network is initialised (section 12) | every way of running this branch, also outside this stack: `make run`, the image of `container/dist.dockerfile`, a manual installation | test suite A13/A16, unit tests of the code |

The historical example of why layer 2 matters: the `tracker_url_remover` plugin used
to download its ClearURLs rules before SearXNG's proxy configuration was
initialised. In this stack that request failed (`Could not resolve host`) instead of
leaking the server's IP; the code has since been fixed (section 12).

## 4. Hardening

| Control | Where | Threat it mitigates |
|---|---|---|
| Tor-only guard, internal network, SafeSocks, Tor-only code | section 3 | clearnet egress, DNS leaks |
| `socks5h://` proxies, `verify: true` | `searxng/settings.yml` | DNS leaks; a malicious exit reading/modifying traffic (TLS certificates are verified) |
| `IsolateSOCKSAuth` + `tor_circuits: 4` | torrc, settings | all searches linkable through one exit; one blocked exit disabling an engine |
| `ClientOnly 1` | torrc | the host acting as a relay (traffic, exposure) |
| ControlPort on 127.0.0.1 inside the tor container, `HashedControlPassword`, never enabled without a password; the password is a Compose file secret (`secrets/tor_control_password` -> `/run/secrets/tor_control_password`, read-only bind mount), not an environment variable, so it does not appear in `docker inspect` or `/proc/*/environ`; SearXNG has no ControlPort access (`tor_control.host: ""`, enforced by the guard) | torrc, `tor/entrypoint.sh`, compose, settings | takeover of tor by a compromised web component (the ControlPort can pin guards, add onion services, ...); guard discovery against the onion service (guard/middle relays are never shown on a web page; operator tool `benchmark/show_circuits.py`) |
| `HiddenServiceEnableIntroDoSDefense 1`, `HiddenServiceMaxStreams 32` + `CloseCircuit`, `HiddenServicePoWDefensesEnabled 1` (enabled at runtime because the tor build has the `pow` module) | torrc, `tor/entrypoint.sh` | flooding of the onion service (introduction floods, stream floods, CPU exhaustion) |
| `MaxMemInQueues 64 MB` | torrc | tor using more memory than its 128 MB container limit (OOM kill) |
| `read_only: true` root filesystems, size-capped `tmpfs` for `/tmp` | compose | tampering and persistence after a compromise |
| `cap_drop: [ALL]`, `no-new-privileges:true`, non-root users (tor, 977, 101) | compose, images | privilege escalation, impact of a container escape |
| `mem_limit`, `cpus`, `pids_limit` per service | compose | resource exhaustion of the host (memory, CPU, fork bombs) |
| json-file logs capped at 3 x 1 MB | compose | disk exhaustion |
| published port bound to `127.0.0.1` only | compose | exposure of the clearnet endpoint to the LAN/internet |
| methods limited to GET/HEAD/POST (405), `client_max_body_size 32k`, 8k header/URI limit (414/400), 10 s client timeouts, 15 s keep-alive | `frontend/nginx.conf` | oversized requests, slowloris, unexpected methods |
| rate limits: `/search`, `/autocompleter` 2 r/s burst 10; `/image_proxy`, `/favicon_proxy` 20 r/s burst 60 (HTTP 429) | nginx | scraping and floods, abuse of the Tor exits; a global cap for onion traffic (all onion visitors share one address) that protects a low-end host |
| `X-Forwarded-For $remote_addr` (set, not appended), `trusted_proxies = ['172.30.0.3']` | nginx, `searxng/limiter.toml` | client address spoofing |
| CSP `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; ...; frame-ancestors 'none'; form-action 'self'; base-uri 'none'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `Cross-Origin-Opener-Policy` / `-Resource-Policy: same-origin`, `X-Robots-Tag` (each exactly once, upstream duplicates hidden) | nginx | XSS, clickjacking, referrer leaks, cross-origin leaks, loading of third-party resources, browser feature abuse |
| `server_tokens off`, `Server-Timing` hidden | nginx | software fingerprinting, backend timing side channel |
| no access log; request-level `error_log` at `crit`; `limit_req_log_level info` | nginx | search terms and image URLs in logs (every nginx request-level message contains the request line) |
| `image_proxy`, `method: POST`, `autocomplete: ""`, `query_in_title: false`, all locked in the preferences | settings | the browser contacting image hosts, queries in URLs/history, keystrokes sent to a third party |
| limiter off, no Valkey | settings | persistent state about visitors |
| `max_page: 5`, short engine suspensions (1-5 min) | settings | deep scraping through the exits; one CAPTCHA disabling an engine for days |
| trimmed image, dead files removed | `Dockerfile` | smaller attack surface and download (section 6) |

Checked in practice: the rendered search page, results page, preferences page and an
image search (including the image viewer) contain no inline scripts, inline styles or
event handler attributes, and a real browser loading them through
`http://127.0.0.1:8080` reports **no CSP violations** (`securitypolicyviolation`
events and console); thumbnails load through `/image_proxy`. Embedded video players
(iframes) would be blocked by `default-src 'none'`; the configured engines produce
none.

## 5. Cryptographic background

This section summarises the mechanisms the setup relies on. Normative details are in
the Tor specifications (<https://spec.torproject.org/>), in particular `tor-spec`
(circuits and relay cells) and `rend-spec` (onion services, version 3).

### 5.1 Circuits

A Tor client routes each stream through a **circuit of three relays**: guard,
middle and exit. The circuit is built telescopically: the client performs a key
exchange with the guard, then, through the guard, with the middle relay, then with
the exit. Each relay learns only its predecessor and successor.

- **Handshake.** The per-hop key agreement is the **ntor** handshake (Goldberg,
  Stebila and Ustaoglu), an authenticated Diffie-Hellman exchange over
  **Curve25519**. The client knows the relay's long-term ntor onion key from the
  directory, which authenticates the relay (one-way authentication; the client
  stays anonymous) and gives forward secrecy through the ephemeral keys. Key
  derivation and the authentication tag use **HMAC-SHA256** (HKDF, RFC 5869). The
  specification also defines an ntor-v3 variant that can carry extra negotiated
  parameters; which variant is used depends on the Tor versions involved.
- **Relay cell encryption.** Data travels in fixed-size relay cells. In the classic
  relay cryptography ("tor1") each hop has its own forward and backward keys; the
  client encrypts a cell once per hop (onion layering), and each relay removes one
  layer with **AES-128 in counter mode**. Integrity is checked with a **running
  SHA-1 digest** per hop, of which a truncated value is carried in the cell. In the
  backward direction every relay adds a layer and the client removes all of them.
- **Newer relay crypto.** Tor is replacing tor1 with **Counter Galois Onion
  (CGO)**, Tor proposal 359, which authenticates cells with a wide-block
  construction and is designed to resist tagging attacks. Deployment is gradual and
  version dependent; consult the current Tor specifications before stating which
  relay crypto a given circuit used.
- **Conflux.** Tor 0.4.8+ may build exit traffic as a *conflux set*: two linked
  circuits (legs) with different guards/middles and the same exit, over which the
  client sends cells of one stream by the faster leg. The control port reports
  them with purpose `CONFLUX_LINKED`; `benchmark/show_circuits.py` shows both legs.
- **Link layer.** Relays talk to each other and to clients over TLS. (The `tor`
  0.4.9 build used here logs that its OpenSSL 3.5 offers the hybrid post-quantum
  group X25519MLKEM768 for link TLS; whether it is negotiated depends on the peer.)
  The link TLS is an additional layer; the anonymity properties come from the
  circuit cryptography above.

### 5.2 Stream isolation and `tor_circuits`

Tor multiplexes many streams over one circuit. Streams that should not be linkable
must be put on different circuits, which Tor calls **stream isolation**. The torrc
flag `IsolateSOCKSAuth` (on by default, spelled out in `tor/torrc`) makes Tor put
streams with **different SOCKS username/password pairs on different circuits**. Tor
does not check the credentials; they only serve as isolation labels.

SearXNG's `outgoing.tor_circuits: N` uses this: every plain `socks5h://host:port`
proxy is expanded into N proxy URLs `socks5h://sxng-<i>:<salt>@host:port`
(`i = 0..N-1`, `salt` random per SearXNG process). The network layer takes the next
URL of this list for every request (round robin, per engine), and a retry takes the
next one, so:

- consecutive requests to an engine go out through up to N different exits, which
  spreads the rate-limit budget of the exits and makes a single blocked exit less
  harmful (together with the short suspensions in `settings.yml`);
- a restart of SearXNG gets fresh circuits (new salt).

The SOCKS username is visible to the control port (`SOCKS_USERNAME` of each circuit),
which is how a circuit is matched exactly to its pool entry. Tor retires a circuit
for new streams after `MaxCircuitDirtiness` (10 minutes by default); open keep-alive
connections keep their circuit until they are closed.

### 5.3 `socks5h` and SafeSocks: no DNS leak

With `socks5://` the client resolves the host name itself and hands Tor an IP
address; that DNS lookup would leave the machine outside Tor (a **DNS leak**) and
reveal to the resolver which engines are queried. With **`socks5h://`** ("h" =
hostname, a curl convention) the client sends the host name inside the SOCKS5
request (address type "domain name", RFC 1928); Tor forwards it in the `RELAY_BEGIN`
cell and the **exit relay resolves it**. `SafeSocks 1` turns this convention into a
rule: tor refuses every SOCKS request that carries an IP address (SOCKS5 reply code
2, "not allowed by ruleset"; tor logs "giving Tor only an IP address ...
Rejecting"). In addition, a local lookup would fail anyway (the isolated network
has no upstream DNS), which the leak test shows (checks 4c and 5).

### 5.4 Version 3 onion services

- **Identity.** A v3 onion service is identified by an **ed25519** key pair. The
  address is the public key itself:
  `address = base32(PUBKEY || CHECKSUM || VERSION) + ".onion"` with
  `CHECKSUM = SHA3-256(".onion checksum" || PUBKEY || VERSION)[:2]` and
  `VERSION = 0x03` (56 characters). The address is therefore
  **self-authenticating**: whoever can prove possession of the private key is the
  service; no certificate authority is involved. The key lives in
  `/var/lib/tor/searxng/hs_ed25519_secret_key` (volume `tor-data`, directory mode
  700). The test suite recomputes the checksum of the published address with
  `hashlib.sha3_256`.
- **Blinded keys.** The service does not publish its identity key. For every time
  period (24 h by default) it derives a **blinded public key** from the identity key
  and the period number; descriptors are signed under (a certificate from) the
  blinded key and stored on directory relays (HSDirs) chosen from the blinded key,
  the period and the network's shared random value. HSDirs cannot link descriptors
  of different periods to each other or to the onion address.
- **Encrypted descriptors.** The descriptor body, which lists the introduction
  points and their keys, is encrypted with keys derived from the blinded key and a
  subcredential of the identity key (per `rend-spec`: SHAKE-256 key derivation,
  AES-256-CTR, SHA3-256 MAC). Only clients that already know the onion address can
  decrypt it. (Optional client authorisation adds another layer; not used here.)
- **Introduction and rendezvous.** The service keeps circuits to a few
  **introduction points** (3 by default). A client picks a **rendezvous point**,
  builds a circuit to it and leaves a one-time cookie there, then sends an
  `INTRODUCE` message via an introduction point, encrypted to the service's key for
  that introduction point, containing the rendezvous point and the cookie. The
  service builds its own circuit to the rendezvous point, and the two circuits are
  joined. The end-to-end keys come from the **hs-ntor** handshake carried in these
  messages; the extra onion-service layer uses AES-256 and SHA3-256 instead of
  AES-128 and SHA-1.
- **DoS defenses.** Introduction points can rate-limit INTRODUCE2 cells on behalf
  of the service (`HiddenServiceEnableIntroDoSDefense`), and with the proof-of-work
  defense (proposal 327, `HiddenServicePoWDefensesEnabled`) clients under attack
  must solve an Equi-X puzzle whose effort the service raises when its queue fills
  up, so a flooding attacker pays CPU per introduction.
- **Consequences.** There are six relays between visitor and service (three chosen
  by each side), **no exit relay is involved** and the traffic never leaves the Tor
  network. Both parties' IP addresses stay hidden from each other. Plain HTTP on
  port 80 is appropriate: the connection is already end-to-end encrypted and
  authenticated by the onion address.

### 5.5 TLS to the engines

Tor protects the path between SearXNG and the exit. From the exit to the engine,
confidentiality and integrity come from **TLS**, which SearXNG opens end-to-end
through the Tor stream (the exit only relays bytes). Certificates are verified
(`outgoing.verify: true`, enforced by the guard), so a malicious exit cannot read
or modify the traffic without a trusted certificate. The exit does see the
destination host name. The onion engines (`ahmia`, `torch`) use `http://` to
`.onion` addresses, which is end-to-end encrypted by the onion service protocol
instead.

### 5.6 SearXNG's own privacy layers

- **No visitor data to engines.** SearXNG builds a fresh request per engine; the
  visitor's cookies, IP address and User-Agent are not forwarded. Engines see a
  User-Agent chosen by SearXNG (a generated browser User-Agent for most engines).
- **Browser TLS impersonation.** The HTTP client (curl_cffi) imitates a common
  browser's TLS ClientHello and HTTP/2 settings, so SearXNG's requests blend in with
  browser traffic instead of carrying a distinctive library fingerprint.
- **Image proxy** (locked on): thumbnails are fetched by SearXNG, through Tor, not
  by the visitor's browser (the CSP `img-src 'self'` would block them anyway).
- **`Referrer-Policy: no-referrer`**: clicking a result does not reveal the SearXNG
  URL or the query to the target site.
- **POST method** (locked): the query is not in URLs, browser history or logs.
- **No autocomplete** (locked off): keystrokes are not sent to a third party.
- **No persistent state.** No Valkey, no access logs, `query_in_title: false`.

## 6. Lightweight

The core image is assembled like the official one (runtime base + virtualenv +
package + container files) but from pieces, so that removed files are really absent
(an overlay on top of the official image can only add layers):

- runtime base: `searxng/base:searxng`, pinned by digest to the exact base layer of
  the official image `searxng/searxng:2026.9.25-12f8b6515` (built from the same
  upstream commit as this fork);
- virtualenv from the official image without build-time-only files (lxml C
  headers/Cython sources, type stubs, test suites, activation scripts);
- `searx/` of this repository (`core/overlay_sync.py` makes the official package
  identical to the tree and keeps the precompressed static assets where valid),
  without `searx/data/lid.176.ftz` (dead fastText model), `translations/**/*.po`
  (only the compiled `.mo` files are read) and `static/**/*.map` (source maps);
  recompiled, because the official bytecode uses unchecked-hash `.pyc` files that
  would otherwise shadow the new sources;
- `container/entrypoint.sh` and `container/settings.template.yml` of this
  repository (the Tor-only versions, see section 7).

Runtime tuning: one granian worker (`GRANIAN_WORKERS=1`), two WSGI threads
(`GRANIAN_BLOCKING_THREADS=2`, upstream 4; a search fans out to the engines in its
own threads, so two concurrent requests are enough for a personal instance and bound
CPU/memory; more requests queue), `PYTHONDONTWRITEBYTECODE=1` (read-only root
filesystem, all bytecode precompiled), one nginx worker, a small engine set
(section 9) and `pool_connections: 16`.

Image sizes (2026-09-26, Docker Desktop 29.6.1 / WSL2 on Windows 11; memory, CPU and
startup figures are in section 10):

| metric | value |
|---|---|
| core image, `docker image ls` size | **368 MB** (stock `searxng/searxng:2026.9.25-12f8b6515`: 382 MB; first overlay version of this project: 413 MB) |
| core image, uncompressed layers | 274.6 MB = base 148 + venv 109 + searx 17.5 (stock: 283.9 MB = 148 + 111 + 24.9) |
| core image, compressed content | 93.8 MB (stock: 97.9 MB) |
| tor image / frontend image | 59.2 MB (Alpine 3.22 + tor 0.4.9.13 + curl) / 73.7 MB (nginx-unprivileged 1.27-alpine) |

Remaining size: the runtime base (148 MB uncompressed: Void Linux + Python 3.14) and
the virtualenv (about 109 MB; babel's locale data alone is 34 MB and is needed for
SearXNG's locale handling, granian 21 MB, lxml 12 MB, pygments 10 MB). Shrinking
those would mean rebuilding the base or the virtualenv from scratch, or deleting
locale data that some language setting might need; both were rejected for
robustness.

## 7. Prerequisites and quick start

- Docker Engine with Compose v2 (tested: Docker Desktop 29.6.1 / Compose v5.2 on
  Windows 11 with the Linux engine), outbound connectivity to the Tor network (if
  Tor is blocked, configure bridges in `tor/torrc`).
- Python 3.10 or newer on the host for the benchmark, leak test, operator tool and
  test suite (standard library only).
- Tor Browser to open the onion address.

```sh
cd torxng
cp .env.example .env
# fill in SEARXNG_SECRET, e.g. with: openssl rand -hex 32

# ControlPort password (operator tool only) as a file secret, BEFORE the first "up"
umask 077 && mkdir -p secrets && openssl rand -hex 32 > secrets/tor_control_password
chmod 0644 secrets/tor_control_password    # Linux: readable by the tor user (uid 100) ...
chmod 0700 secrets                         # ... while the directory keeps other host users out

docker compose up -d --build --wait
docker compose exec tor cat /var/lib/tor/searxng/hostname
```

PowerShell (Windows PowerShell 5.1 and PowerShell 7; writes 64 hex characters as
ASCII without BOM or newline, from the `torxng` directory):

```powershell
$b = [byte[]]::new(32); [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
[IO.File]::WriteAllText("$PWD\secrets\tor_control_password", (($b | ForEach-Object { $_.ToString('x2') }) -join ''))
```

Notes on the secret file. Compose (without Swarm) bind-mounts it read-only and
ignores `uid`/`gid`/`mode`; on Docker Desktop for Windows it appears in the container
as root-owned mode 0777 (readable by tor), on Linux it keeps the host permissions
(hence `chmod 0644` on the file and `0700` on the directory). Do not use `>` in
Windows PowerShell 5.1 (it writes UTF-16); `tor/entrypoint.sh` rejects such a file
with a clear message. If the file is missing at `docker compose up`, Docker creates an
empty *directory* with that name on the host and the ControlPort stays disabled (the
tor log says so); delete the directory, create the file and run
`docker compose up -d --force-recreate tor`. The entrypoint uses the environment
variable `TOR_CONTROL_PASSWORD` only as a fallback when the secret file does not
exist (docker-compose.yml does not set it; it would be visible in `docker inspect`)
and logs which source it used.

- Local access: <http://127.0.0.1:8080/> (bound to loopback only).
- Onion access: open `http://<address>.onion/` in Tor Browser.

**From the repository root** the same stack is started by the upstream-style entry
point `container/docker-compose.yml`, which `include`s `torxng/docker-compose.yml`
under the same project name (`torxng`): same containers, volumes and
onion identity, variables from `torxng/.env`. It replaces the upstream file, which
pulled the stock `docker.io/searxng/searxng` image (not this branch, no Tor) and ran
Valkey; Valkey is dropped because the limiter is off and the stack keeps no state
about visitors (the Valkey-less HTTP 500 of `/client<token>.css` is fixed in the
code).

```sh
docker compose -f container/docker-compose.yml up -d --build --wait
```

The generic image of `container/dist.dockerfile` (`make container`) contains the
Tor-only code as well. It sets `SEARXNG_TOR_PROXY=socks5h://tor:9050` (a Tor container
named `tor` on the same network), because inside a container the built-in default
`127.0.0.1:9050` is the container itself. The variable replaces `outgoing.proxies`
of `settings.yml`. Its entrypoint probes that address first and stops with an
explanation if nothing answers (otherwise SearXNG's own startup check would end
with "Invalid network configuration" after 10-20 s). To use another Tor, override
it, e.g. `docker run --network host -e SEARXNG_TOR_PROXY=socks5h://127.0.0.1:9050 ...`.
The TorXNG core image does not set the variable: its proxy is part of the deployed
`settings.yml`, which the guard validates as a whole.

### Without Docker: `make run`

The developer instance (`make run`, i.e. `./manage webapp.run`, port 8888) needs a
Tor SOCKS proxy on the host as well. Before granian starts, `manage` checks that
the proxy of `SEARXNG_TOR_PROXY` (default `socks5h://127.0.0.1:9050`, the port of the
tor daemon) accepts TCP connections (bash `/dev/tcp`, 3 s timeout). If not, it exits
with status 1 and explains how to start Tor; it also rejects a value that is not a
`socks5h://host:port` URL.

```sh
sudo apt install tor && sudo systemctl start tor    # tor daemon on 127.0.0.1:9050
make run

# or through a running Tor Browser (SOCKS port 9150)
SEARXNG_TOR_PROXY=socks5h://127.0.0.1:9150 make run
```

The developer instance uses the default engine set; many of those engines block
Tor exits (section 10, engine selection), so expect more engine errors than with
`searxng/settings.yml`.

Startup order is enforced by health checks: `tor` is healthy once a request through
its SOCKS port reaches `check.torproject.org` with `"IsTor":true`; only then does
`core` start (it refuses to start if Tor is not usable); `frontend` waits for
`core`'s `/healthz`. The onion address stays the same as long as the `tor-data`
volume exists (`docker compose down` keeps it, `down -v` deletes the identity).

Expected log lines: core warns that `/etc/searxng` is not owned by
`searxng:searxng` (the config directory is mounted read-only on purpose,
`FORCE_OWNERSHIP=false`); tor warns that the SocksPort listens on a non-loopback
address (it is the internal network, restricted by `SocksPolicy`).

## 8. Demonstrations

| Query / command | What it shows |
|---|---|
| `circuit` | one answer per pooled circuit (`tor_circuit` plugin, cached 60 s): exit IP, whether check.torproject.org sees a Tor exit (`Tor: yes`), and the number of distinct exits; never guard or middle relays |
| `tor-check` | "not applicable": SearXNG only sees the private address of nginx/tor, the visitor's IP is unknown to it |
| `ip` | the client address SearXNG sees: `172.30.0.2` for onion visitors |
| `!ah privacy`, or the "onions" tab | onion-only search engines, reachable only because all traffic goes through Tor |
| `python benchmark/show_circuits.py` | **operator only**: full paths of the pooled circuits (guard -> middle -> exit with nickname, country, IP), matched to SearXNG's pool by SOCKS username. Runs `docker compose exec -T tor nc 127.0.0.1 9051` and passes the ControlPort password (read on the host from `torxng/secrets/tor_control_password`, the file behind the Compose secret) on stdin, never on a command line. Never publish this output: revealing the guards of the onion service's tor client is the first step of a guard discovery attack. |

`/stats` shows per-engine response times and error rates.

## 9. Evaluation procedure

Run from `torxng/` with the stack up. The benchmark compares the Tor stack with the
clearnet baseline (stock image, same clearnet engines, same resource limits and
granian settings), searching the `general` category.

```sh
docker compose --profile baseline up -d --wait baseline    # 127.0.0.1:8081

# 1. latency / success (20 queries x 3 runs, shuffled per run, 1 s pause)
python benchmark/bench.py --label tor      --repeat 3 --out results/tor.csv
python benchmark/bench.py --base-url http://127.0.0.1:8081 --label baseline --repeat 3 --out results/baseline.csv
python benchmark/summarize.py results/tor.csv results/baseline.csv --markdown results/summary.md

# 2. fail-closed / leak test (checks 1-7)
python benchmark/leak_test.py

# 3. edge-case and security suite (add --destructive for stop/start scenarios),
#    see tests/README.md for the test groups and options
python tests/test_stack.py -v --json results/tests.json

docker compose --profile baseline rm -sf baseline
```

`bench.py` records per request: latency (client wall clock), HTTP status, number of
results, unresponsive engines with their error and transport errors. Keep `--sleep`
at 0.5 s or more: nginx allows 2 searches/s per client. `summarize.py` reports success
rate (HTTP 200 with at least one result), median / p90 / max latency, mean result
count, the share of searches with at least one unresponsive engine and the most
frequently failing engines.

`leak_test.py` asserts: no default route in `core` (1); no direct egress by host name
(2) or IP address, IPv4 and IPv6 (3); the `circuit` answers all say `Tor: yes` (4);
distinct SOCKS credentials exit via Tor, normally with distinct exit IPs (4b); tor
rejects an IP-literal SOCKS request (4c, SafeSocks); the image refuses a clearnet
configuration, the built-in defaults (a Tor on 127.0.0.1, which does not exist in
the container) and a `socks5://` proxy with exit code 78 (7). It reports the DNS behaviour inside `core` (5)
and the onion address (6). As a negative control, the route and egress probes run
against a container on the egress network report a default route and successful
direct connections, i.e. the test does detect a leak.

Methodological notes: run the two profiles at the same time (the campaign in section
10 ran both `bench.py` processes in parallel with the same seed, i.e. the same query
order and pacing, so both see the same engine and network conditions; the two stacks
share no containers and the host had 16 CPUs) and repeat on several days (Tor
performance and exit blocking vary with the chosen circuits); restart `core` between
runs if suspended engines from a previous run should not carry over. Sample
`docker stats` during the run for the resource figures.

## 10. Results

Measurement campaign of 2026-09-26, 07:32-07:34 UTC; host: Windows 11, Docker Desktop
29.6.1 (WSL2, 16 CPUs, 7.6 GiB for the VM), Compose 5.2.0; Tor 0.4.9.13 with
`tor_circuits: 4`; final images of this repository (core rebuilt from the final code
tree). Raw data: `results/tor.csv`, `results/baseline.csv`, `results/docker_stats_*.csv`
(git-ignored); tables: `results/summary.md` (output of `summarize.py`) and
`results/resources.md`.

Method: `bench.py` with all 20 queries of `benchmark/queries.txt` x 3 runs, category
`general`, 1 s pause after every request, seed 42 (the same shuffled query order for
both profiles). The Tor stack (through nginx, `127.0.0.1:8080`) and the clearnet
baseline (stock image, `127.0.0.1:8081`, same clearnet engines, plugins, resource
limits and granian settings, no nginx) ran **in parallel**, so both saw the same
engine and network conditions. Both searched bing, google, startpage and wikipedia
(the `general` engines of the Tor profile). Latency = client wall clock of one HTTP
search request; success = HTTP 200 with at least one result.

### Search latency and success

| profile | searches | success | median | p90 | max | results per search (mean / median) | searches with >= 1 unresponsive engine |
|---|---:|---:|---:|---:|---:|---:|---:|
| Tor stack | 60 | 100 % | **0.80 s** | 1.36 s | 2.46 s | 16.2 / 16 | 71.7 % |
| clearnet baseline | 60 | 100 % | **0.34 s** | 0.49 s | 0.77 s | 18.2 / 19.5 | 100 % |

- Median per run (runs 1 / 2 / 3): Tor 0.89 / 0.78 / 0.66 s, baseline 0.45 / 0.34 /
  0.30 s. The slowest Tor request was the very first one (2.46 s, cold circuits and
  TLS connections); later requests reuse the pooled connections of the circuits.
- **Overhead of Tor**: +0.46 s at the median (2.4 x), +0.87 s at p90 (2.8 x). In
  absolute terms 9 of 10 searches over Tor returned in under 1.4 s, and no search
  failed.

### Engine failures (all 60 searches of each profile)

| engine | Tor stack: unresponsive | baseline: unresponsive |
|---|---:|---:|
| bing | 0 | 0 |
| google | 0 | 0 |
| wikipedia | 0 | 0 |
| startpage | 43 (1 CAPTCHA, 5 "parsing error", 37 suspended after the CAPTCHA) | 60 (CAPTCHA on the first request, then suspended) |

Startpage is the only engine that failed, and it failed *more* on the clearnet: the
baseline has a single public IP (the host's), which Startpage answered with a CAPTCHA
from the first request on, so it stayed suspended for the whole run. Over Tor the 4
rotating circuits (different exits) still got 17 of 60 Startpage answers before and
between CAPTCHAs. Bing and Google answered every request through the exits during this
campaign; that is not a given (in the engine probe below Google answered one of five
rounds with a CAPTCHA). The Tor profile returned about 2 results per search fewer
(16.2 vs 18.2). This was not analysed further; a plausible cause is that the engines
tailor results to the exit's country.

### Resources (`docker stats`, sampled every ~4 s)

Idle = 6 samples before the campaign; under load = 28 samples during it (one search
about every 1.9 s per profile: a realistic personal-use load, not a stress test).
CPU 100 % = one CPU.

| container | memory limit | idle memory | memory under load (median / max) | CPU under load (median / max) | PIDs idle / max (limit) |
|---|---:|---:|---:|---:|---:|
| tor | 128 MiB | 53.4 MiB | 53.7 / 55.2 MiB | 0.6 / 2.9 % (limit 50 %) | 17 / 20 (64) |
| core | 320 MiB | 104.9 MiB | 128.3 / 131.8 MiB | 3.0 / 7.3 % (limit 100 %) | 8 / 17 (256) |
| frontend | 32 MiB | 2.3 MiB | 2.3 / 2.6 MiB | 0.0 / 1.9 % (limit 25 %) | 2 / 2 (32) |
| **Tor stack total** | 480 MiB | **160.6 MiB** | **184.3 / 189.6 MiB** | | |
| baseline (stock image, for comparison) | 320 MiB | 78.5 MiB | 95.5 / 96.5 MiB | 2.3 / 9.8 % | 8 / 16 (256) |

The whole Tor stack stays below 200 MiB and uses a few percent of one CPU, so it fits
on a low-end PC or a small single-board computer. Every container stays far below its
limits (at the maximum: tor 43 %, core 41 %, frontend 8 % of its memory limit). Core
needs about 30 MiB more than the stock image under load; the extra code paths
(`tor_check`, `tor_circuit`, 4 pooled circuits) are the likely reason, this was not
profiled.

### Startup, fail-closed start and recovery

| measurement | result |
|---|---|
| `docker compose down`, then `up -d --wait` until all three services are healthy (tor-data volume kept, 3 runs) | **23.6 / 23.7 / 24.7 s**; tor healthy 11.3-12.4 s after its start, core healthy 5.7 s after its start, then frontend |
| core started without a usable Tor (fail-closed, exit code 1, "Invalid network configuration") | **8.3 s** with `--network none` (test A13, final image); **17.8 s** when the tor address is unreachable on the isolated network (3 s connect timeout per attempt, retries after 2 s and 5 s); about 107 s before the fail-fast change of the startup check |
| recovery after `docker compose start tor` following an outage (test A17) | tor healthy after 12.1 s, first search with results after **13.1 s** (1 attempt) |

### Leak test and test suite

- `leak_test.py` on the final stack: **all 7 asserted checks PASS** (no default route;
  no direct egress by name or by IP, IPv4 and IPv6; 4/4 circuits exit via Tor; 3/3
  SOCKS credentials with 3 distinct exits; SafeSocks rejects an IP literal; the image
  refuses a clearnet config with exit 78).
- `tests/test_stack.py` (see `tests/README.md`): full run including the destructive
  groups (07:14-07:20 UTC, `results/tests-full.json`): **60 PASS, 0 FAIL, 0 SKIP**.
  Rerun of the non-destructive part after the final code and secret changes: 50 PASS,
  0 FAIL, 10 SKIP (the 10 destructive tests), plus test A13 on its own: PASS.

### Interpretation

- **What Tor costs**: about half a second per search at the median and under a
  second at p90 on this connection; about 30 MiB more memory in SearXNG plus about
  55 MiB for tor. The latency comes mainly from the three-hop round trips of the TCP
  and TLS handshakes to the engines, so connection reuse matters: the per-run median
  over Tor dropped from 0.89 s to 0.66 s.
- **Which engines fail over Tor, and why**: engines that block the public list of Tor
  exits outright (DuckDuckGo "access denied", Brave HTTP 429, Qwant CAPTCHA, Mojeek
  timeouts; see the engine selection below) were excluded before the campaign. Of the
  kept engines only Startpage fails regularly, with CAPTCHAs, and it did so on the
  clearnet as well. Circuit rotation and short suspensions reduce per-exit blocking;
  they cannot remove it.
- **Limitations of the measurement**: one host, one day, one 2-minute window, 60
  searches per profile and a light load. Tor latency varies with the chosen circuits
  and exits, and the blocking decisions of the engines change over time. The numbers
  give the order of magnitude, not a general performance model; repeat on several
  days for statistically robust figures.

### Engine selection

An engine that hangs delays every result page up to its timeout (16 s over Tor), so
the engine set was chosen by measurement. Probe (2026-09-26, Tor 0.4.9.13, 4
isolated circuits): a separate SearXNG instance on the isolated network queried
every candidate with its `!bang`, all candidates in parallel within a round (like a
real search), rounds 130 s apart (longer than the suspension times); 5 rounds for
general engines, 3 for image engines. "answered" = at least one result.

| engine | upstream default | answered over Tor | typical failure | median time when answered | decision |
|---|---|---:|---|---:|---|
| bing | disabled | 4/5 | one empty answer | 1.5 s | **kept** (activated) |
| google | disabled | 4/5 | CAPTCHA (fast) | 1.6 s | **kept** (activated) |
| startpage | inactive | 4/5 | CAPTCHA (fast) | 1.7 s | **kept** (activated) |
| wikipedia | active | 4/5 | no article for the query | 1.3 s | **kept** (infobox) |
| mwmbl | disabled | 5/5 | - | 1.5 s | not kept: up to 215 low-relevance results per query, heavy pages |
| wiby | disabled | 5/5 | - | 1.8 s | not kept: small-web index, low relevance for general queries |
| yandex | disabled | 4/5 | timeout (16 s) | 1.7 s | not kept: occasional timeout delays the whole page |
| wikidata | active | 4/5 | - | 1.9 s | not kept: duplicates the wikipedia infobox, extra SPARQL request |
| swisscows | inactive | 2/5 | HTTP 429 | 1.8 s | dropped |
| quark | disabled | 2/5 | engine crash | 3.6 s | dropped |
| brave | active | 0/5 | HTTP 429 | - | dropped |
| duckduckgo | active | 0/5 | access denied | - | dropped |
| qwant | disabled | 0/5 | CAPTCHA | - | dropped |
| mojeek | inactive | 0/5 | timeout (16 s) | - | dropped |
| seznam | disabled | 0/5 | timeout | - | dropped |
| yahoo | disabled | 0/5 | parsing error (consent page) | - | dropped |
| yep, xprivo, tusksearch, privacywall, dogpile | disabled/inactive | 0/5 | access denied | - | dropped |
| metacrawler | inactive | 0/5 | no results | - | dropped |
| bing images | active | 3/3 | - | 0.8 s | **kept** |
| wikicommons.images | active | 3/3 | - | 1.4 s | **kept** |
| google images, openverse | disabled | 3/3 | - | 1.2 s, 2.3 s | not kept: every thumbnail is another Tor request, two image engines suffice |
| duckduckgo images, brave.images | active | 3/3 | - | 2.8 s | not kept: need their (blocked) general engines loaded |
| startpage images | inactive | 0/3 | CAPTCHA | - | dropped |
| quark images | disabled | 0/3 | timeout | - | dropped |
| ahmia (onion) | active | 5/5 | - | 18.4 s | **kept**, timeout 20 s + 10 s |
| torch (onion) | active | 3/5 | timeout | 3.7 s | **kept**, onion tab only |

Rule applied: keep engines that answered through most circuits and fail fast when
they fail (a CAPTCHA or 403 costs a quick error and a 1-5 minute suspension, the
next request goes through another circuit); drop engines that time out, never
answer, or make pages heavy. Result: 3 general web engines + wikipedia, 2 image
engines, 2 onion engines. A first smoke run after the change: median search latency
over Tor 1.3 s (3 queries), versus 3.2 s with the previous set that still contained
duckduckgo and brave. The probe is a snapshot taken about one hour before the
campaign in the previous subsection; exit blocking changes over time, so re-run it
before later campaigns.

`radio_browser` (resolves host names locally) and `zlibrary` (`verify=False`) must
never be added to `keep_only`. With Tor, SearXNG now refuses to load radio_browser
unless it has a static server list, and the internal network (layer 2) would make
its local DNS lookups fail rather than leak.

## 11. Limitations

- **Exit blocking and CAPTCHAs.** Tor exit IPs are public, and several engines
  answer them with CAPTCHAs, HTTP 403 or 429. Rotating over `tor_circuits` circuits
  and short suspensions reduce the impact but cannot remove it.
- **Latency.** Every engine request crosses three relays plus the exit's DNS lookup
  and a TLS handshake; onion engines cross six relays. Timeouts are raised
  accordingly (`extra_proxy_timeout`); measured cost: +0.46 s at the median
  (section 10).
- **Dependency on check.torproject.org.** Container health, SearXNG's startup check
  and the `tor_check` / `tor_circuit` plugins query `check.torproject.org`. If it is
  down, `core` does not start even though Tor itself works (it exits after 8-18 s
  with "Invalid network configuration", fail-closed).
- **Shared rate limits for onion visitors.** All onion visitors share one address,
  so nginx's per-client limits act as a global cap for onion traffic (intended on a
  low-end host, but one heavy onion user can slow down the others).
- **Request-level nginx errors are not logged** (privacy over debuggability).
- **Two WSGI threads.** Many parallel thumbnail requests queue behind a running
  search on the single worker; raise `GRANIAN_BLOCKING_THREADS` on stronger hosts.
- **Trust in the operator**, who sees all queries.
- **Single host.** Onion service, SearXNG and Tor client run on one machine; a host
  compromise breaks all guarantees, including the onion identity key.

## 12. SearXNG code changes made for this project

- **Tor-only build.** `outgoing.using_tor_proxy` defaults to `true` and
  `outgoing.proxies` to `{"all://": "socks5h://127.0.0.1:9050"}` (a local tor
  daemon). The environment variable `SEARXNG_TOR_PROXY=socks5h://host:port` replaces
  `outgoing.proxies` with `{"all://": <url>}`; any other scheme is a startup error.
  With `using_tor_proxy: false` (settings or `SEARXNG_USING_TOR_PROXY=false`) or
  without proxies SearXNG refuses to start with an error starting `Tor-only build:`;
  with Tor unreachable it stops with "Invalid network configuration" (fail-fast
  check below). No request can leave before the network is initialised (a
  fail-closed placeholder is in place until then).
- **Tor applies to every network.** `outgoing.using_tor_proxy: true` covers all
  networks, including per-engine networks, and `outgoing.extra_proxy_timeout` (now a
  float) is added to every engine's timeout when Tor is on (previously only engines
  with an `onion_url`).
- **`outgoing.tor_circuits`** (env `SEARXNG_TOR_CIRCUITS`, an integer from 0 to 32,
  validated at startup): expands each `socks5h://` proxy into N URLs with distinct
  SOCKS credentials, i.e. N isolated circuits used round robin (section 5.2).
- **`outgoing.tor_control`** `{host, port, password}` (env
  `SEARXNG_TOR_CONTROL_HOST`, `_PORT`, `_PASSWORD`): optional ControlPort access for
  the plugin; `host: ""` disables it (the setting of this deployment).
- **New plugin `tor_circuit`** (keyword `circuit`, not in the upstream default
  plugin list, enabled explicitly in `searxng/settings.yml`): probes the exit IP of
  every pooled circuit through `check.torproject.org/api/ip` and, if a ControlPort
  is configured, adds the exit relay and the hop count; circuits are matched exactly
  to the pool entries by the `SOCKS_USERNAME` the control port reports (not by exit
  IP). Exit circuits are recognised with purpose `GENERAL` or, since Tor 0.4.8,
  `CONFLUX_LINKED` / `CONFLUX_UNLINKED` (conflux legs). Guard and middle relays are
  never shown (guard discovery), the answer is cached for 60 s for all users. In this
  deployment (no ControlPort access) it shows exit IPs only.
- **Startup validation under Tor.** With `using_tor_proxy`, SearXNG refuses to start
  unless every network uses only `socks5h://` proxies (no `socks5://`, `http://`, ...,
  which would resolve names locally or bypass Tor) and the proxies cover all schemes
  (`all://`, or both `http://` and `https://`); `radio_browser` refuses to load under
  Tor without a static `servers:` list (its server discovery resolves host names
  locally, outside Tor).
- **Fail-fast startup check.** The startup Tor check (`check.torproject.org` through
  every circuit of the pool) retries a failing check after 2 s and 5 s and stops at
  the first network that fails; a negative result is only cached when it is
  deterministic (a proxy that is not `socks5h://`). Without a usable Tor, core now
  exits with "Invalid network configuration" after 8-18 s instead of about 107 s
  (section 10).
- **Fix: `tor_check`** answers "not applicable" when the client address is private or
  loopback (onion service, reverse proxy) instead of claiming the visitor does not
  use Tor.
- **Fix: `/client<token>.css`** no longer returns HTTP 500 when no Valkey database is
  configured.
- **Fix: network initialised before plugins.** The ClearURLs rules of
  `tracker_url_remover` were downloaded before the proxy configuration existed and
  bypassed it; they now go through Tor, use a Tor-aware timeout
  (`request_timeout` + `extra_proxy_timeout`) and are retried after a failure (e.g.
  circuits not ready yet) instead of being given up until restart.
- **Autocomplete timeout.** Autocomplete requests now really use `request_timeout`
  (plus `extra_proxy_timeout` over Tor); the old helper set the timeout on a copy of
  the arguments, so it never applied.
- **Privacy: no search terms in logs.** Outside debug mode the network layer logs
  engine request URLs only as `scheme://host/...` (`url_for_log`: no path, no query
  string, no credentials), e.g. in the "HTTP Request failed" warning, so search terms
  never reach the logs of a production instance.
- **Defence in depth against `NO_PROXY`.** The HTTP client forces
  `CURLOPT_NOPROXY` to an empty list whenever a proxy is configured, so environment
  variables cannot make libcurl bypass it (the Tor-only guard also refuses such
  variables).

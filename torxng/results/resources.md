# Resources and startup, measurement campaign 2026-09-26

Host: Windows 11, Docker Desktop 29.6.1 (WSL2, 16 CPUs, 7.6 GiB for the VM),
Compose 5.2.0, Tor 0.4.9.13. Raw samples: `docker_stats_idle.csv` (6 samples before
the benchmark, 07:31 UTC) and `docker_stats_load.csv` (28 samples during the
benchmark, 07:32-07:34 UTC, both `bench.py` runs in parallel, one search about every
1.9 s per profile). CPU 100 % = one CPU.

| container | memory limit | idle memory (median) | memory under load (median / max) | CPU under load (median / max) | PIDs idle / max (limit) |
|---|---:|---:|---:|---:|---:|
| tor | 128 MiB | 53.4 MiB | 53.7 / 55.2 MiB | 0.6 / 2.9 % (limit 50 %) | 17 / 20 (64) |
| core | 320 MiB | 104.9 MiB | 128.3 / 131.8 MiB | 3.0 / 7.3 % (limit 100 %) | 8 / 17 (256) |
| frontend | 32 MiB | 2.3 MiB | 2.3 / 2.6 MiB | 0.0 / 1.9 % (limit 25 %) | 2 / 2 (32) |
| Tor stack total | 480 MiB | 160.6 MiB | 184.3 / 189.6 MiB | | |
| baseline (stock image) | 320 MiB | 78.5 MiB | 95.5 / 96.5 MiB | 2.3 / 9.8 % | 8 / 16 (256) |

## Time to healthy

`docker compose down` (volumes kept), then `docker compose up -d --wait`, 07:29-07:30 UTC:

| run | down -> all healthy | tor start -> core start (= tor healthy) | core start -> frontend start (= core healthy) |
|---:|---:|---:|---:|
| 1 | 23.6 s | 11.3 s | 5.7 s |
| 2 | 23.7 s | 11.4 s | 5.7 s |
| 3 | 24.7 s | 12.4 s | 5.7 s |

## Fail-closed start and recovery

| measurement | result |
|---|---|
| core without network (`--network none`, test A13, final image) | exit 1 "Invalid network configuration" after 8.3 s |
| core on the isolated network, tor address unreachable (`--add-host tor:172.30.0.99`) | exit 1 "Invalid network configuration" after 17.8 s |
| before the fail-fast startup check (full test run 07:14 UTC, A13 / A16) | 106.7 s / 107.0 s |
| recovery after `docker compose start tor` (A17, full test run) | tor healthy 12.1 s, search with results 13.1 s |

## Image sizes

| image | `docker image ls` | compressed content |
|---|---:|---:|
| torxng/core | 368 MB | 93.8 MB |
| docker.io/searxng/searxng:2026.9.25-12f8b6515 (stock) | 382 MB | 97.9 MB |
| torxng/tor | 59.2 MB | 13.4 MB |
| docker.io/nginxinc/nginx-unprivileged:1.27-alpine | 73.7 MB | 21.0 MB |

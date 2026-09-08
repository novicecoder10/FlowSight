# IPFIXMon

Real-time network flow monitoring and visualisation. A C++ libpcap sniffer feeds a
TypeScript/Express server over a line-oriented pipe; the server persists to SQLite,
runs its detection engines inline, and streams live events to a no-build browser
dashboard over Server-Sent Events.

```
cpp-sniffer/packet_sniffer  --stdout-->  src/index.ts  --SSE-->  public/*.js
   (libpcap, 256MB ring)       [IPFIX]     (express)   /api/stream
                                              |
                                         SQLite (data/ipfixmon.sqlite)
```

## Requirements

| Dependency | Why | Install |
|---|---|---|
| Node.js >= 22.5 | `node:sqlite` is used for persistence | `nvm install 22` (selected automatically at start) |
| `libpcap-dev`, `libssl-dev` | building the sniffer | `sudo apt install libpcap-dev libssl-dev` |
| `libmaxminddb-bin` | GeoIP lookups (`mmdblookup`) | `sudo apt install libmaxminddb-bin` |

If no suitable runtime can be found, `npm start` says so plainly instead of failing
with `ERR_UNKNOWN_BUILTIN_MODULE: No such built-in module: node:sqlite`, which reads
like a missing package rather than a version problem.

## Quick start

```sh
npm install
npm start
```

`npm start` selects a Node >= 22.5 runtime itself (via `nvm` if the shell's default is
older), so no `nvm use` step is required.

The dashboard binds `127.0.0.1:5900` by default. Override with `PORT` and `HOST`.

### Development without packet capture

```sh
DISABLE_SNIFFER=1 npm start
```

Runs a synthetic traffic generator in place of the sniffer — normal baseline traffic
plus periodic attack bursts, enough to exercise the DDoS, threat-intel, UEBA, incident
and SOAR paths. Needs no root and no capabilities. This is the recommended way to work
on anything that is not the capture path itself.

### Live capture

Build the sniffer with the Makefile (the CMake recipe emits into `build/`, where the
server does not look for it):

```sh
cd cpp-sniffer && make
```

Then grant it raw-socket capability, once per build:

```sh
sudo setcap cap_net_raw,cap_net_admin+eip cpp-sniffer/packet_sniffer
```

**Re-run `setcap` after every rebuild** — a fresh binary does not inherit file
capabilities, and the only symptom is
`Couldn't activate interface any (code -8): socket: Operation not permitted`
with an empty packet history.

Start the dashboard as a normal user, never under `sudo`:

```sh
npm start
SNIFFER_DEVICE=enp6s0 npm start    # capture one interface instead of `any`
```

`scripts/`  holds the runtime selector used by the `build` and `start` scripts.

## Tests

```sh
npm test
```

Covers HTML-escaping of attacker-controlled packet metadata in the browser renderer,
and the packet parser's handling of hostile input (metadata injection, truncated
transport headers, oversized fields, IPv6 port extraction).

## Security notes

IPFIXMon renders data that arrives from the network, so the threat model includes the
traffic it monitors.

- **Bind address.** Defaults to loopback. Exposing the dashboard on `0.0.0.0` publishes
  your full packet-capture history; set `HOST` deliberately.
- **Authentication.** Set `IPFIXMON_TOKEN` to require `Authorization: Bearer <token>`
  (or `?token=`) on every request. Unset means no authentication.
- **Webhooks.** SOAR webhook URLs are operator-supplied and dispatched from this host.
  Private, loopback and link-local destinations are refused unless
  `SOAR_ALLOW_PRIVATE_WEBHOOKS=1` is set.
- **Blocklist export.** `/api/soar/export-blocklist` emits iptables/ipset/Cisco rules.
  IPFIXMon records shunned addresses but never modifies your firewall — applying the
  export is a deliberate operator step.
- **ASN enrichment.** `/api/asn` forwards observed addresses to RIPEstat, a third party.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `5900` | Dashboard HTTP port |
| `HOST` | `127.0.0.1` | Bind address |
| `IPFIXMON_TOKEN` | — | Enables bearer-token auth when set |
| `DISABLE_SNIFFER` | — | `1` swaps capture for the synthetic generator |
| `SNIFFER_BIN` | `cpp-sniffer/packet_sniffer` | Sniffer binary path |
| `SNIFFER_DEVICE` | `any` | Interface to capture |
| `IPFIXMON_DB` | `data/ipfixmon.sqlite` | SQLite database path |
| `GEOIP_MMDB` | `data/dbip-city-lite.mmdb` | MaxMind-format GeoIP database |
| `SOAR_WEBHOOK_TIMEOUT_MS` | `5000` | Webhook dispatch timeout |
| `SOAR_ALLOW_PRIVATE_WEBHOOKS` | — | `1` permits RFC1918/loopback webhook targets |
| `SOAR_DEFAULT_WEBHOOK` | — | Webhook URL for the seeded default rules |
| `MAX_TRACKED_HOSTS` | `20000` | Cap on per-host detector state |
| `MAX_LOOKUP_CACHE` | `10000` | Cap on GeoIP/DNS/ASN caches |
| `DDOS_PPS_THRESHOLD`, `DDOS_BPS_THRESHOLD`, `DDOS_SUSTAINED_SEC` | see `src/index.ts` | DDoS trigger tuning |

The GeoIP database (`data/dbip-city-lite.mmdb`, DB-IP City Lite, CC BY 4.0) is not
committed because of its size. Point `GEOIP_MMDB` at any MaxMind-format database.

## Layout

```
src/index.ts        server, detection engines and REST API
cpp-sniffer/        libpcap capture, L7 metadata extraction
public/             dashboard pages (no build step, no framework)
tests/              regression tests
data/               SQLite database and GeoIP data (gitignored)
```

## License

MIT

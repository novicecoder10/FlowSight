# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-09-09

### Added

- **Flow aggregation with tiered retention.** Packets are kept for a short window
  (`PACKET_RETENTION_HOURS`, default 6) for the live tail and deep forensics, then rolled
  up into hourly-bucketed 5-tuple flow records for long retention. Measured on a 3.3M
  packet capture: 802 MB to 16 MB, 55x fewer rows, byte and packet totals preserved
  exactly. Roll-up is a periodic SQL job in `src/rollup.ts`, so the packet hot path is
  unchanged; it is transactional and idempotent, and never deletes a packet whose bytes
  are not already counted in a flow.
- Hourly bucketing preserves the time dimension that histograms and trend views need.
- Flow metadata keeps the distinct values seen (capped, with the cap marked rather than
  applied silently), so searching history for an SNI still resolves after the packets
  carrying it are gone.
- `/api/flows/stats` reports roll-up health: rows per tier, compression ratio, last run,
  last purge and database size. A stalled roll-up is otherwise indistinguishable from
  quiet traffic.

### Changed

- Forensics search spans both storage tiers via `UNION ALL`, so the packet/flow boundary
  is invisible. Results carry a `tier` marker and the packet count each row represents,
  and field breakdowns are weighted by that count.
- Sankey and traffic-matrix views read aggregated flows instead of grouping over the
  newest 5,000 packets, removing both the cost and the silent cap.

### Fixed

- **Retention is now enforced, not merely recorded.** `auto_purge` deletes expired flows
  using `compliance_settings.retention_days`. The PCI-DSS 10.5 control was reporting PASS
  whenever the configured number was at least 90, regardless of whether anything was ever
  deleted; it now asserts observed behaviour — last purge time, records removed, oldest
  surviving record — and reports FAIL when the policy is configured but not running.

## [1.1.1] - 2026-09-08

### Added

- `scripts/run-node.sh` — `npm start` and `npm run build` select a Node >= 22.5 runtime
  themselves rather than depending on the invoking shell, and report the requirement
  plainly when none is available.

## [1.1.0] - 2026-09-08

Security and correctness release. Several issues below allowed traffic on a monitored
network to affect the monitoring host itself, so upgrading is recommended.

### Security

- **Cross-site scripting via monitored traffic.** Packet metadata reconstructed from
  HTTP headers, TLS SNI and SSH banners was interpolated into `innerHTML` unescaped on
  the main dashboard and the L7, applications and DNS pages. A crafted `User-Agent` or
  SNI executed script in the analyst's browser, with same-origin access to every API
  endpoint. A shared `escapeHtml` helper now lives in `theme.js` and is applied at all
  affected render sites.
- **Record injection through TLS SNI.** SNI bytes were copied verbatim into the
  comma-delimited, newline-terminated IPFIX line the sniffer writes on stdout. A
  ClientHello containing a newline could forge additional packet records with an
  arbitrary source address, poisoning the database and the detection engines. Metadata
  is now reduced to a conservative printable set with separators removed.
- **Server-side request forgery.** SOAR webhook URLs are dispatched from the monitoring
  host. Loopback, RFC1918 and link-local destinations are now refused unless
  `SOAR_ALLOW_PRIVATE_WEBHOOKS=1` is set, and non-HTTP schemes are rejected.
- **Regular-expression denial of service.** Rule patterns supplied over the API were
  compiled per packet and matched on the hot path, so one catastrophically backtracking
  pattern stalled the server. Patterns are now length-limited, screened for nested
  quantifiers, and compiled once.
- **Unauthenticated network exposure.** The dashboard bound `0.0.0.0` with no
  authentication, publishing the full capture history. It now binds `127.0.0.1` by
  default, and `IPFIXMON_TOKEN` enables bearer-token authentication.
- **Remote memory exhaustion.** Per-host detector state and the GeoIP, DNS and ASN
  caches grew without bound, keyed by an address the sender chooses. All are now capped
  (`MAX_TRACKED_HOSTS`, `MAX_LOOKUP_CACHE`).
- **Out-of-bounds read on truncated captures.** The TCP and UDP header reads were
  guarded only up to the start of the transport header, so a capture truncated at the
  end of the IP header read past the buffer. Bounds now cover the full header.
- **Unterminated metadata buffer.** `strncpy` left `PacketRecord::meta` without a
  terminator when metadata reached the field width, and the surrounding struct is
  uninitialised stack. Writes are now always terminated.

### Fixed

- **Forensics search missed almost all history.** The query filtered an inner
  `ORDER BY id DESC LIMIT 10000` subquery, so any packet older than the most recent ten
  thousand rows was unfindable and reported as no match. On a 1.5M-row database a search
  for an address with 85,043 matching packets returned zero. Searches now cover the full
  table, with true match counts and SQL-level pagination.
- **IPv6 flows had no ports or metadata.** The v6 path stopped after the addresses,
  leaving every IPv6 flow with ports `0` and no application metadata, and reported the
  first extension header as the protocol. This made all IPv6 traffic invisible to
  port-based detection. The extension header chain is now walked and transport parsing
  is shared with the IPv4 path.
- **SOAR reported actions it never performed.** The webhook action wrote a fabricated
  `POST 200 OK` string and always recorded `SUCCESS` without issuing a request, and the
  blocklist action recorded a perimeter update that never happened. Webhooks are now
  dispatched for real with the actual HTTP outcome recorded, shunned addresses are
  stored in a `soar_blocklist` table, and the blocklist wording states that IPFIXMon
  does not modify the firewall.
- **Retention policy silently ignored.** `POST /api/compliance/retention` had no body
  parser, so it always stored 90 days and `auto_purge` off while returning the submitted
  values as if applied.
- **Weak address validation.** `999.999.999.999` and other malformed addresses were
  accepted by the GeoIP, DNS and ASN endpoints.
- **GeoIP failed without explanation** when `mmdblookup` was absent. Its availability is
  now checked at startup and reported, with an actionable error from the endpoint.
- **Placeholder Slack webhook.** Default rules were seeded with
  `https://hooks.slack.com/services/demo`. Existing databases are migrated to clear it,
  so upgrading does not begin sending live traffic to an unintended endpoint.

### Changed

- Blocklist export reads the `soar_blocklist` table instead of regex-scraping the text
  of previous execution records.
- SOAR rules are cached with explicit invalidation rather than re-read from SQLite on
  every packet.

### Added

- `npm test` — regression tests for renderer escaping and for the packet parser's
  handling of hostile input.
- Documented Node >= 22.5, `libmaxminddb-bin` and `setcap` requirements.

## [1.0.0]

- Initial release: libpcap capture with L7 metadata extraction, SQLite persistence,
  SSE dashboard, and the threat intelligence, DDoS, VPN, UEBA, SOAR, MITRE ATT&CK,
  compliance, forensics and incident engines.

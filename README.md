# OnionHop Bridges Collector

Automatically collects, validates and archives Tor bridges for the
[OnionHop](https://github.com/center2055/OnionHop) app. A GitHub Action runs
hourly to fetch fresh bridges from the official Tor Project and community
sources, then TCP/TLS-tests them.

_Last updated: 2026-09-05 22:52 UTC_

## Pooled transports

These have large, rotating bridge pools that the Tor Project and community
sources distribute, so they are scraped fresh and connectivity-tested each run.

| Transport | Tested & Active (IPv4) | Fresh 72h (IPv4) | Full Archive (IPv4) | Full Archive (IPv6) |
| :--- | :--- | :--- | :--- | :--- |
| **obfs4** | [obfs4_tested.txt](https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/obfs4_tested.txt) (233) | [obfs4_72h.txt](https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/obfs4_72h.txt) (21) | [obfs4.txt](https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/obfs4.txt) (696) | [obfs4_ipv6.txt](https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/obfs4_ipv6.txt) (342) |
| **webtunnel** | [webtunnel_tested.txt](https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/webtunnel_tested.txt) (156) | [webtunnel_72h.txt](https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/webtunnel_72h.txt) (11) | [webtunnel.txt](https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/webtunnel.txt) (255) | [webtunnel_ipv6.txt](https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/webtunnel_ipv6.txt) (232) |
| **vanilla** | [vanilla_tested.txt](https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/vanilla_tested.txt) (169) | [vanilla_72h.txt](https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/vanilla_72h.txt) (11) | [vanilla.txt](https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/vanilla.txt) (478) | [vanilla_ipv6.txt](https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/vanilla_ipv6.txt) (52) |

IPv6 variants exist for every pooled list (e.g. `obfs4_ipv6_tested.txt`,
`obfs4_ipv6_72h.txt`). Note: IPv6 `*_tested` lists may be empty because CI
runners often lack IPv6 connectivity — prefer IPv4 where possible.

## Fronted transports

Snowflake, meek and conjure have **no rotating pool** — they reach Tor through a
broker and/or domain fronting using a small set of fixed default bridge lines
(the ones shipped with Tor Browser; the listed IP is a placeholder). These lists
are therefore small and essentially static. The `_tested` list contains the
lines whose broker/front host answered on port 443 (there is no `_72h` or
`_ipv6` variant for these).

| Transport | Tested & Active | Default lines |
| :--- | :--- | :--- |
| **snowflake** | [snowflake_tested.txt](https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/snowflake_tested.txt) (2) | [snowflake.txt](https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/snowflake.txt) (2) |
| **meek-azure** | [meek-azure_tested.txt](https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/meek-azure_tested.txt) (0) | [meek-azure.txt](https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/meek-azure.txt) (1) |
| **conjure** | [conjure_tested.txt](https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/conjure_tested.txt) (1) | [conjure.txt](https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/conjure.txt) (1) |

## Consuming these lists

Fetch the raw files directly, e.g.:

```
https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/obfs4_tested.txt
https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/snowflake_tested.txt
```

For censorship resilience, mirror the same paths behind GitHub Pages, a CDN,
and/or a self-hosted domain, and try them in order. OnionHop's in-app
**Bridge Scanner** reads these files and tests them (TCP for pooled transports,
broker/front reachability for fronted ones) so users can pick the bridges that
actually work in their region.

## Sources

- Official Tor BridgeDB: `https://bridges.torproject.org`
- Community seed: [Delta-Kronecker/Tor-Bridges-Collector](https://github.com/Delta-Kronecker/Tor-Bridges-Collector) — this project is **derived from** it (see License)
- Fronted defaults: the snowflake/meek/conjure bridge lines shipped with Tor Browser

## License

Licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)** — see
[`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

This project is a derivative work, adapted from
[Delta-Kronecker/Tor-Bridges-Collector](https://github.com/Delta-Kronecker/Tor-Bridges-Collector)
(also AGPL-3.0); it is released under the same license with the original
author's copyright preserved.

Tor bridge lines (addresses, fingerprints, transport parameters) are public
data published by the Tor network, not original work of this project.

## Disclaimer

For educational and circumvention purposes. Use bridges responsibly and in
accordance with your local laws.

#!/usr/bin/env python3
"""
OnionHop Bridges Collector
==========================

Collects, validates and archives Tor bridges so the OnionHop app (and anyone else)
can fetch working bridges from a stable set of raw URLs.

It covers two kinds of transports:

* **Pooled** (obfs4, webtunnel, vanilla) - large rotating pools scraped + tested each run. For
  each (transport, IP-version) it writes three lists under ``bridge/``:

  - ``<t>.txt`` / ``<t>_ipv6.txt``              - full archive (union over time)
  - ``<t>_72h.txt`` / ``<t>_ipv6_72h.txt``      - bridges first seen in the last 72h
  - ``<t>_tested.txt`` / ``<t>_ipv6_tested.txt``- bridges that passed a TCP/TLS reachability test

* **Fronted** (snowflake, meek-azure, conjure) - no rotating pool exists; these reach Tor through a
  broker / domain fronting using a small set of fixed default lines (placeholder IP). We publish
  those defaults (``<t>.txt`` / ``<t>_72h.txt``) and a ``<t>_tested.txt`` of the lines whose
  broker/front host answered on 443.

Sources (unioned for resilience):
  1. The official Tor BridgeDB HTTPS endpoint (bridges.torproject.org) - pooled transports.
  2. The community Delta-Kronecker/Tor-Bridges-Collector raw lists (seed/enrichment) - pooled.
  3. Built-in Tor Browser default lines - fronted transports.

Standard library + ``requests`` + ``beautifulsoup4`` only. Designed to run hourly in CI.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import ssl
from datetime import datetime, timedelta, timezone

import requests
from bs4 import BeautifulSoup

# --- Configuration ----------------------------------------------------------

BRIDGE_DIR = "bridge"
HISTORY_FILE = os.path.join(BRIDGE_DIR, "bridge_history.json")

RECENT_HOURS = 72
HISTORY_RETENTION_DAYS = 30

# Bound how many bridges we connectivity-test per list so CI stays fast.
MAX_TEST_PER_LIST = 600
MAX_WORKERS = 50
CONNECT_TIMEOUT = 8

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
)

# Pooled transports: BridgeDB and the Delta-Kronecker seed distribute large, rotating pools of
# these, so they are genuinely "collected" (scraped + connectivity-tested) every run.
POOLED_TRANSPORTS = ["obfs4", "webtunnel", "vanilla"]
IP_VARIANTS = [("", False), ("_ipv6", True)]  # (filename suffix, ipv6?)

DELTA_RAW_BASE = "https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/main/bridge"

# Fronted transports have NO rotating pool: BridgeDB does not hand them out and the Delta seed
# carries none. They reach Tor through a broker and/or domain fronting using a small set of fixed
# default bridge lines (the ones shipped with Tor Browser); the listed IP (192.0.2.x, RFC 5737) is a
# placeholder. We publish those defaults and test them by probing the broker/front host on 443.
# Keys are the OnionHop transport/file names; line tokens may differ (e.g. meek-azure -> "meek_lite").
FRONTED_BRIDGES = {
    "snowflake": [
        "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.com,www.phpmyadmin.net ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478 utls-imitate=hellorandomizedalpn",
        "snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.com,www.phpmyadmin.net ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478 utls-imitate=hellorandomizedalpn",
    ],
    "meek-azure": [
        "meek_lite 192.0.2.20:80 97700DFE9F483596DDA6264C4D7DF7641E1E39CE url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com",
    ],
    "conjure": [
        "conjure 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://registration.refraction.network/api fronts=cdn.sstatic.net,assets.cloud.censys.io transport=min",
    ],
}

# Transport tokens (first word of a bridge line) that are fronted / not directly pingable.
FRONTED_TOKENS = {"snowflake", "meek", "meek_lite", "meek-azure", "conjure"}


def log(message: str) -> None:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{stamp}] {message}", flush=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# --- Parsing helpers --------------------------------------------------------

def is_valid_bridge_line(line: str) -> bool:
    if not line or line.startswith("#"):
        return False
    if "No bridges available" in line or len(line) < 10:
        return False
    # Must contain an IPv4, a bracketed IPv6, or an http(s) endpoint (webtunnel).
    return bool(re.search(r"\d+\.\d+\.\d+\.\d+|\[[0-9A-Fa-f:]+\]|https?://", line))


def extract_endpoint(line: str):
    """Return (host, port, transport) or (None, None, transport)."""
    text = line.strip()
    lower = text.lower()
    if "obfs4" in lower:
        transport = "obfs4"
    elif "webtunnel" in lower or "https://" in lower:
        transport = "webtunnel"
    else:
        transport = "vanilla"

    patterns = [
        (r"https?://\[([0-9A-Fa-f:]+)\](?::(\d+))?", True),
        (r"https?://([^/:]+)(?::(\d+))?", True),
        (r"\[([0-9A-Fa-f:]+)\]:(\d+)", False),
        (r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)", False),
    ]
    for pattern, https_default in patterns:
        match = re.search(pattern, text)
        if match:
            host = match.group(1)
            port = match.group(2)
            if port:
                return host, int(port), transport
            return host, 443 if https_default else 443, transport
    return None, None, transport


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def transport_token(line: str) -> str:
    """Return the leading transport token of a bridge line (lowercased), or '' if none."""
    stripped = strip_bridge_prefix(line).strip()
    if not stripped:
        return ""
    return stripped.split(None, 1)[0].lower()


def is_fronted_line(line: str) -> bool:
    return transport_token(line) in FRONTED_TOKENS


def extract_front_host(line: str):
    """Pull the broker/front host from a fronted bridge line: url= host, then fronts=, then front=."""
    match = re.search(r"(?:^|\s)url=(\S+)", line, re.IGNORECASE)
    if match:
        host_match = re.search(r"https?://([^/:\s]+)", match.group(1))
        if host_match:
            return host_match.group(1)
    match = re.search(r"(?:^|\s)fronts=(\S+)", line, re.IGNORECASE)
    if match:
        first = match.group(1).split(",")[0].strip()
        if first:
            return first
    match = re.search(r"(?:^|\s)front=(\S+)", line, re.IGNORECASE)
    if match and match.group(1).strip():
        return match.group(1).strip()
    return None


# --- Connectivity testing ---------------------------------------------------

def test_tcp(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
            return True
    except OSError:
        return False


def test_tls(host: str, port: int) -> bool:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host if not is_ip_literal(host) else None):
                return True
    except (OSError, ssl.SSLError):
        return False


def is_reachable(bridge_line: str) -> bool:
    # Fronted transports (snowflake/meek/conjure) carry a placeholder IP and reach Tor via a broker
    # or domain front; probe that front/broker host on 443 (TLS) instead of the dummy endpoint.
    if is_fronted_line(bridge_line):
        front_host = extract_front_host(bridge_line)
        if not front_host:
            return False
        return test_tls(front_host, 443)

    host, port, transport = extract_endpoint(bridge_line)
    if not host or not port:
        return False
    host_to_test = host
    if not is_ip_literal(host):
        try:
            host_to_test = socket.gethostbyname(host)
        except OSError:
            return False
    if transport == "webtunnel":
        return test_tls(host_to_test, port)
    return test_tcp(host_to_test, port)


def test_many(bridges: list[str]) -> list[str]:
    candidates = bridges[:MAX_TEST_PER_LIST]
    if len(bridges) > MAX_TEST_PER_LIST:
        log(f"  (capped connectivity test at {MAX_TEST_PER_LIST} of {len(bridges)} bridges)")
    if not candidates:
        return []
    working: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(candidates))) as pool:
        futures = {pool.submit(is_reachable, b): b for b in candidates}
        for future in concurrent.futures.as_completed(futures):
            try:
                if future.result():
                    working.append(futures[future])
            except Exception:  # noqa: BLE001 - never let one probe kill the run
                pass
    return working


# --- Fetching ---------------------------------------------------------------

def fetch_bridgedb(session: requests.Session, transport: str, ipv6: bool) -> set[str]:
    url = f"https://bridges.torproject.org/bridges?transport={transport}"
    if ipv6:
        url += "&ipv6=yes"
    out: set[str] = set()
    try:
        resp = session.get(url, timeout=30)
        if resp.status_code != 200:
            log(f"  BridgeDB {transport} ipv6={ipv6}: HTTP {resp.status_code}")
            return out
        soup = BeautifulSoup(resp.text, "html.parser")
        div = soup.find("div", id="bridgelines")
        if not div:
            log(f"  BridgeDB {transport} ipv6={ipv6}: no bridgelines (likely CAPTCHA)")
            return out
        for line in (l.strip() for l in div.get_text().split("\n")):
            if is_valid_bridge_line(line):
                out.add(strip_bridge_prefix(line))
    except requests.RequestException as exc:
        log(f"  BridgeDB {transport} ipv6={ipv6} error: {exc}")
    return out


def fetch_delta(session: requests.Session, transport: str, ipv6: bool) -> set[str]:
    suffix = "_ipv6" if ipv6 else ""
    out: set[str] = set()
    for variant in (f"{transport}{suffix}.txt", f"{transport}{suffix}_72h.txt"):
        url = f"{DELTA_RAW_BASE}/{variant}"
        try:
            resp = session.get(url, timeout=30)
            if resp.status_code != 200:
                continue
            for line in (l.strip() for l in resp.text.split("\n")):
                if is_valid_bridge_line(line):
                    out.add(strip_bridge_prefix(line))
        except requests.RequestException as exc:
            log(f"  Delta seed {variant} error: {exc}")
    return out


def strip_bridge_prefix(line: str) -> str:
    return line[7:].strip() if line.startswith("Bridge ") else line.strip()


# --- Persistence ------------------------------------------------------------

def read_existing(path: str) -> set[str]:
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8") as handle:
        return {strip_bridge_prefix(l.strip()) for l in handle if is_valid_bridge_line(l.strip())}


def write_lines(path: str, lines) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        for line in sorted(lines):
            handle.write(line + "\n")


def load_history() -> dict:
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, ValueError) as exc:
            log(f"History load error: {exc}")
    return {}


def save_history(history: dict) -> None:
    with open(HISTORY_FILE, "w", encoding="utf-8") as handle:
        json.dump(history, handle, indent=0, sort_keys=True)


def cleanup_history(history: dict) -> dict:
    cutoff = datetime.now(timezone.utc) - timedelta(days=HISTORY_RETENTION_DAYS)
    fresh = {}
    for bridge, stamp in history.items():
        try:
            if datetime.fromisoformat(stamp) > cutoff:
                fresh[bridge] = stamp
        except ValueError:
            continue
    return fresh


# --- Main -------------------------------------------------------------------

def main() -> None:
    os.makedirs(BRIDGE_DIR, exist_ok=True)
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    history = cleanup_history(load_history())
    recent_cutoff = datetime.now(timezone.utc) - timedelta(hours=RECENT_HOURS)
    stats: dict[str, int] = {}

    log("Starting OnionHop bridge collection run...")

    for transport in POOLED_TRANSPORTS:
        for suffix, ipv6 in IP_VARIANTS:
            base_name = f"{transport}{suffix}.txt"
            recent_name = f"{transport}{suffix}_72h.txt"
            tested_name = f"{transport}{suffix}_tested.txt"
            base_path = os.path.join(BRIDGE_DIR, base_name)

            existing = read_existing(base_path)
            fetched = fetch_bridgedb(session, transport, ipv6)
            seeded = fetch_delta(session, transport, ipv6)
            archive = existing | fetched | seeded

            # Record first-seen timestamps for freshly discovered bridges.
            for bridge in (fetched | seeded):
                history.setdefault(bridge, now_iso())

            write_lines(base_path, archive)

            recent = []
            for bridge in archive:
                stamp = history.get(bridge)
                if not stamp:
                    continue
                try:
                    if datetime.fromisoformat(stamp) > recent_cutoff:
                        recent.append(bridge)
                except ValueError:
                    continue
            write_lines(os.path.join(BRIDGE_DIR, recent_name), recent)

            tested = test_many(sorted(archive))
            write_lines(os.path.join(BRIDGE_DIR, tested_name), tested)

            stats[base_name] = len(archive)
            stats[recent_name] = len(recent)
            stats[tested_name] = len(tested)
            log(f"{transport} ipv6={ipv6}: archive={len(archive)} fresh72h={len(recent)} tested={len(tested)}")

    # Fronted transports: no pool to scrape, so seed from the fixed default lines and test each by
    # probing its broker/front host. Single (IPv4-named) list per transport; these lines are static.
    for transport, default_lines in FRONTED_BRIDGES.items():
        base_name = f"{transport}.txt"
        recent_name = f"{transport}_72h.txt"
        tested_name = f"{transport}_tested.txt"
        base_path = os.path.join(BRIDGE_DIR, base_name)

        existing = read_existing(base_path)
        seeded = {line.strip() for line in default_lines if is_valid_bridge_line(line)}
        archive = existing | seeded

        for bridge in seeded:
            history.setdefault(bridge, now_iso())

        write_lines(base_path, archive)

        recent = []
        for bridge in archive:
            stamp = history.get(bridge)
            if not stamp:
                continue
            try:
                if datetime.fromisoformat(stamp) > recent_cutoff:
                    recent.append(bridge)
            except ValueError:
                continue
        write_lines(os.path.join(BRIDGE_DIR, recent_name), recent)

        tested = test_many(sorted(archive))
        write_lines(os.path.join(BRIDGE_DIR, tested_name), tested)

        stats[base_name] = len(archive)
        stats[recent_name] = len(recent)
        stats[tested_name] = len(tested)
        log(f"{transport} (fronted): archive={len(archive)} fresh72h={len(recent)} tested={len(tested)}")

    save_history(history)
    update_readme(stats)
    log("Run complete.")


def update_readme(stats: dict) -> None:
    repo = "https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge"
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def count(name: str) -> int:
        return stats.get(name, 0)

    def row(transport: str) -> str:
        return (
            f"| **{transport}** "
            f"| [{transport}_tested.txt]({repo}/{transport}_tested.txt) ({count(transport + '_tested.txt')}) "
            f"| [{transport}_72h.txt]({repo}/{transport}_72h.txt) ({count(transport + '_72h.txt')}) "
            f"| [{transport}.txt]({repo}/{transport}.txt) ({count(transport + '.txt')}) "
            f"| [{transport}_ipv6.txt]({repo}/{transport}_ipv6.txt) ({count(transport + '_ipv6.txt')}) |"
        )

    def fronted_row(transport: str) -> str:
        return (
            f"| **{transport}** "
            f"| [{transport}_tested.txt]({repo}/{transport}_tested.txt) ({count(transport + '_tested.txt')}) "
            f"| [{transport}.txt]({repo}/{transport}.txt) ({count(transport + '.txt')}) |"
        )

    fronted_rows = "\n".join(fronted_row(t) for t in FRONTED_BRIDGES)

    body = f"""# OnionHop Bridges Collector

Automatically collects, validates and archives Tor bridges for the
[OnionHop](https://github.com/center2055/OnionHop) app. A GitHub Action runs
hourly to fetch fresh bridges from the official Tor Project and community
sources, then TCP/TLS-tests them.

_Last updated: {stamp}_

## Pooled transports

These have large, rotating bridge pools that the Tor Project and community
sources distribute, so they are scraped fresh and connectivity-tested each run.

| Transport | Tested & Active (IPv4) | Fresh 72h (IPv4) | Full Archive (IPv4) | Full Archive (IPv6) |
| :--- | :--- | :--- | :--- | :--- |
{row('obfs4')}
{row('webtunnel')}
{row('vanilla')}

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
{fronted_rows}

## Consuming these lists

Fetch the raw files directly, e.g.:

```
{repo}/obfs4_tested.txt
{repo}/snowflake_tested.txt
```

For censorship resilience, mirror the same paths behind GitHub Pages, a CDN,
and/or a self-hosted domain, and try them in order. OnionHop's in-app
**Bridge Scanner** reads these files and tests them (TCP for pooled transports,
broker/front reachability for fronted ones) so users can pick the bridges that
actually work in their region.

## Sources

- Official Tor BridgeDB: `https://bridges.torproject.org`
- Community seed: [Delta-Kronecker/Tor-Bridges-Collector](https://github.com/Delta-Kronecker/Tor-Bridges-Collector)
- Fronted defaults: the snowflake/meek/conjure bridge lines shipped with Tor Browser

## Disclaimer

For educational and circumvention purposes. Use bridges responsibly and in
accordance with your local laws.
"""
    with open("README.md", "w", encoding="utf-8") as handle:
        handle.write(body)


if __name__ == "__main__":
    main()

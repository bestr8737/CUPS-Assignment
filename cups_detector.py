#!/usr/bin/env python3
import argparse
import csv
import json
import logging
import re
import sys
import time
from collections import defaultdict, deque
from urllib.parse import urlparse

from scapy.all import IP, TCP, UDP, Raw, sniff

# --- Configuration -----------------------------------------------------

# Known-good printer IPs for this lab (adjust to your environment).
# Anything advertising a printer that is NOT in this set is flagged as
# an unauthorized advertisement.
ALLOWED_PRINTER_IPS = {"172.18.0.1"}

# Rate-based detection: more than this many advertisements from one
# source within WINDOW_SECONDS triggers a "repeated/abnormal" alert.
RATE_THRESHOLD = 5
WINDOW_SECONDS = 10

# Expected legacy CUPS browse payload: "<flags> <state> <url> "<loc>" "<desc>""
PAYLOAD_PATTERN = re.compile(r'^(\S+)\s+(\S+)\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"')

VALID_FLAGS = {"0", "1", "2", "3", "4"}  # plausible small bitmask values
MAX_FIELD_LEN = 128  # beyond this, a location/description field looks like injection/overflow


# --- Alert handling -----------------------------------------------------

alerts = []
advertisement_history = defaultdict(deque)  # src_ip -> deque[timestamps]


def record_alert(category: str, src_ip: str, dst_ip: str, detail: str):
    alert = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "category": category,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "detail": detail,
    }
    alerts.append(alert)
    logging.warning("[!] %s | %s -> %s | %s", category, src_ip, dst_ip, detail)


# --- Detection checks -----------------------------------------------------

def check_unauthorized_advertisement(src_ip: str, dst_ip: str, payload: str):
    if src_ip not in ALLOWED_PRINTER_IPS:
        record_alert(
            "Unauthorized Advertisement",
            src_ip, dst_ip,
            f"Printer advertisement from non-allowlisted source: {payload.strip()}",
        )


def check_malformed_fields(src_ip: str, dst_ip: str, payload: str):
    match = PAYLOAD_PATTERN.match(payload.strip())
    if not match:
        record_alert(
            "Malformed Protocol Field",
            src_ip, dst_ip,
            f"Payload does not match expected CUPS browse structure: {payload.strip()!r}",
        )
        return

    flags, state, url, location, description = match.groups()

    if flags not in VALID_FLAGS:
        record_alert(
            "Malformed Protocol Field",
            src_ip, dst_ip,
            f"Unexpected type-flags value '{flags}' (expected one of {sorted(VALID_FLAGS)})",
        )

    parsed_url = urlparse(url)
    if parsed_url.scheme not in ("ipp", "ipps", "http", "https") or not parsed_url.netloc:
        record_alert(
            "Malformed Protocol Field",
            src_ip, dst_ip,
            f"Advertised URL is not a well-formed printer URI: {url!r}",
        )

    if len(location) > MAX_FIELD_LEN or len(description) > MAX_FIELD_LEN:
        record_alert(
            "Malformed Protocol Field",
            src_ip, dst_ip,
            f"Location/description field exceeds {MAX_FIELD_LEN} chars (possible overflow/injection attempt)",
        )


def check_repeated_advertisements(src_ip: str, dst_ip: str):
    now = time.time()
    history = advertisement_history[src_ip]
    history.append(now)

    # Drop timestamps outside the sliding window
    while history and now - history[0] > WINDOW_SECONDS:
        history.popleft()

    if len(history) > RATE_THRESHOLD:
        record_alert(
            "Repeated / Abnormal Discovery Rate",
            src_ip, dst_ip,
            f"{len(history)} advertisements from {src_ip} within {WINDOW_SECONDS}s "
            f"(threshold: {RATE_THRESHOLD})",
        )


def check_suspicious_ipp_connection(pkt):
    """Flag TCP SYNs toward IPP-like ports from a source not in the allowlist."""
    if not pkt.haslayer(TCP):
        return
    tcp = pkt[TCP]
    if tcp.flags != "S":  # only initial SYNs
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    dst_port = tcp.dport

    # IPP traffic conventionally uses 631 or high ephemeral ports opened by
    # ippeveprinter/ippserver-style tools; flag SYNs to 631 or to the common
    # 8000-9999 test-printer range from a source that isn't an allowlisted printer.
    ipp_like_port = dst_port == 631 or 8000 <= dst_port <= 9999

    if ipp_like_port and src_ip not in ALLOWED_PRINTER_IPS:
        record_alert(
            "Suspicious IPP Connection",
            src_ip, dst_ip,
            f"TCP SYN to IPP-like port {dst_port} from non-allowlisted source",
        )


# --- Packet dispatch -----------------------------------------------------

def process_packet(pkt):
    if not pkt.haslayer(IP):
        return

    # UDP 631 — legacy CUPS browsing advertisements
    if pkt.haslayer(UDP) and pkt.haslayer(Raw) and (pkt[UDP].sport == 631 or pkt[UDP].dport == 631):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        try:
            payload = pkt[Raw].load.decode("utf-8", errors="ignore")
        except Exception:
            return

        check_unauthorized_advertisement(src_ip, dst_ip, payload)
        check_malformed_fields(src_ip, dst_ip, payload)
        check_repeated_advertisements(src_ip, dst_ip)

    # TCP SYNs — potential IPP connection attempts
    if pkt.haslayer(TCP):
        check_suspicious_ipp_connection(pkt)


# --- Export -----------------------------------------------------

def export_alerts(path: str):
    if not alerts:
        logging.info("No alerts generated; nothing to export.")
        return

    if path.lower().endswith(".json"):
        with open(path, "w") as f:
            json.dump(alerts, f, indent=2)
    else:
        # default to CSV for any other extension
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["timestamp", "category", "src_ip", "dst_ip", "detail"])
            writer.writeheader()
            writer.writerows(alerts)

    logging.info("Exported %d alert(s) to %s", len(alerts), path)


# --- CLI -----------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="CUPS attack detection engine")
    parser.add_argument("-i", "--interface", help="Live interface to monitor (e.g. br-XXXXXXXXXXXX)")
    parser.add_argument("-r", "--pcap", help="Offline PCAP file to analyze")
    parser.add_argument("-o", "--output", help="Export alerts to this file (.csv or .json)")
    parser.add_argument("--timeout", type=int, help="Stop live capture after N seconds")
    parser.add_argument("--allow", action="append", default=[],
                         help="Additional allowlisted printer IP (repeatable)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug-level logging")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    for ip in args.allow:
        ALLOWED_PRINTER_IPS.add(ip)

    if not args.pcap and not args.interface:
        parser.print_help()
        sys.exit(1)

    bpf = "udp port 631 or tcp"

    try:
        if args.pcap:
            logging.info("Analyzing offline capture: %s", args.pcap)
            sniff(offline=args.pcap, filter=bpf, prn=process_packet, store=0)
        else:
            logging.info("Monitoring live interface %s for CUPS exploits...", args.interface)
            sniff(iface=args.interface, filter=bpf, prn=process_packet, store=0, timeout=args.timeout)
    except PermissionError:
        logging.error("Permission denied — live capture requires sudo/root.")
        sys.exit(1)
    except OSError as e:
        logging.error("Capture error (check interface name/PCAP path): %s", e)
        sys.exit(1)

    logging.info("Capture complete. %d alert(s) generated.", len(alerts))
    if args.output:
        export_alerts(args.output)
    elif alerts:
        logging.info("Tip: use -o alerts.json or -o alerts.csv to save these results.")


if __name__ == "__main__":
    main()
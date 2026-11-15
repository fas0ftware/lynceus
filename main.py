"""Network scanner loop: ARP discovery, port checks, alerts."""

import argparse
import os
import sys
import time

from alert import send_notification
from config import (
    DEFAULT_IP_RANGE,
    PORT_RESCAN_INTERVAL,
    SCAN_INTERVAL,
    __version__,
    env,
    normalize_ip_range,
)
from db import count_devices, create_tables, is_trusted, prune_events, save_device, save_ports
from advisor import RISKY_LEVELS, port_info
from portscan import janus_binary, scan_device
from scanner import scan

def can_send_raw_packets():
    """True when this process may open a raw packet socket: root, or a process given only
    CAP_NET_RAW (as in the Docker image). Asking the kernel beats guessing from the uid."""
    import socket
    if not hasattr(socket, "AF_PACKET"):
        return hasattr(os, "geteuid") and os.geteuid() == 0   # not Linux: keep the old rule
    try:
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW).close()
        return True
    except PermissionError:
        return False


# MAC -> time of the last port scan (kept while the program runs)
last_port_scan = {}


def scan_device_ports(device, silent):
    mac = device["mac"]
    # The first port scan of a device in this run is the baseline; alerts start from the second.
    has_baseline = mac in last_port_scan

    open_ports = scan_device(device["ip"])
    new_ports = save_ports(mac, open_ports, ip=device["ip"], log=has_baseline)
    last_port_scan[mac] = time.monotonic()

    if silent or not has_baseline:
        return

    services = {item[0]: item[1] for item in open_ports}
    # A trusted device's ordinary new ports are only logged. Risky ones (high and critical)
    # still push: telnet suddenly open on the trusted NAS is exactly what you want to hear.
    trusted = is_trusted(mac)
    for port in new_ports:
        info = port_info(port, services[port])
        is_risky = info["risk"] in RISKY_LEVELS
        risky = f" (risky: {info['risk']}, {info['name']})" if is_risky else ""
        text = f"{device['ip']} opened port {port}/{services[port]}{risky}"
        if trusted and not is_risky:
            print(f"  new port on a trusted device (no alert): {text}")
            continue
        print(f"  NEW PORT: {text}")
        send_notification("New open port on your network", text)


def run_round(ip_range, silent):
    devices = scan(ip_range)
    for device in devices:
        is_new = save_device(device)
        if is_new:
            print(f"  NEW: {device['ip']:<16} {device['mac']:<19} {device['vendor']}")
            if not silent:
                send_notification(
                    "New device on your network",
                    f"{device['ip']} - {device['vendor']} ({device['mac']})",
                )

        last = last_port_scan.get(device["mac"])
        due = last is None or time.monotonic() - last >= PORT_RESCAN_INTERVAL
        if due:
            scan_device_ports(device, silent)
    prune_events()
    return len(devices)


def build_parser():
    parser = argparse.ArgumentParser(description="Lynceus: home network watch (ARP discovery + port checks).")
    parser.add_argument(
        "-r", "--range",
        default=env("IP_RANGE", DEFAULT_IP_RANGE),
        help=f"subnet to scan (default: {DEFAULT_IP_RANGE}, or LYNCEUS_IP_RANGE)",
    )
    parser.add_argument(
        "-i", "--interval", type=int, default=SCAN_INTERVAL,
        help=f"seconds between scans (default: {SCAN_INTERVAL})",
    )
    parser.add_argument("--once", action="store_true", help="scan one round and exit")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    try:
        ip_range = normalize_ip_range(args.range)
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    if args.interval < 5:
        print("Error: the scan interval must be at least 5 seconds.", file=sys.stderr)
        return 2

    if not can_send_raw_packets():
        print(
            "Error: ARP scanning needs raw packets (root or the CAP_NET_RAW capability).\n"
            "Run it like this:  sudo venv/bin/python main.py   (or use the Docker image)",
            file=sys.stderr,
        )
        return 1

    create_tables()
    first_run = count_devices() == 0

    if first_run:
        print("Empty database: the first round is silent, current devices are stored as known.")
    print(f"Scanning {ip_range} every {args.interval} seconds. Press Ctrl+C to stop.")
    janus = janus_binary()
    print(f"Port checks: {'Janus (' + janus + ') with service detection' if janus else 'built-in connect scan'}")

    try:
        while True:
            print(f"[{time.strftime('%H:%M:%S')}] scanning...")
            try:
                found = run_round(ip_range, silent=first_run)
                print(f"  {found} device(s) answered")
                first_run = False
            except Exception as error:  # a temporary network error must not stop the monitor
                print(f"  Scan failed, retrying next round: {error}")
            if args.once:
                return 0
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

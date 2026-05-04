#!/usr/bin/env python3
"""
SecToolkit - ARP Spoof Detector
Detects ARP poisoning (ARP Spoofing) attacks on the network.
WARNING: Use only on your own network. Requires root/admin privileges.
Requirement: pip install scapy
"""

import sys
import time
import argparse
from datetime import datetime

try:
    from scapy.all import ARP, sniff, conf
except ImportError:
    print("[!] Scapy is not installed. Run: pip install scapy")
    sys.exit(1)

# IP -> MAC mapping table
arp_table = {}
alert_count = 0


def banner():
    print("""
╔═══════════════════════════════════════╗
║     SecToolkit - ARP Spoof Detector   ║
║  Use only on your own network         ║
╚═══════════════════════════════════════╝
    """)


def get_mac(ip):
    """Returns the known MAC address for a given IP."""
    return arp_table.get(ip, None)


def process_packet(packet):
    """Processes each captured ARP packet."""
    global alert_count

    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc

        known_mac = get_mac(src_ip)

        if known_mac is None:
            # First time seeing this IP, add to table
            arp_table[src_ip] = src_mac
            print(f"[+] New host: {src_ip} -> {src_mac}")

        elif known_mac != src_mac:
            # MAC address changed - possible ARP spoofing!
            alert_count += 1
            print(f"\n[!!!] ARP SPOOFING DETECTED!")
            print(f"  Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  IP       : {src_ip}")
            print(f"  Real MAC : {known_mac}")
            print(f"  Fake MAC : {src_mac}")
            print(f"  Alert #  : {alert_count}\n")

        else:
            # MAC matches, all good
            pass


def start_detection(interface, timeout):
    banner()
    print(f"[*] Starting ARP spoof detection...")
    print(f"[*] Interface : {interface or 'default'}")
    print(f"[*] Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if timeout:
        print(f"[*] Timeout   : {timeout} seconds")
    print(f"[*] Listening for ARP packets... (Ctrl+C to stop)\n")
    print("-" * 45)

    try:
        sniff(
            filter="arp",
            prn=process_packet,
            iface=interface,
            timeout=timeout,
            store=False
        )
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"[!] Error: {e}")
        print("[!] Try running as administrator/root.")
        sys.exit(1)

    # Summary
    print("\n" + "-" * 45)
    print(f"[*] Detection stopped.")
    print(f"[*] Hosts discovered : {len(arp_table)}")
    print(f"[*] Alerts triggered : {alert_count}")
    if alert_count > 0:
        print(f"[!!!] WARNING: ARP spoofing was detected on this network!")
    else:
        print(f"[OK] No ARP spoofing detected.")
    print("-" * 45)


def main():
    parser = argparse.ArgumentParser(
        description="SecToolkit ARP Spoof Detector",
        epilog=(
            "Examples:\n"
            "  python arp_detector.py\n"
            "  python arp_detector.py -i eth0\n"
            "  python arp_detector.py -i eth0 --timeout 60"
        )
    )
    parser.add_argument("-i", "--interface", default=None,
                        help="Network interface to listen on (default: auto)")
    parser.add_argument("--timeout", type=int, default=None,
                        help="Stop after N seconds (default: run until Ctrl+C)")

    args = parser.parse_args()
    start_detection(args.interface, args.timeout)


if __name__ == "__main__":
    main()
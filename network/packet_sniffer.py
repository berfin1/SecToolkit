#!/usr/bin/env python3
"""
SecToolkit - Packet Sniffer
Captures and analyzes network traffic.
WARNING: Use only on your own network. Requires root/admin privileges.
Requirement: pip install scapy
"""

import sys
import argparse
from collections import Counter
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:
    print("[!] Scapy is not installed. Run: pip install scapy")
    sys.exit(1)

# Statistics
stats = {
    'total': 0,
    'protocols': Counter(),
    'src_ips': Counter(),
    'dst_ips': Counter(),
    'http_requests': [],
    'dns_queries': [],
    'credentials': [],
}


def banner():
    print("""
╔═══════════════════════════════════════╗
║      SecToolkit - Packet Sniffer      ║
║  Use only on your own network         ║
╚═══════════════════════════════════════╝
    """)


def process_packet(packet, verbose):
    """Processes each captured packet."""
    stats['total'] += 1

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        stats['src_ips'][src] += 1
        stats['dst_ips'][dst] += 1

        # TCP
        if TCP in packet:
            stats['protocols']['TCP'] += 1
            sport = packet[TCP].sport
            dport = packet[TCP].dport

            # HTTP Request
            if HTTPRequest in packet:
                stats['protocols']['HTTP'] += 1
                method = packet[HTTPRequest].Method.decode(errors='replace') if packet[HTTPRequest].Method else '?'
                host = packet[HTTPRequest].Host.decode(errors='replace') if packet[HTTPRequest].Host else '?'
                path = packet[HTTPRequest].Path.decode(errors='replace') if packet[HTTPRequest].Path else '?'
                stats['http_requests'].append(f"{method} {host}{path}")
                if verbose:
                    print(f"[HTTP] {src} -> {dst} | {method} {host}{path}")

                # Check for credentials in raw data
                if Raw in packet:
                    raw = packet[Raw].load.decode(errors='replace').lower()
                    if any(kw in raw for kw in ['password', 'passwd', 'username', 'user=', 'pass=']):
                        stats['credentials'].append({
                            'src': src, 'dst': dst,
                            'data': raw[:200]
                        })
                        print(f"\n[!!!] POSSIBLE CREDENTIALS DETECTED!")
                        print(f"  From : {src}:{sport}")
                        print(f"  To   : {dst}:{dport}")
                        print(f"  Data : {raw[:200]}\n")

            else:
                if verbose and (sport in [80, 443, 8080] or dport in [80, 443, 8080]):
                    print(f"[TCP] {src}:{sport} -> {dst}:{dport}")

        # UDP
        elif UDP in packet:
            stats['protocols']['UDP'] += 1

            # DNS
            if DNS in packet and packet[DNS].qr == 0:
                try:
                    query = packet[DNS].qd.qname.decode(errors='replace').rstrip('.')
                    stats['dns_queries'].append(query)
                    stats['protocols']['DNS'] += 1
                    if verbose:
                        print(f"[DNS] {src} -> Query: {query}")
                except Exception:
                    pass

        # ICMP
        elif ICMP in packet:
            stats['protocols']['ICMP'] += 1
            if verbose:
                print(f"[ICMP] {src} -> {dst}")

    # Print packet count every 50 packets
    if stats['total'] % 50 == 0:
        print(f"[*] Captured {stats['total']} packets so far...")


def print_summary():
    """Prints a summary of captured traffic."""
    print(f"\n{'='*50}")
    print(f"  CAPTURE SUMMARY")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*50}")

    print(f"\n[*] GENERAL")
    print(f"  Total packets   : {stats['total']}")

    print(f"\n[*] PROTOCOL BREAKDOWN")
    for proto, count in stats['protocols'].most_common():
        pct = count / stats['total'] * 100 if stats['total'] > 0 else 0
        bar = '#' * int(pct / 2)
        print(f"  {proto:<10}: {count:>5} packets  {bar} {pct:.1f}%")

    print(f"\n[*] TOP 5 SOURCE IPs")
    for ip, count in stats['src_ips'].most_common(5):
        print(f"  {ip:<20}: {count} packets")

    print(f"\n[*] TOP 5 DESTINATION IPs")
    for ip, count in stats['dst_ips'].most_common(5):
        print(f"  {ip:<20}: {count} packets")

    if stats['dns_queries']:
        print(f"\n[*] DNS QUERIES ({len(stats['dns_queries'])} total)")
        dns_counter = Counter(stats['dns_queries'])
        for domain, count in dns_counter.most_common(10):
            print(f"  {domain:<40}: {count}x")

    if stats['http_requests']:
        print(f"\n[*] HTTP REQUESTS ({len(stats['http_requests'])} total)")
        for req in stats['http_requests'][:10]:
            print(f"  {req[:70]}")

    if stats['credentials']:
        print(f"\n[!!!] POSSIBLE CREDENTIALS FOUND ({len(stats['credentials'])} times)")
        for c in stats['credentials']:
            print(f"  {c['src']} -> {c['dst']}")
    else:
        print(f"\n[OK] No credentials detected in traffic.")

    print(f"\n{'='*50}\n")


def main():
    parser = argparse.ArgumentParser(
        description="SecToolkit Packet Sniffer",
        epilog=(
            "Examples:\n"
            "  python packet_sniffer.py\n"
            "  python packet_sniffer.py -i eth0 -c 100\n"
            "  python packet_sniffer.py -i eth0 --verbose\n"
            "  python packet_sniffer.py --filter tcp"
        )
    )
    parser.add_argument("-i", "--interface", default=None,
                        help="Network interface (default: auto)")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Number of packets to capture (default: unlimited)")
    parser.add_argument("-f", "--filter", default="ip",
                        help="BPF filter (default: ip). Example: tcp, udp, arp")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show each packet in real time")

    args = parser.parse_args()

    banner()
    print(f"[*] Interface : {args.interface or 'default'}")
    print(f"[*] Filter    : {args.filter}")
    print(f"[*] Count     : {args.count or 'unlimited'}")
    print(f"[*] Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Capturing packets... (Ctrl+C to stop)\n")
    print("-" * 45)

    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=lambda pkt: process_packet(pkt, args.verbose),
            count=args.count,
            store=False
        )
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"[!] Error: {e}")
        print("[!] Try running as administrator/root.")
        sys.exit(1)

    print_summary()


if __name__ == "__main__":
    main()
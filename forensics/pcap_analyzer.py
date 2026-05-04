#!/usr/bin/env python3
"""
SecToolkit - PCAP Analyzer
Analyzes network capture files (.pcap / .pcapng).
WARNING: Use only on systems you are authorized to access.
Requirement: pip install scapy
"""

import sys
import os
import argparse
from collections import defaultdict, Counter
from datetime import datetime

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:
    print("[!] Scapy is not installed. Run: pip install scapy")
    sys.exit(1)


def banner():
    print("""
╔══════════════════════════════════════════╗
║       SecToolkit - PCAP Analyzer         ║
║   Analyzes network capture files         ║
╚══════════════════════════════════════════╝
    """)


def load_pcap(filepath):
    """Loads a PCAP file and returns packets."""
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        sys.exit(1)
    print(f"[*] Loading: {filepath}")
    try:
        packets = rdpcap(filepath)
        print(f"[OK] {len(packets)} packets loaded.\n")
        return packets
    except Exception as e:
        print(f"[!] PCAP read error: {e}")
        sys.exit(1)


def analyze_packets(packets):
    """Analyzes packets and returns statistics."""
    stats = {
        'total': len(packets),
        'protocols': Counter(),
        'src_ips': Counter(),
        'dst_ips': Counter(),
        'src_ports': Counter(),
        'dst_ports': Counter(),
        'conversations': Counter(),
        'dns_queries': [],
        'http_requests': [],
        'suspicious': [],
        'icmp_count': 0,
        'total_bytes': 0,
        'timestamps': [],
    }

    # Known suspicious ports
    suspicious_ports = {
        4444: "Metasploit default",
        1337: "Common hacker port",
        31337: "Back Orifice",
        9001: "Tor/Attack",
        6667: "IRC (botnet)",
        6666: "IRC (botnet)",
        23:   "Telnet (unencrypted)",
        21:   "FTP (unencrypted)",
    }

    for pkt in packets:
        stats['total_bytes'] += len(pkt)

        if pkt.time:
            stats['timestamps'].append(float(pkt.time))

        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            stats['src_ips'][src] += 1
            stats['dst_ips'][dst] += 1
            stats['conversations'][(src, dst)] += 1

            if TCP in pkt:
                stats['protocols']['TCP'] += 1
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                stats['src_ports'][sport] += 1
                stats['dst_ports'][dport] += 1

                # Check for suspicious ports
                for port in [sport, dport]:
                    if port in suspicious_ports:
                        stats['suspicious'].append({
                            'type': 'Suspicious Port',
                            'src': src,
                            'dst': dst,
                            'port': port,
                            'reason': suspicious_ports[port]
                        })

                # Detect HTTP requests
                if HTTPRequest in pkt:
                    stats['protocols']['HTTP'] += 1
                    method = pkt[HTTPRequest].Method.decode(errors='replace') if pkt[HTTPRequest].Method else '?'
                    host = pkt[HTTPRequest].Host.decode(errors='replace') if pkt[HTTPRequest].Host else '?'
                    path = pkt[HTTPRequest].Path.decode(errors='replace') if pkt[HTTPRequest].Path else '?'
                    stats['http_requests'].append({
                        'src': src, 'dst': dst,
                        'method': method, 'host': host, 'path': path
                    })

            elif UDP in pkt:
                stats['protocols']['UDP'] += 1
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                stats['src_ports'][sport] += 1
                stats['dst_ports'][dport] += 1

                # Detect DNS queries
                if DNS in pkt and pkt[DNS].qr == 0:
                    try:
                        query = pkt[DNS].qd.qname.decode(errors='replace').rstrip('.')
                        stats['dns_queries'].append({'src': src, 'query': query})
                        stats['protocols']['DNS'] += 1
                    except Exception:
                        pass

            elif ICMP in pkt:
                stats['protocols']['ICMP'] += 1
                stats['icmp_count'] += 1

            else:
                stats['protocols'][f"Proto-{pkt[IP].proto}"] += 1

        else:
            stats['protocols']['Non-IP'] += 1

    # Detect possible ICMP flood
    if stats['icmp_count'] > 100:
        stats['suspicious'].append({
            'type': 'ICMP Flood (possible)',
            'src': 'Multiple',
            'dst': '-',
            'port': '-',
            'reason': f"{stats['icmp_count']} ICMP packets detected"
        })

    return stats


def print_report(stats):
    """Prints the analysis report."""
    print(f"\n{'='*55}")
    print(f"  PCAP ANALYSIS REPORT  --  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*55}")

    # General stats
    duration = ""
    if len(stats['timestamps']) >= 2:
        secs = stats['timestamps'][-1] - stats['timestamps'][0]
        duration = f"  Duration          : {secs:.2f} seconds"

    print(f"\n[*] GENERAL")
    print(f"  Total packets     : {stats['total']:,}")
    print(f"  Total data        : {stats['total_bytes']:,} bytes ({stats['total_bytes']//1024} KB)")
    if duration:
        print(duration)

    # Protocol breakdown
    print(f"\n[*] PROTOCOL BREAKDOWN")
    for proto, count in stats['protocols'].most_common():
        pct = count / stats['total'] * 100
        bar = '#' * int(pct / 2)
        print(f"  {proto:<12}: {count:>6,} packets  {bar} {pct:.1f}%")

    # Top source IPs
    print(f"\n[*] TOP 5 SOURCE IPs")
    for ip, count in stats['src_ips'].most_common(5):
        print(f"  {ip:<20}: {count:>6,} packets")

    # Top destination IPs
    print(f"\n[*] TOP 5 DESTINATION IPs")
    for ip, count in stats['dst_ips'].most_common(5):
        print(f"  {ip:<20}: {count:>6,} packets")

    # Top destination ports
    print(f"\n[*] TOP 10 DESTINATION PORTS")
    for port, count in stats['dst_ports'].most_common(10):
        print(f"  Port {port:<8}: {count:>6,} connections")

    # DNS queries
    if stats['dns_queries']:
        print(f"\n[*] DNS QUERIES (Top 10)")
        dns_counter = Counter(q['query'] for q in stats['dns_queries'])
        for domain, count in dns_counter.most_common(10):
            print(f"  {domain:<40}: {count:>4}x")

    # HTTP requests
    if stats['http_requests']:
        print(f"\n[*] HTTP REQUESTS (Top 10)")
        for req in stats['http_requests'][:10]:
            print(f"  {req['method']:<6} {req['host']}{req['path'][:50]}")

    # Suspicious activity
    if stats['suspicious']:
        print(f"\n[!!!] SUSPICIOUS ACTIVITY ({len(stats['suspicious'])} alerts)")
        seen = set()
        for s in stats['suspicious']:
            key = (s['type'], s.get('port', ''))
            if key not in seen:
                print(f"  [{s['type']}] {s['src']} -> {s['dst']}  |  {s['reason']}")
                seen.add(key)
    else:
        print(f"\n[OK] No suspicious activity detected.")

    print(f"\n{'='*55}\n")


def main():
    parser = argparse.ArgumentParser(
        description="SecToolkit PCAP Analyzer",
        epilog=(
            "Examples:\n"
            "  python pcap_analyzer.py -f capture.pcap\n"
            "  python pcap_analyzer.py -f traffic.pcapng"
        )
    )
    parser.add_argument("-f", "--file", required=True, help="PCAP or PCAPNG file to analyze")

    args = parser.parse_args()

    banner()
    packets = load_pcap(args.file)
    stats = analyze_packets(packets)
    print_report(stats)


if __name__ == "__main__":
    main()
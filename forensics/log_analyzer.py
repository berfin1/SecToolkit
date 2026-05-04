#!/usr/bin/env python3
"""
SecToolkit - Log Analyzer
Detects suspicious IPs, brute-force attacks, and anomalies in log files.
WARNING: Use only on systems you are authorized to access.
"""

import re
import argparse
import sys
from collections import defaultdict
from datetime import datetime


# Regex patterns
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
FAILED_LOGIN_PATTERNS = [
    re.compile(r'Failed password', re.IGNORECASE),
    re.compile(r'authentication failure', re.IGNORECASE),
    re.compile(r'Invalid user', re.IGNORECASE),
    re.compile(r'FAILED LOGIN', re.IGNORECASE),
    re.compile(r'401 Unauthorized', re.IGNORECASE),
]
SUCCESS_PATTERNS = [
    re.compile(r'Accepted password', re.IGNORECASE),
    re.compile(r'session opened', re.IGNORECASE),
]
SCAN_PATTERNS = [
    re.compile(r'SYN', re.IGNORECASE),
    re.compile(r'port scan', re.IGNORECASE),
]

# Thresholds
BRUTE_FORCE_THRESHOLD = 10   # Failed attempts before alert
SUSPICIOUS_IP_THRESHOLD = 5  # General suspicious activity threshold


def banner():
    print("""
╔══════════════════════════════════════════╗
║       SecToolkit - Log Analyzer          ║
║     Detects suspicious log activity      ║
╚══════════════════════════════════════════╝
    """)


def parse_log_file(filepath):
    """Reads and returns lines from a log file."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.readlines()
    except FileNotFoundError:
        print(f"[!] File not found: {filepath}")
        sys.exit(1)
    except PermissionError:
        print(f"[!] Permission denied: {filepath}")
        sys.exit(1)


def analyze(lines):
    """Analyzes log lines and returns statistics."""
    stats = {
        'total_lines': len(lines),
        'failed_logins': defaultdict(int),      # IP -> failed login count
        'successful_logins': defaultdict(int),  # IP -> successful login count
        'all_ips': defaultdict(int),            # IP -> total appearances
        'brute_force_suspects': [],
        'suspicious_ips': [],
        'scan_attempts': defaultdict(int),
        'timeline': [],
    }

    for i, line in enumerate(lines, 1):
        # Extract IP addresses
        ips = IP_PATTERN.findall(line)
        for ip in ips:
            stats['all_ips'][ip] += 1

        # Check for failed logins
        for pattern in FAILED_LOGIN_PATTERNS:
            if pattern.search(line):
                for ip in ips:
                    stats['failed_logins'][ip] += 1
                    if stats['failed_logins'][ip] == BRUTE_FORCE_THRESHOLD:
                        stats['brute_force_suspects'].append({
                            'ip': ip,
                            'count': stats['failed_logins'][ip],
                            'line': i
                        })
                break

        # Check for successful logins
        for pattern in SUCCESS_PATTERNS:
            if pattern.search(line):
                for ip in ips:
                    stats['successful_logins'][ip] += 1
                break

        # Check for port scan indicators
        for pattern in SCAN_PATTERNS:
            if pattern.search(line):
                for ip in ips:
                    stats['scan_attempts'][ip] += 1
                break

    # Find generally suspicious IPs
    for ip, count in stats['failed_logins'].items():
        if count >= SUSPICIOUS_IP_THRESHOLD and ip not in [s['ip'] for s in stats['brute_force_suspects']]:
            stats['suspicious_ips'].append({'ip': ip, 'failed': count})

    return stats


def print_report(stats, output_file=None):
    """Prints the analysis report."""
    lines_out = []

    def out(text=""):
        lines_out.append(text)
        print(text)

    out(f"\n{'='*50}")
    out(f"  LOG ANALYSIS REPORT")
    out(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    out(f"{'='*50}")

    out(f"\n[*] GENERAL STATISTICS")
    out(f"  Total lines          : {stats['total_lines']}")
    out(f"  Unique IPs           : {len(stats['all_ips'])}")
    out(f"  Failed login IPs     : {len(stats['failed_logins'])}")
    out(f"  Successful login IPs : {len(stats['successful_logins'])}")

    # Brute-force suspects
    if stats['brute_force_suspects']:
        out(f"\n[!!!] BRUTE-FORCE SUSPECTS ({len(stats['brute_force_suspects'])} IPs)")
        out(f"  {'IP Address':<20} {'Failed Attempts':>18} {'First Detected (Line)':>22}")
        out(f"  {'-'*62}")
        for s in sorted(stats['brute_force_suspects'], key=lambda x: -x['count']):
            failed = stats['failed_logins'][s['ip']]
            success = stats['successful_logins'].get(s['ip'], 0)
            success_str = f" -- {success} successful!" if success > 0 else ""
            out(f"  {s['ip']:<20} {failed:>18} {s['line']:>22}{success_str}")
    else:
        out(f"\n[OK] No brute-force suspects detected.")

    # Suspicious IPs
    if stats['suspicious_ips']:
        out(f"\n[!] SUSPICIOUS IPs ({len(stats['suspicious_ips'])} IPs)")
        out(f"  {'IP Address':<20} {'Failed':>10}")
        out(f"  {'-'*35}")
        for s in sorted(stats['suspicious_ips'], key=lambda x: -x['failed']):
            out(f"  {s['ip']:<20} {s['failed']:>10}")

    # Port scan attempts
    if stats['scan_attempts']:
        out(f"\n[?] PORT SCAN ATTEMPTS")
        for ip, count in sorted(stats['scan_attempts'].items(), key=lambda x: -x[1]):
            out(f"  {ip:<20} -> detected {count} times")

    # Most active IPs
    out(f"\n[*] TOP 10 MOST ACTIVE IPs")
    out(f"  {'IP Address':<20} {'Count':>10}")
    out(f"  {'-'*35}")
    for ip, count in sorted(stats['all_ips'].items(), key=lambda x: -x[1])[:10]:
        out(f"  {ip:<20} {count:>10}")

    out(f"\n{'='*50}\n")

    # Save to file
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines_out))
        print(f"[OK] Report saved: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="SecToolkit Log Analyzer",
        epilog=(
            "Examples:\n"
            "  python log_analyzer.py -f auth.log\n"
            "  python log_analyzer.py -f access.log -o report.txt\n"
            "  python log_analyzer.py -f auth.log --threshold 5"
        )
    )
    parser.add_argument("-f", "--file", required=True, help="Log file to analyze")
    parser.add_argument("-o", "--output", help="Save report to file (optional)")
    parser.add_argument("--threshold", type=int, default=10, help="Brute-force threshold (default: 10)")

    args = parser.parse_args()
    global BRUTE_FORCE_THRESHOLD
    BRUTE_FORCE_THRESHOLD = args.threshold

    banner()
    print(f"[*] Analyzing file: {args.file}")
    lines = parse_log_file(args.file)
    stats = analyze(lines)
    print_report(stats, args.output)


if __name__ == "__main__":
    main()
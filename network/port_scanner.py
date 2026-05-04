#!/usr/bin/env python3
"""
SecToolkit - Port Scanner
Scans open ports on a target IP or domain.
WARNING: Use only on systems you are authorized to access.
"""

import socket
import threading
import argparse
import sys
from datetime import datetime
from queue import Queue

# Common ports and their services
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB"
}

open_ports = []
lock = threading.Lock()
queue = Queue()


def banner():
    print("""
╔═══════════════════════════════════════╗
║      SecToolkit - Port Scanner        ║
║  Use only on authorized systems       ║
╚═══════════════════════════════════════╝
    """)


def resolve_host(host):
    """Resolves a domain name to an IP address."""
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror:
        print(f"[!] Error: Could not resolve '{host}'.")
        sys.exit(1)


def scan_port(ip, port, timeout):
    """Scans a single port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            with lock:
                open_ports.append((port, service))
                print(f"  [+] Port {port:5d}/tcp  OPEN  ->  {service}")
    except Exception:
        pass


def worker(ip, timeout):
    """Thread worker function."""
    while not queue.empty():
        port = queue.get()
        scan_port(ip, port, timeout)
        queue.task_done()


def scan(host, start_port, end_port, threads, timeout):
    banner()

    ip = resolve_host(host)
    print(f"[*] Target    : {host} ({ip})")
    print(f"[*] Port Range: {start_port} - {end_port}")
    print(f"[*] Threads   : {threads}")
    print(f"[*] Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 45)

    # Add ports to queue
    for port in range(start_port, end_port + 1):
        queue.put(port)

    # Start threads
    thread_list = []
    for _ in range(min(threads, end_port - start_port + 1)):
        t = threading.Thread(target=worker, args=(ip, timeout))
        t.daemon = True
        t.start()
        thread_list.append(t)

    queue.join()

    # Show results
    print("-" * 45)
    if open_ports:
        open_ports.sort()
        print(f"\n[OK] Found {len(open_ports)} open port(s).\n")
    else:
        print("\n[--] No open ports found.\n")

    print(f"[*] Finished  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


def main():
    parser = argparse.ArgumentParser(
        description="SecToolkit Port Scanner",
        epilog=(
            "Examples:\n"
            "  python port_scanner.py -t 192.168.1.1 -p 1-1000\n"
            "  python port_scanner.py -t example.com --threads 200"
        )
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP or domain")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Port range (default: 1-1024). Example: 1-65535")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=0.5, help="Connection timeout in seconds (default: 0.5)")

    args = parser.parse_args()

    # Parse port range
    try:
        parts = args.ports.split("-")
        start_port = int(parts[0])
        end_port = int(parts[1]) if len(parts) > 1 else start_port
        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
            raise ValueError
    except (ValueError, IndexError):
        print("[!] Invalid port range. Example: 1-1024")
        sys.exit(1)

    scan(args.target, start_port, end_port, args.threads, args.timeout)


if __name__ == "__main__":
    main()
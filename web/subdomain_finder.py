#!/usr/bin/env python3
"""
SecToolkit - Subdomain Finder
Discovers subdomains of a target domain using a wordlist.
WARNING: Use only on domains you are authorized to test.
"""

import socket
import threading
import argparse
import sys
from queue import Queue
from datetime import datetime


# Default subdomain wordlist
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "admin", "blog", "dev", "test", "api",
    "shop", "store", "portal", "vpn", "remote", "staging", "beta",
    "app", "mobile", "cdn", "static", "media", "img", "images",
    "video", "download", "upload", "backup", "old", "new", "secure",
    "login", "auth", "sso", "mx", "smtp", "pop", "imap", "webmail",
    "forum", "wiki", "docs", "help", "support", "status", "monitor",
    "dashboard", "panel", "cpanel", "whm", "plesk", "db", "database",
    "mysql", "sql", "git", "svn", "jenkins", "ci", "cloud", "s3",
    "assets", "search", "news", "jobs", "careers", "about", "contact"
]

found_subdomains = []
lock = threading.Lock()
queue = Queue()


def banner():
    print("""
╔═══════════════════════════════════════╗
║     SecToolkit - Subdomain Finder     ║
║   Use only on authorized domains      ║
╚═══════════════════════════════════════╝
    """)


def resolve_subdomain(subdomain, domain, timeout):
    """Tries to resolve a subdomain."""
    full_domain = f"{subdomain}.{domain}"
    try:
        socket.setdefaulttimeout(timeout)
        ip = socket.gethostbyname(full_domain)
        with lock:
            found_subdomains.append((full_domain, ip))
            print(f"  [+] Found: {full_domain:<40} -> {ip}")
    except (socket.gaierror, socket.timeout):
        pass


def worker(domain, timeout):
    """Thread worker function."""
    while not queue.empty():
        subdomain = queue.get()
        resolve_subdomain(subdomain, domain, timeout)
        queue.task_done()


def scan(domain, wordlist, threads, timeout):
    banner()
    print(f"[*] Target   : {domain}")
    print(f"[*] Wordlist : {len(wordlist)} subdomains")
    print(f"[*] Threads  : {threads}")
    print(f"[*] Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 50)

    # Add subdomains to queue
    for word in wordlist:
        queue.put(word.strip())

    # Start threads
    thread_list = []
    for _ in range(min(threads, len(wordlist))):
        t = threading.Thread(target=worker, args=(domain, timeout))
        t.daemon = True
        t.start()
        thread_list.append(t)

    queue.join()

    # Results
    print("-" * 50)
    if found_subdomains:
        print(f"\n[OK] Found {len(found_subdomains)} subdomain(s):\n")
        for subdomain, ip in sorted(found_subdomains):
            print(f"  {subdomain:<40} -> {ip}")
    else:
        print("\n[--] No subdomains found.")

    print(f"\n[*] Finished : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")


def main():
    parser = argparse.ArgumentParser(
        description="SecToolkit Subdomain Finder",
        epilog=(
            "Examples:\n"
            "  python subdomain_finder.py -d example.com\n"
            "  python subdomain_finder.py -d example.com -w wordlist.txt\n"
            "  python subdomain_finder.py -d example.com --threads 50"
        )
    )
    parser.add_argument("-d", "--domain", required=True,
                        help="Target domain (e.g. example.com)")
    parser.add_argument("-w", "--wordlist", default=None,
                        help="Wordlist file (default: built-in list)")
    parser.add_argument("--threads", type=int, default=30,
                        help="Number of threads (default: 30)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="DNS timeout in seconds (default: 1.0)")

    args = parser.parse_args()

    # Load wordlist
    if args.wordlist:
        try:
            with open(args.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                wordlist = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] Wordlist not found: {args.wordlist}")
            sys.exit(1)
    else:
        wordlist = DEFAULT_WORDLIST

    scan(args.domain, wordlist, args.threads, args.timeout)


if __name__ == "__main__":
    main()
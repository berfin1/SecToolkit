#!/usr/bin/env python3
"""
SecToolkit - HTTP Header Checker
Analyzes HTTP security headers of a target website.
WARNING: Use only on websites you are authorized to test.
"""

import urllib.request
import urllib.error
import argparse
import sys
from datetime import datetime


def banner():
    print("""
╔═══════════════════════════════════════╗
║    SecToolkit - HTTP Header Checker   ║
║   Use only on authorized websites     ║
╚═══════════════════════════════════════╝
    """)


# Security headers and their descriptions
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Forces HTTPS connections (HSTS)",
        "risk": "HIGH - Site can be accessed over HTTP, vulnerable to MITM attacks"
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS and data injection attacks",
        "risk": "HIGH - Site is vulnerable to XSS attacks"
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "risk": "MEDIUM - Site is vulnerable to clickjacking"
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing",
        "risk": "MEDIUM - Browser may execute files with wrong content type"
    },
    "Referrer-Policy": {
        "description": "Controls referrer information",
        "risk": "LOW - Referrer information may be leaked"
    },
    "Permissions-Policy": {
        "description": "Controls browser features and APIs",
        "risk": "LOW - Browser features are not restricted"
    },
    "X-XSS-Protection": {
        "description": "Enables browser XSS filter (legacy)",
        "risk": "LOW - Legacy XSS protection not enabled"
    },
    "Cache-Control": {
        "description": "Controls caching behavior",
        "risk": "LOW - Sensitive data may be cached"
    },
}

# Information headers that reveal server details
INFO_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version",
    "X-AspNetMvc-Version", "X-Generator", "Via"
]


def fetch_headers(url, timeout):
    """Fetches HTTP headers from a URL."""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'SecToolkit-HeaderChecker/1.0'}
        )
        response = urllib.request.urlopen(req, timeout=timeout)
        headers = dict(response.headers)
        final_url = response.geturl()
        status_code = response.status
        return headers, final_url, status_code

    except urllib.error.HTTPError as e:
        return dict(e.headers), url, e.code
    except urllib.error.URLError as e:
        print(f"[!] Connection error: {e.reason}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


def analyze_headers(headers, url):
    """Analyzes HTTP headers for security issues."""
    results = {
        'present': [],
        'missing': [],
        'info_leak': [],
        'score': 0,
        'max_score': len(SECURITY_HEADERS)
    }

    # Check security headers
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for header, info in SECURITY_HEADERS.items():
        if header.lower() in headers_lower:
            results['present'].append({
                'header': header,
                'value': headers_lower[header.lower()],
                'description': info['description']
            })
            results['score'] += 1
        else:
            results['missing'].append({
                'header': header,
                'description': info['description'],
                'risk': info['risk']
            })

    # Check for information leaking headers
    for header in INFO_HEADERS:
        if header.lower() in headers_lower:
            results['info_leak'].append({
                'header': header,
                'value': headers_lower[header.lower()]
            })

    return results


def print_report(results, url, final_url, status_code):
    """Prints the analysis report."""
    score = results['score']
    max_score = results['max_score']
    percentage = (score / max_score) * 100

    # Grade
    if percentage >= 90:
        grade = "A+"
    elif percentage >= 80:
        grade = "A"
    elif percentage >= 70:
        grade = "B"
    elif percentage >= 60:
        grade = "C"
    elif percentage >= 50:
        grade = "D"
    else:
        grade = "F"

    print(f"\n{'='*55}")
    print(f"  HTTP HEADER SECURITY REPORT")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*55}")

    print(f"\n[*] TARGET")
    print(f"  URL         : {final_url}")
    print(f"  Status Code : {status_code}")
    print(f"  Score       : {score}/{max_score} ({percentage:.0f}%)")
    print(f"  Grade       : {grade}")

    # Progress bar
    bar_filled = int(percentage / 5)
    bar = '#' * bar_filled + '-' * (20 - bar_filled)
    print(f"  Progress    : [{bar}] {percentage:.0f}%")

    # Present headers
    if results['present']:
        print(f"\n[OK] SECURITY HEADERS PRESENT ({len(results['present'])})")
        for h in results['present']:
            print(f"  [+] {h['header']}")
            print(f"      Value : {h['value'][:80]}")
            print(f"      Info  : {h['description']}")

    # Missing headers
    if results['missing']:
        print(f"\n[!!!] MISSING SECURITY HEADERS ({len(results['missing'])})")
        for h in results['missing']:
            print(f"  [-] {h['header']}")
            print(f"      Info  : {h['description']}")
            print(f"      Risk  : {h['risk']}")

    # Information leaking headers
    if results['info_leak']:
        print(f"\n[!] INFORMATION LEAKING HEADERS ({len(results['info_leak'])})")
        print(f"  These headers reveal server details to attackers:")
        for h in results['info_leak']:
            print(f"  [!] {h['header']}: {h['value']}")

    # Summary
    print(f"\n{'='*55}")
    print(f"  SUMMARY")
    print(f"{'='*55}")
    if grade in ["A+", "A"]:
        print(f"  [++] Excellent security headers configuration!")
    elif grade in ["B", "C"]:
        print(f"  [~] Moderate security. Fix missing headers above.")
    else:
        print(f"  [!!!] Poor security headers. Immediate action needed!")
    print(f"{'='*55}\n")


def main():
    parser = argparse.ArgumentParser(
        description="SecToolkit HTTP Header Checker",
        epilog=(
            "Examples:\n"
            "  python header_checker.py -u example.com\n"
            "  python header_checker.py -u https://example.com\n"
            "  python header_checker.py -u example.com --timeout 10"
        )
    )
    parser.add_argument("-u", "--url", required=True,
                        help="Target URL or domain (e.g. example.com)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Request timeout in seconds (default: 10)")

    args = parser.parse_args()

    banner()
    print(f"[*] Checking: {args.url}")
    print(f"[*] Please wait...\n")

    headers, final_url, status_code = fetch_headers(args.url, args.timeout)
    results = analyze_headers(headers, args.url)
    print_report(results, args.url, final_url, status_code)


if __name__ == "__main__":
    main()
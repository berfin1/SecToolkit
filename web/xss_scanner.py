#!/usr/bin/env python3
"""
SecToolkit - XSS Scanner
Tests web forms and URL parameters for basic XSS vulnerabilities.
WARNING: Use only on websites you are authorized to test.
"""

import urllib.request
import urllib.parse
import urllib.error
import argparse
import sys
from datetime import datetime


def banner():
    print("""
╔═══════════════════════════════════════╗
║       SecToolkit - XSS Scanner        ║
║   Use only on authorized websites     ║
╚═══════════════════════════════════════╝
    """)


# XSS test payloads
PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "<body onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src=javascript:alert('XSS')>",
    "<<script>alert('XSS');//<</script>",
    "<ScRiPt>alert('XSS')</ScRiPt>",
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
]


def make_request(url, timeout):
    """Makes an HTTP GET request and returns the response body."""
    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'SecToolkit-XSSScanner/1.0'}
        )
        response = urllib.request.urlopen(req, timeout=timeout)
        return response.read().decode('utf-8', errors='replace')
    except urllib.error.HTTPError as e:
        return e.read().decode('utf-8', errors='replace')
    except Exception:
        return None


def extract_params(url):
    """Extracts URL parameters from a URL."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    return parsed, params


def test_url_params(url, timeout):
    """Tests URL parameters for XSS vulnerabilities."""
    parsed, params = extract_params(url)

    if not params:
        print(f"[!] No URL parameters found in: {url}")
        print(f"[!] Example: python xss_scanner.py -u 'http://example.com/search?q=test'")
        return []

    print(f"[*] Found {len(params)} parameter(s): {', '.join(params.keys())}")
    print(f"[*] Testing {len(PAYLOADS)} payloads per parameter...")
    print(f"[*] Total requests: {len(params) * len(PAYLOADS)}\n")
    print("-" * 50)

    vulnerabilities = []

    for param in params:
        print(f"[*] Testing parameter: '{param}'")

        for payload in PAYLOADS:
            # Build test URL
            test_params = dict(params)
            test_params[param] = [payload]
            new_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))

            # Make request
            response = make_request(test_url, timeout)

            if response and payload in response:
                print(f"\n  [!!!] XSS VULNERABILITY FOUND!")
                print(f"  Parameter : {param}")
                print(f"  Payload   : {payload}")
                print(f"  URL       : {test_url[:100]}")
                vulnerabilities.append({
                    'param': param,
                    'payload': payload,
                    'url': test_url
                })
                break  # Found vuln in this param, move to next
            else:
                print(f"  [-] Payload {PAYLOADS.index(payload)+1}/{len(PAYLOADS)} - Not vulnerable")

        print()

    return vulnerabilities


def print_report(vulnerabilities, url, start_time):
    """Prints the scan report."""
    elapsed = (datetime.now() - start_time).total_seconds()

    print(f"\n{'='*55}")
    print(f"  XSS SCAN REPORT")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*55}")
    print(f"  Target  : {url}")
    print(f"  Time    : {elapsed:.2f} seconds")

    if vulnerabilities:
        print(f"\n[!!!] {len(vulnerabilities)} XSS VULNERABILITY(IES) FOUND!\n")
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"  [{i}] Parameter : {vuln['param']}")
            print(f"      Payload   : {vuln['payload']}")
            print(f"      URL       : {vuln['url'][:80]}")
            print()
        print(f"  [!] Recommendation: Sanitize and encode all user inputs.")
        print(f"  [!] Use Content-Security-Policy header.")
    else:
        print(f"\n[OK] No XSS vulnerabilities detected.")
        print(f"  Note: This is a basic scanner. Manual testing is recommended.")

    print(f"\n{'='*55}\n")


def main():
    parser = argparse.ArgumentParser(
        description="SecToolkit XSS Scanner",
        epilog=(
            "Examples:\n"
            "  python xss_scanner.py -u 'http://example.com/search?q=test'\n"
            "  python xss_scanner.py -u 'http://example.com/page?id=1&name=test'\n"
            "  python xss_scanner.py -u 'http://example.com/search?q=test' --timeout 5"
        )
    )
    parser.add_argument("-u", "--url", required=True,
                        help="Target URL with parameters (e.g. http://example.com/search?q=test)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Request timeout in seconds (default: 10)")

    args = parser.parse_args()

    banner()
    print(f"[*] Target  : {args.url}")
    print(f"[*] Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    start_time = datetime.now()
    vulnerabilities = test_url_params(args.url, args.timeout)
    print_report(vulnerabilities, args.url, start_time)


if __name__ == "__main__":
    main()
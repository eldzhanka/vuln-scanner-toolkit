"""
Modular web security scanning toolkit.

Each vulnerability class lives in its own module under modules/, and
shares a common HTTP client and reporting layer from core/. New checks
(XSS, JWT, IDOR, endpoint discovery, etc.) plug in the same way path
traversal does here — see modules/path_traversal.py as the reference
implementation.

Usage:
    python3 main.py path-traversal -u http://example.com/view -p filename
    python3 main.py path-traversal -u http://example.com/view -p filename --os windows -o results.json
    python3 main.py xss -u http://example.com/search -p q
    python3 main.py jwt -t eyJhbGciOi...
"""

import argparse

from core.http_client import HTTPClient, parse_headers, parse_cookie_string, load_wordlist
from modules import path_traversal, xss, jwt_analyzer


def add_common_http_args(subparser):
    """Flags shared by every module that makes HTTP requests."""
    subparser.add_argument("-u", "--url", required=True, help="Target URL")
    subparser.add_argument("-c", "--cookie", help="Session cookie string, e.g. 'session=abc123; role=user'")
    subparser.add_argument("-H", "--header", action="append", help="Custom header, repeatable")
    subparser.add_argument("--proxy", help="Proxy URL, e.g. http://127.0.0.1:8080 (for Burp Suite)")
    subparser.add_argument("--timeout", type=int, default=5, help="Per-request timeout in seconds")
    subparser.add_argument("--insecure", action="store_true", help="Disable SSL certificate verification")
    subparser.add_argument("-o", "--output", help="Save results to a JSON file")


def build_client(args):
    return HTTPClient(
        headers=parse_headers(args.header),
        cookies=parse_cookie_string(args.cookie),
        proxy=args.proxy,
        timeout=args.timeout,
        verify_ssl=not args.insecure,
    )


def main():
    parser = argparse.ArgumentParser(description="Modular web security scanning toolkit")
    subparsers = parser.add_subparsers(dest="module", required=True)

    # --- path-traversal module ---
    pt_parser = subparsers.add_parser("path-traversal", help="Scan a parameter for path traversal")
    add_common_http_args(pt_parser)
    pt_parser.add_argument("-p", "--param", required=True, help="Parameter name to test")
    pt_parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], help="HTTP method")
    pt_parser.add_argument("-w", "--wordlist", help="Path to a custom payload wordlist file")
    pt_parser.add_argument("--os", dest="target_os", default="linux", choices=["linux", "windows", "all"],
                            help="Target OS for success markers")

    # --- xss module ---
    xss_parser = subparsers.add_parser("xss", help="Scan a parameter for reflected XSS")
    add_common_http_args(xss_parser)
    xss_parser.add_argument("-p", "--param", required=True, help="Parameter name to test")
    xss_parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], help="HTTP method")
    xss_parser.add_argument("-w", "--wordlist", help="Path to a custom payload wordlist file")

    # --- jwt module (offline — no HTTP client needed) ---
    jwt_parser = subparsers.add_parser("jwt", help="Analyze a JWT for common weaknesses")
    jwt_parser.add_argument("-t", "--token", required=True, help="The JWT to analyze")
    jwt_parser.add_argument("-w", "--wordlist", help="Path to a custom secret wordlist file (for HMAC brute-force)")
    jwt_parser.add_argument("-o", "--output", help="Save results to a JSON file")

    # Future modules register here the same way, e.g.:
    # idor_parser = subparsers.add_parser("idor", help="Check for insecure direct object references")
    # ...

    args = parser.parse_args()

    if args.module == "path-traversal":
        client = build_client(args)
        payloads = None
        if args.wordlist:
            payloads = load_wordlist(args.wordlist)
            if payloads is None:
                raise SystemExit(1)
        args.payloads = payloads
        report = path_traversal.run(args, client)
    elif args.module == "xss":
        client = build_client(args)
        payloads = None
        if args.wordlist:
            payloads = load_wordlist(args.wordlist)
            if payloads is None:
                raise SystemExit(1)
        args.payloads = payloads
        report = xss.run(args, client)
    elif args.module == "jwt":
        wordlist_entries = None
        if args.wordlist:
            wordlist_entries = load_wordlist(args.wordlist)
            if wordlist_entries is None:
                raise SystemExit(1)
        args.wordlist_entries = wordlist_entries
        report = jwt_analyzer.run(args)
    else:
        raise SystemExit(f"Unknown module: {args.module}")

    if args.output:
        report.save(args.output)


if __name__ == "__main__":
    main()

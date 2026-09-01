"""
IDOR (Insecure Direct Object Reference) checker module.

Enumerates a range of ID values against a parameter and flags responses
that come back accessible (not blocked/not-found) as candidates worth
manual review. IDOR can't be confirmed automatically from a single
session , actually proving it means comparing what one authenticated
user can see against another user's objects , so this module does the
enumeration and comparison legwork and hands you a shortlist, rather
than claiming a confirmed finding on its own.
"""

import urllib.parse

from core.http_client import HTTPClient
from core.report import Report

# Status codes that typically mean "blocked" or "doesn't exist" 
# anything else is worth a second look.
BLOCKED_STATUSES = {401, 403, 404, 400}


def parse_id_range(range_str):
    """Parse '1-50' into a list of string IDs. Also accepts a comma
    list like '1,2,3,17,42'."""
    ids = []
    if "-" in range_str and "," not in range_str:
        start, end = range_str.split("-", 1)
        ids = [str(i) for i in range(int(start), int(end) + 1)]
    else:
        ids = [v.strip() for v in range_str.split(",") if v.strip()]
    return ids


def run(args, client: HTTPClient):
    report = Report("idor")
    ids = args.id_list

    print(f"[*] Scan start: {args.url} (Parameter: {args.param})")
    print(f"[*] IDs to try: {len(ids)}\n")

    baseline = None
    if args.baseline_id:
        print(f"[*] Fetching baseline response for ID {args.baseline_id!r}...")
        baseline_response = _fetch(client, args, args.baseline_id)
        if baseline_response is not None:
            baseline = {
                "status": baseline_response.status_code,
                "length": len(baseline_response.text),
            }
            print(f"[*] Baseline: status {baseline['status']}, "
                  f"length {baseline['length']}\n")

    for object_id in ids:
        if args.baseline_id and object_id == args.baseline_id:
            continue

        response = _fetch(client, args, object_id)
        if response is None:
            continue

        if response.status_code in BLOCKED_STATUSES:
            continue

        note = "accessible, worth manual review to confirm it belongs to another user/object"
        if baseline and response.status_code == baseline["status"]:
            length_diff = abs(len(response.text) - baseline["length"])
            if length_diff < baseline["length"] * 0.2:  # within 20% of baseline size
                note = ("accessible, and response closely resembles the baseline "
                         "response = strong IDOR candidate")

        report.add_finding(
            id=object_id,
            url=response.url,
            status=response.status_code,
            length=len(response.text),
            note=note,
        )

    report.summarize()
    return report


def _fetch(client, args, object_id):
    if args.method.upper() == "GET":
        target_url = f"{args.url}?{args.param}={urllib.parse.quote(object_id)}"
        return client.get(target_url)
    return client.post(args.url, data={args.param: object_id})

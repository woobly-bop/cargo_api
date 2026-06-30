"""
Shipment store (in-memory demo).

SQLAlchemy 1.3.0 is imported here and carries advisories, but the only vulnerable
pattern (raw `text()` string interpolation) lives in `_legacy_raw_query`, which is
DEAD CODE — no route calls it. PRAS marks SQLAlchemy's findings as not-reachable
(PROCEED) for exactly this reason.
"""

from sqlalchemy import text  # imported; advisory-bearing but path is unreachable

_SHIPMENTS = {
    "SHP-1001": {"tracking": "SHP-1001", "carrier": "BlueLine", "eta": "2026-07-02"},
    "SHP-1002": {"tracking": "SHP-1002", "carrier": "RoadRunner", "eta": "2026-07-03"},
}


def list_shipments():
    return list(_SHIPMENTS.values())


def get_shipment(shipment_id):
    return _SHIPMENTS.get(shipment_id, {"tracking": shipment_id, "carrier": "?", "eta": "?"})


def _legacy_raw_query(engine, shipment_id):
    # DEAD CODE: not referenced by any entry point. Kept to show that an
    # *unreachable* vulnerable pattern should not drive a BLOCK verdict.
    stmt = text("SELECT * FROM shipments WHERE id = '%s'" % shipment_id)
    return engine.execute(stmt)

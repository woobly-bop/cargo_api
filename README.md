# cargo-control-api

> **⚠️ Intentionally vulnerable demo application. Do not deploy. Do not reuse this code.**
> It exists to be scanned by **PRAS** (Predictive Risk Assessment System) as a
> reproducible demo target.

A small Flask "cargo / shipment control" API whose dependency manifest pins old,
known-vulnerable library versions. It is engineered so that PRAS produces a clear,
explainable **BLOCK** verdict with a known ground truth.

## The headline

| | |
|---|---|
| Dependencies | 22 |
| Known CVEs (live SCA) | **~86** |
| Reachable from an entry point | 6 |
| Reachable **and** dangerous | **2** |
| Verdict | **BLOCK** (risk 91/100) |
| BLOCK / REVIEW / PROCEED | **2 / 3 / 81** |

A naive CVSS-ranked scanner reports 86 alerts (9 "critical", most from Pillow).
PRAS reports **2 release-blocking issues** and explains why the other 84 don't block.

## Verdict map

| Verdict | CVE | Package | Reachable via | Sink |
|---|---|---|---|---|
| 🔴 BLOCK | CVE-2020-14343 | PyYAML 5.1 | `POST /api/v1/config/import` | `app/config_loader.py:25` (`yaml.load`) |
| 🔴 BLOCK | CVE-2019-10906 | Jinja2 2.10 | `GET /api/v1/shipments/<id>/label` | `app/labels.py:20` (sandbox escape) |
| 🟡 REVIEW | CVE-2018-18074 | requests 2.19.1 | `POST /api/v1/webhooks/forward` | `app/integrations.py:26` |
| 🟡 REVIEW | CVE-2018-20060 | urllib3 1.23 | same path (transitive) | `app/integrations.py:26` |
| 🟡 REVIEW | CVE-2019-11236 | urllib3 1.23 | same path (transitive) | `app/integrations.py:26` |
| 🟢 PROCEED | ~28 image CVEs | Pillow 6.0.0 | **unreachable** (dead code) | `app/reports.py:22` |
| 🟢 PROCEED | lxml / SQLAlchemy | 4.2.5 / 1.3.0 | **unreachable** (dead code) | `app/reports.py:31`, `app/shipments.py:29` |
| 🟢 PROCEED | PyJWT / cryptography | reachable but **not vulnerable on path** | `GET /api/v1/shipments` | `app/auth.py:21` |

Full ground truth: [`.pras/answer_key.json`](.pras/answer_key.json).

## Repo map

```
cargo-control-api/
├── requirements.txt          # the vulnerable manifest PRAS scans
├── app/
│   ├── main.py               # Flask routes  = PRAS entry points (reachability roots)
│   ├── config_loader.py      # BLOCK  · yaml.load on untrusted body  (CVE-2020-14343)
│   ├── labels.py             # BLOCK  · Jinja2 sandbox escape        (CVE-2019-10906)
│   ├── integrations.py       # REVIEW · requests/urllib3 token leak  (CVE-2018-18074)
│   ├── auth.py               # reachable-but-safe JWT verify          (PROCEED w/ note)
│   ├── shipments.py          # SQLAlchemy raw-SQL helper = DEAD CODE  (PROCEED)
│   └── reports.py            # Pillow + lxml = DEAD CODE               (PROCEED, ~34 CVEs)
├── config/default_profile.yaml
├── .pras/answer_key.json     # engineered ground truth for the demo
├── demo_explain.py           # console revision aid (stdlib only)
└── DEMO_SCRIPT.md            # stage narration / talking points
```

## How the reachability story is wired

- **Entry points** = the Flask route handlers in `app/main.py`.
- **BLOCK sinks** are reached by a real call chain from a route (route → helper → sink).
- **PROCEED noise** (`reports.py`, `shipments.py._legacy_raw_query`) is genuinely
  *unreferenced* — no route reaches it — so its CVEs can't drive a verdict.
- **Reachable-but-safe** (`auth.py`) shows the subtle case: the path runs, but the
  vulnerable precondition isn't met (pinned `HS256`), so it's PROCEED, not BLOCK.

## Running

You do **not** need to install the dependencies to run a PRAS scan — PRAS reads
`requirements.txt` statically. To rehearse the demo:

```bash
python3 demo_explain.py            # full walkthrough
python3 demo_explain.py --only BLOCK
python3 demo_explain.py --quiz     # hide rationale, test yourself
```

If you *do* want to run the app, use a throwaway virtualenv — the pins are old and
some transitive resolutions are intentionally messy.

## Tuning the CVE count

Want a bigger/smaller headline number? Edit `requirements.txt`: older Pillow / lxml /
cryptography / urllib3 pins push the count up; relaxing them pulls it down. The two
BLOCK verdicts depend only on PyYAML ≤ 5.3.x and Jinja2 < 2.10.1 plus the wired code
paths, so they stay stable as you tune the noise.

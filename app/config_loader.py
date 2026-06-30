"""
Carrier-profile loader.

BLOCK sink: PyYAML 5.1 is vulnerable to CVE-2020-14343 (arbitrary code execution
via the python/object/new constructor). `yaml.load` with FullLoader does NOT make
this safe on 5.1 — the fix only landed in 5.4. Untrusted YAML from the
/api/v1/config/import route flows straight into this function.
"""

import yaml


def _normalize(profile):
    profile.setdefault("name", "unnamed-carrier")
    profile.setdefault("regions", [])
    return profile


def load_profile(raw_yaml):
    """Parse an operator-supplied carrier profile.

    raw_yaml is fully attacker-controlled (request body). On PyYAML < 5.4 this is
    a remote code execution sink.
    """
    data = yaml.load(raw_yaml, Loader=yaml.FullLoader)   # <== VULNERABLE SINK
    if not isinstance(data, dict):
        raise ValueError("carrier profile must be a mapping")
    return _normalize(data)


def load_profile_file(path):
    """Loads a trusted on-disk default. Same library, but the input is NOT
    attacker-controlled, so this call site is not the reachable risk."""
    with open(path) as fh:
        return _normalize(yaml.safe_load(fh.read()))

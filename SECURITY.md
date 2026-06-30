# Security Notice

**This repository is intentionally vulnerable.** It pins old, known-CVE library
versions and contains deliberately unsafe code paths (YAML deserialization, Jinja2
sandbox rendering of untrusted templates, credential-leaking HTTP forwarding).

It exists solely as a demo target for the PRAS (Predictive Risk Assessment System)
security scanner. **Do not deploy it, do not install it outside a throwaway sandbox,
and do not copy its patterns into real code.**

Please do not file CVE reports against this repo — the vulnerabilities are the point.

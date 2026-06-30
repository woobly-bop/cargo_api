"""
Shipping-label renderer.

BLOCK sink: Jinja2 2.10 is vulnerable to CVE-2019-10906 — str.format_map escapes
the sandbox. The label `template` is taken from the request query string, so an
attacker controls the template body. Even though we use SandboxedEnvironment
(the "safe" path), 2.10 lets `{{ ''.format_map(...) }}`-style payloads break out.
"""

from jinja2.sandbox import SandboxedEnvironment

_env = SandboxedEnvironment(autoescape=True)


def render_label(template_str, shipment):
    """Render an attacker-controllable Jinja template against shipment data.

    On Jinja2 < 2.10.1 the sandbox can be escaped via str.format_map.
    """
    tmpl = _env.from_string(template_str)        # <== compiles untrusted template
    return tmpl.render(
        tracking=shipment.get("tracking", ""),
        carrier=shipment.get("carrier", ""),
        eta=shipment.get("eta", ""),
    )                                            # <== VULNERABLE SINK (sandbox escape)

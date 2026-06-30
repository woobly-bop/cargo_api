"""
cargo-control-api · HTTP entry points

This module defines the externally reachable routes. PRAS treats every Flask
route handler as an *entry point* (a reachability root) and walks the call graph
forward to see which vulnerable dependency functions are actually reachable.

Routes intentionally reach three different vulnerable sinks:
  POST /api/v1/config/import      -> yaml.load        (PyYAML RCE)
  GET  /api/v1/shipments/<id>/label -> SandboxedEnvironment.from_string (Jinja2 escape)
  POST /api/v1/webhooks/forward   -> requests.get     (Authorization leak on redirect)
"""

from flask import Flask, request, jsonify

from app.config_loader import load_profile
from app.labels import render_label
from app.integrations import forward_webhook
from app.auth import verify_bearer
from app.shipments import get_shipment, list_shipments

app = Flask(__name__)


@app.route("/healthz")
def healthz():
    return jsonify(status="ok")


@app.route("/api/v1/shipments")
def shipments_index():
    if not verify_bearer(request.headers.get("Authorization", "")):
        return jsonify(error="unauthorized"), 401
    return jsonify(shipments=list_shipments())


@app.route("/api/v1/config/import", methods=["POST"])
def import_config():
    # Operators paste a YAML "carrier profile" here. The raw body is untrusted.
    raw = request.get_data(as_text=True)
    profile = load_profile(raw)            # --> reaches yaml.load  (BLOCK)
    return jsonify(imported=profile.get("name", "unknown"))


@app.route("/api/v1/shipments/<shipment_id>/label")
def shipment_label(shipment_id):
    shipment = get_shipment(shipment_id)
    # The label "template" is attacker-controllable via query string.
    template = request.args.get("template", "{{ tracking }}")
    html = render_label(template, shipment)  # --> reaches Jinja2 sandbox (BLOCK)
    return html


@app.route("/api/v1/webhooks/forward", methods=["POST"])
def webhooks_forward():
    body = request.get_json(force=True) or {}
    target = body.get("url", "")
    token = request.headers.get("Authorization", "")
    # Forwards the caller's bearer token to an arbitrary URL.
    resp = forward_webhook(target, token)    # --> reaches requests.get (REVIEW)
    return jsonify(status=resp)


if __name__ == "__main__":
    # debug=True activates the Werkzeug interactive debugger (see answer key).
    app.run(host="0.0.0.0", port=8080, debug=False)

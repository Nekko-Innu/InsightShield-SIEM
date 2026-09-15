# web/blueprints/admin_settings.py
# /admin/settings and every mutating endpoint underneath it.
#
# Each POST here still calls verify_csrf() inline even though web/csrf.py
# enforces it for every mutating request: settings.js expects this module's
# JSON error shape, not the blanket handler's.

import json as _json
import logging
import ssl

from flask import (
    Blueprint, abort, flash, jsonify, redirect, render_template, request, url_for,
)
from flask_login import current_user, login_required

import _request_cache
import backup as backup_mod
import config
import db
import rate_limit
from decorators import role_required
from web.csrf import verify_csrf

logger = logging.getLogger("insightshield.web.admin_settings")

bp = Blueprint("admin_settings", __name__)


@bp.route("/admin/settings")
@login_required
@role_required("IT_ADMIN")
def admin_settings():
    tab = (request.args.get("tab") or "service").lower()
    if tab not in ("service", "audit", "backups", "errors"):
        tab = "service"

    # Tab-specific data fetches
    audit_rows: list[dict] = []
    audit_filters = {"actor": "", "action": "", "from": "", "to": ""}
    backups_list: list = []
    error_rows: list[dict] = []
    error_filters = {"source": "", "module": "", "from": "", "to": ""}

    if tab == "audit":
        audit_filters = {
            "actor":  (request.args.get("actor") or "").strip(),
            "action": (request.args.get("action") or "").strip(),
            "from":   (request.args.get("from") or "").strip(),
            "to":     (request.args.get("to") or "").strip(),
        }
        audit_rows = db.search_audit(
            actor=audit_filters["actor"] or None,
            action=audit_filters["action"] or None,
            date_from=audit_filters["from"] or None,
            date_to=audit_filters["to"] or None,
            limit=500,
        )
    elif tab == "backups":
        backups_list = backup_mod.list_backups()
    elif tab == "errors":
        error_filters = {
            "source": (request.args.get("source") or "").strip(),
            "module": (request.args.get("module") or "").strip(),
            "from":   (request.args.get("from") or "").strip(),
            "to":     (request.args.get("to") or "").strip(),
        }
        error_rows = db.search_errors(
            source=error_filters["source"] or None,
            module=error_filters["module"] or None,
            date_from=error_filters["from"] or None,
            date_to=error_filters["to"] or None,
            limit=500,
        )

    # Build the data the service-config partial expects
    providers = db.list_all_providers()

    # api_keys: dict keyed by (service, key_name) -> plaintext (decrypted).
    # Used for the masked-value placeholder display only — the password input
    # never carries the plaintext into the rendered HTML.
    api_keys = {}
    for service, key_name in (
        ("telegram_it", "BOT_TOKEN"),
        ("telegram_manager", "BOT_TOKEN"),
        ("gmail", "APP_PASSWORD"),
        ("wazuh", "PASSWORD"),
    ):
        api_keys[(service, key_name)] = db.get_api_key(service, key_name)

    # settings: plain-text key-value dict for the form value=… attributes.
    settings_kv = {}
    for key in (
        "telegram_it_chat_id", "telegram_manager_chat_id",
        "gmail_address", "it_admin_email",
        "wazuh_api_url", "wazuh_api_user", "alert_focus_mode",
    ):
        settings_kv[key] = db.get_setting(key)

    # Round F (§17.1) — service status data for the redesigned cards.
    # service_status: per-service "online"/"offline" baseline from completeness.
    #   F2 will overlay 10-min live-Test overrides via session["service_test_overrides"].
    # service_active: per-service toggle state for the 2 Telegram cards.
    #   Default: True (no entry = active). Only "0" disables.
    service_status = db.get_service_completeness()
    service_active = {
        svc: (db.get_setting(f"service_active.{svc}") != "0")
        for svc in ("telegram_it", "telegram_manager")
    }

    return render_template(
        "settings.html",
        providers=providers,
        api_keys=api_keys,
        settings_kv=settings_kv,
        service_status=service_status,
        service_active=service_active,
        email_enabled=config.EMAIL_ENABLED,
        provider_templates=config.PROVIDER_TEMPLATES,
        provider_templates_json=_json.dumps(config.PROVIDER_TEMPLATES),
        # Audit Log tab data — audit.html partial expects these names
        rows=audit_rows,
        filter_actor=audit_filters["actor"],
        filter_action=audit_filters["action"],
        filter_from=audit_filters["from"],
        filter_to=audit_filters["to"],
        # Backups tab data — backups.html partial expects `backups`
        backups=backups_list,
        # Errors tab data — errors.html partial expects these names
        error_rows=error_rows,
        filter_source=error_filters["source"],
        filter_module=error_filters["module"],
        filter_error_from=error_filters["from"],
        filter_error_to=error_filters["to"],
        user=current_user,
    )

# ── /admin/settings/api-keys (Round 3 — encrypted credential CRUD + reveal) ─

# The only (service, key_name) pairs this app actually stores — the same four
# that db.bootstrap_settings_from_env seeds and that notifier/wazuh read back.
# The three routes below took both halves straight from the URL and the form
# with no validation, so an IT session could mint unlimited junk api_keys rows
# or overwrite wazuh:PASSWORD / telegram_it:BOT_TOKEN to hijack the Wazuh client
# and notification delivery. Their sibling routes already gate on
# _SETTINGS_WRITE_ALLOWLIST / _TOGGLEABLE_SERVICES / _TESTABLE_SERVICES; this is
# the missing fourth.
_API_KEY_ALLOWLIST = frozenset({
    ("telegram_it", "BOT_TOKEN"),
    ("telegram_manager", "BOT_TOKEN"),
    ("gmail", "APP_PASSWORD"),
    ("wazuh", "PASSWORD"),
})

def _reject_unknown_api_key(service: str, key_name: str):
    """None if the pair is known, else a 400 JSON response."""
    if (service, key_name) in _API_KEY_ALLOWLIST:
        return None
    logger.warning(
        "Rejected api_key write for unknown pair %s:%s (actor=%s)",
        service, key_name, getattr(current_user, "username", "?"),
    )
    return jsonify({
        "error": f"unknown credential '{service}:{key_name}'",
        "allowed": sorted(f"{s}:{k}" for s, k in _API_KEY_ALLOWLIST),
    }), 400

@bp.route("/admin/settings/api-keys/<service>", methods=["POST"])
@login_required
@role_required("IT_ADMIN")
def admin_settings_set_api_key(service):
    if not verify_csrf():
        return jsonify({"error": "csrf"}), 403
    key_name = request.form.get("key_name") or "API_KEY"
    rejected = _reject_unknown_api_key(service, key_name)
    if rejected:
        return rejected
    plaintext = request.form.get("plaintext") or ""
    db.set_api_key(service, key_name, plaintext)
    _request_cache.invalidate_request_cache()
    last4 = plaintext[-4:] if len(plaintext) >= 4 else "????"
    db.log_audit(
        action="setting.update.api_key",
        actor=current_user.username,
        actor_role=current_user.role,
        target=f"{service}:{key_name}",
        ip=request.remote_addr,
        details={"last4": last4 if plaintext else "(cleared)"},
    )
    flash(f"{service} {key_name} saved.", "success")
    return redirect(url_for("admin_settings.admin_settings", tab="service"))

@bp.route("/admin/settings/api-keys/<service>/delete", methods=["POST"])
@login_required
@role_required("IT_ADMIN")
def admin_settings_delete_api_key(service):
    if not verify_csrf():
        return jsonify({"error": "csrf"}), 403
    key_name = request.form.get("key_name") or "API_KEY"
    rejected = _reject_unknown_api_key(service, key_name)
    if rejected:
        return rejected
    ok = db.delete_api_key(service, key_name)
    _request_cache.invalidate_request_cache()
    db.log_audit(
        action="setting.delete.api_key",
        actor=current_user.username,
        actor_role=current_user.role,
        target=f"{service}:{key_name}",
        ip=request.remote_addr,
        details={"removed": bool(ok)},
    )
    flash(f"{service} {key_name} deleted." if ok else f"{service} {key_name} not found.",
          "success" if ok else "warning")
    return redirect(url_for("admin_settings.admin_settings", tab="service"))

@bp.route("/admin/settings/api-keys/<service>/reveal", methods=["POST"])
@login_required
@role_required("IT_ADMIN")
def admin_settings_reveal_api_key(service):
    """CSRF-protected. Returns JSON with the decrypted plaintext value
    (one-shot — the client re-masks after 10s setTimeout)."""
    if not verify_csrf():
        return jsonify({"error": "csrf"}), 403
    # This is the one endpoint that hands back a decrypted credential. The
    # audit row below attributes every reveal; the cap stops a hijacked session
    # from walking the whole key table in one burst. settings.js already toasts
    # on !r.ok, so a 429 needs no client change.
    allowed, _retry = rate_limit.can_call(
        f"reveal:{current_user.username}", limit_per_min=5
    )
    if not allowed:
        return jsonify({"error": "rate_limited"}), 429
    key_name = request.form.get("key_name") or "API_KEY"
    rejected = _reject_unknown_api_key(service, key_name)
    if rejected:
        return rejected
    plaintext = db.get_api_key(service, key_name)
    if plaintext is None:
        return jsonify({"error": "not_found"}), 404
    last4 = plaintext[-4:] if len(plaintext) >= 4 else "????"
    db.log_audit(
        action="setting.reveal.api_key",
        actor=current_user.username,
        actor_role=current_user.role,
        target=f"{service}:{key_name}",
        ip=request.remote_addr,
        details={"last4": last4},
    )
    return jsonify({"value": plaintext})

# ── /admin/settings/ai-providers (Round 3 — provider CRUD + reorder) ────────

def _reject_unsafe_base_url(base_url: str) -> str | None:
    """
    None if the URL is a safe outbound target, else the flash message.

    base_url is free text that the AI chain then makes server-side requests to,
    so an IT session could aim it at 127.0.0.1 or a cloud metadata endpoint and
    read the response back out of the provider test. Providers are public HTTPS
    APIs; nothing legitimate lives on a private address.
    """
    import ipaddress
    from urllib.parse import urlsplit

    parts = urlsplit(base_url)
    if parts.scheme != "https" or not parts.hostname:
        return "Provider base_url must be an https:// URL with a hostname."

    host = parts.hostname
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # A DNS name.
        # ponytail: only the obvious internal names are blocked. Ceiling: a
        # name that resolves to a private address still gets through, so this
        # narrows SSRF rather than closing it. Upgrade: resolve-then-pin at
        # request time, which belongs in the HTTP client, not in a form
        # validator — do it if provider base_url ever becomes settable by
        # anyone less trusted than an IT_ADMIN.
        if host.lower() in {"localhost", "metadata.google.internal"}:
            return f"Provider base_url may not point at {host}."
        return None

    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        return f"Provider base_url may not point at the internal address {host}."
    return None

@bp.route("/admin/settings/ai-providers/add", methods=["POST"])
@login_required
@role_required("IT_ADMIN")
def admin_settings_provider_add():
    if not verify_csrf():
        return jsonify({"error": "csrf"}), 403
    label = (request.form.get("label") or "").strip()
    model = (request.form.get("model") or "").strip()
    api_key = request.form.get("api_key") or ""
    base_url = (request.form.get("base_url") or "").strip()
    auth_header = (request.form.get("auth_header") or "Authorization").strip()
    auth_prefix = request.form.get("auth_prefix") or ""
    request_format = (request.form.get("request_format") or "openai_compat").strip()

    if not (label and model and api_key and base_url and auth_header and request_format):
        flash("Missing required field(s) for provider.", "error")
        return redirect(url_for("admin_settings.admin_settings", tab="service"))

    error = _reject_unsafe_base_url(base_url)
    if error:
        flash(error, "error")
        return redirect(url_for("admin_settings.admin_settings", tab="service"))

    if db.provider_label_exists(label):
        flash(f"A provider labelled '{label}' already exists.", "error")
        return redirect(url_for("admin_settings.admin_settings", tab="service"))

    try:
        new_id = db.add_provider(
            label=label, model=model, api_key=api_key,
            base_url=base_url, auth_header=auth_header,
            auth_prefix=auth_prefix, request_format=request_format,
            is_active=1,
        )
    except Exception as e:
        logger.warning("provider add failed (label=%s): %s", label, e)
        flash(f"Provider add failed ({type(e).__name__}).", "error")
        return redirect(url_for("admin_settings.admin_settings", tab="service"))

    _request_cache.invalidate_request_cache()
    db.log_audit(
        action="provider.add", actor=current_user.username,
        actor_role=current_user.role,
        target=f"ai_providers:{new_id}",
        ip=request.remote_addr,
        details={"label": label, "model": model, "request_format": request_format},
    )
    flash(f"Provider '{label}' added.", "success")
    return redirect(url_for("admin_settings.admin_settings", tab="service"))

@bp.route("/admin/settings/ai-providers/<int:provider_id>/move", methods=["POST"])
@login_required
@role_required("IT_ADMIN")
def admin_settings_provider_move(provider_id):
    if not verify_csrf():
        return jsonify({"error": "csrf"}), 403
    direction = (request.form.get("direction") or "").strip()
    if direction not in ("up", "down"):
        flash("Invalid direction.", "error")
        return redirect(url_for("admin_settings.admin_settings", tab="service"))
    ok = db.move_provider(provider_id, direction)
    _request_cache.invalidate_request_cache()
    db.log_audit(
        action="provider.move", actor=current_user.username,
        actor_role=current_user.role,
        target=f"ai_providers:{provider_id}",
        ip=request.remote_addr,
        details={"direction": direction, "moved": bool(ok)},
    )
    return redirect(url_for("admin_settings.admin_settings", tab="service"))

@bp.route("/admin/settings/ai-providers/<int:provider_id>/toggle", methods=["POST"])
@login_required
@role_required("IT_ADMIN")
def admin_settings_provider_toggle(provider_id):
    if not verify_csrf():
        return jsonify({"error": "csrf"}), 403
    new_state = db.toggle_provider_active(provider_id)
    _request_cache.invalidate_request_cache()
    db.log_audit(
        action="provider.toggle", actor=current_user.username,
        actor_role=current_user.role,
        target=f"ai_providers:{provider_id}",
        ip=request.remote_addr,
        details={"is_active": new_state},
    )
    flash(f"Provider {'activated' if new_state else 'deactivated'}.", "success")
    return redirect(url_for("admin_settings.admin_settings", tab="service"))

@bp.route("/admin/settings/ai-providers/<int:provider_id>/delete", methods=["POST"])
@login_required
@role_required("IT_ADMIN")
def admin_settings_provider_delete(provider_id):
    if not verify_csrf():
        return jsonify({"error": "csrf"}), 403
    ok = db.delete_provider(provider_id)
    _request_cache.invalidate_request_cache()
    db.log_audit(
        action="provider.delete", actor=current_user.username,
        actor_role=current_user.role,
        target=f"ai_providers:{provider_id}",
        ip=request.remote_addr,
        details={"removed": bool(ok)},
    )
    flash("Provider deleted." if ok else "Provider not found.",
          "success" if ok else "warning")
    return redirect(url_for("admin_settings.admin_settings", tab="service"))

# ── /admin/settings/<key> (Round 3 — plain-text setting upsert) ─────────────
# Allowlist of keys the Settings UI is permitted to write. Prevents form-
# injection from creating arbitrary settings rows.

_SETTINGS_WRITE_ALLOWLIST = {
    "telegram_it_chat_id",
    "telegram_manager_chat_id",
    "gmail_address",
    "it_admin_email",
    "wazuh_api_url",
    "wazuh_api_user",
    "alert_focus_mode",   # "1" = Hide-low also hides MEDIUM; anything else = off
}

@bp.route("/admin/settings/<key>", methods=["POST"])
@login_required
@role_required("IT_ADMIN")
def admin_settings_set_setting(key):
    if not verify_csrf():
        return jsonify({"error": "csrf"}), 403
    if key not in _SETTINGS_WRITE_ALLOWLIST:
        abort(404)
    value = request.form.get("value") or ""
    # The AI provider base_url has been validated since it shipped; this field
    # is the same shape of hazard and had nothing. wazuh_api.py sends
    # auth=(user, password) to whatever this holds, and the 30-second agent
    # poller repeats it forever with no further interaction — so pointing it at
    # an attacker host exfiltrates the Wazuh credentials continuously, and at
    # 127.0.0.1 or a metadata endpoint it is a plain SSRF primitive.
    if key == "wazuh_api_url" and value:
        rejected = _reject_unsafe_base_url(value)
        if rejected:
            flash(rejected, "error")
            return redirect(
                url_for("admin_settings.admin_settings", tab="service"))
    db.set_setting(key, value)
    _request_cache.invalidate_request_cache()
    db.log_audit(
        action="setting.update", actor=current_user.username,
        actor_role=current_user.role,
        target=f"settings:{key}",
        ip=request.remote_addr,
        details={"value": value},
    )
    if key == "alert_focus_mode":
        flash(f"Focus Mode {'on' if value == '1' else 'off'}.", "success")
    else:
        flash(f"{key} saved.", "success")
    return redirect(url_for("admin_settings.admin_settings", tab="service"))

# ── /admin/settings/toggle/<service> (Round F §17.1c) ───────────────────────
# Toggle Telegram services on/off without deleting credentials.
# Backed by settings_kv `service_active.<svc>` flag — notifier.py reads
# the same flag via _service_is_active() to gate dispatch.
# AI providers have their own toggle (admin_settings_provider_toggle); this
# is for the 2 notification-channel services only.
_TOGGLEABLE_SERVICES = ("telegram_it", "telegram_manager")

@bp.route("/admin/settings/toggle/<service>", methods=["POST"])
@login_required
@role_required("IT_ADMIN")
def admin_settings_toggle_service(service):
    if not verify_csrf():
        return jsonify({"error": "csrf"}), 403
    if service not in _TOGGLEABLE_SERVICES:
        # 400 not 404: the URL pattern matched, but the service isn't toggleable.
        return jsonify({"error": f"service '{service}' is not toggleable",
                        "toggleable": list(_TOGGLEABLE_SERVICES)}), 400
    key = f"service_active.{service}"
    current = db.get_setting(key)
    # Default state is "active" — only the literal "0" disables. Any other
    # value (None / "1" / never-set) flips to "0" on toggle.
    new_value = "1" if current == "0" else "0"
    db.set_setting(key, new_value)
    db.log_audit(
        action="SERVICE_TOGGLE",
        actor=current_user.username,
        actor_role=current_user.role,
        target=f"service:{service}",
        ip=request.remote_addr,
        details=f"is_active={new_value}",
    )
    state_word = "activated" if new_value == "1" else "deactivated"
    pretty = service.replace('_', ' ').title()

    # Round F §17.6 F5: respond with JSON when the AJAX form-handler is the
    # caller (data-async-submit in ui.js sends Accept: application/json).
    # The HTML/no-JS fallback still gets the redirect + flash.
    if "application/json" in (request.headers.get("Accept") or ""):
        return jsonify({
            "success": True,
            "is_active": new_value == "1",
            "message": f"{pretty} {state_word}.",
        })
    flash(f"{pretty} {state_word}.", "success")
    return redirect(url_for("admin_settings.admin_settings", tab="service"))

# ── /admin/settings/test/<service> (Round F §17.6 Stage F2) ─────────────────
# Live probe — credential validity check ONLY. None of these probes send a
# real notification or cost credits:
#   telegram_it     → Bot API getMe (validates token, no message)
#   telegram_manager→ Bot API getMe
#   gmail           → SMTP login + immediate quit (no email sent)
#   wazuh           → API authenticate + GET /agents?limit=1
#
# Rate-limited 1 test per (service, IP) per 60s to prevent hammering the
# external services. Logs SERVICE_TEST_RUN to audit_log on every call
# (even rate-limited ones — operators should see attempts).
_TESTABLE_SERVICES = (
    "telegram_it", "telegram_manager", "gmail", "wazuh",
)
# The sliding-window length handed to rate_limit.can_call below. Named
# _TEST_RATELIMIT_S while it was the interval of a hand-rolled
# {(service, ip): last_run_ts} dict; that dict is gone and this is now just a
# window width, so it reads as one.
_TEST_WINDOW_S = 60

def _probe_error(prefix: str, e: Exception) -> str:
    """
    User-safe message for a failed credential probe.

    The exception's str() routinely embeds the full request URL, and the
    Telegram probe URL contains the bot token in its path. That string was
    returned as JSON, rendered into a toast, AND written to audit_log.details —
    which is downloadable at /admin/audit.csv. Only the exception class name
    crosses the boundary now; the detail stays in the server log.
    """
    logger.warning("%s probe failed", prefix, exc_info=True)
    return f"{prefix}: probe failed ({type(e).__name__}) — see the server log for detail"

def _test_service_probe(service: str) -> tuple[str, str]:
    """Run the per-service credential probe.

    Returns ('online'|'offline', human-readable message). The Test button
    bypasses the active-toggle (passes bypass_toggle=True where applicable)
    so a deactivated service can still be probed — the operator may be
    re-validating credentials before re-activating.
    """
    if service in ("telegram_it", "telegram_manager"):
        import requests
        token = db.get_api_key(service, "BOT_TOKEN")
        if not token:
            return "offline", f"{service}: bot token not configured"
        try:
            r = requests.get(
                f"https://api.telegram.org/bot{token}/getMe", timeout=5,
            )
            data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            if r.status_code == 200 and data.get("ok"):
                bot = data.get("result", {})
                return "online", f"Bot @{bot.get('username', '?')} reachable (token valid)"
            desc = data.get("description") or f"HTTP {r.status_code}"
            return "offline", f"Telegram: {desc}"
        except Exception as e:
            return "offline", _probe_error("Telegram", e)

    if service == "gmail":
        import smtplib
        addr = db.get_setting("gmail_address")
        pwd = db.get_api_key("gmail", "APP_PASSWORD")
        if not addr or not pwd:
            return "offline", "Gmail: from-address or app password not set"
        try:
            with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as smtp:
                # Verified TLS: bare starttls() is CERT_NONE. See notifier.py.
                smtp.starttls(context=ssl.create_default_context())
                smtp.login(addr, pwd)
            return "online", f"Gmail: SMTP login succeeded for {addr}"
        except smtplib.SMTPAuthenticationError:
            return "offline", "Gmail: authentication failed (check app password)"
        except Exception as e:
            return "offline", _probe_error("Gmail", e)

    if service == "wazuh":
        import requests
        url = db.get_setting("wazuh_api_url")
        user = db.get_setting("wazuh_api_user")
        pwd = db.get_api_key("wazuh", "PASSWORD")
        if not (url and user and pwd):
            return "offline", "Wazuh: URL, user, or password not set"
        try:
            auth = requests.post(
                f"{url}/security/user/authenticate",
                auth=(user, pwd), verify=config.WAZUH_API_VERIFY, timeout=5,
            )
            if auth.status_code != 200:
                return "offline", f"Wazuh: auth returned HTTP {auth.status_code}"
            token = auth.json().get("data", {}).get("token", "")
            agents = requests.get(
                f"{url}/agents?limit=1",
                headers={"Authorization": f"Bearer {token}"},
                verify=config.WAZUH_API_VERIFY, timeout=5,
            )
            if agents.status_code == 200:
                return "online", f"Wazuh: API reachable at {url}"
            return "offline", f"Wazuh: agents endpoint returned HTTP {agents.status_code}"
        except Exception as e:
            return "offline", _probe_error("Wazuh", e)

    return "offline", f"Unknown service: {service}"

@bp.route("/admin/settings/test/<service>", methods=["POST"])
@login_required
@role_required("IT_ADMIN")
def admin_settings_test_service(service):
    if not verify_csrf():
        return jsonify({"error": "csrf"}), 403
    if service not in _TESTABLE_SERVICES:
        return jsonify({"error": f"service '{service}' not testable",
                        "testable": list(_TESTABLE_SERVICES)}), 400

    # Was a module-level {(service, ip): unix_ts} dict, which meant the "1 test
    # per 60s" budget was really 1 per worker per 60s. rate_limit is the same
    # sliding window, shared across workers.
    allowed, retry_after_s = rate_limit.can_call(
        f"svctest:{service}:{request.remote_addr or ''}",
        limit_per_min=1,
        window_seconds=_TEST_WINDOW_S,
    )
    if not allowed:
        retry_after = int(retry_after_s) + 1
        # Audit the rate-limited attempt too — operators should see attempts.
        db.log_audit(
            action="SERVICE_TEST_RUN",
            actor=current_user.username,
            actor_role=current_user.role,
            target=f"service:{service}",
            ip=request.remote_addr,
            details=f"result=rate_limited retry_after={retry_after}s",
        )
        return jsonify({
            "status": "rate_limited",
            "retry_after": retry_after,
            "message": f"Test ran recently. Wait {retry_after}s and try again.",
        }), 429

    status, message = _test_service_probe(service)

    db.log_audit(
        action="SERVICE_TEST_RUN",
        actor=current_user.username,
        actor_role=current_user.role,
        target=f"service:{service}",
        ip=request.remote_addr,
        details=f"result={status} message={message[:200]}",
    )
    return jsonify({"status": status, "message": message})

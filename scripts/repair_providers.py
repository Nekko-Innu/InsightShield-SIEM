#!/usr/bin/env python3
# scripts/repair_providers.py
# Insight Shield — one-shot AI-provider repair for an already-bootstrapped box.
#
#   cd /opt/insightshield/insightshield
#   sudo -u insightshield venv/bin/python scripts/repair_providers.py
#
# Why this exists: bootstrap_settings_from_env() is idempotent (it no-ops once
# 'bootstrap_complete' is set), so fixing a bad model slug in config.py does NOT
# touch a DB that already seeded the bad value. This script repairs the live
# ai_providers table:
#   1. Rewrite any model in config.KNOWN_BAD_AI_MODELS to the valid default for
#      that provider's label (the dead OpenRouter/gemma slugs that made every
#      call 400 and read as "rate limiting").
#   2. If GROQ_API_KEY is set, ensure an active Groq provider exists at
#      position 0 — the fast provider that fits the 5s ingest budget so
#      HIGH/CRITICAL translations actually come back live instead of static.
#
# Idempotent: safe to run repeatedly. Never deletes a provider.

import os
import sys

# Run from the app dir so db.py resolves insightshield.db against the right CWD
# (same convention as the systemd unit's WorkingDirectory).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
import db

# Correct default model per provider label (lower-cased).
_DEFAULT_MODEL_BY_LABEL = {
    "groq":       config.GROQ_MODEL,
    "openrouter": config.OPENROUTER_MODEL,
    "gemini":     config.GEMINI_MODEL,
}


def _fix_known_bad_models() -> int:
    fixed = 0
    for p in db.list_all_providers():
        if p["model"] in config.KNOWN_BAD_AI_MODELS:
            good = _DEFAULT_MODEL_BY_LABEL.get(p["label"].lower())
            if not good:
                print(f"  ! {p['label']} (id={p['id']}) has bad model "
                      f"{p['model']!r} but no known default for this label — "
                      f"fix it in the Settings UI")
                continue
            db.update_provider(p["id"], model=good)
            print(f"  fixed {p['label']} (id={p['id']}): {p['model']!r} -> {good!r}")
            fixed += 1
    return fixed


def _ensure_groq_primary() -> None:
    key = os.environ.get("GROQ_API_KEY", "").strip()
    if not key:
        print("  GROQ_API_KEY not set — skipping Groq provisioning "
              "(set it in .env and re-run to make Groq the primary provider)")
        return

    groq = next((p for p in db.list_all_providers()
                 if p["label"].lower() == "groq"), None)
    if groq is None:
        tmpl = config.PROVIDER_TEMPLATES["Groq"]
        gid = db.add_provider(
            label="Groq", model=config.GROQ_MODEL, api_key=key,
            base_url=tmpl["base_url"], auth_header=tmpl["auth_header"],
            auth_prefix=tmpl["auth_prefix"], request_format=tmpl["request_format"],
            is_active=1,
        )
        print(f"  added Groq (id={gid}, model={config.GROQ_MODEL})")
    else:
        gid = groq["id"]
        if not groq["is_active"]:
            db.update_provider(gid, is_active=1)
            print(f"  activated Groq (id={gid})")
        if not groq.get("api_key"):
            db.update_provider(gid, api_key=key)
            print(f"  set Groq api_key from env (id={gid})")

    # Walk Groq up to position 0 so the fast provider is tried first.
    moved = 0
    while db.move_provider(gid, "up"):
        moved += 1
    if moved:
        print(f"  moved Groq to primary (position 0), {moved} swap(s)")


def _print_state() -> None:
    print("\nFinal ai_providers:")
    print(f"  {'id':>3}  {'label':<12} {'model':<40} {'active':>6} {'pos':>3}")
    for p in db.list_all_providers():
        print(f"  {p['id']:>3}  {p['label']:<12} {p['model']:<40} "
              f"{int(bool(p['is_active'])):>6} {p['position']:>3}")


def main() -> int:
    print("=== Insight Shield AI-provider repair ===")
    print("Fixing known-bad model slugs...")
    n = _fix_known_bad_models()
    print(f"  {n} row(s) rewritten" if n else "  none needed")
    print("Ensuring Groq is present and primary...")
    _ensure_groq_primary()
    _print_state()
    print("\nDone. Restart the app (scripts/update.sh) for a fresh provider read.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

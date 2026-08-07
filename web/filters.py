# web/filters.py
# Jinja template filters and globals.

import json
import os
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from flask import request, url_for

from alerts_util import derive_attacker_ip

PHT = ZoneInfo("Asia/Manila")


def from_json_filter(value):
    """Parse a JSON string into a dict/list for Jinja. Returns {} on failure."""
    if not value:
        return {}
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return {}


def pretty_json_filter(value):
    """Pretty-print a JSON value with 2-space indent for the Raw JSON tab.
    Accepts a JSON-encoded string OR an already-parsed dict/list; falls back
    to str(value) on parse failure so the tab still renders something."""
    if value is None or value == "":
        return ""
    try:
        if isinstance(value, str):
            value = json.loads(value)
        return json.dumps(value, indent=2, ensure_ascii=False)
    except (ValueError, TypeError):
        return str(value)


def forensic_ts_filter(value):
    """Render a timestamp as 'Apr 15, 2026 @ 17:12:34.567' in Asia/Manila.
    Accepts ISO-8601 strings, datetime objects, or epoch numerics.
    Returns '—' on null/empty; falls back to str(value) on parse failure."""
    if value is None or value == "":
        return "—"
    try:
        if isinstance(value, (int, float)):
            dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
        elif isinstance(value, datetime):
            dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        else:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(PHT)
        day_fmt = "%#d" if os.name == "nt" else "%-d"
        return dt.strftime(f"%b {day_fmt}, %Y @ %H:%M:%S") + f".{dt.microsecond // 1000:03d}"
    except Exception:
        return str(value)


def url_with(**overrides) -> str:
    """Current URL with some query-string args replaced. For pager and filter
    links, so a page-2 anchor keeps whatever filters are already applied.
    Passing None drops an arg entirely."""
    args = request.args.to_dict()
    args.update(overrides)
    return url_for(request.endpoint, **{k: v for k, v in args.items() if v not in (None, "")})


def init_app(app) -> None:
    app.add_template_filter(from_json_filter, "from_json")
    app.add_template_filter(pretty_json_filter, "pretty_json")
    app.add_template_filter(forensic_ts_filter, "forensic_ts")
    app.jinja_env.globals["derive_attacker_ip"] = derive_attacker_ip
    app.jinja_env.globals["url_with"] = url_with


def humanize_seconds(s) -> str:
    """Render a seconds value in the largest unit that keeps the number small:
    <60s → '45s', <1h → '12m 34s', <1d → '4h 53m', ≥1d → '3d 7h'.
    Used by the 24h MTTA KPI so 283220s reads as '3d 7h' instead of a
    barely-parseable seconds count."""
    try:
        s = float(s)
    except (TypeError, ValueError):
        return "—"
    if s < 0:
        return "—"
    if s < 60:
        return f"{int(s)}s"
    if s < 3600:
        m, sec = divmod(int(s), 60)
        return f"{m}m {sec}s"
    if s < 86400:
        h, rem = divmod(int(s), 3600)
        m = rem // 60
        return f"{h}h {m}m"
    d, rem = divmod(int(s), 86400)
    h = rem // 3600
    return f"{d}d {h}h"

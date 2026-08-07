# agent_status.py
# Insight Shield — Round 5 (Part 5: Dynamic agent status)
#
# Owns the cached agent-status snapshot and the state computation that
# decides green/amber/red. The 30-second refresh is driven by APScheduler
# (see scheduler.py); request handlers NEVER call Wazuh — they just read
# the cached snapshot. This means /api/status responds in microseconds
# even when Wazuh is slow or unreachable.
#
# Three states, per master spec Part 5:
#   green  : Wazuh manager reachable AND every agent.status == "active"
#   amber  : Wazuh manager reachable AND >=1 agent NOT active
#   red    : Wazuh manager unreachable (network/auth/timeout)
#
# Storing the snapshot IS the notification: /api/events/stream watches the
# settings row's updated_at and emits an agent_status event when it moves.

import json
import logging
from datetime import datetime, timezone

import config
import db
from wazuh_api import get_agent_status

logger = logging.getLogger("insightshield.agent_status")

# The snapshot lives in the settings table, not in a module global. The writer
# is the scheduler process (insightshield-worker.service); the readers are every
# gunicorn worker. A dict could only ever be seen by the one process that filled
# it, so with workers > 1 most /api/status calls hit a worker that had never
# polled Wazuh and answered with the boot-time default forever.
SNAPSHOT_KEY = "agent_status.snapshot"

# 3x the 30s poll interval. Past this the writer is presumed dead, and a dead
# writer must not leave the login page showing a stale green "All systems
# operational" — which is exactly what the in-memory version did, with no way
# to tell the difference.
STALE_AFTER_S = 90

# Served before the first refresh runs, and whenever the stored snapshot is
# missing, unparseable or stale. dot_color="red" is the safe default: an app
# that has not successfully polled Wazuh should NOT advertise that everything
# is fine.
_SNAPSHOT_DEFAULT: dict = {
    "manager_status": "unknown",
    "summary":        "Status unavailable — checking…",
    "dot_color":      "red",
    "agents_online":  0,
    "agents_total":   0,
    "agents":         [],
    "updated_at":     None,
}


def _compute_state(manager_reachable: bool, agents: list[dict]) -> dict:
    """Pure function — given Wazuh reachability and an agent list, return
    the snapshot dict. No side effects, easy to unit-test."""
    total = len(agents)
    online = sum(1 for a in agents if (a.get("status") or "").lower() == "active")

    if not manager_reachable:
        return {
            "manager_status": "offline",
            "summary":        "Wazuh manager unreachable",
            "dot_color":      "red",
            "agents_online":  0,
            "agents_total":   total,
            "agents":         [{"name": a.get("name", "?"), "online": False} for a in agents],
        }

    offline = total - online
    if offline == 0:
        summary = "All systems operational"
        color = "green"
    else:
        summary = f"{offline} agent{'s' if offline != 1 else ''} offline"
        color = "amber"

    return {
        "manager_status": "online",
        "summary":        summary,
        "dot_color":      color,
        "agents_online":  online,
        "agents_total":   total,
        "agents": [
            {"name": a.get("name", "?"),
             "online": (a.get("status") or "").lower() == "active"}
            for a in agents
        ],
    }


def refresh() -> dict:
    """Pull fresh state from Wazuh and store it. Called by the 30s scheduler
    job (and once at boot).

    Never raises — Wazuh failures collapse into a red snapshot. The
    /api/status request path must never see an exception bubble out of
    the cached read.
    """
    manager_reachable = False
    agents: list[dict] = []
    try:
        agents = get_agent_status()
        # get_agent_status() returns the static fallback list when Wazuh is
        # unreachable — every entry has status="unknown". That's how we
        # detect manager_reachable: at least one agent must have a real
        # status string ("active" or "disconnected").
        manager_reachable = any(
            (a.get("status") or "").lower() in ("active", "disconnected", "never_connected", "pending")
            for a in agents
        )
    except Exception as e:
        logger.warning("agent_status.refresh: get_agent_status raised: %s", e)

    published = _compute_state(manager_reachable, agents)
    published["updated_at"] = datetime.now(timezone.utc).isoformat()

    # The write itself is the notification: /api/events/stream watches this
    # row's updated_at and emits an agent_status event when it moves. No
    # publish step, and it reaches every worker rather than only this process.
    db.set_setting(SNAPSHOT_KEY, json.dumps(published))

    logger.info(
        "agent_status: %s (%d/%d online, manager=%s)",
        published["dot_color"], published["agents_online"],
        published["agents_total"], published["manager_status"],
    )
    return published


def get_snapshot() -> dict:
    """Return the current snapshot, or the red default if it cannot be trusted.

    One indexed primary-key read. Never raises — /api/status is unauthenticated
    and on the login page's critical path, so any failure here degrades to the
    safe default rather than a 500.
    """
    try:
        row = db.get_setting_row(SNAPSHOT_KEY)
        if row is None:
            return dict(_SNAPSHOT_DEFAULT)

        age = (datetime.now(tz=config.PHT)
               - datetime.fromisoformat(row["updated_at"])).total_seconds()
        if age > STALE_AFTER_S:
            logger.warning(
                "agent_status: snapshot is %.0fs old (>%ds) — is the scheduler "
                "process running?", age, STALE_AFTER_S,
            )
            return dict(_SNAPSHOT_DEFAULT)

        return json.loads(row["value"])
    except Exception as e:
        # Includes an unparseable updated_at: if we cannot say how old the
        # snapshot is, we cannot vouch for it, so it does not get served.
        logger.warning("agent_status.get_snapshot failed, serving default: %s", e)
        return dict(_SNAPSHOT_DEFAULT)

# wazuh_api.py
# Insight Shield — outbound calls to the Wazuh manager's REST API.
#
# Lives here rather than in app.py because agent_status.refresh needs it and
# runs in the scheduler process, which has no Flask routes. It used to do
# `from app import get_agent_status` inside the function to break the
# app -> scheduler -> agent_status -> app cycle; with the function in a leaf
# module there is no cycle to break.
#
# Credentials come from the DB (via _request_cache) rather than the environment
# so the operator can configure Wazuh in the Settings UI without a restart.
# _request_cache falls through to a direct DB read outside a request context,
# which is exactly the case here.

import logging

import requests

import config
import _request_cache

logger = logging.getLogger("insightshield.wazuh_api")


def get_agent_status() -> list[dict]:
    """
    Get Wazuh agent status. Tries the Wazuh REST API first, falls back to the
    static KNOWN_DEVICES list if the API is unreachable.

    Both calls carry timeout=5, so the worst case is 10s. Callers on a request
    path should treat that as real latency; agent_status.refresh runs it on a
    scheduler tick precisely so no request has to wait for it.
    """
    agents = []

    wazuh_url = _request_cache.cached_setting("wazuh_api_url")
    wazuh_user = _request_cache.cached_setting("wazuh_api_user")
    wazuh_password = _request_cache.cached_api_key("wazuh", "PASSWORD")
    if wazuh_password and wazuh_url and wazuh_user:
        try:
            # Authenticate to get token
            auth_resp = requests.post(
                f"{wazuh_url}/security/user/authenticate",
                auth=(wazuh_user, wazuh_password),
                verify=config.WAZUH_API_VERIFY,
                timeout=5,
            )
            if auth_resp.status_code == 200:
                token = auth_resp.json().get("data", {}).get("token", "")
                # Get agents list
                agents_resp = requests.get(
                    f"{wazuh_url}/agents",
                    headers={"Authorization": f"Bearer {token}"},
                    verify=config.WAZUH_API_VERIFY,
                    timeout=5,
                )
                if agents_resp.status_code == 200:
                    for a in agents_resp.json().get("data", {}).get("affected_items", []):
                        agents.append({
                            "name": a.get("name", "Unknown"),
                            "ip": a.get("ip", "N/A"),
                            "os": a.get("os", {}).get("name", "N/A"),
                            "status": a.get("status", "disconnected"),
                            "agent_type": "Wazuh Agent",
                            "last_keepalive": a.get("lastKeepAlive", "N/A"),
                        })
                    logger.info("Wazuh API: retrieved %d agents", len(agents))
                    return agents
        except Exception as e:
            logger.warning("Wazuh API unreachable: %s. Using static device list.", e)

    # Fallback: static device list from config
    for device in config.KNOWN_DEVICES:
        agents.append({
            "name": device,
            "ip": "N/A",
            "os": "N/A",
            "status": "unknown",
            "agent_type": "Wazuh Agent (status unavailable)",
            "last_keepalive": "N/A",
        })
    return agents

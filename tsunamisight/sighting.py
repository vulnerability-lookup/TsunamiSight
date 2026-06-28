"""Thin wrapper around PyVulnerabilityLookup.create_sighting with error mapping."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from tsunamisight.monitoring import log as monitoring_log

logger = logging.getLogger(__name__)

SOURCE_BASE = "https://github.com/google/tsunami-security-scanner-plugins/"


def build_source_url(plugin_relpath: str, kind: str = "java") -> str:
    ref = "blob" if kind == "templated" else "tree"
    return f"{SOURCE_BASE}{ref}/master/{plugin_relpath.lstrip('/')}"


def push_sighting(
    client: Any,
    *,
    plugin_relpath: str,
    cve: str,
    when: datetime,
    sighting_type: str,
    kind: str = "java",
) -> None:
    sighting = {
        "type": sighting_type,
        "source": build_source_url(plugin_relpath, kind),
        "vulnerability": cve,
        "creation_timestamp": when,
    }
    try:
        response = client.create_sighting(sighting=sighting)
    except Exception as exc:
        logger.warning("create_sighting raised: %s", exc)
        monitoring_log("warning", f"create_sighting raised: {exc}")
        return

    message = (response or {}).get("message", "") if isinstance(response, dict) else ""
    if not message:
        logger.info("sighting created: %s @ %s", cve, plugin_relpath)
        return
    if "duplicate" in message.lower():
        logger.info("duplicate sighting (%s @ %s): %s", cve, plugin_relpath, message)
        monitoring_log("info", f"duplicate: {cve} @ {plugin_relpath}")
    else:
        logger.warning("sighting response (%s @ %s): %s", cve, plugin_relpath, message)
        monitoring_log("warning", f"{cve} @ {plugin_relpath}: {message}")

"""TsunamiSight CLI entry point."""

from __future__ import annotations

import argparse
import logging
import subprocess
import sys
from pathlib import Path

from pyvulnerabilitylookup import PyVulnerabilityLookup

from tsunamisight import config
from tsunamisight.monitoring import heartbeat
from tsunamisight.monitoring import log as monitoring_log
from tsunamisight.parser import (
    discover_plugin_roots,
    extract_cves_for_plugin,
    first_commit_date,
)
from tsunamisight.sighting import push_sighting

logger = logging.getLogger("tsunamisight")


def _git_pull(repo: Path) -> bool:
    try:
        subprocess.run(["git", "pull"], cwd=repo, check=True, text=True)
        return True
    except subprocess.CalledProcessError as exc:
        logger.warning("git pull failed: %s", exc)
        return False


def _added_plugin_roots_since(repo: Path, since: str) -> set[str]:
    """Roots whose directories had files added within `since` (e.g. '7 days ago')."""
    try:
        result = subprocess.run(
            [
                "git",
                "log",
                f"--since={since}",
                "--diff-filter=A",
                "--name-only",
                "--format=",
            ],
            cwd=repo,
            check=True,
            text=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as exc:
        logger.warning("git log failed: %s", exc)
        return set()
    roots: set[str] = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        if "/src/main/java/" not in line:
            continue
        roots.add(line.split("/src/main/java/")[0])
    return roots


def _iter_plugins(repo: Path, roots_filter: set[str] | None):
    for abs_root, rel in discover_plugin_roots(repo):
        if roots_filter is not None and rel not in roots_filter:
            continue
        cves = extract_cves_for_plugin(abs_root, rel)
        if not cves:
            logger.debug("no CVEs extracted for %s — skipping", rel)
            continue
        when = first_commit_date(repo, rel)
        for cve in sorted(cves):
            yield rel, cve, when


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )

    parser = argparse.ArgumentParser(
        prog="TsunamiSight",
        description="Extract CVE references from the Tsunami plugins repo and publish sightings.",
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help="Full sweep: emit sightings for every CVE-bearing plugin.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and print (plugin, CVE, timestamp) triples without POSTing.",
    )
    args = parser.parse_args()

    logger.info("Starting TsunamiSight…")
    heartbeat()
    monitoring_log("info", "TsunamiSight started")

    repo = Path(config.tsunami_plugins_git_repository)
    if not repo.exists():
        logger.error("Plugins repo not found at %s", repo)
        sys.exit(1)

    if not _git_pull(repo):
        sys.exit(1)

    if args.init:
        filter_set: set[str] | None = None
    else:
        filter_set = _added_plugin_roots_since(repo, config.incremental_window)
        if not filter_set:
            logger.info(
                "No new plugin roots in last %s — nothing to do.",
                config.incremental_window,
            )
            return

    client = PyVulnerabilityLookup(
        config.vulnerability_lookup_base_url,
        token=config.vulnerability_auth_token,
    )

    emitted = 0
    for rel, cve, when in _iter_plugins(repo, filter_set):
        logger.info("NEW - %s -> %s (first commit: %s)", rel, cve, when)
        if args.dry_run:
            emitted += 1
            continue
        push_sighting(
            client,
            plugin_relpath=rel,
            cve=cve,
            when=when,
            sighting_type=config.sighting_type,
        )
        emitted += 1

    logger.info("TsunamiSight done — %d sighting(s) emitted.", emitted)
    monitoring_log("info", f"Done, {emitted} sightings emitted")


if __name__ == "__main__":
    main()

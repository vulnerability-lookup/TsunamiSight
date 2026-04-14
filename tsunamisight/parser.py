"""Discover Tsunami plugin roots and extract CVE references."""

from __future__ import annotations

import re
import subprocess
from datetime import datetime
from email.utils import parsedate_to_datetime
from pathlib import Path

PATH_CVE_RE = re.compile(r"(?i)cve[_-]?(20\d{2})[_-]?(\d{4,7})")
SETPUB_CVE_RE = re.compile(
    r'setPublisher\(\s*"CVE"\s*\)\s*\.\s*setValue\(\s*"(CVE-\d{4}-\d{4,7})"\s*\)'
)
SETVAL_ANY_CVE_RE = re.compile(r'setValue\(\s*"(CVE[_-]\d{4}[_-]\d{4,7})"\s*\)')

SKIP_PATH_SEGMENTS = ("/test/", "/build/")


def normalize_cve(raw: str) -> str:
    """CVE_2023_42793 / cve-2023-42793 / CVE-2023-42793 -> CVE-2023-42793."""
    return raw.upper().replace("_", "-")


def extract_cves_from_path(plugin_relpath: str) -> set[str]:
    return {
        f"CVE-{year}-{num}"
        for year, num in PATH_CVE_RE.findall(plugin_relpath)
    }


def extract_cves_from_java_source(body: str) -> set[str]:
    cves: set[str] = set()
    for m in SETPUB_CVE_RE.findall(body):
        cves.add(normalize_cve(m))
    for m in SETVAL_ANY_CVE_RE.findall(body):
        cves.add(normalize_cve(m))
    return cves


def _iter_detector_files(plugin_root: Path):
    for path in plugin_root.rglob("*Detector.java"):
        rel = str(path).replace("\\", "/")
        if any(seg in rel for seg in SKIP_PATH_SEGMENTS):
            continue
        if path.name.endswith("BootstrapModule.java"):
            continue
        yield path


def extract_cves_for_plugin(plugin_root: Path, plugin_relpath: str) -> set[str]:
    cves = extract_cves_from_path(plugin_relpath)
    for java_file in _iter_detector_files(plugin_root):
        try:
            cves |= extract_cves_from_java_source(java_file.read_text(errors="ignore"))
        except OSError:
            continue
    return cves


def discover_plugin_roots(repo_path: Path) -> list[tuple[Path, str]]:
    """Return list of (absolute_root, relative_path_from_repo) for each plugin directory.

    A 'plugin root' is the directory containing src/main/java and at least one *Detector.java.
    """
    roots: dict[Path, str] = {}
    for java in repo_path.rglob("*Detector.java"):
        rel = java.relative_to(repo_path).as_posix()
        if "/src/main/java/" not in rel:
            continue
        if any(seg in f"/{rel}" for seg in SKIP_PATH_SEGMENTS):
            continue
        root_rel = rel.split("/src/main/java/")[0]
        root_abs = repo_path / root_rel
        roots[root_abs] = root_rel
    return sorted(roots.items(), key=lambda kv: kv[1])


def first_commit_date(repo_path: Path, plugin_relpath: str) -> datetime | None:
    """First-commit date of any file under plugin_relpath, as UTC-aware datetime."""
    try:
        result = subprocess.run(
            [
                "git",
                "log",
                "--reverse",
                "--format=%aD",
                "--diff-filter=A",
                "--",
                plugin_relpath,
            ],
            cwd=repo_path,
            check=True,
            text=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError:
        return None
    first_line = result.stdout.splitlines()[0] if result.stdout.strip() else ""
    if not first_line:
        return None
    try:
        return parsedate_to_datetime(first_line)
    except (TypeError, ValueError):
        return None

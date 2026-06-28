"""Discover Tsunami plugin roots and extract CVE references."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Literal

PATH_CVE_RE = re.compile(r"(?i)cve[_-]?(20\d{2})[_-]?(\d{4,7})")
SETPUB_CVE_RE = re.compile(
    r'setPublisher\(\s*"CVE"\s*\)\s*\.\s*setValue\(\s*"(CVE-\d{4}-\d{4,7})"\s*\)'
)
SETVAL_ANY_CVE_RE = re.compile(r'setValue\(\s*"(CVE[_-]\d{4}[_-]\d{4,7})"\s*\)')
VALUE_CVE_RE = re.compile(r'value:\s*"(CVE[_-]\d{4}[_-]\d{4,7})"')

SKIP_PATH_SEGMENTS = ("/test/", "/build/")


@dataclass(frozen=True)
class Plugin:
    abs_path: Path  # directory (java) or file (templated)
    rel_path: str  # posix path from repo root
    kind: Literal["java", "templated"]


def is_templated_plugin_file(rel_path: str) -> bool:
    """True for a real templated plugin file (posix repo-relative path)."""
    if not rel_path.endswith(".textproto"):
        return False
    if rel_path.endswith("_test.textproto"):
        return False
    if any(seg in f"/{rel_path}" for seg in SKIP_PATH_SEGMENTS):
        return False
    return "/templateddetector/plugins/" in f"/{rel_path}"


def normalize_cve(raw: str) -> str:
    """CVE_2023_42793 / cve-2023-42793 / CVE-2023-42793 -> CVE-2023-42793."""
    return raw.upper().replace("_", "-")


def extract_cves_from_path(plugin_relpath: str) -> set[str]:
    return {f"CVE-{year}-{num}" for year, num in PATH_CVE_RE.findall(plugin_relpath)}


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


def extract_cves_for_templated(plugin_file: Path, plugin_relpath: str) -> set[str]:
    cves = extract_cves_from_path(plugin_relpath)
    try:
        body = plugin_file.read_text(errors="ignore")
    except OSError:
        return cves
    for raw in VALUE_CVE_RE.findall(body):
        cves.add(normalize_cve(raw))
    return cves


def extract_cves(plugin: Plugin) -> set[str]:
    if plugin.kind == "templated":
        return extract_cves_for_templated(plugin.abs_path, plugin.rel_path)
    return extract_cves_for_plugin(plugin.abs_path, plugin.rel_path)


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


def discover_plugins(repo_path: Path) -> list[Plugin]:
    """All plugins in the repo: Java detector dirs plus templated textproto files."""
    plugins: list[Plugin] = []
    for abs_root, rel in discover_plugin_roots(repo_path):
        plugins.append(Plugin(abs_path=abs_root, rel_path=rel, kind="java"))
    templated_root = repo_path / "templated" / "templateddetector" / "plugins"
    if templated_root.is_dir():
        for path in templated_root.rglob("*.textproto"):
            rel = path.relative_to(repo_path).as_posix()
            if not is_templated_plugin_file(rel):
                continue
            plugins.append(Plugin(abs_path=path, rel_path=rel, kind="templated"))
    return sorted(plugins, key=lambda p: p.rel_path)


def first_commit_date(repo_path: Path, plugin_relpath: str) -> datetime | None:
    """First-commit date of any file under plugin_relpath, as UTC-aware datetime."""
    try:
        result = subprocess.run(
            [
                "git",
                "log",
                "--reverse",
                "--format=%aD",
                "--",
                plugin_relpath,
            ],
            cwd=repo_path,
            check=True,
            text=True,
            capture_output=True,
        )
    except (subprocess.CalledProcessError, OSError):
        return None
    first_line = result.stdout.splitlines()[0] if result.stdout.strip() else ""
    if not first_line:
        return None
    try:
        return parsedate_to_datetime(first_line)
    except (TypeError, ValueError):
        return None

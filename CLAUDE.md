# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TsunamiSight is a Python CLI that extracts CVE references from Google's Tsunami Security Scanner plugin repository and publishes them as vulnerability sightings to a Vulnerability-Lookup instance via the PyVulnerabilityLookup API.

## Build & Development

Poetry is the build system (`poetry-core>=2.0`). Python 3.10+ required.

```bash
# Install in development mode with test dependencies
pip install -e '.[test]'

# Run all tests
python -m pytest -v

# Run a single test
python -m pytest tests/test_parser.py::test_extract_cves_from_path -v

# Run the CLI (requires TSUNAMISIGHT_CONFIG env var or falls back to conf_sample.py)
TsunamiSight --init          # full sweep of all plugins
TsunamiSight                 # incremental (only recent plugins)
TsunamiSight --dry-run       # parse without POSTing sightings

# Pre-commit hooks (black, isort, flake8, pyupgrade, pip-audit)
pre-commit run --all-files
```

## Code Style

- **Formatter**: Black (default settings)
- **Import sorting**: isort with `profile = "black"`
- **Linter**: flake8 with max-line-length=120 and flake8-bugbear + flake8-implicit-str-concat
- **Python target**: pyupgrade `--py310-plus` (use `from __future__ import annotations` in every module)
- Pre-commit hooks enforce all of the above on commit

## Architecture

The CLI entry point is `tsunamisight/main.py:main`, registered as the `TsunamiSight` console script.

**Flow**: `main` loads config -> pulls the tsunami-plugins git repo -> discovers plugin roots (directories with `*Detector.java` under `src/main/java/`) -> extracts CVEs from path names and Java source -> looks up first commit date per plugin -> pushes sightings to Vulnerability-Lookup (or prints in dry-run mode).

**Modules**:
- `main.py` — CLI args, git operations, orchestration loop. Two modes: `--init` (full sweep) vs incremental (only plugins with files added in the configured window).
- `parser.py` — CVE extraction via regex (`PATH_CVE_RE` for path segments, `SETPUB_CVE_RE`/`SETVAL_ANY_CVE_RE` for Java source). Also handles plugin root discovery and first-commit-date lookup via git.
- `sighting.py` — Builds sighting dicts and calls `PyVulnerabilityLookup.create_sighting`. Handles duplicate detection from API response messages.
- `config.py` — Dynamically imports a user config Python file from the path in `TSUNAMISIGHT_CONFIG` env var. Falls back to `conf_sample.py`.
- `monitoring.py` — Optional Valkey heartbeat and log forwarding. Silently disabled if Valkey is unreachable or `heartbeat_enabled` is false.

## Configuration

Configuration is a Python file loaded at import time via `TSUNAMISIGHT_CONFIG` env var. See `tsunamisight/conf_sample.py` for the template. Required attributes: `vulnerability_lookup_base_url`, `vulnerability_auth_token`, `tsunami_plugins_git_repository`, `sighting_type`.

## Docker

```bash
docker compose up --build    # builds image and runs --init
```

The container clones the tsunami plugins repo at build time. Mount a config file to `/etc/conf.py` (see `docker-compose.yml`).

# Design: Templated `.textproto` Plugin Support

**Date:** 2026-06-28
**Status:** Approved

## Problem

Google's `tsunami-security-scanner-plugins` repository has introduced a
"templated" plugin format under `templated/templateddetector/plugins/`. These
plugins are single `.textproto` files (e.g.
`templated/templateddetector/plugins/cve/2025/Jenkins_CVE_2025_47889.textproto`)
rather than Java directories.

TsunamiSight only discovers plugins via `discover_plugin_roots`, which requires a
`*Detector.java` file under `src/main/java/`. Templated plugins have neither, so
they are never discovered. As of this writing roughly 20 CVE-named templated
plugins (across `cve/2021`–`cve/2025`, plus CVE-bearing `exposedui/` plugins) are
silently skipped, and this is where Google is adding new plugins.

## Goal

Discover and emit sightings for templated `.textproto` plugins wherever a CVE can
be enumerated, mirroring the existing Java behavior ("scan everything, skip
plugins with no CVE").

## Approach

Unify Java and templated plugins under a single `Plugin` descriptor with a `kind`
discriminator. `discover_plugins` returns both kinds; a dispatcher routes CVE
extraction by kind. This keeps the downstream pipeline (`first_commit_date`,
`push_sighting`, source URL) on a single code path and isolates each plugin type
behind one interface.

Rejected alternatives:
- **Parallel functions + two loops in `main`** — duplicates the
  iterate→date→push glue, effectively reinventing the descriptor with worse
  ergonomics.
- **Folding textproto into `discover_plugin_roots`** — breaks that function's
  contract ("root = directory containing `src/main/java` and `*Detector.java`")
  and muddies its tests.

## Detailed Design

### 1. `Plugin` descriptor + unified discovery (`parser.py`)

```python
@dataclass(frozen=True)
class Plugin:
    abs_path: Path     # directory (java) or file (templated)
    rel_path: str      # posix path from repo root — source URL, git date, filter key
    kind: str          # "java" | "templated"
```

`discover_plugins(repo) -> list[Plugin]` combines:

- **java**: existing `discover_plugin_roots` logic, wrapped as
  `Plugin(dir, reldir, "java")`. `discover_plugin_roots` remains as the Java
  helper.
- **templated**: `repo.rglob("*.textproto")`, skipping `*_test.textproto` and the
  existing `SKIP_PATH_SEGMENTS` (`/test/`, `/build/`), wrapped as
  `Plugin(file, relfile, "templated")`.

Result sorted by `rel_path`.

### 2. CVE extraction (`parser.py`)

- `extract_cves_for_plugin(root, relpath)` — **unchanged** (path + `*Detector.java`
  source). Existing tests pin its `(Path, str)` signature.
- `extract_cves_for_templated(file, relpath)` — **new**:
  `extract_cves_from_path(relpath)` (catches `Jenkins_CVE_2025_47889` in the
  filename) ∪ CVEs from structured `value:` fields via
  `VALUE_CVE_RE = re.compile(r'value:\s*"(CVE-\d{4}-\d{4,7})"')` (catches both
  `main_id` and `related_id` values inside the file).

  Matching the structured `value:` field — rather than every CVE token in the body
  — avoids scraping unrelated CVEs mentioned in prose `description:`/`title:`
  lines, mirroring how the Java side targets `setValue(...)`.
- `extract_cves(plugin: Plugin) -> set[str]` — thin dispatcher on `plugin.kind`.

### 3. Incremental mode (`main.py`)

`_added_plugin_roots_since` currently only recognizes added files under
`/src/main/java/`. Extend it so that for each added line it also accepts a
non-test `*.textproto` path (skipping `/test/`, `/build/`) and adds the **file
path itself** as the unit key. Because templated discovery uses the file path as
`rel_path`, the filter in `_iter_plugins` matches naturally.

The textproto-detection predicate is extracted into a small pure helper so the
incremental logic becomes unit-testable (`main.py` has no tests today).

### 4. Orchestration (`main.py`)

`_iter_plugins` iterates `discover_plugins(repo)`, filters on `plugin.rel_path`,
calls `extract_cves(plugin)`, then the **unchanged** `first_commit_date(repo,
plugin.rel_path)` and `push_sighting`. `first_commit_date` and `build_source_url`
already operate correctly on a file path. `sighting.py` is unchanged.

### 5. Tests

- New fixtures: `tests/fixtures/Jenkins_CVE_2025_47889.textproto` (trimmed real
  plugin with `main_id` + `related_id`) and a no-CVE example `.textproto`.
- `TestExtractCvesForTemplated`: structured `value:` + filename → expected set;
  no-CVE example → `set()`.
- `TestDiscoverPlugins`: tmp repo containing a Java plugin, a templated plugin,
  and a `_test.textproto` → both real plugins discovered, test file skipped,
  correct `kind` on each.
- Unit test for the extracted incremental textproto-detection helper.

## Behavior Notes / Non-Goals

- A CVE present in **both** a Java detector and a templated plugin emits **two**
  sightings with different `source` URLs (they are different plugins) — consistent
  with current per-plugin behavior; the Vulnerability-Lookup backend dedups by
  content.
- Templated source URLs use the existing `…/tree/master/<file>.textproto` form
  (GitHub redirects file paths under `/tree/` to the blob view) — kept for
  consistency, no special-casing.
- Not parsing full templated-plugin semantics — only CVE extraction.

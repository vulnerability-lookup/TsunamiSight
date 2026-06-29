# Design: Templated `.textproto` Plugin Support

**Date:** 2026-06-28
**Status:** Approved (revised after multi-agent review)

## Problem

Google's `tsunami-security-scanner-plugins` repository has introduced a
"templated" plugin format under `templated/templateddetector/plugins/`. These
plugins are single `.textproto` files (e.g.
`templated/templateddetector/plugins/cve/2025/Jenkins_CVE_2025_47889.textproto`)
rather than Java directories.

TsunamiSight only discovers plugins via `discover_plugin_roots`, which requires a
`*Detector.java` file under `src/main/java/`. Templated plugins have neither, so
they are never discovered. As of this writing roughly 20 CVE-named templated
plugins live under `cve/2021`–`cve/2025`, and this is where Google is adding new
CVE plugins. (The sibling `exposedui/` and `examples/` templated trees use
label-style identifiers and carry **no** CVE references, so they will be
discovered and correctly skipped — they are not a source of recoverable
sightings.)

## Goal

Discover and emit sightings for templated `.textproto` plugins wherever a CVE can
be enumerated, mirroring the existing Java behavior ("scan everything, skip
plugins with no CVE").

## Approach

Unify Java and templated plugins under a single `Plugin` descriptor with a `kind`
discriminator. `discover_plugins` returns both kinds; a dispatcher routes CVE
extraction by kind. This keeps the downstream pipeline (`first_commit_date`,
`push_sighting`) on a single code path and isolates each plugin type behind one
interface.

Rejected alternatives:
- **Parallel functions + two loops in `main`** — duplicates the
  iterate→date→push glue, effectively reinventing the descriptor with worse
  ergonomics.
- **Folding textproto into `discover_plugin_roots`** — breaks that function's
  contract ("root = directory containing `src/main/java` and `*Detector.java`")
  and muddies its tests.

## Detailed Design

### 0. Shared exclusion predicate (`parser.py`)

A single helper defines what counts as a real templated plugin file, used by
**both** discovery and incremental detection so they can never diverge:

```python
def is_templated_plugin_file(rel_path: str) -> bool:
    # rel_path is a posix path under the repo
    if not rel_path.endswith(".textproto"):
        return False
    if rel_path.endswith("_test.textproto"):
        return False
    if any(seg in f"/{rel_path}" for seg in SKIP_PATH_SEGMENTS):
        return False
    return "/templateddetector/plugins/" in f"/{rel_path}"
```

The `/templateddetector/plugins/` constraint scopes discovery to the actual
plugin tree. Without it, a bare `rglob("*.textproto")` matches non-plugin data
files — e.g. the real
`google/detectors/credentials/.../data/service_default_credentials.textproto`,
which is a `service_default_credentials { … }` data message, not a plugin, and
passes the `/test/`,`/build/` filters. Scoping prevents a future data/config
`.textproto` carrying a stray `CVE-…` token from emitting a bogus sighting.

### 1. `Plugin` descriptor + unified discovery (`parser.py`)

```python
from dataclasses import dataclass
from typing import Literal

@dataclass(frozen=True)
class Plugin:
    abs_path: Path                    # directory (java) or file (templated)
    rel_path: str                     # posix path from repo root — source URL, git date, filter key
    kind: Literal["java", "templated"]
```

`discover_plugins(repo) -> list[Plugin]` combines:

- **java**: existing `discover_plugin_roots` logic, wrapped as
  `Plugin(dir, reldir, "java")`. `discover_plugin_roots` remains as the Java
  helper (still called here — not dead code).
- **templated**: iterate the plugin subtree if it exists —
  `(repo / "templated/templateddetector/plugins")`, guarded by an existence
  check — and `rglob("*.textproto")`, keeping only paths for which
  `is_templated_plugin_file(rel)` is true, wrapped as
  `Plugin(file, relfile, "templated")`.

Result sorted by `rel_path`.

### 2. CVE extraction (`parser.py`)

- `extract_cves_for_plugin(root, relpath)` — **unchanged** (path + `*Detector.java`
  source). Existing tests pin its `(Path, str)` signature.
- `extract_cves_for_templated(file, relpath)` — **new**:
  `extract_cves_from_path(relpath)` (catches `Jenkins_CVE_2025_47889` in the
  filename) ∪ CVEs from structured `value:` fields via
  `VALUE_CVE_RE = re.compile(r'value:\s*"(CVE[_-]\d{4}[_-]\d{4,7})"')`, each match
  passed through the existing `normalize_cve()`.

  The `[_-]` class + `normalize_cve` is required, not cosmetic: real
  `main_id.value` fields are frequently underscore-form (`value: "CVE_2021_41773"`)
  or non-CVE labels (`value: "CYBERPANEL_PREAUTH_RCE"`). A dash-only regex would
  miss the underscore form and regress relative to the Java side, which already
  uses `SETVAL_ANY_CVE_RE` (`[_-]`) + `normalize_cve`. Matching the structured
  `value:` field — rather than every CVE token in the body — still avoids
  scraping unrelated CVEs from prose `description:`/`title:` lines (header
  `value:` fields such as `value: "application/json"` correctly do not match).

  **File reads must mirror the Java path's resilience**: read with
  `read_text(errors="ignore")` inside `try/except OSError: continue`, so an
  unreadable/encoding-broken/just-deleted `.textproto` skips that file instead of
  aborting the whole run.
- `extract_cves(plugin: Plugin) -> set[str]` — thin dispatcher on `plugin.kind`.

### 3. Incremental mode (`main.py`)

`_added_plugin_roots_since` is extended to also surface added templated plugin
files (via `is_templated_plugin_file`), keyed by the **file path itself** —
matching the `rel_path` that `discover_plugins` returns for templated plugins, so
the filter in `_iter_plugins` matches naturally.

**`--diff-filter=A` is dropped here.** Commit `0f95f9e` already removed exactly
this flag from `first_commit_date` because git reports rename-created paths as
`M`/`R`, not `A`; the Tsunami repo relocates plugins, so an `A`-only filter
silently drops them. The same hazard applies to incremental detection, and is
worse for single-file templated plugins, where adding a new `related_id` CVE to
an existing file is a **modification**, not an addition. The window is therefore
treated as a coarse pre-filter over any path touched in the window; the
authoritative gate remains `discover_plugins` + `extract_cves` (which skip
plugins yielding no CVE).

Known incremental limitations (documented, not solved here — see Non-Goals):
upstream lands plugins via merge / Copybara-squash commits whose author dates can
predate the merge, so `--since` (author-date) can still miss a plugin that
appears on `master` within the window but was authored earlier. A full
periodic `--init` remains the backstop. This is pre-existing behavior, unchanged
by this work.

### 4. Orchestration + source URL (`main.py`, `sighting.py`)

`_iter_plugins` iterates `discover_plugins(repo)`, filters on `plugin.rel_path`,
calls `extract_cves(plugin)`, then `first_commit_date(repo, plugin.rel_path)` and
`push_sighting`. `main.py` imports change from
`discover_plugin_roots, extract_cves_for_plugin, first_commit_date` to
`discover_plugins, extract_cves, first_commit_date` (the only importers of these
symbols are `main.py` and `tests/test_parser.py`; `extract_cves_for_plugin`
remains a test-pinned helper). `first_commit_date` operates correctly on a file
pathspec (`git log --reverse -- <file>`), no change needed.

`build_source_url` becomes kind-aware: templated plugins are **files** and get a
`…/blob/master/<file>.textproto` URL; Java plugins are **directories** and keep
`…/tree/master/<dir>` (GitHub 404s `/blob/` on a directory). `push_sighting`
passes the plugin kind (or an `is_file` flag) through. This avoids storing a
redirecting `/tree/`-on-a-file URL and the matching test in `test_sighting.py` is
updated.

No config changes: `config.incremental_window` is the only knob the incremental
path consumes and it is unchanged. `conf_sample.py` is untouched.

### 5. Tests

- New fixtures under `tests/fixtures/`: a CVE-bearing templated plugin (trimmed
  real plugin with `main_id` + `related_id`, including the underscore-form
  `main_id.value` case) and a no-CVE templated plugin (label-style `main_id`).
- `TestExtractCvesForTemplated`: structured `value:` (dash **and** underscore
  forms) + filename → expected normalized set; no-CVE plugin → `set()`.
- `TestExtractCves` (dispatcher): a `kind="java"` Plugin and a `kind="templated"`
  Plugin route to the correct extractor.
- `TestDiscoverPlugins`: tmp repo with a Java plugin, a templated plugin, a
  `_test.textproto`, and an **out-of-tree** `.textproto` (outside
  `templated/templateddetector/plugins/`) → only the two real plugins discovered,
  with correct `kind`; the test file and out-of-tree file are excluded.
- `is_templated_plugin_file` unit tests (in-tree plugin, `_test` companion,
  out-of-tree data file, `/build/` path).
- `build_source_url`: templated/file rel_path → `/blob/master/…`; Java/dir
  rel_path → `/tree/master/…`.
- Unit test for the extracted incremental textproto-detection branch via the
  shared `is_templated_plugin_file` helper. (Note: the git-shelling in
  `_added_plugin_roots_since` itself stays untested, as `main.py` has no tests
  today; the helper carries the logic.)

### 6. Documentation

Update the now-stale discovery descriptions:
- `CLAUDE.md` Architecture / Flow: discovery is no longer only "directories with
  `*Detector.java` under `src/main/java/`" — it also covers templated
  single-file `.textproto` plugins.
- `README.md`: the "each committed Tsunami detector is a compiled, executable
  proof-of-concept" framing should acknowledge templated plugins.

## Behavior Notes / Non-Goals

- A CVE present in **both** a Java detector and a templated plugin (real example:
  `community/detectors/apache_http_server_cve_2021_41773/` and
  `templated/…/ApacheHTTPd_CVE_2021_41773.textproto`, both CVE-2021-41773) emits
  **two** sightings with different `source` URLs and likely different
  `creation_timestamp`. This is intended — they are distinct plugins. We do not
  attempt cross-kind dedup; how the Vulnerability-Lookup backend treats two
  sightings differing only in `source`/timestamp is the backend's concern and is
  not relied upon for correctness here.
- **Non-goal — modified-file related-CVE additions in incremental mode**: adding a
  new `related_id` CVE to an existing templated file is a modification; with the
  author-date window it may not surface until the next `--init`. Accepted; the
  `--init` sweep is the backstop.
- **Non-goal — merge/Copybara author-date window misses**: pre-existing `--since`
  limitation, unchanged by this work.
- Not parsing full templated-plugin semantics — only CVE extraction.
- Performance: two `rglob` passes over the repo tree is negligible; no change.

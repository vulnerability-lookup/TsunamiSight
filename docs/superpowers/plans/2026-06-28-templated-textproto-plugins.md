# Templated `.textproto` Plugin Support — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Discover Google Tsunami "templated" `.textproto` plugins (single files, CVE in filename + structured `value:` fields) alongside the existing Java `*Detector.java` plugins, and emit Vulnerability-Lookup sightings for them.

**Architecture:** Introduce a `Plugin` descriptor with a `kind` discriminator (`"java"` | `"templated"`). A single `discover_plugins()` returns both kinds; an `extract_cves()` dispatcher routes CVE extraction by kind. Templated discovery is scoped to `templated/templateddetector/plugins/`. The downstream pipeline (`first_commit_date`, `push_sighting`) stays on one code path; `build_source_url` becomes kind-aware (`/blob/` for files, `/tree/` for dirs).

**Tech Stack:** Python 3.10+, stdlib `re`/`dataclasses`/`pathlib`, `pytest`, `PyVulnerabilityLookup`.

**Spec:** `docs/superpowers/specs/2026-06-28-templated-textproto-plugins-design.md`

## Global Constraints

- Python 3.10+; every module starts with `from __future__ import annotations`.
- Formatter: Black (default). Imports: isort `profile = "black"`. Linter: flake8 `max-line-length=120`.
- Existing public function `extract_cves_for_plugin(root: Path, plugin_relpath: str)` signature is **unchanged** (pinned by tests).
- Templated plugin files are identified ONLY via the shared `is_templated_plugin_file` predicate — never an ad-hoc `rglob` filter.
- Commit messages: conventional-commit style, no AI/authorship attribution of any kind.
- Run `python -m pytest -v` (all green) before each commit.

---

### Task 1: `is_templated_plugin_file` predicate

**Files:**
- Modify: `tsunamisight/parser.py` (add after `SKIP_PATH_SEGMENTS`, ~line 17)
- Test: `tests/test_parser.py`

**Interfaces:**
- Consumes: module constant `SKIP_PATH_SEGMENTS = ("/test/", "/build/")` (already present).
- Produces: `is_templated_plugin_file(rel_path: str) -> bool` — true only for a real templated plugin file (posix repo-relative path): ends `.textproto`, not `*_test.textproto`, not under `/test/` or `/build/`, and under `…/templateddetector/plugins/…`.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_parser.py` (and add `is_templated_plugin_file` to the existing import block from `tsunamisight.parser`):

```python
class TestIsTemplatedPluginFile:
    @pytest.mark.parametrize(
        "rel,expected",
        [
            ("templated/templateddetector/plugins/cve/2025/Bar_CVE_2025_0001.textproto", True),
            ("templated/templateddetector/plugins/exposedui/Foo_ExposedUi.textproto", True),
            # test companion -> excluded
            ("templated/templateddetector/plugins/cve/2025/Bar_CVE_2025_0001_test.textproto", False),
            # out-of-tree data file -> excluded
            ("google/detectors/credentials/x/src/main/resources/data/service_default_credentials.textproto", False),
            # build/test path segments -> excluded
            ("templated/templateddetector/plugins/build/Gen.textproto", False),
            # not a textproto -> excluded
            ("templated/templateddetector/plugins/cve/2025/Bar_CVE_2025_0001.java", False),
        ],
    )
    def test_predicate(self, rel, expected):
        assert is_templated_plugin_file(rel) is expected
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_parser.py::TestIsTemplatedPluginFile -v`
Expected: FAIL — `ImportError` / `is_templated_plugin_file` not defined.

- [ ] **Step 3: Write minimal implementation**

In `tsunamisight/parser.py`, after the `SKIP_PATH_SEGMENTS` line:

```python
def is_templated_plugin_file(rel_path: str) -> bool:
    """True for a real templated plugin file (posix repo-relative path)."""
    if not rel_path.endswith(".textproto"):
        return False
    if rel_path.endswith("_test.textproto"):
        return False
    if any(seg in f"/{rel_path}" for seg in SKIP_PATH_SEGMENTS):
        return False
    return "/templateddetector/plugins/" in f"/{rel_path}"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_parser.py::TestIsTemplatedPluginFile -v`
Expected: PASS (6 cases).

- [ ] **Step 5: Commit**

```bash
git add tsunamisight/parser.py tests/test_parser.py
git commit -m "feat(parser): add is_templated_plugin_file predicate"
```

---

### Task 2: `VALUE_CVE_RE` + `extract_cves_for_templated`

**Files:**
- Create: `tests/fixtures/templated_cve.textproto`
- Create: `tests/fixtures/templated_no_cve.textproto`
- Modify: `tsunamisight/parser.py` (new regex near the other regexes ~line 15; new function near `extract_cves_for_plugin` ~line 55)
- Test: `tests/test_parser.py`

**Interfaces:**
- Consumes: `extract_cves_from_path`, `normalize_cve` (both already in `parser.py`).
- Produces: `extract_cves_for_templated(plugin_file: Path, plugin_relpath: str) -> set[str]` — union of path CVEs and CVEs from structured `value: "CVE[_-]…"` fields, normalized to dashed/upper. Reads the file resiliently (`errors="ignore"`, `OSError` → return path CVEs only).

- [ ] **Step 1: Create the fixtures**

`tests/fixtures/templated_cve.textproto` (underscore `main_id.value` + dashed `related_id.value`, both the same CVE):

```
# proto-file: proto/templated_plugin.proto
# proto-message: TemplatedPlugin
info: {
  type: VULN_DETECTION
  name: "ApacheHTTPd_CVE_2021_41773"
  version: "1.0"
}
finding: {
  main_id: {
    publisher: "GOOGLE"
    value: "CVE_2021_41773"
  }
  related_id: {
    publisher: "CVE"
    value: "CVE-2021-41773"
  }
  severity: CRITICAL
  title: "Path traversal in Apache HTTPd (CVE-2021-41773)"
}
```

`tests/fixtures/templated_no_cve.textproto` (label identifiers, no CVE — like the real `exposedui` plugins):

```
# proto-message: TemplatedPlugin
info: {
  name: "NODERED_EXPOSED_UI"
}
finding: {
  main_id: {
    publisher: "GOOGLE"
    value: "NODERED_EXPOSED_UI"
  }
  severity: CRITICAL
  title: "Exposed Node-RED UI"
}
```

- [ ] **Step 2: Write the failing test**

Add to `tests/test_parser.py` (add `extract_cves_for_templated` to the import block):

```python
class TestExtractCvesForTemplated:
    def test_value_fields_and_filename(self):
        f = FIXTURES / "templated_cve.textproto"
        cves = extract_cves_for_templated(
            f,
            plugin_relpath="templated/templateddetector/plugins/cve/2021/ApacheHTTPd_CVE_2021_41773.textproto",
        )
        # underscore main_id + dashed related_id + filename all normalize to one CVE
        assert cves == {"CVE-2021-41773"}

    def test_no_cve_plugin_yields_empty(self):
        f = FIXTURES / "templated_no_cve.textproto"
        cves = extract_cves_for_templated(
            f,
            plugin_relpath="templated/templateddetector/plugins/exposedui/NodeRed_ExposedUi.textproto",
        )
        assert cves == set()

    def test_unreadable_file_falls_back_to_path_cves(self, tmp_path):
        missing = tmp_path / "gone.textproto"  # never created
        cves = extract_cves_for_templated(
            missing,
            plugin_relpath="templated/templateddetector/plugins/cve/2025/Bar_CVE_2025_0001.textproto",
        )
        assert cves == {"CVE-2025-0001"}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `python -m pytest tests/test_parser.py::TestExtractCvesForTemplated -v`
Expected: FAIL — `extract_cves_for_templated` not defined.

- [ ] **Step 4: Write minimal implementation**

In `tsunamisight/parser.py`, add the regex next to the existing CVE regexes:

```python
VALUE_CVE_RE = re.compile(r'value:\s*"(CVE[_-]\d{4}[_-]\d{4,7})"')
```

And add the function (near `extract_cves_for_plugin`):

```python
def extract_cves_for_templated(plugin_file: Path, plugin_relpath: str) -> set[str]:
    cves = extract_cves_from_path(plugin_relpath)
    try:
        body = plugin_file.read_text(errors="ignore")
    except OSError:
        return cves
    for raw in VALUE_CVE_RE.findall(body):
        cves.add(normalize_cve(raw))
    return cves
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/test_parser.py::TestExtractCvesForTemplated -v`
Expected: PASS (3 cases).

- [ ] **Step 6: Commit**

```bash
git add tsunamisight/parser.py tests/test_parser.py tests/fixtures/templated_cve.textproto tests/fixtures/templated_no_cve.textproto
git commit -m "feat(parser): extract CVEs from templated textproto plugins"
```

---

### Task 3: `Plugin` descriptor + `discover_plugins`

**Files:**
- Modify: `tsunamisight/parser.py` (imports at top; `Plugin` after imports; `discover_plugins` after `discover_plugin_roots`)
- Test: `tests/test_parser.py`

**Interfaces:**
- Consumes: `discover_plugin_roots` (unchanged), `is_templated_plugin_file` (Task 1).
- Produces:
  - `Plugin` frozen dataclass: `abs_path: Path`, `rel_path: str`, `kind: Literal["java", "templated"]`.
  - `discover_plugins(repo_path: Path) -> list[Plugin]` — Java plugins (from `discover_plugin_roots`) plus templated plugins found under `templated/templateddetector/plugins`, sorted by `rel_path`.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_parser.py` (add `Plugin, discover_plugins` to the import block):

```python
class TestDiscoverPlugins:
    def _make_repo(self, tmp_path):
        # java plugin
        jdir = tmp_path / "community" / "detectors" / "foo" / "src" / "main" / "java" / "com" / "x"
        jdir.mkdir(parents=True)
        (jdir / "FooDetector.java").write_text('.setPublisher("CVE").setValue("CVE-2020-1111")')
        # templated plugin + its test companion
        tdir = tmp_path / "templated" / "templateddetector" / "plugins" / "cve" / "2025"
        tdir.mkdir(parents=True)
        (tdir / "Bar_CVE_2025_0001.textproto").write_text('value: "CVE-2025-0001"')
        (tdir / "Bar_CVE_2025_0001_test.textproto").write_text('value: "CVE-9999-9999"')
        # out-of-tree non-plugin textproto
        odir = tmp_path / "google" / "detectors" / "creds" / "src" / "main" / "resources" / "data"
        odir.mkdir(parents=True)
        (odir / "service_default_credentials.textproto").write_text("service_default_credentials {}")
        return tmp_path

    def test_discovers_java_and_templated_only(self, tmp_path):
        repo = self._make_repo(tmp_path)
        plugins = discover_plugins(repo)
        by_rel = {p.rel_path: p.kind for p in plugins}
        assert by_rel == {
            "community/detectors/foo": "java",
            "templated/templateddetector/plugins/cve/2025/Bar_CVE_2025_0001.textproto": "templated",
        }

    def test_returns_plugin_instances_sorted(self, tmp_path):
        repo = self._make_repo(tmp_path)
        plugins = discover_plugins(repo)
        assert all(isinstance(p, Plugin) for p in plugins)
        assert [p.rel_path for p in plugins] == sorted(p.rel_path for p in plugins)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_parser.py::TestDiscoverPlugins -v`
Expected: FAIL — `Plugin` / `discover_plugins` not defined.

- [ ] **Step 3: Write minimal implementation**

At the top of `tsunamisight/parser.py`, extend imports:

```python
from dataclasses import dataclass
from typing import Literal
```

After the imports / constants, add the dataclass:

```python
@dataclass(frozen=True)
class Plugin:
    abs_path: Path  # directory (java) or file (templated)
    rel_path: str  # posix path from repo root
    kind: Literal["java", "templated"]
```

After `discover_plugin_roots`, add:

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_parser.py::TestDiscoverPlugins -v`
Expected: PASS (2 cases).

- [ ] **Step 5: Commit**

```bash
git add tsunamisight/parser.py tests/test_parser.py
git commit -m "feat(parser): unified discover_plugins for java + templated"
```

---

### Task 4: `extract_cves` dispatcher

**Files:**
- Modify: `tsunamisight/parser.py` (after `extract_cves_for_templated`)
- Test: `tests/test_parser.py`

**Interfaces:**
- Consumes: `Plugin` (Task 3), `extract_cves_for_plugin` (existing), `extract_cves_for_templated` (Task 2).
- Produces: `extract_cves(plugin: Plugin) -> set[str]` — dispatches on `plugin.kind`.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_parser.py` (add `extract_cves` to the import block):

```python
class TestExtractCvesDispatch:
    def test_java_kind_routes_to_java_extractor(self, tmp_path):
        root = tmp_path / "community" / "detectors" / "foo"
        jdir = root / "src" / "main" / "java"
        jdir.mkdir(parents=True)
        (jdir / "FooDetector.java").write_text('.setPublisher("CVE").setValue("CVE-2020-1111")')
        plugin = Plugin(abs_path=root, rel_path="community/detectors/foo", kind="java")
        assert extract_cves(plugin) == {"CVE-2020-1111"}

    def test_templated_kind_routes_to_templated_extractor(self, tmp_path):
        f = tmp_path / "Bar_CVE_2025_0001.textproto"
        f.write_text('value: "CVE-2025-0001"')
        plugin = Plugin(
            abs_path=f,
            rel_path="templated/templateddetector/plugins/cve/2025/Bar_CVE_2025_0001.textproto",
            kind="templated",
        )
        assert extract_cves(plugin) == {"CVE-2025-0001"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_parser.py::TestExtractCvesDispatch -v`
Expected: FAIL — `extract_cves` not defined.

- [ ] **Step 3: Write minimal implementation**

In `tsunamisight/parser.py`, after `extract_cves_for_templated`:

```python
def extract_cves(plugin: Plugin) -> set[str]:
    if plugin.kind == "templated":
        return extract_cves_for_templated(plugin.abs_path, plugin.rel_path)
    return extract_cves_for_plugin(plugin.abs_path, plugin.rel_path)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_parser.py::TestExtractCvesDispatch -v`
Expected: PASS (2 cases).

- [ ] **Step 5: Commit**

```bash
git add tsunamisight/parser.py tests/test_parser.py
git commit -m "feat(parser): add extract_cves kind dispatcher"
```

---

### Task 5: Kind-aware `build_source_url` + `push_sighting`

**Files:**
- Modify: `tsunamisight/sighting.py:13-33`
- Test: `tests/test_sighting.py`

**Interfaces:**
- Produces:
  - `build_source_url(plugin_relpath: str, kind: str = "java") -> str` — `kind == "templated"` → `…/blob/master/<file>`, else `…/tree/master/<dir>`.
  - `push_sighting(..., kind: str = "java")` — passes `kind` to `build_source_url`. Default `"java"` keeps existing call sites/tests valid.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_sighting.py` (import `build_source_url`):

```python
from tsunamisight.sighting import build_source_url, push_sighting


def test_build_source_url_templated_uses_blob():
    rel = "templated/templateddetector/plugins/cve/2025/Bar_CVE_2025_0001.textproto"
    assert build_source_url(rel, kind="templated") == (
        "https://github.com/google/tsunami-security-scanner-plugins/blob/master/" + rel
    )


def test_build_source_url_java_uses_tree():
    rel = "community/detectors/foo"
    assert build_source_url(rel, kind="java") == (
        "https://github.com/google/tsunami-security-scanner-plugins/tree/master/" + rel
    )


def test_push_sighting_templated_payload_uses_blob(fake_client):
    fake_client.create_sighting.return_value = {"message": "created"}
    push_sighting(
        fake_client,
        plugin_relpath="templated/templateddetector/plugins/cve/2025/Bar_CVE_2025_0001.textproto",
        cve="CVE-2025-0001",
        when=datetime(2024, 1, 1, tzinfo=timezone.utc),
        sighting_type="published-proof-of-concept",
        kind="templated",
    )
    payload = _payload(fake_client)
    assert "/blob/master/" in payload["source"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_sighting.py -v`
Expected: FAIL — `build_source_url` import error / `push_sighting` got unexpected `kind`.

- [ ] **Step 3: Write minimal implementation**

In `tsunamisight/sighting.py`, replace the `SOURCE_BASE`/`build_source_url` block and add `kind` to `push_sighting`:

```python
SOURCE_BASE = "https://github.com/google/tsunami-security-scanner-plugins/"


def build_source_url(plugin_relpath: str, kind: str = "java") -> str:
    ref = "blob" if kind == "templated" else "tree"
    return f"{SOURCE_BASE}{ref}/master/{plugin_relpath.lstrip('/')}"
```

Update the signature and the `source` line of `push_sighting`:

```python
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
```

(The rest of `push_sighting` — the `try/except` and message handling — is unchanged.)

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_sighting.py -v`
Expected: PASS — new cases pass and the existing `test_push_sighting_builds_correct_payload` (java default → `/tree/master/`) still passes.

- [ ] **Step 5: Commit**

```bash
git add tsunamisight/sighting.py tests/test_sighting.py
git commit -m "feat(sighting): kind-aware source URL (blob for templated files)"
```

---

### Task 6: Wire `discover_plugins`/`extract_cves` into `main.py`

**Files:**
- Modify: `tsunamisight/main.py:16-20` (imports), `:64-74` (`_iter_plugins`), `:127-139` (main loop)
- Test: covered indirectly; no `main.py` unit tests exist. Verify via full suite + a `--dry-run` smoke check.

**Interfaces:**
- Consumes: `discover_plugins`, `extract_cves` (parser), `push_sighting(..., kind=...)` (Task 5).
- Produces: `_iter_plugins(repo, roots_filter)` now yields `(rel_path, cve, when, kind)`.

- [ ] **Step 1: Update imports**

In `tsunamisight/main.py`, replace the parser import block:

```python
from tsunamisight.parser import (
    discover_plugins,
    extract_cves,
    first_commit_date,
)
```

- [ ] **Step 2: Rewrite `_iter_plugins`**

```python
def _iter_plugins(repo: Path, roots_filter: set[str] | None):
    for plugin in discover_plugins(repo):
        if roots_filter is not None and plugin.rel_path not in roots_filter:
            continue
        cves = extract_cves(plugin)
        if not cves:
            logger.debug("no CVEs extracted for %s — skipping", plugin.rel_path)
            continue
        when = first_commit_date(repo, plugin.rel_path)
        for cve in sorted(cves):
            yield plugin.rel_path, cve, when, plugin.kind
```

- [ ] **Step 3: Update the main emit loop**

Replace the `for rel, cve, when in _iter_plugins(...)` loop body:

```python
    for rel, cve, when, kind in _iter_plugins(repo, filter_set):
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
            kind=kind,
        )
        emitted += 1
```

- [ ] **Step 4: Run the full suite**

Run: `python -m pytest -v`
Expected: PASS (all tests, including existing ones).

- [ ] **Step 5: Smoke-check the import path compiles**

Run: `python -c "import tsunamisight.main"`
Expected: no output, exit 0 (no `ImportError` from the renamed symbols).

- [ ] **Step 6: Commit**

```bash
git add tsunamisight/main.py
git commit -m "feat(cli): discover and emit templated plugin sightings"
```

---

### Task 7: Incremental detection — drop `--diff-filter=A`, add textproto branch

**Files:**
- Modify: `tsunamisight/main.py:35-61` (`_added_plugin_roots_since`; extract pure helper); imports
- Test: `tests/test_main.py` (new file)

**Interfaces:**
- Consumes: `is_templated_plugin_file` (Task 1).
- Produces: `_added_roots_from_names(names: Iterable[str]) -> set[str]` — pure parser of `git log --name-only` output into a set of unit keys (java root dir for `/src/main/java/` paths; the file path itself for templated plugin files).

- [ ] **Step 1: Write the failing test**

Create `tests/test_main.py`:

```python
from tsunamisight.main import _added_roots_from_names


class TestAddedRootsFromNames:
    def test_java_path_yields_root_dir(self):
        names = ["community/detectors/foo/src/main/java/com/x/FooDetector.java"]
        assert _added_roots_from_names(names) == {"community/detectors/foo"}

    def test_templated_file_yields_file_path(self):
        rel = "templated/templateddetector/plugins/cve/2025/Bar_CVE_2025_0001.textproto"
        assert _added_roots_from_names([rel]) == {rel}

    def test_test_companion_and_unrelated_excluded(self):
        names = [
            "templated/templateddetector/plugins/cve/2025/Bar_CVE_2025_0001_test.textproto",
            "README.md",
            "",
        ]
        assert _added_roots_from_names(names) == set()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_main.py -v`
Expected: FAIL — `_added_roots_from_names` not defined.

- [ ] **Step 3: Add the helper and refactor `_added_plugin_roots_since`**

In `tsunamisight/main.py`, add `is_templated_plugin_file` to the parser import block:

```python
from tsunamisight.parser import (
    discover_plugins,
    extract_cves,
    first_commit_date,
    is_templated_plugin_file,
)
```

Add the pure helper above `_added_plugin_roots_since`:

```python
def _added_roots_from_names(names) -> set[str]:
    """Parse `git log --name-only` lines into plugin unit keys."""
    roots: set[str] = set()
    for line in names:
        line = line.strip()
        if not line:
            continue
        if "/src/main/java/" in line:
            roots.add(line.split("/src/main/java/")[0])
        elif is_templated_plugin_file(line):
            roots.add(line)
    return roots
```

Rewrite `_added_plugin_roots_since` to drop `--diff-filter=A` (renames/relocations report as `M`/`R`, not `A`; the window is a coarse pre-filter and `discover_plugins`+`extract_cves` is the authoritative gate) and delegate parsing:

```python
def _added_plugin_roots_since(repo: Path, since: str) -> set[str]:
    """Plugin unit keys touched within `since` (e.g. '7 days ago')."""
    try:
        result = subprocess.run(
            [
                "git",
                "log",
                f"--since={since}",
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
    return _added_roots_from_names(result.stdout.splitlines())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_main.py -v`
Expected: PASS (3 cases).

- [ ] **Step 5: Run the full suite**

Run: `python -m pytest -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add tsunamisight/main.py tests/test_main.py
git commit -m "fix(cli): widen incremental window to renames + templated files"
```

---

### Task 8: Update documentation

**Files:**
- Modify: `CLAUDE.md` (Architecture / Flow sections)
- Modify: `README.md` (plugin/detector description)

**Interfaces:** none (docs only).

- [ ] **Step 1: Update `CLAUDE.md`**

In the **Architecture** section, change the flow line that reads
`discovers plugin roots (directories with *Detector.java under src/main/java/)`
to describe both kinds, e.g.:

> discovers plugins — both Java detector directories (`*Detector.java` under
> `src/main/java/`) and templated single-file `.textproto` plugins under
> `templated/templateddetector/plugins/` —

In the **Modules** list, update the `parser.py` bullet to mention `discover_plugins`
(unified discovery) and `extract_cves` (kind dispatcher) alongside the existing
regex description, and note templated CVE extraction from `value:` fields.

- [ ] **Step 2: Update `README.md`**

Where the README describes plugins as Java detectors, add a sentence noting that
Google's newer **templated** plugins (`.textproto` files under
`templated/templateddetector/plugins/`) are also parsed for CVE sightings.

- [ ] **Step 3: Verify no stale "only Detector.java" claims remain**

Run: `grep -rni "src/main/java\|Detector.java" README.md CLAUDE.md`
Expected: any remaining hits are accurate (they describe the Java kind specifically, not "the only" discovery mechanism).

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md README.md
git commit -m "docs: describe templated textproto plugin discovery"
```

---

## Self-Review

**Spec coverage:**
- §0 shared predicate → Task 1. §1 `Plugin`/`discover_plugins` (scoped, `Literal` kind) → Task 3. §2 regex (`[_-]`+normalize), error handling, dispatcher → Tasks 2 & 4. §3 incremental (drop `--diff-filter=A`, shared predicate) → Task 7. §4 orchestration + kind-aware `build_source_url` → Tasks 5 & 6. §5 tests → folded into each task (out-of-tree exclusion in Task 3, underscore-form in Task 2, dispatcher in Task 4, blob/tree in Task 5, predicate in Task 1, incremental helper in Task 7). §6 docs → Task 8. Non-goals are documentation-only; no task needed.

**Placeholder scan:** No TBD/TODO; every code step shows complete code; every command has expected output.

**Type consistency:** `Plugin(abs_path, rel_path, kind)` used identically in Tasks 3, 4, 6. `extract_cves(plugin)` (Task 4) consumed in Task 6. `build_source_url(relpath, kind)` / `push_sighting(..., kind=)` (Task 5) consumed in Task 6. `is_templated_plugin_file` (Task 1) consumed in Tasks 3 & 7. `_iter_plugins` 4-tuple `(rel, cve, when, kind)` produced in Task 6 Step 2 and consumed in Step 3. Consistent throughout.

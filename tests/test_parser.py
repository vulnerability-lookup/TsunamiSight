from pathlib import Path

import pytest

from tsunamisight.parser import (
    Plugin,
    discover_plugins,
    extract_cves_for_plugin,
    extract_cves_for_templated,
    extract_cves_from_java_source,
    extract_cves_from_path,
    is_templated_plugin_file,
    normalize_cve,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestNormalizeCve:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("CVE-2023-42793", "CVE-2023-42793"),
            ("CVE_2023_42793", "CVE-2023-42793"),
            ("cve-2023-42793", "CVE-2023-42793"),
            ("CVE-2014-7169", "CVE-2014-7169"),
        ],
    )
    def test_normalizes_to_dashed_upper(self, raw, expected):
        assert normalize_cve(raw) == expected


class TestExtractCvesFromPath:
    @pytest.mark.parametrize(
        "path,expected",
        [
            ("google/detectors/rce/cve202342793", {"CVE-2023-42793"}),
            ("community/detectors/cve_2020_3452", {"CVE-2020-3452"}),
            ("community/detectors/adobe_coldfusion_cve_2023_26360", {"CVE-2023-26360"}),
            ("google/detectors/rce/solr_cve201917558", {"CVE-2019-17558"}),
            ("google/detectors/rce/java_jmx", set()),
            ("google/detectors/exposedui/apache_nifi_api", set()),
            ("google/detectors/ai", set()),
        ],
    )
    def test_path_regex(self, path, expected):
        assert extract_cves_from_path(path) == expected


class TestExtractCvesFromJavaSource:
    def test_single_cve(self):
        body = (FIXTURES / "single_cve.java").read_text()
        assert extract_cves_from_java_source(body) == {"CVE-2023-42793"}

    def test_multi_cve_shellshock(self):
        body = (FIXTURES / "multi_cve_shellshock.java").read_text()
        assert extract_cves_from_java_source(body) == {"CVE-2014-6271", "CVE-2014-7169"}

    def test_no_cve_generic(self):
        body = (FIXTURES / "no_cve_generic.java").read_text()
        assert extract_cves_from_java_source(body) == set()

    def test_google_main_id_underscore_normalized(self):
        body = (FIXTURES / "google_main_id_underscore.java").read_text()
        assert extract_cves_from_java_source(body) == {"CVE-2024-32113"}


class TestExtractCvesForPlugin:
    def test_union_of_path_and_source(self, tmp_path):
        root = tmp_path / "google" / "detectors" / "rce" / "cve202342793"
        java_dir = root / "src" / "main" / "java" / "com" / "example"
        java_dir.mkdir(parents=True)
        (java_dir / "FooDetector.java").write_text(
            '.setPublisher("CVE").setValue("CVE-2023-99999")'
        )
        cves = extract_cves_for_plugin(
            root, plugin_relpath="google/detectors/rce/cve202342793"
        )
        assert cves == {"CVE-2023-42793", "CVE-2023-99999"}

    def test_skips_test_and_build_dirs(self, tmp_path):
        root = tmp_path / "google" / "detectors" / "rce" / "cve202342793"
        (root / "src" / "main" / "java").mkdir(parents=True)
        (root / "src" / "main" / "java" / "FooDetector.java").write_text(
            '.setPublisher("CVE").setValue("CVE-2023-42793")'
        )
        (root / "src" / "test" / "java").mkdir(parents=True)
        (root / "src" / "test" / "java" / "FooDetectorTest.java").write_text(
            '.setPublisher("CVE").setValue("CVE-9999-99999")'
        )
        (root / "build" / "libs").mkdir(parents=True)
        (root / "build" / "libs" / "StaleDetector.java").write_text(
            '.setPublisher("CVE").setValue("CVE-8888-88888")'
        )
        cves = extract_cves_for_plugin(
            root, plugin_relpath="google/detectors/rce/cve202342793"
        )
        assert cves == {"CVE-2023-42793"}


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

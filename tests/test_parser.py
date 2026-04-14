from pathlib import Path

import pytest

from tsunamisight.parser import (
    extract_cves_for_plugin,
    extract_cves_from_java_source,
    extract_cves_from_path,
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

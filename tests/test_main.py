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

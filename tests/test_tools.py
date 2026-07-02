from evaluation.core.tools import TOOL_FILE_IDS, tool_file_id


def test_known_tools_mapped():
    assert tool_file_id("Dependency-Track") == "dtrack"
    assert tool_file_id("OSV") == "osv"
    assert tool_file_id("GitHub") == "github"
    assert tool_file_id("Snyk") == "snyk"
    assert tool_file_id("Trivy") == "trivy"
    assert tool_file_id("OSS Index") == "ossindex"


def test_unknown_tool_falls_back_to_slug():
    assert tool_file_id("Some New Tool") == "some-new-tool"


def test_empty_returns_unknown():
    assert tool_file_id("") == "unknown"
    assert tool_file_id(None) == "unknown"


def test_registry_does_not_contain_removed_adapters():
    # mend, fossa, evaltech were removed from the public release.
    assert "Mend" not in TOOL_FILE_IDS
    assert "FOSSA" not in TOOL_FILE_IDS


def test_nvd_registered_as_diagnostic_id():
    # NVD is registered purely for filename / log consistency; it is a
    # standalone completeness diagnostic, not part of the --tool detection set.
    assert tool_file_id("NVD") == "nvd"

from evaluation.core.normalization import (
    ecosystem_from_purl,
    normalize_component,
    normalize_identifier,
    normalize_version,
)


class TestNormalizeComponent:
    def test_empty_name_returns_empty(self):
        assert normalize_component("pypi", "") == ""
        assert normalize_component("pypi", None) == ""

    def test_pypi_pep503_canonical(self):
        assert normalize_component("pypi", "Django") == "django"
        assert normalize_component("pypi", "My_Package") == "my-package"
        assert normalize_component("pypi", "Foo_Bar_Baz") == "foo-bar-baz"

    def test_npm_lowercases(self):
        assert normalize_component("npm", "LoDash") == "lodash"
        assert normalize_component("npm", "@Scope/Pkg") == "@scope/pkg"

    def test_maven_preserves_group_artifact(self):
        assert normalize_component("maven", "org.apache:commons-lang3") == "org.apache:commons-lang3"

    def test_maven_slash_converted_to_colon(self):
        assert normalize_component("maven", "org.apache/commons-lang3") == "org.apache:commons-lang3"

    def test_nuget_preserves_case(self):
        assert normalize_component("nuget", "Newtonsoft.Json") == "Newtonsoft.Json"

    def test_unknown_ecosystem_fallback(self):
        assert normalize_component("cargo", "serde") == "serde"

    def test_ecosystem_case_insensitive(self):
        assert normalize_component("PyPI", "Django") == "django"
        assert normalize_component("NPM", "LoDash") == "lodash"

    def test_whitespace_stripped(self):
        assert normalize_component("pypi", "  Django  ") == "django"


class TestNormalizeIdentifier:
    def test_none_returns_none(self):
        assert normalize_identifier(None) is None
        assert normalize_identifier("") is None

    def test_cve_uppercased(self):
        assert normalize_identifier("cve-2021-1234") == "CVE-2021-1234"
        assert normalize_identifier("CVE-2021-1234") == "CVE-2021-1234"

    def test_ghsa_uppercased(self):
        assert normalize_identifier("ghsa-abcd-1234-efgh") == "GHSA-ABCD-1234-EFGH"

    def test_osv_preserved(self):
        assert normalize_identifier("OSV-2021-1234") == "OSV-2021-1234"
        assert normalize_identifier("PYSEC-2021-1") == "PYSEC-2021-1"


class TestNormalizeVersion:
    def test_none_returns_empty(self):
        assert normalize_version(None) == ""

    def test_strips_whitespace(self):
        assert normalize_version("  1.2.3  ") == "1.2.3"

    def test_preserves_string_semantics(self):
        assert normalize_version("1.2.3-beta+build") == "1.2.3-beta+build"


class TestEcosystemFromPurl:
    def test_pypi(self):
        assert ecosystem_from_purl("pkg:pypi/tensorflow@2.9.0") == "pypi"

    def test_npm(self):
        assert ecosystem_from_purl("pkg:npm/lodash@4.17.0") == "npm"

    def test_maven(self):
        assert ecosystem_from_purl("pkg:maven/org.apache/commons@1.0") == "maven"

    def test_none_or_empty(self):
        assert ecosystem_from_purl(None) is None
        assert ecosystem_from_purl("") is None

    def test_non_purl_returns_none(self):
        assert ecosystem_from_purl("https://example.com/foo") is None

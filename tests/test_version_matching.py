from evaluation.core.version_matching import normalize_specifier, version_in_range


class TestNormalizeSpecifier:
    def test_none_on_empty(self):
        assert normalize_specifier("") is None
        assert normalize_specifier(None) is None

    def test_maven_inclusive(self):
        assert normalize_specifier("[1.0,2.0]") == ">=1.0,<=2.0"

    def test_maven_half_open(self):
        assert normalize_specifier("[1.0,2.0)") == ">=1.0,<2.0"

    def test_maven_open_upper(self):
        assert normalize_specifier("[1.0,)") == ">=1.0"

    def test_maven_open_lower(self):
        assert normalize_specifier("(,1.4.4]") == "<=1.4.4"

    def test_hyphen_range(self):
        assert normalize_specifier("1.2.3 - 2.0.0") == ">=1.2.3,<=2.0.0"

    def test_operator_based_passthrough(self):
        assert normalize_specifier(">=1.0,<2.0") == ">=1.0,<2.0"

    def test_v_prefix_stripped(self):
        assert normalize_specifier(">=v1.0") == ">=1.0"

    def test_build_metadata_dropped(self):
        assert normalize_specifier(">=1.0+build") == ">=1.0"

    def test_plain_version_without_operator_returns_none(self):
        assert normalize_specifier("1.2.3") is None


class TestVersionInRange:
    def test_basic_range(self):
        assert version_in_range("1.5.0", ">=1.0,<2.0") is True
        assert version_in_range("2.0.0", ">=1.0,<2.0") is False

    def test_maven_range(self):
        assert version_in_range("1.5.0", "[1.0,2.0)") is True
        assert version_in_range("0.9.0", "[1.0,2.0)") is False

    def test_v_prefix_on_version(self):
        assert version_in_range("v1.5.0", ">=1.0,<2.0") is True

    def test_invalid_version_returns_false(self):
        assert version_in_range("not-a-version", ">=1.0") is False

    def test_empty_inputs(self):
        assert version_in_range("", ">=1.0") is False
        assert version_in_range("1.0", "") is False

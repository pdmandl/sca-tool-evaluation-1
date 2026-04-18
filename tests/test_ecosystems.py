from evaluation.core.ecosystems import ECOSYSTEMS


def test_all_expected_ecosystems_present():
    assert set(ECOSYSTEMS.keys()) == {"pypi", "npm", "maven", "nuget"}


def test_canonical_matches_key():
    for key, mapping in ECOSYSTEMS.items():
        assert mapping.canonical == key


def test_osv_names():
    assert ECOSYSTEMS["pypi"].osv == "PyPI"
    assert ECOSYSTEMS["npm"].osv == "npm"
    assert ECOSYSTEMS["maven"].osv == "Maven"
    assert ECOSYSTEMS["nuget"].osv == "NuGet"


def test_github_names_uppercase():
    for mapping in ECOSYSTEMS.values():
        assert mapping.github is None or mapping.github.isupper()

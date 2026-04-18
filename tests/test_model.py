from evaluation.core.model import Finding


def _f(**kwargs):
    defaults = dict(ecosystem="pypi", component="django", version="3.2.0")
    defaults.update(kwargs)
    return Finding(**defaults)


def test_finding_defaults():
    f = _f()
    assert f.purl is None
    assert f.cve is None
    assert f.ghsa is None
    assert f.osv_id is None
    assert f.description == ""
    assert f.match_type is None


def test_identifiers_empty_when_no_ids():
    assert _f().identifiers() == set()


def test_identifiers_collects_all_set_ids():
    f = _f(cve="CVE-2021-1", ghsa="GHSA-aaaa-bbbb-cccc", osv_id="OSV-2021-1")
    assert f.identifiers() == {"CVE-2021-1", "GHSA-aaaa-bbbb-cccc", "OSV-2021-1"}


def test_identifiers_skips_none_values():
    f = _f(cve="CVE-2021-1", ghsa=None, osv_id=None)
    assert f.identifiers() == {"CVE-2021-1"}


def test_identifiers_intersection_for_matching():
    gt = _f(cve="CVE-2021-1")
    tool = _f(cve="CVE-2021-1", ghsa="GHSA-xxxx-yyyy-zzzz")
    assert gt.identifiers() & tool.identifiers() == {"CVE-2021-1"}

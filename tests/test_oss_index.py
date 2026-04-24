"""Tests for OSSIndexAdapter helper methods."""

from unittest.mock import MagicMock, patch

import pytest

from evaluation.adapters.oss_index import OSSIndexAdapter, _CoordKey
from evaluation.core.model import Finding


def _make(tmp_path, monkeypatch, gt=None, env=None):
    monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
    return OSSIndexAdapter(config={"env": env or {}, "ground_truth": gt or []})


class TestChunks:
    def test_exact_split(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        assert a._chunks(list(range(6)), 3) == [[0, 1, 2], [3, 4, 5]]

    def test_uneven(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        assert a._chunks([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]

    def test_empty(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        assert a._chunks([], 10) == []


class TestToPurlCoordinate:
    def test_maven_colon(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        r = a._to_purl_coordinate(ecosystem="maven", component="com.foo:bar", version="1.0")
        assert r and r.startswith("pkg:maven/")

    def test_maven_slash(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        r = a._to_purl_coordinate(ecosystem="maven", component="com.foo/bar", version="1.0")
        assert r and "bar" in r

    def test_maven_no_separator(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        assert a._to_purl_coordinate(ecosystem="maven", component="plain", version="1") is None

    def test_nuget(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        r = a._to_purl_coordinate(ecosystem="nuget", component="Foo", version="2.0")
        assert r == "pkg:nuget/Foo@2.0"

    def test_npm(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        r = a._to_purl_coordinate(ecosystem="npm", component="lodash", version="4.0")
        assert r and "lodash" in r

    def test_pypi(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        r = a._to_purl_coordinate(ecosystem="pypi", component="Django", version="3.2")
        assert r and "Django" in r

    def test_unknown_eco(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        assert a._to_purl_coordinate(ecosystem="rubygems", component="x", version="1") is None

    def test_empty_args(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        assert a._to_purl_coordinate(ecosystem="", component="x", version="1") is None
        assert a._to_purl_coordinate(ecosystem="pypi", component="", version="1") is None


class TestBestEffortKeyFromPurl:
    def test_pypi(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        k = a._best_effort_key_from_purl("pkg:pypi/django@3.2.0")
        assert k == _CoordKey("pypi", "django", "3.2.0")

    def test_maven(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        k = a._best_effort_key_from_purl("pkg:maven/com.foo/bar@1.0")
        assert k == _CoordKey("maven", "com.foo:bar", "1.0")

    def test_no_at(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        assert a._best_effort_key_from_purl("pkg:pypi/django") is None

    def test_unknown_type(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        assert a._best_effort_key_from_purl("pkg:rubygems/foo@1") is None

    def test_empty(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        assert a._best_effort_key_from_purl("") is None

    def test_maven_no_slash(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        assert a._best_effort_key_from_purl("pkg:maven/nogroup@1.0") is None


class TestFindTokenWithPrefix:
    def test_found(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        assert a._find_token_with_prefix("see CVE-2024-1234 here", "CVE-") == "CVE-2024-1234"

    def test_not_found(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        assert a._find_token_with_prefix("no cve here", "CVE-") is None

    def test_empty_text(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        assert a._find_token_with_prefix("", "CVE-") is None

    def test_ghsa(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        r = a._find_token_with_prefix("GHSA-xxxx-yyyy-zzzz advisory", "GHSA-")
        assert r and r.startswith("GHSA-")


class TestExtractCve:
    def test_cve_field(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        assert a._extract_cve({"cve": "CVE-2024-1"}, fallback_text="") == "CVE-2024-1"

    def test_cveId_field(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        assert a._extract_cve({"cveId": "CVE-2024-2"}, fallback_text="") == "CVE-2024-2"

    def test_from_references(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        r = a._extract_cve({"references": ["https://nvd.nist.gov/CVE-2024-3"]}, fallback_text="")
        assert r and r.startswith("CVE-")

    def test_from_fallback_text(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        r = a._extract_cve({}, fallback_text="CVE-2024-5 in description")
        assert r == "CVE-2024-5"

    def test_references_as_string(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        r = a._extract_cve({"references": "https://x/CVE-2024-6"}, fallback_text="")
        assert r and "CVE-" in r

    def test_none(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        assert a._extract_cve({}, fallback_text="no cve") is None


class TestExtractGhsa:
    def test_from_references(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        r = a._extract_ghsa({"references": ["https://GHSA-xxxx-yyyy-1234"]}, fallback_text="")
        assert r and r.startswith("GHSA-")

    def test_from_fallback(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        r = a._extract_ghsa({}, fallback_text="GHSA-aaaa-bbbb-cccc advisory")
        assert r and r.startswith("GHSA-")

    def test_none(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        assert a._extract_ghsa({}, fallback_text="no advisory") is None


class TestParseComponentReport:
    def test_basic(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        coord_map = {"pkg:pypi/django@3.2": _CoordKey("pypi", "django", "3.2")}
        data = [
            {
                "coordinates": "pkg:pypi/django@3.2",
                "vulnerabilities": [
                    {"id": "V1", "title": "bad", "description": "", "cve": "CVE-2024-1"},
                ],
            }
        ]
        findings = a._parse_component_report(data, coord_map=coord_map)
        assert len(findings) == 1 and findings[0].cve == "CVE-2024-1"

    def test_no_identifier_skipped(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        coord_map = {"pkg:pypi/x@1": _CoordKey("pypi", "x", "1")}
        data = [
            {
                "coordinates": "pkg:pypi/x@1",
                "vulnerabilities": [
                    {"id": "V1", "title": "nop"},
                ],
            }
        ]
        assert a._parse_component_report(data, coord_map=coord_map) == []

    def test_not_list_returns_empty(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        assert a._parse_component_report({}, coord_map={}) == []

    def test_best_effort_key_fallback(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        data = [
            {
                "coordinates": "pkg:pypi/flask@2.0",
                "vulnerabilities": [
                    {"cve": "CVE-2024-9"},
                ],
            }
        ]
        findings = a._parse_component_report(data, coord_map={})
        assert len(findings) == 1

    def test_coordinate_field_fallback(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        coord_map = {"pkg:pypi/numpy@1.0": _CoordKey("pypi", "numpy", "1.0")}
        data = [
            {
                "coordinate": "pkg:pypi/numpy@1.0",
                "vulnerabilities": [
                    {"cve": "CVE-2024-8"},
                ],
            }
        ]
        findings = a._parse_component_report(data, coord_map=coord_map)
        assert len(findings) == 1


class TestLoadFindings:
    def test_empty_gt(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch, gt=[])
        assert a.load_findings() == []

    def test_cache_returns_same(self, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch, gt=[])
        r1 = a.load_findings()
        r2 = a.load_findings()
        assert r1 == r2

    @patch("time.sleep")
    def test_query_401_returns_empty(self, mock_sleep, tmp_path, monkeypatch):
        gt = [
            Finding(ecosystem="pypi", component="flask", version="2.0", purl="pkg:pypi/flask@2.0")
        ]
        a = _make(tmp_path, monkeypatch, gt=gt)
        mock_resp = MagicMock(status_code=401)
        mock_resp.json.return_value = []
        with patch.object(a, "_api_call", return_value=mock_resp):
            assert a.load_findings() == []

    @patch("time.sleep")
    def test_query_200_with_findings(self, mock_sleep, tmp_path, monkeypatch):
        gt = [
            Finding(ecosystem="pypi", component="flask", version="2.0", purl="pkg:pypi/flask@2.0")
        ]
        a = _make(tmp_path, monkeypatch, gt=gt)
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = [
            {
                "coordinates": "pkg:pypi/flask@2.0",
                "vulnerabilities": [{"cve": "CVE-2024-1"}],
            }
        ]
        with patch.object(a, "_api_call", return_value=mock_resp):
            findings = a.load_findings()
        assert len(findings) == 1

    @patch("time.sleep")
    def test_sleep_backoff_retry_after(self, mock_sleep, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        resp = MagicMock()
        resp.headers = {"Retry-After": "5"}
        a._sleep_backoff(1, honor_retry_after=resp)
        mock_sleep.assert_called_once()

    @patch("time.sleep")
    def test_sleep_backoff_no_header(self, mock_sleep, tmp_path, monkeypatch):
        a = _make(tmp_path, monkeypatch)
        a._sleep_backoff(1, honor_retry_after=None)
        mock_sleep.assert_called_once()

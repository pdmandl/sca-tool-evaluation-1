import logging
from unittest.mock import MagicMock, patch

import pytest
import requests

from evaluation.adapters.base import VulnerabilityToolAdapter
from evaluation.adapters.github_advisory import (
    RangeResult,
    _coerce_semver,
    _map_github_ecosystem,
    _normalize_range_expr,
    _try_parse_maven_style_range,
    version_in_range as gh_version_in_range,
)
from evaluation.adapters.osv import OSVAdapter
from evaluation.core.model import Finding


# --------------------------------------------------------------
# A tiny concrete subclass used to exercise VulnerabilityToolAdapter.
# --------------------------------------------------------------
class _DummyAdapter(VulnerabilityToolAdapter):
    def name(self) -> str:
        return "dummy"

    def load_findings_for_component(self, *, ecosystem, component, version):
        return []


class TestBaseAdapter:
    def test_init_creates_logger(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
        monkeypatch.setenv("GROUND_TRUTH", "custom.csv")
        a = _DummyAdapter(config={})
        assert a.name() == "dummy"
        assert a.supports_fp_heuristic() is False
        # API stats start empty
        assert a.get_api_statistics() == {}
        # re-init keeps existing handlers
        a2 = _DummyAdapter(config={})
        assert a2 is not None

    def test_api_call_records_stats(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
        a = _DummyAdapter(config={})
        sess = MagicMock()
        resp = MagicMock()
        resp.json.return_value = {"ok": 1}
        resp.status_code = 200
        sess.request.return_value = resp

        r = a._api_call(session=sess, method="GET", url="http://x")
        assert r is resp
        stats = a.get_api_statistics()
        assert stats["dummy"]["calls"] == 1
        assert stats["dummy"]["avg_ms"] >= 0

    def test_api_call_non_json_body(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
        a = _DummyAdapter(config={})
        sess = MagicMock()
        resp = MagicMock()
        resp.json.side_effect = ValueError("not json")
        resp.text = "hello text"
        sess.request.return_value = resp
        a._api_call(session=sess, method="GET", url="http://x", json_body={"a": 1})

    def test_api_call_exception(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
        a = _DummyAdapter(config={})
        sess = MagicMock()
        sess.request.side_effect = RuntimeError("network dead")
        with pytest.raises(RuntimeError):
            a._api_call(session=sess, method="POST", url="http://x")

    def test_log_cli_call(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
        a = _DummyAdapter(config={})
        a._log_cli_call(
            tool="cyclonedx",
            command=["cyclonedx", "--help"],
            exit_code=0,
            stdout="out",
            stderr="err",
        )

    def test_log_evaluation_sample(self):
        f = Finding(ecosystem="pypi", component="x", version="1", cve="CVE-1", osv_id="OSV-1")
        VulnerabilityToolAdapter.log_evaluation_sample(
            idx=1,
            total=10,
            result="TP",
            finding=f,
        )

    def test_iter_components(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
        monkeypatch.setenv("EVAL_PROGRESS", "0")
        a = _DummyAdapter(config={})
        out = list(a.iter_with_progress([1, 2, 3], desc="x", total=3))
        assert out == [1, 2, 3]


# --------------------------------------------------------------
# OSV adapter
# --------------------------------------------------------------
def _gt(**kw):
    base = dict(
        ecosystem="pypi", component="django", version="3.2.0", cve="CVE-1", ghsa=None, osv_id=None
    )
    base.update(kw)
    return Finding(**base)


class TestOSVAdapter:
    def _make(self, tmp_path, gt=None):
        import os

        os.environ["GROUND_TRUTH_BUILD_PATH"] = str(tmp_path)
        return OSVAdapter(config={"ground_truth": gt or []})

    def test_basic_properties(self, tmp_path):
        a = self._make(tmp_path)
        assert a.name() == "osv"
        assert a.supports_security_findings() is True
        assert a.supports_fp_heuristic() is False
        assert a.load_findings_for_component(ecosystem="pypi", component="x", version="1.0") == []

    def test_map_ecosystem(self, tmp_path):
        a = self._make(tmp_path)
        assert a._map_ecosystem("pypi") == "PyPI"
        assert a._map_ecosystem("npm") == "npm"
        assert a._map_ecosystem("maven") == "Maven"
        assert a._map_ecosystem("nuget") == "NuGet"
        assert a._map_ecosystem("foo") == "foo"

    def test_osv_package_name_pypi(self, tmp_path):
        a = self._make(tmp_path)
        assert a._osv_package_name(_gt(ecosystem="pypi", component="Foo")) == "Foo"

    def test_osv_package_name_maven(self, tmp_path):
        a = self._make(tmp_path)
        f = _gt(ecosystem="maven", component="X", purl="pkg:maven/com.foo/bar@1")
        assert a._osv_package_name(f) == "com.foo:bar"

    def test_osv_package_name_npm(self, tmp_path):
        a = self._make(tmp_path)
        f = _gt(ecosystem="npm", component="x", purl="pkg:npm/lodash@1.0")
        assert a._osv_package_name(f) == "lodash"

    def test_osv_package_name_nuget(self, tmp_path):
        a = self._make(tmp_path)
        f = _gt(ecosystem="nuget", component="n", purl="pkg:nuget/Foo@1")
        assert a._osv_package_name(f) == "Foo"

    def test_osv_package_name_maven_invalid(self, tmp_path):
        a = self._make(tmp_path)
        f = _gt(ecosystem="maven", component="", purl="not-a-valid-purl")
        assert a._osv_package_name(f) is None

    def test_events_to_spec_introduced_fixed(self, tmp_path):
        a = self._make(tmp_path)
        spec = a._events_to_spec([{"introduced": "1.0"}, {"fixed": "2.0"}])
        assert ">=1.0" in spec and "<2.0" in spec

    def test_events_to_spec_introduced_zero(self, tmp_path):
        a = self._make(tmp_path)
        spec = a._events_to_spec([{"introduced": "0"}, {"fixed": "2.0"}])
        assert spec == "<2.0"

    def test_events_to_spec_last_affected(self, tmp_path):
        a = self._make(tmp_path)
        spec = a._events_to_spec([{"introduced": "1.0"}, {"last_affected": "1.5"}])
        assert "<=1.5" in spec

    def test_events_to_spec_empty(self, tmp_path):
        a = self._make(tmp_path)
        assert a._events_to_spec([]) is None

    def test_version_in_spec(self, tmp_path):
        a = self._make(tmp_path)
        assert a._version_in_spec("1.5.0", ">=1.0,<2.0") is True
        assert a._version_in_spec("2.0.0", ">=1.0,<2.0") is False
        assert a._version_in_spec("not-a-version", ">=1") is False

    def test_load_findings_empty(self, tmp_path):
        a = self._make(tmp_path, gt=[])
        assert a.load_findings() == []

    def test_dedup(self, tmp_path):
        a = self._make(tmp_path)
        f1 = Finding(ecosystem="pypi", component="x", version="1", cve="CVE-1", osv_id="OSV-1")
        f2 = Finding(ecosystem="pypi", component="x", version="1", cve="CVE-1", osv_id="OSV-2")
        out = a._dedup_to_gt_granularity([f1, f2])
        assert len(out) == 1

    def test_build_finding(self, tmp_path):
        a = self._make(tmp_path)
        gt = _gt(cve=None, ghsa=None)
        osv = {"id": "OSV-1", "aliases": ["CVE-9", "GHSA-x"], "summary": "sum"}
        f = a._build_finding(gt=gt, osv=osv, match_type="EXACT", affected_range=None)
        assert f.cve == "CVE-9"
        assert f.ghsa == "GHSA-x"
        assert f.source == "osv"

    @patch("evaluation.adapters.osv.requests.Session")
    def test_check_gt_row_exact(self, mock_sess_cls, tmp_path):
        a = self._make(tmp_path)
        resp = MagicMock(status_code=200)
        resp.json.return_value = {
            "vulns": [
                {
                    "id": "OSV-9",
                    "aliases": ["CVE-1"],
                    "affected": [{"versions": ["3.2.0"], "ranges": []}],
                    "summary": "x",
                }
            ]
        }
        sess = MagicMock()
        sess.request.return_value = resp
        mock_sess_cls.return_value = sess

        gt = _gt()
        out = a._check_ground_truth_row(gt)
        assert out is not None
        assert out.match_type == "EXACT"

    @patch("evaluation.adapters.osv.requests.Session")
    def test_check_gt_row_range(self, mock_sess_cls, tmp_path):
        a = self._make(tmp_path)
        resp = MagicMock(status_code=200)
        resp.json.return_value = {
            "vulns": [
                {
                    "id": "OSV-9",
                    "aliases": ["CVE-1"],
                    "affected": [
                        {
                            "versions": [],
                            "ranges": [
                                {"events": [{"introduced": "1.0"}, {"fixed": "5.0"}]},
                            ],
                        }
                    ],
                    "summary": "x",
                }
            ]
        }
        sess = MagicMock()
        sess.request.return_value = resp
        mock_sess_cls.return_value = sess

        out = a._check_ground_truth_row(_gt())
        assert out is not None
        assert out.match_type == "RANGE"

    @patch("evaluation.adapters.osv.requests.Session")
    def test_check_gt_row_404_returns_none(self, mock_sess_cls, tmp_path):
        a = self._make(tmp_path)
        resp = MagicMock(status_code=404)
        resp.json.return_value = {}
        sess = MagicMock()
        sess.request.return_value = resp
        mock_sess_cls.return_value = sess
        assert a._check_ground_truth_row(_gt()) is None

    @patch("evaluation.adapters.osv.requests.Session")
    def test_check_gt_row_disjoint_ids(self, mock_sess_cls, tmp_path):
        a = self._make(tmp_path)
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"vulns": [{"id": "OSV-9", "aliases": [], "affected": []}]}
        sess = MagicMock()
        sess.request.return_value = resp
        mock_sess_cls.return_value = sess
        assert a._check_ground_truth_row(_gt()) is None


# --------------------------------------------------------------
# github_advisory helpers (pure functions, no adapter instance)
# --------------------------------------------------------------
class TestGitHubHelpers:
    def test_map_github_ecosystem(self):
        assert _map_github_ecosystem("pypi") == "PIP"
        assert _map_github_ecosystem("npm") == "NPM"
        assert _map_github_ecosystem("maven") == "MAVEN"
        assert _map_github_ecosystem("nuget") == "NUGET"
        assert _map_github_ecosystem("unknown") is None

    def test_normalize_range_expr(self):
        assert _normalize_range_expr(" >=1,  <2 ") == ">=1 <2"
        assert _normalize_range_expr("") == ""

    def test_try_parse_maven_style(self):
        assert _try_parse_maven_style_range("[1.0,2.0)") == ("1.0", True, "2.0", False)
        assert _try_parse_maven_style_range("(,2.0]") == (None, False, "2.0", True)
        assert _try_parse_maven_style_range("[1.0,)") == ("1.0", True, None, False)
        assert _try_parse_maven_style_range("not-a-range") is None

    def test_coerce_semver(self):
        assert _coerce_semver("1.2.3") is not None
        assert _coerce_semver("junk-version!!!") is None

    def test_version_in_range_empty(self):
        assert gh_version_in_range("pypi", "1.0", None) == RangeResult.UNDECIDABLE
        assert gh_version_in_range("pypi", "1.0", "   ") == RangeResult.UNDECIDABLE

    def test_version_in_range_maven(self):
        assert gh_version_in_range("maven", "1.5.0", "[1.0,2.0)") == RangeResult.IN_RANGE
        assert gh_version_in_range("maven", "2.0.0", "[1.0,2.0)") == RangeResult.OUT_OF_RANGE
        assert gh_version_in_range("maven", "0.5.0", "[1.0,2.0)") == RangeResult.OUT_OF_RANGE

    def test_version_in_range_npm(self):
        r = gh_version_in_range("npm", "1.5.0", ">=1.0.0 <2.0.0")
        assert r in (RangeResult.IN_RANGE, RangeResult.OUT_OF_RANGE)

    def test_version_in_range_pypi(self):
        r = gh_version_in_range("pypi", "1.5.0", ">=1.0,<2.0")
        assert r in (RangeResult.IN_RANGE, RangeResult.OUT_OF_RANGE)

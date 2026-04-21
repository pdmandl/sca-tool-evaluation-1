"""Tests for helper functions in evaluate.py."""

import os

import pytest

from evaluation.core.model import Finding
from evaluation.evaluate import (
    _build_gt_detection_vector,
    _compute_gt_summary,
    _get_identifier,
    _gt_key,
    _init_adapter,
    compute_per_ecosystem_metrics,
    iter_with_progress,
)


def _f(**kw):
    base = dict(ecosystem="pypi", component="x", version="1.0", cve="CVE-1")
    base.update(kw)
    return Finding(**base)


class TestGetIdentifier:
    def test_cve_preferred(self):
        assert _get_identifier(_f(cve="CVE-1", osv_id="OSV-9")) == "CVE-1"

    def test_osv_fallback(self):
        assert _get_identifier(_f(cve=None, osv_id="OSV-9")) == "OSV-9"

    def test_empty(self):
        assert _get_identifier(_f(cve=None, osv_id=None)) == ""


class TestGtKey:
    def test_key_tuple(self):
        f = _f(ecosystem="npm", component="a", version="2", cve="CVE-2", osv_id=None)
        assert _gt_key(f) == ("npm", "a", "2", "CVE-2")


class TestBuildGtDetectionVector:
    def test_perfect_recall(self):
        gt = [_f(cve="CVE-1"), _f(cve="CVE-2")]
        tp = [_f(cve="CVE-1"), _f(cve="CVE-2")]
        vec = _build_gt_detection_vector(gt, tp)
        assert vec == [1, 1]

    def test_no_tp(self):
        gt = [_f(cve="CVE-1"), _f(cve="CVE-2")]
        vec = _build_gt_detection_vector(gt, [])
        assert vec == [0, 0]

    def test_partial_tp(self):
        gt = [_f(cve="CVE-1"), _f(cve="CVE-2"), _f(cve="CVE-3")]
        tp = [_f(cve="CVE-1")]
        vec = _build_gt_detection_vector(gt, tp)
        assert sum(vec) == 1

    def test_unmatched_tp_logs_warning(self):
        gt = [_f(cve="CVE-1")]
        tp = [_f(cve="CVE-UNKNOWN")]
        vec = _build_gt_detection_vector(gt, tp)
        assert vec == [0]

    def test_duplicate_gt_entries(self):
        gt = [_f(cve="CVE-1"), _f(cve="CVE-1")]
        tp = [_f(cve="CVE-1")]
        vec = _build_gt_detection_vector(gt, tp)
        assert sum(vec) == 1


class TestComputeGtSummary:
    def test_basic(self):
        gt = [
            _f(ecosystem="pypi", component="a", version="1", cve="CVE-1"),
            _f(ecosystem="pypi", component="a", version="1", cve="CVE-2"),
            _f(ecosystem="npm", component="b", version="2", cve="CVE-3"),
        ]
        summary = _compute_gt_summary(gt)
        assert summary["pypi"]["Components"] == 1
        assert summary["pypi"]["CVEs"] == 2
        assert summary["npm"]["Vulnerabilities"] == 1

    def test_empty(self):
        assert _compute_gt_summary([]) == {}


class TestComputePerEcosystemMetrics:
    def test_basic(self):
        gt = [_f(cve="CVE-1"), _f(cve="CVE-2"), _f(ecosystem="npm", cve="CVE-3")]
        tp = [_f(cve="CVE-1")]
        fp = [_f(component="z", version="9")]
        fn = [_f(cve="CVE-2")]
        out = compute_per_ecosystem_metrics(ground_truth=gt, tp=tp, fp=fp, fn=fn)
        assert out["pypi"]["TP"] == 1
        assert out["pypi"]["FN"] == 1
        assert 0.0 <= out["pypi"]["Recall"] <= 1.0

    def test_zero_div_handled(self):
        gt = [_f()]
        out = compute_per_ecosystem_metrics(ground_truth=gt, tp=[], fp=[], fn=[])
        assert out["pypi"]["Recall"] == 0.0
        assert out["pypi"]["Overlap"] == 0.0


class TestIterWithProgress:
    def test_yields_items(self, monkeypatch):
        monkeypatch.setenv("EVAL_PROGRESS", "0")
        items = list(iter_with_progress([1, 2, 3], desc="t", unit="x"))
        assert items == [1, 2, 3]


class TestInitAdapter:
    def test_osv(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
        a = _init_adapter("osv", {"ground_truth": []})
        assert a.name() == "osv"

    def test_oss_index(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
        a = _init_adapter("oss-index", {"env": {}})
        assert a.name() == "oss-index"

    def test_unsupported_raises(self):
        with pytest.raises(SystemExit):
            _init_adapter("unknown-tool", {})

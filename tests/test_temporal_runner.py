"""Tests for pure helper functions in temporal_runner.py."""
import json
import os
from pathlib import Path

import pytest

from evaluation.core.model import Finding
from evaluation.temporal_runner import (
    build_combined_detection_vectors,
    collapse_repeat_metrics,
    extract_repeat_metric_runs,
    get_tools,
    hash_findings,
    render_repeat_comparison_text,
    render_tool_summary_text,
    setup_logger,
    summarize_repeat_consistency,
    summarize_tool_metrics,
    tool_artifact_dir,
    tool_output_environment,
    working_directory,
    write_json,
    write_text,
)


def _f(**kw):
    base = dict(ecosystem="pypi", component="x", version="1.0")
    base.update(kw)
    return Finding(**base)


class TestGetTools:
    def test_default(self, monkeypatch):
        monkeypatch.delenv("EVAL_TOOLS", raising=False)
        tools = get_tools()
        assert "dtrack" in tools and "snyk" in tools

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("EVAL_TOOLS", "osv snyk")
        assert get_tools() == ["osv", "snyk"]


class TestHashFindings:
    def test_stable(self):
        f = _f(cve="CVE-1")
        assert hash_findings([f]) == hash_findings([f])

    def test_different_findings(self):
        h1 = hash_findings([_f(cve="CVE-1")])
        h2 = hash_findings([_f(cve="CVE-2")])
        assert h1 != h2

    def test_empty(self):
        h = hash_findings([])
        assert isinstance(h, str) and len(h) == 64

    def test_osv_id_fallback(self):
        f = _f(cve=None, osv_id="OSV-1")
        h = hash_findings([f])
        assert isinstance(h, str)


class TestWorkingDirectory:
    def test_restores_cwd(self, tmp_path):
        original = Path.cwd()
        with working_directory(tmp_path):
            assert Path.cwd() == tmp_path
        assert Path.cwd() == original

    def test_creates_directory(self, tmp_path):
        new_dir = tmp_path / "sub" / "dir"
        with working_directory(new_dir):
            assert new_dir.is_dir()


class TestToolOutputEnvironment:
    def test_sets_and_restores(self, tmp_path, monkeypatch):
        monkeypatch.delenv("EVAL_ARTIFACTS_DIR", raising=False)
        with tool_output_environment(tmp_path):
            assert os.environ.get("EVAL_ARTIFACTS_DIR") == str(tmp_path)
            assert os.environ.get("GROUND_TRUTH_BUILD_PATH") == str(tmp_path)
        assert "EVAL_ARTIFACTS_DIR" not in os.environ

    def test_restores_existing_value(self, tmp_path, monkeypatch):
        monkeypatch.setenv("EVAL_ARTIFACTS_DIR", "/old")
        with tool_output_environment(tmp_path):
            assert os.environ["EVAL_ARTIFACTS_DIR"] == str(tmp_path)
        assert os.environ["EVAL_ARTIFACTS_DIR"] == "/old"


class TestToolArtifactDir:
    def test_path(self, tmp_path):
        p = tool_artifact_dir(tmp_path, 0, "snyk")
        assert p == tmp_path / "artifacts" / "repeat_1" / "snyk"


class TestWriteHelpers:
    def test_write_json(self, tmp_path):
        path = tmp_path / "x.json"
        write_json(path, {"a": 1})
        assert json.loads(path.read_text()) == {"a": 1}

    def test_write_text(self, tmp_path):
        path = tmp_path / "x.txt"
        write_text(path, "hello")
        assert path.read_text() == "hello"


class TestExtractRepeatMetricRuns:
    def test_basic(self):
        runs = [
            {"osv": {"metrics": {"pypi": {"TP": 5}}}, "snyk": {"metrics": {"pypi": {"TP": 3}}}},
            {"osv": {"metrics": {"pypi": {"TP": 6}}}, "snyk": {"metrics": {"pypi": {"TP": 4}}}},
        ]
        result = extract_repeat_metric_runs(runs, ["osv", "snyk"])
        assert result[0]["osv"] == {"pypi": {"TP": 5}}
        assert result[1]["snyk"] == {"pypi": {"TP": 4}}


class TestCollapseRepeatMetrics:
    def test_empty(self):
        assert collapse_repeat_metrics([], ["osv"]) == {}

    def test_averages_floats(self):
        runs = [
            {"osv": {"pypi": {"Recall": 0.8, "TP": 10}}},
            {"osv": {"pypi": {"Recall": 0.6, "TP": 10}}},
        ]
        out = collapse_repeat_metrics(runs, ["osv"])
        assert out["osv"]["pypi"]["Recall"] == pytest.approx(0.7)
        assert out["osv"]["pypi"]["TP"] == 10

    def test_non_integral_tp_stays_float(self):
        runs = [
            {"osv": {"pypi": {"TP": 10}}},
            {"osv": {"pypi": {"TP": 11}}},
        ]
        out = collapse_repeat_metrics(runs, ["osv"])
        # mean = 10.5 → not integer-rounding safely → float
        assert isinstance(out["osv"]["pypi"]["TP"], float)


class TestSummarizeToolMetrics:
    def _agg(self):
        from evaluation.analysis.statistics import aggregate, add_confidence_intervals
        data = [{"osv": {"pypi": {"TP": 8, "FP": 1, "FN": 2, "Recall": 0.8, "Overlap": 0.9}},
                 "snyk": {"pypi": {"TP": 7, "FP": 2, "FN": 3, "Recall": 0.7, "Overlap": 0.8}}}]
        agg = aggregate(data)
        add_confidence_intervals(agg)
        return agg

    def test_sorted_by_recall(self):
        out = summarize_tool_metrics(self._agg())
        recalls = [r["mean_recall"] for r in out]
        assert recalls == sorted(recalls, reverse=True)

    def test_correct_totals(self):
        out = summarize_tool_metrics(self._agg())
        osv_row = next(r for r in out if r["tool"] == "osv")
        assert osv_row["total_tp"] == pytest.approx(8.0)


class TestSummarizeRepeatConsistency:
    def test_stable(self):
        runs = [
            {"osv": {"hash": "abc", "metrics": {}}},
            {"osv": {"hash": "abc", "metrics": {}}},
        ]
        hashes = [{"osv": "abc"}, {"osv": "abc"}]
        out = summarize_repeat_consistency(runs, hashes, ["osv"])
        assert out["osv"]["stable"] is True

    def test_unstable(self):
        runs = [
            {"osv": {"hash": "abc", "metrics": {}}},
            {"osv": {"hash": "xyz", "metrics": {}}},
        ]
        hashes = [{"osv": "abc"}, {"osv": "xyz"}]
        out = summarize_repeat_consistency(runs, hashes, ["osv"])
        assert out["osv"]["stable"] is False


class TestRenderTexts:
    def test_render_tool_summary(self):
        summary = [{"tool": "osv", "mean_recall": 0.8, "mean_overlap": 0.9,
                    "total_tp": 10.0, "total_fp": 1.0, "total_fn": 2.0}]
        text = render_tool_summary_text(summary, markers={"osv": "*"}, baseline="oss-index")
        assert "osv*" in text
        assert "mean_recall" in text

    def test_render_repeat_comparison(self):
        comp = {"osv": {"stable": True, "hashes": ["abc", "abc"]}}
        text = render_repeat_comparison_text(comp)
        assert "osv" in text
        assert "stable=True" in text


class TestBuildCombinedDetectionVectors:
    def test_basic(self):
        runs = [
            {"osv": {"gt_detection": [1, 0, 1]}},
            {"osv": {"gt_detection": [1, 1, 0]}},
        ]
        out = build_combined_detection_vectors(runs, ["osv"])
        assert out["osv"] == [1, 0, 1, 1, 1, 0]

    def test_missing_gt_detection_raises(self):
        runs = [{"osv": {}}]
        with pytest.raises(RuntimeError):
            build_combined_detection_vectors(runs, ["osv"])


class TestSetupLogger:
    def test_creates_log_file(self, tmp_path):
        setup_logger(tmp_path)
        from evaluation.temporal_runner import log
        log.info("test message")
        log_file = tmp_path / "run.log"
        assert log_file.exists()

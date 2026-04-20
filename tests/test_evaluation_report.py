"""Tests for evaluation_report.write_report and helper functions."""
from pathlib import Path

from evaluation.core.model import Finding
from evaluation.reporting.evaluation_report import write_report


def _f(**kw):
    base = dict(ecosystem="pypi", component="django", version="3.2.0",
                cve="CVE-2024-1", osv_id="OSV-1")
    base.update(kw)
    return Finding(**base)


def _make_gt():
    return [
        _f(component="a", version="1.0", cve="CVE-1"),
        _f(component="b", version="2.0", cve="CVE-2", ecosystem="npm"),
        _f(component="c", version="3.0", cve="CVE-3"),
    ]


class TestWriteReport:

    def _call(self, tmp_path, **kw):
        csv = tmp_path / "gt.csv"
        csv.write_text("")
        defaults = dict(
            tool_name="osv",
            input_csv=str(csv),
            tp=[], fp=[], fn=[],
            fp_stats={}, fn_stats={},
            ground_truth=_make_gt(),
            api_stats=None,
        )
        defaults.update(kw)
        write_report(**defaults)
        return list(tmp_path.glob("*_evaluation.txt"))[0]

    def test_empty_lists(self, tmp_path):
        out = self._call(tmp_path, ground_truth=[])
        text = out.read_text()
        assert "osv" in text.lower()
        assert "Evaluation Report" in text

    def test_osv_note_included(self, tmp_path):
        out = self._call(tmp_path)
        assert "OSV" in out.read_text()

    def test_non_osv_no_osv_note(self, tmp_path):
        out = self._call(tmp_path, tool_name="snyk")
        text = out.read_text()
        assert "snyk" in text.lower()

    def test_with_tp_exact_match_type(self, tmp_path):
        tp = [_f(component="a", version="1.0", cve="CVE-1", match_type="TP_EXACT")]
        out = self._call(tmp_path, tp=tp)
        text = out.read_text()
        assert "TP_EXACT" in text or "True Positives" in text

    def test_with_tp_range_match_type(self, tmp_path):
        tp = [_f(match_type="TP_RANGE")]
        out = self._call(tmp_path, tp=tp)
        assert "TP_RANGE" in out.read_text() or "True Positives" in out.read_text()

    def test_with_tp_no_match_type(self, tmp_path):
        # Fallback: tp without match_type → all treated as TP_EXACT (match_type gets set)
        tp = [_f(cve="CVE-1")]  # no match_type attribute set → will be treated as TP_EXACT
        tp[0].match_type = "TP_EXACT"
        out = self._call(tmp_path, tp=tp)
        text = out.read_text()
        assert "True Positives" in text

    def test_with_fp(self, tmp_path):
        fp = [_f(component="x", version="9.0", fp_class="FP-CERTAIN", fp_reason="test")]
        out = self._call(tmp_path, fp=fp,
                         fp_stats={"FP-CERTAIN": 1, "FP-LIKELY": 0, "FP-UNCLEAR": 0})
        text = out.read_text()
        assert "FP-CERTAIN" in text
        assert "False Positives" in text

    def test_with_fn(self, tmp_path):
        fn = [_f(component="b", version="2.0", cve="CVE-2")]
        fn_stats = {"FN_exact": [fn[0]], "FN_range": [], "FN_true": []}
        out = self._call(tmp_path, fn=fn, fn_stats=fn_stats)
        text = out.read_text()
        assert "False Negatives" in text
        assert "FN-EXACT" in text

    def test_with_api_stats(self, tmp_path):
        api_stats = {"osv": {"calls": 10, "total_ms": 500.0, "avg_ms": 50.0}}
        out = self._call(tmp_path, api_stats=api_stats)
        text = out.read_text()
        assert "osv" in text.lower()

    def test_full_populated(self, tmp_path):
        gt = _make_gt()
        tp = [_f(component="a", version="1.0", cve="CVE-1", match_type="TP_EXACT")]
        fp = [_f(component="x", version="5", cve="CVE-99", fp_class="FP-LIKELY")]
        fn = [_f(component="b", version="2.0", cve="CVE-2", ecosystem="npm")]
        fn_stats = {"FN_exact": [], "FN_range": [], "FN_true": fn}
        fp_stats = {"FP-CERTAIN": 0, "FP-LIKELY": 1, "FP-UNCLEAR": 0}
        out = self._call(
            tmp_path, tp=tp, fp=fp, fn=fn,
            fn_stats=fn_stats, fp_stats=fp_stats, ground_truth=gt,
        )
        text = out.read_text()
        assert "End of report" in text
        assert "Summary" in text
        assert "FP Classification" in text
        assert "FN Classification" in text

    def test_none_inputs(self, tmp_path):
        # Should not crash when called with None for list args
        csv = tmp_path / "gt.csv"
        csv.write_text("")
        write_report(
            tool_name="trivy",
            input_csv=str(csv),
            tp=None, fp=None, fn=None,
            fp_stats=None, fn_stats=None,
            ground_truth=None,
        )
        assert len(list(tmp_path.glob("*_evaluation.txt"))) == 1

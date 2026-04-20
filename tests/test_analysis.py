from pathlib import Path

import numpy as np

from evaluation.analysis.fp_heuristics import compute_fp_heuristic_quality
from evaluation.analysis.significance import (
    build_detection_matrix_from_vectors,
    cochran_q_test,
    holm,
    pairwise_mcnemar_from_matrix,
    write_significance_latex,
)
from evaluation.analysis.statistics import (
    add_confidence_intervals,
    aggregate,
    build_gt_summary,
    compute_significance_markers,
    write_ecosystem_summary_table,
    write_latex_stats,
)
from evaluation.analysis.tool_findings import analyze_tool_findings
from evaluation.core.model import Finding


def _f(**kw):
    base = dict(ecosystem="pypi", component="django", version="3.2.0")
    base.update(kw)
    return Finding(**base)


# --------------------------------------------------------------
# fp_heuristics
# --------------------------------------------------------------
class TestFPHeuristics:
    def test_empty_inputs(self):
        out = compute_fp_heuristic_quality([], [])
        assert out["HTP"] == 0 and out["HFN"] == 0
        assert out["heuristic_precision"] == 0.0
        assert out["heuristic_recall"] == 0.0

    def test_mixed(self):
        tp = [_f(fp_class=None), _f(fp_class="FP-CERTAIN")]  # 1 HFP, 1 HTN
        fp = [_f(fp_class="FP-CERTAIN"), _f(fp_class=None)]  # 1 HTP, 1 HFN
        out = compute_fp_heuristic_quality(tp, fp)
        assert out["HTP"] == 1
        assert out["HFN"] == 1
        assert out["HFP"] == 1
        assert out["HTN"] == 1
        assert out["heuristic_precision"] == 0.5
        assert out["heuristic_recall"] == 0.5


# --------------------------------------------------------------
# significance
# --------------------------------------------------------------
class TestSignificance:
    def test_detection_matrix_consistent(self):
        m, tools = build_detection_matrix_from_vectors(
            {"a": [1, 0, 1], "b": [0, 0, 1]}
        )
        assert tools == ["a", "b"]
        assert m.shape == (3, 2)

    def test_detection_matrix_inconsistent(self):
        try:
            build_detection_matrix_from_vectors({"a": [1, 0], "b": [0]})
        except ValueError:
            return
        raise AssertionError("expected ValueError")

    def test_cochran_all_equal(self):
        m = np.array([[1, 1], [1, 1], [0, 0]])
        q, p = cochran_q_test(m)
        assert q == 0.0 and p == 1.0

    def test_cochran_difference(self):
        m = np.array([[1, 0], [1, 0], [1, 0]])
        q, p = cochran_q_test(m)
        assert q > 0

    def test_pairwise_mcnemar(self):
        m = np.array([[1, 0], [1, 0], [0, 1], [1, 1]])
        rows = pairwise_mcnemar_from_matrix(m, ["a", "b"])
        assert len(rows) == 1
        row = rows[0]
        assert row["tool_a"] == "a" and row["tool_b"] == "b"
        assert "p" in row and row["p_adj"] is None

    def test_pairwise_identical(self):
        m = np.array([[1, 1], [0, 0]])
        rows = pairwise_mcnemar_from_matrix(m, ["a", "b"])
        assert rows[0]["p"] == 1.0

    def test_holm_orders(self):
        rows = [{"p": 0.1}, {"p": 0.01}, {"p": 0.5}]
        out = holm(rows)
        assert out[0]["p_adj"] <= out[1]["p_adj"] <= out[2]["p_adj"]

    def test_write_significance_latex(self, tmp_path: Path):
        out = tmp_path / "sig.tex"
        write_significance_latex(
            q=3.5,
            p_q=0.0001,
            rows=[{"tool_a": "a", "tool_b": "b", "n10": 1, "n01": 2, "p": 0.0005, "p_adj": 0.001}],
            output_path=out,
        )
        txt = out.read_text()
        assert "significant" in txt and "\\begin{table*}" in txt


# --------------------------------------------------------------
# tool_findings
# --------------------------------------------------------------
class TestToolFindings:
    def test_aggregations(self):
        gt = [_f(component="a"), _f(component="b", version="1.0")]
        tp = [_f(component="a")]
        fp = [_f(component="a", ecosystem="npm")]
        fn = [_f(component="b", version="1.0")]
        out = analyze_tool_findings(
            ground_truth=gt, tool_findings=tp + fp, tp=tp, fp=fp, fn=fn,
        )
        assert "by_ecosystem" in out and "by_component" in out
        assert len(out["top_fp_components"]) >= 1
        assert len(out["top_fn_components"]) >= 1


# --------------------------------------------------------------
# statistics
# --------------------------------------------------------------
def _make_run():
    return {
        "osv": {
            "pypi": {"TP": 10, "FP": 1, "FN": 2, "Recall": 0.8, "Overlap": 0.7},
            "npm": {"TP": 5, "FP": 0, "FN": 1, "Recall": 0.9, "Overlap": 0.6},
        },
        "snyk": {
            "pypi": {"TP": 9, "FP": 2, "FN": 3, "Recall": 0.75, "Overlap": 0.65},
            "npm": {"TP": 4, "FP": 1, "FN": 2, "Recall": 0.8, "Overlap": 0.55},
        },
    }


class TestStatistics:
    def test_aggregate_empty(self):
        assert aggregate([]) == {}

    def test_aggregate_and_ci(self):
        data = [_make_run(), _make_run()]
        agg = aggregate(data)
        assert agg["osv"]["pypi"]["TP"]["mean"] == 10
        assert agg["osv"]["pypi"]["TP"]["n"] == 2
        add_confidence_intervals(agg)
        assert "ci95" in agg["osv"]["pypi"]["TP"]

    def test_aggregate_single_run_std_zero(self):
        agg = aggregate([_make_run()])
        assert agg["osv"]["pypi"]["TP"]["std"] == 0.0
        add_confidence_intervals(agg)
        assert agg["osv"]["pypi"]["TP"]["ci95"] == 0.0

    def test_build_gt_summary(self):
        gt = [
            _f(component="a", version="1", cve="CVE-1"),
            _f(component="a", version="1", cve="CVE-2"),
            _f(component="b", version="2", ecosystem="npm"),
        ]
        summary = build_gt_summary(gt)
        assert summary["pypi"]["Components"] == 1
        assert summary["pypi"]["CVEs"] == 2
        assert summary["npm"]["Components"] == 1

    def test_write_latex_stats(self, tmp_path: Path):
        agg = aggregate([_make_run()])
        add_confidence_intervals(agg)
        gt_summary = {"pypi": {"Components": 5, "Vulnerabilities": 10, "CVEs": 8},
                      "npm": {"Components": 3, "Vulnerabilities": 5, "CVEs": 5}}
        out = tmp_path / "stats.tex"
        write_latex_stats(agg, gt_summary, out, markers={"osv": "*"})
        assert "\\textbf{TOTAL}" in out.read_text()

    def test_write_ecosystem_summary(self, tmp_path: Path):
        agg = aggregate([_make_run()])
        gt_summary = {"pypi": {"Components": 5, "Vulnerabilities": 10, "CVEs": 8},
                      "npm": {"Components": 3, "Vulnerabilities": 5, "CVEs": 5}}
        out = tmp_path / "eco.tex"
        write_ecosystem_summary_table(agg, gt_summary, out)
        assert "Ecosystem" in out.read_text()

    def test_significance_markers(self):
        rows = [
            {"tool_a": "oss-index", "tool_b": "snyk", "n10": 1, "n01": 10, "p_adj": 0.001},
            {"tool_a": "trivy", "tool_b": "oss-index", "n10": 8, "n01": 1, "p_adj": 0.001},
            {"tool_a": "oss-index", "tool_b": "other", "n10": 1, "n01": 10, "p_adj": 0.9},
        ]
        markers = compute_significance_markers(rows, baseline="oss-index")
        assert markers.get("snyk") == "*"
        assert markers.get("trivy") == "*"
        assert "other" not in markers

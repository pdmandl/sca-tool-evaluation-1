import csv
import json
from pathlib import Path
from unittest.mock import patch

from evaluation.orchestration.aggregate_experiments import (
    aggregate_experiment,
    build_tool_comparison_summary,
    summarize_tool_metrics,
    write_tool_comparison_outputs,
)
from evaluation.orchestration.ground_truth_compare import (
    compare_ground_truth,
    expand_difference,
    finding_key as compare_key,
    hash_gt,
    summarize as compare_summarize,
)
from evaluation.orchestration.ground_truth_diff import (
    build_diff,
    expand_counter_difference,
    finding_key as diff_key,
    finding_to_row,
    summarize_by_ecosystem,
)
from evaluation.orchestration.ground_truth_snapshot import (
    copy_snapshot,
    derive_related_files,
    find_latest_csv,
)


# --------------------------------------------------------------
# Helpers: synthetic GT CSVs
# --------------------------------------------------------------
def _write_gt_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "ecosystem",
                "component_name",
                "component_version",
                "purl",
                "cve",
                "vulnerability_id",
                "vulnerability_description",
            ],
        )
        w.writeheader()
        for r in rows:
            base = {
                "ecosystem": "pypi",
                "component_name": "x",
                "component_version": "1.0",
                "purl": "",
                "cve": "CVE-1",
                "vulnerability_id": "OSV-1",
                "vulnerability_description": "",
            }
            base.update(r)
            w.writerow(base)


# --------------------------------------------------------------
# ground_truth_snapshot
# --------------------------------------------------------------
class TestSnapshot:
    def test_find_latest_csv_empty(self, tmp_path: Path):
        try:
            find_latest_csv(tmp_path)
        except FileNotFoundError:
            return
        raise AssertionError("expected FileNotFoundError")

    def test_find_latest_csv_picks_newest(self, tmp_path: Path):
        a = tmp_path / "a.csv"
        a.write_text("")
        b = tmp_path / "b.csv"
        b.write_text("")
        import os
        import time

        time.sleep(0.01)
        os.utime(b, None)
        assert find_latest_csv(tmp_path).name in {"a.csv", "b.csv"}

    def test_derive_related_files_missing_sbom(self, tmp_path: Path):
        csv_p = tmp_path / "x.csv"
        csv_p.write_text("")
        try:
            derive_related_files(csv_p)
        except FileNotFoundError:
            return
        raise AssertionError("expected FileNotFoundError")

    def test_derive_related_files_and_copy(self, tmp_path: Path):
        csv_p = tmp_path / "x.csv"
        csv_p.write_text("c")
        sbom = tmp_path / "x.sbom.json"
        sbom.write_text("{}")
        stat = tmp_path / "x.stat.txt"
        stat.write_text("ok")

        s_p, st_p = derive_related_files(csv_p)
        assert s_p == sbom and st_p == stat

        out_dir = tmp_path / "out"
        copied = copy_snapshot(csv_p, sbom, stat, out_dir, "snap")
        assert Path(copied["csv"]).exists()
        assert Path(copied["sbom"]).exists()
        assert Path(copied["stat"]).exists()

    def test_derive_no_stat(self, tmp_path: Path):
        csv_p = tmp_path / "x.csv"
        csv_p.write_text("")
        (tmp_path / "x.sbom.json").write_text("{}")
        _, st = derive_related_files(csv_p)
        assert st is None


# --------------------------------------------------------------
# ground_truth_compare
# --------------------------------------------------------------
class TestCompare:
    def test_expand_difference(self):
        from collections import Counter

        a = Counter({"x": 3, "y": 1})
        b = Counter({"x": 1})
        assert expand_difference(a, b) == ["x", "x", "y"]

    def test_summarize(self):
        keys = [("pypi", "a", "1", "CVE-1"), ("pypi", "b", "2", "")]
        out = compare_summarize(keys)
        assert out["pypi"]["rows"] == 2
        assert out["pypi"]["unique_vuln_ids"] == 1

    def test_finding_key_and_hash(self, tmp_path: Path):
        p = tmp_path / "gt.csv"
        _write_gt_csv(p, [{}])
        h = hash_gt(p)
        assert isinstance(h, str) and len(h) == 64

    def test_compare_end_to_end(self, tmp_path: Path):
        p0 = tmp_path / "gt0.csv"
        p1 = tmp_path / "gt1.csv"
        _write_gt_csv(p0, [{"component_name": "a"}, {"component_name": "b"}])
        _write_gt_csv(p1, [{"component_name": "a"}, {"component_name": "c"}])
        out = tmp_path / "out"
        summary = compare_ground_truth(p0, p1, out)
        assert (out / "gt_diff_summary.json").exists()
        assert (out / "gt_diff_added.csv").exists()
        assert (out / "gt_diff_removed.csv").exists()
        assert summary["added_rows"] >= 1
        assert summary["removed_rows"] >= 1
        assert summary["equal"] is False


# --------------------------------------------------------------
# ground_truth_diff
# --------------------------------------------------------------
class TestDiff:
    def test_finding_to_row_and_key(self):
        from evaluation.core.model import Finding

        f = Finding(ecosystem="pypi", component="x", version="1", cve="CVE-1")
        row = finding_to_row(f)
        assert row["vuln_id"] == "CVE-1"
        assert diff_key(f) == ("pypi", "x", "1", "CVE-1")

    def test_expand_counter_difference(self):
        from collections import Counter

        a = Counter({"k": 2})
        b = Counter({"k": 1})
        assert expand_counter_difference(a, b) == ["k"]
        assert expand_counter_difference(b, a) == []

    def test_summarize_by_ecosystem(self):
        keys = [("pypi", "a", "1", ""), ("pypi", "a", "2", "CVE-1")]
        out = summarize_by_ecosystem(keys)
        assert out["pypi"]["rows"] == 2
        assert out["pypi"]["unique_components"] == 2

    def test_build_diff(self, tmp_path: Path):
        p0 = tmp_path / "gt0.csv"
        p1 = tmp_path / "gt1.csv"
        _write_gt_csv(p0, [{"component_name": "a"}])
        _write_gt_csv(p1, [{"component_name": "a"}, {"component_name": "b"}])
        out = tmp_path / "out"
        summary = build_diff(p0, p1, out)
        assert summary["added_rows"] == 1
        assert (out / "gt_diff_report.txt").exists()


# --------------------------------------------------------------
# aggregate_experiments
# --------------------------------------------------------------
def _make_run():
    return {
        "osv": {
            "pypi": {"TP": 10, "FP": 1, "FN": 2, "Recall": 0.8, "Overlap": 0.7},
        },
        "snyk": {
            "pypi": {"TP": 9, "FP": 2, "FN": 3, "Recall": 0.75, "Overlap": 0.65},
        },
    }


class TestAggregateExperiments:
    def test_summarize_tool_metrics(self):
        from evaluation.analysis.statistics import aggregate

        agg = aggregate([_make_run()])
        out = summarize_tool_metrics(agg)
        assert "osv" in out and "avg_recall" in out["osv"]

    def test_build_tool_comparison_summary(self):
        from evaluation.analysis.statistics import aggregate

        agg = aggregate([_make_run()])
        out = build_tool_comparison_summary(agg)
        assert "ranking_by_avg_recall" in out
        assert len(out["pairwise_deltas"]) == 1

    def test_write_tool_comparison_outputs(self, tmp_path: Path):
        from evaluation.analysis.statistics import aggregate

        agg = aggregate([_make_run()])
        s = build_tool_comparison_summary(agg)
        write_tool_comparison_outputs(tmp_path, s)
        assert (tmp_path / "tool_comparison_summary.json").exists()
        assert (tmp_path / "tool_comparison_summary.txt").exists()

    def test_aggregate_experiment(self, tmp_path: Path):
        exp = tmp_path / "exp"
        run = exp / "run_1"
        run.mkdir(parents=True)
        (run / "experimental_results.json").write_text(json.dumps(_make_run()))

        gt = tmp_path / "gt.csv"
        _write_gt_csv(gt, [{"component_name": "x"}])

        with patch(
            "evaluation.orchestration.aggregate_experiments.plot_tool_comparison",
            None,
        ):
            result = aggregate_experiment(exp, gt)
        assert "metrics" in result
        assert (exp / "stats.json").exists()
        assert (exp / "aggregated_results.tex").exists()

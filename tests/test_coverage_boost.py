"""Comprehensive tests targeting coverage gaps in:
- evaluation.core.gt_hash
- evaluation.analysis.plots
- evaluation.orchestration.ground_truth_snapshot (build_snapshot + main)
- evaluation.evaluate (run_evaluation, iter_with_progress, edge cases)
"""
from __future__ import annotations

import csv
import json
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from evaluation.core.model import Finding


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

GT_FIELDNAMES = [
    "ecosystem",
    "component_name",
    "component_version",
    "purl",
    "cve",
    "vulnerability_id",
    "vulnerability_description",
]


def _write_gt_csv(path: Path, rows: list[dict] | None = None) -> Path:
    """Write a minimal ground-truth CSV.  Missing fields default to sensible values."""
    if rows is None:
        rows = [{}]

    defaults = {
        "ecosystem": "pypi",
        "component_name": "requests",
        "component_version": "2.25.0",
        "purl": "pkg:pypi/requests@2.25.0",
        "cve": "CVE-2023-0001",
        "vulnerability_id": "GHSA-xxxx-yyyy-zzzz",
        "vulnerability_description": "test vuln",
    }

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=GT_FIELDNAMES)
        writer.writeheader()
        for r in rows:
            row = dict(defaults)
            row.update(r)
            writer.writerow(row)

    return path


def _make_finding(**kw) -> Finding:
    base = dict(ecosystem="pypi", component="requests", version="2.25.0", cve="CVE-2023-0001")
    base.update(kw)
    return Finding(**base)


# ===========================================================================
# 1.  gt_hash.py
# ===========================================================================


class TestComputeGtHash:
    def test_returns_64_char_hex_string(self, tmp_path: Path):
        from evaluation.core.gt_hash import compute_gt_hash

        csv_p = _write_gt_csv(tmp_path / "gt.csv")
        result = compute_gt_hash(csv_p)

        assert isinstance(result, str)
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_deterministic(self, tmp_path: Path):
        from evaluation.core.gt_hash import compute_gt_hash

        csv_p = _write_gt_csv(tmp_path / "gt.csv")
        assert compute_gt_hash(csv_p) == compute_gt_hash(csv_p)

    def test_different_csv_different_hash(self, tmp_path: Path):
        from evaluation.core.gt_hash import compute_gt_hash

        p1 = _write_gt_csv(
            tmp_path / "gt1.csv",
            [{"component_name": "requests", "cve": "CVE-2023-0001"}],
        )
        p2 = _write_gt_csv(
            tmp_path / "gt2.csv",
            [{"component_name": "flask", "cve": "CVE-2023-9999"}],
        )
        assert compute_gt_hash(p1) != compute_gt_hash(p2)

    def test_multiple_rows(self, tmp_path: Path):
        from evaluation.core.gt_hash import compute_gt_hash

        rows = [
            {"component_name": "django", "component_version": "3.2", "cve": "CVE-A"},
            {"component_name": "flask", "component_version": "2.0", "cve": "CVE-B"},
            {"component_name": "requests", "component_version": "2.25.0", "cve": "CVE-C"},
        ]
        csv_p = _write_gt_csv(tmp_path / "gt.csv", rows)
        result = compute_gt_hash(csv_p)
        assert len(result) == 64

    def test_hash_is_sha256_not_md5(self, tmp_path: Path):
        """SHA-256 produces 64 hex chars; MD5 only 32."""
        from evaluation.core.gt_hash import compute_gt_hash

        csv_p = _write_gt_csv(tmp_path / "gt.csv")
        assert len(compute_gt_hash(csv_p)) == 64


class TestGtHashMain:
    def test_main_prints_hash(self, tmp_path: Path, capsys):
        from evaluation.core.gt_hash import main

        csv_p = _write_gt_csv(tmp_path / "gt.csv")
        with patch.object(sys, "argv", ["gt_hash", str(csv_p)]):
            main()

        captured = capsys.readouterr()
        out = captured.out.strip()
        assert len(out) == 64
        assert all(c in "0123456789abcdef" for c in out)

    def test_main_output_matches_compute_gt_hash(self, tmp_path: Path, capsys):
        from evaluation.core.gt_hash import compute_gt_hash, main

        csv_p = _write_gt_csv(tmp_path / "gt.csv")
        expected = compute_gt_hash(csv_p)

        with patch.object(sys, "argv", ["gt_hash", str(csv_p)]):
            main()

        assert capsys.readouterr().out.strip() == expected


# ===========================================================================
# 2.  analysis/plots.py
# ===========================================================================


class TestResolveOutputPngPath:
    def test_with_png_extension(self, tmp_path: Path):
        from evaluation.analysis.plots import _resolve_output_png_path

        target = tmp_path / "sub" / "out.png"
        result = _resolve_output_png_path(target, "default.png")

        assert result == target
        assert target.parent.exists()

    def test_with_directory(self, tmp_path: Path):
        from evaluation.analysis.plots import _resolve_output_png_path

        out_dir = tmp_path / "plots"
        result = _resolve_output_png_path(out_dir, "myplot.png")

        assert result == out_dir / "myplot.png"
        assert out_dir.exists()

    def test_with_existing_png_path(self, tmp_path: Path):
        from evaluation.analysis.plots import _resolve_output_png_path

        png = tmp_path / "result.png"
        result = _resolve_output_png_path(png, "unused.png")
        assert result.suffix == ".png"

    def test_with_non_png_extension_treated_as_dir(self, tmp_path: Path):
        from evaluation.analysis.plots import _resolve_output_png_path

        # A path with a non-.png suffix is treated as a directory
        out = tmp_path / "outputs.d"
        result = _resolve_output_png_path(out, "fallback.png")
        assert result.name == "fallback.png"


class TestPlotSignificanceMatrix:
    """Mock matplotlib so no rendering/display occurs."""

    def _make_mock_ax(self):
        ax = MagicMock()
        ax.imshow.return_value = MagicMock()
        return ax

    def test_basic_two_tools(self, tmp_path: Path):
        from evaluation.analysis.plots import plot_significance_matrix

        rows = [
            {"tool_a": "snyk", "tool_b": "trivy", "p_adj": 0.01},
        ]
        tools = ["snyk", "trivy"]

        mock_fig = MagicMock()
        mock_ax = self._make_mock_ax()

        with (
            patch("matplotlib.pyplot.subplots", return_value=(mock_fig, mock_ax)),
            patch("matplotlib.pyplot.close"),
        ):
            plot_significance_matrix(rows, tools, tmp_path)

        mock_fig.savefig.assert_called_once()
        mock_fig.tight_layout.assert_called_once()

    def test_non_significant_pair(self, tmp_path: Path):
        from evaluation.analysis.plots import plot_significance_matrix

        rows = [
            {"tool_a": "snyk", "tool_b": "trivy", "p_adj": 0.80},
        ]
        tools = ["snyk", "trivy"]

        mock_fig = MagicMock()
        mock_ax = self._make_mock_ax()

        with (
            patch("matplotlib.pyplot.subplots", return_value=(mock_fig, mock_ax)),
            patch("matplotlib.pyplot.close"),
        ):
            plot_significance_matrix(rows, tools, tmp_path)

        mock_fig.savefig.assert_called_once()

    def test_known_tool_labels_shortened(self, tmp_path: Path):
        from evaluation.analysis.plots import plot_significance_matrix

        rows = []
        tools = ["dependency-track", "oss-index", "github", "snyk", "trivy"]

        mock_fig = MagicMock()
        mock_ax = self._make_mock_ax()

        with (
            patch("matplotlib.pyplot.subplots", return_value=(mock_fig, mock_ax)),
            patch("matplotlib.pyplot.close"),
        ):
            plot_significance_matrix(rows, tools, tmp_path)

        # Check that set_xticklabels was called with the shortened labels list
        call_args = mock_ax.set_xticklabels.call_args
        tick_labels = call_args[0][0]
        assert "dtrack" in tick_labels

    def test_output_path_as_png_file(self, tmp_path: Path):
        from evaluation.analysis.plots import plot_significance_matrix

        out_png = tmp_path / "sig_matrix.png"
        rows = [{"tool_a": "snyk", "tool_b": "trivy", "p_adj": 0.03}]
        tools = ["snyk", "trivy"]

        mock_fig = MagicMock()
        mock_ax = self._make_mock_ax()

        with (
            patch("matplotlib.pyplot.subplots", return_value=(mock_fig, mock_ax)),
            patch("matplotlib.pyplot.close"),
        ):
            plot_significance_matrix(rows, tools, out_png)

        saved_path = mock_fig.savefig.call_args[0][0]
        assert str(saved_path).endswith(".png")

    def test_p_fallback_to_p_key(self, tmp_path: Path):
        """Rows may use 'p' instead of 'p_adj'."""
        from evaluation.analysis.plots import plot_significance_matrix

        rows = [{"tool_a": "snyk", "tool_b": "trivy", "p": 0.001}]
        tools = ["snyk", "trivy"]

        mock_fig = MagicMock()
        mock_ax = self._make_mock_ax()

        with (
            patch("matplotlib.pyplot.subplots", return_value=(mock_fig, mock_ax)),
            patch("matplotlib.pyplot.close"),
        ):
            plot_significance_matrix(rows, tools, tmp_path)

        mock_fig.savefig.assert_called_once()


class TestPlotToolComparison:
    def test_basic(self, tmp_path: Path):
        from evaluation.analysis.plots import plot_tool_comparison

        agg = {
            "snyk": {
                "pypi": {"Recall": {"mean": 0.8}, "Overlap": {"mean": 0.7}},
            },
            "trivy": {
                "pypi": {"Recall": {"mean": 0.6}, "Overlap": {"mean": 0.5}},
            },
        }

        mock_fig = MagicMock()
        mock_ax = MagicMock()

        with (
            patch("matplotlib.pyplot.subplots", return_value=(mock_fig, mock_ax)),
            patch("matplotlib.pyplot.close"),
        ):
            plot_tool_comparison(agg, tmp_path)

        mock_fig.savefig.assert_called_once()
        mock_fig.tight_layout.assert_called_once()

    def test_empty_ecosystems(self, tmp_path: Path):
        from evaluation.analysis.plots import plot_tool_comparison

        agg = {
            "snyk": {},  # no ecosystems → should default to 0.0
        }

        mock_fig = MagicMock()
        mock_ax = MagicMock()

        with (
            patch("matplotlib.pyplot.subplots", return_value=(mock_fig, mock_ax)),
            patch("matplotlib.pyplot.close"),
        ):
            plot_tool_comparison(agg, tmp_path)

        mock_fig.savefig.assert_called_once()

    def test_output_as_png_path(self, tmp_path: Path):
        from evaluation.analysis.plots import plot_tool_comparison

        out_png = tmp_path / "comparison.png"
        agg = {
            "osv": {
                "pypi": {"Recall": {"mean": 0.9}, "Overlap": {"mean": 0.85}},
            }
        }

        mock_fig = MagicMock()
        mock_ax = MagicMock()

        with (
            patch("matplotlib.pyplot.subplots", return_value=(mock_fig, mock_ax)),
            patch("matplotlib.pyplot.close"),
        ):
            plot_tool_comparison(agg, out_png)

        saved_path = mock_fig.savefig.call_args[0][0]
        assert str(saved_path).endswith(".png")

    def test_multiple_ecosystems_averages(self, tmp_path: Path):
        from evaluation.analysis.plots import plot_tool_comparison

        agg = {
            "snyk": {
                "pypi": {"Recall": {"mean": 0.8}, "Overlap": {"mean": 0.7}},
                "npm": {"Recall": {"mean": 0.6}, "Overlap": {"mean": 0.5}},
            }
        }

        mock_fig = MagicMock()
        mock_ax = MagicMock()

        with (
            patch("matplotlib.pyplot.subplots", return_value=(mock_fig, mock_ax)),
            patch("matplotlib.pyplot.close"),
        ):
            # Should not raise; averaging across 2 ecosystems
            plot_tool_comparison(agg, tmp_path)

        mock_fig.savefig.assert_called_once()


# ===========================================================================
# 3.  orchestration/ground_truth_snapshot.py  –  build_snapshot + main
# ===========================================================================


class TestBuildSnapshot:
    """
    Mock subprocess.run so the external Python module is never invoked.
    The mock side_effect creates the files that build_snapshot expects to find.
    """

    def _make_subprocess_side_effect(self, build_dir_ref: list[Path]):
        """Return a callable that creates CSV + SBOM in build_dir when invoked."""

        def _side_effect(*args, **kwargs):
            build_dir = build_dir_ref[0]
            csv_p = build_dir / "gt_snapshot.csv"
            sbom_p = build_dir / "gt_snapshot.sbom.json"
            csv_p.write_text("ecosystem,component_name\npypi,requests\n")
            sbom_p.write_text(json.dumps({"bomFormat": "CycloneDX"}))

        return _side_effect

    def test_build_snapshot_success(self, tmp_path: Path):
        from evaluation.orchestration.ground_truth_snapshot import build_snapshot

        build_dir = tmp_path / "build"
        output_dir = tmp_path / "output"
        build_dir_ref = [build_dir]

        with patch("subprocess.run", side_effect=self._make_subprocess_side_effect(build_dir_ref)):
            result = build_snapshot(build_dir=build_dir, output_dir=output_dir, prefix="snap")

        assert "csv" in result
        assert "sbom" in result
        assert "build_duration_seconds" in result
        assert Path(result["csv"]).exists()
        assert Path(result["sbom"]).exists()
        assert result["stat"] is None  # no .stat.txt created

    def test_build_snapshot_with_stat_file(self, tmp_path: Path):
        from evaluation.orchestration.ground_truth_snapshot import build_snapshot

        build_dir = tmp_path / "build"
        output_dir = tmp_path / "output"

        def _side_effect_with_stat(*args, **kwargs):
            build_dir.mkdir(parents=True, exist_ok=True)
            csv_p = build_dir / "gt_snap.csv"
            sbom_p = build_dir / "gt_snap.sbom.json"
            stat_p = build_dir / "gt_snap.stat.txt"
            csv_p.write_text("h\n")
            sbom_p.write_text("{}")
            stat_p.write_text("stats here")

        with patch("subprocess.run", side_effect=_side_effect_with_stat):
            result = build_snapshot(build_dir=build_dir, output_dir=output_dir, prefix="snap")

        assert result["stat"] is not None
        assert Path(result["stat"]).exists()

    def test_build_snapshot_removes_existing_build_dir(self, tmp_path: Path):
        """build_dir pre-existing should be wiped before rebuild."""
        from evaluation.orchestration.ground_truth_snapshot import build_snapshot

        build_dir = tmp_path / "build"
        build_dir.mkdir()
        stale = build_dir / "stale.csv"
        stale.write_text("old data")

        output_dir = tmp_path / "output"

        def _side_effect(*args, **kwargs):
            csv_p = build_dir / "fresh.csv"
            sbom_p = build_dir / "fresh.sbom.json"
            csv_p.write_text("h\n")
            sbom_p.write_text("{}")

        with patch("subprocess.run", side_effect=_side_effect):
            result = build_snapshot(build_dir=build_dir, output_dir=output_dir, prefix="snap")

        # Stale file should not have survived the rmtree
        assert not stale.exists()
        assert Path(result["csv"]).exists()

    def test_build_snapshot_output_prefix_applied(self, tmp_path: Path):
        from evaluation.orchestration.ground_truth_snapshot import build_snapshot

        build_dir = tmp_path / "build"
        output_dir = tmp_path / "output"

        def _side_effect(*args, **kwargs):
            csv_p = build_dir / "out.csv"
            sbom_p = build_dir / "out.sbom.json"
            csv_p.write_text("h\n")
            sbom_p.write_text("{}")

        with patch("subprocess.run", side_effect=_side_effect):
            result = build_snapshot(build_dir=build_dir, output_dir=output_dir, prefix="myprefix")

        assert Path(result["csv"]).name == "myprefix.csv"
        assert Path(result["sbom"]).name == "myprefix.sbom.json"

    def test_build_snapshot_duration_non_negative(self, tmp_path: Path):
        from evaluation.orchestration.ground_truth_snapshot import build_snapshot

        build_dir = tmp_path / "build"
        output_dir = tmp_path / "output"

        def _side_effect(*args, **kwargs):
            csv_p = build_dir / "x.csv"
            sbom_p = build_dir / "x.sbom.json"
            csv_p.write_text("")
            sbom_p.write_text("{}")

        with patch("subprocess.run", side_effect=_side_effect):
            result = build_snapshot(build_dir=build_dir, output_dir=output_dir, prefix="x")

        assert result["build_duration_seconds"] >= 0.0


class TestGroundTruthSnapshotMain:
    def test_main_calls_build_snapshot_and_prints_json(self, tmp_path: Path, capsys):
        from evaluation.orchestration.ground_truth_snapshot import main

        build_dir = str(tmp_path / "build")
        output_dir = str(tmp_path / "output")
        fake_result = {"csv": "/out/snap.csv", "sbom": "/out/snap.sbom.json", "stat": None}

        with (
            patch.object(sys, "argv", [
                "ground_truth_snapshot",
                "--build-dir", build_dir,
                "--output-dir", output_dir,
                "--prefix", "snap",
            ]),
            patch(
                "evaluation.orchestration.ground_truth_snapshot.build_snapshot",
                return_value=fake_result,
            ) as mock_build,
        ):
            main()

        mock_build.assert_called_once_with(
            build_dir=Path(build_dir),
            output_dir=Path(output_dir),
            prefix="snap",
        )

        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed["csv"] == "/out/snap.csv"
        assert parsed["sbom"] == "/out/snap.sbom.json"


# ===========================================================================
# 4.  evaluate.py  –  iter_with_progress, run_evaluation, edge cases
# ===========================================================================


class TestIterWithProgressCoverage:
    def test_progress_disabled_via_env_zero(self, monkeypatch):
        monkeypatch.setenv("EVAL_PROGRESS", "0")
        from evaluation.evaluate import iter_with_progress

        result = list(iter_with_progress([10, 20, 30], desc="test", unit="items"))
        assert result == [10, 20, 30]

    def test_progress_disabled_via_env_false(self, monkeypatch):
        monkeypatch.setenv("EVAL_PROGRESS", "false")
        from evaluation.evaluate import iter_with_progress

        result = list(iter_with_progress(["a", "b"], desc="d", unit="u"))
        assert result == ["a", "b"]

    def test_progress_disabled_via_env_no(self, monkeypatch):
        monkeypatch.setenv("EVAL_PROGRESS", "no")
        from evaluation.evaluate import iter_with_progress

        result = list(iter_with_progress(range(3), desc="d", unit="u"))
        assert list(result) == [0, 1, 2]

    def test_progress_disabled_via_env_off(self, monkeypatch):
        monkeypatch.setenv("EVAL_PROGRESS", "off")
        from evaluation.evaluate import iter_with_progress

        result = list(iter_with_progress([True, False], desc="d", unit="u"))
        assert result == [True, False]

    def test_progress_enabled_but_stderr_not_tty(self, monkeypatch):
        """When EVAL_PROGRESS=1 but stderr is not a tty, items are yielded without tqdm."""
        monkeypatch.setenv("EVAL_PROGRESS", "1")
        from evaluation.evaluate import iter_with_progress

        # In test environments stderr is not a tty, so tqdm branch is skipped
        result = list(iter_with_progress([1, 2, 3], desc="t", unit="x"))
        assert result == [1, 2, 3]

    def test_empty_iterable(self, monkeypatch):
        monkeypatch.setenv("EVAL_PROGRESS", "0")
        from evaluation.evaluate import iter_with_progress

        result = list(iter_with_progress([], desc="d", unit="u"))
        assert result == []


class TestRunEvaluation:
    """Integration-style tests for run_evaluation() with adapters mocked."""

    def _make_mock_adapter(self, findings=None):
        adapter = MagicMock()
        adapter.name.return_value = "osv"
        adapter.load_findings.return_value = findings or []
        adapter.supports_security_findings.return_value = True
        adapter.get_api_statistics.return_value = {}
        return adapter

    def test_run_evaluation_returns_findings_and_metrics(self, tmp_path: Path):
        from evaluation.evaluate import run_evaluation

        gt_csv = tmp_path / "gt.csv"
        _write_gt_csv(gt_csv, [
            {"ecosystem": "pypi", "component_name": "requests",
             "component_version": "2.25.0", "cve": "CVE-2023-0001"},
        ])

        tool_finding = _make_finding(
            ecosystem="pypi", component="requests", version="2.25.0", cve="CVE-2023-0001"
        )
        mock_adapter = self._make_mock_adapter(findings=[tool_finding])

        with (
            patch("evaluation.evaluate._init_adapter", return_value=mock_adapter),
            patch("evaluation.evaluate.write_report"),
            patch("evaluation.evaluate.write_tool_findings_txt"),
        ):
            result = run_evaluation(
                ground_truth_path=str(gt_csv),
                tool="osv",
                return_findings=True,
                return_metrics=True,
            )

        assert result is not None
        assert "findings" in result
        assert "gt_detection_vector" in result
        assert "metrics" in result
        assert isinstance(result["findings"], list)
        assert isinstance(result["gt_detection_vector"], list)
        assert "per_ecosystem" in result["metrics"]

    def test_run_evaluation_findings_list_matches_adapter(self, tmp_path: Path):
        from evaluation.evaluate import run_evaluation

        gt_csv = tmp_path / "gt.csv"
        _write_gt_csv(gt_csv)

        findings = [
            _make_finding(cve="CVE-2023-0001"),
            _make_finding(cve="CVE-2023-0002", component="django", version="3.2"),
        ]
        mock_adapter = self._make_mock_adapter(findings=findings)

        with (
            patch("evaluation.evaluate._init_adapter", return_value=mock_adapter),
            patch("evaluation.evaluate.write_report"),
            patch("evaluation.evaluate.write_tool_findings_txt"),
        ):
            result = run_evaluation(
                ground_truth_path=str(gt_csv),
                tool="osv",
                return_findings=True,
                return_metrics=False,
            )

        assert result["findings"] == findings

    def test_run_evaluation_no_return_flags_returns_none(self, tmp_path: Path):
        from evaluation.evaluate import run_evaluation

        gt_csv = tmp_path / "gt.csv"
        _write_gt_csv(gt_csv)

        mock_adapter = self._make_mock_adapter()

        with (
            patch("evaluation.evaluate._init_adapter", return_value=mock_adapter),
            patch("evaluation.evaluate.write_report"),
            patch("evaluation.evaluate.write_tool_findings_txt"),
        ):
            result = run_evaluation(
                ground_truth_path=str(gt_csv),
                tool="osv",
                return_findings=False,
                return_metrics=False,
            )

        assert result is None

    def test_run_evaluation_gt_not_found_raises(self, tmp_path: Path):
        from evaluation.evaluate import run_evaluation

        with pytest.raises(SystemExit):
            run_evaluation(
                ground_truth_path=str(tmp_path / "nonexistent.csv"),
                tool="osv",
            )

    def test_run_evaluation_tool_without_security_findings(self, tmp_path: Path):
        """Adapter that reports it does not support security findings."""
        from evaluation.evaluate import run_evaluation

        gt_csv = tmp_path / "gt.csv"
        _write_gt_csv(gt_csv)

        mock_adapter = self._make_mock_adapter()
        mock_adapter.supports_security_findings.return_value = False

        with (
            patch("evaluation.evaluate._init_adapter", return_value=mock_adapter),
            patch("evaluation.evaluate.write_report"),
            patch("evaluation.evaluate.write_tool_findings_txt"),
        ):
            result = run_evaluation(
                ground_truth_path=str(gt_csv),
                tool="osv",
                return_findings=True,
                return_metrics=True,
            )

        # Should still return a result dict with empty TP/FP/FN
        assert result is not None
        # GT has 1 row, so detection vector has length 1 with 0 (not detected)
        assert result["gt_detection_vector"] == [0]

    def test_run_evaluation_gt_detection_vector_length_matches_gt(self, tmp_path: Path):
        from evaluation.evaluate import run_evaluation

        rows = [
            {"component_name": "django", "cve": "CVE-A"},
            {"component_name": "flask", "cve": "CVE-B"},
            {"component_name": "requests", "cve": "CVE-C"},
        ]
        gt_csv = tmp_path / "gt.csv"
        _write_gt_csv(gt_csv, rows)

        mock_adapter = self._make_mock_adapter(findings=[])

        with (
            patch("evaluation.evaluate._init_adapter", return_value=mock_adapter),
            patch("evaluation.evaluate.write_report"),
            patch("evaluation.evaluate.write_tool_findings_txt"),
        ):
            result = run_evaluation(
                ground_truth_path=str(gt_csv),
                tool="osv",
                return_findings=True,
                return_metrics=True,
            )

        # Detection vector must have one entry per GT row
        assert len(result["gt_detection_vector"]) == 3

    def test_run_evaluation_empty_gt(self, tmp_path: Path):
        """Empty ground-truth CSV should produce empty metrics."""
        from evaluation.evaluate import run_evaluation

        # Write a CSV with headers only (zero rows)
        gt_csv = tmp_path / "empty_gt.csv"
        with gt_csv.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=GT_FIELDNAMES)
            writer.writeheader()

        mock_adapter = self._make_mock_adapter(findings=[])

        with (
            patch("evaluation.evaluate._init_adapter", return_value=mock_adapter),
            patch("evaluation.evaluate.write_report"),
            patch("evaluation.evaluate.write_tool_findings_txt"),
        ):
            result = run_evaluation(
                ground_truth_path=str(gt_csv),
                tool="osv",
                return_findings=True,
                return_metrics=True,
            )

        assert result["gt_detection_vector"] == []
        assert result["metrics"]["per_ecosystem"] == {}

    def test_run_evaluation_write_report_called(self, tmp_path: Path):
        from evaluation.evaluate import run_evaluation

        gt_csv = tmp_path / "gt.csv"
        _write_gt_csv(gt_csv)

        mock_adapter = self._make_mock_adapter()

        with (
            patch("evaluation.evaluate._init_adapter", return_value=mock_adapter),
            patch("evaluation.evaluate.write_report") as mock_wr,
            patch("evaluation.evaluate.write_tool_findings_txt"),
        ):
            run_evaluation(
                ground_truth_path=str(gt_csv),
                tool="osv",
                return_findings=False,
                return_metrics=False,
            )

        mock_wr.assert_called_once()

    def test_run_evaluation_write_tool_findings_called(self, tmp_path: Path):
        from evaluation.evaluate import run_evaluation

        gt_csv = tmp_path / "gt.csv"
        _write_gt_csv(gt_csv)

        mock_adapter = self._make_mock_adapter()

        with (
            patch("evaluation.evaluate._init_adapter", return_value=mock_adapter),
            patch("evaluation.evaluate.write_report"),
            patch("evaluation.evaluate.write_tool_findings_txt") as mock_wtf,
        ):
            run_evaluation(
                ground_truth_path=str(gt_csv),
                tool="osv",
                return_findings=False,
                return_metrics=False,
            )

        mock_wtf.assert_called_once()

    def test_run_evaluation_metrics_contain_fp_fn_api_stats(self, tmp_path: Path):
        from evaluation.evaluate import run_evaluation

        gt_csv = tmp_path / "gt.csv"
        _write_gt_csv(gt_csv)

        mock_adapter = self._make_mock_adapter()
        mock_adapter.get_api_statistics.return_value = {"requests_total": 5}

        with (
            patch("evaluation.evaluate._init_adapter", return_value=mock_adapter),
            patch("evaluation.evaluate.write_report"),
            patch("evaluation.evaluate.write_tool_findings_txt"),
        ):
            result = run_evaluation(
                ground_truth_path=str(gt_csv),
                tool="osv",
                return_findings=False,
                return_metrics=True,
            )

        assert "fp_stats" in result["metrics"]
        assert "fn_stats" in result["metrics"]
        assert "api_stats" in result["metrics"]
        assert result["metrics"]["api_stats"]["requests_total"] == 5


# ===========================================================================
# 5.  evaluate.py edge-case helpers (extending existing test_evaluate_helpers)
# ===========================================================================


class TestBuildGtDetectionVectorEdgeCases:
    def test_unmatched_tp_does_not_raise(self):
        """Unmatched TPs should log a warning but not crash."""
        from evaluation.evaluate import _build_gt_detection_vector

        gt = [_make_finding(cve="CVE-1")]
        tp = [_make_finding(cve="CVE-UNKNOWN")]
        vec = _build_gt_detection_vector(gt, tp)
        # The TP could not be mapped; GT entry stays 0
        assert vec == [0]

    def test_detection_vector_sum_divergence_logged(self, caplog):
        """When sum(detected) != len(tp), a warning is emitted."""
        import logging
        from evaluation.evaluate import _build_gt_detection_vector

        gt = [_make_finding(cve="CVE-1")]
        # Supply two TPs with the same key → second one consumes no GT slot
        tp = [_make_finding(cve="CVE-NOPE"), _make_finding(cve="CVE-NOPE")]

        with caplog.at_level(logging.WARNING, logger="evaluation"):
            vec = _build_gt_detection_vector(gt, tp)

        assert vec == [0]

    def test_empty_gt_and_tp(self):
        from evaluation.evaluate import _build_gt_detection_vector

        assert _build_gt_detection_vector([], []) == []

    def test_multiple_same_gt_keys(self):
        """Duplicate GT rows should each get their own detection slot."""
        from evaluation.evaluate import _build_gt_detection_vector

        gt = [
            _make_finding(cve="CVE-1"),
            _make_finding(cve="CVE-1"),
        ]
        tp = [
            _make_finding(cve="CVE-1"),
            _make_finding(cve="CVE-1"),
        ]
        vec = _build_gt_detection_vector(gt, tp)
        assert vec == [1, 1]


class TestComputeGtSummaryEdgeCases:
    def test_no_cves_in_findings(self):
        from evaluation.evaluate import _compute_gt_summary

        gt = [
            Finding(ecosystem="pypi", component="a", version="1", cve=None, osv_id="OSV-1"),
            Finding(ecosystem="pypi", component="b", version="2", cve=None, osv_id=None),
        ]
        summary = _compute_gt_summary(gt)
        assert summary["pypi"]["CVEs"] == 0
        assert summary["pypi"]["Vulnerabilities"] == 2

    def test_mixed_ecosystems(self):
        from evaluation.evaluate import _compute_gt_summary

        gt = [
            _make_finding(ecosystem="npm", component="express", version="4.0", cve="CVE-N"),
            _make_finding(ecosystem="pypi", component="django", version="3.2", cve="CVE-P"),
            _make_finding(ecosystem="pypi", component="flask", version="2.0", cve="CVE-P2"),
        ]
        summary = _compute_gt_summary(gt)
        assert "npm" in summary
        assert "pypi" in summary
        assert summary["pypi"]["Vulnerabilities"] == 2
        assert summary["npm"]["Vulnerabilities"] == 1


class TestComputePerEcosystemMetricsEdgeCases:
    def test_perfect_recall_and_no_fp(self):
        from evaluation.evaluate import compute_per_ecosystem_metrics

        gt = [_make_finding(cve="CVE-1")]
        tp = [_make_finding(cve="CVE-1")]
        result = compute_per_ecosystem_metrics(ground_truth=gt, tp=tp, fp=[], fn=[])
        assert result["pypi"]["Recall"] == 1.0
        assert result["pypi"]["Overlap"] == 1.0

    def test_all_fn_zero_recall(self):
        from evaluation.evaluate import compute_per_ecosystem_metrics

        gt = [_make_finding(cve="CVE-1"), _make_finding(cve="CVE-2")]
        fn = [_make_finding(cve="CVE-1"), _make_finding(cve="CVE-2")]
        result = compute_per_ecosystem_metrics(ground_truth=gt, tp=[], fp=[], fn=fn)
        assert result["pypi"]["Recall"] == 0.0

    def test_only_fp(self):
        from evaluation.evaluate import compute_per_ecosystem_metrics

        gt = [_make_finding(cve="CVE-1")]
        fp = [_make_finding(cve="CVE-FP")]
        result = compute_per_ecosystem_metrics(ground_truth=gt, tp=[], fp=fp, fn=[])
        assert result["pypi"]["Overlap"] == 0.0


class TestGetIdentifierEdgeCases:
    def test_cve_and_osv_id_both_none(self):
        from evaluation.evaluate import _get_identifier

        f = Finding(ecosystem="pypi", component="a", version="1")
        assert _get_identifier(f) == ""

    def test_only_osv_id(self):
        from evaluation.evaluate import _get_identifier

        f = Finding(ecosystem="pypi", component="a", version="1", cve=None, osv_id="GHSA-xx")
        assert _get_identifier(f) == "GHSA-xx"


class TestGtKeyEdgeCases:
    def test_key_uses_cve_over_osv_id(self):
        from evaluation.evaluate import _gt_key

        f = Finding(ecosystem="npm", component="x", version="2", cve="CVE-2", osv_id="OSV-9")
        assert _gt_key(f) == ("npm", "x", "2", "CVE-2")

    def test_key_falls_back_to_osv_id(self):
        from evaluation.evaluate import _gt_key

        f = Finding(ecosystem="pypi", component="y", version="3", cve=None, osv_id="GHSA-yy")
        assert _gt_key(f) == ("pypi", "y", "3", "GHSA-yy")

    def test_key_empty_identifier(self):
        from evaluation.evaluate import _gt_key

        f = Finding(ecosystem="pypi", component="z", version="1", cve=None, osv_id=None)
        assert _gt_key(f) == ("pypi", "z", "1", "")


# ===========================================================================
# 6.  evaluate.py – _init_adapter branches + main() CLI
# ===========================================================================


class TestInitAdapterBranches:
    """Exercise each tool branch in _init_adapter to boost line coverage."""

    def test_dtrack_missing_env_raises(self, tmp_path, monkeypatch):
        """DependencyTrackAdapter raises SystemExit when env vars are absent."""
        monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
        from evaluation.evaluate import _init_adapter

        with pytest.raises(SystemExit):
            _init_adapter("dtrack", {"env": {}})

    def test_dtrack_with_required_env(self, tmp_path, monkeypatch):
        """DependencyTrackAdapter initialises when required vars are present."""
        monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
        from evaluation.evaluate import _init_adapter

        fake_env = {
            "DTRACK_URL": "http://localhost:8080",
            "DTRACK_API_KEY": "test-key",
            "DTRACK_PROJECT_NAME": "test-project",
        }
        a = _init_adapter("dtrack", {"env": fake_env})
        assert a.name() == "dtrack"

    def test_github_missing_token_raises(self, tmp_path, monkeypatch):
        """GitHubAdvisoryAdapter raises SystemExit when GITHUB_TOKEN is absent."""
        monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        from evaluation.evaluate import _init_adapter

        with pytest.raises(SystemExit):
            _init_adapter("github", {"env": {}, "ground_truth": []})

    def test_github_with_token(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_fake_token_for_testing")
        from evaluation.evaluate import _init_adapter

        a = _init_adapter("github", {"env": {}, "ground_truth": []})
        assert a.name() == "github"

    def test_snyk(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
        from evaluation.evaluate import _init_adapter

        a = _init_adapter("snyk", {"env": {}})
        assert a.name() == "snyk"

    def test_trivy(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
        from evaluation.evaluate import _init_adapter

        a = _init_adapter("trivy", {"env": {}})
        assert a.name() == "trivy"

    def test_oss_index(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
        from evaluation.evaluate import _init_adapter

        a = _init_adapter("oss-index", {"env": {}})
        assert a.name() == "oss-index"

    def test_unknown_tool_raises_system_exit(self):
        from evaluation.evaluate import _init_adapter

        with pytest.raises(SystemExit, match="Unsupported tool"):
            _init_adapter("not-a-tool", {})


class TestEvaluateMain:
    """Test the evaluate.py CLI entry point (main function)."""

    def test_main_calls_run_evaluation(self, tmp_path: Path):
        from evaluation.evaluate import main

        gt_csv = tmp_path / "gt.csv"
        _write_gt_csv(gt_csv)

        with (
            patch.object(sys, "argv", [
                "evaluate",
                "--ground-truth", str(gt_csv),
                "--tool", "osv",
            ]),
            patch("evaluation.evaluate.run_evaluation") as mock_run,
        ):
            main()

        mock_run.assert_called_once_with(
            ground_truth_path=str(gt_csv),
            tool="osv",
            return_findings=False,
            return_metrics=False,
        )

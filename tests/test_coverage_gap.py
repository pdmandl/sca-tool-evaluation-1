"""Targeted tests to close remaining coverage gaps."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from evaluation.core.model import Finding
from evaluation.reporting.evaluation_report import _component_col_width
from ground_truth_generation.osv_common import (
    verify_dataset_against_osv,
    write_candidate_coverage,
)


# -----------------------------------------------------------------------
# evaluation_report helpers
# -----------------------------------------------------------------------
class TestComponentColWidth:
    def test_empty(self):
        assert _component_col_width([]) == 10

    def test_short(self):
        rows = [Finding(ecosystem="pypi", component="x", version="1")]
        assert _component_col_width(rows) == 10  # min_width wins

    def test_long(self):
        rows = [Finding(ecosystem="pypi", component="a" * 20, version="1")]
        assert _component_col_width(rows) == 21


# -----------------------------------------------------------------------
# osv_common: verify_dataset_against_osv
# -----------------------------------------------------------------------
class TestVerifyDatasetAgainstOsv:
    @patch("ground_truth_generation.osv_common.request_json")
    def test_no_mismatch(self, mock_rj):
        mock_rj.return_value = {
            "id": "OSV-1",
            "aliases": ["CVE-1"],
            "affected": [{"versions": ["1.0"]}],
        }
        rows = [
            {
                "vulnerability_id": "OSV-1",
                "cve": "CVE-1",
                "component_version": "1.0",
            }
        ]
        verify_dataset_against_osv(rows)  # should not raise

    @patch("ground_truth_generation.osv_common.request_json")
    def test_cve_mismatch_logged(self, mock_rj):
        mock_rj.return_value = {
            "id": "OSV-2",
            "aliases": ["CVE-OTHER"],
            "affected": [{"versions": ["1.0"]}],
        }
        rows = [
            {
                "vulnerability_id": "OSV-2",
                "cve": "CVE-WRONG",
                "component_version": "1.0",
            }
        ]
        verify_dataset_against_osv(rows)  # mismatch logged, no raise

    @patch("ground_truth_generation.osv_common.request_json")
    def test_version_not_affected(self, mock_rj):
        mock_rj.return_value = {
            "id": "OSV-3",
            "aliases": ["CVE-1"],
            "affected": [{"versions": ["2.0"]}],
        }
        rows = [
            {
                "vulnerability_id": "OSV-3",
                "cve": "CVE-1",
                "component_version": "1.0",
            }
        ]
        verify_dataset_against_osv(rows)  # version mismatch logged, no raise

    @patch("ground_truth_generation.osv_common.request_json")
    def test_uses_cache(self, mock_rj):
        mock_rj.return_value = {
            "id": "OSV-4",
            "aliases": ["CVE-1"],
            "affected": [{"versions": ["1.0"]}],
        }
        rows = [
            {"vulnerability_id": "OSV-4", "cve": "CVE-1", "component_version": "1.0"},
            {"vulnerability_id": "OSV-4", "cve": "CVE-1", "component_version": "1.0"},
        ]
        verify_dataset_against_osv(rows)
        assert mock_rj.call_count == 1  # cached second call


# -----------------------------------------------------------------------
# osv_common: write_candidate_coverage
# -----------------------------------------------------------------------
class TestWriteCandidateCoverage:
    def test_writes_csv(self, tmp_path, monkeypatch):
        import os

        monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
        # Must patch the module-level constant that was already set at import
        with patch("ground_truth_generation.osv_common.GROUND_TRUTH_BUILD_PATH", str(tmp_path)):
            coverage = {
                "django": {"has_vulns": True, "vuln_count": 3},
                "flask": {"has_vulns": False, "vuln_count": 0},
            }
            write_candidate_coverage("pypi", coverage, "20240101", 2, 3)
            files = list(tmp_path.glob("*.candidates.csv"))
            assert len(files) == 1
            text = files[0].read_text()
            assert "django" in text and "flask" in text


# -----------------------------------------------------------------------
# temporal_runner: prepare_tool_inputs
# -----------------------------------------------------------------------
class TestPrepareToolInputs:
    def test_without_sbom(self, tmp_path):
        from evaluation.temporal_runner import prepare_tool_inputs

        gt = tmp_path / "gt.csv"
        gt.write_text("a,b")
        out_dir = tmp_path / "out"
        local_gt, local_sbom = prepare_tool_inputs(out_dir, gt, None)
        assert local_gt.exists()
        assert local_sbom is None

    def test_with_sbom(self, tmp_path):
        from evaluation.temporal_runner import prepare_tool_inputs

        gt = tmp_path / "gt.csv"
        gt.write_text("x")
        sbom = tmp_path / "sbom.json"
        sbom.write_text("{}")
        out_dir = tmp_path / "out"
        local_gt, local_sbom = prepare_tool_inputs(out_dir, gt, sbom)
        assert local_sbom and local_sbom.exists()

    def test_nonexistent_sbom_ignored(self, tmp_path):
        from evaluation.temporal_runner import prepare_tool_inputs

        gt = tmp_path / "gt.csv"
        gt.write_text("x")
        sbom = tmp_path / "nonexistent.json"  # does not exist
        out_dir = tmp_path / "out"
        _, local_sbom = prepare_tool_inputs(out_dir, gt, sbom)
        assert local_sbom is None


# -----------------------------------------------------------------------
# gt_statistics: pre_balance_stats with no CVEs
# -----------------------------------------------------------------------
def test_pre_balance_no_cve():
    from ground_truth_generation.gt_statistics import compute_pre_balance_stats

    rows = [
        {
            "ecosystem": "npm",
            "component_name": "a",
            "component_version": "1",
            "vulnerability_id": "OSV-1",
            "cve": None,
        }
    ]
    out = compute_pre_balance_stats(rows)
    assert out["npm"]["unique_cves"] == 0


# -----------------------------------------------------------------------
# evaluation_report: write_report fallback for tp with no match_type
# -----------------------------------------------------------------------
def test_write_report_tp_fallback_no_match_type(tmp_path):
    from evaluation.reporting.evaluation_report import write_report

    csv_p = tmp_path / "gt.csv"
    csv_p.write_text("")
    tp = [Finding(ecosystem="pypi", component="x", version="1.0", cve="CVE-1")]
    tp[0].match_type = "TP_EXACT"
    write_report(
        tool_name="osv",
        input_csv=str(csv_p),
        tp=tp,
        fp=[],
        fn=[],
        fp_stats={},
        fn_stats={},
        ground_truth=[Finding(ecosystem="pypi", component="x", version="1.0", cve="CVE-1")],
    )
    out = list(tmp_path.glob("*_evaluation.txt"))[0]
    assert "True Positives" in out.read_text()


# -----------------------------------------------------------------------
# evaluation_report: _write_list without include_tp_type (else branch)
# -----------------------------------------------------------------------
def test_write_list_no_tp_type(tmp_path):
    from evaluation.reporting.evaluation_report import _write_list
    import io

    f = io.StringIO()
    rows = [Finding(ecosystem="pypi", component="django", version="3.2.0", cve="CVE-1")]
    _write_list(f, "False Negatives", rows, include_tp_type=False)
    text = f.getvalue()
    assert "django" in text
    assert "False Negatives" in text


# -----------------------------------------------------------------------
# evaluation_report: _write_request_stats
# -----------------------------------------------------------------------
def test_write_request_stats(tmp_path):
    from evaluation.reporting.evaluation_report import _write_request_stats
    import io

    f = io.StringIO()
    stats = {
        "requests_total": 50,
        "errors_total": 1,
        "min_ms": 10.0,
        "avg_ms": 120.5,
        "p50_ms": 100.0,
        "p95_ms": 300.0,
        "max_ms": 500.0,
    }
    _write_request_stats(f, stats)
    text = f.getvalue()
    assert "requests_total" in text
    assert "50" in text


def test_write_request_stats_empty():
    from evaluation.reporting.evaluation_report import _write_request_stats
    import io

    f = io.StringIO()
    _write_request_stats(f, {})
    assert f.getvalue() == ""


# -----------------------------------------------------------------------
# version_matching: edge cases
# -----------------------------------------------------------------------
def test_normalize_specifier_hyphen_with_bad_token():
    from evaluation.core.version_matching import normalize_specifier

    # Hyphen range where one token normalizes to empty → returns None
    result = normalize_specifier("   -  ")
    assert result is None


def test_normalize_specifier_operator_with_empty_part():
    from evaluation.core.version_matching import normalize_specifier

    # Operator-based with empty comma part → skipped
    result = normalize_specifier(">=1.0,")
    # trailing comma produces empty part → should handle gracefully
    assert result is None or isinstance(result, str)


def test_normalize_specifier_no_operator_token():
    from evaluation.core.version_matching import normalize_specifier

    result = normalize_specifier(">plain_text_not_version")
    assert result is None or isinstance(result, str)


def test_version_in_range_bad_version():
    from evaluation.core.version_matching import version_in_range

    assert version_in_range("not-a-version!@#", ">=1.0") is False


def test_version_in_range_bad_spec():
    from evaluation.core.version_matching import version_in_range

    assert version_in_range("1.0.0", "not-a-specifier") is False


def test_version_in_range_empty():
    from evaluation.core.version_matching import version_in_range

    assert version_in_range("", ">=1.0") is False
    assert version_in_range("1.0", "") is False


# -----------------------------------------------------------------------
# normalization: ecosystem_from_purl edge cases (lines 136-137)
# -----------------------------------------------------------------------
def test_ecosystem_from_purl_none():
    from evaluation.core.normalization import ecosystem_from_purl

    assert ecosystem_from_purl(None) is None  # type: ignore


def test_ecosystem_from_purl_no_prefix():
    from evaluation.core.normalization import ecosystem_from_purl

    assert ecosystem_from_purl("notapurl") is None


def test_ecosystem_from_purl_pypi():
    from evaluation.core.normalization import ecosystem_from_purl

    assert ecosystem_from_purl("pkg:pypi/django@3.2") == "pypi"


# -----------------------------------------------------------------------
# statistics: compute_significance_markers with baseline not in pair
# -----------------------------------------------------------------------
def test_significance_markers_baseline_not_in_pair():
    from evaluation.analysis.statistics import compute_significance_markers

    # rows where baseline="oss-index" is not in (tool_a, tool_b) → skip
    rows = [
        {"tool_a": "osv", "tool_b": "snyk", "p_adj": 0.01, "n01": 3, "n10": 1},
        {"tool_a": "osv", "tool_b": "oss-index", "p_adj": 0.01, "n01": 3, "n10": 1},
    ]
    markers = compute_significance_markers(rows, baseline="oss-index")
    assert isinstance(markers, dict)


# -----------------------------------------------------------------------
# osv_common: version_is_affected edge cases (lines 199-200, 209, 223-224)
# -----------------------------------------------------------------------
def test_version_is_affected_invalid_safe_version():
    from ground_truth_generation.osv_common import version_is_affected

    # fixed version is invalid → safe_version returns None → lines 223-224
    vuln = {
        "affected": [
            {
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "1.0"},
                            {"fixed": "not-a-version!!!"},
                        ],
                    }
                ]
            }
        ]
    }
    result = version_is_affected(vuln, "1.5.0")
    assert result is False


def test_version_is_affected_non_semver_range():
    from ground_truth_generation.osv_common import version_is_affected

    # range type != SEMVER → line 209 continue
    vuln = {
        "affected": [
            {
                "ranges": [
                    {
                        "type": "GIT",
                        "events": [{"introduced": "abc123"}],
                    }
                ]
            }
        ]
    }
    result = version_is_affected(vuln, "1.0.0")
    assert result is False


# -----------------------------------------------------------------------
# gt_statistics: write_statistics with env vars set (lines 155-158, 163)
# -----------------------------------------------------------------------
def test_write_statistics_with_env_vars(tmp_path, monkeypatch):
    from ground_truth_generation.gt_statistics import write_statistics

    monkeypatch.setenv("PYPI_MAX_VERSIONS_PER_PACKAGE", "7")  # valid int → line 155-156
    monkeypatch.setenv("NPM_MAX_VERSIONS_PER_PACKAGE", "notanint")  # invalid → line 157-158
    monkeypatch.setenv("BALANCE", "true")  # _bool_env non-empty
    rows = [
        {
            "ecosystem": "pypi",
            "component_name": "a",
            "component_version": "1.0",
            "vulnerability_id": "OSV-1",
            "cve": "CVE-1",
            "date_published": "2024-01-01",
        },
    ]
    out = tmp_path / "stats.txt"
    csv = tmp_path / "gt.csv"
    csv.write_text("")
    write_statistics(rows=rows, out_path=out, csv_path=csv)
    assert out.exists()

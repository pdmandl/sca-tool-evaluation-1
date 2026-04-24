from evaluation.core.evaluation import (
    evaluate_finding,
    evaluate_project_centric,
    version_in_range,
)
from evaluation.core.model import Finding


def _f(**kwargs):
    defaults = dict(ecosystem="pypi", component="django", version="3.2.0")
    defaults.update(kwargs)
    return Finding(**defaults)


# ------------------------------------------------------------
# version_in_range
# ------------------------------------------------------------


class TestVersionInRange:
    def test_gte_lt_match(self):
        assert version_in_range("1.5.0", ">=1.0.0,<2.0.0") is True

    def test_gte_lt_below_low(self):
        assert version_in_range("0.9.0", ">=1.0.0,<2.0.0") is False

    def test_gte_lt_at_upper_excluded(self):
        assert version_in_range("2.0.0", ">=1.0.0,<2.0.0") is False

    def test_lte_inclusive_upper(self):
        assert version_in_range("2.0.0", ">=1.0.0,<=2.0.0") is True

    def test_gt_exclusive_lower(self):
        assert version_in_range("1.0.0", ">1.0.0") is False
        assert version_in_range("1.0.1", ">1.0.0") is True

    def test_eq(self):
        assert version_in_range("1.2.3", "==1.2.3") is True
        assert version_in_range("1.2.4", "==1.2.3") is False

    def test_unparseable_version_returns_false(self):
        assert version_in_range("not-a-version", ">=1.0.0") is False

    def test_unparseable_boundary_returns_false(self):
        assert version_in_range("1.0.0", ">=not-a-version") is False


# ------------------------------------------------------------
# evaluate_finding
# ------------------------------------------------------------


class TestEvaluateFinding:
    def test_tp_exact_version_and_cve(self):
        gt = _f(cve="CVE-2021-1", version="1.0.0")
        tf = _f(cve="CVE-2021-1", version="1.0.0")
        assert evaluate_finding(ground_truth=gt, tool_finding=tf) == "TP"

    def test_tp_range(self):
        gt = _f(cve="CVE-2021-1", version="1.5.0")
        tf = _f(cve="CVE-2021-1", version="0.0.0", affected_version_range=">=1.0.0,<2.0.0")
        assert evaluate_finding(ground_truth=gt, tool_finding=tf) == "TP_RANGE"

    def test_fn_same_id_but_version_out_of_range(self):
        gt = _f(cve="CVE-2021-1", version="3.0.0")
        tf = _f(cve="CVE-2021-1", version="1.0.0", affected_version_range=">=1.0.0,<2.0.0")
        assert evaluate_finding(ground_truth=gt, tool_finding=tf) == "FN"

    def test_fp_when_ids_mismatch(self):
        gt = _f(cve="CVE-2021-1", version="1.0.0")
        tf = _f(cve="CVE-2099-9", version="1.0.0")
        assert evaluate_finding(ground_truth=gt, tool_finding=tf) == "FP"

    def test_fp_when_gt_has_no_ids(self):
        gt = _f(version="1.0.0")
        tf = _f(cve="CVE-2021-1", version="1.0.0")
        assert evaluate_finding(ground_truth=gt, tool_finding=tf) == "FP"


# ------------------------------------------------------------
# evaluate_project_centric
# ------------------------------------------------------------


class TestEvaluateProjectCentric:
    def test_tp_exact(self):
        gt = [_f(cve="CVE-1", version="1.0.0")]
        tools = [_f(cve="CVE-1", version="1.0.0")]
        tp_exact, tp_range, fp, fn = evaluate_project_centric(ground_truth=gt, tool_findings=tools)
        assert len(tp_exact) == 1
        assert tp_range == [] and fp == [] and fn == []
        assert gt[0].match_type == "TP_EXACT"

    def test_tp_range(self):
        gt = [_f(cve="CVE-1", version="1.5.0")]
        tools = [_f(cve="CVE-1", version="0.0.0", affected_version_range=">=1.0.0,<2.0.0")]
        tp_exact, tp_range, fp, fn = evaluate_project_centric(ground_truth=gt, tool_findings=tools)
        assert tp_exact == [] and len(tp_range) == 1 and fn == []
        # The tool finding is used and should not count as FP.
        assert fp == []
        assert gt[0].match_type == "TP_RANGE"

    def test_fn_when_no_tool_finding(self):
        gt = [_f(cve="CVE-1", version="1.0.0")]
        tp_exact, tp_range, fp, fn = evaluate_project_centric(ground_truth=gt, tool_findings=[])
        assert fn == gt
        assert tp_exact == [] and tp_range == [] and fp == []

    def test_fp_when_tool_finding_has_no_matching_gt(self):
        gt = [_f(cve="CVE-1", version="1.0.0")]
        extra = _f(component="numpy", cve="CVE-9", version="1.0.0")
        tools = [_f(cve="CVE-1", version="1.0.0"), extra]
        tp_exact, tp_range, fp, fn = evaluate_project_centric(ground_truth=gt, tool_findings=tools)
        assert len(tp_exact) == 1
        assert fp == [extra]

    def test_exact_preferred_over_range(self):
        gt = [_f(cve="CVE-1", version="1.0.0")]
        tools = [
            _f(cve="CVE-1", version="0.0.0", affected_version_range=">=1.0.0,<2.0.0"),
            _f(cve="CVE-1", version="1.0.0"),
        ]
        tp_exact, tp_range, fp, fn = evaluate_project_centric(ground_truth=gt, tool_findings=tools)
        assert len(tp_exact) == 1 and tp_range == []

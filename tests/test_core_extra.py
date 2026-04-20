import csv
from pathlib import Path
from unittest.mock import patch, MagicMock

from evaluation.core.evaluation import classify_false_negatives
from evaluation.core.fp_classification import (
    FP_KEYWORDS,
    classify_fp_candidate,
    description_indicates_product,
    osv_has_cve_for_package,
)
from evaluation.core.ground_truth import load_ground_truth
from evaluation.core.model import Finding


# --------------------------------------------------------------
# fp_classification
# --------------------------------------------------------------
class TestFPClassification:
    def test_description_product_keywords(self):
        assert description_indicates_product("some ENTERPRISE appliance")
        assert description_indicates_product("An RSA Archer tool")
        assert not description_indicates_product("a small library")
        assert not description_indicates_product("")
        assert not description_indicates_product(None)

    def test_keywords_list_nonempty(self):
        assert len(FP_KEYWORDS) > 0

    def test_classify_no_cve(self):
        out = classify_fp_candidate({"cve": None, "ecosystem": "pypi", "component": "x"})
        assert out[0] == "FP-UNCLEAR"

    @patch("evaluation.core.fp_classification.requests.post")
    def test_classify_fp_certain(self, mock_post):
        mock_post.return_value = MagicMock(
            json=lambda: {"vulns": [{"aliases": ["CVE-OTHER"]}]},
            raise_for_status=lambda: None,
        )
        out = classify_fp_candidate(
            {"cve": "CVE-2024-9999", "ecosystem": "pypi", "component": "django",
             "description": "hi"}
        )
        assert out[0] == "FP-CERTAIN"

    @patch("evaluation.core.fp_classification.requests.post")
    def test_classify_fp_likely_product(self, mock_post):
        mock_post.return_value = MagicMock(
            json=lambda: {"vulns": [{"aliases": ["CVE-1"]}]},
            raise_for_status=lambda: None,
        )
        out = classify_fp_candidate(
            {"cve": "CVE-1", "ecosystem": "pypi", "component": "x",
             "description": "enterprise console"}
        )
        assert out[0] == "FP-LIKELY"

    @patch("evaluation.core.fp_classification.requests.post")
    def test_classify_default_unclear(self, mock_post):
        mock_post.return_value = MagicMock(
            json=lambda: {"vulns": [{"aliases": ["CVE-1"]}]},
            raise_for_status=lambda: None,
        )
        out = classify_fp_candidate(
            {"cve": "CVE-1", "ecosystem": "pypi", "component": "x",
             "description": "a library"}
        )
        assert out[0] == "FP-UNCLEAR"

    @patch("evaluation.core.fp_classification.requests.post")
    def test_osv_has_cve_handles_exception(self, mock_post):
        mock_post.side_effect = RuntimeError("boom")
        assert osv_has_cve_for_package("pypi", "x", "CVE-1") is False

    def test_osv_has_cve_empty_args(self):
        assert osv_has_cve_for_package("", "x", "CVE-1") is False
        assert osv_has_cve_for_package("pypi", "", "CVE-1") is False
        assert osv_has_cve_for_package("pypi", "x", "") is False


# --------------------------------------------------------------
# ground_truth loader
# --------------------------------------------------------------
class TestGroundTruthLoad:
    def test_load(self, tmp_path: Path):
        p = tmp_path / "gt.csv"
        with p.open("w", newline="") as f:
            w = csv.DictWriter(
                f,
                fieldnames=[
                    "ecosystem", "component_name", "component_version",
                    "purl", "cve", "vulnerability_id",
                    "vulnerability_description",
                ],
            )
            w.writeheader()
            w.writerow({
                "ecosystem": "PyPI", "component_name": "Django",
                "component_version": "3.2.0",
                "purl": "pkg:pypi/django@3.2.0",
                "cve": "CVE-2024-1",
                "vulnerability_id": "GHSA-aaaa",
                "vulnerability_description": "some desc",
            })
            w.writerow({
                "ecosystem": "Maven", "component_name": "com.foo:bar",
                "component_version": "1.0",
                "purl": "",
                "cve": "", "vulnerability_id": "OSV-1",
                "vulnerability_description": "",
            })

        rows = load_ground_truth(p)
        assert len(rows) == 2
        assert rows[0].ecosystem == "pypi"
        assert rows[0].cve == "CVE-2024-1"
        assert rows[1].ecosystem == "maven"
        assert rows[1].component == "com.foo:bar"


# --------------------------------------------------------------
# classify_false_negatives
# --------------------------------------------------------------
def _f(**kw):
    base = dict(ecosystem="pypi", component="x", version="1.0")
    base.update(kw)
    return Finding(**base)


class TestClassifyFN:
    def test_fn_exact_same_version(self):
        fn = [_f(cve="CVE-1")]
        tools = [_f(cve="CVE-OTHER")]
        out = classify_false_negatives(false_negatives=fn, tool_findings=tools)
        assert out["FN_exact"] and not out["FN_true"]

    def test_fn_range_uncertain(self):
        fn = [_f(version="1.5", cve="CVE-1")]
        tools = [_f(version="9.0", cve="CVE-1", affected_version_range=">=1.0,<2.0")]
        out = classify_false_negatives(false_negatives=fn, tool_findings=tools)
        assert out["FN_range"]

    def test_fn_true_when_no_tool_entries(self):
        fn = [_f()]
        out = classify_false_negatives(false_negatives=fn, tool_findings=[])
        assert out["FN_true"] and not out["FN_exact"] and not out["FN_range"]

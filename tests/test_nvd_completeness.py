"""
Tests for the NVD completeness classifier seam, product matcher, record parser,
and report aggregation. No network — everything is driven from small recorded
NVD fixtures, mirroring tests/test_oss_index.py and tests/test_adapters.py.
"""

import logging

from evaluation.core.model import Finding
from evaluation.nvd_completeness.coverage import (
    CVE_ABSENT,
    MATCH_EXACT,
    MATCH_SUBSTRING,
    NO_CPE_CONFIG,
    NO_CVE,
    PRODUCT_MATCHED,
    PRODUCT_MISMATCH,
    classify_nvd_coverage,
    component_tokens,
    format_coverage_log_line,
    log_coverage_observation,
    node_product_match,
)
from evaluation.nvd_completeness.record import (
    NvdCpeNode,
    ParsedNvdRecord,
    parse_nvd_record,
)
from evaluation.nvd_completeness.report import (
    aggregate_buckets,
    render_report,
)

# ------------------------------------------------------------
# Fixtures / helpers
# ------------------------------------------------------------


def _obs(ecosystem, component, version="1.0.0", cve="CVE-2024-0001"):
    return Finding(ecosystem=ecosystem, component=component, version=version, cve=cve)


def _node(vendor, product, **kw):
    return NvdCpeNode(vendor=vendor, product=product, **kw)


def _record(cve_id, nodes):
    return ParsedNvdRecord(cve_id=cve_id, cpe_nodes=list(nodes))


def _nvd_body(cve_id, cpe_matches):
    """A minimal NVD 2.0 response body around one CVE with one config node."""
    return {
        "version": "2.0",
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "configurations": [
                        {"nodes": [{"operator": "OR", "cpeMatch": cpe_matches}]}
                    ],
                }
            }
        ],
    }


def _match(vendor, product, version="*", **kw):
    criteria = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    d = {"vulnerable": True, "criteria": criteria}
    d.update(kw)
    return d


# ------------------------------------------------------------
# classify_nvd_coverage — bucket precedence
# ------------------------------------------------------------


class TestClassifyBuckets:
    def test_no_cve_takes_precedence_even_with_record(self):
        obs = _obs("pypi", "django", cve=None)
        rec = _record("CVE-2024-0001", [_node("djangoproject", "django")])
        assert classify_nvd_coverage(obs, rec) == NO_CVE

    def test_no_cve_empty_string(self):
        assert classify_nvd_coverage(_obs("pypi", "django", cve="  "), None) == NO_CVE

    def test_cve_absent_when_record_none(self):
        assert classify_nvd_coverage(_obs("pypi", "django"), None) == CVE_ABSENT

    def test_no_cpe_config_when_record_has_no_nodes(self):
        rec = _record("CVE-2024-0001", [])
        assert classify_nvd_coverage(_obs("pypi", "django"), rec) == NO_CPE_CONFIG

    def test_product_mismatch(self):
        rec = _record("CVE-2024-0001", [_node("apache", "tomcat")])
        assert classify_nvd_coverage(_obs("pypi", "django"), rec) == PRODUCT_MISMATCH

    def test_product_matched_exact(self):
        rec = _record("CVE-2024-0001", [_node("djangoproject", "django")])
        assert classify_nvd_coverage(_obs("pypi", "django"), rec) == PRODUCT_MATCHED

    def test_product_matched_via_vendor(self):
        rec = _record("CVE-2024-0001", [_node("lodash", "irrelevant")])
        assert classify_nvd_coverage(_obs("npm", "lodash"), rec) == PRODUCT_MATCHED


class TestMismatchDistinctFromVersion:
    """PRODUCT_MISMATCH must never be conflated with a version gap: a matched
    product with an out-of-range version still classifies as PRODUCT_MATCHED
    (the version split is a later slice), and a wrong product with a perfectly
    in-range version still classifies as PRODUCT_MISMATCH."""

    def test_matched_product_out_of_range_version_still_matched(self):
        obs = _obs("pypi", "django", version="99.0")
        rec = _record(
            "CVE-2024-0001",
            [_node("djangoproject", "django", version_end_excluding="3.0")],
        )
        assert classify_nvd_coverage(obs, rec) == PRODUCT_MATCHED

    def test_wrong_product_in_range_version_still_mismatch(self):
        obs = _obs("pypi", "django", version="1.0")
        rec = _record(
            "CVE-2024-0001",
            [_node("apache", "tomcat", version_end_excluding="99.0")],
        )
        assert classify_nvd_coverage(obs, rec) == PRODUCT_MISMATCH


# ------------------------------------------------------------
# Generous product matching
# ------------------------------------------------------------


class TestNodeProductMatch:
    def test_exact_on_product(self):
        assert node_product_match(_node("v", "requests"), ["requests"]) == MATCH_EXACT

    def test_exact_on_vendor(self):
        assert node_product_match(_node("requests", "p"), ["requests"]) == MATCH_EXACT

    def test_substring_on_product(self):
        # product "requests_oauthlib" contains token "requests"
        assert (
            node_product_match(_node("v", "requests_oauthlib"), ["requests"])
            == MATCH_SUBSTRING
        )

    def test_exact_preferred_over_substring(self):
        # one node candidate is an exact match, another only substring -> exact wins
        assert (
            node_product_match(_node("requests_x", "requests"), ["requests"])
            == MATCH_EXACT
        )

    def test_no_match(self):
        assert node_product_match(_node("apache", "tomcat"), ["django"]) is None

    def test_separator_insensitive(self):
        # pypi canonical form uses '-', CPE product uses '_'
        assert (
            node_product_match(_node("v", "python_jose"), ["python-jose"])
            == MATCH_EXACT
        )


class TestComponentTokens:
    def test_maven_splits_group_and_artifact(self):
        toks = component_tokens("maven", "org.apache.struts:struts2-core")
        assert toks == ["org.apache.struts", "struts2-core"]

    def test_maven_artifact_matches_product(self):
        obs = _obs("maven", "org.apache.struts:struts2-core")
        rec = _record("CVE-2024-0001", [_node("apache", "struts2-core")])
        assert classify_nvd_coverage(obs, rec) == PRODUCT_MATCHED

    def test_maven_artifact_matches_vendor_field(self):
        # both segments are candidate tokens against CPE vendor:product, so an
        # artifact token matching the vendor field (cross-field) still counts.
        obs = _obs("maven", "com.fasterxml.jackson.core:jackson-databind")
        rec = _record("CVE-2024-0001", [_node("jackson-databind", "unrelated")])
        assert classify_nvd_coverage(obs, rec) == PRODUCT_MATCHED

    def test_pypi_single_token(self):
        assert component_tokens("pypi", "Django") == ["django"]

    def test_npm_lowercased(self):
        assert component_tokens("npm", "Lodash") == ["lodash"]


# ------------------------------------------------------------
# parse_nvd_record
# ------------------------------------------------------------


class TestParseNvdRecord:
    def test_full_response_shape(self):
        body = _nvd_body(
            "CVE-2021-0001",
            [
                _match(
                    "djangoproject",
                    "django",
                    versionStartIncluding="3.0",
                    versionEndExcluding="3.2.5",
                )
            ],
        )
        rec = parse_nvd_record(body)
        assert rec is not None
        assert rec.cve_id == "CVE-2021-0001"
        assert len(rec.cpe_nodes) == 1
        node = rec.cpe_nodes[0]
        assert node.vendor == "djangoproject"
        assert node.product == "django"
        assert node.version is None  # '*' -> None
        assert node.version_start_including == "3.0"
        assert node.version_end_excluding == "3.2.5"

    def test_exact_cpe_version_kept(self):
        body = _nvd_body("CVE-2021-0002", [_match("v", "p", version="2.9.0")])
        rec = parse_nvd_record(body)
        assert rec.cpe_nodes[0].version == "2.9.0"

    def test_absent_cve_returns_none(self):
        assert parse_nvd_record({"totalResults": 0, "vulnerabilities": []}) is None

    def test_non_dict_returns_none(self):
        assert parse_nvd_record(None) is None
        assert parse_nvd_record("nope") is None

    def test_present_cve_no_config_yields_empty_nodes(self):
        body = {"vulnerabilities": [{"cve": {"id": "CVE-2021-0003"}}]}
        rec = parse_nvd_record(body)
        assert rec is not None and rec.cpe_nodes == []

    def test_unwrapped_cve_object(self):
        cve_obj = {
            "id": "CVE-2021-0004",
            "configurations": [{"nodes": [{"cpeMatch": [_match("v", "p")]}]}],
        }
        rec = parse_nvd_record(cve_obj)
        assert rec is not None and len(rec.cpe_nodes) == 1

    def test_non_vulnerable_match_skipped(self):
        m = _match("v", "p")
        m["vulnerable"] = False
        body = _nvd_body("CVE-2021-0005", [m])
        rec = parse_nvd_record(body)
        assert rec.cpe_nodes == []

    def test_end_to_end_no_cpe_config_maps_to_bucket(self):
        body = {"vulnerabilities": [{"cve": {"id": "CVE-2021-0006"}}]}
        rec = parse_nvd_record(body)
        assert classify_nvd_coverage(_obs("pypi", "x"), rec) == NO_CPE_CONFIG


# ------------------------------------------------------------
# Report aggregation
# ------------------------------------------------------------


class TestReport:
    def test_counts_per_ecosystem_and_denominator(self):
        classified = [
            (_obs("pypi", "django"), PRODUCT_MATCHED),
            (_obs("pypi", "flask"), PRODUCT_MISMATCH),
            (_obs("pypi", "x", cve=None), NO_CVE),
            (_obs("npm", "lodash"), PRODUCT_MATCHED),
        ]
        report = aggregate_buckets(classified, meta={"ground_truth": "gt-demo"})
        assert report.count("pypi", PRODUCT_MATCHED) == 1
        assert report.count("pypi", PRODUCT_MISMATCH) == 1
        assert report.count("pypi", NO_CVE) == 1
        assert report.denominator("pypi") == 3
        assert report.count("npm", PRODUCT_MATCHED) == 1
        assert report.denominator("npm") == 1

    def test_no_cve_stays_in_denominator(self):
        classified = [(_obs("pypi", "x", cve=None), NO_CVE)]
        report = aggregate_buckets(classified)
        assert report.denominator("pypi") == 1

    def test_default_ecosystems_always_present(self):
        report = aggregate_buckets([])
        for eco in ("pypi", "npm", "maven"):
            assert eco in report.per_ecosystem
            assert report.denominator(eco) == 0

    def test_mismatch_and_matched_stay_distinct_in_counts(self):
        classified = [
            (_obs("pypi", "a"), PRODUCT_MISMATCH),
            (_obs("pypi", "b"), PRODUCT_MATCHED),
        ]
        report = aggregate_buckets(classified)
        assert report.count("pypi", PRODUCT_MISMATCH) == 1
        assert report.count("pypi", PRODUCT_MATCHED) == 1

    def test_render_contains_metadata_and_buckets(self):
        report = aggregate_buckets(
            [(_obs("pypi", "django"), PRODUCT_MATCHED)],
            meta={
                "ground_truth": "gt-demo",
                "fetch_date_utc": "2026-07-02",
                "nvd_api_version": "2.0",
            },
        )
        text = render_report(report)
        assert "gt-demo" in text
        assert "2026-07-02" in text
        assert "PRODUCT_MATCHED" in text
        assert "not reproducible" in text


# ------------------------------------------------------------
# Greppable per-observation log line
# ------------------------------------------------------------


class TestCoverageLogLine:
    def test_format_is_greppable(self):
        obs = _obs("pypi", "django", version="3.2.0", cve="CVE-2024-1234")
        rec = _record("CVE-2024-1234", [_node("djangoproject", "django")])
        line = format_coverage_log_line(obs, PRODUCT_MATCHED, rec)
        assert line.startswith("NVD_COVERAGE")
        assert "bucket=PRODUCT_MATCHED" in line
        assert "ecosystem=pypi" in line
        assert "component=django" in line
        assert "version=3.2.0" in line
        assert "cve=CVE-2024-1234" in line
        assert "matched_nodes=1" in line

    def test_matched_nodes_zero_for_non_matched_bucket(self):
        obs = _obs("pypi", "x", cve=None)
        line = format_coverage_log_line(obs, NO_CVE)
        assert "matched_nodes=0" in line
        assert "cve=-" in line

    def test_log_coverage_observation_emits_line(self, caplog):
        obs = _obs("pypi", "django", cve="CVE-2024-1")
        rec = _record("CVE-2024-1", [_node("djangoproject", "django")])
        logger = logging.getLogger("nvd.coverage.test")
        with caplog.at_level(logging.INFO, logger="nvd.coverage.test"):
            log_coverage_observation(logger, obs, PRODUCT_MATCHED, rec)
        assert any("NVD_COVERAGE" in r.message for r in caplog.records)

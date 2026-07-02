"""
Tests for the NVD CPE-data completeness diagnostic.

Covers the classifier seam (five buckets: NO_CVE / CVE_ABSENT / NO_CPE_CONFIG /
PRODUCT_MISMATCH / PRODUCT_MATCHED), the record parser, the report aggregation,
the NVD adapter's transport (rate limit / retry / tracing, all network-mocked),
and the runner (CVE de-duplication, denominator policy, report artifact, no
Overlap). The suite never hits the network.
"""

import csv
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from evaluation.adapters.nvd import NvdAdapter
from evaluation.core.model import Finding
from evaluation.nvd_completeness.coverage import (
    CVE_ABSENT,
    NO_CPE_CONFIG,
    NO_CVE,
    PRODUCT_MATCHED,
    PRODUCT_MISMATCH,
    classify_nvd_coverage,
    format_coverage_log_line,
)
from evaluation.nvd_completeness.record import ParsedNvdRecord, parse_nvd_record
from evaluation.nvd_completeness.report import (
    DEFAULT_ECOSYSTEMS,
    aggregate_buckets,
    render_report,
)
from evaluation.nvd_completeness.runner import _unique_cves, run_nvd_completeness


# ------------------------------------------------------------
# Fixtures / helpers
# ------------------------------------------------------------


def _obs(ecosystem, component, version, cve):
    return Finding(ecosystem=ecosystem, component=component, version=version, cve=cve)


def _cpe(vendor, product, version="*"):
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def _body(cve_id="CVE-2021-1234", vendor="acme", product="widget", version="*", **bounds):
    """
    A full NVD 2.0 envelope with a single vulnerable cpeMatch.

    ``bounds`` accepts the NVD range keys verbatim, e.g.
    ``versionEndExcluding="2.0"`` or ``versionStartIncluding="1.0"``.
    """
    match = {"vulnerable": True, "criteria": _cpe(vendor, product, version)}
    match.update(bounds)
    return {
        "version": "2.0",
        "totalResults": 1,
        "vulnerabilities": [
            {"cve": {"id": cve_id, "configurations": [{"nodes": [{"cpeMatch": [match]}]}]}}
        ],
    }


def _nvd_body_present_with_config(cve_id="CVE-2021-1234"):
    return _body(cve_id, vendor="acme", product="widget", versionEndExcluding="2.0")


def _nvd_body_present_no_config(cve_id="CVE-2021-9999"):
    return {
        "version": "2.0",
        "totalResults": 1,
        "vulnerabilities": [{"cve": {"id": cve_id, "configurations": []}}],
    }


def _nvd_body_absent():
    return {"version": "2.0", "totalResults": 0, "vulnerabilities": []}


class _FakeResp:
    def __init__(self, status_code, body=None, headers=None, text=""):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}
        self.text = text

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


def _make_adapter(tmp_path, monkeypatch, env=None):
    monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
    # Skip real pacing sleeps and make backoff instantaneous.
    monkeypatch.setattr("evaluation.adapters.nvd.time.sleep", lambda *_a, **_k: None)
    base_env = {"NVD_MIN_REQUEST_INTERVAL_S": "0"}
    base_env.update(env or {})
    return NvdAdapter(config={"env": base_env, "ground_truth": []})


# ------------------------------------------------------------
# record.parse_nvd_record
# ------------------------------------------------------------


class TestParseRecord:
    def test_present_with_config_yields_nodes(self):
        rec = parse_nvd_record(_nvd_body_present_with_config())
        assert isinstance(rec, ParsedNvdRecord)
        assert rec.cve_id == "CVE-2021-1234"
        assert rec.has_cpe_config
        assert len(rec.cpe_nodes) == 1
        node = rec.cpe_nodes[0]
        assert node.vendor == "acme"
        assert node.product == "widget"
        assert node.version is None  # '*' wildcard -> None
        assert node.version_end_excluding == "2.0"

    def test_unwrapped_cve_object_yields_nodes(self):
        # Already-unwrapped CVE object (no {"vulnerabilities": [...]} envelope).
        cve_obj = _body(product="widget")["vulnerabilities"][0]["cve"]
        rec = parse_nvd_record(cve_obj)
        assert rec is not None
        assert rec.cve_id == "CVE-2021-1234"
        assert rec.cpe_nodes and rec.cpe_nodes[0].product == "widget"

    def test_present_no_config_yields_empty_nodes(self):
        rec = parse_nvd_record(_nvd_body_present_no_config())
        assert rec is not None
        assert rec.cve_id == "CVE-2021-9999"
        assert rec.cpe_nodes == []
        assert not rec.has_cpe_config

    def test_absent_returns_none(self):
        assert parse_nvd_record(_nvd_body_absent()) is None

    def test_malformed_never_raises(self):
        assert parse_nvd_record(None) is None
        assert parse_nvd_record("garbage") is None
        assert parse_nvd_record({"unexpected": True}) is None

    def test_nested_children_flattened(self):
        body = {
            "version": "2.0",
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-7777",
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "operator": "AND",
                                        "children": [
                                            {
                                                "cpeMatch": [
                                                    {
                                                        "vulnerable": True,
                                                        "criteria": _cpe("acme", "widget"),
                                                    }
                                                ]
                                            }
                                        ],
                                    }
                                ]
                            }
                        ],
                    }
                }
            ],
        }
        rec = parse_nvd_record(body)
        assert rec is not None
        assert [n.product for n in rec.cpe_nodes] == ["widget"]

    def test_non_vulnerable_nodes_dropped(self):
        body = _nvd_body_present_with_config()
        body["vulnerabilities"][0]["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0][
            "vulnerable"
        ] = False
        rec = parse_nvd_record(body)
        assert rec is not None
        assert rec.cpe_nodes == []


# ------------------------------------------------------------
# coverage.classify_nvd_coverage (the single seam)
# ------------------------------------------------------------


class TestClassifier:
    def test_no_cve(self):
        assert classify_nvd_coverage(_obs("pypi", "flask", "1.0", None), None) == NO_CVE
        assert classify_nvd_coverage(_obs("pypi", "flask", "1.0", "  "), None) == NO_CVE

    def test_cve_absent(self):
        obs = _obs("pypi", "flask", "1.0", "CVE-2021-1234")
        assert classify_nvd_coverage(obs, None) == CVE_ABSENT

    def test_no_cpe_config(self):
        obs = _obs("npm", "left-pad", "1.0.0", "CVE-2021-9999")
        rec = parse_nvd_record(_nvd_body_present_no_config())
        assert classify_nvd_coverage(obs, rec) == NO_CPE_CONFIG

    def test_product_mismatch(self):
        # CPE names acme/widget but the component is flask -> wrong product.
        obs = _obs("pypi", "flask", "1.0", "CVE-2021-1234")
        rec = parse_nvd_record(_nvd_body_present_with_config())
        assert classify_nvd_coverage(obs, rec) == PRODUCT_MISMATCH

    def test_product_matched(self):
        obs = _obs("pypi", "flask", "1.0", "CVE-2021-1234")
        rec = parse_nvd_record(_body(product="flask"))
        assert classify_nvd_coverage(obs, rec) == PRODUCT_MATCHED

    def test_product_matched_on_vendor(self):
        # Component matches the CPE *vendor* even though the product differs.
        obs = _obs("pypi", "acme", "1.0", "CVE-2021-1234")
        rec = parse_nvd_record(_body(vendor="acme", product="somethingelse"))
        assert classify_nvd_coverage(obs, rec) == PRODUCT_MATCHED

    def test_maven_group_artifact_dual_tokens(self):
        # Maven identity is group:artifact; the artifact segment matches the CPE.
        obs = _obs("maven", "com.foo:bar", "2.0", "CVE-2021-1234")
        rec = parse_nvd_record(_body(vendor="foo", product="bar"))
        assert classify_nvd_coverage(obs, rec) == PRODUCT_MATCHED

    def test_token_canonicalization(self):
        # CPE product uses '_' where the component uses '-' -> canonical match.
        obs = _obs("pypi", "spring-framework", "5.0", "CVE-2021-1234")
        rec = parse_nvd_record(_body(vendor="pivotal", product="spring_framework"))
        assert classify_nvd_coverage(obs, rec) == PRODUCT_MATCHED

    def test_no_cve_takes_precedence_over_record(self):
        # A record present but no CVE on the observation -> NO_CVE wins.
        rec = parse_nvd_record(_nvd_body_present_with_config())
        assert classify_nvd_coverage(_obs("pypi", "x", "1", None), rec) == NO_CVE

    def test_log_line_is_greppable(self):
        obs = _obs("pypi", "flask", "1.0", "CVE-2021-1234")
        rec = parse_nvd_record(_body(product="flask"))
        line = format_coverage_log_line(obs, PRODUCT_MATCHED, rec)
        assert line.startswith("NVD_COVERAGE | bucket=PRODUCT_MATCHED")
        assert "cve=CVE-2021-1234" in line
        assert "matched_nodes=1" in line


# ------------------------------------------------------------
# report aggregation / rendering
# ------------------------------------------------------------


class TestReport:
    def test_default_ecosystems_always_present(self):
        report = aggregate_buckets([])
        for eco in DEFAULT_ECOSYSTEMS:
            assert eco in report.per_ecosystem

    def test_extra_ecosystem_appears_alongside_defaults(self):
        report = aggregate_buckets([(_obs("nuget", "n", "1", "CVE-1"), PRODUCT_MATCHED)])
        for eco in DEFAULT_ECOSYSTEMS:
            assert eco in report.per_ecosystem
        assert "nuget" in report.per_ecosystem

    def test_zero_denominator_ratio_is_zero(self):
        report = aggregate_buckets([])
        assert report.product_matched_ratio("pypi") == 0.0

    def test_no_cve_stays_in_denominator(self):
        classified = [
            (_obs("pypi", "a", "1", "CVE-1"), PRODUCT_MATCHED),
            (_obs("pypi", "b", "1", None), NO_CVE),
            (_obs("pypi", "c", "1", "CVE-2"), CVE_ABSENT),
        ]
        report = aggregate_buckets(classified)
        assert report.denominator("pypi") == 3
        assert report.count("pypi", PRODUCT_MATCHED) == 1
        assert report.count("pypi", NO_CVE) == 1
        # interim ratio = PRODUCT_MATCHED / denominator (NO_CVE counted in denom)
        assert report.product_matched_ratio("pypi") == pytest.approx(1 / 3)

    def test_render_has_metadata_header_and_no_overlap(self):
        classified = [(_obs("npm", "x", "1", "CVE-1"), PRODUCT_MATCHED)]
        report = aggregate_buckets(
            classified,
            meta={
                "ground_truth": "gt_demo",
                "fetch_date_utc": "2026-07-02T00:00:00Z",
                "nvd_api_version": "2.0",
            },
        )
        text = render_report(report)
        assert "gt_demo" in text
        assert "2026-07-02T00:00:00Z" in text
        assert "nvd_api_version: 2.0" in text
        assert "not reproducible" in text.lower()
        assert "product_matched_ratio=" in text
        # Interim report must not publish a "completeness" figure yet.
        assert "completeness=" not in text
        # The diagnostic never prints Overlap / detection metrics.
        assert "overlap" not in text.lower()
        assert "recall" not in text.lower()


# ------------------------------------------------------------
# NvdAdapter transport (network mocked)
# ------------------------------------------------------------


class TestAdapter:
    def test_rate_limit_interval_depends_on_key(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
        a_key = NvdAdapter(config={"env": {"NVD_API_KEY": "k"}})
        a_anon = NvdAdapter(config={"env": {}})
        assert a_key.min_interval_s == pytest.approx(30.0 / 50)
        assert a_anon.min_interval_s == pytest.approx(30.0 / 5)
        assert a_key.session.headers.get("apiKey") == "k"
        assert "apiKey" not in a_anon.session.headers

    def test_fetch_present(self, tmp_path, monkeypatch):
        a = _make_adapter(tmp_path, monkeypatch)
        a.session.request = MagicMock(
            return_value=_FakeResp(200, _nvd_body_present_with_config())
        )
        rec = a.fetch_record("CVE-2021-1234")
        assert rec is not None
        assert rec.cve_id == "CVE-2021-1234"
        assert a.api_version == "2.0"

    def test_fetch_absent_returns_none(self, tmp_path, monkeypatch):
        a = _make_adapter(tmp_path, monkeypatch)
        a.session.request = MagicMock(return_value=_FakeResp(200, _nvd_body_absent()))
        assert a.fetch_record("CVE-0000-0000") is None

    def test_404_treated_as_absent(self, tmp_path, monkeypatch):
        a = _make_adapter(tmp_path, monkeypatch)
        a.session.request = MagicMock(return_value=_FakeResp(404, text="not found"))
        assert a.fetch_record("CVE-0000-0000") is None

    def test_empty_cve_short_circuits(self, tmp_path, monkeypatch):
        a = _make_adapter(tmp_path, monkeypatch)
        a.session.request = MagicMock()
        assert a.fetch_record("   ") is None
        a.session.request.assert_not_called()

    def test_429_then_success_retries(self, tmp_path, monkeypatch):
        a = _make_adapter(tmp_path, monkeypatch)
        a.session.request = MagicMock(
            side_effect=[
                _FakeResp(429, headers={"Retry-After": "0"}),
                _FakeResp(200, _nvd_body_present_with_config()),
            ]
        )
        rec = a.fetch_record("CVE-2021-1234")
        assert rec is not None
        assert a.session.request.call_count == 2

    def test_transport_error_then_success(self, tmp_path, monkeypatch):
        import requests

        a = _make_adapter(tmp_path, monkeypatch)
        a.session.request = MagicMock(
            side_effect=[
                requests.RequestException("boom"),
                _FakeResp(200, _nvd_body_present_with_config()),
            ]
        )
        assert a.fetch_record("CVE-2021-1234") is not None
        assert a.session.request.call_count == 2

    def test_exhausted_retries_raise_not_silently_absent(self, tmp_path, monkeypatch):
        a = _make_adapter(tmp_path, monkeypatch, env={"NVD_MAX_RETRIES": "2"})
        a.session.request = MagicMock(return_value=_FakeResp(500))
        with pytest.raises(RuntimeError):
            a.fetch_record("CVE-2021-1234")
        assert a.session.request.call_count == 2

    def test_calls_are_traced_to_api_log(self, tmp_path, monkeypatch):
        # The base class caches the api logger by name; reset it so the trace
        # file lands in this test's tmp dir rather than an earlier test's.
        import logging

        api_logger = logging.getLogger("evaluation.api.nvd")
        for h in list(api_logger.handlers):
            api_logger.removeHandler(h)

        a = _make_adapter(tmp_path, monkeypatch)
        a.session.request = MagicMock(
            return_value=_FakeResp(200, _nvd_body_present_with_config())
        )
        a.fetch_record("CVE-2021-1234")
        logs = list(Path(tmp_path).glob("*_nvd_api.log"))
        assert logs, "expected a *_nvd_api.log trace file"
        assert "CVE-2021-1234" in logs[0].read_text()

    def test_no_detection_semantics(self, tmp_path, monkeypatch):
        a = _make_adapter(tmp_path, monkeypatch)
        with pytest.raises(NotImplementedError):
            a.load_findings_for_component(ecosystem="pypi", component="x", version="1")


# ------------------------------------------------------------
# Runner
# ------------------------------------------------------------


def _write_gt_csv(path: Path, rows):
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "ecosystem",
                "component_name",
                "component_version",
                "purl",
                "vulnerability_id",
                "cve",
                "vulnerability_description",
                "is_vulnerable",
            ],
        )
        w.writeheader()
        for r in rows:
            base = {k: "" for k in w.fieldnames}
            base.update(r)
            w.writerow(base)


class _FakeAdapter:
    """Records fetch calls; returns a canned record per CVE."""

    def __init__(self, records):
        self._records = records
        self.calls = []
        self.api_version = "2.0"

    def name(self):
        return "nvd"

    def iter_with_progress(self, items, **_kw):
        for x in items:
            yield x

    def fetch_record(self, cve_id):
        self.calls.append(cve_id)
        return self._records.get(cve_id)


class TestRunner:
    def test_unique_cves_dedupes_and_orders(self):
        gt = [
            _obs("pypi", "a", "1", "CVE-1"),
            _obs("npm", "b", "1", "CVE-2"),
            _obs("pypi", "c", "1", "CVE-1"),
            _obs("maven", "g:h", "1", None),
        ]
        assert _unique_cves(gt) == ["CVE-1", "CVE-2"]

    def test_end_to_end_one_request_per_unique_cve(self, tmp_path):
        gt_path = tmp_path / "gt_demo.csv"
        _write_gt_csv(
            gt_path,
            [
                {"ecosystem": "pypi", "component_name": "flask", "component_version": "1.0",
                 "cve": "CVE-2021-1234"},
                # duplicate CVE on a second observation -> still one request
                {"ecosystem": "pypi", "component_name": "flask", "component_version": "1.1",
                 "cve": "CVE-2021-1234"},
                {"ecosystem": "npm", "component_name": "left-pad", "component_version": "1.0.0",
                 "cve": "CVE-2021-5678"},
                # GHSA-only (no CVE) -> NO_CVE, stays in denominator, not queried
                {"ecosystem": "maven", "component_name": "com.foo:bar", "component_version": "2.0",
                 "vulnerability_id": "GHSA-xxxx", "cve": ""},
            ],
        )

        fake = _FakeAdapter(
            {
                # CPE product 'flask' matches the component -> PRODUCT_MATCHED
                "CVE-2021-1234": parse_nvd_record(_body("CVE-2021-1234", product="flask")),
                "CVE-2021-5678": None,  # absent in NVD
            }
        )

        report = run_nvd_completeness(ground_truth_path=str(gt_path), adapter=fake)

        # Exactly one request per unique CVE (2 unique, despite 3 CVE rows).
        assert sorted(fake.calls) == ["CVE-2021-1234", "CVE-2021-5678"]

        # pypi: two product-matched observations
        assert report.count("pypi", PRODUCT_MATCHED) == 2
        assert report.denominator("pypi") == 2
        # npm: one CVE absent
        assert report.count("npm", CVE_ABSENT) == 1
        # maven: GHSA-only stays counted as NO_CVE
        assert report.count("maven", NO_CVE) == 1
        assert report.denominator("maven") == 1

        # Report artifact written next to the ground truth.
        out = tmp_path / "gt_demo_nvd_completeness.txt"
        assert out.exists()
        text = out.read_text()
        assert "gt_demo" in text
        assert "overlap" not in text.lower()

    def test_empty_ground_truth_fails_loudly(self, tmp_path):
        gt_path = tmp_path / "empty.csv"
        _write_gt_csv(gt_path, [])
        with pytest.raises(SystemExit):
            run_nvd_completeness(ground_truth_path=str(gt_path), adapter=_FakeAdapter({}))

    def test_missing_ground_truth_fails_loudly(self, tmp_path):
        with pytest.raises(SystemExit):
            run_nvd_completeness(
                ground_truth_path=str(tmp_path / "nope.csv"), adapter=_FakeAdapter({})
            )

    def test_malformed_ground_truth_fails_loudly(self, tmp_path):
        gt_path = tmp_path / "bad.csv"
        # Wrong header -> load yields rows with empty ecosystem values.
        gt_path.write_text("foo,bar\n1,2\n3,4\n", encoding="utf-8")
        with pytest.raises(SystemExit):
            run_nvd_completeness(ground_truth_path=str(gt_path), adapter=_FakeAdapter({}))

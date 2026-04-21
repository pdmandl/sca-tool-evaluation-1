from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from ground_truth_generation.api_call_tracker import ApiCallTracker
from ground_truth_generation.balancing import (
    balance_rows_by_vulnerability_deterministic,
    cap_per_component,
)
from ground_truth_generation.osv_common import (
    env_int,
    expand_advisories,
    is_stable,
    normalize_pypi_name,
    parse_iso_date,
    purl,
    request_json,
    request_json_with_retry,
    version_is_affected,
    within_date_window,
)
from ground_truth_generation.validation import compute_balance_validation


# --------------------------------------------------------------
# api_call_tracker
# --------------------------------------------------------------
class TestApiCallTracker:
    def test_start_end_records(self):
        t = ApiCallTracker()
        token = t.start("OSV")
        t.end("OSV", token)
        stats = t.get_stats()
        assert stats["OSV"]["calls"] == 1
        assert stats["OSV"]["total_time_sec"] >= 0
        assert stats["OSV"]["avg_time_sec"] >= 0

    def test_reset(self):
        t = ApiCallTracker()
        t.end("X", t.start("X"))
        t.reset()
        assert t.get_stats() == {}


# --------------------------------------------------------------
# validation
# --------------------------------------------------------------
class TestValidation:
    def test_compute(self):
        rows = [
            {"ecosystem": "PyPI", "component_name": "a", "component_version": "1"},
            {"ecosystem": "pypi", "component_name": "a", "component_version": "2"},
            {"ecosystem": "pypi", "component_name": "b", "component_version": "1"},
        ]
        out = compute_balance_validation(rows)
        assert out["pypi"]["rows"] == 3
        assert out["pypi"]["unique_components"] == 2
        assert out["pypi"]["top1_share"] > 0


# --------------------------------------------------------------
# balancing
# --------------------------------------------------------------
class TestBalancing:
    def test_min_strategy(self):
        rows = [
            {
                "ecosystem": "pypi",
                "component_name": "a",
                "component_version": "1",
                "cve": "c1",
                "vulnerability_id": "v1",
            },
            {
                "ecosystem": "pypi",
                "component_name": "a",
                "component_version": "2",
                "cve": "c2",
                "vulnerability_id": "v2",
            },
            {
                "ecosystem": "npm",
                "component_name": "b",
                "component_version": "1",
                "cve": "c3",
                "vulnerability_id": "v3",
            },
        ]
        balanced, stats = balance_rows_by_vulnerability_deterministic(
            rows,
            ["pypi", "npm"],
            strategy="min",
        )
        assert stats["pypi"]["kept_rows"] == 1
        assert stats["npm"]["kept_rows"] == 1

    def test_median_strategy(self):
        rows = [
            {
                "ecosystem": "pypi",
                "component_name": "a",
                "component_version": "1",
                "cve": "c1",
                "vulnerability_id": "v1",
            },
            {
                "ecosystem": "pypi",
                "component_name": "a",
                "component_version": "2",
                "cve": "c2",
                "vulnerability_id": "v2",
            },
            {
                "ecosystem": "npm",
                "component_name": "b",
                "component_version": "1",
                "cve": "c3",
                "vulnerability_id": "v3",
            },
        ]
        balanced, stats = balance_rows_by_vulnerability_deterministic(
            rows,
            ["pypi", "npm"],
            strategy="median",
        )
        assert stats["pypi"]["target"] == stats["npm"]["target"]

    def test_invalid_strategy_raises(self):
        rows = [{"ecosystem": "pypi", "component_name": "a", "component_version": "1"}]
        try:
            balance_rows_by_vulnerability_deterministic(rows, ["pypi"], "invalid")
        except ValueError:
            return
        raise AssertionError("expected ValueError")

    def test_no_data_raises(self):
        try:
            balance_rows_by_vulnerability_deterministic([], ["pypi"], "min")
        except RuntimeError:
            return
        raise AssertionError("expected RuntimeError")

    def test_cap_per_component(self):
        rows = [{"ecosystem": "pypi", "component_name": "a"} for _ in range(15)]
        out = cap_per_component(rows, max_per_component=10)
        assert len(out) == 10


# --------------------------------------------------------------
# osv_common
# --------------------------------------------------------------
class TestOSVCommon:
    def test_is_stable(self):
        assert is_stable("1.0.0") is True
        assert is_stable("1.0.0a1") is False
        assert is_stable("not-a-version") is False

    def test_normalize_pypi_name(self):
        assert normalize_pypi_name("Foo_Bar") == "foo-bar"

    def test_purl(self):
        assert purl("PyPI", "Foo_Bar", "1.0") == "pkg:pypi/foo-bar@1.0"
        assert purl("npm", "lodash", "1.0") == "pkg:npm/lodash@1.0"

    def test_expand_advisories_with_cves(self):
        v = {"id": "GHSA-x", "aliases": ["CVE-1", "CVE-2", "GHSA-y"]}
        out = expand_advisories(v)
        assert len(out) == 2
        assert all(pair[0] == "GHSA-x" for pair in out)

    def test_expand_advisories_no_cves(self):
        v = {"id": "GHSA-x", "aliases": []}
        out = expand_advisories(v)
        assert out == [("GHSA-x", None)]

    def test_version_is_affected_versions(self):
        v = {"affected": [{"versions": ["1.0.0"]}]}
        assert version_is_affected(v, "1.0.0") is True
        assert version_is_affected(v, "1.0.1") is False

    def test_version_is_affected_range(self):
        v = {
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "1.0.0"},
                                {"fixed": "2.0.0"},
                            ],
                        }
                    ]
                }
            ]
        }
        assert version_is_affected(v, "1.5.0") is True
        assert version_is_affected(v, "2.0.0") is False

    def test_version_is_affected_introduced_zero(self):
        v = {
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "1.0.0"},
                            ],
                        }
                    ]
                }
            ]
        }
        assert version_is_affected(v, "0.5.0") is True

    def test_version_is_affected_open_ended(self):
        v = {
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "1.0.0"},
                            ],
                        }
                    ]
                }
            ]
        }
        assert version_is_affected(v, "2.0.0") is True

    def test_version_is_affected_invalid(self):
        assert version_is_affected({"affected": []}, "not-a-version") is False

    def test_within_date_window(self):
        s = datetime(2024, 1, 1, tzinfo=timezone.utc)
        e = datetime(2024, 12, 31, tzinfo=timezone.utc)
        p = datetime(2024, 6, 1, tzinfo=timezone.utc)
        assert within_date_window(p, s, e) is True
        assert within_date_window(None, s, e) is False
        assert within_date_window(datetime(2023, 1, 1, tzinfo=timezone.utc), s, e) is False
        assert within_date_window(datetime(2025, 1, 1, tzinfo=timezone.utc), s, e) is False
        assert within_date_window(p, None, None) is True

    def test_parse_iso_date(self):
        assert parse_iso_date(None) is None
        d = parse_iso_date("2024-03-15")
        assert d.year == 2024 and d.tzinfo is not None

    def test_env_int(self, monkeypatch):
        monkeypatch.delenv("FOO_TEST", raising=False)
        assert env_int("FOO_TEST", 5) == 5
        monkeypatch.setenv("FOO_TEST", "")
        assert env_int("FOO_TEST", 7) == 7
        monkeypatch.setenv("FOO_TEST", "abc")
        assert env_int("FOO_TEST", 9) == 9
        monkeypatch.setenv("FOO_TEST", "42")
        assert env_int("FOO_TEST", 0) == 42

    @patch("ground_truth_generation.osv_common.requests.post")
    def test_request_json_post(self, mock_post):
        mock_post.return_value = MagicMock(
            json=lambda: {"ok": 1},
            raise_for_status=lambda: None,
        )
        out = request_json("http://example.com", payload={"a": 1})
        assert out == {"ok": 1}

    @patch("ground_truth_generation.osv_common.requests.get")
    def test_request_json_get(self, mock_get):
        mock_get.return_value = MagicMock(
            json=lambda: {"ok": 2},
            raise_for_status=lambda: None,
        )
        out = request_json("http://example.com")
        assert out == {"ok": 2}

    @patch("ground_truth_generation.osv_common.requests.get")
    def test_request_json_retries_then_raises(self, mock_get):
        mock_get.side_effect = RuntimeError("boom")
        try:
            request_json("http://x", retries=2)
        except RuntimeError:
            return
        raise AssertionError("expected RuntimeError")

    @patch("requests.get")
    def test_request_json_with_retry_200(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"k": "v"},
        )
        assert request_json_with_retry("http://x") == {"k": "v"}

    @patch("requests.get")
    def test_request_json_with_retry_client_error(self, mock_get):
        mock_get.return_value = MagicMock(status_code=404)
        assert request_json_with_retry("http://x") is None

    @patch("requests.post")
    def test_request_json_with_retry_post(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"ok": True},
        )
        assert request_json_with_retry("http://x", payload={"a": 1}) == {"ok": True}

    @patch("requests.get")
    def test_request_json_with_retry_invalid_json(self, mock_get):
        def _raise():
            raise ValueError("nope")

        mock_get.return_value = MagicMock(
            status_code=200,
            json=_raise,
        )
        assert request_json_with_retry("http://x") is None

    @patch("time.sleep", lambda *_: None)
    @patch("requests.get")
    def test_request_json_with_retry_server_error_retries(self, mock_get):
        mock_get.return_value = MagicMock(status_code=500)
        assert request_json_with_retry("http://x", retries=2) is None

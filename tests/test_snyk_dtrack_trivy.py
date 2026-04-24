"""Tests for Snyk, Dtrack, and Trivy adapter helpers."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from evaluation.core.model import Finding


# -----------------------------------------------------------------------
# Snyk helpers
# -----------------------------------------------------------------------
class TestSnykHelpers:
    def _make(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
        from evaluation.adapters.snyk import SnykAdapter

        return SnykAdapter(config={"env": {}})

    def test_safe_text_none(self, tmp_path, monkeypatch):
        from evaluation.adapters.snyk import SnykAdapter

        assert SnykAdapter._safe_text(None) == ""

    def test_safe_text_bytes(self, tmp_path, monkeypatch):
        from evaluation.adapters.snyk import SnykAdapter

        assert SnykAdapter._safe_text(b"hello") == "hello"

    def test_safe_text_str(self, tmp_path, monkeypatch):
        from evaluation.adapters.snyk import SnykAdapter

        assert SnykAdapter._safe_text("hello") == "hello"

    def test_extract_identifiers_cve(self, tmp_path, monkeypatch):
        a = self._make(tmp_path, monkeypatch)
        ids = a._extract_identifiers({"identifiers": {"CVE": ["CVE-2024-1"], "GHSA": []}})
        assert ids["cve"] == "CVE-2024-1"
        assert ids["ghsa"] is None

    def test_extract_identifiers_ghsa(self, tmp_path, monkeypatch):
        a = self._make(tmp_path, monkeypatch)
        ids = a._extract_identifiers({"identifiers": {"CVE": [], "GHSA": ["GHSA-a-b-c"]}})
        assert ids["ghsa"] == "GHSA-A-B-C"

    def test_extract_identifiers_empty(self, tmp_path, monkeypatch):
        a = self._make(tmp_path, monkeypatch)
        ids = a._extract_identifiers({})
        assert ids["cve"] is None and ids["ghsa"] is None

    def test_extract_affected_version_range(self, tmp_path, monkeypatch):
        a = self._make(tmp_path, monkeypatch)
        v = {"semver": {"vulnerable": [">=1.0,<2.0", ">=3.0"]}}
        r = a._extract_affected_version_range(v)
        assert r == ">=1.0,<2.0,>=3.0"

    def test_extract_affected_version_range_none(self, tmp_path, monkeypatch):
        a = self._make(tmp_path, monkeypatch)
        assert a._extract_affected_version_range({}) is None
        assert a._extract_affected_version_range({"semver": {}}) is None
        assert a._extract_affected_version_range({"semver": {"vulnerable": []}}) is None

    def test_infer_ecosystem_pypi(self, tmp_path, monkeypatch):
        a = self._make(tmp_path, monkeypatch)
        assert a._infer_ecosystem_from_purl("pkg:pypi/django") == "pypi"

    def test_infer_ecosystem_npm(self, tmp_path, monkeypatch):
        a = self._make(tmp_path, monkeypatch)
        assert a._infer_ecosystem_from_purl("pkg:npm/lodash") == "npm"

    def test_infer_ecosystem_unknown(self, tmp_path, monkeypatch):
        a = self._make(tmp_path, monkeypatch)
        assert a._infer_ecosystem_from_purl("pkg:rubygems/sinatra") is None

    def test_extract_findings_basic(self, tmp_path, monkeypatch):
        a = self._make(tmp_path, monkeypatch)
        data = {
            "vulnerabilities": [
                {
                    "packageName": "django",
                    "version": "3.2.0",
                    "packageUrl": "pkg:pypi/django@3.2.0",
                    "identifiers": {"CVE": ["CVE-2024-1"], "GHSA": []},
                    "title": "Django vulnerability",
                }
            ]
        }
        findings = a._extract_findings(data)
        assert len(findings) == 1
        assert findings[0].cve == "CVE-2024-1"
        assert findings[0].ecosystem == "pypi"

    def test_extract_findings_maven_slash_component(self, tmp_path, monkeypatch):
        a = self._make(tmp_path, monkeypatch)
        data = {
            "vulnerabilities": [
                {
                    "packageName": "com.foo/bar",
                    "version": "1.0",
                    "packageUrl": "pkg:maven/com.foo/bar@1.0",
                    "identifiers": {"CVE": ["CVE-2024-2"], "GHSA": []},
                    "title": "Maven vuln",
                }
            ]
        }
        findings = a._extract_findings(data)
        assert len(findings) == 1
        assert ":" in findings[0].component

    def test_extract_findings_no_identifier_skipped(self, tmp_path, monkeypatch):
        a = self._make(tmp_path, monkeypatch)
        data = {
            "vulnerabilities": [
                {
                    "packageName": "x",
                    "version": "1.0",
                    "packageUrl": "pkg:pypi/x@1.0",
                    "identifiers": {},
                }
            ]
        }
        assert a._extract_findings(data) == []

    def test_extract_findings_dedup(self, tmp_path, monkeypatch):
        a = self._make(tmp_path, monkeypatch)
        vuln = {
            "packageName": "django",
            "version": "3.2.0",
            "packageUrl": "pkg:pypi/django@3.2.0",
            "identifiers": {"CVE": ["CVE-2024-1"], "GHSA": []},
        }
        data = {"vulnerabilities": [vuln, vuln]}
        findings = a._extract_findings(data)
        assert len(findings) == 1

    def test_load_findings_disabled(self, tmp_path, monkeypatch):
        a = self._make(tmp_path, monkeypatch)
        assert a.enabled is False
        assert a.load_findings() == []


# -----------------------------------------------------------------------
# DependencyTrack helpers
# -----------------------------------------------------------------------
class TestDTrackHelpers:
    def _make(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
        from evaluation.adapters.dtrack import DependencyTrackAdapter

        return DependencyTrackAdapter(
            config={
                "env": {
                    "DTRACK_URL": "http://localhost",
                    "DTRACK_API_KEY": "key",
                    "DTRACK_PROJECT_NAME": "proj",
                }
            }
        )

    def test_strip_qualifiers(self, tmp_path, monkeypatch):
        from evaluation.adapters.dtrack import DependencyTrackAdapter

        assert DependencyTrackAdapter._strip_qualifiers_and_subpath("1.0?q=a") == "1.0"
        assert DependencyTrackAdapter._strip_qualifiers_and_subpath("1.0#sub") == "1.0"
        assert DependencyTrackAdapter._strip_qualifiers_and_subpath("1.0") == "1.0"

    def test_maven_name_from_purl_name(self, tmp_path, monkeypatch):
        from evaluation.adapters.dtrack import DependencyTrackAdapter

        assert DependencyTrackAdapter._maven_name_from_purl_name("com.foo/bar") == "com.foo:bar"
        assert DependencyTrackAdapter._maven_name_from_purl_name("noslash") == "noslash"

    def test_extract_findings_pypi(self, tmp_path, monkeypatch):
        a = self._make(tmp_path, monkeypatch)
        raw = [
            {
                "component": {"purl": "pkg:pypi/django@3.2.0"},
                "vulnerability": {"vulnId": "CVE-2024-1", "description": "bad"},
            }
        ]
        findings = a._extract_findings(raw)
        assert len(findings) == 1
        assert findings[0].cve == "CVE-2024-1"
        assert findings[0].ecosystem == "pypi"

    def test_extract_findings_ghsa(self, tmp_path, monkeypatch):
        a = self._make(tmp_path, monkeypatch)
        raw = [
            {
                "component": {"purl": "pkg:pypi/flask@2.0"},
                "vulnerability": {"vulnId": "GHSA-xx-yy-zz", "description": ""},
            }
        ]
        findings = a._extract_findings(raw)
        assert len(findings) == 1
        assert findings[0].ghsa == "GHSA-XX-YY-ZZ"

    def test_extract_findings_no_identifier_skipped(self, tmp_path, monkeypatch):
        a = self._make(tmp_path, monkeypatch)
        raw = [{"component": {"purl": "pkg:pypi/x@1.0"}, "vulnerability": {"vulnId": "UNKNOWN-1"}}]
        assert a._extract_findings(raw) == []

    def test_extract_findings_no_purl_skipped(self, tmp_path, monkeypatch):
        a = self._make(tmp_path, monkeypatch)
        raw = [{"component": {}, "vulnerability": {"vulnId": "CVE-1"}}]
        assert a._extract_findings(raw) == []

    def test_extract_findings_maven(self, tmp_path, monkeypatch):
        a = self._make(tmp_path, monkeypatch)
        raw = [
            {
                "component": {"purl": "pkg:maven/com.example/mylib@1.0"},
                "vulnerability": {"vulnId": "CVE-2024-5"},
            }
        ]
        findings = a._extract_findings(raw)
        assert len(findings) == 1
        assert ":" in findings[0].component

    def test_load_findings_for_component_uses_cache(self, tmp_path, monkeypatch):
        a = self._make(tmp_path, monkeypatch)
        a._cache_all_findings = [
            Finding(ecosystem="pypi", component="django", version="3.2", cve="CVE-1"),
        ]
        out = a.load_findings_for_component(ecosystem="pypi", component="django", version="3.2")
        assert len(out) == 1


# -----------------------------------------------------------------------
# Trivy helpers
# -----------------------------------------------------------------------
class TestTrivyHelpers:
    def _make_enabled(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
        sbom = tmp_path / "sbom.json"
        sbom.write_text("{}")
        bash = tmp_path / "trivy"
        bash.write_text("#!/bin/sh\necho OK\n")
        bash.chmod(0o755)
        from evaluation.adapters.trivy import TrivyAdapter

        return TrivyAdapter(
            config={
                "env": {
                    "TRIVY_SBOM_FILE": str(sbom),
                    "TRIVY_BIN": str(bash),
                }
            }
        )

    def test_disabled_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
        from evaluation.adapters.trivy import TrivyAdapter

        a = TrivyAdapter(config={"env": {}})
        assert a.load_findings() == []

    def test_name(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
        from evaluation.adapters.trivy import TrivyAdapter

        a = TrivyAdapter(config={"env": {}})
        assert a.name() == "trivy"

    def test_load_findings_for_component_empty(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
        from evaluation.adapters.trivy import TrivyAdapter

        a = TrivyAdapter(config={"env": {}})
        result = a.load_findings_for_component(ecosystem="pypi", component="x", version="1")
        assert result == []

    def test_enabled_init(self, tmp_path, monkeypatch):
        a = self._make_enabled(tmp_path, monkeypatch)
        assert a.enabled is True
        assert a.name() == "trivy"

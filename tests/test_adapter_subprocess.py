"""
Comprehensive tests targeting subprocess/CLI paths and range-evaluation logic
in trivy.py, snyk.py, and github_advisory.py.

Run with:
    poetry run pytest tests/test_adapter_subprocess.py
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_completed_process(stdout: str = "", stderr: str = "", returncode: int = 0):
    """Return a subprocess.CompletedProcess-like object."""
    p = MagicMock(spec=subprocess.CompletedProcess)
    p.stdout = stdout
    p.stderr = stderr
    p.returncode = returncode
    return p


def _make_trivy_adapter(tmp_path, monkeypatch):
    """Create an enabled TrivyAdapter with real files in tmp_path."""
    monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
    sbom = tmp_path / "sbom.json"
    sbom.write_text("{}")
    trivy_bin = tmp_path / "trivy"
    trivy_bin.write_text("#!/bin/sh\necho OK\n")
    trivy_bin.chmod(0o755)
    from evaluation.adapters.trivy import TrivyAdapter
    return TrivyAdapter(
        config={
            "env": {
                "TRIVY_SBOM_FILE": str(sbom),
                "TRIVY_BIN": str(trivy_bin),
            }
        }
    )


def _make_snyk_adapter(tmp_path, monkeypatch):
    """Create an enabled SnykAdapter with real files in tmp_path."""
    monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
    sbom = tmp_path / "sbom.cdx.json"
    sbom.write_text("{}")
    bash_script = tmp_path / "run_snyk.sh"
    bash_script.write_text("#!/bin/sh\necho '{}'\n")
    bash_script.chmod(0o755)
    bash_path = Path("/bin/bash")
    if not bash_path.exists():
        bash_path = Path("/usr/bin/bash")
    from evaluation.adapters.snyk import SnykAdapter
    return SnykAdapter(
        config={
            "env": {
                "SNYK_SBOM_FILE": str(sbom),
                "SNYK_BASH_SCRIPT": str(bash_script),
                "BASH_PATH": str(bash_path),
                "SNYK_CLI_MAX_ATTEMPTS": "2",
                "SNYK_CLI_RETRY_SLEEP": "0",
                "SNYK_CLI_TIMEOUT": "30",
            }
        }
    )


def _make_github_adapter(tmp_path, monkeypatch):
    """Create a GitHubAdvisoryAdapter with a fake token and minimal GT."""
    monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
    monkeypatch.setenv("GITHUB_TOKEN", "fake-token")
    from evaluation.adapters.github_advisory import GitHubAdvisoryAdapter
    from evaluation.core.model import Finding
    gt = [
        Finding(ecosystem="npm", component="lodash", version="4.17.15", cve="CVE-2021-23337"),
    ]
    return GitHubAdvisoryAdapter(config={"env": {}, "ground_truth": gt})


# ===========================================================================
# TRIVY TESTS
# ===========================================================================

class TestTrivyRunSbom:
    """Tests for TrivyAdapter._run_trivy_sbom."""

    def test_run_trivy_sbom_success(self, tmp_path, monkeypatch):
        """Valid JSON stdout returns parsed dict."""
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        output = {"Results": []}
        with patch("subprocess.run", return_value=_make_completed_process(
            stdout=json.dumps(output), returncode=0
        )):
            result = adapter._run_trivy_sbom()
        assert result == output

    def test_run_trivy_sbom_empty_stdout(self, tmp_path, monkeypatch):
        """Empty stdout returns empty dict."""
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        with patch("subprocess.run", return_value=_make_completed_process(
            stdout="", returncode=0
        )):
            result = adapter._run_trivy_sbom()
        assert result == {}

    def test_run_trivy_sbom_invalid_json(self, tmp_path, monkeypatch):
        """Invalid JSON stdout returns empty dict."""
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        with patch("subprocess.run", return_value=_make_completed_process(
            stdout="not-json", returncode=0
        )):
            result = adapter._run_trivy_sbom()
        assert result == {}

    def test_run_trivy_sbom_subprocess_exception(self, tmp_path, monkeypatch):
        """Exception in subprocess.run returns empty dict."""
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        with patch("subprocess.run", side_effect=OSError("exec failed")):
            result = adapter._run_trivy_sbom()
        assert result == {}

    def test_run_trivy_sbom_nonzero_exit_code(self, tmp_path, monkeypatch):
        """Non-zero exit code but valid JSON still returns parsed data."""
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        output = {"Results": [{"Vulnerabilities": []}]}
        with patch("subprocess.run", return_value=_make_completed_process(
            stdout=json.dumps(output), returncode=1
        )):
            # Trivy does NOT fail on non-zero exit; it just logs and parses
            result = adapter._run_trivy_sbom()
        assert result == output

    def test_run_trivy_sbom_passes_sbom_path(self, tmp_path, monkeypatch):
        """Command includes the SBOM file path."""
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        captured_cmd = []
        def fake_run(cmd, **kwargs):
            captured_cmd.extend(cmd)
            return _make_completed_process(stdout="{}", returncode=0)
        with patch("subprocess.run", side_effect=fake_run):
            adapter._run_trivy_sbom()
        assert "sbom" in captured_cmd
        assert "--format" in captured_cmd
        assert "json" in captured_cmd


class TestTrivyExtractFindings:
    """Tests for TrivyAdapter._extract_findings."""

    def test_extract_findings_empty_results(self, tmp_path, monkeypatch):
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        assert adapter._extract_findings({"Results": []}) == []

    def test_extract_findings_no_results_key(self, tmp_path, monkeypatch):
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        assert adapter._extract_findings({}) == []

    def test_extract_findings_basic_cve(self, tmp_path, monkeypatch):
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        data = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "PkgName": "lodash",
                            "InstalledVersion": "4.17.15",
                            "FixedVersion": "4.17.21",
                            "VulnerabilityID": "CVE-2021-23337",
                            "Title": "Lodash command injection",
                            "PkgIdentifier": {
                                "PURL": "pkg:npm/lodash@4.17.15"
                            },
                        }
                    ]
                }
            ]
        }
        findings = adapter._extract_findings(data)
        assert len(findings) == 1
        f = findings[0]
        assert f.cve == "CVE-2021-23337"
        assert f.ghsa is None
        assert f.ecosystem == "npm"
        assert f.component == "lodash"
        assert f.version == "4.17.15"
        assert f.affected_version_range == "< 4.17.21"
        assert f.source == "trivy"

    def test_extract_findings_ghsa_id(self, tmp_path, monkeypatch):
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        data = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "PkgName": "flask",
                            "InstalledVersion": "2.0.0",
                            "VulnerabilityID": "GHSA-ab12-cd34-ef56",
                            "PkgIdentifier": {
                                "PURL": "pkg:pypi/flask@2.0.0"
                            },
                        }
                    ]
                }
            ]
        }
        findings = adapter._extract_findings(data)
        assert len(findings) == 1
        assert findings[0].ghsa == "GHSA-AB12-CD34-EF56"
        assert findings[0].cve is None

    def test_extract_findings_maven_slash_normalization(self, tmp_path, monkeypatch):
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        data = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "PkgName": "org.apache.logging.log4j/log4j-core",
                            "InstalledVersion": "2.14.0",
                            "VulnerabilityID": "CVE-2021-44228",
                            "PkgIdentifier": {
                                "PURL": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0"
                            },
                        }
                    ]
                }
            ]
        }
        findings = adapter._extract_findings(data)
        assert len(findings) == 1
        assert ":" in findings[0].component
        assert findings[0].component == "org.apache.logging.log4j:log4j-core"

    def test_extract_findings_deduplication(self, tmp_path, monkeypatch):
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        vuln = {
            "PkgName": "django",
            "InstalledVersion": "3.2.0",
            "VulnerabilityID": "CVE-2024-1111",
            "PkgIdentifier": {"PURL": "pkg:pypi/django@3.2.0"},
        }
        data = {"Results": [{"Vulnerabilities": [vuln, vuln]}]}
        findings = adapter._extract_findings(data)
        assert len(findings) == 1

    def test_extract_findings_no_identifier_skipped(self, tmp_path, monkeypatch):
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        data = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "PkgName": "somelib",
                            "InstalledVersion": "1.0",
                            "VulnerabilityID": "UNKNOWN-1",
                            "PkgIdentifier": {"PURL": "pkg:npm/somelib@1.0"},
                        }
                    ]
                }
            ]
        }
        assert adapter._extract_findings(data) == []

    def test_extract_findings_missing_purl_skipped(self, tmp_path, monkeypatch):
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        data = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "PkgName": "somelib",
                            "InstalledVersion": "1.0",
                            "VulnerabilityID": "CVE-2024-0001",
                            "PkgIdentifier": {},
                        }
                    ]
                }
            ]
        }
        assert adapter._extract_findings(data) == []

    def test_extract_findings_unknown_purl_ecosystem_skipped(self, tmp_path, monkeypatch):
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        data = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "PkgName": "sinatra",
                            "InstalledVersion": "1.0",
                            "VulnerabilityID": "CVE-2024-0002",
                            "PkgIdentifier": {"PURL": "pkg:gem/sinatra@1.0"},
                        }
                    ]
                }
            ]
        }
        assert adapter._extract_findings(data) == []

    def test_extract_findings_missing_pkg_name_skipped(self, tmp_path, monkeypatch):
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        data = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "InstalledVersion": "1.0",
                            "VulnerabilityID": "CVE-2024-0003",
                            "PkgIdentifier": {"PURL": "pkg:npm/x@1.0"},
                        }
                    ]
                }
            ]
        }
        assert adapter._extract_findings(data) == []

    def test_extract_findings_multiple_results(self, tmp_path, monkeypatch):
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        data = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "PkgName": "lodash",
                            "InstalledVersion": "4.17.15",
                            "VulnerabilityID": "CVE-2021-23337",
                            "PkgIdentifier": {"PURL": "pkg:npm/lodash@4.17.15"},
                        }
                    ]
                },
                {
                    "Vulnerabilities": [
                        {
                            "PkgName": "django",
                            "InstalledVersion": "3.2.0",
                            "VulnerabilityID": "CVE-2024-1111",
                            "PkgIdentifier": {"PURL": "pkg:pypi/django@3.2.0"},
                        }
                    ]
                },
            ]
        }
        findings = adapter._extract_findings(data)
        assert len(findings) == 2


class TestTrivyExtractIdentifiers:
    """Tests for TrivyAdapter._extract_identifiers."""

    def test_cve_prefix(self, tmp_path, monkeypatch):
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        cve, ghsa = adapter._extract_identifiers({"VulnerabilityID": "CVE-2024-1234"})
        assert cve == "CVE-2024-1234"
        assert ghsa is None

    def test_ghsa_prefix(self, tmp_path, monkeypatch):
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        cve, ghsa = adapter._extract_identifiers({"VulnerabilityID": "GHSA-aa-bb-cccc"})
        assert cve is None
        assert ghsa == "GHSA-AA-BB-CCCC"

    def test_ghsa_in_references_fallback(self, tmp_path, monkeypatch):
        """When VulnerabilityID is a CVE, GHSA is picked from References."""
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        cve, ghsa = adapter._extract_identifiers({
            "VulnerabilityID": "CVE-2024-9999",
            "References": [
                "https://nvd.nist.gov/vuln/detail/CVE-2024-9999",
                "https://github.com/advisories/GHSA-xx-yy-zzz1",
            ],
        })
        assert cve == "CVE-2024-9999"
        assert ghsa == "GHSA-XX-YY-ZZZ1"

    def test_ghsa_in_references_when_no_vuln_id(self, tmp_path, monkeypatch):
        """No VulnerabilityID but GHSA in references."""
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        cve, ghsa = adapter._extract_identifiers({
            "VulnerabilityID": "",
            "References": ["https://github.com/advisories/GHSA-ab12-cd34-ef56"],
        })
        assert cve is None
        assert ghsa == "GHSA-AB12-CD34-EF56"

    def test_no_id_returns_none_none(self, tmp_path, monkeypatch):
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        cve, ghsa = adapter._extract_identifiers({"VulnerabilityID": "UNKNOWN-1"})
        assert cve is None
        assert ghsa is None

    def test_no_vuln_id_key(self, tmp_path, monkeypatch):
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        cve, ghsa = adapter._extract_identifiers({})
        assert cve is None
        assert ghsa is None


class TestTrivyExtractAffectedRange:
    """Tests for TrivyAdapter._extract_affected_range."""

    def test_fixed_version_present(self, tmp_path, monkeypatch):
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        r = adapter._extract_affected_range({"FixedVersion": "2.0.0"})
        assert r == "< 2.0.0"

    def test_no_fixed_version(self, tmp_path, monkeypatch):
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        assert adapter._extract_affected_range({}) is None
        assert adapter._extract_affected_range({"FixedVersion": ""}) is None


class TestTrivyInferEcosystem:
    """Tests for TrivyAdapter._infer_ecosystem_from_purl."""

    def test_npm(self, tmp_path, monkeypatch):
        a = _make_trivy_adapter(tmp_path, monkeypatch)
        assert a._infer_ecosystem_from_purl("pkg:npm/lodash@4.17") == "npm"

    def test_pypi(self, tmp_path, monkeypatch):
        a = _make_trivy_adapter(tmp_path, monkeypatch)
        assert a._infer_ecosystem_from_purl("pkg:pypi/django@3.2") == "pypi"

    def test_maven(self, tmp_path, monkeypatch):
        a = _make_trivy_adapter(tmp_path, monkeypatch)
        assert a._infer_ecosystem_from_purl("pkg:maven/org.apache/log4j@1.0") == "maven"

    def test_nuget(self, tmp_path, monkeypatch):
        a = _make_trivy_adapter(tmp_path, monkeypatch)
        assert a._infer_ecosystem_from_purl("pkg:nuget/newtonsoft.json@13.0") == "nuget"

    def test_unknown_returns_none(self, tmp_path, monkeypatch):
        a = _make_trivy_adapter(tmp_path, monkeypatch)
        assert a._infer_ecosystem_from_purl("pkg:gem/rails@7.0") is None

    def test_empty_returns_none(self, tmp_path, monkeypatch):
        a = _make_trivy_adapter(tmp_path, monkeypatch)
        assert a._infer_ecosystem_from_purl("") is None


class TestTrivyLoadFindings:
    """Integration-level tests for TrivyAdapter.load_findings."""

    def test_load_findings_disabled_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
        from evaluation.adapters.trivy import TrivyAdapter
        a = TrivyAdapter(config={"env": {}})
        assert a.load_findings() == []

    def test_load_findings_enabled_returns_findings(self, tmp_path, monkeypatch):
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        output = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "PkgName": "lodash",
                            "InstalledVersion": "4.17.15",
                            "FixedVersion": "4.17.21",
                            "VulnerabilityID": "CVE-2021-23337",
                            "PkgIdentifier": {"PURL": "pkg:npm/lodash@4.17.15"},
                        }
                    ]
                }
            ]
        }
        with patch("subprocess.run", return_value=_make_completed_process(
            stdout=json.dumps(output), returncode=0
        )):
            findings = adapter.load_findings()
        assert len(findings) == 1
        assert findings[0].cve == "CVE-2021-23337"

    def test_load_findings_empty_data(self, tmp_path, monkeypatch):
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        with patch("subprocess.run", return_value=_make_completed_process(
            stdout="", returncode=0
        )):
            findings = adapter.load_findings()
        assert findings == []

    def test_load_findings_subprocess_error(self, tmp_path, monkeypatch):
        adapter = _make_trivy_adapter(tmp_path, monkeypatch)
        with patch("subprocess.run", side_effect=OSError("failed")):
            findings = adapter.load_findings()
        assert findings == []


# ===========================================================================
# SNYK TESTS
# ===========================================================================

VALID_SNYK_OUTPUT = {
    "vulnerabilities": [
        {
            "packageName": "lodash",
            "version": "4.17.15",
            "packageUrl": "pkg:npm/lodash@4.17.15",
            "identifiers": {
                "CVE": ["CVE-2021-23337"],
                "GHSA": ["GHSA-35jh-r3h4-6jhm"],
            },
            "title": "Prototype Pollution",
            "semver": {"vulnerable": [">=4.0.0 <4.17.21"]},
        }
    ]
}


class TestSnykRunViaBashScript:
    """Tests for SnykAdapter._run_snyk_via_bash_script."""

    def test_success_returns_data(self, tmp_path, monkeypatch):
        adapter = _make_snyk_adapter(tmp_path, monkeypatch)
        with patch("subprocess.run", return_value=_make_completed_process(
            stdout=json.dumps(VALID_SNYK_OUTPUT), returncode=0
        )):
            result = adapter._run_snyk_via_bash_script()
        assert result == VALID_SNYK_OUTPUT

    def test_nonzero_exit_code_retries_then_raises(self, tmp_path, monkeypatch):
        """Non-zero exit code should retry and raise RuntimeError."""
        adapter = _make_snyk_adapter(tmp_path, monkeypatch)
        calls = []
        def fake_run(*args, **kwargs):
            calls.append(1)
            return _make_completed_process(stdout="", returncode=1, stderr="error")
        with patch("subprocess.run", side_effect=fake_run):
            with patch("time.sleep"):
                with pytest.raises(RuntimeError, match="non-zero exit code"):
                    adapter._run_snyk_via_bash_script()
        assert len(calls) == 2  # max_attempts=2

    def test_empty_stdout_retries_then_raises(self, tmp_path, monkeypatch):
        """Empty stdout should retry and raise RuntimeError."""
        adapter = _make_snyk_adapter(tmp_path, monkeypatch)
        calls = []
        def fake_run(*args, **kwargs):
            calls.append(1)
            return _make_completed_process(stdout="", returncode=0)
        with patch("subprocess.run", side_effect=fake_run):
            with patch("time.sleep"):
                with pytest.raises(RuntimeError, match="empty stdout"):
                    adapter._run_snyk_via_bash_script()
        assert len(calls) == 2

    def test_invalid_json_retries_then_raises(self, tmp_path, monkeypatch):
        """Invalid JSON should retry and raise RuntimeError."""
        adapter = _make_snyk_adapter(tmp_path, monkeypatch)
        calls = []
        def fake_run(*args, **kwargs):
            calls.append(1)
            return _make_completed_process(stdout="not-json", returncode=0)
        with patch("subprocess.run", side_effect=fake_run):
            with patch("time.sleep"):
                with pytest.raises(RuntimeError, match="Invalid JSON"):
                    adapter._run_snyk_via_bash_script()
        assert len(calls) == 2

    def test_timeout_exception_retries_then_raises(self, tmp_path, monkeypatch):
        """TimeoutExpired should retry and raise RuntimeError."""
        adapter = _make_snyk_adapter(tmp_path, monkeypatch)
        calls = []
        def fake_run(*args, **kwargs):
            calls.append(1)
            exc = subprocess.TimeoutExpired(cmd=["bash"], timeout=30)
            exc.stdout = None
            exc.stderr = None
            raise exc
        with patch("subprocess.run", side_effect=fake_run):
            with patch("time.sleep"):
                with pytest.raises(RuntimeError, match="timed out"):
                    adapter._run_snyk_via_bash_script()
        assert len(calls) == 2

    def test_generic_exception_retries_then_raises(self, tmp_path, monkeypatch):
        """Generic subprocess exception should retry and raise RuntimeError."""
        adapter = _make_snyk_adapter(tmp_path, monkeypatch)
        calls = []
        def fake_run(*args, **kwargs):
            calls.append(1)
            raise OSError("exec error")
        with patch("subprocess.run", side_effect=fake_run):
            with patch("time.sleep"):
                with pytest.raises(RuntimeError, match="Failed to execute"):
                    adapter._run_snyk_via_bash_script()
        assert len(calls) == 2

    def test_no_vulnerabilities_list_raises(self, tmp_path, monkeypatch):
        """Response without 'vulnerabilities' list raises RuntimeError."""
        adapter = _make_snyk_adapter(tmp_path, monkeypatch)
        bad_data = {"something_else": []}
        with patch("subprocess.run", return_value=_make_completed_process(
            stdout=json.dumps(bad_data), returncode=0
        )):
            with patch("time.sleep"):
                with pytest.raises(RuntimeError, match="vulnerabilities"):
                    adapter._run_snyk_via_bash_script()

    def test_success_on_second_attempt(self, tmp_path, monkeypatch):
        """Returns data when first attempt fails but second succeeds."""
        adapter = _make_snyk_adapter(tmp_path, monkeypatch)
        attempt = [0]
        def fake_run(*args, **kwargs):
            attempt[0] += 1
            if attempt[0] == 1:
                return _make_completed_process(stdout="", returncode=0)
            return _make_completed_process(stdout=json.dumps(VALID_SNYK_OUTPUT), returncode=0)
        with patch("subprocess.run", side_effect=fake_run):
            with patch("time.sleep"):
                result = adapter._run_snyk_via_bash_script()
        assert result == VALID_SNYK_OUTPUT

    def test_stderr_logged_on_nonzero(self, tmp_path, monkeypatch):
        """Verifies stderr is captured and non-zero still triggers retry logic."""
        adapter = _make_snyk_adapter(tmp_path, monkeypatch)
        with patch("subprocess.run", return_value=_make_completed_process(
            stdout="", stderr="auth failed", returncode=2
        )):
            with patch("time.sleep"):
                with pytest.raises(RuntimeError):
                    adapter._run_snyk_via_bash_script()


class TestSnykLoadFindings:
    """Tests for SnykAdapter.load_findings (end-to-end with subprocess mock)."""

    def test_load_findings_disabled_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
        from evaluation.adapters.snyk import SnykAdapter
        a = SnykAdapter(config={"env": {}})
        assert a.load_findings() == []

    def test_load_findings_enabled_returns_findings(self, tmp_path, monkeypatch):
        adapter = _make_snyk_adapter(tmp_path, monkeypatch)
        with patch("subprocess.run", return_value=_make_completed_process(
            stdout=json.dumps(VALID_SNYK_OUTPUT), returncode=0
        )):
            findings = adapter.load_findings()
        assert len(findings) == 1
        assert findings[0].cve == "CVE-2021-23337"
        assert findings[0].ecosystem == "npm"
        assert findings[0].component == "lodash"

    def test_load_findings_for_component_empty(self, tmp_path, monkeypatch):
        adapter = _make_snyk_adapter(tmp_path, monkeypatch)
        result = adapter.load_findings_for_component(ecosystem="npm", component="x", version="1")
        assert result == []


# ===========================================================================
# GITHUB ADVISORY TESTS
# ===========================================================================

class TestVersionInRange:
    """Tests for github_advisory.version_in_range."""

    @pytest.fixture(autouse=True)
    def import_fn(self):
        from evaluation.adapters.github_advisory import version_in_range, RangeResult
        self.version_in_range = version_in_range
        self.RangeResult = RangeResult

    def test_maven_range_in_range(self):
        r = self.version_in_range("maven", "1.5.0", "[1.0.0,2.0.0)")
        assert r == self.RangeResult.IN_RANGE

    def test_maven_range_out_of_range_below(self):
        r = self.version_in_range("maven", "0.9.0", "[1.0.0,2.0.0)")
        assert r == self.RangeResult.OUT_OF_RANGE

    def test_maven_range_out_of_range_above(self):
        r = self.version_in_range("maven", "2.1.0", "[1.0.0,2.0.0)")
        assert r == self.RangeResult.OUT_OF_RANGE

    def test_maven_range_exclusive_upper_boundary(self):
        r = self.version_in_range("maven", "2.0.0", "[1.0.0,2.0.0)")
        assert r == self.RangeResult.OUT_OF_RANGE

    def test_maven_range_inclusive_upper_boundary(self):
        r = self.version_in_range("maven", "2.0.0", "[1.0.0,2.0.0]")
        assert r == self.RangeResult.IN_RANGE

    def test_maven_range_only_upper_bound(self):
        r = self.version_in_range("maven", "0.5.0", "(,1.2.3]")
        assert r == self.RangeResult.IN_RANGE

    def test_maven_range_only_upper_bound_out(self):
        r = self.version_in_range("maven", "2.0.0", "(,1.2.3]")
        assert r == self.RangeResult.OUT_OF_RANGE

    def test_maven_range_only_lower_bound(self):
        r = self.version_in_range("maven", "2.0.0", "[1.0.0,)")
        assert r == self.RangeResult.IN_RANGE

    def test_npm_semver_in_range(self):
        # NpmSpec requires no space between operator and version (e.g. ">=1.0.0 <2.0.0")
        r = self.version_in_range("npm", "1.5.0", ">=1.0.0 <2.0.0")
        assert r == self.RangeResult.IN_RANGE

    def test_npm_semver_out_of_range(self):
        r = self.version_in_range("npm", "2.0.0", ">=1.0.0 <2.0.0")
        assert r == self.RangeResult.OUT_OF_RANGE

    def test_npm_semver_with_comma_separator(self):
        r = self.version_in_range("npm", "1.5.0", ">=1.0.0,<2.0.0")
        assert r == self.RangeResult.IN_RANGE

    def test_pypi_fallback_in_range(self):
        r = self.version_in_range("pypi", "1.5.0", ">=1.0,<2.0")
        assert r == self.RangeResult.IN_RANGE

    def test_pypi_fallback_out_of_range(self):
        r = self.version_in_range("pypi", "2.0.0", ">=1.0,<2.0")
        assert r == self.RangeResult.OUT_OF_RANGE

    def test_undecidable_bad_version(self):
        r = self.version_in_range("maven", "not-a-version", "[1.0.0,2.0.0)")
        assert r == self.RangeResult.UNDECIDABLE

    def test_undecidable_no_range(self):
        r = self.version_in_range("npm", "1.0.0", None)
        assert r == self.RangeResult.UNDECIDABLE

    def test_undecidable_empty_range(self):
        r = self.version_in_range("npm", "1.0.0", "")
        assert r == self.RangeResult.UNDECIDABLE

    def test_undecidable_unknown_range_format(self):
        r = self.version_in_range("nuget", "1.0.0", "some-garbage-range-format-xyz")
        # not pypi, so falls through to UNDECIDABLE
        assert r == self.RangeResult.UNDECIDABLE


class TestGitHubAdvisoryQueryAdvisories:
    """Tests for GitHubAdvisoryAdapter._query_advisories."""

    def test_query_returns_advisories(self, tmp_path, monkeypatch):
        adapter = _make_github_adapter(tmp_path, monkeypatch)

        fake_response = MagicMock()
        fake_response.raise_for_status.return_value = None
        fake_response.json.return_value = {
            "data": {
                "securityVulnerabilities": {
                    "nodes": [
                        {
                            "vulnerableVersionRange": ">=4.0.0 <4.17.21",
                            "advisory": {
                                "ghsaId": "GHSA-35jh-r3h4-6jhm",
                                "summary": "Prototype Pollution in lodash",
                                "identifiers": [
                                    {"type": "CVE", "value": "CVE-2021-23337"},
                                    {"type": "GHSA", "value": "GHSA-35jh-r3h4-6jhm"},
                                ],
                            },
                        }
                    ]
                }
            }
        }

        adapter._api_call = MagicMock(return_value=fake_response)

        advisories = adapter._query_advisories(ecosystem="NPM", package="lodash")
        assert len(advisories) == 1
        assert advisories[0]["ghsaId"] == "GHSA-35jh-r3h4-6jhm"
        assert advisories[0]["vulnerableVersionRange"] == ">=4.0.0 <4.17.21"

    def test_query_api_call_exception_returns_empty(self, tmp_path, monkeypatch):
        adapter = _make_github_adapter(tmp_path, monkeypatch)
        adapter._api_call = MagicMock(side_effect=Exception("network error"))
        result = adapter._query_advisories(ecosystem="NPM", package="lodash")
        assert result == []

    def test_query_raise_for_status_raises_returns_empty(self, tmp_path, monkeypatch):
        adapter = _make_github_adapter(tmp_path, monkeypatch)
        fake_response = MagicMock()
        fake_response.raise_for_status.side_effect = Exception("401 Unauthorized")
        adapter._api_call = MagicMock(return_value=fake_response)
        result = adapter._query_advisories(ecosystem="NPM", package="lodash")
        assert result == []

    def test_query_invalid_json_returns_empty(self, tmp_path, monkeypatch):
        adapter = _make_github_adapter(tmp_path, monkeypatch)
        fake_response = MagicMock()
        fake_response.raise_for_status.return_value = None
        fake_response.json.side_effect = ValueError("invalid json")
        fake_response.text = "not-json"
        adapter._api_call = MagicMock(return_value=fake_response)
        result = adapter._query_advisories(ecosystem="NPM", package="lodash")
        assert result == []

    def test_query_empty_nodes_returns_empty(self, tmp_path, monkeypatch):
        adapter = _make_github_adapter(tmp_path, monkeypatch)
        fake_response = MagicMock()
        fake_response.raise_for_status.return_value = None
        fake_response.json.return_value = {
            "data": {"securityVulnerabilities": {"nodes": []}}
        }
        adapter._api_call = MagicMock(return_value=fake_response)
        result = adapter._query_advisories(ecosystem="NPM", package="lodash")
        assert result == []

    def test_query_skips_non_dict_nodes(self, tmp_path, monkeypatch):
        adapter = _make_github_adapter(tmp_path, monkeypatch)
        fake_response = MagicMock()
        fake_response.raise_for_status.return_value = None
        fake_response.json.return_value = {
            "data": {
                "securityVulnerabilities": {
                    "nodes": [
                        None,
                        "string-node",
                        {
                            "vulnerableVersionRange": ">=1.0.0",
                            "advisory": {
                                "ghsaId": "GHSA-aa-bb-cccc",
                                "summary": "Test",
                                "identifiers": [],
                            },
                        },
                    ]
                }
            }
        }
        adapter._api_call = MagicMock(return_value=fake_response)
        result = adapter._query_advisories(ecosystem="NPM", package="x")
        # Only the dict node should be included
        assert len(result) == 1

    def test_query_skips_non_dict_advisory(self, tmp_path, monkeypatch):
        adapter = _make_github_adapter(tmp_path, monkeypatch)
        fake_response = MagicMock()
        fake_response.raise_for_status.return_value = None
        fake_response.json.return_value = {
            "data": {
                "securityVulnerabilities": {
                    "nodes": [
                        {"vulnerableVersionRange": ">=1.0", "advisory": "not-a-dict"},
                    ]
                }
            }
        }
        adapter._api_call = MagicMock(return_value=fake_response)
        result = adapter._query_advisories(ecosystem="NPM", package="x")
        assert result == []


class TestGitHubAdvisoryLoadFindingsForComponent:
    """Tests for GitHubAdvisoryAdapter.load_findings_for_component."""

    def test_returns_findings_for_affected_version(self, tmp_path, monkeypatch):
        adapter = _make_github_adapter(tmp_path, monkeypatch)
        advisory = {
            "ghsaId": "GHSA-35jh-r3h4-6jhm",
            "summary": "Prototype Pollution",
            "identifiers": [{"type": "CVE", "value": "CVE-2021-23337"}],
            "vulnerableVersionRange": ">=4.0.0 <4.17.21",
        }
        adapter._query_advisories = MagicMock(return_value=[advisory])

        findings = adapter.load_findings_for_component(
            ecosystem="npm", component="lodash", version="4.17.15"
        )
        assert len(findings) == 1
        f = findings[0]
        assert f.cve == "CVE-2021-23337"
        assert f.ghsa == "GHSA-35JH-R3H4-6JHM"
        assert f.component == "lodash"
        assert f.version == "4.17.15"
        assert f.source == "github-advisory-db"

    def test_skips_out_of_range_version(self, tmp_path, monkeypatch):
        adapter = _make_github_adapter(tmp_path, monkeypatch)
        advisory = {
            "ghsaId": "GHSA-35jh-r3h4-6jhm",
            "summary": "Old vuln",
            "identifiers": [{"type": "CVE", "value": "CVE-2021-23337"}],
            "vulnerableVersionRange": ">=4.0.0 <4.17.21",
        }
        adapter._query_advisories = MagicMock(return_value=[advisory])

        findings = adapter.load_findings_for_component(
            ecosystem="npm", component="lodash", version="4.17.21"
        )
        assert findings == []

    def test_keeps_undecidable_range(self, tmp_path, monkeypatch):
        """UNDECIDABLE range result should keep the finding."""
        adapter = _make_github_adapter(tmp_path, monkeypatch)
        advisory = {
            "ghsaId": "GHSA-aa-bb-cccc",
            "summary": "Some vuln",
            "identifiers": [],
            "vulnerableVersionRange": "some-unparseable-range",
        }
        adapter._query_advisories = MagicMock(return_value=[advisory])

        findings = adapter.load_findings_for_component(
            ecosystem="npm", component="somelib", version="1.0.0"
        )
        # UNDECIDABLE → kept (not OUT_OF_RANGE)
        assert len(findings) == 1

    def test_no_range_keeps_finding(self, tmp_path, monkeypatch):
        """Advisory without a version range is kept (advisory-level)."""
        adapter = _make_github_adapter(tmp_path, monkeypatch)
        advisory = {
            "ghsaId": "GHSA-aa-bb-cccc",
            "summary": "Generic vuln",
            "identifiers": [],
            "vulnerableVersionRange": None,
        }
        adapter._query_advisories = MagicMock(return_value=[advisory])

        findings = adapter.load_findings_for_component(
            ecosystem="npm", component="somelib", version="1.0.0"
        )
        assert len(findings) == 1

    def test_deduplication(self, tmp_path, monkeypatch):
        """Same (ecosystem, component, version, id) is deduplicated."""
        adapter = _make_github_adapter(tmp_path, monkeypatch)
        advisory = {
            "ghsaId": "GHSA-aa-bb-cccc",
            "summary": "Dup vuln",
            "identifiers": [],
            "vulnerableVersionRange": None,
        }
        adapter._query_advisories = MagicMock(return_value=[advisory, advisory])

        findings = adapter.load_findings_for_component(
            ecosystem="npm", component="somelib", version="1.0.0"
        )
        assert len(findings) == 1

    def test_unknown_ecosystem_returns_empty(self, tmp_path, monkeypatch):
        """Ecosystem not in ECOSYSTEMS (or without github attr) returns []."""
        adapter = _make_github_adapter(tmp_path, monkeypatch)
        adapter._query_advisories = MagicMock(return_value=[])

        findings = adapter.load_findings_for_component(
            ecosystem="rubygems", component="sinatra", version="1.0"
        )
        assert findings == []

    def test_no_ghsa_id_skipped(self, tmp_path, monkeypatch):
        """Advisory without ghsaId is skipped."""
        adapter = _make_github_adapter(tmp_path, monkeypatch)
        advisory = {
            "summary": "No GHSA",
            "identifiers": [{"type": "CVE", "value": "CVE-2024-9999"}],
            "vulnerableVersionRange": None,
        }
        adapter._query_advisories = MagicMock(return_value=[advisory])

        findings = adapter.load_findings_for_component(
            ecosystem="npm", component="somelib", version="1.0.0"
        )
        assert findings == []


class TestGitHubAdvisoryExtractCve:
    """Tests for GitHubAdvisoryAdapter._extract_cve static method."""

    @pytest.fixture(autouse=True)
    def import_cls(self):
        from evaluation.adapters.github_advisory import GitHubAdvisoryAdapter
        self.cls = GitHubAdvisoryAdapter

    def test_extracts_cve(self):
        advisory = {
            "identifiers": [
                {"type": "GHSA", "value": "GHSA-aa-bb-cccc"},
                {"type": "CVE", "value": "CVE-2024-1234"},
            ]
        }
        cve = self.cls._extract_cve(advisory)
        assert cve == "CVE-2024-1234"

    def test_no_cve_returns_none(self):
        advisory = {
            "identifiers": [
                {"type": "GHSA", "value": "GHSA-aa-bb-cccc"},
            ]
        }
        assert self.cls._extract_cve(advisory) is None

    def test_empty_identifiers(self):
        assert self.cls._extract_cve({"identifiers": []}) is None

    def test_no_identifiers_key(self):
        assert self.cls._extract_cve({}) is None

    def test_normalizes_cve(self):
        advisory = {
            "identifiers": [{"type": "CVE", "value": "cve-2024-1234"}]
        }
        cve = self.cls._extract_cve(advisory)
        # normalize_identifier uppercases CVE
        assert cve is not None and "CVE" in cve.upper()


class TestGitHubAdvisoryInit:
    """Tests for GitHubAdvisoryAdapter initialization."""

    def test_raises_systemexit_without_token(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        from evaluation.adapters.github_advisory import GitHubAdvisoryAdapter
        from evaluation.core.model import Finding
        gt = [Finding(ecosystem="npm", component="x", version="1.0")]
        with pytest.raises(SystemExit):
            GitHubAdvisoryAdapter(config={"env": {}, "ground_truth": gt})

    def test_initializes_with_token(self, tmp_path, monkeypatch):
        adapter = _make_github_adapter(tmp_path, monkeypatch)
        assert adapter.name() == "github"
        assert adapter.supports_security_findings() is True
        assert adapter.supports_fp_heuristic() is False
        assert adapter._session is not None

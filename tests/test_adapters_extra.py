"""Smoke tests that instantiate adapters to cover __init__ paths."""
import os
from unittest.mock import MagicMock, patch

import pytest

from evaluation.core.model import Finding


def _ensure_build_path(tmp_path, monkeypatch):
    monkeypatch.setenv("GROUND_TRUTH_BUILD_PATH", str(tmp_path))


# --------------------------------------------------------------
# Trivy
# --------------------------------------------------------------
class TestTrivyAdapter:
    def test_disabled_without_sbom(self, tmp_path, monkeypatch):
        _ensure_build_path(tmp_path, monkeypatch)
        monkeypatch.delenv("TRIVY_SBOM_FILE", raising=False)
        from evaluation.adapters.trivy import TrivyAdapter
        a = TrivyAdapter(config={"env": {}})
        assert a.name() == "trivy"
        assert a.supports_fp_heuristic() is False
        assert a.supports_security_findings() is False
        assert a.load_findings() == []

    def test_basic_with_sbom_but_no_bin(self, tmp_path, monkeypatch):
        _ensure_build_path(tmp_path, monkeypatch)
        sbom = tmp_path / "sbom.json"
        sbom.write_text("{}")
        from evaluation.adapters.trivy import TrivyAdapter
        a = TrivyAdapter(config={
            "env": {"TRIVY_SBOM_FILE": str(sbom),
                    "TRIVY_BIN": "/nonexistent/trivy"}
        })
        # trivy_bin does not exist → disabled
        assert a.enabled is False


# --------------------------------------------------------------
# Snyk
# --------------------------------------------------------------
class TestSnykAdapter:
    def test_init(self, tmp_path, monkeypatch):
        _ensure_build_path(tmp_path, monkeypatch)
        from evaluation.adapters.snyk import SnykAdapter
        monkeypatch.delenv("SNYK_SBOM_FILE", raising=False)
        monkeypatch.delenv("SNYK_BIN", raising=False)
        a = SnykAdapter(config={"env": {}})
        assert a.name() == "snyk"
        assert a.supports_fp_heuristic() is False


# --------------------------------------------------------------
# OSS Index
# --------------------------------------------------------------
class TestOSSIndexAdapter:
    def test_init(self, tmp_path, monkeypatch):
        _ensure_build_path(tmp_path, monkeypatch)
        from evaluation.adapters.oss_index import OSSIndexAdapter
        a = OSSIndexAdapter(config={"env": {}})
        assert a.name() == "oss-index"
        assert a.supports_fp_heuristic() is False
        assert a.supports_security_findings() is True

    def test_init_authenticated(self, tmp_path, monkeypatch):
        _ensure_build_path(tmp_path, monkeypatch)
        from evaluation.adapters.oss_index import OSSIndexAdapter
        a = OSSIndexAdapter(config={
            "env": {"OSSINDEX_USERNAME": "u", "OSSINDEX_TOKEN": "t"}
        })
        assert a.session.auth == ("u", "t")


# --------------------------------------------------------------
# Dependency-Track
# --------------------------------------------------------------
class TestDTrackAdapter:
    def test_init_fails_without_env(self, tmp_path, monkeypatch):
        _ensure_build_path(tmp_path, monkeypatch)
        from evaluation.adapters.dtrack import DependencyTrackAdapter
        with pytest.raises(SystemExit):
            DependencyTrackAdapter(config={"env": {}})

    def test_init_basic(self, tmp_path, monkeypatch):
        _ensure_build_path(tmp_path, monkeypatch)
        from evaluation.adapters.dtrack import DependencyTrackAdapter
        a = DependencyTrackAdapter(config={"env": {
            "DTRACK_URL": "http://x/",
            "DTRACK_API_KEY": "k",
            "DTRACK_PROJECT_NAME": "p",
        }})
        assert a.name() == "dtrack"
        assert a.supports_security_findings() is True


# --------------------------------------------------------------
# GitHub Advisory adapter (needs GITHUB_TOKEN)
# --------------------------------------------------------------
class TestGitHubAdvisoryAdapter:
    def test_init_fails_without_token(self, tmp_path, monkeypatch):
        _ensure_build_path(tmp_path, monkeypatch)
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        from evaluation.adapters.github_advisory import GitHubAdvisoryAdapter
        with pytest.raises(SystemExit):
            GitHubAdvisoryAdapter(config={"ground_truth": []})

    def test_init_with_token(self, tmp_path, monkeypatch):
        _ensure_build_path(tmp_path, monkeypatch)
        monkeypatch.setenv("GITHUB_TOKEN", "dummy")
        from evaluation.adapters.github_advisory import GitHubAdvisoryAdapter
        a = GitHubAdvisoryAdapter(config={"ground_truth": []})
        assert a.name() == "github"
        assert a.supports_security_findings() is True
        assert a.load_findings() == []

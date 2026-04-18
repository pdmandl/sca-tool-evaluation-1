"""
Central normalization utilities.

These functions MUST be used symmetrically by:
- Ground truth loading
- Tool adapters
- Evaluation logic

Never normalize ad-hoc in adapters.
"""

from __future__ import annotations


# ------------------------------------------------------------
# Component normalization
# ------------------------------------------------------------

def normalize_component(ecosystem: str, name: str) -> str:
    """
    Normalize component names across ecosystems.

    INVARIANT (binding rule):
    - Matching is string-exact on (ecosystem, component, version)
    - Normalization MUST be symmetric (GT, tools, evaluation)
    - No heuristics, no fuzzy matching

    Ecosystem-specific identity:
    - maven:  groupId:artifactId  (preserved exactly)
    - nuget:  PackageId (case-insensitive, but complete)
    - npm:    lowercase (npm specification)
    - pypi:   PEP 503 canonical form
    """

    if not name:
        return ""

    eco = (ecosystem or "").strip().lower()
    n = name.strip()

    # ------------------------------------------------------------
    # Maven
    # ------------------------------------------------------------
    # Identity = groupId:artifactId
    # NO truncation, NO normalization other than format alignment
    if eco == "maven":
        # accept both group:artifact and group/artifact
        if "/" in n and ":" not in n:
            group, artifact = n.split("/", 1)
            return f"{group}:{artifact}"
        return n

    # ------------------------------------------------------------
    # NuGet
    # ------------------------------------------------------------
    # PackageId is case-insensitive but part of the identity in full
    # DO NOT strip prefixes (System., Microsoft., etc.)
    if eco == "nuget":
        return n

    # ------------------------------------------------------------
    # npm
    # ------------------------------------------------------------
    # npm package names are canonically lowercase
    if eco == "npm":
        return n.lower()

    # ------------------------------------------------------------
    # PyPI
    # ------------------------------------------------------------
    # PEP 503: lowercase + '_' -> '-'
    if eco == "pypi":
        return n.lower().replace("_", "-")

    # ------------------------------------------------------------
    # Fallback (conservative)
    # ------------------------------------------------------------
    return n



# ------------------------------------------------------------
# Vulnerability identifier normalization
# ------------------------------------------------------------

def normalize_identifier(vuln_id: str | None) -> str | None:
    """
    Normalize vulnerability identifiers (CVE, GHSA, OSV).

    - uppercases CVE / GHSA
    - leaves OSV IDs as-is
    """
    if not vuln_id:
        return None

    v = vuln_id.strip()

    if v.upper().startswith("CVE-"):
        return v.upper()

    if v.upper().startswith("GHSA-"):
        return v.upper()

    return v


# ------------------------------------------------------------
# Version normalization (string-safe)
# ------------------------------------------------------------

def normalize_version(version: str | None) -> str:
    """
    Normalize version string.

    NOTE:
    - DO NOT parse or coerce semver here
    - Keep string semantics stable
    """
    return (version or "").strip()


def ecosystem_from_purl(purl: str) -> str | None:
    """
    Extract ecosystem from a Package URL (purl).
    Example: pkg:pypi/tensorflow@2.9.0 -> pypi
    """
    if not purl:
        return None

    purl = purl.strip().lower()
    if not purl.startswith("pkg:"):
        return None

    try:
        return purl.split(":", 1)[1].split("/", 1)[0]
    except Exception:
        return None


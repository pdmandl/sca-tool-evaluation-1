"""
The single classification seam for the NVD completeness diagnostic.

``classify_nvd_coverage`` is a pure, I/O-free function: given a ground-truth
observation (a :class:`~evaluation.core.model.Finding`) and the parsed NVD record
for its CVE (or ``None`` for "CVE absent from NVD"), it returns exactly one of six
coverage buckets. A present CVE with product-matched CPE nodes is resolved to the
version-precise ``COVERED`` / ``VERSION_OUT_OF_RANGE`` split — the headline of the
diagnostic.

Precedence (evaluated per observation):
    NO_CVE -> CVE_ABSENT -> NO_CPE_CONFIG -> PRODUCT_MISMATCH
          -> VERSION_OUT_OF_RANGE -> COVERED

Product matching is *generous within a CVE*: because OSV already asserts the CVE
affects this component, a CPE node matches when its product or vendor **contains**
the normalized component token (exact match preferred over substring). For maven
the component is ``group:artifact`` and both segments are candidate tokens.
``PRODUCT_MISMATCH`` ("wrong product") is kept strictly distinct from the version
buckets ("version gap") — the matcher never consults versions.

Version coverage is decided over the **product-matched nodes only**: the
observation is ``COVERED`` iff its version falls inside at least one matched
node's applicability range (``versionStart*/End*`` bounds, an exact pinned CPE
version, or a bare wildcard = all versions), else ``VERSION_OUT_OF_RANGE``. An
unparseable version/range is never treated as covered, and the ranges of
unrelated products in a multi-product CVE never flip the verdict.
"""

from __future__ import annotations

import logging
from typing import Any, List, Optional

from evaluation.core.normalization import normalize_component
from evaluation.core.version_matching import version_in_range
from evaluation.nvd_completeness.record import NvdCpeNode, ParsedNvdRecord

log = logging.getLogger("nvd.coverage")

# ------------------------------------------------------------
# Coverage buckets (in precedence order)
# ------------------------------------------------------------

NO_CVE = "NO_CVE"
CVE_ABSENT = "CVE_ABSENT"
NO_CPE_CONFIG = "NO_CPE_CONFIG"
PRODUCT_MISMATCH = "PRODUCT_MISMATCH"
VERSION_OUT_OF_RANGE = "VERSION_OUT_OF_RANGE"
COVERED = "COVERED"

#: All buckets, in precedence order (used for report layout). ``COVERED`` is the
#: terminal "the diagnostic confirms NVD covers this observation" bucket.
COVERAGE_BUCKETS = (
    NO_CVE,
    CVE_ABSENT,
    NO_CPE_CONFIG,
    PRODUCT_MISMATCH,
    VERSION_OUT_OF_RANGE,
    COVERED,
)

# Product-match quality (exact preferred over substring).
MATCH_EXACT = "exact"
MATCH_SUBSTRING = "substring"

#: Greppable prefix for the per-observation classification log line.
COVERAGE_LOG_PREFIX = "NVD_COVERAGE"


# ------------------------------------------------------------
# Token canonicalization + generous product matcher
# ------------------------------------------------------------


def _canon(token: str) -> str:
    """
    Canonicalize a token for generous comparison: trim, lowercase, and unify the
    ``_``/``-`` separator (CPE products favor ``_`` where PyPI canonical form
    favors ``-``). Deliberately conservative — no other rewriting.
    """
    return (token or "").strip().lower().replace("_", "-")


def component_tokens(ecosystem: str, component: str) -> List[str]:
    """
    Candidate tokens for a component, matched against CPE ``vendor``/``product``.

    Maven's ``group:artifact`` identity contributes **both** segments as separate
    tokens; every other ecosystem contributes its single normalized component
    name. Tokens are de-duplicated on their canonical form, order preserved.
    """
    norm = normalize_component(ecosystem, component)
    eco = (ecosystem or "").strip().lower()

    raw: List[str] = []
    if eco == "maven" and ":" in norm:
        group, artifact = norm.split(":", 1)
        raw.extend([group.strip(), artifact.strip()])
    elif norm:
        raw.append(norm)

    seen = set()
    tokens: List[str] = []
    for t in raw:
        c = _canon(t)
        if c and c not in seen:
            seen.add(c)
            tokens.append(t)
    return tokens


def node_product_match(node: NvdCpeNode, tokens: List[str]) -> Optional[str]:
    """
    Does this CPE node's product or vendor match any candidate token?

    Returns :data:`MATCH_EXACT` if a token equals a vendor/product (preferred),
    :data:`MATCH_SUBSTRING` if a vendor/product merely contains a token, or
    ``None`` for no match. Versions are never consulted here.
    """
    candidates = [_canon(node.vendor), _canon(node.product)]
    best: Optional[str] = None
    for tok in tokens:
        ct = _canon(tok)
        if not ct:
            continue
        for cand in candidates:
            if not cand:
                continue
            if cand == ct:
                return MATCH_EXACT
            if ct in cand:
                best = MATCH_SUBSTRING
    return best


# ------------------------------------------------------------
# Version-range coverage (over product-matched nodes only)
# ------------------------------------------------------------


def _spec_from_bounds(node: NvdCpeNode) -> Optional[str]:
    """
    Translate a node's ``versionStart*/End*`` bounds into a PEP 440-style spec
    string (``>=/>``/``<=/<``) for :func:`version_in_range`, or ``None`` when the
    node carries no range bounds at all.
    """
    parts: List[str] = []
    if node.version_start_including:
        parts.append(f">={node.version_start_including}")
    if node.version_start_excluding:
        parts.append(f">{node.version_start_excluding}")
    if node.version_end_including:
        parts.append(f"<={node.version_end_including}")
    if node.version_end_excluding:
        parts.append(f"<{node.version_end_excluding}")
    return ",".join(parts) if parts else None


def node_version_covered(node: NvdCpeNode, version: Optional[str]) -> bool:
    """
    Does this (already product-matched) CPE node's applicability include ``version``?

    Range bounds take priority; else an exact pinned CPE version must equal the
    observation version; else a bare wildcard node (no version, no bounds) applies
    to every version of the product and is covered. An unparseable version or
    range is never treated as covered.
    """
    ver = (version or "").strip()
    spec = _spec_from_bounds(node)
    if spec is not None:
        return version_in_range(ver, spec)
    if node.version:
        return version_in_range(ver, f"=={node.version}")
    # No exact version and no bounds: wildcard CPE -> all versions vulnerable.
    return True


# ------------------------------------------------------------
# The classification seam
# ------------------------------------------------------------


def classify_nvd_coverage(
    gt_observation: Any,
    parsed_nvd_record: Optional[ParsedNvdRecord],
) -> str:
    """
    Classify one ground-truth observation into a coverage bucket.

    Pure and I/O-free. ``parsed_nvd_record`` is ``None`` iff the observation's
    CVE is absent from NVD. See module docstring for the precedence order, the
    generous product-matching rule, and the version-coverage rule.
    """
    cve = getattr(gt_observation, "cve", None)
    if not cve or not str(cve).strip():
        return NO_CVE

    if parsed_nvd_record is None:
        return CVE_ABSENT

    if not parsed_nvd_record.cpe_nodes:
        return NO_CPE_CONFIG

    tokens = component_tokens(
        getattr(gt_observation, "ecosystem", ""),
        getattr(gt_observation, "component", ""),
    )
    # Version coverage is decided over the product-matched nodes ONLY, so the
    # ranges of unrelated products in a multi-product CVE can never flip a verdict.
    matched_nodes = [n for n in parsed_nvd_record.cpe_nodes if node_product_match(n, tokens)]
    if not matched_nodes:
        return PRODUCT_MISMATCH

    version = getattr(gt_observation, "version", None)
    if any(node_version_covered(node, version) for node in matched_nodes):
        return COVERED

    return VERSION_OUT_OF_RANGE


# ------------------------------------------------------------
# Greppable per-observation log line
# ------------------------------------------------------------


def format_coverage_log_line(
    gt_observation: Any,
    bucket: str,
    parsed_nvd_record: Optional[ParsedNvdRecord] = None,
) -> str:
    """
    Render the greppable per-observation classification line.

    Prefixed with :data:`COVERAGE_LOG_PREFIX` so a reviewer can ``grep`` the run
    log and spot-check each verdict against the raw NVD record. ``matched_nodes``
    reports how many CPE nodes matched the component (0 unless the bucket is a
    product-matched terminal, ``COVERED`` / ``VERSION_OUT_OF_RANGE``), which is
    exactly the product-matcher-fidelity guard.
    """
    cve = getattr(gt_observation, "cve", None) or "-"
    matched = 0
    if parsed_nvd_record is not None and bucket in (COVERED, VERSION_OUT_OF_RANGE):
        tokens = component_tokens(
            getattr(gt_observation, "ecosystem", ""),
            getattr(gt_observation, "component", ""),
        )
        matched = sum(
            1 for node in parsed_nvd_record.cpe_nodes if node_product_match(node, tokens)
        )

    return (
        f"{COVERAGE_LOG_PREFIX} | bucket={bucket}"
        f" | ecosystem={getattr(gt_observation, 'ecosystem', '')}"
        f" | component={getattr(gt_observation, 'component', '')}"
        f" | version={getattr(gt_observation, 'version', '')}"
        f" | cve={cve}"
        f" | matched_nodes={matched}"
    )


def log_coverage_observation(
    logger: logging.Logger,
    gt_observation: Any,
    bucket: str,
    parsed_nvd_record: Optional[ParsedNvdRecord] = None,
) -> None:
    """Emit :func:`format_coverage_log_line` at INFO on ``logger``."""
    logger.info(format_coverage_log_line(gt_observation, bucket, parsed_nvd_record))

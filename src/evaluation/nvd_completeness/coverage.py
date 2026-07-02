"""
The single classification seam for the NVD completeness diagnostic.

``classify_nvd_coverage`` is a pure, I/O-free function: given a ground-truth
observation (a :class:`~evaluation.core.model.Finding`) and the parsed NVD record
for its CVE (or ``None`` for "CVE absent from NVD"), it returns exactly one
coverage bucket.

This is the **walking-skeleton** slice. It deliberately makes only the coarsest
distinction — enough to prove the end-to-end pipe from ground truth to a
per-ecosystem completeness figure — and leaves matching precision to later
slices:

    NO_CVE  -> the observation has no CVE (GHSA-only OSV entry); NVD is CVE-keyed
               and structurally cannot cover it. Stays in the denominator.
    CVE_ABSENT -> the CVE is absent / reserved / rejected in NVD.
    PRESENT -> the CVE was found in NVD.

Precedence (evaluated per observation): ``NO_CVE -> CVE_ABSENT -> PRESENT``.

Later slices split ``PRESENT`` further (no CPE config / product mismatch /
version out of range) and turn the ratio into a version-precise completeness
figure. The parsed record already carries the CPE nodes needed for that; this
slice simply does not consult them.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from evaluation.nvd_completeness.record import ParsedNvdRecord

log = logging.getLogger("nvd.coverage")

# ------------------------------------------------------------
# Coverage buckets (in precedence order)
# ------------------------------------------------------------

NO_CVE = "NO_CVE"
CVE_ABSENT = "CVE_ABSENT"
PRESENT = "PRESENT"

#: All buckets emitted by this slice, in precedence order (report layout order).
COVERAGE_BUCKETS = (
    NO_CVE,
    CVE_ABSENT,
    PRESENT,
)

#: The bucket that counts toward completeness for this slice.
COVERED_BUCKET = PRESENT

#: Greppable prefix for the per-observation classification log line.
COVERAGE_LOG_PREFIX = "NVD_COVERAGE"


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
    CVE is absent from NVD. See the module docstring for the precedence order.
    """
    cve = getattr(gt_observation, "cve", None)
    if not cve or not str(cve).strip():
        return NO_CVE

    if parsed_nvd_record is None:
        return CVE_ABSENT

    return PRESENT


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
    log and spot-check each verdict against the raw NVD record. ``cpe_nodes``
    reports how many CPE nodes the CVE carried (0 unless the CVE is present),
    which is the seam later slices use to refine ``PRESENT``.
    """
    cve = getattr(gt_observation, "cve", None) or "-"
    cpe_nodes = len(parsed_nvd_record.cpe_nodes) if parsed_nvd_record is not None else 0

    return (
        f"{COVERAGE_LOG_PREFIX} | bucket={bucket}"
        f" | ecosystem={getattr(gt_observation, 'ecosystem', '')}"
        f" | component={getattr(gt_observation, 'component', '')}"
        f" | version={getattr(gt_observation, 'version', '')}"
        f" | cve={cve}"
        f" | cpe_nodes={cpe_nodes}"
    )


def log_coverage_observation(
    logger: logging.Logger,
    gt_observation: Any,
    bucket: str,
    parsed_nvd_record: Optional[ParsedNvdRecord] = None,
) -> None:
    """Emit :func:`format_coverage_log_line` at INFO on ``logger``."""
    logger.info(format_coverage_log_line(gt_observation, bucket, parsed_nvd_record))

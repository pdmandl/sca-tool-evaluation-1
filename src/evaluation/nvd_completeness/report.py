"""
Per-ecosystem aggregation and rendering of the ``*_nvd_completeness`` report.

The report never enters the head-to-head detection table and never computes
Overlap. It presents, per ecosystem, the coverage-bucket counts and the
denominator so a reviewer can reconstruct the figures, plus a run-metadata header
making the point-in-time / non-reproducible nature explicit.

This slice reports all buckets emitted so far (``NO_CVE`` .. ``PRODUCT_MATCHED``).
``PRODUCT_MATCHED`` is the closest-to-covered bucket here; it is split into
version-covered vs version-out-of-range — and turned into the headline
completeness ratio — in the next slice, so the ratio shown now is labeled
provisional.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Tuple

from evaluation.nvd_completeness.coverage import COVERAGE_BUCKETS, PRODUCT_MATCHED

#: Ecosystems always shown, even at zero — "gap by ecosystem" is the point.
DEFAULT_ECOSYSTEMS = ("pypi", "npm", "maven")


@dataclass
class NvdCompletenessReport:
    """Aggregated bucket counts per ecosystem plus run metadata."""

    per_ecosystem: Dict[str, Dict[str, int]] = field(default_factory=dict)
    meta: Dict[str, str] = field(default_factory=dict)

    def denominator(self, ecosystem: str) -> int:
        return sum(self.per_ecosystem.get(ecosystem, {}).values())

    def count(self, ecosystem: str, bucket: str) -> int:
        return self.per_ecosystem.get(ecosystem, {}).get(bucket, 0)


def aggregate_buckets(
    classified: Iterable[Tuple[Any, str]],
    *,
    meta: Dict[str, str] | None = None,
) -> NvdCompletenessReport:
    """
    Aggregate ``(observation, bucket)`` pairs into per-ecosystem bucket counts.

    Every ecosystem in :data:`DEFAULT_ECOSYSTEMS` is present in the result even
    with all-zero counts, and every bucket key is always present per ecosystem so
    the report layout is stable and the denominator is reconstructible.
    """
    ecosystems = set(DEFAULT_ECOSYSTEMS)
    counts: Dict[str, Dict[str, int]] = {}

    pairs = list(classified)
    for observation, _bucket in pairs:
        eco = (getattr(observation, "ecosystem", "") or "").strip().lower()
        if eco:
            ecosystems.add(eco)

    for eco in ecosystems:
        counts[eco] = {bucket: 0 for bucket in COVERAGE_BUCKETS}

    for observation, bucket in pairs:
        eco = (getattr(observation, "ecosystem", "") or "").strip().lower()
        if not eco:
            continue
        if bucket not in counts[eco]:
            counts[eco][bucket] = 0
        counts[eco][bucket] += 1

    return NvdCompletenessReport(per_ecosystem=counts, meta=dict(meta or {}))


def _matched_ratio(report: NvdCompletenessReport, ecosystem: str) -> float:
    denom = report.denominator(ecosystem)
    if denom == 0:
        return 0.0
    return report.count(ecosystem, PRODUCT_MATCHED) / denom


def render_report(report: NvdCompletenessReport) -> str:
    """Render the ``*_nvd_completeness`` report as plain text."""
    lines: List[str] = []
    lines.append("NVD CPE-data completeness diagnostic")
    lines.append("=" * 40)

    meta = report.meta or {}
    lines.append(f"ground_truth   : {meta.get('ground_truth', '-')}")
    lines.append(f"fetch_date_utc : {meta.get('fetch_date_utc', '-')}")
    lines.append(f"nvd_api_version: {meta.get('nvd_api_version', '-')}")
    lines.append(
        "NOTE: point-in-time figure; NVD backfills CPE data and offers no "
        "historical query, so this is not reproducible."
    )
    lines.append("")

    for eco in sorted(report.per_ecosystem):
        denom = report.denominator(eco)
        lines.append(f"[{eco}] denominator={denom}")
        for bucket in COVERAGE_BUCKETS:
            lines.append(f"    {bucket:<16} {report.count(eco, bucket)}")
        lines.append(
            f"    product_matched_ratio={_matched_ratio(report, eco):.4f}"
            "  (provisional; version check pending)"
        )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"

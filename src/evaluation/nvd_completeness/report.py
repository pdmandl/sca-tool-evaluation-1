"""
Per-ecosystem aggregation and rendering of the ``*_nvd_completeness`` report.

The report never enters the head-to-head detection table and never computes
Overlap. It presents, per ecosystem, the coverage-bucket counts, the denominator,
and the derived completeness ratio, so a reviewer can reconstruct the figure,
plus a run-metadata header making the point-in-time / non-reproducible nature
explicit.

For this walking-skeleton slice completeness is ``PRESENT / total observations``
in that ecosystem; later slices refine ``PRESENT`` into a version-precise
covered/uncovered split.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from evaluation.nvd_completeness.coverage import COVERAGE_BUCKETS, COVERED_BUCKET

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

    def completeness(self, ecosystem: str) -> float:
        denom = self.denominator(ecosystem)
        if denom == 0:
            return 0.0
        return self.count(ecosystem, COVERED_BUCKET) / denom


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
    pairs = list(classified)

    ecosystems = set(DEFAULT_ECOSYSTEMS)
    for observation, _bucket in pairs:
        eco = (getattr(observation, "ecosystem", "") or "").strip().lower()
        if eco:
            ecosystems.add(eco)

    counts: Dict[str, Dict[str, int]] = {
        eco: {bucket: 0 for bucket in COVERAGE_BUCKETS} for eco in ecosystems
    }

    for observation, bucket in pairs:
        eco = (getattr(observation, "ecosystem", "") or "").strip().lower()
        if not eco:
            continue
        if bucket not in counts[eco]:
            counts[eco][bucket] = 0
        counts[eco][bucket] += 1

    return NvdCompletenessReport(per_ecosystem=counts, meta=dict(meta or {}))


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
        "historical query, so this is NOT reproducible."
    )
    lines.append("")

    for eco in sorted(report.per_ecosystem):
        denom = report.denominator(eco)
        lines.append(f"[{eco}] denominator={denom}")
        for bucket in COVERAGE_BUCKETS:
            lines.append(f"    {bucket:<12} {report.count(eco, bucket)}")
        lines.append(f"    completeness={report.completeness(eco):.4f}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_report(report: NvdCompletenessReport, *, out_dir: Path, ground_truth_name: str) -> Path:
    """
    Write the rendered report to ``<out_dir>/<ground_truth_name>_nvd_completeness.txt``
    and return the path. This artifact is dedicated to the diagnostic and never
    written into the standard evaluation report or the aggregated LaTeX tables.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{ground_truth_name}_nvd_completeness.txt"
    path.write_text(render_report(report), encoding="utf-8")
    return path

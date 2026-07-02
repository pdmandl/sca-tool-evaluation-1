#!/usr/bin/env python3
"""
Entry point for the NVD CPE-data completeness diagnostic.

This runner is deliberately **separate** from ``run_evaluation`` / the ``--tool``
machinery: NVD is a side-by-side diagnostic, not a detection tool, so it never
enters the TP / FP / FN pipeline, never computes Overlap, and is never run by the
temporal runner. It reads the *same* ground-truth CSV every other tool uses,
seeds from the ground-truth CVEs, queries NVD live (once per unique CVE), and
writes a dedicated ``*_nvd_completeness`` report.

Run it with::

    python -m evaluation.nvd_completeness.runner --ground-truth path/to/ground_truth.csv
"""

from __future__ import annotations

import argparse
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from evaluation.adapters.nvd import NvdAdapter
from evaluation.core.ground_truth import load_ground_truth
from evaluation.core.model import Finding
from evaluation.nvd_completeness.coverage import (
    classify_nvd_coverage,
    log_coverage_observation,
)
from evaluation.nvd_completeness.record import ParsedNvdRecord
from evaluation.nvd_completeness.report import (
    NvdCompletenessReport,
    aggregate_buckets,
    render_report,
    write_report,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-5s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("nvd.completeness")

# Dedicated logger for the greppable per-observation coverage lines.
_coverage_log = logging.getLogger("nvd.coverage")

#: The NVD API version this diagnostic targets, used when no live response has
#: yet reported one (e.g. every seeded CVE was absent).
DEFAULT_NVD_API_VERSION = "2.0"


def _unique_cves(ground_truth: List[Finding]) -> List[str]:
    """Return the distinct, non-empty CVE ids across all observations, ordered."""
    seen = set()
    ordered: List[str] = []
    for obs in ground_truth:
        cve = (getattr(obs, "cve", None) or "").strip()
        if cve and cve not in seen:
            seen.add(cve)
            ordered.append(cve)
    return ordered


def run_nvd_completeness(
    *,
    ground_truth_path: str,
    adapter: Optional[NvdAdapter] = None,
) -> NvdCompletenessReport:
    """
    Execute the full completeness diagnostic and write the report artifact.

    ``adapter`` is injectable for testing; when omitted a live :class:`NvdAdapter`
    is constructed from the environment. Fails loudly on a missing / empty /
    malformed ground truth rather than emitting a silent zero-coverage report.
    """
    log.info("=== NVD completeness diagnostic started ===")

    gt_path = Path(ground_truth_path).resolve()
    if not gt_path.exists():
        raise SystemExit(f"Ground truth file not found: {gt_path}")

    ground_truth_name = gt_path.stem

    log.info("Loading ground truth CSV: %s", gt_path)
    ground_truth: List[Finding] = load_ground_truth(gt_path)

    if not ground_truth:
        raise SystemExit(f"Ground truth is empty: {gt_path}")
    if not any((getattr(o, "ecosystem", "") or "").strip() for o in ground_truth):
        raise SystemExit(
            f"Ground truth is malformed (no ecosystem column values): {gt_path}"
        )

    log.info("Ground truth loaded: %d observations", len(ground_truth))

    if adapter is None:
        config = {
            "env": os.environ,
            "ground_truth": ground_truth,
            "ground_truth_path": gt_path,
        }
        adapter = NvdAdapter(config)
    log.info("Initialized adapter: %s", adapter.name())

    # ---- Seed from ground-truth CVEs, de-duplicated, one request each. ----
    unique_cves = _unique_cves(ground_truth)
    log.info("Querying NVD for %d unique CVEs (one request each)", len(unique_cves))

    records: Dict[str, Optional[ParsedNvdRecord]] = {}
    for cve in adapter.iter_with_progress(
        unique_cves,
        desc="NVD CVE lookup",
        unit="cve",
    ):
        try:
            records[cve] = adapter.fetch_record(cve)
        except RuntimeError as exc:
            # A transport/auth failure (exhausted retries, non-JSON body, or an
            # invalid-API-key 404) must abort the run: emitting a report where
            # every lookup silently became CVE_ABSENT would publish a misleading
            # zero-coverage figure.
            raise SystemExit(f"NVD lookup for {cve} failed; aborting diagnostic. {exc}")

    # ---- Classify every observation (NO_CVE observations stay counted). ----
    classified: List[Tuple[Finding, str]] = []
    for obs in ground_truth:
        cve = (getattr(obs, "cve", None) or "").strip()
        record = records.get(cve) if cve else None
        bucket = classify_nvd_coverage(obs, record)
        log_coverage_observation(_coverage_log, obs, bucket, record)
        classified.append((obs, bucket))

    meta = {
        "ground_truth": ground_truth_name,
        "fetch_date_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nvd_api_version": adapter.api_version or DEFAULT_NVD_API_VERSION,
    }

    report = aggregate_buckets(classified, meta=meta)

    out_path = write_report(report, out_dir=gt_path.parent, ground_truth_name=ground_truth_name)
    log.info("Wrote NVD completeness report: %s", out_path)

    # Echo the report so a run is demoable end-to-end from the console.
    print(render_report(report))

    log.info("=== NVD completeness diagnostic finished ===")
    return report


def main() -> None:
    ap = argparse.ArgumentParser(
        description="NVD CPE-data completeness diagnostic (standalone, not a detection tool)",
    )
    ap.add_argument(
        "--ground-truth",
        required=True,
        help="Path to the ground truth CSV file (same file the SCA tools use)",
    )
    args = ap.parse_args()

    run_nvd_completeness(ground_truth_path=args.ground_truth)


if __name__ == "__main__":
    main()

"""
Typed view of an NVD CVE record and the parser that produces it.

The NVD 2.0 API returns, per CVE, a nested ``configurations -> nodes ->
cpeMatch`` tree of CPE applicability statements. For this walking skeleton the
:mod:`coverage <evaluation.nvd_completeness.coverage>` classifier only needs to
know whether the CVE is *present* in NVD at all; but the adapter already returns
a small typed view of the CPE configuration nodes so the later precision slices
(product matching / version-range checks) can be built on top of it without
re-parsing.

:func:`parse_nvd_record` performs that reduction. It does no I/O and never raises
on a malformed record — an unrecognized shape simply yields no nodes, and an
absent CVE yields ``None``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Tuple


@dataclass(frozen=True)
class NvdCpeNode:
    """
    One CPE applicability entry, extracted from an NVD ``cpeMatch``.

    ``vendor`` / ``product`` come from the CPE 2.3 URI
    (``cpe:2.3:<part>:<vendor>:<product>:<version>:...``). ``version`` is the
    exact CPE version when the URI pins one (i.e. not ``*`` / ``-``), otherwise
    ``None``; the range bounds carry the ``versionStart*`` / ``versionEnd*``
    qualifiers verbatim. These fields are parsed now for the later precision
    slices; the coarse classifier in this slice ignores them.
    """

    vendor: str
    product: str
    version: Optional[str] = None
    version_start_including: Optional[str] = None
    version_start_excluding: Optional[str] = None
    version_end_including: Optional[str] = None
    version_end_excluding: Optional[str] = None
    vulnerable: bool = True


@dataclass(frozen=True)
class ParsedNvdRecord:
    """A CVE id plus its flattened, vulnerable CPE nodes."""

    cve_id: str
    cpe_nodes: List[NvdCpeNode] = field(default_factory=list)

    @property
    def has_cpe_config(self) -> bool:
        return bool(self.cpe_nodes)


def _iter_cpe_matches(container: Any) -> Iterator[Dict[str, Any]]:
    """
    Yield every ``cpeMatch`` dict reachable from an NVD configuration container.

    Walks ``configurations`` and the recursive ``nodes`` / ``children`` trees so
    that both the flat NVD 2.0 shape and any nested AND/OR nodes are covered.
    """

    if isinstance(container, dict):
        for match in container.get("cpeMatch") or []:
            if isinstance(match, dict):
                yield match
        for key in ("configurations", "nodes", "children"):
            yield from _iter_cpe_matches(container.get(key))
    elif isinstance(container, list):
        for item in container:
            yield from _iter_cpe_matches(item)


def _cpe_fields(criteria: str) -> Tuple[str, str, Optional[str]]:
    """
    Extract ``(vendor, product, exact_version)`` from a CPE 2.3 URI.

    A ``*`` or ``-`` version placeholder is returned as ``None`` (range-based or
    not-applicable), so callers never mistake a wildcard for a pinned version.
    """

    parts = (criteria or "").split(":")
    # cpe:2.3:<part>:<vendor>:<product>:<version>:...
    vendor = parts[3] if len(parts) > 3 else ""
    product = parts[4] if len(parts) > 4 else ""
    raw_version = parts[5] if len(parts) > 5 else ""
    version = raw_version if raw_version not in ("", "*", "-") else None
    return vendor, product, version


def _extract_cve_object(raw: Any) -> Optional[Dict[str, Any]]:
    """
    Locate the single CVE object inside a raw NVD body.

    Accepts either a full NVD 2.0 response (``{"vulnerabilities": [{"cve": ...}]}``)
    or an already-unwrapped CVE object (``{"id": ..., "configurations": [...]}``).
    Returns ``None`` when no CVE is present — the ``CVE_ABSENT`` case (reserved /
    rejected / unknown CVEs come back with an empty ``vulnerabilities`` list).
    """

    if not isinstance(raw, dict):
        return None

    if "vulnerabilities" in raw:
        vulns = raw.get("vulnerabilities") or []
        if not isinstance(vulns, list) or not vulns:
            return None
        first = vulns[0]
        if isinstance(first, dict) and isinstance(first.get("cve"), dict):
            return first["cve"]
        return first if isinstance(first, dict) else None

    # Already a CVE object.
    if raw.get("id") or "configurations" in raw:
        return raw

    return None


def parse_nvd_record(raw: Any) -> Optional[ParsedNvdRecord]:
    """
    Parse a raw NVD body into a :class:`ParsedNvdRecord`, or ``None`` if the CVE
    is absent from NVD.

    A returned record with an empty ``cpe_nodes`` list means "CVE present but
    carries no CPE configuration". Only nodes flagged ``vulnerable`` are kept.
    """

    cve = _extract_cve_object(raw)
    if cve is None:
        return None

    cve_id = str(cve.get("id") or "").strip()

    nodes: List[NvdCpeNode] = []
    for match in _iter_cpe_matches(cve.get("configurations")):
        if not match.get("vulnerable", True):
            continue
        vendor, product, version = _cpe_fields(str(match.get("criteria") or ""))
        nodes.append(
            NvdCpeNode(
                vendor=vendor,
                product=product,
                version=version,
                version_start_including=match.get("versionStartIncluding"),
                version_start_excluding=match.get("versionStartExcluding"),
                version_end_including=match.get("versionEndIncluding"),
                version_end_excluding=match.get("versionEndExcluding"),
                vulnerable=bool(match.get("vulnerable", True)),
            )
        )

    return ParsedNvdRecord(cve_id=cve_id, cpe_nodes=nodes)

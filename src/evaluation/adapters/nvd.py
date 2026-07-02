"""
NVD adapter — HTTP transport only, for the CPE-data completeness diagnostic.

Unlike the six SCA adapters, this adapter is **not** a detection tool. It never
emits ``Finding``s and implements no detection semantics; it exists purely to:

- build the NVD 2.0 REST query by ``cveId``,
- honor ``NVD_API_KEY`` (50 requests / 30 s with a key, 5 / 30 s anonymous),
- back off / retry on HTTP 429 and transport errors,
- trace every call through the base-class API-call logging (``*_api.log``), and
- return a *parsed* record (raw JSON → :class:`ParsedNvdRecord`) for the
  classifier seam, or ``None`` when the CVE is absent from NVD.

It reuses :class:`~evaluation.adapters.base.VulnerabilityToolAdapter` so the
diagnostic gets the same auditable per-tool API log every other source has, per
``decision-0001-adapter-pattern-for-tools``.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional

import requests

from evaluation.adapters.base import VulnerabilityToolAdapter
from evaluation.core.model import Finding
from evaluation.nvd_completeness.record import ParsedNvdRecord, parse_nvd_record

log = logging.getLogger("adapters.nvd")

# NVD documented rate limits (requests per rolling 30 s window).
_RATE_WITH_KEY = 50
_RATE_ANONYMOUS = 5
_RATE_WINDOW_S = 30.0


class NvdAdapter(VulnerabilityToolAdapter):
    """
    NVD 2.0 REST transport for the completeness diagnostic (no detection).
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)

        env = config.get("env", {})

        self.api_key = env.get("NVD_API_KEY") or None
        self.max_retries = int(env.get("NVD_MAX_RETRIES", 4))
        self.retry_backoff_s = float(env.get("NVD_RETRY_BACKOFF_S", 2.0))

        # Rate limit: 50/30s with a key, 5/30s anonymous. An explicit override is
        # honored mainly so tests can drive the transport without real sleeps.
        rate = _RATE_WITH_KEY if self.api_key else _RATE_ANONYMOUS
        override = env.get("NVD_MIN_REQUEST_INTERVAL_S")
        self.min_interval_s = float(override) if override is not None else _RATE_WINDOW_S / rate
        self._last_request_ts: Optional[float] = None

        #: NVD API version, captured from the first successful response.
        self.api_version: Optional[str] = None

        self.session = requests.Session()
        headers = {
            "Accept": "application/json",
            "User-Agent": "sca-tool-evaluation/nvd-adapter",
        }
        if self.api_key:
            headers["apiKey"] = self.api_key
            log.info("NVD adapter initialized (authenticated, %d req/%ds)", rate, int(_RATE_WINDOW_S))
        else:
            log.info("NVD adapter initialized (anonymous, %d req/%ds)", rate, int(_RATE_WINDOW_S))
        self.session.headers.update(headers)

    # ------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------

    def name(self) -> str:
        return "nvd"

    def load_findings_for_component(
        self,
        *,
        ecosystem: str,
        component: str,
        version: str,
    ) -> List[Finding]:
        """
        The NVD diagnostic is not a detection tool: it never emits ``Finding``s.

        This method exists only to satisfy the adapter contract; driving NVD
        through the detection pipeline is a programming error and fails loudly.
        """
        raise NotImplementedError(
            "NvdAdapter is a completeness diagnostic and emits no Findings; "
            "use fetch_record(cve_id) via the nvd_completeness runner instead."
        )

    # ------------------------------------------------------------
    # Public transport API (used by the nvd_completeness runner)
    # ------------------------------------------------------------

    def fetch_record(self, cve_id: str) -> Optional[ParsedNvdRecord]:
        """
        Fetch one CVE from NVD and return its parsed record.

        Returns ``None`` only when the CVE is genuinely absent / reserved /
        rejected in NVD — i.e. NVD answers 200 with an empty ``vulnerabilities``
        list. Raises :class:`RuntimeError` when the request cannot be completed
        (retries exhausted, a non-JSON body, or an HTTP 404 that signals an
        invalid / not-yet-active API key), so a transport or auth failure is
        never silently counted as "CVE absent".
        """
        cve = (cve_id or "").strip()
        if not cve:
            return None

        raw = self._get_cve(cve)
        record = parse_nvd_record(raw)
        return record

    # ------------------------------------------------------------
    # NVD interaction
    # ------------------------------------------------------------

    def _get_cve(self, cve_id: str) -> Any:
        params = {"cveId": cve_id}
        last_status: Optional[int] = None

        for attempt in range(1, self.max_retries + 1):
            self._respect_rate_limit()

            try:
                r = self._api_call(
                    session=self.session,
                    method="GET",
                    url=self.BASE_URL,
                    params=params,
                    timeout=45,
                )
            except requests.RequestException:
                self._sleep_backoff(attempt)
                continue

            last_status = r.status_code

            if r.status_code == 200:
                try:
                    data = r.json()
                except Exception:
                    # A 200 with a non-JSON / empty body is a transport anomaly,
                    # NOT an absent CVE (absent = 200 with an empty
                    # ``vulnerabilities`` list). Retry rather than silently
                    # returning None, so a flaky endpoint can never masquerade as
                    # CVE_ABSENT and deflate the completeness figure.
                    self._sleep_backoff(attempt)
                    continue
                self._capture_api_version(data)
                return data

            # NVD signals an invalid / not-yet-active API key with 404 — a
            # genuinely unknown CVE comes back as 200 with an empty
            # ``vulnerabilities`` list, never 404. So a 404 is never "CVE absent";
            # treating it as such would silently zero the completeness figure.
            # Retrying a bad key would not help, so fail loudly and immediately.
            if r.status_code == 404:
                hint = (
                    "Check that NVD_API_KEY is correct and activated."
                    if self.api_key
                    else "No NVD_API_KEY is set; if you supplied one, ensure it is "
                    "exported into the environment."
                )
                raise RuntimeError(
                    f"NVD returned HTTP 404 for {cve_id}. NVD uses 404 to signal an "
                    f"invalid or not-yet-active API key (unknown CVEs return 200 "
                    f"with an empty list), so this is not treated as 'CVE absent'. "
                    f"{hint}"
                )

            # Rate limited or transient server error → back off and retry.
            if r.status_code == 429 or 500 <= r.status_code < 600:
                self._sleep_backoff(attempt, honor_retry_after=r)
                continue

            # Anything else is unexpected; retry with plain backoff.
            self._sleep_backoff(attempt)

        raise RuntimeError(
            f"NVD request for {cve_id} failed after {self.max_retries} attempts "
            f"(last HTTP status: {last_status})"
        )

    def _capture_api_version(self, data: Any) -> None:
        if self.api_version is None and isinstance(data, dict):
            version = data.get("version")
            if version:
                self.api_version = str(version)

    # ------------------------------------------------------------
    # Rate limiting + backoff
    # ------------------------------------------------------------

    def _respect_rate_limit(self) -> None:
        if self.min_interval_s <= 0:
            return
        now = time.monotonic()
        if self._last_request_ts is not None:
            elapsed = now - self._last_request_ts
            wait = self.min_interval_s - elapsed
            if wait > 0:
                time.sleep(wait)
        self._last_request_ts = time.monotonic()

    def _sleep_backoff(
        self, attempt: int, honor_retry_after: Optional[requests.Response] = None
    ) -> None:
        if honor_retry_after is not None:
            ra = honor_retry_after.headers.get("Retry-After")
            if ra:
                try:
                    time.sleep(min(float(ra), 60.0))
                    return
                except Exception:
                    pass

        delay = self.retry_backoff_s * attempt
        time.sleep(min(delay, 30.0))

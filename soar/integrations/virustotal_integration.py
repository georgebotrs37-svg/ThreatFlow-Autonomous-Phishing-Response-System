"""
ThreatFlow SOAR - VirusTotal Integration
=========================================
Full-featured VirusTotal v3 API client with rate limiting, retry logic,
error handling, and normalized response format for use in Shuffle SOAR
phishing response workflows.

Author: ThreatFlow SOC Automation
Version: 1.0.0
"""

from __future__ import annotations

import base64
import logging
import time
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urlencode

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VT_API_BASE = "https://www.virustotal.com/api/v3"
VT_FREE_TIER_RPM = 4          # requests per minute on free tier
VT_FREE_TIER_DAILY = 500       # daily quota
VT_REQUEST_INTERVAL = 60 / VT_FREE_TIER_RPM  # 15 seconds between requests


class VirusTotalError(Exception):
    """Raised on non-recoverable VirusTotal API errors."""
    pass


class VirusTotalRateLimitError(VirusTotalError):
    """Raised when the rate limit is exceeded and retries are exhausted."""
    pass


class VirusTotalIntegration:
    """
    VirusTotal v3 API integration for ThreatFlow SOAR.

    Provides threat intelligence enrichment for file hashes, domains,
    IP addresses, and URLs with built-in rate limiting and retry logic.

    Usage:
        vt = VirusTotalIntegration(api_key="YOUR_VT_API_KEY")
        result = vt.check_file_hash("abc123...")
        verdict, score = vt.get_verdict(result)
    """

    def __init__(
        self,
        api_key: str,
        requests_per_minute: int = VT_FREE_TIER_RPM,
        max_retries: int = 3,
        timeout: int = 30,
    ) -> None:
        """
        Initialise the VirusTotal integration.

        Args:
            api_key: VirusTotal API key (v3).
            requests_per_minute: Rate limit cap. Defaults to free-tier 4 RPM.
            max_retries: Max retry attempts on transient errors.
            timeout: HTTP request timeout in seconds.
        """
        self.api_key = api_key
        self.rpm = requests_per_minute
        self.request_interval = 60.0 / requests_per_minute
        self.max_retries = max_retries
        self.timeout = timeout
        self._last_request_time: float = 0.0

        self.session = self._build_session()

    # ------------------------------------------------------------------
    # Session setup
    # ------------------------------------------------------------------

    def _build_session(self) -> requests.Session:
        """Build a requests.Session with retry logic and default headers."""
        session = requests.Session()
        retry_strategy = Retry(
            total=self.max_retries,
            status_forcelist=[429, 500, 502, 503, 504],
            backoff_factor=2,
            respect_retry_after_header=True,
            allowed_methods=["GET", "POST"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        session.headers.update({
            "x-apikey": self.api_key,
            "Accept": "application/json",
            "User-Agent": "ThreatFlow-SOAR/1.0 VirusTotalIntegration",
        })
        return session

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    def _wait_for_rate_limit(self) -> None:
        """Block until the per-request interval has elapsed."""
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < self.request_interval:
            wait_time = self.request_interval - elapsed
            logger.debug("VirusTotal rate-limit: sleeping %.2fs", wait_time)
            time.sleep(wait_time)

    def _get(self, endpoint: str, params: Optional[dict] = None) -> dict:
        """
        Perform a rate-limited, retried GET request.

        Args:
            endpoint: API endpoint path (e.g. '/files/{hash}').
            params: Optional query parameters.

        Returns:
            Parsed JSON response body.

        Raises:
            VirusTotalRateLimitError: If rate limit persists after retries.
            VirusTotalError: On other non-recoverable API errors.
        """
        self._wait_for_rate_limit()
        url = f"{VT_API_BASE}{endpoint}"

        try:
            self._last_request_time = time.monotonic()
            response = self.session.get(url, params=params, timeout=self.timeout)

            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 60))
                logger.warning("VT rate limit hit; backing off %ds", retry_after)
                time.sleep(retry_after)
                # One final retry after backing off
                self._last_request_time = time.monotonic()
                response = self.session.get(url, params=params, timeout=self.timeout)

            if response.status_code == 404:
                logger.info("VT: resource not found — %s", url)
                return {"error": "not_found", "data": None}

            if response.status_code == 401:
                raise VirusTotalError("Invalid or expired VirusTotal API key")

            response.raise_for_status()
            return response.json()

        except requests.exceptions.ConnectionError as exc:
            raise VirusTotalError(f"Connection failed: {exc}") from exc
        except requests.exceptions.Timeout as exc:
            raise VirusTotalError(f"Request timed out after {self.timeout}s") from exc
        except requests.exceptions.HTTPError as exc:
            raise VirusTotalError(f"HTTP error: {exc}") from exc

    def _post(self, endpoint: str, data: Optional[dict] = None, files: Optional[dict] = None) -> dict:
        """Perform a rate-limited POST request (used for URL submissions)."""
        self._wait_for_rate_limit()
        url = f"{VT_API_BASE}{endpoint}"
        try:
            self._last_request_time = time.monotonic()
            response = self.session.post(
                url, data=data, files=files, timeout=self.timeout
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as exc:
            raise VirusTotalError(f"HTTP error: {exc}") from exc

    # ------------------------------------------------------------------
    # Public API methods
    # ------------------------------------------------------------------

    def check_file_hash(self, hash_value: str) -> dict:
        """
        Look up a file hash (MD5, SHA1, or SHA256) in VirusTotal.

        Args:
            hash_value: The file hash to look up.

        Returns:
            Normalized result dict with keys:
                verdict, score, detections, total_engines, last_analysis_date,
                tags, file_name, file_type, file_size, raw_response
        """
        logger.info("VT hash lookup: %s", hash_value)
        raw = self._get(f"/files/{hash_value}")

        if raw.get("error") == "not_found" or not raw.get("data"):
            return self._not_found_response(ioc=hash_value, ioc_type="file_hash")

        return self._normalize_file_response(raw)

    def check_domain(self, domain: str) -> dict:
        """
        Look up a domain's reputation in VirusTotal.

        Args:
            domain: The domain to query (e.g. 'evil.example.com').

        Returns:
            Normalized result dict with keys:
                verdict, score, detections, total_engines, last_analysis_date,
                tags, categories, raw_response
        """
        logger.info("VT domain lookup: %s", domain)
        raw = self._get(f"/domains/{domain}")

        if raw.get("error") == "not_found" or not raw.get("data"):
            return self._not_found_response(ioc=domain, ioc_type="domain")

        return self._normalize_domain_ip_response(raw, ioc_type="domain")

    def check_ip(self, ip: str) -> dict:
        """
        Look up an IP address reputation in VirusTotal.

        Args:
            ip: The IPv4 or IPv6 address to query.

        Returns:
            Normalized result dict with keys:
                verdict, score, detections, total_engines, last_analysis_date,
                tags, country, asn, raw_response
        """
        logger.info("VT IP lookup: %s", ip)
        raw = self._get(f"/ip_addresses/{ip}")

        if raw.get("error") == "not_found" or not raw.get("data"):
            return self._not_found_response(ioc=ip, ioc_type="ip")

        return self._normalize_domain_ip_response(raw, ioc_type="ip")

    def check_url(self, url: str) -> dict:
        """
        Look up a URL in VirusTotal (submits for analysis then retrieves result).

        Args:
            url: The URL to check.

        Returns:
            Normalized result dict.
        """
        logger.info("VT URL lookup: %s", url)
        # VT v3 URL lookup uses base64url-encoded URL as ID
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        raw = self._get(f"/urls/{url_id}")

        if raw.get("error") == "not_found" or not raw.get("data"):
            # Submit for scanning and re-check
            logger.info("VT URL not in cache, submitting: %s", url)
            self._post("/urls", data={"url": url})
            time.sleep(15)  # Allow scan to complete
            raw = self._get(f"/urls/{url_id}")

        if not raw.get("data"):
            return self._not_found_response(ioc=url, ioc_type="url")

        return self._normalize_url_response(raw)

    def get_verdict(self, response: dict) -> tuple[str, int]:
        """
        Extract a simple (verdict, score) tuple from a normalized response.

        Args:
            response: Normalized dict returned by any check_* method.

        Returns:
            Tuple of (verdict_string, score_0_to_100):
                verdict: 'malicious' | 'suspicious' | 'harmless' | 'undetected' | 'unknown'
                score: integer 0-100
        """
        verdict = response.get("verdict", "unknown")
        score = response.get("score", 0)
        return verdict, int(score)

    # ------------------------------------------------------------------
    # Response normalization helpers
    # ------------------------------------------------------------------

    def _extract_analysis_stats(self, attributes: dict) -> tuple[int, int, int, int]:
        """Return (malicious, suspicious, harmless, undetected) counts."""
        stats = attributes.get("last_analysis_stats", {})
        return (
            stats.get("malicious", 0),
            stats.get("suspicious", 0),
            stats.get("harmless", 0),
            stats.get("undetected", 0),
        )

    def _calc_score(self, malicious: int, suspicious: int, total_engines: int) -> int:
        """
        Compute a 0-100 risk score from VT engine verdicts.

        Malicious detections are weighted 1.0, suspicious 0.4.
        Score = (weighted_hits / total_engines) * 100
        """
        if total_engines == 0:
            return 0
        weighted = malicious * 1.0 + suspicious * 0.4
        return min(int((weighted / total_engines) * 100), 100)

    def _determine_verdict(self, malicious: int, suspicious: int, total: int) -> str:
        """Classify the verdict based on hit counts."""
        if total == 0:
            return "unknown"
        if malicious >= 3:
            return "malicious"
        if malicious >= 1 or suspicious >= 5:
            return "suspicious"
        if suspicious >= 1:
            return "suspicious"
        return "harmless"

    def _parse_date(self, epoch: Optional[int]) -> Optional[str]:
        """Convert a Unix epoch timestamp to ISO 8601 string."""
        if epoch is None:
            return None
        try:
            return datetime.utcfromtimestamp(epoch).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (OSError, ValueError):
            return None

    def _normalize_file_response(self, raw: dict) -> dict:
        """Normalize a /files/{id} API response."""
        attrs = raw["data"].get("attributes", {})
        malicious, suspicious, harmless, undetected = self._extract_analysis_stats(attrs)
        total_engines = malicious + suspicious + harmless + undetected
        score = self._calc_score(malicious, suspicious, total_engines)
        verdict = self._determine_verdict(malicious, suspicious, total_engines)

        # Collect detecting engine names
        analysis_results = attrs.get("last_analysis_results", {})
        detections = [
            engine for engine, result in analysis_results.items()
            if result.get("category") in ("malicious", "suspicious")
        ]

        return {
            "ioc_type": "file_hash",
            "ioc_value": attrs.get("sha256") or raw["data"].get("id"),
            "verdict": verdict,
            "score": score,
            "detections": detections,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "total_engines": total_engines,
            "last_analysis_date": self._parse_date(attrs.get("last_analysis_date")),
            "tags": attrs.get("tags", []),
            "file_name": attrs.get("meaningful_name") or attrs.get("names", [None])[0],
            "file_type": attrs.get("type_description"),
            "file_size": attrs.get("size"),
            "magic": attrs.get("magic"),
            "threat_names": list({
                r.get("result") for r in analysis_results.values()
                if r.get("category") == "malicious" and r.get("result")
            }),
            "raw_response": raw,
        }

    def _normalize_domain_ip_response(self, raw: dict, ioc_type: str) -> dict:
        """Normalize a /domains/{d} or /ip_addresses/{ip} API response."""
        attrs = raw["data"].get("attributes", {})
        malicious, suspicious, harmless, undetected = self._extract_analysis_stats(attrs)
        total_engines = malicious + suspicious + harmless + undetected
        score = self._calc_score(malicious, suspicious, total_engines)
        verdict = self._determine_verdict(malicious, suspicious, total_engines)

        result = {
            "ioc_type": ioc_type,
            "ioc_value": raw["data"].get("id"),
            "verdict": verdict,
            "score": score,
            "detections": [],
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "total_engines": total_engines,
            "last_analysis_date": self._parse_date(attrs.get("last_analysis_date")),
            "tags": attrs.get("tags", []),
            "categories": attrs.get("categories", {}),
            "raw_response": raw,
        }

        if ioc_type == "ip":
            result["country"] = attrs.get("country")
            result["asn"] = attrs.get("asn")
            result["as_owner"] = attrs.get("as_owner")
            result["regional_internet_registry"] = attrs.get("regional_internet_registry")

        if ioc_type == "domain":
            result["registrar"] = attrs.get("registrar")
            result["creation_date"] = self._parse_date(attrs.get("creation_date"))
            result["whois"] = attrs.get("whois", "")[:500]  # Truncate for log safety

        return result

    def _normalize_url_response(self, raw: dict) -> dict:
        """Normalize a /urls/{id} API response."""
        attrs = raw["data"].get("attributes", {})
        malicious, suspicious, harmless, undetected = self._extract_analysis_stats(attrs)
        total_engines = malicious + suspicious + harmless + undetected
        score = self._calc_score(malicious, suspicious, total_engines)
        verdict = self._determine_verdict(malicious, suspicious, total_engines)

        return {
            "ioc_type": "url",
            "ioc_value": attrs.get("url"),
            "verdict": verdict,
            "score": score,
            "detections": [],
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "total_engines": total_engines,
            "last_analysis_date": self._parse_date(attrs.get("last_analysis_date")),
            "tags": attrs.get("tags", []),
            "final_url": attrs.get("last_final_url"),
            "title": attrs.get("title"),
            "raw_response": raw,
        }

    def _not_found_response(self, ioc: str, ioc_type: str) -> dict:
        """Return a normalised 'not found' result for unknown IOCs."""
        return {
            "ioc_type": ioc_type,
            "ioc_value": ioc,
            "verdict": "undetected",
            "score": 0,
            "detections": [],
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_engines": 0,
            "last_analysis_date": None,
            "tags": [],
            "raw_response": {"error": "not_found"},
        }


# ---------------------------------------------------------------------------
# CLI helper (for manual testing / Shuffle script-node compatibility)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import os
    import sys
    import json

    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        sys.exit("ERROR: VIRUSTOTAL_API_KEY environment variable not set")

    vt = VirusTotalIntegration(api_key=api_key)

    if len(sys.argv) < 3:
        print("Usage: python virustotal_integration.py <hash|domain|ip|url> <value>")
        sys.exit(1)

    ioc_type, ioc_value = sys.argv[1], sys.argv[2]
    dispatch = {
        "hash": vt.check_file_hash,
        "domain": vt.check_domain,
        "ip": vt.check_ip,
        "url": vt.check_url,
    }

    if ioc_type not in dispatch:
        sys.exit(f"ERROR: Unknown IOC type '{ioc_type}'. Choose from: {', '.join(dispatch)}")

    result = dispatch[ioc_type](ioc_value)
    verdict, score = vt.get_verdict(result)
    print(f"Verdict: {verdict} | Score: {score}/100")
    print(json.dumps(result, indent=2, default=str))

"""
ThreatFlow SOAR - AbuseIPDB Integration
=========================================
Full-featured AbuseIPDB v2 API client with rate limiting, retry logic,
error handling, and normalized response format for use in Shuffle SOAR
phishing response workflows.

Author: ThreatFlow SOC Automation
Version: 1.0.0
"""

from __future__ import annotations

import logging
import time
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ABUSEIPDB_API_BASE = "https://api.abuseipdb.com/api/v2"
ABUSEIPDB_FREE_TIER_DAILY = 1000       # requests per day on free tier
ABUSEIPDB_REQUEST_INTERVAL = 1.2       # min seconds between requests (safe default)

# Known Tor exit-node list endpoint (crowd-sourced; AbuseIPDB usage_type also flags it)
TOR_CATEGORY_ID = 9  # AbuseIPDB category 9 = "Open Proxy"


class AbuseIPDBError(Exception):
    """Raised on non-recoverable AbuseIPDB API errors."""
    pass


class AbuseIPDBRateLimitError(AbuseIPDBError):
    """Raised when rate limit is exceeded and retries exhausted."""
    pass


class AbuseIPDBIntegration:
    """
    AbuseIPDB v2 API integration for ThreatFlow SOAR.

    Provides threat intelligence enrichment for IP addresses, including
    abuse confidence scores, geolocation, ISP data, and Tor exit-node
    detection.

    Usage:
        aipdb = AbuseIPDBIntegration(api_key="YOUR_ABUSEIPDB_KEY")
        result = aipdb.check_ip("198.51.100.42")
        score = aipdb.get_risk_score(result)
        is_tor = aipdb.is_tor_exit_node("198.51.100.42")
    """

    def __init__(
        self,
        api_key: str,
        max_retries: int = 3,
        timeout: int = 20,
        request_interval: float = ABUSEIPDB_REQUEST_INTERVAL,
    ) -> None:
        """
        Initialise the AbuseIPDB integration.

        Args:
            api_key: AbuseIPDB API key (v2).
            max_retries: Max retry attempts on transient HTTP errors.
            timeout: HTTP request timeout in seconds.
            request_interval: Minimum seconds between successive requests.
        """
        self.api_key = api_key
        self.max_retries = max_retries
        self.timeout = timeout
        self.request_interval = request_interval
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
            allowed_methods=["GET"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        session.headers.update({
            "Key": self.api_key,
            "Accept": "application/json",
            "User-Agent": "ThreatFlow-SOAR/1.0 AbuseIPDBIntegration",
        })
        return session

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    def _wait_for_rate_limit(self) -> None:
        """Block until the minimum request interval has elapsed."""
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < self.request_interval:
            wait = self.request_interval - elapsed
            logger.debug("AbuseIPDB rate-limit: sleeping %.2fs", wait)
            time.sleep(wait)

    def _get(self, endpoint: str, params: dict) -> dict:
        """
        Perform a rate-limited, retried GET request.

        Args:
            endpoint: API path (e.g. '/check').
            params: Query parameters dict.

        Returns:
            Parsed JSON response body.

        Raises:
            AbuseIPDBRateLimitError: If 429 persists after backoff.
            AbuseIPDBError: On non-recoverable API errors.
        """
        self._wait_for_rate_limit()
        url = f"{ABUSEIPDB_API_BASE}{endpoint}"

        try:
            self._last_request_time = time.monotonic()
            response = self.session.get(url, params=params, timeout=self.timeout)

            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 60))
                logger.warning("AbuseIPDB rate limit hit; waiting %ds", retry_after)
                time.sleep(retry_after)
                self._last_request_time = time.monotonic()
                response = self.session.get(url, params=params, timeout=self.timeout)
                if response.status_code == 429:
                    raise AbuseIPDBRateLimitError("AbuseIPDB rate limit persists after backoff")

            if response.status_code == 401:
                raise AbuseIPDBError("Invalid or missing AbuseIPDB API key")

            if response.status_code == 422:
                error_detail = response.json().get("errors", [{}])
                raise AbuseIPDBError(f"AbuseIPDB validation error: {error_detail}")

            response.raise_for_status()
            return response.json()

        except requests.exceptions.ConnectionError as exc:
            raise AbuseIPDBError(f"Connection failed: {exc}") from exc
        except requests.exceptions.Timeout as exc:
            raise AbuseIPDBError(f"Request timed out after {self.timeout}s") from exc
        except requests.exceptions.HTTPError as exc:
            raise AbuseIPDBError(f"HTTP error: {exc}") from exc

    # ------------------------------------------------------------------
    # Public API methods
    # ------------------------------------------------------------------

    def check_ip(self, ip: str, max_age_days: int = 90) -> dict:
        """
        Query AbuseIPDB for IP reputation data.

        Args:
            ip: IPv4 or IPv6 address to check.
            max_age_days: Look back window for reports (1-365). Default 90.

        Returns:
            Normalized dict with keys:
                ip, abuse_score (0-100), country, country_code,
                isp, domain, usage_type, is_tor, is_public,
                reports_count, last_reported_at, hostnames,
                distinct_users, raw_response

        Raises:
            AbuseIPDBError: On API or connectivity failure.
        """
        logger.info("AbuseIPDB IP check: %s (max_age=%d days)", ip, max_age_days)

        # Clamp max_age_days within allowed bounds
        max_age_days = max(1, min(max_age_days, 365))

        params = {
            "ipAddress": ip,
            "maxAgeInDays": str(max_age_days),
            "verbose": "",       # verbose mode returns reports[] array
        }

        raw = self._get("/check", params)
        return self._normalize_response(raw, ip)

    def get_risk_score(self, response: dict) -> int:
        """
        Extract the AbuseIPDB confidence score from a normalized response.

        Args:
            response: Normalized dict returned by check_ip().

        Returns:
            Integer abuse confidence score 0-100.
        """
        return int(response.get("abuse_score", 0))

    def is_tor_exit_node(self, ip: str) -> bool:
        """
        Determine whether an IP is a known Tor exit node.

        Uses two detection methods:
        1. AbuseIPDB usage_type == 'Tor Proxy'
        2. AbuseIPDB report categories containing category 9 (Open Proxy)

        Args:
            ip: IPv4 or IPv6 address to check.

        Returns:
            True if the IP is detected as a Tor exit node.
        """
        logger.info("AbuseIPDB Tor exit node check: %s", ip)
        try:
            result = self.check_ip(ip, max_age_days=30)
        except AbuseIPDBError as exc:
            logger.error("AbuseIPDB Tor check failed for %s: %s", ip, exc)
            return False

        # Method 1: usage_type field
        usage_type = (result.get("usage_type") or "").lower()
        if any(t in usage_type for t in ("tor", "anonymous")):
            logger.info("IP %s flagged as Tor by usage_type: %s", ip, usage_type)
            return True

        # Method 2: Check if Open Proxy category appears in reports
        raw_reports = (
            result.get("raw_response", {})
                  .get("data", {})
                  .get("reports", [])
        )
        for report in raw_reports:
            if TOR_CATEGORY_ID in report.get("categories", []):
                logger.info("IP %s flagged as Tor by report category 9", ip)
                return True

        return False

    def check_ip_bulk(self, ips: list[str], max_age_days: int = 90) -> dict[str, dict]:
        """
        Check multiple IPs sequentially with rate limiting.

        Args:
            ips: List of IP address strings.
            max_age_days: Lookback window for all checks.

        Returns:
            Dict mapping each IP → normalized result.
        """
        results: dict[str, dict] = {}
        for ip in ips:
            try:
                results[ip] = self.check_ip(ip, max_age_days=max_age_days)
            except AbuseIPDBError as exc:
                logger.error("AbuseIPDB bulk check failed for %s: %s", ip, exc)
                results[ip] = self._error_response(ip, str(exc))
        return results

    # ------------------------------------------------------------------
    # Response normalization
    # ------------------------------------------------------------------

    def _normalize_response(self, raw: dict, ip: str) -> dict:
        """
        Normalize an AbuseIPDB /check response into a consistent schema.

        Args:
            raw: Raw JSON response from the API.
            ip: Original IP queried (used as fallback if data is absent).

        Returns:
            Normalized dict with standardized keys.
        """
        data = raw.get("data", {})

        if not data:
            logger.warning("AbuseIPDB returned empty data for IP: %s", ip)
            return self._error_response(ip, "empty_response")

        abuse_score = int(data.get("abuseConfidenceScore", 0))

        # Determine if Tor from usage_type
        usage_type = data.get("usageType", "")
        is_tor = any(t in (usage_type or "").lower() for t in ("tor", "anonymous"))

        # Build hostnames list
        hostnames = data.get("hostnames", []) or []

        return {
            "ip": data.get("ipAddress", ip),
            "abuse_score": abuse_score,
            "country": data.get("countryName"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "usage_type": usage_type,
            "is_tor": is_tor,
            "is_public": bool(data.get("isPublic", True)),
            "is_whitelisted": bool(data.get("isWhitelisted", False)),
            "reports_count": int(data.get("totalReports", 0)),
            "distinct_users": int(data.get("numDistinctUsers", 0)),
            "last_reported_at": data.get("lastReportedAt"),
            "hostnames": hostnames,
            "risk_tier": self._score_to_tier(abuse_score),
            "raw_response": raw,
        }

    def _score_to_tier(self, score: int) -> str:
        """Map an abuse score to a human-readable risk tier."""
        if score >= 90:
            return "CRITICAL"
        if score >= 70:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        if score >= 10:
            return "LOW"
        return "INFO"

    def _error_response(self, ip: str, error: str) -> dict:
        """Return a safe default response on error."""
        return {
            "ip": ip,
            "abuse_score": 0,
            "country": None,
            "country_code": None,
            "isp": None,
            "domain": None,
            "usage_type": None,
            "is_tor": False,
            "is_public": True,
            "is_whitelisted": False,
            "reports_count": 0,
            "distinct_users": 0,
            "last_reported_at": None,
            "hostnames": [],
            "risk_tier": "INFO",
            "raw_response": {"error": error},
        }


# ---------------------------------------------------------------------------
# CLI helper (for manual testing / Shuffle script-node compatibility)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import os
    import sys
    import json

    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        sys.exit("ERROR: ABUSEIPDB_API_KEY environment variable not set")

    if len(sys.argv) < 2:
        print("Usage: python abuseipdb_integration.py <ip_address> [--tor]")
        sys.exit(1)

    target_ip = sys.argv[1]
    check_tor = "--tor" in sys.argv

    client = AbuseIPDBIntegration(api_key=api_key)

    if check_tor:
        is_tor_node = client.is_tor_exit_node(target_ip)
        print(f"Is Tor Exit Node: {is_tor_node}")
    else:
        result = client.check_ip(target_ip)
        risk_score = client.get_risk_score(result)
        print(f"IP: {result['ip']}")
        print(f"Abuse Score: {risk_score}/100 ({result['risk_tier']})")
        print(f"Country: {result['country']} ({result['country_code']})")
        print(f"ISP: {result['isp']}")
        print(f"Usage Type: {result['usage_type']}")
        print(f"Is Tor: {result['is_tor']}")
        print(f"Reports (90d): {result['reports_count']} from {result['distinct_users']} users")
        print()
        print(json.dumps(result, indent=2, default=str))

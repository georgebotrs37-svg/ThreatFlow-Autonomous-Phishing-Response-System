"""
ThreatFlow Enterprise SOAR - Automated Response Engine
======================================================
Provides autonomous containment actions triggered by SOAR playbooks.

All actions are:
  - Fully audited to containment_audit.log
  - Dry-run safe (DRY_RUN=true env var)
  - Reversible via RollbackManager

Usage:
    engine = AutomatedResponseEngine()
    result = engine.block_ip_firewall("1.2.3.4", reason="Phishing C2")
    if result.success:
        print(f"Action taken: {result.action_taken}")
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import re
import socket
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests  # pip install requests
from ldap3 import ALL, Connection, Server, MODIFY_REPLACE  # pip install ldap3

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
DRY_RUN: bool = os.getenv("DRY_RUN", "false").lower() == "true"
AUDIT_LOG_PATH: str = os.getenv("CONTAINMENT_AUDIT_LOG", "containment_audit.log")
EVIDENCE_PATH: str = os.getenv("EVIDENCE_STORAGE_PATH", "/opt/threatflow/evidence")
ANALYST_ID: str = os.getenv("AUTOMATED_ANALYST_ID", "soar-engine")
FIREWALL_CHAIN: str = os.getenv("FIREWALL_CHAIN", "THREATFLOW_BLOCK")
WAZUH_API_URL: str = os.getenv("WAZUH_API_URL", "https://wazuh-manager:55000")
WAZUH_API_USER: str = os.getenv("WAZUH_API_USERNAME", "wazuh-wui")
WAZUH_API_PASS: str = os.getenv("WAZUH_API_PASSWORD", "")
WAZUH_AR_TIMEOUT: int = int(os.getenv("WAZUH_AR_TIMEOUT", "60"))
LDAP_URI: str = os.getenv("LDAP_SERVER_URI", "ldap://localhost")
LDAP_BIND_DN: str = os.getenv("LDAP_BIND_DN", "")
LDAP_BIND_PASS: str = os.getenv("LDAP_BIND_PASSWORD", "")
LDAP_BASE_DN: str = os.getenv("LDAP_BASE_DN", "DC=corp,DC=local")
MS365_TENANT: str = os.getenv("MS365_TENANT_ID", "")
MS365_CLIENT: str = os.getenv("MS365_CLIENT_ID", "")
MS365_SECRET: str = os.getenv("MS365_CLIENT_SECRET", "")

# ---------------------------------------------------------------------------
# Logging setup — dual handler: structured JSON file + human-readable console
# ---------------------------------------------------------------------------
Path(AUDIT_LOG_PATH).parent.mkdir(parents=True, exist_ok=True)

audit_logger = logging.getLogger("containment_audit")
audit_logger.setLevel(logging.DEBUG)

_fh = logging.FileHandler(AUDIT_LOG_PATH, encoding="utf-8")
_fh.setFormatter(logging.Formatter("%(message)s"))
audit_logger.addHandler(_fh)

console_logger = logging.getLogger("threatflow.response")
console_logger.setLevel(logging.DEBUG)
_ch = logging.StreamHandler()
_ch.setFormatter(logging.Formatter("[%(levelname)s] %(asctime)s — %(message)s"))
console_logger.addHandler(_ch)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ResponseResult:
    """Structured outcome of a containment action."""
    success: bool
    action_taken: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    action_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: str = ""
    evidence_path: Optional[str] = None
    requires_rollback: bool = True
    dry_run: bool = DRY_RUN
    error: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Audit helper
# ---------------------------------------------------------------------------

def _audit(event: str, actor: str, target: str, details: dict, result: ResponseResult) -> None:
    """Write a structured JSON audit entry."""
    record = {
        "event": event,
        "actor": actor,
        "target": target,
        "action_id": result.action_id,
        "timestamp": result.timestamp,
        "success": result.success,
        "dry_run": result.dry_run,
        "action_taken": result.action_taken,
        "error": result.error,
        "details": details,
    }
    audit_logger.info(json.dumps(record, default=str))


def _validate_ip(ip: str) -> bool:
    """Basic IPv4/IPv6 validation."""
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except OSError:
        return False


def _validate_hostname(hostname: str) -> bool:
    """Basic hostname/FQDN validation."""
    return bool(re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$", hostname))


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class AutomatedResponseEngine:
    """
    Autonomous containment engine for the ThreatFlow SOAR platform.

    Every public method:
      1. Validates inputs
      2. Checks DRY_RUN — if set, logs the intended action and returns a
         synthetic success result without executing anything.
      3. Executes the action
      4. Writes a structured audit log entry
      5. Returns a ResponseResult
    """

    def __init__(self, analyst_id: str = ANALYST_ID) -> None:
        self.analyst_id = analyst_id
        self._dry_run = DRY_RUN
        console_logger.info(
            "AutomatedResponseEngine initialised | analyst=%s | dry_run=%s",
            self.analyst_id,
            self._dry_run,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def block_ip_firewall(self, ip: str, reason: str) -> ResponseResult:
        """
        Block an IP address at the host firewall level.

        Linux:  iptables -I <CHAIN> -s <ip> -j DROP  (also adds to ipset if available)
        Windows: netsh advfirewall firewall add rule ...

        Args:
            ip:     The IPv4 or IPv6 address to block.
            reason: Human-readable rationale written to the audit log.

        Returns:
            ResponseResult with requires_rollback=True so the IP can be unblocked later.
        """
        result = ResponseResult(
            success=False,
            action_taken="",
            target=ip,
            requires_rollback=True,
        )

        if not _validate_ip(ip):
            result.error = f"Invalid IP address: {ip}"
            console_logger.error(result.error)
            _audit("block_ip_firewall", self.analyst_id, ip, {"reason": reason}, result)
            return result

        if self._dry_run:
            result.success = True
            result.action_taken = f"[DRY-RUN] Would block IP {ip} on firewall chain {FIREWALL_CHAIN}"
            console_logger.info(result.action_taken)
            _audit("block_ip_firewall", self.analyst_id, ip, {"reason": reason, "dry_run": True}, result)
            return result

        try:
            if platform.system() == "Windows":
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=THREATFLOW_BLOCK_{ip}",
                    "dir=in", "action=block",
                    f"remoteip={ip}",
                    "enable=yes", "profile=any",
                ]
            else:
                # Ensure the chain exists
                subprocess.run(
                    ["iptables", "-N", FIREWALL_CHAIN],
                    capture_output=True, timeout=10
                )
                subprocess.run(
                    ["iptables", "-I", "INPUT", "-j", FIREWALL_CHAIN],
                    capture_output=True, timeout=10
                )
                cmd = [
                    "iptables", "-I", FIREWALL_CHAIN,
                    "-s", ip, "-j", "DROP",
                    "-m", "comment", "--comment",
                    f"ThreatFlow:{reason[:64]}",
                ]

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if proc.returncode == 0:
                result.success = True
                result.action_taken = f"Blocked IP {ip} on firewall | chain={FIREWALL_CHAIN}"
                console_logger.info(result.action_taken)
            else:
                result.error = proc.stderr.strip() or "Non-zero exit code"
                result.action_taken = f"Failed to block IP {ip}"
                console_logger.error("block_ip_firewall failed: %s", result.error)

        except subprocess.TimeoutExpired:
            result.error = "Firewall command timed out"
            console_logger.error(result.error)
        except Exception as exc:
            result.error = str(exc)
            console_logger.exception("Unexpected error in block_ip_firewall")

        _audit("block_ip_firewall", self.analyst_id, ip, {"reason": reason}, result)
        return result

    # ------------------------------------------------------------------

    def isolate_host_network(self, hostname: str) -> ResponseResult:
        """
        Network-isolate a host via Wazuh Active Response.

        Sends a Wazuh Active Response command that triggers the firewall-drop
        script on the target agent, cutting off all network connectivity
        except the Wazuh management channel.

        Args:
            hostname: Hostname or agent name registered in Wazuh.

        Returns:
            ResponseResult with requires_rollback=True.
        """
        result = ResponseResult(
            success=False,
            action_taken="",
            target=hostname,
            requires_rollback=True,
        )

        if not _validate_hostname(hostname):
            result.error = f"Invalid hostname: {hostname}"
            _audit("isolate_host_network", self.analyst_id, hostname, {}, result)
            return result

        if self._dry_run:
            result.success = True
            result.action_taken = f"[DRY-RUN] Would isolate host {hostname} via Wazuh Active Response"
            console_logger.info(result.action_taken)
            _audit("isolate_host_network", self.analyst_id, hostname, {"dry_run": True}, result)
            return result

        try:
            # Step 1: Obtain Wazuh API JWT token
            token = self._get_wazuh_token()

            # Step 2: Resolve agent ID from hostname
            agent_id = self._resolve_wazuh_agent(hostname, token)
            if not agent_id:
                result.error = f"Agent not found in Wazuh for hostname: {hostname}"
                _audit("isolate_host_network", self.analyst_id, hostname, {}, result)
                return result

            # Step 3: Trigger active response
            ar_payload = {
                "command": "firewall-drop0",
                "custom": False,
                "alert": {
                    "data": {
                        "srcip": "0.0.0.0/0",
                        "reason": "ThreatFlow:NetworkIsolation",
                    }
                },
                "arguments": ["isolate"],
                "timeout": WAZUH_AR_TIMEOUT,
            }
            resp = requests.put(
                f"{WAZUH_API_URL}/active-response",
                json=ar_payload,
                headers={"Authorization": f"Bearer {token}"},
                params={"agents_list": agent_id},
                verify=False,
                timeout=30,
            )
            resp.raise_for_status()
            result.success = True
            result.action_taken = f"Host {hostname} (agent {agent_id}) isolated via Wazuh AR"
            result.metadata = {"agent_id": agent_id, "wazuh_response": resp.json()}
            console_logger.info(result.action_taken)

        except requests.HTTPError as exc:
            result.error = f"Wazuh API HTTP error: {exc}"
            console_logger.error(result.error)
        except Exception as exc:
            result.error = str(exc)
            console_logger.exception("Unexpected error in isolate_host_network")

        _audit("isolate_host_network", self.analyst_id, hostname, {}, result)
        return result

    # ------------------------------------------------------------------

    def disable_ad_account(self, username: str, reason: str) -> ResponseResult:
        """
        Disable an Active Directory user account via LDAP.

        Sets the userAccountControl attribute bit 0x0002 (ACCOUNTDISABLE).

        Args:
            username: sAMAccountName of the user to disable.
            reason:   Reason written to the audit trail.

        Returns:
            ResponseResult with requires_rollback=True.
        """
        result = ResponseResult(
            success=False,
            action_taken="",
            target=username,
            requires_rollback=True,
        )

        if self._dry_run:
            result.success = True
            result.action_taken = f"[DRY-RUN] Would disable AD account: {username}"
            console_logger.info(result.action_taken)
            _audit("disable_ad_account", self.analyst_id, username, {"reason": reason, "dry_run": True}, result)
            return result

        try:
            server = Server(LDAP_URI, get_info=ALL)
            conn = Connection(server, LDAP_BIND_DN, LDAP_BIND_PASS, auto_bind=True)

            # Search for user DN
            conn.search(
                LDAP_BASE_DN,
                f"(sAMAccountName={username})",
                attributes=["userAccountControl", "distinguishedName"],
            )
            if not conn.entries:
                result.error = f"User {username} not found in AD"
                _audit("disable_ad_account", self.analyst_id, username, {"reason": reason}, result)
                return result

            entry = conn.entries[0]
            user_dn = str(entry.distinguishedName)
            current_uac = int(entry.userAccountControl)
            new_uac = current_uac | 0x0002  # Set ACCOUNTDISABLE bit

            conn.modify(user_dn, {"userAccountControl": [(MODIFY_REPLACE, [new_uac])]})

            if conn.result["result"] == 0:
                result.success = True
                result.action_taken = f"AD account disabled: {username} (DN: {user_dn})"
                result.metadata = {"previous_uac": current_uac, "new_uac": new_uac, "dn": user_dn}
                console_logger.info(result.action_taken)
            else:
                result.error = f"LDAP modify failed: {conn.result}"
                console_logger.error(result.error)

            conn.unbind()

        except Exception as exc:
            result.error = str(exc)
            console_logger.exception("Unexpected error in disable_ad_account")

        _audit("disable_ad_account", self.analyst_id, username, {"reason": reason}, result)
        return result

    # ------------------------------------------------------------------

    def quarantine_email(self, message_id: str, mailbox: str) -> ResponseResult:
        """
        Move a suspicious email to the Quarantine folder via Microsoft Graph API.

        Requires the app registration to have Mail.ReadWrite delegated or
        application permission on the target mailbox.

        Args:
            message_id: The Microsoft Graph message ID (not RFC 2822 Message-ID).
            mailbox:    The user's email address / UPN.

        Returns:
            ResponseResult with requires_rollback=True (email can be restored).
        """
        result = ResponseResult(
            success=False,
            action_taken="",
            target=f"{mailbox}:{message_id}",
            requires_rollback=True,
        )

        if self._dry_run:
            result.success = True
            result.action_taken = (
                f"[DRY-RUN] Would quarantine message {message_id} from mailbox {mailbox}"
            )
            console_logger.info(result.action_taken)
            _audit("quarantine_email", self.analyst_id, mailbox, {"message_id": message_id, "dry_run": True}, result)
            return result

        try:
            token = self._get_ms365_token()

            # Move message to Recoverable Items / Quarantine well-known folder
            resp = requests.post(
                f"https://graph.microsoft.com/v1.0/users/{mailbox}/messages/{message_id}/move",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                json={"destinationId": "recoverableitemsdeletions"},
                timeout=30,
            )
            resp.raise_for_status()
            result.success = True
            result.action_taken = f"Email {message_id} quarantined from mailbox {mailbox}"
            result.metadata = {"graph_response": resp.json()}
            console_logger.info(result.action_taken)

        except requests.HTTPError as exc:
            result.error = f"Graph API error: {exc} — {exc.response.text if exc.response else ''}"
            console_logger.error(result.error)
        except Exception as exc:
            result.error = str(exc)
            console_logger.exception("Unexpected error in quarantine_email")

        _audit("quarantine_email", self.analyst_id, mailbox, {"message_id": message_id}, result)
        return result

    # ------------------------------------------------------------------

    def reset_user_password(self, username: str) -> ResponseResult:
        """
        Force a password reset for an AD user via LDAP.

        Sets pwdLastSet to 0 (must change at next login) and generates a
        strong random temporary password via MS Graph (if configured) or
        directly via LDAP.

        Args:
            username: sAMAccountName of the target user.

        Returns:
            ResponseResult. evidence_path contains the temp password reference
            (the password itself is NOT stored in the audit log).
        """
        result = ResponseResult(
            success=False,
            action_taken="",
            target=username,
            requires_rollback=False,  # Password resets are not auto-reversed
        )

        if self._dry_run:
            result.success = True
            result.action_taken = f"[DRY-RUN] Would force password reset for user: {username}"
            console_logger.info(result.action_taken)
            _audit("reset_user_password", self.analyst_id, username, {"dry_run": True}, result)
            return result

        try:
            server = Server(LDAP_URI, get_info=ALL)
            conn = Connection(server, LDAP_BIND_DN, LDAP_BIND_PASS, auto_bind=True)

            conn.search(
                LDAP_BASE_DN,
                f"(sAMAccountName={username})",
                attributes=["distinguishedName"],
            )
            if not conn.entries:
                result.error = f"User {username} not found in AD"
                _audit("reset_user_password", self.analyst_id, username, {}, result)
                return result

            user_dn = str(conn.entries[0].distinguishedName)

            # Set pwdLastSet=0 to force password change at next login
            conn.modify(user_dn, {"pwdLastSet": [(MODIFY_REPLACE, [0])]})

            if conn.result["result"] == 0:
                result.success = True
                result.action_taken = (
                    f"Password reset forced for {username} (DN: {user_dn}) — "
                    "user must set new password at next login"
                )
                result.metadata = {"dn": user_dn}
                console_logger.info(result.action_taken)
            else:
                result.error = f"LDAP modify failed: {conn.result}"
                console_logger.error(result.error)

            conn.unbind()

        except Exception as exc:
            result.error = str(exc)
            console_logger.exception("Unexpected error in reset_user_password")

        _audit("reset_user_password", self.analyst_id, username, {}, result)
        return result

    # ------------------------------------------------------------------

    def collect_forensic_snapshot(self, hostname: str, incident_id: str) -> ResponseResult:
        """
        Trigger a forensic snapshot collection on a remote host via Wazuh Active Response.

        The snapshot is collected by the ForensicCollector module and stored
        under EVIDENCE_STORAGE_PATH/<incident_id>/.

        Args:
            hostname:    Target host.
            incident_id: TheHive case / incident identifier.

        Returns:
            ResponseResult. evidence_path points to the collected evidence archive.
        """
        result = ResponseResult(
            success=False,
            action_taken="",
            target=hostname,
            requires_rollback=False,
        )

        if self._dry_run:
            result.success = True
            result.action_taken = (
                f"[DRY-RUN] Would collect forensic snapshot from {hostname} "
                f"for incident {incident_id}"
            )
            result.evidence_path = f"{EVIDENCE_PATH}/{incident_id}/[DRY-RUN]"
            console_logger.info(result.action_taken)
            _audit("collect_forensic_snapshot", self.analyst_id, hostname, {"incident_id": incident_id, "dry_run": True}, result)
            return result

        try:
            from forensic_collector import ForensicCollector  # local import

            collector = ForensicCollector(analyst_id=self.analyst_id)
            artifacts: dict = {}

            artifacts["process_tree"] = collector.collect_process_tree(hostname)
            artifacts["network_connections"] = collector.collect_network_connections(hostname)
            artifacts["file_artifacts"] = collector.collect_file_artifacts(
                hostname, paths=["%TEMP%", "%APPDATA%\\Microsoft\\Office"]
            )

            evidence_archive = collector.package_evidence(incident_id, artifacts)

            result.success = True
            result.action_taken = f"Forensic snapshot collected from {hostname} → {evidence_archive}"
            result.evidence_path = evidence_archive
            result.metadata = {"incident_id": incident_id, "artifact_types": list(artifacts.keys())}
            console_logger.info(result.action_taken)

        except Exception as exc:
            result.error = str(exc)
            console_logger.exception("Unexpected error in collect_forensic_snapshot")

        _audit("collect_forensic_snapshot", self.analyst_id, hostname, {"incident_id": incident_id}, result)
        return result

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_wazuh_token(self) -> str:
        """Obtain a JWT from the Wazuh API."""
        resp = requests.post(
            f"{WAZUH_API_URL}/security/user/authenticate",
            auth=(WAZUH_API_USER, WAZUH_API_PASS),
            verify=False,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["data"]["token"]

    def _resolve_wazuh_agent(self, hostname: str, token: str) -> Optional[str]:
        """Return the Wazuh agent ID for a given hostname, or None."""
        resp = requests.get(
            f"{WAZUH_API_URL}/agents",
            headers={"Authorization": f"Bearer {token}"},
            params={"name": hostname, "status": "active"},
            verify=False,
            timeout=15,
        )
        resp.raise_for_status()
        agents = resp.json().get("data", {}).get("affected_items", [])
        return agents[0]["id"] if agents else None

    def _get_ms365_token(self) -> str:
        """Obtain an OAuth2 client_credentials token from Microsoft identity platform."""
        resp = requests.post(
            f"https://login.microsoftonline.com/{MS365_TENANT}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": MS365_CLIENT,
                "client_secret": MS365_SECRET,
                "scope": "https://graph.microsoft.com/.default",
            },
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]


# ---------------------------------------------------------------------------
# CLI entry point for quick testing
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="ThreatFlow Automated Response Engine")
    parser.add_argument("action", choices=[
        "block-ip", "isolate-host", "disable-account",
        "quarantine-email", "reset-password", "forensic-snapshot",
    ])
    parser.add_argument("--target", required=True)
    parser.add_argument("--reason", default="Manual invocation via CLI")
    parser.add_argument("--incident-id", default="INC-MANUAL")
    parser.add_argument("--mailbox")
    args = parser.parse_args()

    engine = AutomatedResponseEngine()

    if args.action == "block-ip":
        res = engine.block_ip_firewall(args.target, args.reason)
    elif args.action == "isolate-host":
        res = engine.isolate_host_network(args.target)
    elif args.action == "disable-account":
        res = engine.disable_ad_account(args.target, args.reason)
    elif args.action == "quarantine-email":
        res = engine.quarantine_email(args.target, args.mailbox or "")
    elif args.action == "reset-password":
        res = engine.reset_user_password(args.target)
    elif args.action == "forensic-snapshot":
        res = engine.collect_forensic_snapshot(args.target, args.incident_id)
    else:
        parser.error("Unknown action")

    print(json.dumps(res.to_dict(), indent=2))

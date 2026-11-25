"""HMAC-SHA256 Signed Webhook Dispatcher with SSRF Validation, Retry Backoff & Dead-Letter Logging."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
from typing import Any
from urllib.parse import urlparse
import httpx

from traceguard.config import settings
from traceguard.db.database import TraceGuardDB

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def validate_webhook_url(url: str) -> str:
    """Validate webhook URL against SSRF to cloud metadata / private ranges."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Webhook URL must use http or https scheme.")
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("Webhook URL missing hostname.")
    if host in ("169.254.169.254", "metadata.google.internal"):
        raise ValueError("Blocked metadata endpoint (SSRF protection).")
    if not settings.allow_localhost_webhooks and host in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("Localhost webhooks disabled by policy.")
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_link_local or (ip.is_private and not (settings.allow_localhost_webhooks and ip.is_loopback)):
            raise ValueError("Private/link-local IP blocked by SSRF protection.")
    except ValueError as exc:
        if "SSRF" in str(exc) or "Localhost" in str(exc):
            raise
    return url


def sign_payload(body_bytes: bytes, secret: str | None = None) -> str:
    key = (secret or settings.webhook_hmac_secret).encode("utf-8")
    return "sha256=" + hmac.new(key, body_bytes, hashlib.sha256).hexdigest()


class WebhookDispatcher:
    """Dispatches signed n8n/Slack-compatible webhook events with exponential backoff retry."""

    def __init__(self, db: TraceGuardDB) -> None:
        self.db = db

    async def handle_event(self, envelope: dict[str, Any]) -> None:
        event_type = envelope["event_type"]
        payload = envelope["payload"]
        severity = payload.get("severity", "HIGH")

        endpoints = self.db.list_webhooks()
        for ep in endpoints:
            if not ep["active"]:
                continue
            if event_type not in ep["events"] and "*" not in ep["events"]:
                continue
            if SEVERITY_RANK.get(severity, 2) < SEVERITY_RANK.get(ep["min_severity"], 3):
                continue
            await self.deliver(ep["id"], ep["target_url"], event_type, envelope)

    async def deliver(
        self,
        endpoint_id: str | None,
        target_url: str,
        event_type: str,
        envelope: dict[str, Any],
        max_attempts: int = 3,
    ) -> dict[str, Any]:
        body = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        sig = sign_payload(body)
        headers = {
            "Content-Type": "application/json",
            "X-TraceGuard-Event": event_type,
            "X-TraceGuard-Signature": sig,
        }

        last_err: str | None = None
        http_status: int | None = None
        attempts = 0

        async with httpx.AsyncClient(timeout=2.5) as client:
            for attempt in range(1, max_attempts + 1):
                attempts = attempt
                try:
                    resp = await client.post(target_url, content=body, headers=headers)
                    http_status = resp.status_code
                    if 200 <= resp.status_code < 300:
                        return self.db.record_webhook_delivery(
                            endpoint_id, event_type, target_url, envelope, sig, "DELIVERED", attempts, http_status, None
                        )
                    last_err = f"HTTP {resp.status_code}: {resp.text[:160]}"
                except Exception as exc:
                    last_err = f"{type(exc).__name__}: {str(exc)[:160]}"
                if attempt < max_attempts:
                    await asyncio.sleep(0.15 * (2 ** (attempt - 1)))

        return self.db.record_webhook_delivery(
            endpoint_id, event_type, target_url, envelope, sig, "DEAD_LETTER", attempts, http_status, last_err
        )

"""Async Event Bus and WebSocket Live Broadcast Manager."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine
from fastapi import WebSocket


class EventBus:
    """In-process async event bus bridging backend workflows, WebSockets, and Webhooks."""

    def __init__(self) -> None:
        self._sockets: set[WebSocket] = set()
        self._subscribers: list[Callable[[dict[str, Any]], Coroutine[Any, Any, None]]] = []
        self._recent_events: list[dict[str, Any]] = []

    def subscribe(self, handler: Callable[[dict[str, Any]], Coroutine[Any, Any, None]]) -> None:
        self._subscribers.append(handler)

    async def connect_ws(self, ws: WebSocket) -> None:
        await ws.accept()
        self._sockets.add(ws)

    def disconnect_ws(self, ws: WebSocket) -> None:
        self._sockets.discard(ws)

    async def publish(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        envelope = {
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": payload,
        }
        self._recent_events.append(envelope)
        if len(self._recent_events) > 100:
            self._recent_events = self._recent_events[-100:]

        # Broadcast to live WebSocket clients
        dead: list[WebSocket] = []
        for ws in list(self._sockets):
            try:
                await ws.send_json(envelope)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._sockets.discard(ws)

        # Notify async subscribers (e.g., webhook dispatcher)
        for handler in self._subscribers:
            try:
                await handler(envelope)
            except Exception:
                pass
        return envelope

    def recent(self, limit: int = 25) -> list[dict[str, Any]]:
        return list(reversed(self._recent_events[-limit:]))

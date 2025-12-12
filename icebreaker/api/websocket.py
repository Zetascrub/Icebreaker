"""
WebSocket manager for real-time scan updates.
"""
from __future__ import annotations
from typing import Dict, Set
from fastapi import WebSocket


class ConnectionManager:
    """Manages WebSocket connections for real-time updates."""

    def __init__(self):
        # Store active connections by scan_id
        self.active_connections: Dict[int, Set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, scan_id: int):
        """Accept a new WebSocket connection for a scan."""
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = set()
        self.active_connections[scan_id].add(websocket)

    def disconnect(self, websocket: WebSocket, scan_id: int):
        """Remove a WebSocket connection."""
        if scan_id in self.active_connections:
            self.active_connections[scan_id].discard(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]

    async def send_update(self, scan_id: int, message: dict):
        """Send an update to all connections watching a scan."""
        if scan_id in self.active_connections:
            dead_connections = set()
            for connection in self.active_connections[scan_id]:
                try:
                    await connection.send_json(message)
                except Exception:
                    dead_connections.add(connection)

            # Clean up dead connections
            for connection in dead_connections:
                self.active_connections[scan_id].discard(connection)

    async def broadcast(self, message: dict):
        """Broadcast a message to all connections."""
        for scan_connections in self.active_connections.values():
            dead_connections = set()
            for connection in scan_connections:
                try:
                    await connection.send_json(message)
                except Exception:
                    dead_connections.add(connection)

            # Clean up dead connections
            for connection in dead_connections:
                scan_connections.discard(connection)


# Global connection manager
manager = ConnectionManager()

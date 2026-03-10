"""API key authentication middleware for the MCP SSE server."""

import os
import logging
import json

logger = logging.getLogger(__name__)

EXEMPT_PATHS = {"/health"}


class APIKeyAuthMiddleware:
    """Pure ASGI middleware that validates API key from Authorization header or query parameter.

    Uses pure ASGI (not BaseHTTPMiddleware) so it works correctly with SSE/streaming responses.

    Set the MCP_API_KEY environment variable to enable authentication.
    When MCP_API_KEY is not set, all requests are allowed (open mode).
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path in EXEMPT_PATHS:
            await self.app(scope, receive, send)
            return

        api_key = os.environ.get("MCP_API_KEY")
        if not api_key:
            await self.app(scope, receive, send)
            return

        # Extract headers (ASGI headers are list of (name_bytes, value_bytes))
        headers = dict(scope.get("headers", []))
        auth_header = headers.get(b"authorization", b"").decode()
        if auth_header.startswith("Bearer ") and auth_header[7:] == api_key:
            await self.app(scope, receive, send)
            return

        # Query parameter fallback
        query_string = scope.get("query_string", b"").decode()
        if f"api_key={api_key}" in query_string:
            await self.app(scope, receive, send)
            return

        client = scope.get("client")
        logger.warning(
            "Unauthorized request from %s to %s",
            client[0] if client else "unknown",
            path,
        )
        body = json.dumps(
            {"error": "Unauthorized. Provide API key via 'Authorization: Bearer <key>' header."}
        ).encode()
        await send({"type": "http.response.start", "status": 401,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body, "more_body": False})

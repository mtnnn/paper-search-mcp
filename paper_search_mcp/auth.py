"""API key authentication middleware for the MCP SSE server."""

import os
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)


class APIKeyAuthMiddleware(BaseHTTPMiddleware):
    """Validates API key from Authorization header or query parameter.

    Set the MCP_API_KEY environment variable to enable authentication.
    When MCP_API_KEY is not set, all requests are allowed (open mode).
    """

    EXEMPT_PATHS = {"/health"}

    async def dispatch(self, request: Request, call_next):
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        api_key = os.environ.get("MCP_API_KEY")
        if not api_key:
            return await call_next(request)

        # Check Authorization: Bearer <key>
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer ") and auth_header[7:] == api_key:
            return await call_next(request)

        # Query parameter fallback
        if request.query_params.get("api_key") == api_key:
            return await call_next(request)

        logger.warning(
            "Unauthorized request from %s to %s",
            request.client.host if request.client else "unknown",
            request.url.path,
        )
        return JSONResponse(
            {"error": "Unauthorized. Provide API key via 'Authorization: Bearer <key>' header."},
            status_code=401,
        )

"""Shared bearer-token authentication for the Kali MCP SSE servers.

STRIDE S10 defense-in-depth. The MCP tool servers are consumed ONLY by the agent
over the internal Docker bridge (``http://kali-sandbox:PORT/sse``); their host
ports are loopback-only (see docker-compose.yml). This middleware adds a second
control: every HTTP/WebSocket request must carry
``Authorization: Bearer <MCP_AUTH_TOKEN>`` when ``MCP_AUTH_TOKEN`` is set.

Behaviour:
- ``MCP_AUTH_TOKEN`` set    -> require a matching bearer token (constant-time),
                               otherwise reply 401 (HTTP) / close 1008 (WS).
- ``MCP_AUTH_TOKEN`` unset  -> FAIL OPEN and log a one-time warning, so dev
  or empty                    stacks (and the loopback-only publish) keep working
                               without a token. Fresh installs always get a token
                               from redamon.sh ``ensure_auth_secrets``.

Implemented as a pure-ASGI wrapper (no Starlette/FastMCP-version coupling) so it
composes with whatever SSE app the installed FastMCP builds. ``lifespan`` and any
non-http/websocket scope pass straight through untouched.
"""

import hmac
import logging
import os

logger = logging.getLogger("mcp-auth")

# One-time fail-open warning guard (per process).
_warned_failopen = False


def configured_token() -> str:
    """Return the expected bearer token from the environment (may be empty)."""
    return os.environ.get("MCP_AUTH_TOKEN", "") or ""


def _extract_bearer(headers) -> str:
    """Pull the bearer token out of raw ASGI headers (list[(bytes, bytes)])."""
    for key, value in headers or []:
        if key == b"authorization":
            try:
                text = value.decode("latin-1")
            except Exception:
                return ""
            if text[:7].lower() == "bearer ":
                return text[7:].strip()
            return ""
    return ""


class BearerAuthASGI:
    """Wrap an ASGI app, gating http/websocket requests on a bearer token."""

    def __init__(self, app, token_getter=configured_token):
        self.app = app
        self._token_getter = token_getter

    async def __call__(self, scope, receive, send):
        global _warned_failopen

        if scope.get("type") not in ("http", "websocket"):
            # lifespan / other — never gate these.
            await self.app(scope, receive, send)
            return

        expected = self._token_getter()
        if not expected:
            if not _warned_failopen:
                logger.warning(
                    "MCP_AUTH_TOKEN is not set - MCP servers are serving WITHOUT "
                    "bearer authentication (fail-open). Set MCP_AUTH_TOKEN to "
                    "enforce it. Host ports are loopback-only by default."
                )
                _warned_failopen = True
            await self.app(scope, receive, send)
            return

        presented = _extract_bearer(scope.get("headers"))
        if presented and hmac.compare_digest(presented, expected):
            await self.app(scope, receive, send)
            return

        await self._reject(scope, send)

    async def _reject(self, scope, send):
        if scope.get("type") == "websocket":
            # Reject the handshake with a policy-violation close code.
            await send({"type": "websocket.close", "code": 1008})
            return
        body = b'{"error":"unauthorized","detail":"missing or invalid bearer token"}'
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    (b"www-authenticate", b"Bearer"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def _build_sse_app(mcp):
    """Get the SSE ASGI app from a FastMCP instance across FastMCP 2.x variants."""
    builders = (
        lambda: mcp.sse_app(),
        lambda: mcp.http_app(transport="sse"),
    )
    last_err = None
    for build in builders:
        try:
            return build()
        except (AttributeError, TypeError) as exc:
            last_err = exc
            continue
    raise RuntimeError(f"no usable SSE app builder on this FastMCP: {last_err}")


def serve_sse_with_auth(mcp, host: str, port: int) -> None:
    """Serve a FastMCP instance over SSE with the bearer wrapper applied.

    Falls back to the unwrapped ``mcp.run()`` (with a loud error) if the app
    cannot be built/served on the installed FastMCP version — the loopback-only
    port publish remains the primary control in that degraded case, so we never
    brick tool serving over an auth-wiring detail.
    """
    try:
        import uvicorn

        app = _build_sse_app(mcp)
        wrapped = BearerAuthASGI(app)
        token_state = "enforced" if configured_token() else "fail-open (no token)"
        logger.info("MCP SSE server on %s:%s - bearer auth %s", host, port, token_state)
        uvicorn.run(wrapped, host=host, port=port, log_level="info")
    except Exception as exc:  # noqa: BLE001 - last-resort safety net
        logger.error(
            "Could not start MCP SSE server with bearer auth (%s); falling back to "
            "unauthenticated serving. Host ports are loopback-only.",
            exc,
        )
        mcp.run(transport="sse", host=host, port=port)

"""Bound Origin POST ingress before JSON parsing, authentication or DB work."""
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

# Origin accepts signed notification/control envelopes and Telegram webhook
# metadata, never media/file uploads. 64 KiB leaves headroom over those small
# payloads while bounding both absent-length and chunked request bodies.
MAX_ORIGIN_BODY_BYTES = 64 * 1024


class OriginBodyLimit:
    def __init__(self, app: ASGIApp, max_bytes: int = MAX_ORIGIN_BODY_BYTES):
        if not isinstance(max_bytes, int) or max_bytes <= 0:
            raise ValueError("positive Origin body limit required")
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") != "POST":
            await self.app(scope, receive, send)
            return

        async def refuse(status: int, detail: str) -> None:
            await JSONResponse({"detail": detail}, status_code=status)(scope, receive, send)

        lengths = [value for key, value in scope.get("headers", []) if key.lower() == b"content-length"]
        if len(lengths) > 1 or (lengths and not lengths[0].isdigit()):
            await refuse(400, "Invalid Content-Length")
            return
        if lengths:
            # Compare decimal length before int() so an attacker-controlled
            # thousands-digit header cannot overflow Python's integer budget.
            digits = lengths[0].lstrip(b"0") or b"0"
            if len(digits) > len(str(self.max_bytes)) or int(digits) > self.max_bytes:
                await refuse(413, "Origin request body exceeds limit")
                return

        buffered, size = bytearray(), 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                await refuse(400, "Invalid request body")
                return
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > self.max_bytes:
                await refuse(413, "Origin request body exceeds limit")
                return
            buffered.extend(chunk)
            if not message.get("more_body", False):
                break

        # Replay only the bounded bytes. No downstream handler sees a partial
        # oversized JSON/envelope or invokes auth/database work before the cap.
        bounded_body = bytes(buffered)
        buffered.clear()
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bounded_body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)

"""Strict Device-envelope payloads for calls and large-file sessions.

The returned objects are still encrypted by the Device Envelope layer.  These
validators only constrain the protocol shape and never inspect Account E2EE.
"""

from __future__ import annotations

import base64
import binascii
import re


_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_MIME = {"audio/ogg", "audio/wav", "audio/webm", "audio/mpeg"}
_SIGNAL_KEYS = {"wss_endpoint", "one_time_key"}


def _token(value, name):
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise ValueError(f"invalid {name}")
    return value


def _signaling(value):
    if not isinstance(value, dict) or set(value) != _SIGNAL_KEYS:
        raise ValueError("invalid signaling ticket")
    if not isinstance(value["wss_endpoint"], str) or not value["wss_endpoint"].startswith("wss://"):
        raise ValueError("invalid signaling endpoint")
    if not isinstance(value["one_time_key"], str) or not 16 <= len(value["one_time_key"]) <= 512:
        raise ValueError("invalid signaling ticket")
    return dict(value)


def validate_call_request(value: dict) -> dict:
    required = {"version", "call_id", "expires_at", "signaling", "caller_display_name",
                "ringtone", "media_capabilities"}
    if not isinstance(value, dict) or set(value) != required or value["version"] != 2:
        raise ValueError("invalid CALL_REQUEST_V2")
    _token(value["call_id"], "call_id")
    if type(value["expires_at"]) is not int:
        raise ValueError("invalid call expiry")
    _signaling(value["signaling"])
    if not isinstance(value["caller_display_name"], str) or not 1 <= len(value["caller_display_name"]) <= 128:
        raise ValueError("invalid caller display name")
    ringtone = value["ringtone"]
    if not isinstance(ringtone, dict) or set(ringtone) != {"mime", "base64"}:
        raise ValueError("invalid ringtone")
    if ringtone["mime"] not in _MIME or not isinstance(ringtone["base64"], str):
        raise ValueError("invalid ringtone")
    try:
        raw = base64.b64decode(ringtone["base64"], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid ringtone encoding") from exc
    if not 1 <= len(raw) <= 256 * 1024:
        raise ValueError("ringtone exceeds 256 KiB")
    caps = value["media_capabilities"]
    if not isinstance(caps, dict) or len(caps) > 32 or any(not isinstance(k, str) or len(k) > 64 for k in caps):
        raise ValueError("invalid media capabilities")
    return dict(value)


def validate_file_session_request(value: dict) -> dict:
    required = {"version", "session_id", "expires_at", "signaling", "encrypted_metadata",
                "size_bytes", "chunk_bytes", "sha256", "resumable"}
    if not isinstance(value, dict) or set(value) != required or value["version"] != 1:
        raise ValueError("invalid FILE_SESSION_REQUEST")
    _token(value["session_id"], "session_id")
    if type(value["expires_at"]) is not int or type(value["size_bytes"]) is not int:
        raise ValueError("invalid file limits")
    if not 1 <= value["size_bytes"] <= 50 * 1024 * 1024 * 1024:
        raise ValueError("file size exceeds 50 GiB")
    if type(value["chunk_bytes"]) is not int or not 16 * 1024 <= value["chunk_bytes"] <= 1024 * 1024:
        raise ValueError("invalid file chunk size")
    if not isinstance(value["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["sha256"]):
        raise ValueError("invalid file hash")
    if type(value["resumable"]) is not bool:
        raise ValueError("invalid resumable flag")
    _signaling(value["signaling"])
    if not isinstance(value["encrypted_metadata"], str) or not 1 <= len(value["encrypted_metadata"]) <= 64 * 1024:
        raise ValueError("invalid encrypted file metadata")
    return dict(value)

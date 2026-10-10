from __future__ import annotations

import json
import struct
from typing import Any

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class EnvelopeError(ValueError):
    pass


def variant_aad(
    owner_id: str,
    item_id: str,
    algorithm: str,
    mode: str,
    crypto_version: str,
    envelope_version: str = "gcm-a256-v1",
) -> bytes:
    """Authenticate the stored identity and format fields for a cipher variant."""
    return (
        f"securebox:{envelope_version}:{owner_id}:{item_id}:{algorithm}:"
        f"{mode}:{crypto_version}:schema1"
    ).encode("ascii")


def staging_aad(owner_id: str, item_id: str) -> bytes:
    return f"securebox:staging:v1:{owner_id}:{item_id}:schema1".encode("ascii")


def metadata_aad(owner_id: str, item_id: str) -> bytes:
    return f"securebox:metadata:v1:{owner_id}:{item_id}:schema1".encode("ascii")


def _wrap_dek(dek: bytes, kek: bytes, aad: bytes) -> bytes:
    nonce = get_random_bytes(12)
    cipher = AES.new(kek, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(dek)
    return nonce + ciphertext + tag


def _unwrap_dek(wrapped: bytes, kek: bytes, aad: bytes) -> bytes:
    if len(wrapped) != 12 + 32 + 16:
        raise EnvelopeError("Invalid wrapped key")
    nonce, sealed = wrapped[:12], wrapped[12:]
    cipher = AES.new(kek, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(b"securebox:kek:v1:" + aad)
    try:
        return cipher.decrypt_and_verify(sealed[:-16], sealed[-16:])
    except ValueError as exc:
        raise EnvelopeError("Envelope authentication failed") from exc


def seal_payload(payload: bytes, kek: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt an object with a fresh DEK and wrap the DEK under KEK v1."""
    dek = get_random_bytes(32)
    nonce = get_random_bytes(12)
    cipher = AES.new(dek, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(payload)
    wrapped = _wrap_dek(dek, kek, b"securebox:kek:v1:" + aad)
    return nonce + ciphertext + tag, wrapped


def open_payload(envelope: bytes, wrapped_dek: bytes, kek: bytes, aad: bytes) -> bytes:
    if len(envelope) < 12 + 16:
        raise EnvelopeError("Truncated envelope")
    dek = _unwrap_dek(wrapped_dek, kek, aad)
    nonce, sealed = envelope[:12], envelope[12:]
    cipher = AES.new(dek, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(aad)
    try:
        return cipher.decrypt_and_verify(sealed[:-16], sealed[-16:])
    except ValueError as exc:
        raise EnvelopeError("Envelope authentication failed") from exc


def seal_metadata(metadata: dict[str, Any], kek: bytes, aad: bytes) -> bytes:
    nonce = get_random_bytes(12)
    payload = json.dumps(metadata, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    cipher = AES.new(kek, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(payload)
    return nonce + ciphertext + tag


def open_metadata(envelope: bytes, kek: bytes, aad: bytes) -> dict[str, Any]:
    if len(envelope) < 28:
        raise EnvelopeError("Truncated metadata")
    nonce, sealed = envelope[:12], envelope[12:]
    cipher = AES.new(kek, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(aad)
    try:
        decoded = cipher.decrypt_and_verify(sealed[:-16], sealed[-16:])
        result = json.loads(decoded)
    except (ValueError, json.JSONDecodeError) as exc:
        raise EnvelopeError("Metadata authentication failed") from exc
    if not isinstance(result, dict):
        raise EnvelopeError("Invalid metadata")
    return result


def pack_inner_material(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(key) > 255 or len(iv) > 255:
        raise ValueError("Invalid key material")
    return struct.pack("BB", len(key), len(iv)) + key + iv + ciphertext


def unpack_inner_material(payload: bytes) -> tuple[bytes, bytes, bytes]:
    if len(payload) < 2:
        raise EnvelopeError("Truncated inner material")
    key_size, iv_size = struct.unpack("BB", payload[:2])
    offset = 2 + key_size + iv_size
    if offset > len(payload):
        raise EnvelopeError("Truncated inner material")
    return payload[2 : 2 + key_size], payload[2 + key_size : offset], payload[offset:]

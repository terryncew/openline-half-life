from __future__ import annotations

import base64
import copy
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .util import canonical_json, sha256_bytes

RECEIPT_SCHEMA = "openline.half-life.receipt.v2"
ANCHOR_SCHEMA = "openline.half-life.anchor.v2"
HASH256 = re.compile(r"^[0-9a-f]{64}$")
PUBLIC_KEY_HEX = re.compile(r"^[0-9a-f]{64}$")


def _public_raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def sign_envelope(body: Mapping[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    payload = copy.deepcopy(dict(body))
    digest = sha256_bytes(canonical_json(payload))
    return {
        **payload,
        "payload_hash": digest,
        "signature": {
            "algorithm": "Ed25519",
            "public_key": _public_raw(key).hex(),
            "value": key.sign(bytes.fromhex(digest)).hex(),
        },
    }


def verify_envelope(value: Mapping[str, Any], expected_public_keys: set[str] | None = None) -> bool:
    try:
        signature = value["signature"]
        if signature.get("algorithm") != "Ed25519":
            return False
        public_hex = signature["public_key"]
        if PUBLIC_KEY_HEX.fullmatch(public_hex) is None:
            return False
        if expected_public_keys is not None and public_hex not in expected_public_keys:
            return False
        body = dict(value)
        body.pop("payload_hash", None)
        body.pop("signature", None)
        digest = sha256_bytes(canonical_json(body))
        if value.get("payload_hash") != digest:
            return False
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(bytes.fromhex(signature["value"]), bytes.fromhex(digest))
        return True
    except (KeyError, ValueError, TypeError, InvalidSignature):
        return False


@dataclass(frozen=True)
class ReceiptSigner:
    private_key: Ed25519PrivateKey

    @classmethod
    def from_hex_file(cls, path: Path) -> "ReceiptSigner":
        text = path.read_text(encoding="ascii").strip()
        if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
            raise ValueError("signing key must contain exactly 32 lowercase-hex bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(text)))

    @property
    def public_b64(self) -> str:
        return base64.b64encode(_public_raw(self.private_key)).decode("ascii")


def create_receipt(kind: str, payload: Mapping[str, Any], signer: ReceiptSigner, *, index: int, parent_hash: str | None) -> dict[str, Any]:
    body = {
        "schema": RECEIPT_SCHEMA,
        "index": index,
        "kind": kind,
        "parent_hash": parent_hash,
        "payload": copy.deepcopy(dict(payload)),
        "signer_public_key": signer.public_b64,
    }
    digest = sha256_bytes(canonical_json(body))
    return {**body, "receipt_hash": digest, "signature": base64.b64encode(signer.private_key.sign(bytes.fromhex(digest))).decode("ascii")}


def create_chain(items: Sequence[tuple[str, Mapping[str, Any]]], signer: ReceiptSigner) -> list[dict[str, Any]]:
    chain: list[dict[str, Any]] = []
    parent: str | None = None
    for index, (kind, payload) in enumerate(items):
        receipt = create_receipt(kind, payload, signer, index=index, parent_hash=parent)
        chain.append(receipt)
        parent = receipt["receipt_hash"]
    return chain


def chain_digest(chain: Sequence[Mapping[str, Any]]) -> str:
    return sha256_bytes(canonical_json([item.get("receipt_hash") for item in chain]))


def verify_chain(chain: Sequence[Mapping[str, Any]], *, expected_signer_public_key: str | None = None) -> dict[str, Any]:
    errors: list[str] = []
    if not chain:
        return {"valid": False, "errors": ["empty_chain"], "count": 0}
    signer_key = expected_signer_public_key or str(chain[0].get("signer_public_key", ""))
    try:
        raw_key = base64.b64decode(signer_key, validate=True)
        if len(raw_key) != 32:
            raise ValueError
        verifier = Ed25519PublicKey.from_public_bytes(raw_key)
    except Exception:
        return {"valid": False, "errors": ["invalid_signer_public_key"], "count": len(chain)}
    parent: str | None = None
    for index, receipt in enumerate(chain):
        if receipt.get("schema") != RECEIPT_SCHEMA:
            errors.append(f"schema:{index}")
        if receipt.get("index") != index:
            errors.append(f"index:{index}")
        if receipt.get("parent_hash") != parent:
            errors.append(f"parent:{index}")
        if receipt.get("signer_public_key") != signer_key:
            errors.append(f"signer:{index}")
        body = dict(receipt)
        signature = body.pop("signature", None)
        observed_hash = body.pop("receipt_hash", None)
        computed = sha256_bytes(canonical_json(body))
        if observed_hash != computed:
            errors.append(f"hash:{index}")
        try:
            verifier.verify(base64.b64decode(signature, validate=True), bytes.fromhex(computed))
        except Exception:
            errors.append(f"signature:{index}")
        parent = str(observed_hash)
    return {"valid": not errors, "errors": errors, "count": len(chain), "tail_hash": chain[-1].get("receipt_hash"), "chain_digest": chain_digest(chain), "signer_public_key": signer_key}


def create_anchor(chain: Sequence[Mapping[str, Any]], signer: ReceiptSigner) -> dict[str, Any]:
    if not chain:
        raise ValueError("cannot anchor an empty chain")
    verification = verify_chain(chain, expected_signer_public_key=signer.public_b64)
    if not verification["valid"]:
        raise ValueError("cannot anchor an invalid chain")
    body = {
        "schema": ANCHOR_SCHEMA,
        "expected_count": len(chain),
        "expected_tail_hash": chain[-1]["receipt_hash"],
        "chain_digest": chain_digest(chain),
        "signer_public_key": signer.public_b64,
    }
    digest = sha256_bytes(canonical_json(body))
    return {**body, "anchor_hash": digest, "signature": base64.b64encode(signer.private_key.sign(bytes.fromhex(digest))).decode("ascii")}


def verify_anchor(anchor: Mapping[str, Any], chain: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    errors: list[str] = []
    if anchor.get("schema") != ANCHOR_SCHEMA:
        errors.append("schema")
    body = dict(anchor)
    signature = body.pop("signature", None)
    observed_hash = body.pop("anchor_hash", None)
    computed = sha256_bytes(canonical_json(body))
    if observed_hash != computed:
        errors.append("hash")
    if anchor.get("expected_count") != len(chain):
        errors.append("count")
    if not chain or anchor.get("expected_tail_hash") != chain[-1].get("receipt_hash"):
        errors.append("tail")
    if anchor.get("chain_digest") != chain_digest(chain):
        errors.append("digest")
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(str(anchor.get("signer_public_key")), validate=True))
        key.verify(base64.b64decode(signature, validate=True), bytes.fromhex(computed))
    except Exception:
        errors.append("signature")
    return {"valid": not errors, "errors": errors, "anchor_hash": observed_hash}

def verify_receipt(receipt: Mapping[str, Any], *, expected_index: int, expected_parent_hash: str | None, expected_signer_public_key: str) -> dict[str, Any]:
    errors: list[str] = []
    if receipt.get("schema") != RECEIPT_SCHEMA:
        errors.append("schema")
    if receipt.get("index") != expected_index:
        errors.append("index")
    if receipt.get("parent_hash") != expected_parent_hash:
        errors.append("parent")
    if receipt.get("signer_public_key") != expected_signer_public_key:
        errors.append("signer")
    body = dict(receipt)
    signature = body.pop("signature", None)
    observed = body.pop("receipt_hash", None)
    computed = sha256_bytes(canonical_json(body))
    if observed != computed:
        errors.append("hash")
    try:
        verifier = Ed25519PublicKey.from_public_bytes(base64.b64decode(expected_signer_public_key, validate=True))
        verifier.verify(base64.b64decode(signature, validate=True), bytes.fromhex(computed))
    except Exception:
        errors.append("signature")
    return {"valid": not errors, "errors": errors, "receipt_hash": observed}

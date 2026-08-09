from __future__ import annotations

import copy
from pathlib import Path

from openline_half_life.receipts import ReceiptSigner, create_anchor, create_chain, verify_anchor, verify_chain, verify_receipt


def test_chain_and_anchor_verify(root: Path):
    signer = ReceiptSigner.from_hex_file(root / "fixtures/demo_source_signing_key.hex")
    chain = create_chain([("a", {"run_id": "r", "x": 1}), ("b", {"run_id": "r", "x": 2})], signer)
    assert verify_chain(chain)["valid"]
    anchor = create_anchor(chain, signer)
    assert verify_anchor(anchor, chain)["valid"]


def test_chain_mutation_fails(root: Path):
    signer = ReceiptSigner.from_hex_file(root / "fixtures/demo_source_signing_key.hex")
    chain = create_chain([("a", {"run_id": "r", "x": 1})], signer)
    changed = copy.deepcopy(chain)
    changed[0]["payload"]["x"] = 9
    assert verify_chain(changed)["valid"] is False


def test_extension_parent_is_bound(root: Path):
    signer = ReceiptSigner.from_hex_file(root / "fixtures/demo_source_signing_key.hex")
    chain = create_chain([("a", {"run_id": "r"})], signer)
    extension = create_chain([("x", {"run_id": "r"})], signer)[0]
    assert verify_receipt(extension, expected_index=1, expected_parent_hash=chain[-1]["receipt_hash"], expected_signer_public_key=signer.public_b64)["valid"] is False

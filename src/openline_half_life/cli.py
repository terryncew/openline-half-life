from __future__ import annotations

import argparse
import json
from contextlib import ExitStack
from importlib import resources
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import __version__
from .compaction import build_policy_body, sign_policy
from .pipeline import run_pipeline, verify_output_directory


def _resource(stack: ExitStack, *parts: str) -> Path:
    target = resources.files("openline_half_life").joinpath(*parts)
    return stack.enter_context(resources.as_file(target))


def _load_keys(path: Path) -> set[str]:
    return {line.strip() for line in path.read_text(encoding="ascii").splitlines() if line.strip() and not line.lstrip().startswith("#")}


def _private_key(path: Path) -> Ed25519PrivateKey:
    text = path.read_text(encoding="ascii").strip()
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(text))


def _summary(result: Mapping[str, Any]) -> str:
    ratio = int(result["active_size_ratio_micros"]) / 10_000
    return "\n".join([
        f"Verified state compaction passed at turn {result['checkpoint_turn']}.",
        f"Independent replay mismatches: {result['decision_mismatch_count']}.",
        f"Compact state: {ratio:.1f}% of the verified source receipt chain.",
        f"Archived receipts recovered: {result['archive_receipt_count']}.",
        f"Output: {Path(str(result['output_dir'])).resolve()}",
    ])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="openline-half-life", description="Verified state compaction with independent replay and recoverable archives.")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="compact a verified history under an operator-owned policy")
    run.add_argument("trajectory", type=Path)
    run.add_argument("--compaction-policy", type=Path, required=True)
    run.add_argument("--compaction-policy-public-key", type=Path, required=True)
    run.add_argument("--source-signing-key", type=Path, required=True)
    run.add_argument("--operator-approval-signing-key", type=Path, required=True)
    run.add_argument("--replay-latency-micros", type=int, required=True)
    run.add_argument("--checkpoint-turn", type=int)
    run.add_argument("--operator-disposition", choices=["APPROVE", "DENY"], default="APPROVE")
    run.add_argument("--out", type=Path, required=True)
    run.add_argument("--json", action="store_true")

    verify = sub.add_parser("verify", help="verify source chain, compact state, independent replay report, and archive custody")
    verify.add_argument("output_dir", type=Path)
    verify.add_argument("--compaction-policy-public-key", type=Path, required=True)

    demo = sub.add_parser("demo", help="run the bundled deterministic compaction example")
    demo.add_argument("--out", type=Path, default=Path("build/demo"))
    demo.add_argument("--replay-latency-micros", type=int, default=75_000)
    demo.add_argument("--json", action="store_true")

    policy = sub.add_parser("build-demo-policy", help="regenerate the bundled demonstration compaction policy")
    policy.add_argument("--out", type=Path, required=True)

    args = parser.parse_args(argv)
    if args.command == "run":
        result = run_pipeline(
            args.trajectory,
            args.source_signing_key,
            args.out,
            compaction_policy_path=args.compaction_policy,
            compaction_policy_public_key_path=args.compaction_policy_public_key,
            operator_approval_signing_key_path=args.operator_approval_signing_key,
            replay_latency_micros=args.replay_latency_micros,
            checkpoint_turn=args.checkpoint_turn,
            operator_disposition=args.operator_disposition,
        )
    elif args.command == "verify":
        result = verify_output_directory(args.output_dir, expected_policy_public_keys=_load_keys(args.compaction_policy_public_key))
    elif args.command == "build-demo-policy":
        with ExitStack() as stack:
            source_key = _private_key(_resource(stack, "data", "fixtures", "demo_source_signing_key.hex"))
            approval_key = _private_key(_resource(stack, "data", "fixtures", "demo_operator_approval_key.hex"))
            policy_key = _private_key(_resource(stack, "data", "fixtures", "demo_policy_signing_key.hex"))
            import base64
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            source_b64 = base64.b64encode(source_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")
            approval_public = approval_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
            result = sign_policy(build_policy_body(trusted_source_signer_keys_b64=[source_b64], trusted_operator_approval_public_keys=[approval_public], active_receipt_bytes_budget=25_000, replay_latency_micros_budget=50_000), policy_key)
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            result = {"policy": str(args.out), "payload_hash": result["payload_hash"]}
    else:
        with ExitStack() as stack:
            result = run_pipeline(
                _resource(stack, "data", "fixtures", "demo_trajectory.jsonl"),
                _resource(stack, "data", "fixtures", "demo_source_signing_key.hex"),
                args.out,
                compaction_policy_path=_resource(stack, "data", "policy", "compaction_policy.json"),
                compaction_policy_public_key_path=_resource(stack, "data", "policy", "compaction_policy_public_key.hex"),
                operator_approval_signing_key_path=_resource(stack, "data", "fixtures", "demo_operator_approval_key.hex"),
                replay_latency_micros=args.replay_latency_micros,
            )
    if args.command in {"run", "demo"} and not args.json:
        print(_summary(result))
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    valid = result.get("passed") is True if args.command in {"run", "demo"} else result.get("valid", True) is True
    return 0 if valid else 1

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCALE = 1_000_000


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _percent(micros: int) -> int:
    return (abs(int(micros)) + 5_000) // 10_000


def build(reference_dir: Path, output_dir: Path) -> dict:
    required = {
        "comparison.json",
        "decision_equivalence_report.json",
        "break_even_report.json",
        "half_life_receipt.json",
        "share_card.html",
        "break_even_card.html",
    }
    missing = sorted(name for name in required if not (reference_dir / name).exists())
    if missing:
        raise FileNotFoundError("missing reference artifacts: " + ", ".join(missing))

    comparison = _load(reference_dir / "comparison.json")
    equivalence = _load(reference_dir / "decision_equivalence_report.json")
    economics = _load(reference_dir / "break_even_report.json")
    receipt = _load(reference_dir / "half_life_receipt.json")

    if not (
        comparison.get("passed") is True
        and equivalence.get("passed") is True
        and receipt.get("valid") is not False
    ):
        raise ValueError("reference run has not earned a launch surface")

    full = comparison["full_history"]["metrics"]
    compact = comparison["verified_residue"]["metrics"]
    retirement_turn = int(receipt["retirement_turn"])
    error_reduction = _percent(comparison["delta"]["error_reduction_micros"])
    active_ratio = _percent(equivalence["active_size_ratio_micros"])
    mismatches = len(equivalence.get("mismatches", []))
    break_even = economics.get("dollar_durable_break_even_turn")
    if break_even is None:
        break_even_label = "Not established"
        break_even_sentence = "This reference scenario did not earn a durable dollar break-even claim."
    else:
        break_even_label = f"Turn {int(break_even)}"
        break_even_sentence = (
            f"Under the declared reference scenario, the compact path reaches durable break-even after {int(break_even)} future turns."
        )

    reference = output_dir / "reference"
    reference.mkdir(parents=True, exist_ok=True)
    for name in required:
        shutil.copy2(reference_dir / name, reference / name)
    for name in (
        "cost_assumptions.json",
        "break_even_curve.csv",
        "comparison.json",
        "decision_equivalence_report.json",
        "half_life_receipt.json",
        "causal_capsule.json",
        "archive_manifest.json",
        "compaction_receipt.json",
        "verified_residue_handoff.json",
    ):
        source = reference_dir / name
        if source.exists():
            shutil.copy2(source, reference / name)

    metrics = {
        "retirement_turn": retirement_turn,
        "full_history_tokens": int(full["estimated_input_tokens"]),
        "compact_tokens": int(compact["estimated_input_tokens"]),
        "full_history_errors": int(full["error_count"]),
        "compact_errors": int(compact["error_count"]),
        "error_reduction_percent": error_reduction,
        "active_state_percent": active_ratio,
        "decision_mismatches": mismatches,
        "break_even_turn": break_even,
    }
    (reference / "reference_metrics.json").write_text(
        json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    proof = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenLine Reference Proof</title><style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;background:#090c12;color:#f4f7fb;font-family:ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}main{{max-width:900px;margin:auto;padding:64px 24px 90px}}a{{color:#b9cdf0}}h1{{font-size:clamp(42px,8vw,78px);line-height:1;letter-spacing:-.04em}}p,li{{color:#c4cedd;line-height:1.6}}.box{{margin-top:28px;padding:22px;border:1px solid #2b3442;border-radius:18px;background:#111722}}code{{word-break:break-all}}</style></head><body><main>
<p><a href="index.html">← Back to OpenLine</a></p><h1>The reference run.</h1>
<p>This page links to the checked-in artifacts behind the public numbers. The demo is synthetic and deterministic. It proves the disclosed harness behavior, not universal model support.</p>
<div class="box"><strong>Receiver result</strong><p>Retirement turn: {retirement_turn}<br>Error reduction: {error_reduction}%<br>Active state: {active_ratio}% of full receipt history<br>Decision mismatches: {mismatches}<br>Reference break-even: {html.escape(break_even_label)}</p></div>
<div class="box"><strong>Inspect</strong><ul>
<li><a href="reference/share_card.html">Share card</a></li><li><a href="reference/break_even_card.html">Break-even card</a></li>
<li><a href="reference/comparison.json">Same-exam comparison</a></li><li><a href="reference/decision_equivalence_report.json">Decision-equivalence report</a></li>
<li><a href="reference/half_life_receipt.json">Half-Life receipt bundle</a></li><li><a href="reference/archive_manifest.json">Cold-archive manifest receipt</a></li>
<li><a href="reference/reference_metrics.json">Derived page metrics</a></li></ul></div>
</main></body></html>'''
    (output_dir / "proof.html").write_text(proof, encoding="utf-8")

    index = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="OpenLine is a cross-platform save file for AI agents. Save the verified job state on one model and continue on another.">
<title>OpenLine — Your agent should survive changing models</title><style>
:root{{--bg:#090c12;--panel:#111722;--line:#2b3442;--text:#f5f7fb;--muted:#b5c0d1;--accent:#c8d9f3;color-scheme:dark}}*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:var(--bg);color:var(--text);font-family:ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}a{{color:inherit}}.wrap{{width:min(1120px,calc(100% - 40px));margin:auto}}nav{{display:flex;justify-content:space-between;align-items:center;padding:24px 0;color:var(--muted)}}.brand{{font-weight:800;color:var(--text)}}.hero{{padding:88px 0 72px}}.eyebrow{{letter-spacing:.14em;text-transform:uppercase;color:#91a3bd;font-size:13px}}h1{{max-width:980px;margin:18px 0 24px;font-size:clamp(54px,10vw,116px);line-height:.92;letter-spacing:-.06em}}.lead{{max-width:780px;color:var(--muted);font-size:clamp(21px,3vw,31px);line-height:1.35}}.category{{margin-top:26px;font-size:20px;font-weight:800}}.actions{{display:flex;flex-wrap:wrap;gap:12px;margin-top:34px}}.button{{display:inline-block;padding:14px 18px;border-radius:999px;text-decoration:none;border:1px solid var(--line);font-weight:800}}.primary{{background:var(--text);color:#0b0e14}}section{{padding:66px 0;border-top:1px solid #202735}}h2{{font-size:clamp(36px,6vw,70px);letter-spacing:-.045em;margin:0 0 20px}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:30px}}.metric,.step,.terminal{{border:1px solid var(--line);border-radius:18px;background:var(--panel);padding:22px}}.metric strong{{display:block;font-size:34px;margin-top:10px}}.label{{color:#8fa0b8;text-transform:uppercase;letter-spacing:.1em;font-size:12px}}.steps{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-top:30px}}.step b{{display:block;margin-bottom:10px}}.step p,.note{{color:var(--muted);line-height:1.55}}pre{{white-space:pre-wrap;margin:0;color:#dbe5f5;font-size:16px;line-height:1.6}}.cards{{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:28px}}iframe{{width:100%;height:620px;border:1px solid var(--line);border-radius:18px;background:#090c12}}footer{{padding:44px 0 80px;color:#7f8fa6}}@media(max-width:900px){{.grid{{grid-template-columns:1fr 1fr}}.steps{{grid-template-columns:1fr 1fr}}.cards{{grid-template-columns:1fr}}}}@media(max-width:560px){{.grid,.steps{{grid-template-columns:1fr}}iframe{{height:690px}}}}
</style></head><body><div class="wrap"><nav><div class="brand">OpenLine Protocol</div><a href="proof.html">Reference proof</a></nav>
<header class="hero"><div class="eyebrow">Cross-platform continuity for AI agents</div><h1>Your agent should survive changing models.</h1>
<p class="lead">OpenLine works like a cross-platform save file: save the verified state of a job on one model, load it on another, and continue with the record intact.</p>
<p class="category">You own the job. The model is the console.</p><div class="actions"><a class="button primary" href="#run">Run the demo</a><a class="button" href="proof.html">See the proof</a></div></header>
<section><div class="eyebrow">Reference run</div><h2>The progress survives. The console changes.</h2><p class="note">These figures are generated from the checked-in deterministic demo, not typed into the page.</p><div class="grid">
<div class="metric"><span class="label">Retirement point</span><strong>Turn {retirement_turn}</strong></div><div class="metric"><span class="label">Same-exam errors</span><strong>{full['error_count']} → {compact['error_count']}</strong></div>
<div class="metric"><span class="label">Active save state</span><strong>{active_ratio}%</strong></div><div class="metric"><span class="label">Decision mismatches</span><strong>{mismatches}</strong></div></div>
<p class="note">Verified handoff reduced errors by {error_reduction}% on the same exam. {html.escape(break_even_sentence)}</p></section>
<section id="run"><div class="eyebrow">One command</div><h2>Make the save file.</h2><div class="terminal"><pre>uvx openline-half-life demo

# or
pipx run openline-half-life demo</pre></div><p class="note">The CLI prints a five-line human receipt and writes the signed artifacts locally. Add <code>--json</code> for the full machine-readable result.</p></section>
<section><div class="eyebrow">What moves</div><h2>Job state, not a hidden mind.</h2><p class="lead">The save file carries supported claims, evidence references, commitments, constraints, confirmed outcomes, unresolved questions, contradictions, policy versions, and tombstones. It does not claim to transfer model weights, private chain of thought, or provider-internal memory.</p></section>
<section><div class="eyebrow">One stack</div><h2>The metaphor holds all the way down.</h2><div class="steps">
<div class="step"><b>Receipts</b><p>Record what happened.</p></div><div class="step"><b>Half-Life</b><p>Makes the verified save file small enough to carry.</p></div><div class="step"><b>Model Swap</b><p>Loads the state into another model.</p></div><div class="step"><b>Receipt Gate</b><p>Checks what the transferred evidence earns.</p></div><div class="step"><b>Verified Commit</b><p>Gives fresh permission for one exact action.</p></div></div></section>
<section><div class="eyebrow">Reference artifacts</div><h2>Understand it without touching GitHub.</h2><div class="cards"><iframe title="OpenLine Half-Life reference share card" src="reference/share_card.html"></iframe><iframe title="OpenLine Half-Life reference break-even card" src="reference/break_even_card.html"></iframe></div></section>
<footer>Terrynce White · OpenLine Protocol · The demo proves the disclosed deterministic harness, not universal model support.</footer></div></body></html>'''
    (output_dir / "index.html").write_text(index, encoding="utf-8")
    (output_dir / ".nojekyll").write_text("", encoding="utf-8")
    return metrics


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", type=Path, default=ROOT / "examples" / "demo_output")
    parser.add_argument("--out", type=Path, default=ROOT / "docs")
    args = parser.parse_args()
    metrics = build(args.reference, args.out)
    print(json.dumps(metrics, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

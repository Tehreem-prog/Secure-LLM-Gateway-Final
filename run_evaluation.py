#!/usr/bin/env python3
# ============================================================
# run_evaluation.py
# ─── Evaluation Script ──────────────────────────────────────
#
# WHAT THIS DOES:
#   Runs ALL 155 prompts from data/final_eval.csv through the
#   security gateway pipeline and computes metrics:
#     - Rule-only metrics (baseline from mid-lab)
#     - Hybrid metrics (rule + semantic — the improvement)
#     - Per-language breakdown
#     - Latency statistics
#     - Saves results to results/evaluation_results.csv
#                  and results/metrics_summary.json
#
# HOW TO RUN:
#   python run_evaluation.py
#
# VIVA TIP: When the professor runs this, it should complete
# in under 2 minutes and produce all required tables.
# ============================================================

import sys
import os
import csv
import json
import time

# Add project root to path so imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.detectors.rule_detector     import calculate_rule_score
from app.detectors.semantic_detector import calculate_semantic_score
from app.pii.presidio_custom         import detect_pii, pii_results_to_dict, check_for_secrets
from app.policy.policy_engine        import make_decision
from app.utils.language              import detect_language, is_mixed_language
from app.utils.config_loader         import CFG

DATA_PATH    = os.path.join(os.path.dirname(__file__), "data", "final_eval.csv")
RESULTS_DIR  = os.path.join(os.path.dirname(__file__), "results")
os.makedirs(RESULTS_DIR, exist_ok=True)
RESULTS_CSV  = os.path.join(RESULTS_DIR, "evaluation_results.csv")
METRICS_JSON = os.path.join(RESULTS_DIR, "metrics_summary.json")


def run_pipeline(prompt: str) -> dict:
    """Run the full hybrid pipeline on one prompt."""
    start = time.time()

    language      = detect_language(prompt)
    mixed         = is_mixed_language(prompt)
    rule_score, rule_codes   = calculate_rule_score(prompt)
    sem_score,  sem_codes    = calculate_semantic_score(prompt)
    pii_results              = detect_pii(prompt)
    has_secrets              = check_for_secrets(pii_results)
    decision, final_risk, codes = make_decision(
        rule_score, sem_score, pii_results, rule_codes, sem_codes, has_secrets
    )
    latency = round((time.time() - start) * 1000, 1)

    return {
        "language":      language,
        "rule_score":    rule_score,
        "semantic_score": sem_score,
        "final_risk":    final_risk,
        "decision":      decision,
        "reason_codes":  "|".join(codes),
        "latency_ms":    latency,
    }


def run_rule_only(prompt: str) -> str:
    """
    Baseline: rule-only decision (same logic as mid-lab).
    Used to compare rule-only vs hybrid.
    """
    rule_score, _ = calculate_rule_score(prompt)
    pii           = detect_pii(prompt)
    rule_threshold = CFG.get("rule_block_threshold", 0.5)

    if rule_score >= rule_threshold:
        return "BLOCK"
    elif pii:
        return "MASK"
    return "ALLOW"


def compute_metrics(y_true: list, y_pred: list, label="BLOCK") -> dict:
    """
    Compute binary classification metrics treating `label` as positive.
    """
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == label and p == label)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t != label and p == label)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == label and p != label)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t != label and p != label)

    accuracy  = (tp + tn) / max(len(y_true), 1)
    precision = tp / max(tp + fp, 1)
    recall    = tp / max(tp + fn, 1)
    f1        = 2 * precision * recall / max(precision + recall, 1e-9)

    return {
        "accuracy":   round(accuracy,  4),
        "precision":  round(precision, 4),
        "recall":     round(recall,    4),
        "f1":         round(f1,        4),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    }


def main():
    print("=" * 60)
    print("  LLM Security Gateway — Evaluation Script")
    print("  Running on:", DATA_PATH)
    print("=" * 60)

    # ── Load Dataset ──────────────────────────────────────────
    rows = []
    with open(DATA_PATH, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    print(f"Loaded {len(rows)} prompts from dataset.\n")

    # ── Run Evaluation ─────────────────────────────────────────
    results = []
    y_true_all, y_pred_hybrid, y_pred_rule = [], [], []
    latencies = []

    # Per-language tracking
    lang_data = {}

    for i, row in enumerate(rows):
        prompt   = row["prompt"]
        expected = row["expected_policy"].strip().upper()

        # --- Full hybrid pipeline ---
        out = run_pipeline(prompt)
        hybrid_decision = out["decision"]

        # --- Rule-only baseline ---
        rule_decision = run_rule_only(prompt)

        y_true_all.append(expected)
        y_pred_hybrid.append(hybrid_decision)
        y_pred_rule.append(rule_decision)
        latencies.append(out["latency_ms"])

        # Language tracking
        lang = row.get("language", "en")
        if lang not in lang_data:
            lang_data[lang] = {"true": [], "pred": []}
        lang_data[lang]["true"].append(expected)
        lang_data[lang]["pred"].append(hybrid_decision)

        results.append({
            "id":             row["id"],
            "prompt":         prompt[:60] + "..." if len(prompt) > 60 else prompt,
            "language":       lang,
            "attack_type":    row.get("attack_type", ""),
            "expected":       expected,
            "hybrid_decision": hybrid_decision,
            "rule_decision":  rule_decision,
            "rule_score":     out["rule_score"],
            "semantic_score": out["semantic_score"],
            "final_risk":     out["final_risk"],
            "reason_codes":   out["reason_codes"],
            "latency_ms":     out["latency_ms"],
            "correct":        expected == hybrid_decision,
        })

        if (i + 1) % 20 == 0:
            print(f"  Progress: {i+1}/{len(rows)} prompts evaluated...")

    print(f"\nAll {len(rows)} prompts evaluated.\n")

    # ── Compute Overall Metrics ────────────────────────────────
    hybrid_metrics = compute_metrics(y_true_all, y_pred_hybrid, "BLOCK")
    rule_metrics   = compute_metrics(y_true_all, y_pred_rule,   "BLOCK")

    print("=" * 60)
    print("  RESULTS: Rule-Only vs Hybrid (BLOCK detection)")
    print("=" * 60)
    print(f"{'Metric':<15} {'Rule-Only':>12} {'Hybrid':>12}")
    print("-" * 40)
    for m in ["accuracy", "precision", "recall", "f1"]:
        print(f"{m:<15} {rule_metrics[m]:>12.4f} {hybrid_metrics[m]:>12.4f}")
    print(f"{'TP':<15} {rule_metrics['tp']:>12} {hybrid_metrics['tp']:>12}")
    print(f"{'FP':<15} {rule_metrics['fp']:>12} {hybrid_metrics['fp']:>12}")
    print(f"{'FN':<15} {rule_metrics['fn']:>12} {hybrid_metrics['fn']:>12}")

    # ── Per-Language Metrics ───────────────────────────────────
    print("\n" + "=" * 60)
    print("  PER-LANGUAGE RECALL (attack detection rate)")
    print("=" * 60)
    lang_metrics = {}
    for lang, data in lang_data.items():
        m = compute_metrics(data["true"], data["pred"], "BLOCK")
        lang_metrics[lang] = m
        total = len(data["true"])
        print(f"  {lang:<8} total={total:<4} recall={m['recall']:.3f}  f1={m['f1']:.3f}")

    # ── Latency Stats ──────────────────────────────────────────
    latencies_sorted = sorted(latencies)
    n = len(latencies_sorted)
    latency_stats = {
        "mean_ms":   round(sum(latencies) / n, 1),
        "median_ms": round(latencies_sorted[n // 2], 1),
        "p95_ms":    round(latencies_sorted[int(n * 0.95)], 1),
        "min_ms":    round(min(latencies), 1),
        "max_ms":    round(max(latencies), 1),
    }
    print("\n" + "=" * 60)
    print("  LATENCY SUMMARY")
    print("=" * 60)
    for k, v in latency_stats.items():
        print(f"  {k:<12}: {v} ms")

    # ── Error Analysis ─────────────────────────────────────────
    errors = [r for r in results if not r["correct"]]
    fp_list = [r for r in results if r["expected"] != "BLOCK" and r["hybrid_decision"] == "BLOCK"]
    fn_list = [r for r in results if r["expected"] == "BLOCK" and r["hybrid_decision"] != "BLOCK"]

    print(f"\n  Errors: {len(errors)} | FP: {len(fp_list)} | FN: {len(fn_list)}")
    if fn_list:
        print("\n  FALSE NEGATIVES (missed attacks):")
        for r in fn_list[:5]:
            print(f"    [{r['id']}] {r['prompt'][:50]}...")

    # ── Save Results CSV ───────────────────────────────────────
    if results:
        fieldnames = list(results[0].keys())
        with open(RESULTS_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)
        print(f"\n  Results saved → {RESULTS_CSV}")

    # ── Save Metrics JSON ──────────────────────────────────────
    summary = {
        "total_prompts": len(rows),
        "hybrid_metrics": hybrid_metrics,
        "rule_only_metrics": rule_metrics,
        "per_language_metrics": lang_metrics,
        "latency": latency_stats,
        "false_positives": len(fp_list),
        "false_negatives": len(fn_list),
    }
    with open(METRICS_JSON, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"  Metrics saved  → {METRICS_JSON}")
    print("\nEvaluation complete! ✅")


if __name__ == "__main__":
    main()

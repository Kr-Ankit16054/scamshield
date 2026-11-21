"""ScamShield Phase 3.5: Blind Holdout Evaluation Runner.

Runs HOLDOUT_DATASET.json through the untouched production ScamShield pipeline:
- Computes Multiclass metrics (Accuracy, Precision, Recall, F1)
- Computes Binary Threat metrics (SAFE vs SUSPICIOUS/SCAM)
- Generates 3x3 Multiclass Confusion Matrix
- Calculates latency percentiles (P50, P90, P95, P99, Mean)
- Analyzes every misclassification (False Positives and False Negatives)
- Exports comprehensive reproducible report to HOLDOUT_REPORT.md
"""

import json
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List

from app.engine.explainer import generate_explanation, generate_recommended_action
from app.engine.heuristics import run_all_heuristics
from app.engine.scorer import evaluate_flags


def run_holdout_evaluation(dataset_path: Path) -> Dict[str, Any]:
    with open(dataset_path, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    total_samples = len(dataset)
    results = []
    latencies_ms = []

    classes = ["SAFE", "SUSPICIOUS", "SCAM"]
    confusion_matrix = {act: {pred: 0 for pred in classes} for act in classes}
    category_stats = defaultdict(lambda: {"total": 0, "correct": 0})
    obfuscation_stats = defaultdict(lambda: {"total": 0, "correct": 0})
    scores_by_tier = defaultdict(list)

    batch_start = time.perf_counter()

    for item in dataset:
        msg = item["message"]
        sender = item.get("sender_id")
        gt = item["ground_truth"]
        cat = item["category"]
        obf = item.get("obfuscation_type", "none")

        t0 = time.perf_counter()
        flags = run_all_heuristics(msg, sender)
        score, label = evaluate_flags(flags)
        explanation = generate_explanation(flags, score, label)
        action = generate_recommended_action(flags, score, label)
        duration_ms = (time.perf_counter() - t0) * 1000.0

        latencies_ms.append(duration_ms)
        scores_by_tier[gt].append(score)

        is_correct = (label == gt)
        confusion_matrix[gt][label] += 1

        category_stats[cat]["total"] += 1
        if is_correct:
            category_stats[cat]["correct"] += 1

        obfuscation_stats[obf]["total"] += 1
        if is_correct:
            obfuscation_stats[obf]["correct"] += 1

        results.append({
            "id": item["id"],
            "message": msg,
            "sender_id": sender,
            "ground_truth": gt,
            "predicted_label": label,
            "risk_score": score,
            "flags": flags,
            "latency_ms": duration_ms,
            "category": cat,
            "obfuscation_type": obf,
            "explanation": explanation,
            "recommended_action": action,
            "is_correct": is_correct,
        })

    batch_duration_sec = time.perf_counter() - batch_start

    # Metrics computation
    correct_count = sum(1 for r in results if r["is_correct"])
    accuracy = correct_count / total_samples

    # Per-tier precision, recall, f1
    per_tier_metrics = {}
    for c in classes:
        tp = confusion_matrix[c][c]
        fp = sum(confusion_matrix[other][c] for other in classes if other != c)
        fn = sum(confusion_matrix[c][other] for other in classes if other != c)
        support = sum(confusion_matrix[c].values())

        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

        per_tier_metrics[c] = {
            "support": support,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": prec,
            "recall": rec,
            "f1": f1,
        }

    macro_prec = sum(m["precision"] for m in per_tier_metrics.values()) / len(classes)
    macro_rec = sum(m["recall"] for m in per_tier_metrics.values()) / len(classes)
    macro_f1 = sum(m["f1"] for m in per_tier_metrics.values()) / len(classes)

    # Rates directly derived from Multiclass Confusion Matrix
    # SAFE FPR: Non-SAFE predictions among actual SAFE
    safe_fp = confusion_matrix["SAFE"]["SUSPICIOUS"] + confusion_matrix["SAFE"]["SCAM"]
    safe_fpr = safe_fp / per_tier_metrics["SAFE"]["support"]

    # SCAM FNR: All SCAM misclassifications outside SCAM (predicted as SUSPICIOUS or SAFE)
    scam_fn = confusion_matrix["SCAM"]["SUSPICIOUS"] + confusion_matrix["SCAM"]["SAFE"]
    scam_fnr = scam_fn / per_tier_metrics["SCAM"]["support"]

    # Critical Threat Escape: SCAM misclassified as benign SAFE
    scam_escape_safe = confusion_matrix["SCAM"]["SAFE"]
    scam_escape_rate = scam_escape_safe / per_tier_metrics["SCAM"]["support"]

    # Binary Threat Evaluation (SAFE vs Potential Threat: SUSPICIOUS + SCAM)
    # Actual Threat = SUSPICIOUS + SCAM
    # Actual Safe = SAFE
    binary_tp = (confusion_matrix["SUSPICIOUS"]["SUSPICIOUS"] + confusion_matrix["SUSPICIOUS"]["SCAM"] +
                 confusion_matrix["SCAM"]["SUSPICIOUS"] + confusion_matrix["SCAM"]["SCAM"])
    binary_fn = confusion_matrix["SUSPICIOUS"]["SAFE"] + confusion_matrix["SCAM"]["SAFE"]
    binary_fp = confusion_matrix["SAFE"]["SUSPICIOUS"] + confusion_matrix["SAFE"]["SCAM"]
    binary_tn = confusion_matrix["SAFE"]["SAFE"]

    binary_accuracy = (binary_tp + binary_tn) / total_samples
    binary_prec = binary_tp / (binary_tp + binary_fp) if (binary_tp + binary_fp) > 0 else 0.0
    binary_rec = binary_tp / (binary_tp + binary_fn) if (binary_tp + binary_fn) > 0 else 0.0
    binary_f1 = (2 * binary_prec * binary_rec) / (binary_prec + binary_rec) if (binary_prec + binary_rec) > 0 else 0.0
    binary_fnr = binary_fn / (binary_tp + binary_fn) if (binary_tp + binary_fn) > 0 else 0.0

    # Latency percentiles
    sorted_lats = sorted(latencies_ms)
    p50 = sorted_lats[int(len(sorted_lats) * 0.50)]
    p90 = sorted_lats[int(len(sorted_lats) * 0.90)]
    p95 = sorted_lats[int(len(sorted_lats) * 0.95)]
    p99 = sorted_lats[int(len(sorted_lats) * 0.99)]
    mean_lat = sum(sorted_lats) / len(sorted_lats)

    # Score distribution
    score_stats = {}
    for t in classes:
        s_list = sorted(scores_by_tier[t])
        score_stats[t] = {
            "min": s_list[0] if s_list else 0,
            "mean": round(sum(s_list) / len(s_list), 1) if s_list else 0.0,
            "median": s_list[len(s_list) // 2] if s_list else 0,
            "max": s_list[-1] if s_list else 0,
        }

    discrepancies = [r for r in results if not r["is_correct"]]

    return {
        "total_samples": total_samples,
        "correct_count": correct_count,
        "accuracy": accuracy,
        "macro_precision": macro_prec,
        "macro_recall": macro_rec,
        "macro_f1": macro_f1,
        "safe_fpr": safe_fpr,
        "scam_fnr": scam_fnr,
        "scam_escape_rate": scam_escape_rate,
        "binary_fnr": binary_fnr,
        "binary_metrics": {
            "tp": binary_tp,
            "fp": binary_fp,
            "tn": binary_tn,
            "fn": binary_fn,
            "accuracy": binary_accuracy,
            "precision": binary_prec,
            "recall": binary_rec,
            "f1": binary_f1,
            "fnr": binary_fnr,
        },
        "per_tier_metrics": per_tier_metrics,
        "confusion_matrix": confusion_matrix,
        "latency_stats": {
            "mean_ms": mean_lat,
            "p50_ms": p50,
            "p90_ms": p90,
            "p95_ms": p95,
            "p99_ms": p99,
            "min_ms": sorted_lats[0],
            "max_ms": sorted_lats[-1],
            "batch_duration_sec": batch_duration_sec,
        },
        "score_stats": score_stats,
        "category_stats": dict(category_stats),
        "obfuscation_stats": dict(obfuscation_stats),
        "discrepancies": discrepancies,
    }


def format_markdown_report(eval_data: Dict[str, Any]) -> str:
    cm = eval_data["confusion_matrix"]
    ptm = eval_data["per_tier_metrics"]
    lats = eval_data["latency_stats"]
    bm = eval_data["binary_metrics"]
    ss = eval_data["score_stats"]
    discs = eval_data["discrepancies"]

    md = []
    md.append("# ScamShield: Post-Fix Holdout Evaluation Report\n")
    md.append("## Executive Summary")
    md.append(f"- **Total Post-Fix Holdout Samples**: {eval_data['total_samples']}")
    md.append(f"- **Overall Multiclass Accuracy**: **{eval_data['accuracy']*100:.2f}%** ({eval_data['correct_count']}/{eval_data['total_samples']})")
    md.append(f"- **Macro F1-Score**: **{eval_data['macro_f1']*100:.2f}%**")
    md.append(f"- **Macro Precision**: **{eval_data['macro_precision']*100:.2f}%**")
    md.append(f"- **Macro Recall**: **{eval_data['macro_recall']*100:.2f}%**")
    md.append(f"- **SAFE False Positive Rate (FPR)**: **{eval_data['safe_fpr']*100:.2f}%** ({cm['SAFE']['SUSPICIOUS'] + cm['SAFE']['SCAM']}/{ptm['SAFE']['support']} false alarms)")
    md.append(f"- **Multiclass SCAM FNR**: **{eval_data['scam_fnr']*100:.2f}%** ({cm['SCAM']['SUSPICIOUS'] + cm['SCAM']['SAFE']}/{ptm['SCAM']['support']} non-SCAM predictions)")
    md.append(f"- **Critical Threat Escape Rate (SCAM -> SAFE)**: **{eval_data['scam_escape_rate']*100:.2f}%** ({cm['SCAM']['SAFE']}/{ptm['SCAM']['support']} completely missed)")
    md.append(f"- **Binary Threat FNR (Threat -> SAFE)**: **{eval_data['binary_fnr']*100:.2f}%** ({bm['fn']}/{bm['tp'] + bm['fn']} threats missed as safe)")
    md.append(f"- **Binary Threat Accuracy (Safe vs Threat)**: **{bm['accuracy']*100:.2f}%** (Threat F1: **{bm['f1']*100:.2f}%**)")
    md.append(f"- **Average Processing Latency**: **{lats['mean_ms']:.2f} ms** (P99: **{lats['p99_ms']:.2f} ms**)\n")

    md.append("---\n")
    md.append("## 1. Multiclass Confusion Matrix")
    md.append("| Actual \\ Predicted | Predicted SAFE | Predicted SUSPICIOUS | Predicted SCAM | Total |")
    md.append("| :--- | :---: | :---: | :---: | :---: |")
    md.append(f"| **SAFE** | {cm['SAFE']['SAFE']} | {cm['SAFE']['SUSPICIOUS']} | {cm['SAFE']['SCAM']} | {ptm['SAFE']['support']} |")
    md.append(f"| **SUSPICIOUS** | {cm['SUSPICIOUS']['SAFE']} | {cm['SUSPICIOUS']['SUSPICIOUS']} | {cm['SUSPICIOUS']['SCAM']} | {ptm['SUSPICIOUS']['support']} |")
    md.append(f"| **SCAM** | {cm['SCAM']['SAFE']} | {cm['SCAM']['SUSPICIOUS']} | {cm['SCAM']['SCAM']} | {ptm['SCAM']['support']} |\n")

    md.append("---\n")
    md.append("## 2. Classification Metrics (Per-Tier & Macro Average)")
    md.append("| Class Tier | Support | Precision | Recall | F1-Score | FP | FN |")
    md.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: |")
    for t in ["SAFE", "SUSPICIOUS", "SCAM"]:
        m = ptm[t]
        md.append(f"| **{t}** | {m['support']} | {m['precision']*100:.2f}% | {m['recall']*100:.2f}% | {m['f1']*100:.2f}% | {m['fp']} | {m['fn']} |")
    md.append(f"| **Macro Average** | {eval_data['total_samples']} | {eval_data['macro_precision']*100:.2f}% | {eval_data['macro_recall']*100:.2f}% | {eval_data['macro_f1']*100:.2f}% | {eval_data['total_samples']-eval_data['correct_count']} | {eval_data['total_samples']-eval_data['correct_count']} |\n")

    md.append("---\n")
    md.append("## 3. Binary Threat Detection Performance (Safe vs Threat)")
    md.append("| Metric | Value | Interpretation |")
    md.append("| :--- | :---: | :--- |")
    md.append(f"| **Binary Accuracy** | **{bm['accuracy']*100:.2f}%** | Overall ability to separate benign from any risk |")
    md.append(f"| **Threat Precision** | **{bm['precision']*100:.2f}%** | When flagged as threat, percentage truly threatening |")
    md.append(f"| **Threat Recall** | **{bm['recall']*100:.2f}%** | Percentage of all real threats intercepted |")
    md.append(f"| **Threat F1-Score** | **{bm['f1']*100:.2f}%** | Harmonic balance between threat detection and false alarm avoidance |")
    md.append(f"| **True Positives (Threats)** | {bm['tp']} | Suspicious and Scam correctly isolated from Safe |")
    md.append(f"| **False Positives (Benign Alarmed)** | {bm['fp']} | Legitimate messages incorrectly flagged as threat |")
    md.append(f"| **False Negatives (Threats Missed)** | {bm['fn']} | Threats misclassified as clean SAFE messages |\n")

    md.append("---\n")
    md.append("## 4. Score Distribution Statistics")
    md.append("| Ground Truth Tier | Min Score | Mean Score | Median Score | Max Score |")
    md.append("| :--- | :---: | :---: | :---: | :---: |")
    for t in ["SAFE", "SUSPICIOUS", "SCAM"]:
        md.append(f"| **{t}** | {ss[t]['min']} | {ss[t]['mean']} | {ss[t]['median']} | {ss[t]['max']} |")

    md.append("\n---\n")
    md.append("## 5. Latency Profile")
    md.append(f"- **Mean Latency**: `{lats['mean_ms']:.2f} ms`")
    md.append(f"- **Median (P50)**: `{lats['p50_ms']:.2f} ms`")
    md.append(f"- **90th Percentile (P90)**: `{lats['p90_ms']:.2f} ms`")
    md.append(f"- **95th Percentile (P95)**: `{lats['p95_ms']:.2f} ms`")
    md.append(f"- **99th Percentile (P99)**: `{lats['p99_ms']:.2f} ms`")
    md.append(f"- **Min / Max Latency**: `{lats['min_ms']:.2f} ms` / `{lats['max_ms']:.2f} ms`")
    md.append(f"- **Total Batch Time**: `{lats['batch_duration_sec']:.3f} s` for {eval_data['total_samples']} samples\n")

    md.append("---\n")
    md.append("## 6. Performance by Scenario Category")
    md.append("| Category | Total | Correct | Accuracy |")
    md.append("| :--- | :---: | :---: | :---: |")
    for cat, stats in sorted(eval_data["category_stats"].items()):
        acc = (stats["correct"] / stats["total"]) * 100.0 if stats["total"] > 0 else 0.0
        md.append(f"| {cat} | {stats['total']} | {stats['correct']} | {acc:.1f}% |")

    md.append("\n---\n")
    md.append("## 7. Discrepancy & Error Analysis")
    if not discs:
        md.append("_Zero misclassifications detected across all 100 blind holdout samples._\n")
    else:
        md.append("| ID | Ground Truth | Predicted | Score | Category | Matched Flags | Message Preview |")
        md.append("| :--- | :---: | :---: | :---: | :--- | :--- | :--- |")
        for d in discs:
            flags_str = ", ".join(f"{f.id} (sev={f.severity})" for f in d["flags"]) if d["flags"] else "None"
            prev = d["message"][:45] + ("..." if len(d["message"]) > 45 else "")
            md.append(f"| {d['id']} | **{d['ground_truth']}** | **{d['predicted_label']}** | {d['risk_score']} | {d['category']} | {flags_str} | {prev} |")
        md.append("\n### Detailed Discrepancy Investigation")
        for d in discs:
            md.append(f"#### Sample `{d['id']}`")
            md.append(f"- **Message**: `{d['message']}`")
            md.append(f"- **Sender ID**: `{d['sender_id']}`")
            md.append(f"- **Ground Truth**: `{d['ground_truth']}` | **Predicted**: `{d['predicted_label']}` (Score: {d['risk_score']})")
            md.append(f"- **Flags Detected**: `{[f.id for f in d['flags']]}`")
            md.append(f"- **Explanation**: {d['explanation']}")
            md.append(f"- **Recommended Action**: {d['recommended_action']}\n")

    return "\n".join(md)


def main():
    holdout_path = Path(__file__).resolve().parent / "HOLDOUT_DATASET.json"
    assert holdout_path.exists(), "HOLDOUT_DATASET.json not found"

    print("Evaluating untouched ScamShield pipeline on HOLDOUT_DATASET.json...")
    eval_data = run_holdout_evaluation(holdout_path)

    report_md = format_markdown_report(eval_data)
    out_report = Path(__file__).resolve().parent / "HOLDOUT_REPORT.md"
    with open(out_report, "w", encoding="utf-8") as f:
        f.write(report_md)

    print(report_md)
    print(f"\nHoldout report successfully written to '{out_report}'.")


if __name__ == "__main__":
    main()


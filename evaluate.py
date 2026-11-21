"""ScamShield Phase 3: Adversarial Evaluation & Accuracy Benchmark Runner.

Executes a reproducible, independent 200-sample benchmark across the full
ScamShield deterministic analysis pipeline.
Computes:
- Multiclass Confusion Matrix (SAFE, SUSPICIOUS, SCAM)
- Precision, Recall, F1-score (per-class and macro-averaged)
- False Positive Rate (FPR) on SAFE communications
- False Negative Rate (FNR) on fraudulent threats
- High-resolution latency profiling (Mean, Median P50, P90, P95, P99, Max)
- Score distribution statistics per ground truth tier
- Granular category and obfuscation performance breakdowns
"""

import json
import math
import os
import sys
import time
from collections import defaultdict
from typing import Any, Dict, List, Tuple

try:
    from app.engine.heuristics import run_all_heuristics
    from app.engine.scorer import evaluate_flags
    from app.engine.explainer import generate_explanation, generate_recommended_action
except ModuleNotFoundError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from app.engine.heuristics import run_all_heuristics
    from app.engine.scorer import evaluate_flags
    from app.engine.explainer import generate_explanation, generate_recommended_action


def load_dataset(filepath: str = "benchmark_dataset.json") -> List[Dict[str, Any]]:
    """Loads the benchmark dataset from JSON."""
    if not os.path.exists(filepath):
        # Try relative to script dir
        script_dir = os.path.dirname(os.path.abspath(__file__))
        alt_path = os.path.join(script_dir, filepath)
        if os.path.exists(alt_path):
            filepath = alt_path
        else:
            raise FileNotFoundError(f"Benchmark dataset not found at {filepath}")

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


def run_benchmark(dataset: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Runs all dataset samples through ScamShield pipeline and collects performance metrics."""
    results = []
    latencies_ms = []

    classes = ["SAFE", "SUSPICIOUS", "SCAM"]
    confusion_matrix = {actual: {pred: 0 for pred in classes} for actual in classes}
    category_results = defaultdict(lambda: {"total": 0, "correct": 0})
    obfuscation_results = defaultdict(lambda: {"total": 0, "correct": 0})
    score_distributions = {cls: [] for cls in classes}
    discrepancies = []

    # Warmup
    _ = run_all_heuristics("Warmup message check with shortener https://bit.ly/test and OTP 123456.")

    total_start = time.perf_counter()

    for sample in dataset:
        s_id = sample["id"]
        message = sample["message"]
        sender_id = sample.get("sender_id")
        ground_truth = sample["ground_truth"]
        category = sample.get("category", "Uncategorized")
        obf_type = sample.get("obfuscation_type", "none")

        t0 = time.perf_counter()
        flags = run_all_heuristics(message, sender_id=sender_id)
        score, label = evaluate_flags(flags)
        _ = generate_explanation(flags, score, label)
        _ = generate_recommended_action(flags, score, label)
        duration_ms = (time.perf_counter() - t0) * 1000

        latencies_ms.append(duration_ms)
        confusion_matrix[ground_truth][label] += 1
        score_distributions[ground_truth].append(score)

        is_correct = (label == ground_truth)
        category_results[category]["total"] += 1
        if is_correct:
            category_results[category]["correct"] += 1

        obfuscation_results[obf_type]["total"] += 1
        if is_correct:
            obfuscation_results[obf_type]["correct"] += 1

        if not is_correct:
            discrepancies.append({
                "id": s_id,
                "category": category,
                "obfuscation_type": obf_type,
                "ground_truth": ground_truth,
                "predicted": label,
                "score": score,
                "flags": [f"{f.id} (sev={f.severity})" for f in flags],
                "message": message,
            })

        results.append({
            "id": s_id,
            "ground_truth": ground_truth,
            "predicted": label,
            "score": score,
            "latency_ms": duration_ms,
            "flags_count": len(flags),
        })

    total_duration_sec = time.perf_counter() - total_start

    # Metrics computation
    total_samples = len(dataset)
    correct_total = sum(confusion_matrix[c][c] for c in classes)
    accuracy = correct_total / total_samples

    # Per-class metrics
    class_metrics = {}
    for c in classes:
        tp = confusion_matrix[c][c]
        fp = sum(confusion_matrix[other][c] for other in classes if other != c)
        fn = sum(confusion_matrix[c][other] for other in classes if other != c)
        tn = total_samples - (tp + fp + fn)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        class_metrics[c] = {
            "TP": tp,
            "FP": fp,
            "FN": fn,
            "TN": tn,
            "support": sum(confusion_matrix[c].values()),
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }

    macro_precision = sum(m["precision"] for m in class_metrics.values()) / len(classes)
    macro_recall = sum(m["recall"] for m in class_metrics.values()) / len(classes)
    macro_f1 = sum(m["f1"] for m in class_metrics.values()) / len(classes)

    # False Positive Rate on SAFE: proportion of SAFE predicted as SUSPICIOUS or SCAM
    safe_total = class_metrics["SAFE"]["support"]
    safe_fps = class_metrics["SAFE"]["FP"]  # items where actual was not SAFE but predicted SAFE
    # Actually, false positive for SAFE means Actual is SAFE, but predicted != SAFE
    safe_false_positives = sum(confusion_matrix["SAFE"][p] for p in ("SUSPICIOUS", "SCAM"))
    safe_fpr = safe_false_positives / safe_total if safe_total > 0 else 0.0

    # False Negative Rate on SCAM: proportion of actual SCAM predicted as SAFE
    scam_total = class_metrics["SCAM"]["support"]
    scam_missed_as_safe = confusion_matrix["SCAM"]["SAFE"]
    scam_fnr = scam_missed_as_safe / scam_total if scam_total > 0 else 0.0

    # Overall Threat Miss Rate: (Actual SCAM or SUSPICIOUS) predicted as SAFE
    threat_total = class_metrics["SCAM"]["support"] + class_metrics["SUSPICIOUS"]["support"]
    threat_missed = confusion_matrix["SCAM"]["SAFE"] + confusion_matrix["SUSPICIOUS"]["SAFE"]
    threat_fnr = threat_missed / threat_total if threat_total > 0 else 0.0

    # Latency percentiles
    sorted_latencies = sorted(latencies_ms)
    def percentile(p: float) -> float:
        k = (len(sorted_latencies) - 1) * (p / 100.0)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return sorted_latencies[int(k)]
        d0 = sorted_latencies[int(f)] * (c - k)
        d1 = sorted_latencies[int(c)] * (k - f)
        return d0 + d1

    latency_stats = {
        "mean_ms": sum(latencies_ms) / len(latencies_ms),
        "median_p50_ms": percentile(50.0),
        "p90_ms": percentile(90.0),
        "p95_ms": percentile(95.0),
        "p99_ms": percentile(99.0),
        "min_ms": min(latencies_ms),
        "max_ms": max(latencies_ms),
        "total_time_sec": total_duration_sec,
    }

    # Score distribution stats
    score_stats = {}
    for c in classes:
        scores = score_distributions[c]
        if scores:
            scores_sorted = sorted(scores)
            score_stats[c] = {
                "min": min(scores),
                "max": max(scores),
                "mean": sum(scores) / len(scores),
                "median": scores_sorted[len(scores_sorted) // 2],
            }
        else:
            score_stats[c] = {"min": 0, "max": 0, "mean": 0.0, "median": 0}

    return {
        "total_samples": total_samples,
        "accuracy": accuracy,
        "macro_precision": macro_precision,
        "macro_recall": macro_recall,
        "macro_f1": macro_f1,
        "class_metrics": class_metrics,
        "confusion_matrix": confusion_matrix,
        "safe_false_positives": safe_false_positives,
        "safe_fpr": safe_fpr,
        "scam_missed_as_safe": scam_missed_as_safe,
        "scam_fnr": scam_fnr,
        "threat_fnr": threat_fnr,
        "latency_stats": latency_stats,
        "score_stats": score_stats,
        "category_results": dict(category_results),
        "obfuscation_results": dict(obfuscation_results),
        "discrepancies": discrepancies,
    }


def generate_report(metrics: Dict[str, Any]) -> str:
    """Formats benchmark results into a clean, comprehensive Markdown report."""
    classes = ["SAFE", "SUSPICIOUS", "SCAM"]
    cm = metrics["confusion_matrix"]
    cm_text = (
        "| Actual \\ Predicted | Predicted SAFE | Predicted SUSPICIOUS | Predicted SCAM | Total |\n"
        "| :--- | :---: | :---: | :---: | :---: |\n"
    )
    for actual in classes:
        row_tot = sum(cm[actual].values())
        cm_text += f"| **{actual}** | {cm[actual]['SAFE']} | {cm[actual]['SUSPICIOUS']} | {cm[actual]['SCAM']} | {row_tot} |\n"

    # Per-class table
    cls_text = (
        "| Class | Support | Precision | Recall | F1-Score |\n"
        "| :--- | :---: | :---: | :---: | :---: |\n"
    )
    for c in classes:
        m = metrics["class_metrics"][c]
        cls_text += f"| **{c}** | {m['support']} | {m['precision']*100:.2f}% | {m['recall']*100:.2f}% | {m['f1']*100:.2f}% |\n"
    cls_text += f"| **Macro Average** | {metrics['total_samples']} | {metrics['macro_precision']*100:.2f}% | {metrics['macro_recall']*100:.2f}% | {metrics['macro_f1']*100:.2f}% |\n"

    # Score stats table
    score_text = (
        "| Ground Truth Tier | Min Score | Mean Score | Median Score | Max Score |\n"
        "| :--- | :---: | :---: | :---: | :---: |\n"
    )
    for c in classes:
        st = metrics["score_stats"][c]
        score_text += f"| **{c}** | {st['min']} | {st['mean']:.1f} | {st['median']} | {st['max']} |\n"

    # Category performance table
    cat_text = (
        "| Category | Total Samples | Correct | Accuracy |\n"
        "| :--- | :---: | :---: | :---: |\n"
    )
    for cat, res in sorted(metrics["category_results"].items()):
        acc = (res["correct"] / res["total"]) * 100 if res["total"] > 0 else 0
        cat_text += f"| {cat} | {res['total']} | {res['correct']} | {acc:.1f}% |\n"

    # Obfuscation performance table
    obf_text = (
        "| Obfuscation Type | Total Samples | Correct | Accuracy |\n"
        "| :--- | :---: | :---: | :---: |\n"
    )
    for obf, res in sorted(metrics["obfuscation_results"].items()):
        acc = (res["correct"] / res["total"]) * 100 if res["total"] > 0 else 0
        obf_text += f"| {obf} | {res['total']} | {res['correct']} | {acc:.1f}% |\n"

    # Discrepancies table
    disc_text = ""
    if metrics["discrepancies"]:
        disc_text = (
            "| ID | Ground Truth | Predicted | Score | Category | Matched Flags | Message Preview |\n"
            "| :--- | :---: | :---: | :---: | :--- | :--- | :--- |\n"
        )
        for d in metrics["discrepancies"]:
            flags_str = ", ".join(d["flags"]) if d["flags"] else "None"
            msg_snippet = d["message"][:45] + "..." if len(d["message"]) > 45 else d["message"]
            disc_text += f"| {d['id']} | **{d['ground_truth']}** | **{d['predicted']}** | {d['score']} | {d['category']} | {flags_str} | {msg_snippet} |\n"
    else:
        disc_text = "_Zero misclassifications detected across all 200 evaluation samples (100% accuracy)._\n"

    lat = metrics["latency_stats"]

    report = f"""# ScamShield Phase 3: Adversarial Benchmark & Accuracy Evaluation Report

## Executive Summary
- **Total Samples Evaluated**: {metrics['total_samples']}
- **Overall Accuracy**: **{metrics['accuracy']*100:.2f}%**
- **Macro F1-Score**: **{metrics['macro_f1']*100:.2f}%**
- **Macro Precision**: **{metrics['macro_precision']*100:.2f}%**
- **Macro Recall**: **{metrics['macro_recall']*100:.2f}%**
- **False Positive Rate on SAFE**: **{metrics['safe_fpr']*100:.2f}%** ({metrics['safe_false_positives']}/{metrics['class_metrics']['SAFE']['support']} false alarms)
- **False Negative Rate on SCAM**: **{metrics['scam_fnr']*100:.2f}%** ({metrics['scam_missed_as_safe']}/{metrics['class_metrics']['SCAM']['support']} missed scams)
- **Overall Threat Miss Rate**: **{metrics['threat_fnr']*100:.2f}%**
- **Average Pipeline Latency**: **{lat['mean_ms']:.2f} ms** per message (P99: **{lat['p99_ms']:.2f} ms**)

---

## 1. Multiclass Confusion Matrix
{cm_text}

---

## 2. Classification Metrics (Per-Tier & Macro Average)
{cls_text}

---

## 3. Score Distribution Statistics
{score_text}

---

## 4. Latency Profile
- **Mean Processing Time**: `{lat['mean_ms']:.2f} ms`
- **Median (P50) Latency**: `{lat['median_p50_ms']:.2f} ms`
- **90th Percentile (P90)**: `{lat['p90_ms']:.2f} ms`
- **95th Percentile (P95)**: `{lat['p95_ms']:.2f} ms`
- **99th Percentile (P99)**: `{lat['p99_ms']:.2f} ms`
- **Min Latency**: `{lat['min_ms']:.2f} ms`
- **Max Latency**: `{lat['max_ms']:.2f} ms`
- **Total Batch Execution Time**: `{lat['total_time_sec']:.3f} s` for {metrics['total_samples']} full pipeline analyses

---

## 5. Performance by Scenario Category
{cat_text}

---

## 6. Performance by Evasion / Obfuscation Technique
{obf_text}

---

## 7. Discrepancy & Error Analysis
{disc_text}
"""
    return report


if __name__ == "__main__":
    dataset_file = sys.argv[1] if len(sys.argv) > 1 else "benchmark_dataset.json"
    dataset = load_dataset(dataset_file)
    print(f"Loaded {len(dataset)} evaluation samples from '{dataset_file}'.")
    print("Executing full ScamShield pipeline evaluation...")

    results = run_benchmark(dataset)
    report_md = generate_report(results)

    # Save to disk
    with open("BENCHMARK_REPORT.md", "w", encoding="utf-8") as f:
        f.write(report_md)

    print(report_md)
    print("Evaluation complete. Report saved to 'BENCHMARK_REPORT.md'.")


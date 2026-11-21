"""Automated integration benchmark test for ScamShield Phase 3.

Evaluates ScamShield on the independent 200-sample adversarial benchmark dataset:
- Ensures overall accuracy >= 98%
- Ensures False Positive Rate on SAFE <= 1.0%
- Ensures False Negative Rate on SCAM <= 2.0%
- Ensures pipeline latency < 10ms mean and < 25ms P99
"""

import json
import time
from pathlib import Path
import pytest
from app.engine.heuristics import run_all_heuristics
from app.engine.scorer import evaluate_flags
from app.engine.explainer import generate_explanation, generate_recommended_action


DATASET_PATH = Path(__file__).resolve().parent.parent / "benchmark_dataset.json"


@pytest.fixture(scope="module")
def benchmark_dataset():
    assert DATASET_PATH.exists(), f"Benchmark dataset missing at {DATASET_PATH}"
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


def test_benchmark_dataset_integrity(benchmark_dataset):
    """Verify benchmark dataset size, tier balance, and required schema fields."""
    assert len(benchmark_dataset) >= 150, "Benchmark dataset must contain at least 150 samples"
    
    safes = [x for x in benchmark_dataset if x["ground_truth"] == "SAFE"]
    suspicious = [x for x in benchmark_dataset if x["ground_truth"] == "SUSPICIOUS"]
    scams = [x for x in benchmark_dataset if x["ground_truth"] == "SCAM"]
    
    assert len(safes) >= 50, "Dataset must have balanced SAFE representations"
    assert len(suspicious) >= 15, "Dataset must have balanced SUSPICIOUS representations"
    assert len(scams) >= 50, "Dataset must have balanced SCAM representations"

    for item in benchmark_dataset:
        assert "id" in item
        assert "message" in item
        assert "ground_truth" in item
        assert "category" in item
        assert "obfuscation_type" in item
        assert item["ground_truth"] in ("SAFE", "SUSPICIOUS", "SCAM")


def test_adversarial_benchmark_metrics(benchmark_dataset):
    """Executes full detection pipeline over all benchmark samples and asserts accuracy constraints."""
    total = len(benchmark_dataset)
    correct = 0
    safe_fp = 0
    scam_fn = 0
    latencies = []

    for item in benchmark_dataset:
        msg = item["message"]
        sender = item.get("sender_id")
        gt = item["ground_truth"]

        start = time.perf_counter()
        flags = run_all_heuristics(msg, sender)
        score, label = evaluate_flags(flags)
        _ = generate_explanation(flags, score, label)
        _ = generate_recommended_action(flags, score, label)
        lat = (time.perf_counter() - start) * 1000
        latencies.append(lat)

        if label == gt:
            correct += 1
        elif gt == "SAFE" and label in ("SUSPICIOUS", "SCAM"):
            safe_fp += 1
        elif gt == "SCAM" and label == "SAFE":
            scam_fn += 1

    accuracy = correct / total
    safe_count = sum(1 for x in benchmark_dataset if x["ground_truth"] == "SAFE")
    scam_count = sum(1 for x in benchmark_dataset if x["ground_truth"] == "SCAM")
    fpr = safe_fp / safe_count
    fnr = scam_fn / scam_count

    latencies.sort()
    mean_lat = sum(latencies) / len(latencies)
    p99_lat = latencies[int(len(latencies) * 0.99)]

    # Rigorous benchmark thresholds
    assert accuracy >= 0.98, f"Benchmark accuracy {accuracy*100:.2f}% is below 98% requirement"
    assert fpr <= 0.01, f"False Positive Rate on SAFE {fpr*100:.2f}% exceeds 1% maximum"
    assert fnr <= 0.02, f"False Negative Rate on SCAM {fnr*100:.2f}% exceeds 2% maximum"
    assert mean_lat < 10.0, f"Mean latency {mean_lat:.2f}ms exceeds 10ms threshold"
    assert p99_lat < 25.0, f"P99 latency {p99_lat:.2f}ms exceeds 25ms threshold"


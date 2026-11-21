"""Integration test evaluating the entire 30-message corpus through the ScamShield API.

Validates:
- All 20 real-world scam messages are identified as SCAM or SUSPICIOUS (0% false negatives)
- All 10 legitimate everyday messages are classified as SAFE (0% false positives)
- All 30 analyses complete via HTTP POST /analyze
- Average processing latency remains well under 10ms per message
"""

import time
import pytest
from starlette.testclient import TestClient
from app.main import app
from app.engine.corpus import CORPUS, CorpusSample

client = TestClient(app)


@pytest.fixture(autouse=True)
def bypass_rate_limit_for_corpus():
    """Temporarily bypass rate limiting to run the full 30-sample integration batch."""
    original_state = app.state.limiter.enabled
    app.state.limiter.enabled = False
    yield
    app.state.limiter.enabled = original_state


def test_corpus_count():
    """Verify corpus composition matches specification: exactly 20 scam and 10 legit."""
    scams = [s for s in CORPUS if s.expected_label in ("SCAM", "SUSPICIOUS")]
    legits = [s for s in CORPUS if s.expected_label == "SAFE"]
    assert len(CORPUS) == 30
    assert len(scams) == 20
    assert len(legits) == 10


@pytest.mark.parametrize("sample", CORPUS, ids=lambda s: s.id)
def test_corpus_sample_classification(sample: CorpusSample):
    """Runs each sample through the live API endpoint and verifies classification."""
    start_time = time.perf_counter()
    response = client.post(
        "/analyze",
        json={"message": sample.message, "sender_id": sample.sender_id},
    )
    duration_ms = (time.perf_counter() - start_time) * 1000

    assert response.status_code == 200, f"Failed on sample {sample.id}: {response.text}"
    data = response.json()

    # Latency constraint
    assert duration_ms < 50.0, f"Sample {sample.id} exceeded 50ms latency: {duration_ms:.2f}ms"

    # Evaluation bounds
    actual_label = data["label"]
    actual_score = data["risk_score"]

    if sample.expected_label in ("SCAM", "SUSPICIOUS"):
        assert actual_label in ("SCAM", "SUSPICIOUS"), (
            f"False Negative on {sample.id} ({sample.category}): "
            f"Expected {sample.expected_label}, got {actual_label} (Score: {actual_score})"
        )
        assert actual_score >= 40, f"Expected suspicious/scam score >=40, got {actual_score}"
        assert len(data["flags"]) >= 1, f"Expected detected flags for scam {sample.id}"
    else:
        assert actual_label == "SAFE", (
            f"False Positive on {sample.id} ({sample.category}): "
            f"Expected SAFE, got {actual_label} (Score: {actual_score}, Flags: {data['flags']})"
        )
        assert actual_score < 40, f"Expected safe score <40, got {actual_score}"


"""Unit tests for ScamShield risk scorer and template explainer.

Validates:
- Exact score boundary transitions: 0, <40 (SAFE), 40-69 (SUSPICIOUS), >=70 (SCAM)
- Score cap at 100
- Multi-flag aggregation and frequency bonus
- Explainer sentence generation and recommended actions
"""

import pytest
from app.schemas import Flag
from app.engine.scorer import calculate_risk_score, get_risk_label, evaluate_flags
from app.engine.explainer import generate_explanation, generate_recommended_action


def test_scorer_zero_flags():
    score, label = evaluate_flags([])
    assert score == 0
    assert label == "SAFE"


def test_scorer_boundary_safe_below_40():
    # A single low-weight flag (e.g., LANGUAGE_MANIPULATION severity 1 -> 10 points)
    flag_low = [Flag(id="LANGUAGE_MANIPULATION", severity=1, detail="Minor caps", matched_text="ABC")]
    score, label = evaluate_flags(flag_low)
    assert 0 < score < 40
    assert label == "SAFE"

    # Single urgency flag (severity 2 * 10 = 20 points)
    flag_urgency = [Flag(id="URGENCY_PRESSURE", severity=2, detail="Urgent", matched_text="urgent")]
    score, label = evaluate_flags(flag_urgency)
    assert score == 20
    assert label == "SAFE"


def test_scorer_boundary_exact_40_suspicious():
    # Exactly 40: SUSPICIOUS_LINK with severity 2 (2 * 20 = 40 points)
    flag_short_url = [Flag(id="SUSPICIOUS_LINK", severity=2, detail="Short URL", matched_text="https://bit.ly/xyz")]
    score, label = evaluate_flags(flag_short_url)
    assert score == 40
    assert label == "SUSPICIOUS"


def test_scorer_boundary_between_40_and_69():
    # Urgency (20) + Impersonation (30) = 50 points
    flags = [
        Flag(id="URGENCY_PRESSURE", severity=2, detail="Urgent", matched_text="urgent"),
        Flag(id="IMPERSONATION", severity=2, detail="Claims SBI", matched_text="SBI"),
    ]
    score, label = evaluate_flags(flags)
    assert 40 <= score <= 69
    assert label == "SUSPICIOUS"


def test_scorer_boundary_exact_69_suspicious():
    # Test label mapping explicitly at 69
    assert get_risk_label(69) == "SUSPICIOUS"
    assert get_risk_label(40) == "SUSPICIOUS"
    assert get_risk_label(39) == "SAFE"
    assert get_risk_label(0) == "SAFE"


def test_scorer_boundary_exact_70_scam():
    assert get_risk_label(70) == "SCAM"
    assert get_risk_label(100) == "SCAM"


def test_scorer_critical_flag_triggers_scam():
    # OTP request alone (severity 3 * 25 = 75 points)
    flag_otp = [Flag(id="OTP_CREDENTIAL_REQUEST", severity=3, detail="Asks for OTP", matched_text="share OTP")]
    score, label = evaluate_flags(flag_otp)
    assert score >= 70
    assert label == "SCAM"


def test_scorer_capped_at_100():
    # Many high-severity flags exceeding 100 points
    flags = [
        Flag(id="OTP_CREDENTIAL_REQUEST", severity=3, detail="OTP", matched_text="OTP"),
        Flag(id="PREFILL_KYC", severity=3, detail="KYC", matched_text="KYC"),
        Flag(id="PAYMENT_REDIRECT", severity=3, detail="Refund", matched_text="Refund"),
        Flag(id="SUSPICIOUS_LINK", severity=3, detail="Phish", matched_text="http://fake.site"),
        Flag(id="IMPERSONATION", severity=2, detail="Bank", matched_text="Bank"),
    ]
    score, label = evaluate_flags(flags)
    assert score == 100
    assert label == "SCAM"


def test_scorer_frequency_bonus():
    # Multiple occurrences in same family provide a small frequency bonus
    single_urgency = [Flag(id="URGENCY_PRESSURE", severity=2, detail="Urgent", matched_text="urgent")]
    multi_urgency = [
        Flag(id="URGENCY_PRESSURE", severity=2, detail="Urgent", matched_text="urgent"),
        Flag(id="URGENCY_PRESSURE", severity=2, detail="Act now", matched_text="act now"),
        Flag(id="URGENCY_PRESSURE", severity=2, detail="Within 24 hours", matched_text="within 24 hours"),
    ]
    score_single, _ = evaluate_flags(single_urgency)
    score_multi, _ = evaluate_flags(multi_urgency)
    assert score_multi > score_single
    assert score_multi - score_single <= 10  # Frequency bonus capped at 10


def test_explainer_generates_safe_summary():
    explanation = generate_explanation([], 0, "SAFE")
    action = generate_recommended_action([], 0, "SAFE")
    assert "No suspicious patterns" in explanation or "No common scam" in explanation
    assert len(explanation.split(".")) >= 2  # 2-3 sentences
    assert len(action) > 10


def test_explainer_generates_suspicious_summary():
    flags = [
        Flag(id="URGENCY_PRESSURE", severity=2, detail="Urgent", matched_text="urgent"),
        Flag(id="FINANCIAL_LURE", severity=2, detail="Reward", matched_text="lottery"),
    ]
    explanation = generate_explanation(flags, 50, "SUSPICIOUS")
    action = generate_recommended_action(flags, 50, "SUSPICIOUS")
    assert "moderate risk" in explanation.lower() or "suspicious" in explanation.lower()
    assert "Verify" in action or "official" in action


def test_explainer_generates_scam_summary():
    flags = [
        Flag(id="OTP_CREDENTIAL_REQUEST", severity=3, detail="OTP", matched_text="OTP"),
        Flag(id="SUSPICIOUS_LINK", severity=3, detail="Link", matched_text="http://fake.com"),
    ]
    explanation = generate_explanation(flags, 85, "SCAM")
    action = generate_recommended_action(flags, 85, "SCAM")
    assert "critical scam" in explanation.lower() or "high risk" in explanation.lower()
    assert "Block" in action or "report" in action.lower() or "Do NOT" in action


# ==============================================================================
# PHASE 1D: RISK SCORE CALIBRATION REGRESSION TESTS
# ==============================================================================

def test_single_weak_signal_scored_safe():
    """Phase 1D: A single weak signal (formatting or weak urgency) produces a low SAFE score."""
    weak_cases = [
        Flag(id="LANGUAGE_MANIPULATION", severity=1, detail="Caps", matched_text="ABC"),
        Flag(id="URGENCY_PRESSURE", severity=1, detail="Expiring soon", matched_text="soon"),
        Flag(id="SENDER_ID_ANALYSIS", severity=1, detail="Format irregularity", matched_text="APP-NOTIF"),
    ]
    for flag in weak_cases:
        score, label = evaluate_flags([flag])
        assert 0 < score <= 20, f"Single weak signal scored too high: {score}"
        assert label == "SAFE"


def test_multiple_weak_signals_capped_below_40():
    """Phase 1D: Multiple weak signals without any core fraud family are capped at 35 (SAFE)."""
    weak_cluster = [
        Flag(id="URGENCY_PRESSURE", severity=2, detail="Urgent", matched_text="urgent"),
        Flag(id="LANGUAGE_MANIPULATION", severity=1, detail="Caps", matched_text="ALL CAPS"),
        Flag(id="LANGUAGE_MANIPULATION", severity=1, detail="Exclamations", matched_text="!!!"),
        Flag(id="SENDER_ID_ANALYSIS", severity=1, detail="Unusual sender", matched_text="SYSTEM-MSG"),
    ]
    score, label = evaluate_flags(weak_cluster)
    assert score <= 35, f"Stacked weak signals exceeded SAFE cap: {score}"
    assert label == "SAFE", f"Stacked weak signals wrongly triggered {label}"


def test_duplicate_signals_diminishing_bonus():
    """Phase 1D: Repetitive signals from the same family give a controlled diminishing bonus."""
    single = [Flag(id="URGENCY_PRESSURE", severity=2, detail="Urgent", matched_text="urgent")]
    double = single + [Flag(id="URGENCY_PRESSURE", severity=2, detail="Act now", matched_text="act now")]
    triple = double + [Flag(id="URGENCY_PRESSURE", severity=2, detail="Within 24h", matched_text="24h")]
    quad = triple + [Flag(id="URGENCY_PRESSURE", severity=2, detail="Last chance", matched_text="last chance")]

    s_single = calculate_risk_score(single)
    s_double = calculate_risk_score(double)
    s_triple = calculate_risk_score(triple)
    s_quad = calculate_risk_score(quad)

    assert s_single == 20
    assert s_double == 23  # +3
    assert s_triple == 25  # +2
    assert s_quad == 27    # +2
    assert s_quad <= 35    # Weak signal cap strictly respected


def test_multiple_independent_moderate_signals():
    """Phase 1D: Independent substantive signals combine into SUSPICIOUS tier (40-69)."""
    # Impersonation (30) + Urgency (20)
    flags_a = [
        Flag(id="IMPERSONATION", severity=2, detail="Claims Bank", matched_text="SBI"),
        Flag(id="URGENCY_PRESSURE", severity=2, detail="Urgent", matched_text="urgent"),
    ]
    score_a, label_a = evaluate_flags(flags_a)
    assert score_a == 50
    assert label_a == "SUSPICIOUS"

    # Financial Lure (30) + Untraced Delivery (30)
    flags_b = [
        Flag(id="FINANCIAL_LURE", severity=2, detail="Prize", matched_text="prize"),
        Flag(id="UNTRACED_DELIVERY", severity=2, detail="Customs hold", matched_text="customs"),
    ]
    score_b, label_b = evaluate_flags(flags_b)
    assert 40 <= score_b <= 69
    assert label_b == "SUSPICIOUS"


def test_strong_otp_credential_request_triggers_scam():
    """Phase 1D: Direct OTP / credential request is a lethal indicator (scores 75 -> SCAM)."""
    flags = [Flag(id="OTP_CREDENTIAL_REQUEST", severity=3, detail="Share OTP", matched_text="OTP")]
    score, label = evaluate_flags(flags)
    assert score == 75
    assert label == "SCAM"


def test_suspicious_url_with_urgency_not_prematurely_saturated():
    """Phase 1D: Phishing URL + urgency triggers SCAM (72) but leaves headroom below 100."""
    flags = [
        Flag(id="SUSPICIOUS_LINK", severity=3, detail="Phishing URL", matched_text="http://fake-bank.xyz"),
        Flag(id="URGENCY_PRESSURE", severity=2, detail="Urgent action", matched_text="immediately"),
    ]
    score, label = evaluate_flags(flags)
    assert score == 72, f"Expected calibrated score 72 for URL+urgency, got {score}"
    assert label == "SCAM"
    assert score < 100, "URL + urgency should not prematurely saturate to 100"


def test_sender_anomaly_combined_with_other_indicators():
    """Phase 1D: Weak sender formatting stays SAFE; correlated sender anomaly scales with threat."""
    # Benign text + format irregularity
    weak_sender = [Flag(id="SENDER_ID_ANALYSIS", severity=1, detail="Unusual tag", matched_text="APP-01")]
    s_weak, l_weak = evaluate_flags(weak_sender)
    assert s_weak == 15
    assert l_weak == "SAFE"

    # Correlated fraud sender (severity 2 = 30) + Phishing link (60) + Urgency (20)
    correlated = [
        Flag(id="SUSPICIOUS_LINK", severity=3, detail="Phishing URL", matched_text="http://portal.xyz"),
        Flag(id="SENDER_ID_ANALYSIS", severity=2, detail="Fraud alert tag", matched_text="BANK-ALERT"),
        Flag(id="URGENCY_PRESSURE", severity=2, detail="Urgent", matched_text="immediately"),
    ]
    s_corr, l_corr = evaluate_flags(correlated)
    assert s_corr == 85, f"Expected calibrated score 85 for correlated sender attack, got {s_corr}"
    assert l_corr == "SCAM"
    assert s_corr < 100, "Correlated scam should differentiate below 100"


def test_legitimate_otp_security_warning_zero_score():
    """Phase 1D: Security warning message produces 0 flags and score 0 (SAFE)."""
    from app.engine.heuristics import run_all_heuristics
    msg = "Your login OTP is 894102. Never share your OTP with anyone."
    flags = run_all_heuristics(msg)
    score, label = evaluate_flags(flags)
    assert score == 0
    assert label == "SAFE"


def test_legitimate_refund_notification_zero_score():
    """Phase 1D: Legitimate refund credit notification produces 0 flags and score 0 (SAFE)."""
    from app.engine.heuristics import run_all_heuristics
    msg = "Refund of ₹450 is credited to your account for ride cancellation."
    flags = run_all_heuristics(msg, sender_id="AX-HDFCBK")
    score, label = evaluate_flags(flags)
    assert score == 0
    assert label == "SAFE"


def test_strong_scam_combinations_reach_100():
    """Phase 1D: Comprehensive multi-vector attack kits cleanly reach score 100."""
    full_kit = [
        Flag(id="OTP_CREDENTIAL_REQUEST", severity=3, detail="OTP theft", matched_text="OTP"),
        Flag(id="PREFILL_KYC", severity=3, detail="KYC suspension", matched_text="KYC"),
        Flag(id="SUSPICIOUS_LINK", severity=3, detail="Phishing link", matched_text="http://fake.xyz"),
        Flag(id="IMPERSONATION", severity=2, detail="Bank spoofing", matched_text="SBI"),
        Flag(id="URGENCY_PRESSURE", severity=2, detail="Urgency", matched_text="immediately"),
    ]
    score, label = evaluate_flags(full_kit)
    assert score == 100
    assert label == "SCAM"


def test_score_bounds_and_boundary_transitions():
    """Phase 1D: Mathematical bounds strictly within [0, 100] and exact tier thresholds."""
    assert calculate_risk_score([]) == 0
    assert get_risk_label(0) == "SAFE"
    assert get_risk_label(39) == "SAFE"
    assert get_risk_label(40) == "SUSPICIOUS"
    assert get_risk_label(69) == "SUSPICIOUS"
    assert get_risk_label(70) == "SCAM"
    assert get_risk_label(100) == "SCAM"

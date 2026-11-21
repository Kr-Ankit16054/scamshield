"""ScamShield Risk Scorer.

Combines detected heuristic flags into a calibrated 0-100 risk score and risk tier label:
- >=70 : SCAM (High risk / Fraud)
- 40-69: SUSPICIOUS (Moderate risk / Phishing cues)
- <40  : SAFE (Low risk / Routine communications)

Mathematical Model (Calibrated Diminishing Returns):
1. Evaluates each detected heuristic family by taking its highest severity.
2. The lead threat family contributes 100% of its base weight.
3. Secondary and tertiary families contribute with calibrated diminishing returns
   to avoid premature saturation while allowing strong scam combinations to cleanly
   differentiate up to 100.
4. Purely contextual/weak signals (urgency, formatting, non-standard sender tag) without
   any substantive or critical fraud factor are capped at 35 (guaranteeing SAFE classification).
5. Duplicate occurrences within the same family provide a small, diminishing frequency bonus.
"""

from typing import Dict, List, Literal, Set, Tuple

try:
    from app.schemas import Flag
except ModuleNotFoundError:
    from scamshield.app.schemas import Flag

# Configurable weights per heuristic family reflecting real-world fraud danger
FAMILY_WEIGHTS: Dict[str, int] = {
    "OTP_CREDENTIAL_REQUEST": 25,   # Critical: 3 * 25 = 75 (Immediate SCAM trigger)
    "REMOTE_ACCESS_APP": 25,        # Critical: 3 * 25 = 75 (Immediate SCAM trigger)
    "JOB_OFFER_SCAM": 25,           # Critical: 3 * 25 = 75 (Immediate SCAM trigger)
    "FINANCIAL_LURE": 25,           # Critical: 3 * 25 = 75 (Immediate SCAM trigger)
    "PREFILL_KYC": 20,              # Critical: 3 * 20 = 60
    "PAYMENT_REDIRECT": 20,         # Critical: 3 * 20 = 60
    "SUSPICIOUS_LINK": 20,          # High: 2 * 20 = 40 (Suspicious threshold), 3 * 20 = 60
    "CONTACT_MISMATCH": 20,         # High: 2 * 20 = 40
    "IMPERSONATION": 15,            # High: 2 * 15 = 30
    "UNTRACED_DELIVERY": 15,        # High: 2 * 15 = 30
    "SENDER_ID_ANALYSIS": 15,       # Moderate to High: 1 * 15 = 15, 2 * 15 = 30
    "URGENCY_PRESSURE": 10,         # Moderate: 1 * 10 = 10, 2 * 10 = 20
    "LANGUAGE_MANIPULATION": 10,    # Low to Moderate: 1 * 10 = 10, 2 * 10 = 20
}

# Core fraud indicator families that represent active social engineering or credential/money theft
CORE_FRAUD_FAMILIES: Set[str] = {
    "OTP_CREDENTIAL_REQUEST",
    "REMOTE_ACCESS_APP",
    "PREFILL_KYC",
    "PAYMENT_REDIRECT",
    "SUSPICIOUS_LINK",
    "FINANCIAL_LURE",
    "IMPERSONATION",
    "CONTACT_MISMATCH",
    "UNTRACED_DELIVERY",
    "JOB_OFFER_SCAM",
}

RiskLabel = Literal["SAFE", "SUSPICIOUS", "SCAM"]


def get_risk_label(score: int) -> RiskLabel:
    """Maps a 0-100 score to its calibrated classification tier."""
    if score >= 70:
        return "SCAM"
    if score >= 40:
        return "SUSPICIOUS"
    return "SAFE"


def calculate_risk_score(flags: List[Flag]) -> int:
    """Computes an aggregate calibrated risk score (0-100) based on detected flags and severities.

    Prevents premature saturation, limits accumulation of weak signals, and accurately
    differentiates moderate phishing cues from lethal credential attacks.
    """
    if not flags:
        return 0

    # 1. Group flags by family and take highest severity in each family
    family_severities: Dict[str, int] = {}
    for f in flags:
        current_max = family_severities.get(f.id, 0)
        if f.severity > current_max:
            family_severities[f.id] = f.severity

    # Calculate raw family scores (severity * family weight)
    family_scores: List[Tuple[str, int]] = [
        (fam_id, sev * FAMILY_WEIGHTS.get(fam_id, 10))
        for fam_id, sev in family_severities.items()
    ]

    # Sort descending so the strongest indicator establishes the primary base
    family_scores.sort(key=lambda item: item[1], reverse=True)

    # 2. Check if any core/substantive fraud indicator exists
    has_core_fraud = any(fam_id in CORE_FRAUD_FAMILIES for fam_id, _ in family_scores)
    # Severity 2 sender analysis (personal phone claiming authority, or fraud lure tag) is substantive
    has_substantive_sender = family_severities.get("SENDER_ID_ANALYSIS", 0) >= 2

    # 3. Graduated Diminishing Returns for Multi-Family Combinations
    lead_score = family_scores[0][1]
    accumulated_secondary = 0.0

    for idx, (fam_id, raw_val) in enumerate(family_scores[1:], start=2):
        if idx == 2:
            # Secondary indicator: if combination is low/moderate (sum <= 50), preserve full weight;
            # otherwise apply calibrated 0.60 multiplier to prevent premature saturation to 100
            if lead_score + raw_val <= 50:
                accumulated_secondary += float(raw_val)
            else:
                accumulated_secondary += 0.60 * raw_val
        elif idx == 3:
            # Tertiary indicator
            accumulated_secondary += 0.35 * raw_val
        else:
            # 4th and subsequent indicators
            accumulated_secondary += 0.20 * raw_val

    base_score = lead_score + int(round(accumulated_secondary))

    # 4. Frequency Bonus (diminishing return per repetitive indicator within families)
    extra_flags = max(0, len(flags) - len(family_severities))
    if extra_flags == 1:
        frequency_bonus = 3
    elif extra_flags == 2:
        frequency_bonus = 5
    elif extra_flags == 3:
        frequency_bonus = 7
    elif extra_flags >= 4:
        frequency_bonus = 8
    else:
        frequency_bonus = 0

    total_score = base_score + frequency_bonus

    # 5. Weak Signal Cap: If NO core fraud family and NO substantive sender anomaly exists,
    # multiple weak signals (urgency, formatting caps, weak sender tag) cannot exceed 35 (SAFE).
    if not has_core_fraud and not has_substantive_sender:
        total_score = min(35, total_score)

    # 6. Bound strictly between 0 and 100
    final_score = max(0, min(100, total_score))
    return final_score


def evaluate_flags(flags: List[Flag]) -> Tuple[int, RiskLabel]:
    """Evaluates detected flags and returns (risk_score, label)."""
    score = calculate_risk_score(flags)
    label = get_risk_label(score)
    return score, label

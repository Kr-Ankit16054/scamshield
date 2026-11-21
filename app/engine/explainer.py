"""ScamShield Natural-Language Explainer.

Generates template-based, plain-English 2-3 sentence summaries and targeted
recommended actions based on detected heuristic flags and risk classifications.
Zero external API calls, deterministic, and instant.
"""

from typing import Dict, List

try:
    from app.schemas import Flag
except ModuleNotFoundError:
    from scamshield.app.schemas import Flag

FAMILY_DESCRIPTIONS: Dict[str, str] = {
    "URGENCY_PRESSURE": "artificial urgency pressure tactics",
    "OTP_CREDENTIAL_REQUEST": "direct solicitation of confidential credentials (OTP, PIN, or CVV)",
    "REMOTE_ACCESS_APP": "unauthorized requests to install remote access or screen-sharing software",
    "SUSPICIOUS_LINK": "suspicious, shortened, or lookalike web links",
    "FINANCIAL_LURE": "unrealistic financial lures or unearned lottery claims",
    "IMPERSONATION": "unverified claims of institutional or law enforcement authority",
    "PREFILL_KYC": "threat-based demands for urgent KYC verification",
    "PAYMENT_REDIRECT": "unsolicited payment requests or fake refund verifications",
    "CONTACT_MISMATCH": "requests to contact personal mobile numbers instead of official support",
    "LANGUAGE_MANIPULATION": "manipulative formatting, aggressive punctuation, or homoglyph encoding",
    "SENDER_ID_ANALYSIS": "a mismatched or unverified sender identity",
    "UNTRACED_DELIVERY": "false package delivery alerts demanding clearance fees",
    "JOB_OFFER_SCAM": "fraudulent work-from-home schemes promising quick daily income",
}


def generate_explanation(flags: List[Flag], risk_score: int, label: str) -> str:
    """Generates a concise 2-3 sentence plain-English explanation of risk factors."""
    if not flags or label == "SAFE":
        return (
            "No common scam patterns or fraudulent indicators were detected in this message. "
            "The content appears routine and does not request sensitive credentials, payments, or immediate unverified actions."
        )

    # Gather human-friendly descriptions of the top flagged factors
    unique_ids = list(dict.fromkeys(f.id for f in flags))
    factor_phrases = [FAMILY_DESCRIPTIONS.get(fid, fid.lower().replace("_", " ")) for fid in unique_ids[:3]]

    if len(factor_phrases) == 1:
        factors_text = factor_phrases[0]
    elif len(factor_phrases) == 2:
        factors_text = f"{factor_phrases[0]} and {factor_phrases[1]}"
    else:
        factors_text = f"{factor_phrases[0]}, {factor_phrases[1]}, and {factor_phrases[2]}"

    if label == "SCAM":
        return (
            f"This message exhibits critical scam indicators, notably {factors_text}. "
            "These characteristics strongly suggest a coordinated social engineering attempt designed to compromise credentials or illicitly extract funds. "
            f"Given the elevated risk score of {risk_score}/100, do not interact with this sender."
        )
    elif label == "SUSPICIOUS":
        return (
            f"This message displays moderate risk indicators, including {factors_text}. "
            "While it may not contain an overt credential theft attempt, the combination of cues warrants elevated caution before taking any action. "
            f"The computed risk score of {risk_score}/100 indicates caution is advised."
        )
    else:
        return (
            f"This message contains low-level cues such as {factors_text}, but lacks severe indicators. "
            f"With a risk score of {risk_score}/100, the message is classified as relatively safe, though standard caution is always prudent."
        )


def generate_recommended_action(flags: List[Flag], risk_score: int, label: str) -> str:
    """Generates clear, protective next steps for the user."""
    if label == "SAFE":
        return "No immediate threat identified. Always practice standard cyber hygiene and never disclose private passwords or OTPs."

    has_otp = any(f.id == "OTP_CREDENTIAL_REQUEST" for f in flags)
    has_remote_access = any(f.id == "REMOTE_ACCESS_APP" for f in flags)
    has_link = any(f.id == "SUSPICIOUS_LINK" for f in flags)
    has_kyc = any(f.id == "PREFILL_KYC" for f in flags)

    if label == "SCAM":
        actions = ["Do NOT click any links"]
        if has_otp:
            actions.append("never disclose your OTP or banking PIN")
        if has_remote_access:
            actions.append("never install remote desktop apps or share device access codes")
        if has_kyc:
            actions.append("do not submit KYC details on third-party sites")
        actions.append("block the sender immediately, and report the message to the National Cyber Crime Portal (1930 / cybercrime.gov.in).")
        return ", ".join(actions[:3]) + (". " + actions[-1] if len(actions) > 3 else "")

    # SUSPICIOUS label
    if has_link:
        return "Do not click any provided links. Independently verify the sender by opening the official application or visiting the provider's verified website directly."
    return "Do not respond or call any phone numbers listed in the message. Verify any account alerts through your official banking portal or customer service."

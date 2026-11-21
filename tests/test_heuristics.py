"""Comprehensive test suite for ScamShield deterministic heuristic rules.

Validates that:
- Every rule family correctly flags malicious patterns
- Benign text produces zero false positives
- Performance stays well under the 50ms efficiency budget for 2000-character inputs
"""

import time
import pytest
from app.engine.heuristics import (
    check_urgency_pressure,
    check_otp_credential_request,
    check_suspicious_link,
    check_financial_lure,
    check_impersonation,
    check_prefill_kyc,
    check_payment_redirect,
    check_contact_mismatch,
    check_language_manipulation,
    check_sender_id_analysis,
    check_untraced_delivery,
    check_job_offer_scam,
    check_remote_access_app,
    run_all_heuristics,
)
from app.engine.scorer import calculate_risk_score, get_risk_label


def test_urgency_pressure():
    msg = "URGENT: Your account will be blocked within 24 hours. Act now immediately!"
    flags = check_urgency_pressure(msg)
    assert len(flags) >= 1
    assert any(f.id == "URGENCY_PRESSURE" for f in flags)
    assert any("24 hours" in f.matched_text.lower() or "immediately" in f.matched_text.lower() or "blocked" in f.matched_text.lower() for f in flags)


def test_otp_credential_request():
    msg = "Dear customer, your card is blocked. Send your 6-digit OTP and CVV to unblock."
    flags = check_otp_credential_request(msg)
    assert len(flags) >= 1
    assert any(f.id == "OTP_CREDENTIAL_REQUEST" for f in flags)
    assert any(f.severity == 3 for f in flags)


def test_otp_negation_security_warnings():
    """Phase 1A: Legitimate security warnings must NOT be flagged as credential solicitation."""
    legit_messages = [
        "Your HDFC netbanking login OTP is 894102. Do not share your OTP with anyone.",
        "Your verification code is 123456. Never share it with anyone.",
        "Security alert: We will never ask you to disclose your OTP.",
        "Your OTP is 998877. Never share your OTP with anyone.",
        "Please don't share your OTP or password.",
        "We advise you not to share your PIN with anyone.",
        "OTP must not be shared with anyone.",
    ]
    for msg in legit_messages:
        flags = check_otp_credential_request(msg)
        assert len(flags) == 0, f"False positive on legitimate warning: '{msg}' -> {flags}"


def test_otp_credential_solicitation_detected():
    """Phase 1A: Malicious credential requests (including trick/adversarial phrases) MUST be detected."""
    malicious_messages = [
        "Send your OTP to verify your account.",
        "Share your OTP immediately to prevent account suspension.",
        "Reply with your OTP to unlock your bank account.",
        "Do not delay, share your OTP now.",
        "Do not hesitate to share your OTP.",
        "Never share your OTP with strangers! Send your OTP to our executive now.",
    ]
    for msg in malicious_messages:
        flags = check_otp_credential_request(msg)
        assert len(flags) >= 1, f"False negative on malicious request: '{msg}'"
        assert any(f.id == "OTP_CREDENTIAL_REQUEST" for f in flags)


def test_suspicious_link_ip_and_shortener():
    msg_ip = "Verify your account at http://192.168.1.100/login"
    flags_ip = check_suspicious_link(msg_ip)
    assert any(f.id == "SUSPICIOUS_LINK" for f in flags_ip)

    msg_shortener = "Check your delivery details here: https://bit.ly/3x99Scam"
    flags_short = check_suspicious_link(msg_shortener)
    assert any(f.id == "SUSPICIOUS_LINK" for f in flags_short)


def test_suspicious_link_lookalike_and_punycode():
    msg_lookalike = "Log in to your account at https://sbi-bank.xyz/update"
    flags_lookalike = check_suspicious_link(msg_lookalike)
    assert any(f.id == "SUSPICIOUS_LINK" for f in flags_lookalike)

    msg_punycode = "Reset password at http://xn--g0gle-p4a.com/auth"
    flags_puny = check_suspicious_link(msg_punycode)
    assert any(f.id == "SUSPICIOUS_LINK" for f in flags_puny)


# ==============================================================================
# PHASE 1B: URL DETECTION MODERNIZATION REGRESSION TESTS
# ==============================================================================

def test_generic_malicious_domains_detected():
    """Phase 1B: Generic deceptive domains combining smishing keywords and high-risk TLDs or chained hyphens."""
    generic_malicious_messages = [
        "Verify your profile at http://account-validation-portal.xyz/login to avoid suspension.",
        "Security alert: Access http://update-kyc-account-verify.com immediately.",
        "Unclaimed reward available at https://claim-reward-cash.online for the next 2 hours.",
        "Service notification: http://kyc-verification-service.site/form",
        "Payment issue: visit https://secure-portal-update.top to update your billing.",
        "Account alert: visit http://update-kyc.com to avoid account closure.",
    ]
    for msg in generic_malicious_messages:
        flags = check_suspicious_link(msg)
        assert len(flags) >= 1, f"Failed to detect generic deceptive domain in: '{msg}'"
        assert any(f.id == "SUSPICIOUS_LINK" for f in flags)
        assert any(f.severity == 3 for f in flags)


def test_ip_address_urls_detected():
    """Phase 1B: IP-address-based URLs with standard ports, non-standard ports, and paths."""
    ip_messages = [
        ("Verify your account at http://192.168.1.1/login", "192.168.1.1/login"),
        ("Package clearance fee due at 45.33.32.156:8080/clearance", "45.33.32.156:8080/clearance"),
        ("Server alert: access http://10.0.0.1:3000/auth to confirm identity.", "10.0.0.1:3000/auth"),
        ("Direct IP portal: 192.168.1.100/login", "192.168.1.100/login"),
    ]
    for msg, expected_snippet in ip_messages:
        flags = check_suspicious_link(msg)
        assert len(flags) >= 1, f"Failed to detect IP URL in: '{msg}'"
        assert any(f.id == "SUSPICIOUS_LINK" for f in flags)
        assert any(f.severity == 3 for f in flags)
        assert any(expected_snippet in f.matched_text for f in flags)


def test_expanded_url_shorteners_detected():
    """Phase 1B: Expanded URL shorteners beyond the initial subset (s.id, t.ly, cutt.ly, etc.)."""
    shortener_messages = [
        ("Claim prize at https://s.id/verify", "s.id/verify"),
        ("Download statement at https://t.ly/bank", "t.ly/bank"),
        ("Track package at https://cutt.ly/gift", "cutt.ly/gift"),
        ("Special offer: http://rebrand.ly/promo", "rebrand.ly/promo"),
        ("Check delivery status at v.gd/order123", "v.gd/order123"),
        ("Review document at https://tiny.one/doc", "tiny.one/doc"),
    ]
    for msg, expected_snippet in shortener_messages:
        flags = check_suspicious_link(msg)
        assert len(flags) >= 1, f"Failed to detect shortener in: '{msg}'"
        assert any(f.id == "SUSPICIOUS_LINK" for f in flags)
        assert any(f.severity == 2 for f in flags)
        assert any(expected_snippet in f.matched_text for f in flags)


def test_brand_impersonation_domains_detected():
    """Phase 1B: Brand impersonation with hyphens, keywords, or lookalikes on arbitrary domains."""
    brand_messages = [
        "Log in to your account at https://sbi-bank.xyz/update",
        "Confirm PayPal transaction at https://paypal-verify.site",
        "HDFC security alert: https://hdfc-security.online/netbanking",
        "Amazon alert: verify account at https://amazon-security.info",
        "Netflix billing update: https://netflix-billing.com/update",
        "PayTM alert: claim bonus at https://paytm0nline.com/claim",
    ]
    for msg in brand_messages:
        flags = check_suspicious_link(msg)
        assert len(flags) >= 1, f"Failed to detect brand impersonation in: '{msg}'"
        assert any(f.id == "SUSPICIOUS_LINK" for f in flags)
        assert any(f.severity == 3 for f in flags)


def test_defanged_urls_detected():
    """Phase 1B: Defanged URL formats (hxxp://, http[:]//, [.] or (.) delimiters)."""
    defanged_messages = [
        ("Security notice: malicious link observed: hxxp://sbi-fake[.]com/login", "hxxp://sbi-fake[.]com/login"),
        ("Suspect URL: http[:]//bit[.]ly/scam", "http[:]//bit[.]ly/scam"),
        ("Check site: bank[.]xyz/update", "bank[.]xyz/update"),
        ("Phishing sample: hxxps://secure-portal[.]top/auth", "hxxps://secure-portal[.]top/auth"),
        ("Suspicious link domain(.)com reported.", "domain(.)com"),
    ]
    for msg, expected_snippet in defanged_messages:
        flags = check_suspicious_link(msg)
        assert len(flags) >= 1, f"Failed to detect defanged URL in: '{msg}'"
        assert any(f.id == "SUSPICIOUS_LINK" for f in flags)
        assert any(f.severity == 3 for f in flags)
        assert any(expected_snippet in f.matched_text for f in flags)


def test_suspicious_subdomain_structures_detected():
    """Phase 1B: Brand spoofing in subdomains where apex domain is distinct or generic."""
    subdomain_messages = [
        "SBI alert: Update netbanking at https://sbi.bank.com.fake.xyz",
        "Verify PayPal account at http://paypal.com.verify-user.top",
        "HDFC NetBanking: https://hdfc.verify-portal.site",
        "SBI Bank login: https://sbi.bank-login.xyz",
        "Amazon order alert: http://amazon.co.in.fake-orders.top/track",
    ]
    for msg in subdomain_messages:
        flags = check_suspicious_link(msg)
        assert len(flags) >= 1, f"Failed to detect suspicious subdomain structure in: '{msg}'"
        assert any(f.id == "SUSPICIOUS_LINK" for f in flags)
        assert any(f.severity == 3 for f in flags)


def test_legitimate_ordinary_urls_not_flagged():
    """Phase 1B False-Positive Protection: Reputable, educational, and ordinary domains must NOT be flagged."""
    ordinary_messages = [
        "Check the article at https://en.wikipedia.org/wiki/Phishing for more details.",
        "Our open source repo is hosted at https://github.com/fastapi/fastapi",
        "Product details available at https://amazon.in/dp/B08N5WRWNW",
        "Live train status can be verified on https://irctc.co.in/eticketing",
        "Order lunch via https://zomato.com/order/12345",
    ]
    for msg in ordinary_messages:
        flags = check_suspicious_link(msg)
        assert len(flags) == 0, f"False positive on legitimate URL: '{msg}' -> {flags}"


def test_legitimate_https_urls_not_flagged():
    """Phase 1B False-Positive Protection: Standard HTTPS search, news, and travel links must NOT be flagged."""
    https_messages = [
        "Search for nearby clinics at https://www.google.com/search?q=hospital",
        "Read the news at https://nytimes.com/world/article.html",
        "Check flight status at https://goindigo.in/flight-booking.html",
    ]
    for msg in https_messages:
        flags = check_suspicious_link(msg)
        assert len(flags) == 0, f"False positive on legitimate HTTPS URL: '{msg}' -> {flags}"


def test_legitimate_low_risk_http_urls_not_flagged():
    """Phase 1B False-Positive Protection: Plain informational HTTP URLs without auth endpoints must NOT be flagged."""
    low_risk_http_messages = [
        "Read the history of the web at http://info.cern.ch/hypertext/WWW/TheProject.html",
        "Check the web standards specification at http://www.w3.org/Consortium/",
        "Domain for documentation examples: http://example.com",
        "Read regional weather reports at http://news.bbc.co.uk/local",
    ]
    for msg in low_risk_http_messages:
        flags = check_suspicious_link(msg)
        assert len(flags) == 0, f"False positive on low-risk HTTP URL: '{msg}' -> {flags}"


def test_insecure_http_in_sensitive_context_detected():
    """Phase 1B: Cleartext HTTP links pointing to sensitive auth/banking actions or in credential contexts."""
    sensitive_http_messages = [
        "Please update your password at http://customer-support-desk.org/login",
        "Verify your account at http://my-service.net/verify",
        "Submit KYC form at http://service-center.org/kyc",
        "Enter OTP and verify payment at http://payment-gateway-check.org/checkout",
    ]
    for msg in sensitive_http_messages:
        flags = check_suspicious_link(msg)
        assert len(flags) >= 1, f"Failed to detect insecure HTTP sensitive link in: '{msg}'"
        assert any(f.id == "SUSPICIOUS_LINK" for f in flags)
        assert any(f.severity == 2 for f in flags)


def test_url_detection_inside_longer_messages():
    """Phase 1B: URLs embedded midway inside multi-sentence messages are extracted and flagged."""
    long_messages = [
        (
            "Dear valued customer, please be informed that our scheduled maintenance has concluded. "
            "If you experience issues, access your account at https://account-validation-portal.xyz/login "
            "immediately to restore your preferences. Thank you for your patience.",
            "https://account-validation-portal.xyz/login"
        ),
        (
            "Hello team, the report has been uploaded to the server. You can access it at "
            "http://45.33.32.156:8080/clearance before 5 PM today.",
            "http://45.33.32.156:8080/clearance"
        ),
    ]
    for msg, expected_url in long_messages:
        flags = check_suspicious_link(msg)
        assert len(flags) >= 1, f"Failed to detect URL inside long message: '{msg}'"
        assert any(f.id == "SUSPICIOUS_LINK" for f in flags)
        assert any(expected_url in f.matched_text for f in flags)


def test_url_sentence_ending_punctuation_stripped():
    """Phase 1B: Trailing periods, commas, or parentheses are cleanly stripped from matched URLs."""
    msg = "Please update your details at https://sbi-bank.xyz/login."
    flags = check_suspicious_link(msg)
    assert len(flags) >= 1
    matched = [f.matched_text for f in flags if f.id == "SUSPICIOUS_LINK"]
    assert "https://sbi-bank.xyz/login" in matched
    assert not any(m.endswith(".") for m in matched)


def test_financial_lure():
    msg = "Congratulations! You have won a prize in lottery of ₹25,00,000! Claim your reward now with guaranteed returns."
    flags = check_financial_lure(msg)
    assert len(flags) >= 1
    assert any(f.id == "FINANCIAL_LURE" for f in flags)


def test_impersonation():
    msg = "This is TRAI and DELHI POLICE Cyber Crime Cell notice regarding your mobile disconnection."
    flags = check_impersonation(msg)
    assert len(flags) >= 1
    assert any(f.id == "IMPERSONATION" for f in flags)


def test_prefill_kyc():
    msg = "Dear Customer, your KYC expired. Update KYC to avoid deactivation of SBI bank account."
    flags = check_prefill_kyc(msg)
    assert len(flags) >= 1
    assert any(f.id == "PREFILL_KYC" for f in flags)
    assert any(f.severity == 3 for f in flags)


def test_prefill_kyc_due_to_pending_kyc():
    """Verify narrow pattern detection for 'due to pending KYC'."""
    msg = "URGENT: Your SBI netbanking will be blocked today due to pending KYC."
    flags = check_prefill_kyc(msg)
    assert len(flags) >= 1
    assert any(f.id == "PREFILL_KYC" for f in flags)
    assert any("pending kyc" in f.matched_text.lower() for f in flags)


def test_payment_redirect():
    msg = "A refund of ₹4500 credited to your account. Click link to pay or claim your refund now."
    flags = check_payment_redirect(msg)
    assert len(flags) >= 1
    assert any(f.id == "PAYMENT_REDIRECT" for f in flags)


def test_legitimate_refund_notices_not_flagged():
    """Phase 1A: Informational refund and credit receipts must NOT be flagged as payment redirects."""
    legit_refunds = [
        "Refund of ₹450 is credited to your account for ride cancellation.",
        "Your ₹1200 refund has been successfully processed.",
        "Payment refund credited to your original payment method.",
        "A refund of ₹250 was initiated for your returned item.",
    ]
    for msg in legit_refunds:
        flags = check_payment_redirect(msg)
        assert len(flags) == 0, f"False positive on legitimate refund notice: '{msg}' -> {flags}"


def test_fraudulent_refund_scams_detected():
    """Phase 1A: Refund scams involving links, QR codes, or payment traps MUST be detected."""
    scam_refunds = [
        "A refund of ₹4500 credited to your account. Click link to pay or claim your refund now.",
        "Refund of ₹5000 is credited, verify at http://bank.com to receive.",
        "Scan QR code to receive money into your account or click link to pay ₹1 to verify refund.",
        "Claim your refund now at bit.ly/refund",
        "Click to claim refund of ₹10,000 immediately.",
    ]
    for msg in scam_refunds:
        flags = check_payment_redirect(msg)
        assert len(flags) >= 1, f"False negative on fraudulent refund: '{msg}'"
        assert any(f.id == "PAYMENT_REDIRECT" for f in flags)


def test_contact_mismatch():
    msg = "Your SIM card will be deactivated today. Call officer at 9876543210 immediately for verification."
    flags = check_contact_mismatch(msg)
    assert len(flags) >= 1
    assert any(f.id == "CONTACT_MISMATCH" for f in flags)


def test_language_manipulation_capitalization():
    msg = "ATTENTION ALL CUSTOMERS YOUR SERVICES ARE GOING TO BE SUSPENDED TODAY"
    flags = check_language_manipulation(msg)
    assert any(f.id == "LANGUAGE_MANIPULATION" for f in flags)


def test_language_manipulation_exclamation():
    msg = "Exclusive cash offer valid right now!!!! Hurry up!!!!"
    flags = check_language_manipulation(msg)
    assert any(f.id == "LANGUAGE_MANIPULATION" for f in flags)


def test_language_manipulation_homoglyphs():
    # Cyrillic 'а' (U+0430) and 'о' (U+043E) embedded in Latin text
    msg = "Update your P\u0430yp\u0430l account immediately"
    flags = check_language_manipulation(msg)
    assert any(f.id == "LANGUAGE_MANIPULATION" for f in flags)


def test_sender_id_personal_for_institution():
    msg = "Dear SBI Customer, your netbanking access is locked."
    sender_id = "+919876543210"
    flags = check_sender_id_analysis(msg, sender_id)
    assert any(f.id == "SENDER_ID_ANALYSIS" for f in flags)


def test_sender_id_legitimate_bank_header():
    msg = "Dear SBI Customer, your OTP for transaction is 123456."
    sender_id = "VK-SBIINB"
    flags = check_sender_id_analysis(msg, sender_id)
    assert len(flags) == 0


# ==============================================================================
# PHASE 1C: SENDER ID CALIBRATION REGRESSION TESTS
# ==============================================================================

def test_normal_alphanumeric_sender_ids():
    """Phase 1C: Standard alphanumeric brand and business sender IDs must NOT be flagged."""
    normal_senders = ["Uber", "Netflix", "Apple", "Amazon", "Flipkart", "Zomato", "Swiggy", "Google", "Microsoft", "PayPal"]
    benign_msg = "Your ride is confirmed and the driver is arriving in 5 minutes."
    for s_id in normal_senders:
        flags = check_sender_id_analysis(benign_msg, s_id)
        assert len(flags) == 0, f"False positive on legitimate sender ID: '{s_id}' -> {flags}"


def test_legitimate_bank_sender_ids():
    """Phase 1C: Standard telecom-format bank route headers must NOT be flagged."""
    bank_headers = ["AX-HDFCBK", "VK-SBIINB", "DZ-ICICIB", "CP-KOTAKB", "AD-AXISBK"]
    txn_msg = "Your account 1234 has been credited with INR 10,000 via NEFT."
    for s_id in bank_headers:
        flags = check_sender_id_analysis(txn_msg, s_id)
        assert len(flags) == 0, f"False positive on legitimate bank header: '{s_id}' -> {flags}"


def test_legitimate_delivery_sender_ids():
    """Phase 1C: Standard delivery and logistics notification headers must NOT be flagged."""
    delivery_senders = ["AM-AMAZON", "ZM-ZOMATO", "SWIGGY", "BLUEDART", "FEDEX", "DUNZO"]
    delivery_msg = "Your order has been picked up and is out for delivery."
    for s_id in delivery_senders:
        flags = check_sender_id_analysis(delivery_msg, s_id)
        assert len(flags) == 0, f"False positive on delivery sender ID: '{s_id}' -> {flags}"


def test_legitimate_technology_sender_ids():
    """Phase 1C: Standard technology, developer, and travel notification headers must NOT be flagged."""
    tech_senders = ["GITHUB", "MICROSOFT", "GOOGLE", "6E-INDIGO", "TWITTER", "LIB-NOTIFY"]
    tech_msg = "Your security verification code is 894102. Valid for 10 minutes."
    for s_id in tech_senders:
        flags = check_sender_id_analysis(tech_msg, s_id)
        assert len(flags) == 0, f"False positive on technology sender ID: '{s_id}' -> {flags}"


def test_unusual_sender_id_with_benign_content():
    """Phase 1C: Unusual sender ID format on benign content must remain strictly SAFE (<40 points)."""
    unusual_senders = ["APP-NOTIF-01", "CUSTOM-TAG-99", "SYSTEM_MSG_2024"]
    benign_msg = "Team standup meeting is starting in 10 minutes on Zoom."
    for s_id in unusual_senders:
        flags = run_all_heuristics(benign_msg, sender_id=s_id)
        score = calculate_risk_score(flags)
        label = get_risk_label(score)
        # Format irregularities alone must NEVER cause a scam or suspicious classification
        assert label == "SAFE", f"Unusual sender '{s_id}' on benign message caused unsafe label: {label}"
        assert score < 40, f"Unusual sender '{s_id}' scored {score} (must be <40)"
        # If flagged, must be at most severity 1 (weak evidence)
        sender_flags = [f for f in flags if f.id == "SENDER_ID_ANALYSIS"]
        assert all(f.severity == 1 for f in sender_flags)


def test_suspicious_sender_id_with_phishing_url():
    """Phase 1C: Generic fraud alert header correlated with a phishing link triggers severity 2."""
    msg = "Security alert: Access your profile immediately at http://account-validation-portal.xyz/login to avoid suspension."
    s_id = "BANK-ALERT"
    flags = check_sender_id_analysis(msg, s_id)
    assert len(flags) >= 1, f"Expected sender analysis flag for '{s_id}' with phishing content"
    assert any(f.id == "SENDER_ID_ANALYSIS" for f in flags)
    assert any(f.severity == 2 for f in flags)
    # Full analysis must reach SCAM tier
    all_flags = run_all_heuristics(msg, sender_id=s_id)
    score = calculate_risk_score(all_flags)
    assert score >= 70
    assert get_risk_label(score) == "SCAM"


def test_suspicious_sender_id_with_otp_solicitation():
    """Phase 1C: Personal phone or generic alert header soliciting OTP credentials triggers severity 2."""
    msg = "Dear SBI Customer, your account is suspended. Reply with your OTP immediately to restore access."
    # Case A: Personal phone number
    flags_phone = check_sender_id_analysis(msg, "+919876543210")
    assert any(f.id == "SENDER_ID_ANALYSIS" and f.severity == 2 for f in flags_phone)

    # Case B: Generic fraud alert header
    flags_alert = check_sender_id_analysis(msg, "SEC-ALERT")
    assert any(f.id == "SENDER_ID_ANALYSIS" and f.severity == 2 for f in flags_alert)


def test_empty_or_absent_sender_id():
    """Phase 1C: Absent, empty, or whitespace-only sender ID must return 0 flags cleanly."""
    msg = "Your delivery is scheduled for tomorrow afternoon."
    for empty_val in [None, "", "   ", "\t\n"]:
        flags = check_sender_id_analysis(msg, empty_val)
        assert len(flags) == 0, f"Expected 0 flags for empty sender ID '{empty_val}', got {flags}"


def test_untraced_delivery():
    msg = "Notice: Your parcel held at customs. Courier fee due of ₹150. Package cannot be delivered without payment."
    flags = check_untraced_delivery(msg)
    assert len(flags) >= 1
    assert any(f.id == "UNTRACED_DELIVERY" for f in flags)


def test_job_offer_scam():
    msg = "Work from home part-time: no interview needed, earn ₹5000 daily! Pay registration fee of ₹200."
    flags = check_job_offer_scam(msg)
    assert len(flags) >= 1
    assert any(f.id == "JOB_OFFER_SCAM" for f in flags)


def test_legit_message_no_false_positives():
    msg = "Hey, are we still meeting for lunch at 1 PM today? Let me know!"
    flags = run_all_heuristics(msg, sender_id=None)
    assert len(flags) == 0


def test_legit_transaction_alert():
    msg = "Your A/C ending with 4321 is credited by INR 15,000 on 20-Nov-2024. Available balance INR 45,210. Info: NEFT."
    flags = run_all_heuristics(msg, sender_id="AX-HDFCBK")
    assert len(flags) == 0


def test_zero_width_evasion_mitigation():
    # Attacker inserts zero-width space (\u200B) into "OTP" and "immediately" to evade keyword detection
    evasive_msg = "Please send your O\u200bT\u200bP immed\u200biately to unlock account."
    flags = run_all_heuristics(evasive_msg)
    assert any(f.id == "OTP_CREDENTIAL_REQUEST" for f in flags), "Zero-width space evasion was not mitigated!"


def test_efficiency_benchmark_2000_chars():
    # Construct a 2000 character realistic message containing multiple patterns
    base_text = "URGENT Notice from SBI bank: Your parcel held at customs. Update KYC immediately or account blocked within 24 hours. Click https://sbi-bank.xyz/verify and share OTP. "
    padded_message = (base_text * 15)[:2000]
    assert len(padded_message) == 2000

    # Warmup
    _ = run_all_heuristics(padded_message, sender_id="+919876543210")

    # Benchmark run
    start = time.perf_counter()
    flags = run_all_heuristics(padded_message, sender_id="+919876543210")
    duration_ms = (time.perf_counter() - start) * 1000

    assert len(flags) > 0
    # Must comfortably complete in <50ms as per efficiency rubric
    assert duration_ms < 50.0, f"Execution took {duration_ms:.2f}ms, which exceeds the 50ms budget!"


# ==============================================================================
# PHASE 2: EVASION RESISTANCE & DETECTION EXPANSION REGRESSION TESTS
# ==============================================================================

def test_evasion_spaced_and_punctuated_otp():
    """Phase 2: Detects OTP obfuscated via spaces, periods, dashes, underscores, and leetspeak."""
    evasive_otp_messages = [
        "Please send your O T P immediately to avoid account suspension.",
        "Share your 0TP now with our verification agent.",
        "Kindly enter your O.T.P. to restore access to your bank account.",
        "Your O-T-P is required immediately: reply to verify.",
        "Submit 0-T-P code now to complete authentication.",
        "Share your O_T_P with support executive.",
        "Enter your 0 T P to proceed.",
    ]
    for msg in evasive_otp_messages:
        flags = check_otp_credential_request(msg)
        assert any(f.id == "OTP_CREDENTIAL_REQUEST" for f in flags), f"Failed to detect evasive OTP in: '{msg}'"


def test_evasion_spaced_and_punctuated_kyc():
    """Phase 2: Detects KYC obfuscated via spaces, dots, and hyphens."""
    evasive_kyc_messages = [
        "URGENT: Your K Y C expired today. Update immediately.",
        "Complete your K.Y.C. to avoid permanent account block.",
        "Mandatory K-Y-C update pending for your bank account.",
        "Your K_Y_C is suspended. Verify now.",
    ]
    for msg in evasive_kyc_messages:
        flags = check_prefill_kyc(msg)
        assert any(f.id == "PREFILL_KYC" for f in flags), f"Failed to detect evasive KYC in: '{msg}'"


def test_evasion_spaced_and_punctuated_pin_and_cvv():
    """Phase 2: Detects PIN, MPIN, and CVV obfuscated via spaces, dots, and leetspeak."""
    evasive_credentials = [
        "Send your debit card P I N immediately to unlock card.",
        "Enter your P.I.N. to verify account.",
        "Submit your P1N now to cancel transaction.",
        "Please provide your M P I N and OTP to verify.",
        "Share your C V V and expiry date with executive.",
        "Enter your C.V.V. to claim refund.",
    ]
    for msg in evasive_credentials:
        flags = check_otp_credential_request(msg)
        assert any(f.id == "OTP_CREDENTIAL_REQUEST" for f in flags), f"Failed to detect credential solicitation in: '{msg}'"


def test_evasion_repeated_character_manipulation():
    """Phase 2: Normalizes repeated character exaggerations used to bypass exact keyword matching."""
    evasive_messages = [
        ("URGENTTTTT: Your account is suspended. Act now!", "URGENCY_PRESSURE"),
        ("Congratulations! You are the grand looooottery winner!", "FINANCIAL_LURE"),
        ("Claim your freeeeee cash reward today!", "FINANCIAL_LURE"),
        ("Your account has been blooockkked. Update KYC immediately.", "URGENCY_PRESSURE"),
        ("Special winneeeer announced in lucky draw today!", "FINANCIAL_LURE"),
    ]
    for msg, expected_flag_id in evasive_messages:
        flags = run_all_heuristics(msg)
        assert any(f.id == expected_flag_id for f in flags), f"Failed to detect repeated-char evasion '{msg}' (expected {expected_flag_id})"


def test_evasion_unicode_confusables_and_fullwidth():
    """Phase 2: Neutralizes Cyrillic lookalikes and fullwidth Unicode characters."""
    # Cyrillic lookalikes in OTP and KYC
    msg_cyrillic_otp = "Please share your \u041e\u0422\u0420 immediately to verify."
    flags_otp = check_otp_credential_request(msg_cyrillic_otp)
    assert any(f.id == "OTP_CREDENTIAL_REQUEST" for f in flags_otp), "Failed on Cyrillic OTP lookalike"

    msg_cyrillic_kyc = "Mandatory \u041a\u04ae\u0421 update required to avoid suspension."
    flags_kyc = check_prefill_kyc(msg_cyrillic_kyc)
    assert any(f.id == "PREFILL_KYC" for f in flags_kyc), "Failed on Cyrillic KYC lookalike"

    # Fullwidth Unicode characters (e.g. ＯＴＰ)
    msg_fullwidth = "Enter your \uff2f\uff34\uff30 now."
    flags_fullwidth = check_otp_credential_request(msg_fullwidth)
    assert any(f.id == "OTP_CREDENTIAL_REQUEST" for f in flags_fullwidth), "Failed on fullwidth OTP"


def test_remote_access_app_lures_detected():
    """Phase 2: Detects remote access software installation traps (AnyDesk, TeamViewer, RustDesk, APK downloads)."""
    remote_access_scams = [
        "Electricity Department: Power will be cut off tonight. Install AnyDesk app and share 9-digit code to verify bill payment.",
        "SBI Support: Your account is locked. Download QuickSupport app from link to unblock immediately.",
        "To receive your cashback of Rs 5,000, install RustDesk on your phone now.",
        "India Post Alert: Package held. Download apk file from http://indiapost-update.site/app.apk to track parcel.",
        "Customer Care: Please install screen share app to complete your verification.",
        "Please install this support app to verify your refund status.",
    ]
    for msg in remote_access_scams:
        flags = check_remote_access_app(msg)
        assert any(f.id == "REMOTE_ACCESS_APP" for f in flags), f"Failed to detect remote access lure in: '{msg}'"
        # Full evaluation must classify as SCAM
        all_flags = run_all_heuristics(msg)
        score = calculate_risk_score(all_flags)
        assert score >= 70, f"Remote access message did not reach SCAM tier: score={score} for '{msg}'"
        assert get_risk_label(score) == "SCAM"


def test_hinglish_scam_detection():
    """Phase 2: Detects common Indian scam terminology and Hinglish fraud patterns."""
    hinglish_scams = [
        # Electricity bill disconnection threat with personal mobile
        ("Bijli vibhag alert: Aapki bijli aaj raat 9:30 baje kat jayegi. Bill baki hai. Turant call karein 9876543210 par.", "CONTACT_MISMATCH"),
        # SBI KYC suspension with credential request
        ("SBI khata band ho jayega. Turant apna KYC update kare aur apna OTP bhejo.", "OTP_CREDENTIAL_REQUEST"),
        # KBC lottery prize
        ("Badhaai ho! Aapne 25 lakh ka inaam jeeta hai. KBC lucky winner claim now: https://bit.ly/kbc-inam", "FINANCIAL_LURE"),
        # Work from home earning scam
        ("Ghar baithe paise kamaye: Daily payout Rs 4000. Telegram task job. No interview needed. Join bit.ly/tele-job", "JOB_OFFER_SCAM"),
        # Customs parcel hold in Hinglish
        ("India Post: Aapka parcel customs me ruka hai. Delivery address update kare aur courier fee pay kare: http://45.33.32.156/clearance", "UNTRACED_DELIVERY"),
    ]
    for msg, expected_flag_id in hinglish_scams:
        flags = run_all_heuristics(msg)
        assert any(f.id == expected_flag_id for f in flags), f"Hinglish scam '{msg}' missed expected flag '{expected_flag_id}'"
        score = calculate_risk_score(flags)
        assert score >= 40, f"Hinglish scam scored below SUSPICIOUS threshold: {score} for '{msg}'"
        assert get_risk_label(score) in ("SUSPICIOUS", "SCAM")


def test_benign_hinglish_messages_not_flagged():
    """Phase 2: Everyday benign Hinglish conversations must produce 0 false positives and remain strictly SAFE."""
    benign_hinglish = [
        "Bhai kal lunch par chalein? Mujhe batao.",
        "Maine paise bhej diye hain Google Pay se, check kar lo.",
        "Kal subah 10 baje office me milte hain.",
        "Bhai movie ke tickets book ho gaye hain.",
        "Ghar pahunch kar phone karna.",
        "Mera laptop kharab ho gaya hai, theek karwane ja raha hu.",
        "Kal exam hai, ache se padhna all the best!",
    ]
    for msg in benign_hinglish:
        flags = run_all_heuristics(msg, sender_id=None)
        score = calculate_risk_score(flags)
        label = get_risk_label(score)
        assert label == "SAFE", f"Benign Hinglish message falsely classified as {label}: '{msg}' (score={score})"
        assert score == 0, f"Benign Hinglish message generated non-zero score: {score} (flags={flags})"


def test_legitimate_otp_warning_with_evasive_spelling_not_flagged():
    """Phase 2: Legitimate security warnings with spaced, punctuated, or Hinglish OTP must NOT be flagged as solicitation."""
    legit_warnings = [
        "Your HDFC netbanking password is changed. Never share your O T P with anyone.",
        "Do not share your 0TP or password with any bank executive.",
        "Do not share your O.T.P. under any circumstances.",
        "Bank security alert: Apna OTP kisi ke saath share na karein.",
        "Apna OTP kisi ko mat de, bank kabhi bhi aapse OTP nahi mangta.",
    ]
    for msg in legit_warnings:
        cred_flags = check_otp_credential_request(msg)
        assert len(cred_flags) == 0, f"Security warning falsely flagged as credential request: '{msg}' -> {cred_flags}"
        flags = run_all_heuristics(msg, sender_id="AX-HDFCBK")
        score = calculate_risk_score(flags)
        assert score < 40, f"Security advisory scored too high: {score} for '{msg}'"
        assert get_risk_label(score) == "SAFE"


def test_defanged_and_obfuscated_urls():
    """Phase 2: Preserves Phase 1B defanged URL detection alongside Phase 2 normalization."""
    defanged_samples = [
        "Access your account at hxxps://secure-banking-portal[.]xyz/login immediately.",
        "Update KYC at http[:]//sbi-bank-verify(.)top/auth now.",
        "Click http://192.168.1.100:8080/bank/update to prevent suspension.",
    ]
    for msg in defanged_samples:
        flags = check_suspicious_link(msg)
        assert any(f.id == "SUSPICIOUS_LINK" for f in flags), f"Failed to detect defanged URL in: '{msg}'"

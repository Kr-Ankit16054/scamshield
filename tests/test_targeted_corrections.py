"""Phase 4 Targeted Regression Test Suite.

Verifies fixes for the four failure families identified during Phase 3.5 blind validation:
1. Pronoun-referenced credential negation and verification codes (HOLD_024 family).
2. Generic utility and electricity disconnection impersonation (HOLD_078 family).
3. Telecom authority disconnection extortion and correlated signals (HOLD_079 family).
4. QR code reverse-payment lures with intervening application phrases (HOLD_100 family).
"""

import pytest
from app.engine.heuristics import run_all_heuristics
from app.engine.scorer import evaluate_flags


# ==============================================================================
# FAMILY 1: PRONOUN-REFERENCED NEGATION & VERIFICATION CODES (HOLD_024)
# ==============================================================================

def test_hold_024_exact_message():
    """HOLD_024: Conversational credential discussion with pronoun negation must be SAFE."""
    msg = (
        "Hey, did you get the OTP for Netflix login on the living room TV? "
        "Please don't share it if it wasn't you trying to log in."
    )
    sender = "+919876543103"
    flags = run_all_heuristics(msg, sender)
    score, label = evaluate_flags(flags)
    assert label == "SAFE", f"Expected SAFE for HOLD_024, got {label} (score {score})"
    assert not any(f.id == "OTP_CREDENTIAL_REQUEST" for f in flags)


def test_pin_pronoun_negation_protective_warning():
    """Protective warning across question boundary with pronoun 'it' must be SAFE."""
    msg = "Did you receive the PIN? Never share it with anyone."
    flags = run_all_heuristics(msg, sender_id="+919876543106")
    score, label = evaluate_flags(flags)
    assert label == "SAFE"
    assert not any(f.id == "OTP_CREDENTIAL_REQUEST" for f in flags)


def test_otp_pronoun_solicitation_detected():
    """Actual credential solicitation using pronoun 'it' must still be DETECTED."""
    msg = "Your OTP is 123456, send it to me."
    flags = run_all_heuristics(msg, sender_id="+919876543107")
    score, label = evaluate_flags(flags)
    assert any(f.id == "OTP_CREDENTIAL_REQUEST" for f in flags)
    assert label in ("SUSPICIOUS", "SCAM")


def test_verification_code_solicitation_detected():
    """Forwarding verification code must be DETECTED as credential solicitation."""
    msg = "Please forward that verification code."
    flags = run_all_heuristics(msg, sender_id="+919876543108")
    score, label = evaluate_flags(flags)
    assert any(f.id == "OTP_CREDENTIAL_REQUEST" for f in flags)
    assert label in ("SUSPICIOUS", "SCAM")


def test_user_refusal_pronoun_negation_safe():
    """User refusal to disclose OTP using pronoun 'it' must be SAFE."""
    msg = "I received your OTP but I will not share it."
    flags = run_all_heuristics(msg, sender_id="+919876543109")
    score, label = evaluate_flags(flags)
    assert label == "SAFE"
    assert not any(f.id == "OTP_CREDENTIAL_REQUEST" for f in flags)


# ==============================================================================
# FAMILY 2: GENERIC UTILITY & DISCONNECTION IMPERSONATION (HOLD_078)
# ==============================================================================

def test_hold_078_exact_message():
    """HOLD_078: Generic electricity disconnection threat with personal contact must be SCAM."""
    msg = (
        "Priye grahak, pichle mahine ka bijli bill update na hone ke karan aaj raat "
        "bijli kat jayegi. Turant sampark karein officer 9811223344 par."
    )
    sender = "+919876543136"
    flags = run_all_heuristics(msg, sender)
    score, label = evaluate_flags(flags)
    assert label == "SCAM", f"Expected SCAM for HOLD_078, got {label} (score {score})"
    assert any(f.id == "IMPERSONATION" for f in flags)
    assert any(f.id == "CONTACT_MISMATCH" for f in flags)
    assert score >= 70


def test_english_power_disconnection_scam():
    """English electricity overdue notice with personal officer phone must be SCAM."""
    msg = (
        "Electricity Department: Power disconnection scheduled tonight at 10 PM "
        "due to unpaid bill Rs 2,340. Call electricity officer at 9876543210 immediately."
    )
    flags = run_all_heuristics(msg, sender_id="+919876543135")
    score, label = evaluate_flags(flags)
    assert label == "SCAM"
    assert score >= 70


def test_bijli_bill_pending_line_kat_jayegi_scam():
    """Hinglish bijli bill pending with line disconnection threat must be SCAM."""
    msg = "Bijli bill pending hai. Aaj shaam tak payment na karne par line kat di jayegi. Sampark karein 9823456789."
    flags = run_all_heuristics(msg, sender_id="+919876543137")
    score, label = evaluate_flags(flags)
    assert label == "SCAM"
    assert score >= 70


def test_electricity_restoration_pressure_scam():
    """Electricity connection suspended pressure demand must be SCAM."""
    msg = "Power supply disconnected for CA #901281. Call power department executive at 9811002233 for service restoration."
    flags = run_all_heuristics(msg, sender_id="+919876543138")
    score, label = evaluate_flags(flags)
    assert label == "SCAM"


def test_benign_bescom_bill_reminder_safe():
    """Legitimate electricity bill reminder without disconnection threats must be SAFE."""
    msg = (
        "Electricity bill reminder: Consumer #1029481, current bill amount Rs 1,420 "
        "due date is tomorrow 22-Nov-2026. Pay at your nearest BESCOM sub-division."
    )
    flags = run_all_heuristics(msg, sender_id="AX-BESCOM")
    score, label = evaluate_flags(flags)
    assert label == "SAFE"
    assert score < 40


def test_benign_utility_bill_generated_safe():
    """Routine bill generation notice with official web portal must be SAFE."""
    msg = "Your electricity bill for meter #892819 is generated. Amount Rs 940. Pay before 30-Nov at https://bescom.karnataka.gov.in."
    flags = run_all_heuristics(msg, sender_id="AX-BESCOM")
    score, label = evaluate_flags(flags)
    assert label == "SAFE"
    assert score < 40


def test_benign_roommate_electricity_chat_safe():
    """Peer conversation about splitting electricity bill must be SAFE."""
    msg = "Hey, our electricity bill for this month came out to Rs 1,120. Can you Google Pay me your half Rs 560?"
    flags = run_all_heuristics(msg, sender_id="+919876543105")
    score, label = evaluate_flags(flags)
    assert label == "SAFE"
    assert score < 40


def test_benign_power_maintenance_alert_safe():
    """Scheduled power maintenance alert without threats or contact mismatch must be SAFE."""
    msg = "Dear consumer, scheduled power maintenance in Indiranagar on Saturday 10 AM to 2 PM. Inconvenience regretted. - BESCOM"
    flags = run_all_heuristics(msg, sender_id="AX-BESCOM")
    score, label = evaluate_flags(flags)
    assert label == "SAFE"
    assert score < 40


# ==============================================================================
# FAMILY 3: TELECOM AUTHORITY & DISCONNECTION EXTORTION (HOLD_079)
# ==============================================================================

def test_hold_079_exact_message():
    """HOLD_079: Fake TRAI disconnection alert within short fuse must be SCAM."""
    msg = (
        "TRAI Disconnection Alert: Your mobile SIM service is scheduled for "
        "permanent disconnection in 2 hours due to illegal messaging. Call TRAI officer at 9876509922."
    )
    sender = "+919876543137"
    flags = run_all_heuristics(msg, sender)
    score, label = evaluate_flags(flags)
    assert label == "SCAM", f"Expected SCAM for HOLD_079, got {label} (score {score})"
    assert score >= 70


def test_fake_trai_sim_suspension_scam():
    """Fake TRAI SIM suspension warning with personal contact must be SCAM."""
    msg = "TRAI Notice: Your SIM card will be suspended within 24 hours due to Aadhaar de-linking. Contact TRAI officer at 9822334455."
    flags = run_all_heuristics(msg, sender_id="+919876543138")
    score, label = evaluate_flags(flags)
    assert label == "SCAM"
    assert score >= 70


def test_fake_dot_illegal_broadcasting_scam():
    """Department of Telecommunications claim with personal contact must be SCAM."""
    msg = "DoT Disconnection Notice: Illegal calls traced to your number. Disconnection in 2 hours. Call DoT officer at 9876543100."
    flags = run_all_heuristics(msg, sender_id="+919876543139")
    score, label = evaluate_flags(flags)
    assert label == "SCAM"
    assert score >= 70


def test_genuine_carrier_recharge_reminder_safe():
    """Legitimate telecom carrier plan validity reminder must be SAFE."""
    msg = "Dear Airtel customer, your current unlimited pack expires in 2 days on 23-Nov-2026. Recharge with Rs 299 to continue services."
    flags = run_all_heuristics(msg, sender_id="VM-AIRTEL")
    score, label = evaluate_flags(flags)
    assert label == "SAFE"
    assert score < 40


def test_genuine_telecom_support_ticket_safe():
    """Legitimate telecom customer support ticket update must be SAFE."""
    msg = "Your JioFiber service request #SR00029181 has been resolved. For any queries, please visit the MyJio app."
    flags = run_all_heuristics(msg, sender_id="AX-JIOFBR")
    score, label = evaluate_flags(flags)
    assert label == "SAFE"
    assert score < 40


# ==============================================================================
# FAMILY 4: QR CODE REVERSE-PAYMENT FRAUD (HOLD_100)
# ==============================================================================

def test_hold_100_exact_message():
    """HOLD_100: Reverse QR scam with intervening app phrase must be SCAM."""
    msg = (
        "Maine OLX item ke paise bhej diye hain. Scan this QR code in PhonePe to "
        "receive refund Rs 4,500 directly into your bank."
    )
    sender = "+919876543152"
    flags = run_all_heuristics(msg, sender)
    score, label = evaluate_flags(flags)
    assert label == "SCAM", f"Expected SCAM for HOLD_100, got {label} (score {score})"
    assert any(f.id == "PAYMENT_REDIRECT" for f in flags)
    assert score >= 70


def test_qr_phonepe_receive_money_scam():
    """QR receive money lure in PhonePe must be SCAM."""
    msg = "Scan this QR in PhonePe to receive money of Rs 2,500."
    flags = run_all_heuristics(msg, sender_id="+919876543153")
    score, label = evaluate_flags(flags)
    assert any(f.id == "PAYMENT_REDIRECT" for f in flags)
    assert score >= 70


def test_qr_gpay_claim_refund_scam():
    """QR claim refund lure using Google Pay must be SCAM."""
    msg = "Scan QR using Google Pay to claim refund of Rs 1,800."
    flags = run_all_heuristics(msg, sender_id="+919876543154")
    score, label = evaluate_flags(flags)
    assert any(f.id == "PAYMENT_REDIRECT" for f in flags)
    assert score >= 70


def test_qr_payment_app_receive_payment_scam():
    """QR code through payment app to receive payment must be SCAM."""
    msg = "Scan this code through your payment application to receive payment."
    flags = run_all_heuristics(msg, sender_id="+919876543155")
    score, label = evaluate_flags(flags)
    assert any(f.id == "PAYMENT_REDIRECT" for f in flags)
    assert score >= 70


def test_legitimate_counter_qr_pay_safe():
    """Legitimate instruction to scan QR code at counter to PAY bill must be SAFE."""
    msg = "Scan QR code at the counter to pay your bill of Rs 450."
    flags = run_all_heuristics(msg, sender_id="+919876543156")
    score, label = evaluate_flags(flags)
    assert label == "SAFE"
    assert not any(f.id == "PAYMENT_REDIRECT" for f in flags)


def test_legitimate_table_qr_menu_safe():
    """Legitimate instruction to scan QR code on restaurant table to view menu must be SAFE."""
    msg = "Scan the QR code on the table to view our digital menu."
    flags = run_all_heuristics(msg, sender_id="VK-RESTRO")
    score, label = evaluate_flags(flags)
    assert label == "SAFE"
    assert not any(f.id == "PAYMENT_REDIRECT" for f in flags)


def test_upi_qr_security_warning_safe():
    """Official educational security warning about QR codes must be SAFE."""
    msg = "UPI Security Tip: You never need to scan a QR code or enter your UPI PIN to receive money. Stay alert."
    flags = run_all_heuristics(msg, sender_id="AX-NPSTIP")
    score, label = evaluate_flags(flags)
    assert label == "SAFE"
    assert not any(f.id == "PAYMENT_REDIRECT" for f in flags)


def test_legitimate_refund_receipt_without_qr_safe():
    """Legitimate refund receipt confirmation must be SAFE."""
    msg = "Refund receipt: Refund of Rs 4,500 has been processed successfully to your account ending 1234. - HDFC Bank"
    flags = run_all_heuristics(msg, sender_id="AX-HDFCBK")
    score, label = evaluate_flags(flags)
    assert label == "SAFE"
    assert not any(f.id == "PAYMENT_REDIRECT" for f in flags)


# ==============================================================================
# FAMILY 5: ADVANCE-FEE PRIZE / REWARD FRAUD CORRECTIONS
# ==============================================================================

def test_exact_prize_processing_fee_scam():
    """Exact test case: Prize lure with upfront processing fee must be SCAM."""
    msg = "Congratulations! You won ₹25,000. Pay ₹500 processing fee immediately to claim your prize."
    flags = run_all_heuristics(msg)
    score, label = evaluate_flags(flags)
    assert label == "SCAM", f"Expected SCAM, got {label} with score {score}"
    assert score >= 70, f"Expected score >= 70, got {score}"
    assert any(f.id == "FINANCIAL_LURE" for f in flags)
    assert any(f.id == "PAYMENT_REDIRECT" for f in flags)


def test_prize_upfront_fee_no_urgency_scam():
    """Variation: Prize lure with upfront processing fee without urgency keywords must be SCAM."""
    msg = "You won ₹25,000. Pay ₹500 processing fee to claim your prize."
    flags = run_all_heuristics(msg)
    score, label = evaluate_flags(flags)
    assert label == "SCAM", f"Expected SCAM, got {label} with score {score}"
    assert score >= 70
    assert any(f.id == "FINANCIAL_LURE" for f in flags)
    assert any(f.id == "PAYMENT_REDIRECT" for f in flags)


def test_cash_prize_registration_fee_scam():
    """Variation: Cash prize requiring registration fee to claim must be SCAM."""
    msg = "You won a cash prize of ₹50,000! Pay ₹1,000 registration fee to claim your prize."
    flags = run_all_heuristics(msg)
    score, label = evaluate_flags(flags)
    assert label == "SCAM"
    assert score >= 70
    assert any(f.id == "FINANCIAL_LURE" for f in flags)
    assert any(f.id == "PAYMENT_REDIRECT" for f in flags)


def test_lottery_claiming_charges_scam():
    """Variation: Lottery jackpot requiring claiming charges transfer must be SCAM."""
    msg = "Congratulations! You won the lottery jackpot of ₹10,00,000. Transfer ₹2,500 claiming charges to release your funds."
    flags = run_all_heuristics(msg)
    score, label = evaluate_flags(flags)
    assert label == "SCAM"
    assert score >= 70
    assert any(f.id == "FINANCIAL_LURE" for f in flags)
    assert any(f.id == "PAYMENT_REDIRECT" for f in flags)


def test_advance_fee_claim_reward_notice_scam():
    """Variation: Advance clearance fee to claim prize reward must be SCAM."""
    msg = "Prize claim notice: Pay advance fee of ₹500 to claim your reward."
    flags = run_all_heuristics(msg)
    score, label = evaluate_flags(flags)
    assert label == "SCAM"
    assert score >= 70
    assert any(f.id == "FINANCIAL_LURE" for f in flags)
    assert any(f.id == "PAYMENT_REDIRECT" for f in flags)


def test_legitimate_reward_points_credited_safe():
    """Legitimate reward points notification with automatic statement credit must be SAFE."""
    msg = "Congratulations! You won 500 reward points on your HDFC credit card. Points will be automatically credited to your statement."
    flags = run_all_heuristics(msg, sender_id="AX-HDFCBK")
    score, label = evaluate_flags(flags)
    assert label == "SAFE", f"Expected SAFE, got {label} with score {score}"
    assert score < 40
    assert not any(f.id == "PAYMENT_REDIRECT" for f in flags)
    assert not any(f.id == "FINANCIAL_LURE" for f in flags)


def test_legitimate_wallet_cashback_credited_safe():
    """Legitimate cashback notification credited directly to wallet must be SAFE."""
    msg = "Your Amazon Pay cashback of Rs 50 for mobile recharge has been credited to your wallet."
    flags = run_all_heuristics(msg, sender_id="AX-AMZNPAY")
    score, label = evaluate_flags(flags)
    assert label == "SAFE", f"Expected SAFE, got {label} with score {score}"
    assert score < 40
    assert not any(f.id == "PAYMENT_REDIRECT" for f in flags)
    assert not any(f.id == "FINANCIAL_LURE" for f in flags)


def test_legitimate_fuel_rewards_earned_safe():
    """Legitimate credit card loyalty rewards earned on fuel transaction must be SAFE."""
    msg = "You have earned 120 ICICI Rewards on your fuel transaction at HPCL Outlet. Total points: 4,890."
    flags = run_all_heuristics(msg, sender_id="DZ-ICICIB")
    score, label = evaluate_flags(flags)
    assert label == "SAFE", f"Expected SAFE, got {label} with score {score}"
    assert score < 40
    assert not any(f.id == "PAYMENT_REDIRECT" for f in flags)
    assert not any(f.id == "FINANCIAL_LURE" for f in flags)


def test_legitimate_upi_cashback_received_safe():
    """Legitimate UPI cashback received notification must be SAFE."""
    msg = "Cashback of Rs 100 has been credited to your bank account via UPI. Ref no 123456."
    flags = run_all_heuristics(msg, sender_id="AX-SBIUPI")
    score, label = evaluate_flags(flags)
    assert label == "SAFE", f"Expected SAFE, got {label} with score {score}"
    assert score < 40
    assert not any(f.id == "PAYMENT_REDIRECT" for f in flags)


def test_ordinary_workplace_urgency_safe():
    """Ordinary workplace urgency request without fraud indicators must remain SAFE (<40)."""
    msg = "Urgent: please submit the quarterly budget report immediately before 5pm."
    flags = run_all_heuristics(msg)
    score, label = evaluate_flags(flags)
    assert label == "SAFE", f"Expected SAFE, got {label} with score {score}"
    assert score < 40
    assert not any(f.id == "PAYMENT_REDIRECT" for f in flags)
    assert not any(f.id == "FINANCIAL_LURE" for f in flags)


def test_ordinary_appointment_reminder_safe():
    """Routine medical appointment reminder must be SAFE (<40)."""
    msg = "Reminder: Your doctor appointment is scheduled for tomorrow at 10 AM. Please arrive 15 minutes early."
    flags = run_all_heuristics(msg, sender_id="VM-CLINIC")
    score, label = evaluate_flags(flags)
    assert label == "SAFE", f"Expected SAFE, got {label} with score {score}"
    assert score < 40


def test_ordinary_utility_due_reminder_safe():
    """Legitimate utility bill reminder with due date urgency must remain SAFE (<40)."""
    msg = "Urgent reminder: Your electricity bill payment of Rs 1,420 is due today. Pay via official BESCOM portal."
    flags = run_all_heuristics(msg, sender_id="AX-BESCOM")
    score, label = evaluate_flags(flags)
    assert label == "SAFE", f"Expected SAFE, got {label} with score {score}"
    assert score < 40
    assert not any(f.id == "PAYMENT_REDIRECT" for f in flags)



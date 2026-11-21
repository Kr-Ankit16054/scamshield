"""Evaluation Corpus for ScamShield.

Contains 30 carefully curated, real-world representative messages:
- 20 Scam/Phishing/Smishing messages spanning the 12 heuristic rule families
- 10 Legitimate/Benign everyday personal, transactional, and service messages
"""

from dataclasses import dataclass
from typing import List, Literal, Optional

RiskLabel = Literal["SAFE", "SUSPICIOUS", "SCAM"]


@dataclass(frozen=True)
class CorpusSample:
    id: str
    category: str
    expected_label: RiskLabel
    message: str
    sender_id: Optional[str] = None
    min_score: int = 0
    max_score: int = 100


CORPUS: List[CorpusSample] = [
    # ==========================================================================
    # 20 SCAM / FRAUDULENT SAMPLES
    # ==========================================================================
    CorpusSample(
        id="SCAM_01_SBI_KYC",
        category="Banking Phishing",
        expected_label="SCAM",
        message="URGENT: Dear SBI Customer, your account is suspended today due to KYC expired. Update KYC immediately at https://sbi-bank.xyz/login and submit OTP to avoid permanent deactivation.",
        sender_id="+919876543210",
        min_score=70,
    ),
    CorpusSample(
        id="SCAM_02_HDFC_CREDENTIALS",
        category="Credential Theft",
        expected_label="SCAM",
        message="Dear HDFC customer, your debit card is blocked due to suspicious activity. Send your 16-digit card number, CVV and 6-digit OTP immediately to unblock.",
        sender_id="+919123456789",
        min_score=70,
    ),
    CorpusSample(
        id="SCAM_03_KBC_LOTTERY",
        category="Lottery / Prize",
        expected_label="SCAM",
        message="Congratulations! You have won a prize of ₹25,00,000 in KBC Mega Lucky Draw! Claim your reward now with guaranteed returns by clicking https://bit.ly/kbc-prize.",
        sender_id="VK-PRIZE",
        min_score=70,
    ),
    CorpusSample(
        id="SCAM_04_INDIA_POST_CUSTOMS",
        category="Customs / Delivery",
        expected_label="SCAM",
        message="India Post Alert: Your parcel held at customs. Delivery address incomplete and courier fee due of ₹150. Package cannot be delivered without payment. Visit http://45.33.32.156/clearance",
        sender_id="+918877665544",
        min_score=70,
    ),
    CorpusSample(
        id="SCAM_05_ELECTRICITY_DISCONNECTION",
        category="Utility Threat",
        expected_label="SCAM",
        message="URGENT NOTICE: Your electricity power will be disconnected tonight at 9:30 PM due to unpaid bill arrear. Immediately call officer at 9876543210 to avoid disconnection.",
        sender_id="+919988112233",
        min_score=70,
    ),
    CorpusSample(
        id="SCAM_06_TAX_REFUND_REVERSE_UPI",
        category="Fake Refund",
        expected_label="SCAM",
        message="Income Tax Department: A refund of ₹14,500 is credited to your bank account. Click link to pay or claim your refund now: https://icici-online.top/claim",
        sender_id="IT-REFUND",
        min_score=70,
    ),
    CorpusSample(
        id="SCAM_07_YOUTUBE_JOB_SCAM",
        category="Employment Scam",
        expected_label="SCAM",
        message="Work from home part-time: no interview needed, earn ₹5000 daily by liking YouTube videos! Pay registration fee of ₹500 to begin instant daily payout.",
        sender_id="JOB-ALRT",
        min_score=70,
    ),
    CorpusSample(
        id="SCAM_08_TRAI_DISCONNECTION",
        category="Impersonation Threat",
        expected_label="SCAM",
        message="TRAI and DELHI POLICE notification: Your mobile number will be blocked within 24 hours due to illegal activities. Call officer at 9811223344 immediately.",
        sender_id="+919811223344",
        min_score=70,
    ),
    CorpusSample(
        id="SCAM_09_FEDEX_NARCOTICS",
        category="Courier Extortion",
        expected_label="SCAM",
        message="FedEx package seized at Mumbai Airport containing contraband. Mumbai Police Cyber Crime Cell issued arrest warrant. Call officer on 9845012345 immediately to clear customs.",
        sender_id="+919845012345",
        min_score=70,
    ),
    CorpusSample(
        id="SCAM_10_CRYPTO_DOUBLING",
        category="Investment Fraud",
        expected_label="SCAM",
        message="Special VIP Investment: Double your money in 48 hours! Guaranteed returns on crypto profit. Deposit ₹10,000 today and claim your reward of ₹50,000 at https://secure-login-crypto.xyz",
        sender_id="CRYPTO-WIN",
        min_score=70,
    ),
    CorpusSample(
        id="SCAM_11_HOMOGLYPH_PAYPAL",
        category="Homoglyph Spoofing",
        expected_label="SCAM",
        message="URGENT: Your P\u0430yp\u0430l account has unauthorized login attempts. Verify your account immediately at http://xn--payp-q1a.com/auth or access will be suspended within 24 hours.",
        sender_id="SEC-ALERT",
        min_score=70,
    ),
    CorpusSample(
        id="SCAM_12_PAN_AADHAAR_PENALTY",
        category="Government Phishing",
        expected_label="SCAM",
        message="Dear Taxpayer, update PAN Aadhaar link immediately to avoid deactivation and ₹10,000 penalty. Click https://netbanking-sbi.top/pan to complete KYC today.",
        sender_id="+919321456780",
        min_score=70,
    ),
    CorpusSample(
        id="SCAM_13_IP_PHISHING_CREDENTIALS",
        category="IP Direct Phishing",
        expected_label="SCAM",
        message="Your net banking access expired. Log in to http://192.168.1.105/bank/verify and enter OTP and MPIN to reactivate.",
        sender_id="+919100223344",
        min_score=70,
    ),
    CorpusSample(
        id="SCAM_14_EXCLAMATION_PRIZE",
        category="Emotional Manipulation",
        expected_label="SCAM",
        message="YOU WON 10 LAKHS CASH IN LUCKY DRAW TODAY!!!! CLAIM YOUR REWARD RIGHT NOW AT bit.ly/3claim9 !!!! HURRY BEFORE OFFER EXPIRES TODAY!!!!",
        sender_id="+919445566778",
        min_score=70,
    ),
    CorpusSample(
        id="SCAM_15_TELEGRAM_TASK_FRAUD",
        category="Task Scam",
        expected_label="SCAM",
        message="Earn ₹8000 per day! Work from home part time Telegram task job. No interview needed, guaranteed daily payout of ₹8000. Registration fee only ₹299.",
        sender_id="TASK-BOT",
        min_score=70,
    ),
    CorpusSample(
        id="SCAM_16_CUSTOMS_GIFT_HOLD",
        category="Customs Clearance",
        expected_label="SCAM",
        message="DHL shipment on hold: An international gift parcel held at customs clearance. Pay customs clearance fee of ₹3,400 to release parcel immediately: https://bit.ly/dhl-pay-fee",
        sender_id="+918765432190",
        min_score=70,
    ),
    CorpusSample(
        id="SCAM_17_WHATSAPP_REVERSE_PAYMENT",
        category="QR Reverse Payment",
        expected_label="SCAM",
        message="OLX Buyer: I have sent advance of ₹5,000. Scan QR code to receive money into your account or click link to pay ₹1 to verify refund.",
        sender_id="+919911223399",
        min_score=70,
    ),
    CorpusSample(
        id="SCAM_18_SBI_REWARD_POINTS",
        category="Rewards Phishing",
        expected_label="SCAM",
        message="Dear SBI user, your ₹9,850 reward points will expire today! Redeem cash prize to your bank account immediately by clicking https://sbi-bank.xyz/rewards",
        sender_id="+919933445566",
        min_score=70,
    ),
    CorpusSample(
        id="SCAM_19_AIRTEL_SIM_KYC",
        category="SIM Swap / KYC",
        expected_label="SCAM",
        message="Airtel Warning: Your SIM card will be deactivated within 24 hours. Update KYC immediately or call executive at 9876543210 to avoid cancellation.",
        sender_id="+919876543210",
        min_score=70,
    ),
    CorpusSample(
        id="SCAM_20_CARD_LIMIT_INCREASE",
        category="Card Fraud",
        expected_label="SCAM",
        message="Congratulations! Your credit card limit increased to ₹5,00,000. Share your OTP and CVV with executive to activate this free upgrade immediately.",
        sender_id="+919012345678",
        min_score=70,
    ),

    # ==========================================================================
    # 10 LEGITIMATE / SAFE SAMPLES
    # ==========================================================================
    CorpusSample(
        id="LEGIT_01_DINNER_PLAN",
        category="Personal Conversation",
        expected_label="SAFE",
        message="Hey Ankit, are we still on for dinner at 8 PM tonight? Let me know if you want me to pick you up.",
        sender_id=None,
        min_score=0,
        max_score=39,
    ),
    CorpusSample(
        id="LEGIT_02_SALARY_CREDIT",
        category="Transactional Bank Alert",
        expected_label="SAFE",
        message="Your A/C ending with 4567 is credited by INR 75,000 on 30-Nov-2024. Available balance INR 1,20,450. Info: SALARY-NOV. - HDFC Bank",
        sender_id="AX-HDFCBK",
        min_score=0,
        max_score=39,
    ),
    CorpusSample(
        id="LEGIT_03_ZOMATO_DELIVERY",
        category="Food Delivery",
        expected_label="SAFE",
        message="Your delivery partner Ramesh is on the way with your Zomato order. Track live on your Zomato mobile app. Enjoy your meal!",
        sender_id="ZM-ZOMATO",
        min_score=0,
        max_score=39,
    ),
    CorpusSample(
        id="LEGIT_04_INDIGO_FLIGHT",
        category="Travel Confirmation",
        expected_label="SAFE",
        message="IndiGo Flight 6E-204 from Delhi to Bengaluru is on schedule for departure at 10:15 AM tomorrow. Web check-in is now open.",
        sender_id="6E-INDIGO",
        min_score=0,
        max_score=39,
    ),
    CorpusSample(
        id="LEGIT_05_DOCTOR_APPOINTMENT",
        category="Healthcare Reminder",
        expected_label="SAFE",
        message="Reminder: You have an appointment with Dr. Sharma tomorrow at 4:30 PM at City Care Clinic. Please arrive 10 minutes prior.",
        sender_id="CLINIC",
        min_score=0,
        max_score=39,
    ),
    CorpusSample(
        id="LEGIT_06_ZOOM_MEETING",
        category="Work Invitation",
        expected_label="SAFE",
        message="Antigravity Team Sprint Planning is scheduled for Friday at 3:00 PM. The calendar event has been added to your work calendar.",
        sender_id=None,
        min_score=0,
        max_score=39,
    ),
    CorpusSample(
        id="LEGIT_07_MOBILE_RECHARGE",
        category="Telecom Service",
        expected_label="SAFE",
        message="Recharge of Rs.299 successful for your mobile number. Plan benefits: 1.5GB/day data, unlimited calls for 28 days. Thank you for choosing Jio.",
        sender_id="VK-JIOINF",
        min_score=0,
        max_score=39,
    ),
    CorpusSample(
        id="LEGIT_08_COLLEGE_NOTES",
        category="Peer Chat",
        expected_label="SAFE",
        message="Can you please share the lecture notes for Computer Networks when you get home? Thanks a lot!",
        sender_id=None,
        min_score=0,
        max_score=39,
    ),
    CorpusSample(
        id="LEGIT_09_AMAZON_DISPATCHED",
        category="Order Tracking",
        expected_label="SAFE",
        message="Your Amazon package containing 'Python Programming 3rd Ed' has been dispatched and will arrive by tomorrow evening.",
        sender_id="AM-AMAZON",
        min_score=0,
        max_score=39,
    ),
    CorpusSample(
        id="LEGIT_10_LIBRARY_RETURN",
        category="Institutional Reminder",
        expected_label="SAFE",
        message="Central Library: The borrowed book 'Designing Data-Intensive Applications' is due for return on 5th December. You may renew online.",
        sender_id="LIB-NOTIFY",
        min_score=0,
        max_score=39,
    ),
]

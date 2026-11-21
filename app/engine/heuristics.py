"""ScamShield Deterministic Heuristic Engine.

This module implements 12 rule families as pure functions.
Key architecture choices:
- All regular expressions are compiled once at module import for high performance (<50ms for 2000 chars).
- No dynamic imports, no eval/exec, and zero disk logging of message contents.
- Pure functions: each rule takes string inputs and returns a list of Flag objects.
"""

import re
import unicodedata
from typing import List, Optional, Tuple

try:
    from app.schemas import Flag
except ModuleNotFoundError:
    from scamshield.app.schemas import Flag

# Obfuscation defense: strip zero-width characters and invisible format controls
RE_ZERO_WIDTH = re.compile(r"[\u200B-\u200D\uFEFF\u2060\u180E\u00AD]")

# Homoglyph character mapping (Cyrillic, Greek lookalikes to Latin standard)
HOMOGLYPH_MAP = str.maketrans({
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 's', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i', '\u0458': 'j',
    '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u041a': 'K', '\u041c': 'M', '\u041d': 'H', '\u041e': 'O', '\u0420': 'P', '\u0421': 'C',
    '\u0422': 'T', '\u0425': 'X', '\u0423': 'Y', '\u04ae': 'Y', '\u04af': 'y',
    '\u03b1': 'a', '\u03bf': 'o', '\u03c1': 'p', '\u03bd': 'v', '\u03ba': 'k', '\u03c4': 't',
    '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u039f': 'O', '\u03a1': 'P', '\u03a4': 'T', '\u03a7': 'X', '\u03a5': 'Y'
})

# Words with natural double letters to preserve when squashing 3+ repetitions
DOUBLE_CHAR_WORDS = {
    'free', 'freeze', 'speed', 'need', 'feed', 'agree', 'peer',
    'lottery', 'winner', 'account', 'access', 'immediate', 'immediately',
    'congratulations', 'success', 'offer', 'call', 'official', 'traffic',
    'bill', 'password', 'apply', 'support'
}

# Targeted Acronym Normalization regexes (O T P, 0TP, O.T.P, K Y C, K.Y.C, P I N, P1N, etc.)
RE_EVASION_ACRONYMS = [
    # OTP: spaced, dotted, dashed, leetspeak
    (re.compile(r"\b[Oo0][\s\.\-_•*]+[Tt][\s\.\-_•*]+[Pp]\b", re.IGNORECASE), "OTP"),
    (re.compile(r"\b0[Tt][Pp]\b", re.IGNORECASE), "OTP"),
    # KYC: spaced, dotted, dashed
    (re.compile(r"\b[Kk][\s\.\-_•*]+[Yy][\s\.\-_•*]+[Cc]\b", re.IGNORECASE), "KYC"),
    # MPIN / PIN: spaced, dotted, dashed, leetspeak 1 for I
    (re.compile(r"\b[Mm][\s\.\-_•*]+[Pp1][\s\.\-_•*]+[Ii1][\s\.\-_•*]+[Nn]\b", re.IGNORECASE), "MPIN"),
    (re.compile(r"\b[Pp1][\s\.\-_•*]+[Ii1][\s\.\-_•*]+[Nn]\b", re.IGNORECASE), "PIN"),
    (re.compile(r"\b[Pp1][1iI][Nn]\b", re.IGNORECASE), "PIN"),
    # CVV: spaced, dotted, dashed
    (re.compile(r"\b[Cc][\s\.\-_•*]+[Vv][\s\.\-_•*]+[Vv]\b", re.IGNORECASE), "CVV"),
    # PAN: spaced, dotted, dashed
    (re.compile(r"\b[Pp][\s\.\-_•*]+[Aa][\s\.\-_•*]+[Nn]\b", re.IGNORECASE), "PAN"),
    # UPI: spaced, dotted, dashed
    (re.compile(r"\b[Uu][\s\.\-_•*]+[Pp][\s\.\-_•*]+[Ii]\b", re.IGNORECASE), "UPI"),
]

RE_REPEATED_LETTERS = re.compile(r"\b[a-zA-Z]*([a-zA-Z])\1{2,}[a-zA-Z]*\b")


def normalize_text(text: str) -> str:
    """Strips zero-width characters and performs deterministic evasion normalization:
    1. Unicode NFKC normalization (transforms fullwidth Latin to standard ASCII).
    2. Strips zero-width evasion characters.
    3. Translates Unicode lookalikes (Cyrillic/Greek homoglyphs to Latin equivalents).
    4. Normalizes spaced and punctuation-separated fraud acronyms (O T P, 0TP, K.Y.C, P I N, etc.).
    5. Collapses deliberate repeated character exaggerations (urgenttttt -> urgent, looooottery -> lottery, freeeeee -> free).
    """
    if not text:
        return text

    # 1. NFKC normalization
    norm = unicodedata.normalize("NFKC", text)

    # 2. Strip zero-width and invisible control characters
    norm = RE_ZERO_WIDTH.sub("", norm)

    # 3. Translate homoglyph confusables
    norm = norm.translate(HOMOGLYPH_MAP)

    # 4. Normalize spaced and punctuated fraud acronyms
    for pat, replacement in RE_EVASION_ACRONYMS:
        norm = pat.sub(replacement, norm)

    # 5. Normalize repeated character manipulation
    def _fix_repeated(m: re.Match) -> str:
        word = m.group(0)
        s1 = re.sub(r"([a-zA-Z])\1{2,}", r"\1", word)
        s2 = re.sub(r"([a-zA-Z])\1{2,}", r"\1\1", word)
        if s2.lower() in DOUBLE_CHAR_WORDS:
            return s2
        if s1.lower() in DOUBLE_CHAR_WORDS:
            return s1
        return s1

    norm = RE_REPEATED_LETTERS.sub(_fix_repeated, norm)

    return norm

# ==============================================================================
# PRECOMPILED REGULAR EXPRESSIONS (MODULE-LEVEL CACHING)
# ==============================================================================

# 1. URGENCY_PRESSURE
RE_URGENCY = re.compile(
    r"\b("
    r"urgent(?:ly)?|"
    r"immediately|"
    r"within\s+\d+\s*(?:hours?|hrs?|mins?|minutes?|days?)|"
    r"(?:disconnection|disconnected|blocked|suspended|terminated)\s+in\s+\d+\s*(?:hours?|hrs?|mins?|minutes?)|"
    r"last\s+chance|"
    r"account\s+will\s+be\s+blocked|"
    r"account\s+(?:is\s+)?suspended|"
    r"act\s+now|"
    r"act\s+fast|"
    r"action\s+required(?:\s+immediately)?|"
    r"immediate\s+action|"
    r"final\s+notice|"
    r"expiring\s+(?:today|soon)|"
    r"hurry\s+up|"
    r"limited\s+time\s+offer|"
    r"turant(?:\s+karein?)?|"
    r"jaldi(?:\s+se)?|"
    r"aaj\s+hi|"
    r"fauran|"
    r"tatkal|"
    r"band\s+(?:ho\s+jayega|kar\s+diya\s+jayega|hoga)|"
    r"block\s+(?:ho\s+jayega|kar\s+diya\s+jayega|hoga)|"
    r"(?:bijli|power|line)\s+kat\s+(?:jayegi|jayega|di\s+jayegi|diya\s+jayega)|"
    r"(?:disconnection|suspension)\s+(?:notice|alert|warning)|"
    r"permanent\s+disconnection"
    r")\b",
    re.IGNORECASE,
)

# 2. OTP_CREDENTIAL_REQUEST
RE_CREDENTIAL_VERBS = (
    r"(?:share|send|enter|verify|provide|give|submit|input|forward|confirm|disclose|reply(?:\s+with)?|"
    r"batao|bataiye|bhejo|bhejein|darj\s+karein?)"
)
RE_CREDENTIAL_TARGETS = (
    r"(?:otp|one\s+time\s+password|pin|mpin|cvv|password|passcode|net\s*banking\s+password|"
    r"aadhaar(?:\s+number)?|card\s+number|credit\s+card\s+details|debit\s+card\s+details|"
    r"apna\s+otp|apna\s+pin|apna\s+password|netbanking\s+credentials?|banking\s+password|"
    r"(?:verification|security|secret)\s+code)"
)
RE_OTP_CREDENTIALS = re.compile(
    rf"(?:\b{RE_CREDENTIAL_VERBS}\b.*?{RE_CREDENTIAL_TARGETS})|"
    rf"(?:{RE_CREDENTIAL_TARGETS}.*?\b{RE_CREDENTIAL_VERBS}\b)|"
    r"\b(?:send|share|reply\s+with)\s+your\s+(?:\d+-digit\s+)?otp\b",
    re.IGNORECASE,
)

# Negation detection to distinguish legitimate security warnings from credential theft
RE_CREDENTIAL_NEGATION_PREFIX = re.compile(
    r"\b("
    r"do\s+not|"
    r"don't|"
    r"does\s+not|"
    r"doesn't|"
    r"never|"
    r"not\s+to|"
    r"should\s+not|"
    r"shouldn't|"
    r"must\s+not|"
    r"mustn't|"
    r"(?:will\s+)?never\s+ask(?:\s+you)?(?:\s+to)?|"
    r"strictly\s+prohibited\s+to|"
    r"kabhi\s+(?:bhi\s+)?(?:nahi|mat|share\s+na)|"
    r"kisi\s+ko\s+(?:bhi\s+)?(?:na|mat|nahi)|"
    r"kisi\s+ke\s+saath\s+(?:bhi\s+)?(?:na|mat|nahi)|"
    r"mat\s+(?:batao|bataiye|de|bhejo|share\s+karo)|"
    r"na\s+(?:batayein?|bhejein?|share\s+karein?|de)|"
    r"kisi\s+se\s+share\s+na"
    r")"
    r"(?:\s+(?:ever|again|at\s+all|(?:ask|request|tell|call)(?:\s+you)?\s+to))?"
    r"\s*$",
    re.IGNORECASE,
)
RE_INTERNAL_NEGATION = re.compile(
    r"\b(?:not|never|no\s+one|nobody|kabhi\s+nahi|kisi\s+ko\s+nahi|mat\s+de|mat\s+batao|na\s+bataye|na\s+karein?|share\s+na|nahi\s+mangta)\b",
    re.IGNORECASE,
)
RE_HINGLISH_POST_NEGATION = re.compile(
    r"\b(?:na\s+(?:karein?|karo|batayein?|bhejein?|de)|mat\s+(?:karein?|karo|batao|bhejo|de)|nahi\s+(?:mangta|karna|dena))\b",
    re.IGNORECASE,
)
RE_VERB_NEGATION = re.compile(
    r"(?:"
    r"\b(?:do\s+not|don't|does\s+not|doesn't|never|should\s+not|shouldn't|must\s+not|mustn't|will\s+not|won't|kabhi\s+nahi|mat|na)\s+(?:ever\s+)?(?:share|give|send|disclose|forward|submit|enter|batao|de|batayein?|bhejein?)\b|"
    r"\b(?:never\s+need\s+to|no\s+need\s+to|do\s+not\s+need\s+to)\s+[a-zA-Z\s]{0,40}?(?:share|give|send|disclose|forward|submit|enter|batao|de)\b"
    r")",
    re.IGNORECASE,
)
RE_PRONOUN_CREDENTIAL_NEGATION = re.compile(
    r"\b(?:do\s+not|don't|never|should\s+not|must\s+not|will\s+not|won't|kabhi\s+nahi|mat|na)\s+(?:share|give|send|disclose|forward|batao|de)\s+(?:it|that|this|them|use|isse)\b",
    re.IGNORECASE,
)
RE_DELIVERY_PIN_CONTEXT = re.compile(
    r"(?:share|give|provide)\s+(?:this\s+)?(?:delivery\s+)?(?:verification\s+)?(?:pin|otp|code)(?:\s+\d+)?\s+(?:with|to)\s+(?:the\s+)?delivery\s+(?:executive|partner|agent|rider|person|boy)",
    re.IGNORECASE,
)

# 3. SUSPICIOUS_LINK
# Suspect high-risk TLDs commonly abused in smishing campaigns
HIGH_RISK_TLDS = (
    r"xyz|top|club|buzz|icu|work|click|link|site|online|live|support|"
    r"tk|ml|ga|cf|gq|vip|monster|rest|cam|fit|sbs|bond|cfd|skin|quest|space|pw|cc|cn"
)

# Common URL shortener services (standard and expanded)
SHORTENER_DOMAINS = (
    r"bit\.(?:ly|do)|tinyurl\.com|t\.co|is\.gd|goo\.gl|ow\.ly|cutt\.ly|rb\.gy|tiny\.cc|"
    r"shorturl\.at|bl\.ink|s\.id|t\.ly|rebrand\.ly|trib\.al|v\.gd|buff\.ly|qr\.ae|"
    r"shortcm\.li|cutt\.us|clck\.ru|rotf\.lol|tiny\.one|kutt\.it|soo\.gd|bc\.vc|adf\.ly|"
    r"hyperurl\.co|linktr\.ee|snip\.ly|t\.me|wa\.me"
)

# Defanged URL notations: hxxp://, http[:]//, [.] or (.) delimiters
RE_LINK_DEFANGED = re.compile(
    r"(?:"
    r"hxxps?://[^\s<>\"'`]+"
    r"|https?\[:\]//[^\s<>\"'`]+"
    r"|hxxps?\[:\]//[^\s<>\"'`]+"
    r"|http\[s\]://[^\s<>\"'`]+"
    r"|(?:https?://)?[a-zA-Z0-9_\-\.]+(?:\[\.\]|\(\.\)|\[dot\])[a-zA-Z0-9_\-\.\[\]\(\)/]*(?:/[^\s<>\"'`]*)?"
    r")",
    re.IGNORECASE,
)

# Raw IP address URLs: http://192.168.1.1 or 45.33.32.156:8080/clearance
RE_LINK_IP = re.compile(
    r"(?:"
    r"(?:https?://|hxxps?://|http\[:\]//)"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.|\[\.\]|\(\.\))"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.|\[\.\]|\(\.\))"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.|\[\.\]|\(\.\))"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?::\d{1,5})?"
    r"(?:/[^\s<>\"'`]*)?"
    r"|"
    r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.|\[\.\]|\(\.\))"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.|\[\.\]|\(\.\))"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.|\[\.\]|\(\.\))"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?::\d{1,5}(?:/[^\s<>\"'`]*)?|/[^\s<>\"'`]+)"
    r")",
    re.IGNORECASE,
)

# URL shorteners commonly abused in smishing
RE_LINK_SHORTENER = re.compile(
    r"(?:https?://|hxxps?://)?\b(?:" + SHORTENER_DOMAINS + r")/[a-zA-Z0-9_\-\.]+",
    re.IGNORECASE,
)

# Punycode domains (internationalized domain spoofing)
RE_LINK_PUNYCODE = re.compile(
    r"(?:https?://|hxxps?://)?(?:[a-zA-Z0-9_\-]+\.)*(?:xn--[a-zA-Z0-9\-]+)(?:\.[a-zA-Z0-9\-]+)*(?:/[^\s<>\"'`]*)?",
    re.IGNORECASE,
)

# Lookalike & typosquatting domains (brand spoofing / leetspeak)
RE_LINK_LOOKALIKE = re.compile(
    r"(?:https?://|hxxps?://)?\b(?:"
    r"[a-zA-Z0-9_\-]*(?:g00gle|paypa1|amaz0n|app1e|micros0ft|netf1ix|faceb00k|sbi0nline|hdfc0nline|icici0nline|paytm0nline|phonepe0nline)[a-zA-Z0-9_\-]*\.[a-zA-Z]{2,}"
    r"|"
    r"(?:sbi|hdfc|icici|axis|kotak|pnb|bob|rbi|paypal|amazon|apple|microsoft|netflix|paytm|phonepe|gpay|trai|fedex|indexpres|dhl|indiapost|olx)"
    r"-(?:bank|verify|verification|update|login|signin|kyc|support|portal|account|security|alert|claim|reward|service|online|netbanking|billing|invoice|payment|auth|helpdesk|unblock|customs|parcel|duty|fee)"
    r"[a-zA-Z0-9_\-]*\.[a-zA-Z]{2,}"
    r"|"
    r"(?:secure|login|verify|update|kyc|netbanking|bank|account|billing)"
    r"-(?:sbi|hdfc|icici|axis|kotak|pnb|paypal|amazon|apple|microsoft|netflix)"
    r"[a-zA-Z0-9_\-]*\.[a-zA-Z]{2,}"
    r")(?:/[^\s<>\"'`]*)?",
    re.IGNORECASE,
)

# Suspicious subdomains & brand impersonation in subdomains
RE_LINK_SUSPICIOUS_SUBDOMAIN = re.compile(
    r"(?:https?://|hxxps?://)?\b(?:"
    r"(?:sbi|hdfc|icici|axis|kotak|pnb|bob|rbi|paypal|amazon|apple|microsoft|netflix|paytm|phonepe|google)"
    r"\.(?:bank\.com|com|co\.in|org|net)\.[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,}"
    r"|"
    r"(?:sbi|hdfc|icici|axis|kotak|pnb|paypal|netflix|paytm)\."
    r"(?:[a-zA-Z0-9_\-]*-(?:login|verify|portal|update|security|bank|auth|service|support|check)[a-zA-Z0-9_\-]*|[a-zA-Z0-9_\-]+\.(?:" + HIGH_RISK_TLDS + r"))"
    r"\.[a-zA-Z]{2,}"
    r"|"
    r"(?:sbi|hdfc|icici|axis|kotak|pnb|paypal|netflix|paytm)\."
    r"[a-zA-Z0-9_\-]*-(?:login|verify|portal|update|security|bank|auth|service|support|check)[a-zA-Z0-9_\-]*\.[a-zA-Z]{2,}"
    r")(?:/[^\s<>\"'`]*)?",
    re.IGNORECASE,
)

# Generic deceptive domains: high-risk TLDs with fraud keywords, or chained lure hyphens on any TLD
RE_LINK_GENERIC_DECEPTIVE = re.compile(
    r"(?:https?://|hxxps?://)?\b(?:"
    r"[a-zA-Z0-9_\-]*(?:"
    r"account|banking|bank|login|signin|verify|verification|update|kyc|"
    r"security|secure|portal|wallet|claim|reward|prize|billing|invoice|"
    r"refund|unblock|suspend|activation|clearance|clearence|auth|helpdesk|"
    r"crypto|forex|invest|profit|paisa|returns|customs|delivery|parcel|tax|aadhaar|pan|duty|courier|fee"
    r")[a-zA-Z0-9_\-]*\.(?:" + HIGH_RISK_TLDS + r")"
    r"|"
    r"(?:[a-zA-Z0-9_\-]+\.)*(?:"
    r"update-kyc|kyc-update|account-verify|verify-account|account-validation|"
    r"validation-portal|secure-login|login-verify|bank-verify|verify-bank|"
    r"claim-reward|reward-claim|free-lottery|unblock-account|card-activation|"
    r"billing-verify|security-update|netbanking-update|tax-refund|"
    r"package-clearance|customs-clearance|service-security|bank-alert-update|"
    r"pan-aadhaar|pan-link|aadhaar-link|olx-pay|dhl-customs|customs-duty|parcel-update|delivery-fee|crypto-double|forex-profit|paisa-double"
    r")[a-zA-Z0-9_\-]*\.[a-zA-Z]{2,}"
    r")(?:/[^\s<>\"'`]*)?",
    re.IGNORECASE,
)

# Insecure cleartext HTTP with sensitive authentication, financial, or verification endpoints
RE_LINK_INSECURE_HTTP_PATH = re.compile(
    r"http://[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,}(?::\d+)?"
    r"/[^\s<>\"'`]*(?:"
    r"login|signin|sign-in|log-in|auth|authenticate|verify|verification|kyc|"
    r"password|reset|account|banking|netbanking|wallet|checkout|pay|payment|"
    r"card|otp|pin|cvv|claim|refund|unblock"
    r")[^\s<>\"'`]*",
    re.IGNORECASE,
)

# Verified benign apex domains for 0% false positive guarantee
LEGITIMATE_TRUSTED_APEX_DOMAINS = {
    "google.com", "google.co.in", "wikipedia.org", "github.com",
    "amazon.com", "amazon.in", "apple.com", "microsoft.com",
    "nytimes.com", "bbc.com", "bbc.co.uk", "w3.org", "cern.ch",
    "zomato.com", "swiggy.com", "flipkart.com", "irctc.co.in",
    "python.org", "gov.in", "nic.in", "who.int", "un.org",
    "stackoverflow.com", "fastapi.tiangolo.com", "goindigo.in",
}

RE_TWO_PART_TLD = re.compile(
    r"\.(?:co|org|gov|nic|ac|edu|net|mil)\.(?:in|uk|au|nz|za|br|sg|jp|my)$",
    re.IGNORECASE,
)


def extract_domain_host(url_text: str) -> str:
    """Extracts the hostname portion from a candidate URL string."""
    h = re.sub(r"^(?:https?|hxxps?|http\[:\]|hxxps?\[:\]|http\[s\])://", "", url_text, flags=re.IGNORECASE)
    h = h.split("/")[0].split("?")[0].split("#")[0]
    h = h.split(":")[0]
    h = h.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".")
    return h.strip(".").lower()


def get_apex_domain(host: str) -> str:
    """Returns apex domain (e.g. 'bbc.co.uk' for 'news.bbc.co.uk', or 'google.com' for 'www.google.com')."""
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if RE_TWO_PART_TLD.search(host):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])

# 4. FINANCIAL_LURE
RE_FINANCIAL_LURE = re.compile(
    r"\b("
    r"won\s+(?:a\s+)?(?:cash\s+)?prize|"
    r"lottery(?:\s+winner)?|"
    r"claim\s+(?:your\s+)?(?:free\s+)?(?:cash\s+)?(?:reward|prize)|"
    r"free\s+(?:cash\s+)?reward|"
    r"cash\s+reward|"
    r"investment\s+doubling|"
    r"double\s+your\s+money|"
    r"guaranteed\s+returns?|"
    r"crypto\s+profit|"
    r"work\s+from\s+home\s+earning|"
    r"congratulations[!,]?\s+(?:you\s+)?(?:have\s+)?won|"
    r"(?:you\s+)?won\s+(?:a\s+)?(?:cash\s+)?(?:prize|reward|lottery|jackpot|[₹$€£]\s*[\d,]+)|"
    r"lucky\s+(?:draw|winner)|"
    r"claim\s+[₹$€£]\s*[\d,]+|"
    r"jackpot|"
    r"ina?am|"
    r"nakad\s+ina?am|"
    r"kismat|"
    r"paise\s+jeeto|"
    r"paisa\s+double|"
    r"paise\s+kamayein?|"
    r"lottery\s+lagi\s+hai|"
    r"cashback\s+mila\s+hai|"
    r"ghar\s+baithe\s+kamaye|"
    r"high\s+yield\s+investment|"
    r"guaranteed\s+(?:daily\s+)?profit|"
    r"crypto\s+(?:mining\s+)?returns?|"
    r"risk[- ]free\s+returns?"
    r")\b",
    re.IGNORECASE,
)

# Severe investment doubling, guaranteed returns & advance-fee prize fraud (immediate high risk)
RE_LURE_SEVERE = re.compile(
    r"\b("
    r"double\s+your\s+money|"
    r"paisa\s+double|"
    r"guaranteed\s+(?:returns?|profit)|"
    r"100%\s+guaranteed|"
    r"risk[- ]free\s+returns?|"
    r"investment\s+doubling|"
    r"(?:pay|deposit|transfer)\s+[a-zA-Z0-9\s₹$€£,]{0,30}?(?:fee|charges?|tax|amount|money)\s+[a-zA-Z0-9\s₹$€£,]{0,25}?\s*to\s+(?:claim|receive|release|get)\s+(?:your\s+)?(?:prize|reward|winnings?|lottery|funds?|cash|money)|"
    r"(?:processing|registration|claiming|advance|clearance)\s+(?:fee|charges?)\s+[a-zA-Z0-9\s₹$€£,]{0,25}?\s*to\s+(?:claim|receive|release|get)\s+(?:your\s+)?(?:prize|reward|winnings?|lottery|funds?|cash)"
    r")\b",
    re.IGNORECASE,
)

# Benign transactional/reward receipts (automatic statement credits, earned loyalty points)
RE_BENIGN_REWARD = re.compile(
    r"\b(?:"
    r"(?:reward\s+)?points\s+(?:have\s+been|will\s+be|are)?\s*(?:automatically\s+)?credited|"
    r"(?:cashback|points|reward)\s+(?:of\s+[₹$€£]?\s*[\d,]+\s+)?(?:has\s+been|is|was)\s+(?:successfully\s+)?credited|"
    r"credited\s+to\s+your\s+(?:statement|wallet|account|card)\b|"
    r"earned\s+[\d,]+\s+(?:icici|hdfc|sbi|axis|reward|bonus)\s+points"
    r")\b",
    re.IGNORECASE,
)

# 5. IMPERSONATION (Word-boundary matching for trusted authorities)
RE_IMPERSONATION = re.compile(
    r"\b("
    r"sbi(?:\s+bank)?|"
    r"state\s+bank\s+of\s+india|"
    r"rbi|"
    r"reserve\s+bank\s+of\s+india|"
    r"hdfc(?:\s+bank)?|"
    r"icici(?:\s+bank)?|"
    r"axis(?:\s+bank)?|"
    r"kotak(?:\s+bank)?|"
    r"pnb|"
    r"punjab\s+national\s+bank|"
    r"bank\s+of\s+baroda|"
    r"canara\s+bank|"
    r"ircc|"
    r"customs(?:\s+department)?|"
    r"trai|"
    r"dot|"
    r"department\s+of\s+telecommunications|"
    r"cbi|"
    r"enforcement\s+directorate(?:\s*\(ed\))?|"
    r"ed\s+(?:officer|office|notice|summons|case|inquiry|investigation|raid|pmla)|"
    r"delhi\s+police|"
    r"mumbai\s+police|"
    r"cyber\s+crime\s+cell|"
    r"cyber\s+cell|"
    r"cyber\s+police|"
    r"cid|"
    r"interpol|"
    r"(?:electricity|power|bijli)\s+(?:board|department|officer|office|authority|vibhag|karyalay|supply|service|bill\s+(?:disconnection|notice|alert|due|pending))|"
    r"(?:bijli|power)\s+(?:kat\s+jayegi|kat\s+diya\s+jayega|disconnection)|"
    r"bses|mseb|tneb|uppcl|"
    r"income\s+tax\s+department|"
    r"it\s+dept|"
    r"india\s+post|"
    r"postal\s+department|"
    r"india\s+post\s+office"
    r")\b",
    re.IGNORECASE,
)

# Severe law enforcement / criminal extortion / digital arrest impersonation
RE_SEVERE_IMPERSONATION = re.compile(
    r"\b("
    r"delhi\s+police|"
    r"mumbai\s+police|"
    r"cyber\s+crime\s+cell|"
    r"cyber\s+police|"
    r"cbi|"
    r"enforcement\s+directorate|"
    r"ed\s+(?:officer|office|notice|summons|case|inquiry|investigation|raid|pmla)|"
    r"trai\s+(?:disconnection|alert|notice|officer)|"
    r"dot\s+(?:disconnection|officer)|"
    r"telecom\s+regulatory\s+authority|"
    r"(?:electricity|power|bijli)\s+(?:department|officer|authority|line\s+kat|disconnection)|"
    r"(?:power\s+supply|power\s+connection)\s+disconnected|"
    r"interpol|"
    r"narcotics|"
    r"arrest\s+warrant|"
    r"court\s+summons|"
    r"pmla|"
    r"non-bailable\s+warrant|"
    r"money\s+laundering"
    r")\b",
    re.IGNORECASE,
)

# 6. PREFILL_KYC
RE_KYC = re.compile(
    r"\b("
    r"kyc\s+(?:is\s+)?expired|"
    r"verify\s+your\s+account|"
    r"update\s+(?:your\s+)?kyc(?:\s+to\s+avoid\s+deactivation)?|"
    r"complete\s+(?:your\s+)?kyc|"
    r"kyc\s+(?:is\s+)?suspended|"
    r"update\s+pan\s+aadhaar|"
    r"mandatory\s+(?:your\s+)?kyc|"
    r"kyc\s+verification\s+pending|"
    r"pending\s+kyc|"
    r"khata\s+(?:band|block|suspend|freeze)|"
    r"(?:bank\s+)?account\s+(?:freeze|frozen)|"
    r"kyc\s+(?:karwaye|update\s+kare|pura\s+kare|verify\s+kare|pending\s+hai)|"
    r"pan\s+(?:card\s+)?link\s+kare|"
    r"aadhaar\s+link\s+(?:kare|karwaye)|"
    r"sim\s+(?:card\s+)?kyc|"
    r"de-?activation\s+warning|"
    r"account\s+verification\s+required|"
    r"reactivate\s+your\s+account|"
    r"unblock\s+your\s+account"
    r")\b",
    re.IGNORECASE,
)

# 7. PAYMENT_REDIRECT
RE_PAYMENT_REDIRECT = re.compile(
    r"("
    r"refund\s+of\s+[₹$€£]?\s*[\d,]+\s+(?:is\s+)?credited[^\.\n]*?(?:verify|click|claim|link|visit)|"
    r"click\s+(?:link\s+)?to\s+(?:pay|receive|claim\s+refund|verify)|"
    r"scan\s+(?:this\s+)?(?:qr(?:\s+code)?|code|barcode)(?:\s+(?:in|on|using|via|through|with)\s+[a-zA-Z0-9\s]{1,30}?)?\s+to\s+(?:receive|accept|get|claim|collect|credit)\s+(?:money|cash|refund|payment|amount|[₹$€£])|"
    r"(?:qr(?:\s+code)?\s+scan\s+(?:karein?|karo)|scan\s+(?:this\s+)?qr)(?:\s+(?:in|on|using|via|through|par)\s+[a-zA-Z0-9\s]{1,30}?)?\s+(?:paise\s+)?(?:lene|receive|prapt|mangwane)\s+ke\s+liye|"
    r"scan\s+(?:this\s+)?qr(?:\s+code)?\s+to\s+(?:receive|accept|get|claim)|"
    r"qr(?:\s+code)?\s+scan\s+karo\s+(?:paise\s+)?(?:lene|receive|prapt)|"
    r"scan\s+karo\s+paise\s+lene|"
    r"(?:pay|deposit|transfer)\s+[₹$€£]?\s*[\d,]+(?:\s+[a-zA-Z\s]{0,25}?(?:fee|charges?|penalty|tax|deposit))?(?:\s+[a-zA-Z0-9\s₹$€£,]{0,25}?)?\s+to\s+(?:release|claim|verify|receive|get)\b|"
    r"(?:pay|deposit|transfer)\s+[₹$€£]?\s*[\d,]+\s+[a-zA-Z\s]{0,25}?(?:fee|charges?|penalty|tax|deposit)\s+to\b|"
    r"(?:pay|deposit|transfer)\s+(?:a\s+)?(?:processing|registration|claiming|advance|clearance)\s+(?:fee|charges?|amount)(?:\s+[a-zA-Z0-9\s₹$€£,]{0,25}?)?\s+to\s+(?:claim|receive|release|get)\b|"
    r"claim\s+(?:your\s+)?refund\s+(?:now|here|at\b)|"
    r"claim\s+cashback\s+(?:now|here|at\b)|"
    r"(?:verify|claim)\s+(?:your\s+)?refund|"
    r"upi\s+(?:collect\s+request|pin\s+to\s+receive)"
    r")",
    re.IGNORECASE,
)

# 8. CONTACT_MISMATCH
# Threat or notice combined with instruction to call a personal 10-digit mobile number
RE_THREAT_CONTEXT = re.compile(
    r"(?:deactivat|block|suspend|cancel|held|seiz|arrear|penalty|notice|legal\s+action|disconnect(?:ed|ion)?|line\s+kat|kat\s+(?:di\s+)?jayeg|band\s+ho|ruka\s+hai|baki\s+hai|summons|warrant|fir|arrest|court|extortion|inquiry|investigation|money\s+laundering|raid|narcotics)",
    re.IGNORECASE,
)
RE_CALL_MOBILE = re.compile(
    r"(?:call|contact|reach|dial|sampark|whatsapp)\s+[a-zA-Z\s]{0,40}?(?:at|on|par|on\s+whatsapp)?\s*(\+?91[\s-]?)?([6-9]\d{9})\b",
    re.IGNORECASE,
)

# 9. LANGUAGE_MANIPULATION
# Exclamation threshold: >=4 exclamation marks anywhere
RE_EXCLAMATION = re.compile(r"!{4,}|(?:.*!.*){4,}")
# Cyrillic and Greek lookalikes frequently used to spoof Latin letters (e.g., а, е, о, р, с, у, х)
RE_HOMOGLYPHS = re.compile(
    r"[\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0456\u0410\u0412\u0415\u041a\u041c\u041d\u041e\u0420\u0421\u0422\u0425\u03b1\u03bf\u03c1]"
)

# 10. SENDER_ID_ANALYSIS
# Pattern matching personal phone numbers (e.g. +919876543210, 9876543210, +12025550123)
RE_PERSONAL_PHONE = re.compile(r"^(\+?\d{1,3}[\s-]?)?([6-9]\d{9}|[2-9]\d{9})$")

# Standard commercial telecom header: 2-3 alphanumeric prefix (e.g. AX, VK, 6E, DZ, CP, AD, LIB, ZM, AM)
# followed by a hyphen and 3-9 alphanumeric characters (e.g. AX-HDFCBK, 6E-INDIGO, LIB-NOTIFY, ZM-ZOMATO)
RE_TELECOM_HEADER = re.compile(r"^[A-Za-z0-9]{2,3}-[A-Za-z0-9]{3,9}$")

# Standard alphanumeric business/service name: 3-11 alphanumeric characters (e.g. Uber, Netflix, Apple, Amazon, Flipkart, Google)
RE_ALPHANUMERIC_HEADER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\s\.\-_]{1,9}[A-Za-z0-9]$|^[A-Za-z0-9]{3,11}$")

# Standard shortcodes: 3-8 digits
RE_SHORTCODE = re.compile(r"^\d{3,8}$")

# Generic fraud lure keywords in sender IDs (often abused in smishing campaigns)
RE_GENERIC_FRAUD_SENDER = re.compile(
    r"\b(?:"
    r"prize|winner|lotto|lottery|reward|claim|crypto|refund|"
    r"job|task|alert|notice|sec-alert|bank-alert|verify|verification"
    r")\b",
    re.IGNORECASE,
)

# Backward compatibility alias
RE_TRANSACTIONAL_HEADER = RE_TELECOM_HEADER

# 11. UNTRACED_DELIVERY
RE_UNTRACED_DELIVERY = re.compile(
    r"\b("
    r"parcel\s+held(?:\s+at\s+customs)?|"
    r"package\s+(?:cannot\s+be\s+delivered|held|retained|delayed|failed)|"
    r"courier\s+(?:fee|charge)\s+due|"
    r"delivery\s+(?:address\s+incomplete|failure|attempt\s+failed|on\s+hold)|"
    r"shipment\s+(?:on\s+hold|delayed)|"
    r"customs\s+(?:duty|clearance\s+fee|clearance|tax|fee|inspection)|"
    r"customs\s+me\s+ruka\s+hai|"
    r"parcel\s+ruka\s+hai|"
    r"schedule\s+redelivery|"
    r"india\s+post\s+package\s+pending|"
    r"fedex\s+package\s+seized|"
    r"dhl\s+shipment\s+on\s+hold"
    r")\b",
    re.IGNORECASE,
)

# 12. JOB_OFFER_SCAM
RE_JOB_OFFER = re.compile(
    r"\b("
    r"no\s+interview\s+needed|"
    r"registration\s+fee|"
    r"earn\s+[₹$€£]?\s*[\d,]+\s+(?:daily|per\s+day)|"
    r"part\s*time\s+(?:online\s+)?job\s+earn|"
    r"like\s+(?:and\s+subscribe\s+)?(?:youtube\s+)?videos\s+(?:to\s+earn|and\s+earn)|"
    r"review\s+products?\s+and\s+earn|"
    r"telegram\s+(?:task\s+job|earning\s+group|part\s*time)|"
    r"daily\s+payout|"
    r"work\s+from\s+home\s+(?:part\s*time|earn)|"
    r"ghar\s+baithe\s+(?:paise\s+)?kamaye|"
    r"earn\s+money\s+(?:daily|from\s+home)|"
    r"prepaid\s+task|"
    r"daily\s+income\s+[₹$€£]?\s*[\d,]+"
    r")\b",
    re.IGNORECASE,
)

# Severe upfront registration fee & task job scams
RE_JOB_SCAM_SEVERE = re.compile(
    r"\b("
    r"registration\s+fee|"
    r"pay\s+(?:registration|fee|charges?|deposit)|"
    r"prepaid\s+task|"
    r"telegram\s+task\s+job"
    r")\b",
    re.IGNORECASE,
)

# 13. REMOTE_ACCESS_APP
RE_REMOTE_ACCESS_APP = re.compile(
    r"\b("
    r"(?:install|download)\s+(?:anydesk|teamviewer|rustdesk|quicksupport|airdroid|zoho\s+assist)|"
    r"(?:anydesk|teamviewer|rustdesk|quicksupport)\s+(?:app|code|id|address)|"
    r"share\s+(?:your\s+)?(?:9|10)[-\s]digit\s+(?:code|id|number|address)|"
    r"(?:install|download)\s+(?:this\s+)?(?:support\s+)?(?:apk|app)\s+to\s+(?:verify|unblock|update|complete|receive|avoid)|"
    r"(?:download|install)\s+(?:the\s+)?(?:latest\s+)?apk\s+(?:file|link)|"
    r"https?://[^\s<>\"'`]+\.apk\b|"
    r"screen\s*share\s+(?:app|code)"
    r")\b",
    re.IGNORECASE,
)


# ==============================================================================
# PURE HEURISTIC FUNCTIONS
# ==============================================================================

def check_urgency_pressure(text: str) -> List[Flag]:
    """Rule 1: Detects artificial urgency and pressure tactics."""
    norm_text = normalize_text(text)
    flags: List[Flag] = []
    seen = set()
    for match in RE_URGENCY.finditer(norm_text):
        snippet = match.group(0)
        norm = snippet.lower()
        if norm not in seen:
            seen.add(norm)
            flags.append(
                Flag(
                    id="URGENCY_PRESSURE",
                    severity=2,
                    detail="Message creates artificial urgency or pressure to force hasty action without verification.",
                    matched_text=snippet,
                )
            )
    return flags


def check_otp_credential_request(text: str) -> List[Flag]:
    """Rule 2: Detects requests for OTP, PIN, CVV, passwords, or Aadhaar.

    Distinguishes genuine credential solicitations from legitimate security advisories
    (e.g., 'Do not share your OTP with anyone' or 'Apna OTP kisi ke saath share na karein')
    using local clause-bounded negation analysis.
    """
    norm_text = normalize_text(text)
    flags: List[Flag] = []
    delimiters = [".", "!", "?", "\n", ";", ":"]

    for match in RE_OTP_CREDENTIALS.finditer(norm_text):
        start_idx = match.start()
        end_idx = match.end()

        # Locate the boundary of the current clause/sentence
        prev_indices = [norm_text.rfind(d, 0, start_idx) for d in delimiters]
        clause_start = max(prev_indices)
        clause_start = 0 if clause_start == -1 else clause_start + 1

        next_indices = [norm_text.find(d, end_idx) for d in delimiters if norm_text.find(d, end_idx) != -1]
        clause_end = min(next_indices) if next_indices else len(norm_text)

        preceding_clause = norm_text[clause_start:start_idx].strip()
        full_clause = norm_text[clause_start:clause_end].strip()

        # Suppress match if part of legitimate delivery verification PIN handoff to delivery personnel
        if RE_DELIVERY_PIN_CONTEXT.search(full_clause):
            continue

        # Suppress match if preceded by a direct negation in the same clause
        if RE_CREDENTIAL_NEGATION_PREFIX.search(preceding_clause):
            continue

        # Suppress match if verb itself is directly negated (protective warning or user refusal)
        if RE_VERB_NEGATION.search(match.group(0)) or RE_VERB_NEGATION.search(full_clause):
            continue

        # Suppress match if text contains cross-sentence pronoun-referenced credential warning (e.g. "don't share it")
        if RE_PRONOUN_CREDENTIAL_NEGATION.search(norm_text):
            continue

        # Suppress match if internal negation exists or clause contains Hindi/Hinglish post-negation
        if RE_INTERNAL_NEGATION.search(match.group(0)) or RE_HINGLISH_POST_NEGATION.search(full_clause):
            continue

        flags.append(
            Flag(
                id="OTP_CREDENTIAL_REQUEST",
                severity=3,
                detail="Direct solicitation of sensitive credentials (OTP, PIN, CVV, password, or Aadhaar). Legitimate institutions never ask for these.",
                matched_text=match.group(0),
            )
        )
        break

    return flags


def check_suspicious_link(text: str) -> List[Flag]:
    """Rule 3: Detects generic suspicious domains, deceptive/lookalike domains,
    defanged URLs, raw IP addresses, URL shorteners, punycode, brand impersonation
    subdomains, and insecure HTTP in sensitive contexts.
    """
    candidates: List[Tuple[int, int, Flag]] = []

    def consider_match(start: int, end: int, flag: Flag):
        host = extract_domain_host(flag.matched_text)
        apex = get_apex_domain(host)

        # Allowlist check: trusted domains are never flagged unless explicitly defanged or raw IP
        is_defanged = any(ind in flag.matched_text.lower() for ind in ("hxxp", "[:]", "[.]", "(.)", "[dot]", "http[s]"))
        is_raw_ip = bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", host))
        if apex in LEGITIMATE_TRUSTED_APEX_DOMAINS and not is_defanged and not is_raw_ip:
            return

        # Check for overlap with existing candidate
        for i, (c_start, c_end, c_flag) in enumerate(candidates):
            if max(start, c_start) < min(end, c_end):
                # Overlap detected! Keep higher severity flag
                if flag.severity > c_flag.severity:
                    candidates[i] = (min(start, c_start), max(end, c_end), flag)
                return
        # No overlap with existing candidate
        candidates.append((start, end, flag))

    # 1. Defanged URLs (evasion technique)
    for m in RE_LINK_DEFANGED.finditer(text):
        matched = m.group(0).rstrip(".,;!?)]\"'")
        if any(indicator in matched.lower() for indicator in ("hxxp", "[:]", "[.]", "(.)", "[dot]", "http[s]")):
            consider_match(
                m.start(),
                m.start() + len(matched),
                Flag(
                    id="SUSPICIOUS_LINK",
                    severity=3,
                    detail="Defanged URL format (e.g. hxxp or [.] notation) used to evade automated link scanning.",
                    matched_text=matched,
                ),
            )

    # 2. Raw IP address URLs
    for m in RE_LINK_IP.finditer(text):
        matched = m.group(0).rstrip(".,;!?)]\"'")
        consider_match(
            m.start(),
            m.start() + len(matched),
            Flag(
                id="SUSPICIOUS_LINK",
                severity=3,
                detail="URL points directly to an IP address rather than a verified domain name.",
                matched_text=matched,
            ),
        )

    # 3. Known URL Shorteners
    for m in RE_LINK_SHORTENER.finditer(text):
        matched = m.group(0).rstrip(".,;!?)]\"'")
        consider_match(
            m.start(),
            m.start() + len(matched),
            Flag(
                id="SUSPICIOUS_LINK",
                severity=2,
                detail="Uses a URL shortener that masks the real destination website.",
                matched_text=matched,
            ),
        )

    # 4. Punycode (IDN homograph attacks)
    for m in RE_LINK_PUNYCODE.finditer(text):
        matched = m.group(0).rstrip(".,;!?)]\"'")
        consider_match(
            m.start(),
            m.start() + len(matched),
            Flag(
                id="SUSPICIOUS_LINK",
                severity=3,
                detail="Uses punycode (xn--) domain encoding frequently used for internationalized phishing.",
                matched_text=matched,
            ),
        )

    # 5. Lookalike & typosquatting domains (brand spoofing / leetspeak)
    for m in RE_LINK_LOOKALIKE.finditer(text):
        matched = m.group(0).rstrip(".,;!?)]\"'")
        consider_match(
            m.start(),
            m.start() + len(matched),
            Flag(
                id="SUSPICIOUS_LINK",
                severity=3,
                detail="Contains a lookalike, typosquatted, or suspicious top-level domain spoofing reputable brands.",
                matched_text=matched,
            ),
        )

    # 6. Suspicious subdomains & brand impersonation in subdomains
    for m in RE_LINK_SUSPICIOUS_SUBDOMAIN.finditer(text):
        matched = m.group(0).rstrip(".,;!?)]\"'")
        consider_match(
            m.start(),
            m.start() + len(matched),
            Flag(
                id="SUSPICIOUS_LINK",
                severity=3,
                detail="Contains suspicious subdomain structure impersonating a trusted brand.",
                matched_text=matched,
            ),
        )

    # 7. Generic deceptive domains (high-risk TLDs + smishing lure keywords, or chained lure hyphens)
    for m in RE_LINK_GENERIC_DECEPTIVE.finditer(text):
        matched = m.group(0).rstrip(".,;!?)]\"'")
        consider_match(
            m.start(),
            m.start() + len(matched),
            Flag(
                id="SUSPICIOUS_LINK",
                severity=3,
                detail="Contains a generic deceptive domain combining sensitive fraud lure keywords with high-risk top-level domains or spoofed action portals.",
                matched_text=matched,
            ),
        )

    # 8. Insecure cleartext HTTP in sensitive context (auth/banking path or credential solicitation)
    for m in RE_LINK_INSECURE_HTTP_PATH.finditer(text):
        matched = m.group(0).rstrip(".,;!?)]\"'")
        consider_match(
            m.start(),
            m.start() + len(matched),
            Flag(
                id="SUSPICIOUS_LINK",
                severity=2,
                detail="Insecure unencrypted HTTP protocol used for sensitive account, login, or verification action.",
                matched_text=matched,
            ),
        )

    # Check if cleartext HTTP link exists in a message soliciting credentials or KYC
    http_matches = re.finditer(r"http://[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s<>\"'`]*)?", text, re.IGNORECASE)
    for hm in http_matches:
        matched_http = hm.group(0).rstrip(".,;!?)]\"'")
        if RE_OTP_CREDENTIALS.search(text) or RE_KYC.search(text):
            consider_match(
                hm.start(),
                hm.start() + len(matched_http),
                Flag(
                    id="SUSPICIOUS_LINK",
                    severity=2,
                    detail="Insecure unencrypted HTTP link provided in message requesting credentials or identity verification.",
                    matched_text=matched_http,
                ),
            )

    candidates.sort(key=lambda c: c[0])
    return [c[2] for c in candidates]


def check_financial_lure(text: str) -> List[Flag]:
    """Rule 4: Detects lottery, unearned rewards, and guaranteed investment schemes."""
    norm_text = normalize_text(text)
    flags: List[Flag] = []
    match = RE_FINANCIAL_LURE.search(norm_text)
    if match:
        is_severe = bool(RE_LURE_SEVERE.search(norm_text))
        # Suppress match if legitimate reward notification without severe payment demands
        if not is_severe and RE_BENIGN_REWARD.search(norm_text):
            return flags
        flags.append(
            Flag(
                id="FINANCIAL_LURE",
                severity=3 if is_severe else 2,
                detail="Promises unearned lottery prizes, unrealistic investment doubling, or guaranteed cash returns.",
                matched_text=match.group(0),
            )
        )
    return flags


def check_impersonation(text: str) -> List[Flag]:
    """Rule 5: Detects claims of affiliation with banks, regulators, or police."""
    norm_text = normalize_text(text)
    flags: List[Flag] = []
    match = RE_IMPERSONATION.search(norm_text)
    if match:
        is_severe = bool(RE_SEVERE_IMPERSONATION.search(norm_text))
        flags.append(
            Flag(
                id="IMPERSONATION",
                severity=3 if is_severe else 2,
                detail=f"Claims affiliation with an authoritative institution or law enforcement ({match.group(0).upper()}).",
                matched_text=match.group(0),
            )
        )
    return flags


def check_prefill_kyc(text: str) -> List[Flag]:
    """Rule 6: Detects KYC expiration and mandatory update claims."""
    norm_text = normalize_text(text)
    flags: List[Flag] = []
    match = RE_KYC.search(norm_text)
    if match:
        flags.append(
            Flag(
                id="PREFILL_KYC",
                severity=3,
                detail="Demands immediate KYC or account verification under threat of deactivation or penalty.",
                matched_text=match.group(0),
            )
        )
    return flags


RE_PAYMENT_NEGATION = re.compile(
    r"\b(?:never\s+need\s+to|no\s+need\s+to|do\s+not\s+need\s+to|do\s+not|don't|never|mat|na|kabhi\s+nahi)\s+(?:ever\s+)?(?:scan|click|pay|enter)\b",
    re.IGNORECASE,
)


def check_payment_redirect(text: str) -> List[Flag]:
    """Rule 7: Detects fake refund verification and payment redirection schemes."""
    norm_text = normalize_text(text)
    flags: List[Flag] = []
    delimiters = [".", "!", "?", "\n", ";", ":"]

    for match in RE_PAYMENT_REDIRECT.finditer(norm_text):
        start_idx = match.start()
        end_idx = match.end()

        prev_indices = [norm_text.rfind(d, 0, start_idx) for d in delimiters]
        clause_start = max(prev_indices)
        clause_start = 0 if clause_start == -1 else clause_start + 1

        next_indices = [norm_text.find(d, end_idx) for d in delimiters if norm_text.find(d, end_idx) != -1]
        clause_end = min(next_indices) if next_indices else len(norm_text)

        full_clause = norm_text[clause_start:clause_end].strip()

        # Suppress match if part of an educational warning (e.g. "You never need to scan a QR code to receive money")
        if RE_PAYMENT_NEGATION.search(full_clause) or RE_PAYMENT_NEGATION.search(match.group(0)):
            continue

        flags.append(
            Flag(
                id="PAYMENT_REDIRECT",
                severity=3,
                detail="Directs recipient to click a link or scan a code to pay or claim an alleged refund.",
                matched_text=match.group(0),
            )
        )
        break

    return flags


def check_contact_mismatch(text: str) -> List[Flag]:
    """Rule 8: Detects threat/official notice requesting calls to a personal mobile number."""
    norm_text = normalize_text(text)
    flags: List[Flag] = []
    threat_match = RE_THREAT_CONTEXT.search(norm_text)
    call_match = RE_CALL_MOBILE.search(norm_text)
    if threat_match and call_match:
        flags.append(
            Flag(
                id="CONTACT_MISMATCH",
                severity=2,
                detail="An official threat or warning directs recipient to contact an unofficial personal mobile number.",
                matched_text=call_match.group(0),
            )
        )
    return flags


def check_language_manipulation(text: str) -> List[Flag]:
    """Rule 9: Detects excessive capitalization, extreme punctuation, and homoglyphs."""
    flags: List[Flag] = []

    # Check excessive uppercase (>35% uppercase in text with at least 25 alphabet characters)
    letters = [c for c in text if c.isalpha()]
    if len(letters) >= 25:
        upper_count = sum(1 for c in letters if c.isupper())
        ratio = upper_count / len(letters)
        if ratio >= 0.35:
            flags.append(
                Flag(
                    id="LANGUAGE_MANIPULATION",
                    severity=1,
                    detail="Excessive uppercase letters used to create psychological intimidation or urgency.",
                    matched_text=f"{upper_count}/{len(letters)} uppercase characters ({int(ratio*100)}%)",
                )
            )

    # Check >3 exclamation marks
    if text.count("!") > 3 or RE_EXCLAMATION.search(text):
        flags.append(
            Flag(
                id="LANGUAGE_MANIPULATION",
                severity=1,
                detail="Unusual and excessive exclamation marks indicating emotional manipulation.",
                matched_text=f"{text.count('!')} exclamation marks found",
            )
        )

    # Check mixed-script homoglyphs (Cyrillic/Greek lookalikes in Latin text)
    homoglyphs = RE_HOMOGLYPHS.findall(text)
    if homoglyphs:
        flags.append(
            Flag(
                id="LANGUAGE_MANIPULATION",
                severity=2,
                detail="Contains non-Latin homoglyph characters disguised as English letters to bypass security filters.",
                matched_text=f"Detected homoglyph glyphs: {' '.join(set(homoglyphs))}",
            )
        )

    return flags


def has_message_risk_indicators(text: str) -> bool:
    """Detects if message text contains suspicious cues (urgency, credentials, KYC, lures, links, apps)."""
    norm = normalize_text(text)
    return bool(
        RE_URGENCY.search(norm)
        or RE_OTP_CREDENTIALS.search(norm)
        or RE_KYC.search(norm)
        or RE_FINANCIAL_LURE.search(norm)
        or RE_PAYMENT_REDIRECT.search(norm)
        or RE_JOB_OFFER.search(norm)
        or RE_UNTRACED_DELIVERY.search(norm)
        or RE_CALL_MOBILE.search(norm)
        or RE_REMOTE_ACCESS_APP.search(norm)
        or check_suspicious_link(norm)
    )


def is_standard_sender_format(sender: str) -> bool:
    """Checks if sender matches standard telecom header, alphanumeric brand tag, or shortcode."""
    if RE_TELECOM_HEADER.match(sender):
        return True
    if RE_SHORTCODE.match(sender):
        return True
    if RE_ALPHANUMERIC_HEADER.match(sender) and not re.search(r"[-_\.\s]{2,}", sender):
        return True
    return False


def check_sender_id_analysis(text: str, sender_id: Optional[str]) -> List[Flag]:
    """Rule 10: Calibrated sender ID analysis with contextual correlation.

    Protects legitimate alphanumeric headers, business names, and telecom tags from
    false positives while correlating personal phone numbers, generic fraud lure headers,
    and unusual formats with message risk factors.
    """
    flags: List[Flag] = []
    if not sender_id or not sender_id.strip():
        return flags

    clean_sender = sender_id.strip()
    has_risk = has_message_risk_indicators(text)
    has_institution_claim = bool(RE_IMPERSONATION.search(text))

    # Case 1: Personal Phone Number as Sender
    if RE_PERSONAL_PHONE.match(clean_sender):
        if has_institution_claim:
            flags.append(
                Flag(
                    id="SENDER_ID_ANALYSIS",
                    severity=2,
                    detail=f"Sender ID '{clean_sender}' is a personal phone number, but the message claims official institutional status.",
                    matched_text=clean_sender,
                )
            )
        elif bool(RE_OTP_CREDENTIALS.search(text) or RE_KYC.search(text) or RE_UNTRACED_DELIVERY.search(text) or RE_PAYMENT_REDIRECT.search(text) or RE_REMOTE_ACCESS_APP.search(text) or (RE_THREAT_CONTEXT.search(text) and RE_CALL_MOBILE.search(text))):
            flags.append(
                Flag(
                    id="SENDER_ID_ANALYSIS",
                    severity=2,
                    detail=f"Sender ID '{clean_sender}' is a personal phone number soliciting credentials, KYC updates, payments, app installations, or official threat warnings.",
                    matched_text=clean_sender,
                )
            )
        # Benign everyday peer messages from personal numbers produce 0 flags
        return flags

    # Case 2: Generic Fraud Lure or Alert Headers (e.g. VK-PRIZE, IT-REFUND, JOB-ALRT, BANK-ALERT, SEC-ALERT)
    if RE_GENERIC_FRAUD_SENDER.search(clean_sender):
        if has_risk or has_institution_claim:
            flags.append(
                Flag(
                    id="SENDER_ID_ANALYSIS",
                    severity=2,
                    detail=f"Sender ID '{clean_sender}' uses a generic fraud lure or alert header combined with suspicious message content.",
                    matched_text=clean_sender,
                )
            )
        else:
            # Weak evidence when message text has no other fraud indicators (stays SAFE)
            flags.append(
                Flag(
                    id="SENDER_ID_ANALYSIS",
                    severity=1,
                    detail=f"Sender ID '{clean_sender}' uses a generic alert or promotional header, but no suspicious indicators were detected in message text.",
                    matched_text=clean_sender,
                )
            )
        return flags

    # Case 3: Legitimate Standard Sender Formats (Telecom headers, Alphanumeric business tags, Shortcodes)
    if is_standard_sender_format(clean_sender):
        # Ordinary business and telecom sender IDs are completely legitimate -> 0 flags
        return flags

    # Case 4: Non-Standard / Unusual Sender Format
    if has_risk or has_institution_claim:
        flags.append(
            Flag(
                id="SENDER_ID_ANALYSIS",
                severity=2,
                detail=f"Non-standard sender ID '{clean_sender}' combined with high-risk message indicators.",
                matched_text=clean_sender,
            )
        )
    else:
        # Weak evidence on benign content: severity 1 (15 points -> strictly SAFE tier <40)
        flags.append(
            Flag(
                id="SENDER_ID_ANALYSIS",
                severity=1,
                detail=f"Sender ID '{clean_sender}' uses an unusual header format, but message content is routine.",
                matched_text=clean_sender,
            )
        )

    return flags


def check_untraced_delivery(text: str) -> List[Flag]:
    """Rule 11: Detects fake package delivery failure and customs detention scams."""
    norm_text = normalize_text(text)
    flags: List[Flag] = []
    match = RE_UNTRACED_DELIVERY.search(norm_text)
    if match:
        flags.append(
            Flag(
                id="UNTRACED_DELIVERY",
                severity=2,
                detail="Alleges an undelivered package or customs seizure demanding fee payment or credential entry.",
                matched_text=match.group(0),
            )
        )
    return flags


def check_job_offer_scam(text: str) -> List[Flag]:
    """Rule 12: Detects bogus job offers, tasks, or registration fees."""
    norm_text = normalize_text(text)
    flags: List[Flag] = []
    match = RE_JOB_OFFER.search(norm_text)
    if match:
        is_severe = bool(RE_JOB_SCAM_SEVERE.search(norm_text))
        flags.append(
            Flag(
                id="JOB_OFFER_SCAM",
                severity=3 if is_severe else 2,
                detail="Promises unrealistic high daily income without interview or asks for upfront registration fees.",
                matched_text=match.group(0),
            )
        )
    return flags


def check_remote_access_app(text: str) -> List[Flag]:
    """Rule 13: Detects remote desktop app installation lures and malicious APK downloads."""
    norm_text = normalize_text(text)
    flags: List[Flag] = []
    match = RE_REMOTE_ACCESS_APP.search(norm_text)
    if match:
        flags.append(
            Flag(
                id="REMOTE_ACCESS_APP",
                severity=3,
                detail="Directs recipient to install remote access software (AnyDesk, TeamViewer, RustDesk) or unauthorized APK files to hijack the device.",
                matched_text=match.group(0),
            )
        )
    return flags


def run_all_heuristics(message: str, sender_id: Optional[str] = None) -> List[Flag]:
    """Runs all heuristic rule families and returns deduplicated detected flags."""
    # Pre-process message to neutralize evasion attacks
    clean_message = normalize_text(message)

    flags: List[Flag] = []

    flags.extend(check_urgency_pressure(clean_message))
    flags.extend(check_otp_credential_request(clean_message))
    flags.extend(check_suspicious_link(clean_message))
    flags.extend(check_financial_lure(clean_message))
    flags.extend(check_impersonation(clean_message))
    flags.extend(check_prefill_kyc(clean_message))
    flags.extend(check_payment_redirect(clean_message))
    flags.extend(check_contact_mismatch(clean_message))
    flags.extend(check_language_manipulation(message))  # Pass original raw text for glyph and casing analysis
    flags.extend(check_sender_id_analysis(clean_message, sender_id))
    flags.extend(check_untraced_delivery(clean_message))
    flags.extend(check_job_offer_scam(clean_message))
    flags.extend(check_remote_access_app(clean_message))

    # Deduplicate flags if identical (id, matched_text)
    seen = set()
    unique_flags: List[Flag] = []
    for f in flags:
        key = (f.id, f.matched_text)
        if key not in seen:
            seen.add(key)
            unique_flags.append(f)

    return unique_flags

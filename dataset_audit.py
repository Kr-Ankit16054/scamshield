"""ScamShield Dataset Audit & Similarity Analyzer.

Audits benchmark_dataset.json without external dependencies:
1. Exact and normalized duplicates.
2. Template and structural near-duplicates (Jaccard token similarity & template skeletons).
3. Sender ID distribution and potential label leakage.
4. Message length distributions (char/word length per tier).
5. Keyword and token overrepresentation analysis.
6. Structural cues and heuristic correlation (URLs, phone numbers, punctuation).
7. Evaluation of genuine ambiguity in the SUSPICIOUS class.
"""

import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple


def tokenize(text: str) -> List[str]:
    """Extracts lowercase alphanumeric tokens."""
    return re.findall(r"\b[a-zA-Z0-9]+\b", text.lower())


def get_template_skeleton(text: str) -> str:
    """Replaces numbers, URLs, phone numbers, and currency values with tokens to detect templated repetition."""
    s = re.sub(r"https?://\S+|hxxps?://\S+", "<URL>", text, flags=re.IGNORECASE)
    s = re.sub(r"\b(?:\+?91[\s-]?)?[6-9]\d{9}\b", "<PHONE>", s)
    s = re.sub(r"[₹$€£]\s*[\d,]+(?:\.\d+)?", "<MONEY>", s)
    s = re.sub(r"\b\d+\b", "<NUM>", s)
    s = re.sub(r"\s+", " ", s).strip().lower()
    return s


def jaccard_similarity(set_a: Set[str], set_b: Set[str]) -> float:
    if not set_a or not set_b:
        return 0.0
    return len(set_a & set_b) / len(set_a | set_b)


def audit_dataset(dataset_path: Path) -> Dict[str, Any]:
    with open(dataset_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    total_samples = len(data)

    # 1. Exact & Normalized duplicates
    exact_duplicates = []
    normalized_duplicates = []
    seen_exact = {}
    seen_norm = {}

    for idx, item in enumerate(data):
        raw = item["message"].strip()
        norm = re.sub(r"\s+", " ", raw.lower())

        if raw in seen_exact:
            exact_duplicates.append((seen_exact[raw], item["id"], raw))
        else:
            seen_exact[raw] = item["id"]

        if norm in seen_norm:
            normalized_duplicates.append((seen_norm[norm], item["id"], norm))
        else:
            seen_norm[norm] = item["id"]

    # 2. Template / Near-duplicate clustering
    template_map = defaultdict(list)
    for item in data:
        skel = get_template_skeleton(item["message"])
        template_map[skel].append(item["id"])

    repetitive_templates = {
        skel: ids for skel, ids in template_map.items() if len(ids) > 1
    }

    # Pairwise Jaccard near-duplicates (threshold >= 0.75)
    token_sets = {item["id"]: set(tokenize(item["message"])) for item in data}
    near_duplicate_pairs = []
    ids = [item["id"] for item in data]
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            sim = jaccard_similarity(token_sets[ids[i]], token_sets[ids[j]])
            if sim >= 0.75:
                near_duplicate_pairs.append((ids[i], ids[j], sim))

    # 3. Class and Category Distribution
    tier_counts = Counter(item["ground_truth"] for item in data)
    cat_counts = Counter(item["category"] for item in data)
    obf_counts = Counter(item["obfuscation_type"] for item in data)

    # 4. Length distributions
    lengths_by_tier = defaultdict(lambda: {"char": [], "word": []})
    for item in data:
        t = item["ground_truth"]
        msg = item["message"]
        lengths_by_tier[t]["char"].append(len(msg))
        lengths_by_tier[t]["word"].append(len(tokenize(msg)))

    length_stats = {}
    for t, metrics in lengths_by_tier.items():
        c_list = sorted(metrics["char"])
        w_list = sorted(metrics["word"])
        length_stats[t] = {
            "char_min": c_list[0],
            "char_mean": round(sum(c_list) / len(c_list), 1),
            "char_median": c_list[len(c_list) // 2],
            "char_max": c_list[-1],
            "word_min": w_list[0],
            "word_mean": round(sum(w_list) / len(w_list), 1),
            "word_median": w_list[len(w_list) // 2],
            "word_max": w_list[-1],
        }

    # 5. Sender ID Analysis & Leakage Check
    sender_by_tier = defaultdict(list)
    sender_counts = Counter(item.get("sender_id") or "NONE" for item in data)
    for item in data:
        s = item.get("sender_id") or "NONE"
        sender_by_tier[item["ground_truth"]].append(s)

    # Check sender formats
    phone_senders = [
        item for item in data if re.match(r"^(\+?91[\s-]?)?[6-9]\d{9}$", (item.get("sender_id") or ""))
    ]
    header_senders = [
        item for item in data if re.match(r"^[A-Za-z0-9]{2,3}-[A-Za-z0-9]{3,9}$", (item.get("sender_id") or ""))
    ]
    personal_phone_by_tier = Counter(item["ground_truth"] for item in phone_senders)
    header_by_tier = Counter(item["ground_truth"] for item in header_senders)

    # 6. Keyword & Feature Leakage
    url_pattern = re.compile(r"https?://|hxxps?://|\b[a-zA-Z0-9_\-\.]+\.(?:com|org|net|xyz|top|co|in|gov|io)\b", re.IGNORECASE)
    phone_pattern = re.compile(r"\b(?:\+?91[\s-]?)?[6-9]\d{9}\b")
    otp_words = re.compile(r"\b(?:otp|pin|cvv|password)\b", re.IGNORECASE)
    kyc_words = re.compile(r"\b(?:kyc|pan|aadhaar|freeze|blocked|suspended)\b", re.IGNORECASE)
    urgent_words = re.compile(r"\b(?:urgent|immediately|action\s+required|within\s+\d+|hurry|last\s+chance)\b", re.IGNORECASE)
    money_words = re.compile(r"\b(?:refund|cashback|prize|lottery|payout|earn|double)\b", re.IGNORECASE)

    feature_distribution = {
        "has_url": Counter(),
        "has_phone_number": Counter(),
        "has_otp_keywords": Counter(),
        "has_kyc_keywords": Counter(),
        "has_urgency_keywords": Counter(),
        "has_money_keywords": Counter(),
    }

    for item in data:
        t = item["ground_truth"]
        m = item["message"]
        if url_pattern.search(m):
            feature_distribution["has_url"][t] += 1
        if phone_pattern.search(m):
            feature_distribution["has_phone_number"][t] += 1
        if otp_words.search(m):
            feature_distribution["has_otp_keywords"][t] += 1
        if kyc_words.search(m):
            feature_distribution["has_kyc_keywords"][t] += 1
        if urgent_words.search(m):
            feature_distribution["has_urgency_keywords"][t] += 1
        if money_words.search(m):
            feature_distribution["has_money_keywords"][t] += 1

    # 7. Ambiguity Analysis of SUSPICIOUS Class
    suspicious_samples = [item for item in data if item["ground_truth"] == "SUSPICIOUS"]
    suspicious_features = []
    for item in suspicious_samples:
        m = item["message"]
        s = item.get("sender_id")
        has_url = bool(url_pattern.search(m))
        has_phone = bool(phone_pattern.search(m))
        has_urgency = bool(urgent_words.search(m))
        suspicious_features.append({
            "id": item["id"],
            "has_url": has_url,
            "has_phone": has_phone,
            "has_urgency": has_urgency,
            "sender_id": s,
            "message_snippet": m[:60] + "...",
        })

    return {
        "total_samples": total_samples,
        "exact_duplicates": exact_duplicates,
        "normalized_duplicates": normalized_duplicates,
        "repetitive_templates": repetitive_templates,
        "near_duplicate_pairs": near_duplicate_pairs,
        "tier_distribution": dict(tier_counts),
        "category_distribution": dict(cat_counts),
        "obfuscation_distribution": dict(obf_counts),
        "length_stats": length_stats,
        "sender_stats": {
            "unique_senders": len(sender_counts),
            "top_10_senders": sender_counts.most_common(10),
            "personal_phone_by_tier": dict(personal_phone_by_tier),
            "telecom_header_by_tier": dict(header_by_tier),
        },
        "feature_leakage": {k: dict(v) for k, v in feature_distribution.items()},
        "suspicious_ambiguity_summary": {
            "total_suspicious": len(suspicious_samples),
            "with_url": sum(1 for x in suspicious_features if x["has_url"]),
            "with_phone": sum(1 for x in suspicious_features if x["has_phone"]),
            "with_urgency": sum(1 for x in suspicious_features if x["has_urgency"]),
            "examples": suspicious_features[:5],
        },
    }


def main():
    dataset_path = Path(__file__).resolve().parent / "benchmark_dataset.json"
    audit = audit_dataset(dataset_path)

    print("=" * 70)
    print("SCAMSHIELD BENCHMARK DATASET INTEGRITY AUDIT")
    print("=" * 70)
    print(f"Total Samples Evaluated: {audit['total_samples']}")
    print(f"Exact Duplicates: {len(audit['exact_duplicates'])}")
    print(f"Normalized Duplicates: {len(audit['normalized_duplicates'])}")
    print(f"Repetitive Structural Templates: {len(audit['repetitive_templates'])}")
    print(f"Near-Duplicate Pairs (Jaccard >= 0.75): {len(audit['near_duplicate_pairs'])}")
    print("\n--- Tier Distribution ---")
    for tier, count in audit["tier_distribution"].items():
        print(f"  {tier:<12}: {count:>3} ({count/audit['total_samples']*100:.1f}%)")

    print("\n--- Length Statistics (Characters) ---")
    for tier, st in audit["length_stats"].items():
        print(f"  {tier:<12}: Min={st['char_min']}, Mean={st['char_mean']}, Median={st['char_median']}, Max={st['char_max']}")

    print("\n--- Sender ID Breakdown ---")
    print(f"  Unique Sender IDs: {audit['sender_stats']['unique_senders']}")
    print(f"  Personal 10-Digit Phones: {audit['sender_stats']['personal_phone_by_tier']}")
    print(f"  Telecom Alphanumeric Headers: {audit['sender_stats']['telecom_header_by_tier']}")

    print("\n--- Feature Presence Across Tiers ---")
    for feat, counts in audit["feature_leakage"].items():
        print(f"  {feat:<22}: SAFE={counts.get('SAFE', 0):>2}, SUSPICIOUS={counts.get('SUSPICIOUS', 0):>2}, SCAM={counts.get('SCAM', 0):>2}")

    print("\n--- SUSPICIOUS Class Ambiguity ---")
    susp_info = audit["suspicious_ambiguity_summary"]
    print(f"  Total: {susp_info['total_suspicious']}")
    print(f"  With Shortener/URL: {susp_info['with_url']}")
    print(f"  With Urgent wording: {susp_info['with_urgency']}")


if __name__ == "__main__":
    main()


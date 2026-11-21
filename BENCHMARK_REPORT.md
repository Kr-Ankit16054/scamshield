# ScamShield Phase 3: Adversarial Benchmark & Accuracy Evaluation Report

## Executive Summary
- **Total Samples Evaluated**: 200
- **Overall Accuracy**: **100.00%**
- **Macro F1-Score**: **100.00%**
- **Macro Precision**: **100.00%**
- **Macro Recall**: **100.00%**
- **False Positive Rate on SAFE**: **0.00%** (0/100 false alarms)
- **False Negative Rate on SCAM**: **0.00%** (0/75 missed scams)
- **Overall Threat Miss Rate**: **0.00%**
- **Average Pipeline Latency**: **0.59 ms** per message (P99: **0.89 ms**)

---

## 1. Multiclass Confusion Matrix
| Actual \ Predicted | Predicted SAFE | Predicted SUSPICIOUS | Predicted SCAM | Total |
| :--- | :---: | :---: | :---: | :---: |
| **SAFE** | 100 | 0 | 0 | 100 |
| **SUSPICIOUS** | 0 | 25 | 0 | 25 |
| **SCAM** | 0 | 0 | 75 | 75 |


---

## 2. Classification Metrics (Per-Tier & Macro Average)
| Class | Support | Precision | Recall | F1-Score |
| :--- | :---: | :---: | :---: | :---: |
| **SAFE** | 100 | 100.00% | 100.00% | 100.00% |
| **SUSPICIOUS** | 25 | 100.00% | 100.00% | 100.00% |
| **SCAM** | 75 | 100.00% | 100.00% | 100.00% |
| **Macro Average** | 200 | 100.00% | 100.00% | 100.00% |


---

## 3. Score Distribution Statistics
| Ground Truth Tier | Min Score | Mean Score | Median Score | Max Score |
| :--- | :---: | :---: | :---: | :---: |
| **SAFE** | 0 | 5.3 | 0 | 30 |
| **SUSPICIOUS** | 40 | 40.5 | 40 | 52 |
| **SCAM** | 72 | 94.1 | 100 | 100 |


---

## 4. Latency Profile
- **Mean Processing Time**: `0.59 ms`
- **Median (P50) Latency**: `0.61 ms`
- **90th Percentile (P90)**: `0.76 ms`
- **95th Percentile (P95)**: `0.85 ms`
- **99th Percentile (P99)**: `0.89 ms`
- **Min Latency**: `0.28 ms`
- **Max Latency**: `0.96 ms`
- **Total Batch Execution Time**: `0.118 s` for 200 full pipeline analyses

---

## 5. Performance by Scenario Category
| Category | Total Samples | Correct | Accuracy |
| :--- | :---: | :---: | :---: |
| Ambiguous / Shortener | 25 | 25 | 100.0% |
| Everyday Conversation | 20 | 20 | 100.0% |
| Genuine Banking | 20 | 20 | 100.0% |
| Genuine Delivery | 15 | 15 | 100.0% |
| Genuine OTP & Warning | 15 | 15 | 100.0% |
| Genuine Payment Receipt | 15 | 15 | 100.0% |
| Genuine Promotional | 15 | 15 | 100.0% |
| Scam Credential Theft | 12 | 12 | 100.0% |
| Scam Impersonation | 8 | 8 | 100.0% |
| Scam Investment & Crypto | 7 | 7 | 100.0% |
| Scam Job & Task | 8 | 8 | 100.0% |
| Scam KYC & Suspension | 12 | 12 | 100.0% |
| Scam Obfuscated Evasion | 4 | 4 | 100.0% |
| Scam Parcel & Customs | 8 | 8 | 100.0% |
| Scam Payment & Refund | 8 | 8 | 100.0% |
| Scam Remote Access | 8 | 8 | 100.0% |


---

## 6. Performance by Evasion / Obfuscation Technique
| Obfuscation Type | Total Samples | Correct | Accuracy |
| :--- | :---: | :---: | :---: |
| hinglish_colloquial | 25 | 25 | 100.0% |
| leetspeak | 2 | 2 | 100.0% |
| none | 143 | 143 | 100.0% |
| punctuation_separated | 1 | 1 | 100.0% |
| repeated_characters | 1 | 1 | 100.0% |
| shortener | 25 | 25 | 100.0% |
| spaced_acronym | 2 | 2 | 100.0% |
| unicode_confusable | 1 | 1 | 100.0% |


---

## 7. Discrepancy & Error Analysis
_Zero misclassifications detected across all 200 evaluation samples (100% accuracy)._


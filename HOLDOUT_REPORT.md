# ScamShield: Post-Fix Holdout Evaluation Report

## Executive Summary
- **Total Post-Fix Holdout Samples**: 100
- **Overall Multiclass Accuracy**: **100.00%** (100/100)
- **Macro F1-Score**: **100.00%**
- **Macro Precision**: **100.00%**
- **Macro Recall**: **100.00%**
- **SAFE False Positive Rate (FPR)**: **0.00%** (0/50 false alarms)
- **Multiclass SCAM FNR**: **0.00%** (0/30 non-SCAM predictions)
- **Critical Threat Escape Rate (SCAM -> SAFE)**: **0.00%** (0/30 completely missed)
- **Binary Threat FNR (Threat -> SAFE)**: **0.00%** (0/50 threats missed as safe)
- **Binary Threat Accuracy (Safe vs Threat)**: **100.00%** (Threat F1: **100.00%**)
- **Average Processing Latency**: **0.84 ms** (P99: **1.36 ms**)

---

## 1. Multiclass Confusion Matrix
| Actual \ Predicted | Predicted SAFE | Predicted SUSPICIOUS | Predicted SCAM | Total |
| :--- | :---: | :---: | :---: | :---: |
| **SAFE** | 50 | 0 | 0 | 50 |
| **SUSPICIOUS** | 0 | 20 | 0 | 20 |
| **SCAM** | 0 | 0 | 30 | 30 |

---

## 2. Classification Metrics (Per-Tier & Macro Average)
| Class Tier | Support | Precision | Recall | F1-Score | FP | FN |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **SAFE** | 50 | 100.00% | 100.00% | 100.00% | 0 | 0 |
| **SUSPICIOUS** | 20 | 100.00% | 100.00% | 100.00% | 0 | 0 |
| **SCAM** | 30 | 100.00% | 100.00% | 100.00% | 0 | 0 |
| **Macro Average** | 100 | 100.00% | 100.00% | 100.00% | 0 | 0 |

---

## 3. Binary Threat Detection Performance (Safe vs Threat)
| Metric | Value | Interpretation |
| :--- | :---: | :--- |
| **Binary Accuracy** | **100.00%** | Overall ability to separate benign from any risk |
| **Threat Precision** | **100.00%** | When flagged as threat, percentage truly threatening |
| **Threat Recall** | **100.00%** | Percentage of all real threats intercepted |
| **Threat F1-Score** | **100.00%** | Harmonic balance between threat detection and false alarm avoidance |
| **True Positives (Threats)** | 50 | Suspicious and Scam correctly isolated from Safe |
| **False Positives (Benign Alarmed)** | 0 | Legitimate messages incorrectly flagged as threat |
| **False Negatives (Threats Missed)** | 0 | Threats misclassified as clean SAFE messages |

---

## 4. Score Distribution Statistics
| Ground Truth Tier | Min Score | Mean Score | Median Score | Max Score |
| :--- | :---: | :---: | :---: | :---: |
| **SAFE** | 0 | 4.4 | 0 | 30 |
| **SUSPICIOUS** | 40 | 41.5 | 40 | 58 |
| **SCAM** | 75 | 92.5 | 95 | 100 |

---

## 5. Latency Profile
- **Mean Latency**: `0.84 ms`
- **Median (P50)**: `0.84 ms`
- **90th Percentile (P90)**: `1.06 ms`
- **95th Percentile (P95)**: `1.13 ms`
- **99th Percentile (P99)**: `1.36 ms`
- **Min / Max Latency**: `0.54 ms` / `1.36 ms`
- **Total Batch Time**: `0.084 s` for 100 samples

---

## 6. Performance by Scenario Category
| Category | Total | Correct | Accuracy |
| :--- | :---: | :---: | :---: |
| Ambiguous / Shortener | 20 | 20 | 100.0% |
| Benign Security Context | 12 | 12 | 100.0% |
| Everyday Conversation | 12 | 12 | 100.0% |
| Genuine Promotional | 8 | 8 | 100.0% |
| Genuine Transactional | 10 | 10 | 100.0% |
| Genuine Urgency | 8 | 8 | 100.0% |
| Scam Disconnection | 4 | 4 | 100.0% |
| Scam Extortion | 2 | 2 | 100.0% |
| Scam Financial Lure | 4 | 4 | 100.0% |
| Scam Job & Task | 4 | 4 | 100.0% |
| Scam KYC & Banking | 6 | 6 | 100.0% |
| Scam Parcel & Delivery | 5 | 5 | 100.0% |
| Scam Payment & Refund | 2 | 2 | 100.0% |
| Scam Remote Access | 3 | 3 | 100.0% |

---

## 7. Discrepancy & Error Analysis
_Zero misclassifications detected across all 100 blind holdout samples._

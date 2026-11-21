/**
 * ScamShield v1.0 — Frontend Application Controller
 * Single-Page Utilitarian Security Intelligence Tool
 * Fully compliant with UI_SPEC.md (Dark Theme, WCAG AA, No External JS Libraries)
 */

// 1. Configurable & Adaptive API Endpoint (Render & Multi-Port Compatible)
const API_BASE_URL = window.SCAMSHIELD_API_BASE || (
  window.location.protocol.startsWith("http")
    ? ""
    : "http://localhost:8000"
);

// 2. 6 Required Example Messages Archetypes
const SAMPLES = {
  bank_safe: {
    title: "Benign banking notification",
    sender_id: "HDFCBK",
    message: "Your HDFC Bank account XX4102 has been credited with Rs 5,000.00 on 21-Nov-2026. Available balance: Rs 42,500.00. - HDFC Bank"
  },
  delivery_safe: {
    title: "Genuine delivery notification",
    sender_id: "AMAZON",
    message: "Your Amazon package with tracking ID 402-9182391 is out for delivery. Give delivery verification code 8391 to delivery executive."
  },
  otp_warning: {
    title: "OTP security warning",
    sender_id: "NETFLIX",
    message: "Your Netflix login code is 492018. Do not share this OTP with anyone, including customer support."
  },
  shortlink_suspicious: {
    title: "Suspicious shortened link",
    sender_id: "+919876543210",
    message: "Your package delivery could not be completed. Please confirm your delivery address immediately at https://bit.ly/pkg-update-in to avoid return."
  },
  kyc_phishing: {
    title: "KYC phishing",
    sender_id: "VK-SBIBNK",
    message: "URGENT: Your SBI netbanking will be blocked today due to pending KYC. Click http://sbi-kyc-verify.top/update to submit OTP immediately."
  },
  qr_refund_scam: {
    title: "QR refund scam",
    sender_id: "+919811223344",
    message: "Scan this QR code in PhonePe to receive refund of Rs 1,450 directly into your bank account."
  }
};

// 3. Human-readable Rule Titles and Explanations Dictionary for 12 Heuristic Families
const RULE_METADATA = {
  URGENCY_PRESSURE: {
    name: "Urgency Pressure",
    desc: "Creates artificial time urgency to force hasty action and bypass rational verification."
  },
  OTP_CREDENTIAL_REQUEST: {
    name: "Credential / OTP Harvesting",
    desc: "Solicits sensitive one-time passwords, netbanking PINs, or confidential credentials."
  },
  SUSPICIOUS_LINK: {
    name: "Suspicious / Lookalike Domain",
    desc: "Contains an unverified domain, high-risk TLD, raw IP host, or deceptive brand lookalike."
  },
  FINANCIAL_LURE: {
    name: "Financial Lure / Lottery",
    desc: "Lures recipients with unrealistic monetary prizes, lottery draws, or investment doubling schemes."
  },
  IMPERSONATION: {
    name: "Authority Impersonation",
    desc: "Claims false affiliation with a bank, utility board, telecom regulator, or law enforcement agency."
  },
  PREFILL_KYC: {
    name: "KYC Deactivation Threat",
    desc: "Demands immediate PAN/Aadhaar/KYC update under threat of immediate account or SIM suspension."
  },
  PAYMENT_REDIRECT: {
    name: "Payment Redirection / Reverse QR",
    desc: "Directs recipient to click a payment link or scan a QR code under the guise of receiving a refund."
  },
  CONTACT_MISMATCH: {
    name: "Contact Channel Mismatch",
    desc: "An official threat or notice instructs the recipient to contact an unofficial personal mobile number."
  },
  LANGUAGE_MANIPULATION: {
    name: "Language Manipulation",
    desc: "Employs excessive uppercase letters, punctuation abuse, or homoglyphs to bypass spam filters."
  },
  SENDER_ID_ANALYSIS: {
    name: "Sender ID Analysis",
    desc: "Official institutional claims delivered from an ordinary personal mobile number or non-standard header."
  },
  UNTRACED_DELIVERY: {
    name: "Fake Delivery / Customs Hold",
    desc: "Claims a package or parcel is held at customs pending immediate fee payment or address update."
  },
  JOB_OFFER_SCAM: {
    name: "Part-Time Task / Job Scam",
    desc: "Promises lucrative daily wages for effortless tasks while soliciting upfront registration fees."
  },
  REMOTE_ACCESS_APP: {
    name: "Remote Access App Coercion",
    desc: "Pressures recipient to install screen-sharing or remote-control apps (AnyDesk, TeamViewer, QuickSupport)."
  }
};

// SVG Progress Ring Circumference: 2 * PI * 78 = 490.088
const GAUGE_CIRCUMFERENCE = 490.09;

// State Management
let currentAnalysisData = null;
let currentRawMessage = "";
let currentActiveFlagId = null;
let currentPreviewFilter = "all"; // "all" | "flagged"

// DOM Elements
const analyzeForm = document.getElementById("analyze-form");
const messageInput = document.getElementById("message-input");
const senderInput = document.getElementById("sender-input");
const charCounter = document.getElementById("char-counter");
const validationError = document.getElementById("message-validation-error");
const analyzeBtn = document.getElementById("analyze-btn");
const btnSpinner = document.getElementById("btn-spinner");
const btnLabel = document.getElementById("btn-label");
const btnPaste = document.getElementById("btn-paste");
const btnClear = document.getElementById("btn-clear");

const toastContainer = document.getElementById("toast-container");
const emptyState = document.getElementById("empty-state");
const loadingSkeleton = document.getElementById("loading-skeleton");
const activeResults = document.getElementById("active-results");
const resultsHeading = document.getElementById("results-heading");

// Gauge Elements
const gaugeWrapper = document.getElementById("gauge-wrapper");
const gaugeProgress = document.getElementById("gauge-progress");
const gaugeScoreNum = document.getElementById("gauge-score-num");
const gaugeRiskLabel = document.getElementById("gauge-risk-label");
const riskCategoryBadge = document.getElementById("risk-category-badge");
const riskHeadlineText = document.getElementById("risk-headline-text");
const riskAdvisoryStatement = document.getElementById("risk-advisory-statement");
const latencyMs = document.getElementById("latency-ms");

// Flags Elements
const flagsCounterBadge = document.getElementById("flags-counter-badge");
const flagsChipsWrap = document.getElementById("flags-chips-wrap");
const flagAccordionCard = document.getElementById("flag-accordion-card");
const accordionRuleName = document.getElementById("accordion-rule-name");
const accordionSeverityBadge = document.getElementById("accordion-severity-badge");
const accordionMatchedText = document.getElementById("accordion-matched-text");
const accordionRuleExplanation = document.getElementById("accordion-rule-explanation");
const accordionCloseBtn = document.getElementById("accordion-close-btn");

// Explanation & Action Elements
const analysisExplanationText = document.getElementById("analysis-explanation-text");
const recommendedActionContent = document.getElementById("recommended-action-content");

// Preview Elements
const toggleShowAll = document.getElementById("toggle-show-all");
const toggleShowFlagged = document.getElementById("toggle-show-flagged");
const messagePreviewContainer = document.getElementById("message-preview-container");

// ==============================================================================
// INITIALIZATION
// ==============================================================================
document.addEventListener("DOMContentLoaded", () => {
  initCharacterCounter();
  initActionToolbar();
  initSampleButtons();
  initFormSubmission();
  initAccordionControls();
  initPreviewToggles();
  checkBackendHealth();

  // Periodic health check every 15s to update connectivity indicator
  setInterval(checkBackendHealth, 15000);
});

// Character Counter & Validation
function initCharacterCounter() {
  messageInput.addEventListener("input", () => {
    updateCharCounter();
  });

  // Keyboard shortcut: Ctrl+Enter or Cmd+Enter submits the analysis
  messageInput.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      analyzeForm.dispatchEvent(new Event("submit"));
    }
  });
}

function updateCharCounter() {
  const len = messageInput.value.length;
  charCounter.textContent = `${len}/2000`;
  if (len > 2000) {
    charCounter.classList.add("limit-exceeded");
    messageInput.classList.add("input-error");
    validationError.textContent = "Message exceeds the 2,000 character maximum limit.";
  } else {
    charCounter.classList.remove("limit-exceeded");
    messageInput.classList.remove("input-error");
    validationError.textContent = "";
  }
}

// Action Toolbar: Paste & Clear Buttons
function initActionToolbar() {
  if (btnPaste) {
    btnPaste.addEventListener("click", async () => {
      try {
        if (!navigator.clipboard || !navigator.clipboard.readText) {
          throw new Error("Clipboard API not supported in this browser");
        }
        const text = await navigator.clipboard.readText();
        if (!text || !text.trim()) {
          showToast("Clipboard is empty or does not contain text.", 3000);
          return;
        }
        messageInput.value = text;
        updateCharCounter();
        messageInput.focus();
        showToast("Pasted from clipboard", 2000, "info");
      } catch (err) {
        showToast("Unable to paste from clipboard. Please paste manually.", 4000);
        messageInput.focus();
      }
    });
  }

  if (btnClear) {
    btnClear.addEventListener("click", () => {
      resetAnalyzer();
      showToast("Input cleared", 2000, "info");
    });
  }
}

function resetAnalyzer() {
  messageInput.value = "";
  senderInput.value = "";
  updateCharCounter();
  messageInput.classList.remove("input-error");
  validationError.textContent = "";

  currentAnalysisData = null;
  currentRawMessage = "";
  collapseAccordion();

  emptyState.classList.remove("hidden");
  activeResults.classList.add("hidden");
  loadingSkeleton.classList.add("hidden");
  messageInput.focus();
}

// Sample Click -> Load & Auto-Analyze
function initSampleButtons() {
  const sampleCards = document.querySelectorAll(".sample-card");
  sampleCards.forEach((btn) => {
    btn.addEventListener("click", () => {
      const sampleId = btn.getAttribute("data-sample-id");
      const sample = SAMPLES[sampleId];
      if (!sample) return;

      messageInput.value = sample.message;
      senderInput.value = sample.sender_id || "";

      // Trigger character counter update
      updateCharCounter();

      // Trigger analysis immediately via live API
      triggerAnalysis();
    });
  });
}

// Form Submission & Reset
function initFormSubmission() {
  analyzeForm.addEventListener("submit", (e) => {
    e.preventDefault();
    triggerAnalysis();
  });

  analyzeForm.addEventListener("reset", () => {
    resetAnalyzer();
  });
}

// Accordion & Global Escape Listener
function initAccordionControls() {
  if (accordionCloseBtn) {
    accordionCloseBtn.addEventListener("click", () => {
      collapseAccordion();
    });
  }

  // Escape collapses active flag accordion
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && currentActiveFlagId) {
      collapseAccordion();
    }
  });
}

// Preview Toggles (Show Original vs Show Flagged Only)
function initPreviewToggles() {
  toggleShowAll.addEventListener("click", () => {
    if (currentPreviewFilter === "all") return;
    currentPreviewFilter = "all";
    toggleShowAll.classList.add("active");
    toggleShowAll.setAttribute("aria-checked", "true");
    toggleShowFlagged.classList.remove("active");
    toggleShowFlagged.setAttribute("aria-checked", "false");
    renderMessagePreview();
  });

  toggleShowFlagged.addEventListener("click", () => {
    if (currentPreviewFilter === "flagged") return;
    currentPreviewFilter = "flagged";
    toggleShowFlagged.classList.add("active");
    toggleShowFlagged.setAttribute("aria-checked", "true");
    toggleShowAll.classList.remove("active");
    toggleShowAll.setAttribute("aria-checked", "false");
    renderMessagePreview();
  });
}

// ==============================================================================
// ANALYSIS TRIGGER & API CALL
// ==============================================================================
async function triggerAnalysis() {
  const rawMessage = messageInput.value.trim();
  const senderId = senderInput.value.trim();

  // Validate Input
  if (!rawMessage) {
    messageInput.classList.add("input-error");
    validationError.textContent = "Please enter or paste a message to analyze.";
    messageInput.focus();
    return;
  }

  if (rawMessage.length > 2000) {
    messageInput.classList.add("input-error");
    validationError.textContent = "Message exceeds the 2,000 character maximum limit.";
    messageInput.focus();
    return;
  }

  validationError.textContent = "";
  messageInput.classList.remove("input-error");
  currentRawMessage = rawMessage;

  // 1. Trigger Scanline Button Effect (800ms)
  analyzeBtn.classList.add("animate-scan");
  setTimeout(() => {
    analyzeBtn.classList.remove("animate-scan");
  }, 800);

  // 2. Set UI Loading State (prevents duplicate submissions)
  setLoadingState(true);
  const startTime = performance.now();

  try {
    const payload = {
      message: rawMessage,
      ...(senderId ? { sender_id: senderId } : {})
    };

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10s timeout

    const response = await fetch(`${API_BASE_URL}/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload),
      signal: controller.signal
    });

    clearTimeout(timeoutId);
    const elapsedMs = Math.max(1, Math.round(performance.now() - startTime));

    if (!response.ok) {
      let errMsg = `Server returned HTTP status ${response.status}`;
      try {
        const errJson = await response.json();
        if (errJson.detail) {
          errMsg = typeof errJson.detail === "string" ? errJson.detail : JSON.stringify(errJson.detail);
        }
      } catch (_) {}
      throw new Error(errMsg);
    }

    const data = await response.json();
    currentAnalysisData = data;
    renderResults(data, elapsedMs);

  } catch (err) {
    let friendlyMessage = err.message;
    if (err.name === "AbortError") {
      friendlyMessage = "Request timed out after 10 seconds. Please try again.";
    } else if (err instanceof TypeError && err.message.includes("fetch")) {
      friendlyMessage = "Cannot connect to ScamShield backend. Please check that the server is running on localhost:8000.";
      updateBackendStatus(false);
    }

    showToast(`Analysis error: ${friendlyMessage}`, 6000);
    messageInput.classList.add("input-error");
    setLoadingState(false);
    emptyState.classList.remove("hidden");
  }
}

// UI State Switcher: Loading vs Idle
function setLoadingState(isLoading) {
  analyzeBtn.disabled = isLoading;
  messageInput.disabled = isLoading;
  senderInput.disabled = isLoading;
  if (btnPaste) btnPaste.disabled = isLoading;
  if (btnClear) btnClear.disabled = isLoading;

  if (isLoading) {
    btnSpinner.classList.remove("hidden");
    btnLabel.textContent = "Analyzing...";
    emptyState.classList.add("hidden");
    activeResults.classList.add("hidden");
    loadingSkeleton.classList.remove("hidden");
  } else {
    btnSpinner.classList.add("hidden");
    btnLabel.textContent = "Analyze Message";
    loadingSkeleton.classList.add("hidden");
  }
}

// ==============================================================================
// RESULTS RENDERING
// ==============================================================================
function renderResults(data, latencyDurationMs) {
  setLoadingState(false);
  emptyState.classList.add("hidden");
  activeResults.classList.remove("hidden");

  const score = Math.min(100, Math.max(0, Number(data.risk_score) || 0));
  const label = (data.label || "SAFE").toUpperCase();
  const flags = Array.isArray(data.flags) ? data.flags : [];
  const groupedFlags = groupFlagsByRule(flags);

  // Update Latency Indicator
  latencyMs.textContent = `${latencyDurationMs}ms`;

  // 1. Animate Hero Risk Gauge with Strict Advisory Copy (Section 3.4)
  updateHeroGauge(score, label);

  // 2. Announce via ARIA Live Region (Section 4.1)
  announceScreenReader(`Analysis complete. Risk score ${score} out of 100. ${label} risk detected. ${groupedFlags.length} flags found.`);

  // 3. Render Flags Detected (Section 3.5)
  renderFlagsChips(flags);

  // 4. Render Explanation & Recommended Action (Section 3.6)
  renderExplanation(data.explanation, data.recommended_action);

  // 5. Render Monospace Message Preview with Highlighting (Section 3.7)
  renderMessagePreview();

  // 6. Focus Management (Section 4.2)
  if (resultsHeading) {
    resultsHeading.focus();
  }
  if (gaugeWrapper) {
    gaugeWrapper.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
}

// Hero SVG Circular Progress Ring Animation & Strict Advisory Wording
function updateHeroGauge(score, label) {
  gaugeWrapper.classList.remove("glow-scam");

  let strokeColor = "var(--risk-safe)";
  let badgeClass = "badge-safe";
  let headline = "Low Detected Risk";
  let advisoryCopy = "No common smishing or credential harvesting indicators detected in this message. Note: This advisory score does not guarantee complete authenticity—always verify unexpected transactions through official channels.";

  if (label === "SCAM" || score >= 70) {
    strokeColor = "var(--risk-scam)";
    badgeClass = "badge-scam";
    headline = "Critical Threat Warning — High Scam Probability";
    advisoryCopy = "High-confidence fraud indicators detected. Immediate protective steps: Do NOT share OTPs or PINs, do NOT click links, do NOT transfer money, and do NOT install remote-access apps.";
    gaugeWrapper.classList.add("glow-scam");
  } else if (label === "SUSPICIOUS" || score >= 40) {
    strokeColor = "var(--risk-suspicious)";
    badgeClass = "badge-suspicious";
    headline = "Caution Advised — Suspicious Signals Detected";
    advisoryCopy = "Suspicious patterns detected (such as shortened links, urgent deadlines, or sender anomalies). Exercise caution and independently verify sender authenticity before responding.";
  }

  // Update Badges & Advisory Copy
  gaugeRiskLabel.textContent = label;
  gaugeRiskLabel.style.color = strokeColor;

  riskCategoryBadge.textContent = label;
  riskCategoryBadge.className = `risk-category-badge font-mono ${badgeClass}`;
  riskHeadlineText.textContent = headline;
  riskAdvisoryStatement.textContent = advisoryCopy;

  // ARIA descriptive label
  gaugeWrapper.setAttribute("aria-label", `Risk score: ${score} out of 100. ${label} risk level.`);

  // Check Reduced Motion Preference
  const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Gauge Ring Calculation
  const targetOffset = GAUGE_CIRCUMFERENCE * (1 - score / 100);
  gaugeProgress.style.stroke = strokeColor;

  if (prefersReducedMotion) {
    gaugeProgress.style.strokeDashoffset = targetOffset;
    gaugeScoreNum.textContent = score;
    return;
  }

  // Animate Gauge Ring and Score Count-up over 800ms
  gaugeProgress.style.strokeDashoffset = GAUGE_CIRCUMFERENCE;
  const animationDuration = 800;
  const startTime = performance.now();

  function animateFrame(now) {
    const elapsed = now - startTime;
    const progress = Math.min(1, elapsed / animationDuration);
    // Ease-out cubic
    const easeProgress = 1 - Math.pow(1 - progress, 3);

    const currentScore = Math.round(score * easeProgress);
    const currentOffset = GAUGE_CIRCUMFERENCE - (GAUGE_CIRCUMFERENCE - targetOffset) * easeProgress;

    gaugeScoreNum.textContent = currentScore;
    gaugeProgress.style.strokeDashoffset = currentOffset;

    if (progress < 1) {
      requestAnimationFrame(animateFrame);
    } else {
      gaugeScoreNum.textContent = score;
      gaugeProgress.style.strokeDashoffset = targetOffset;
    }
  }

  requestAnimationFrame(animateFrame);
}

// Group flags by rule_id for clean presentation
function groupFlagsByRule(flags) {
  if (!Array.isArray(flags)) return [];
  const groups = new Map();

  flags.forEach((flag, index) => {
    const ruleId = flag.rule_id || flag.id || `FLAG_${index + 1}`;
    if (!groups.has(ruleId)) {
      groups.set(ruleId, {
        rule_id: ruleId,
        id: ruleId,
        severity: flag.severity,
        detail: flag.detail,
        matched_phrases: []
      });
    }
    const group = groups.get(ruleId);
    if (flag.matched_text && typeof flag.matched_text === "string" && flag.matched_text.trim()) {
      const phrase = flag.matched_text.trim();
      if (!group.matched_phrases.includes(phrase)) {
        group.matched_phrases.push(phrase);
      }
    }
    const currentSev = Number(group.severity) || 0;
    const flagSev = Number(flag.severity) || 0;
    if (flagSev > currentSev) {
      group.severity = flag.severity;
      group.detail = flag.detail;
    }
  });

  return Array.from(groups.values());
}

// Expandable Accordion Flags List (Section 3.5)
function renderFlagsChips(flags) {
  collapseAccordion();
  flagsChipsWrap.replaceChildren();

  const groupedFlags = groupFlagsByRule(flags);
  flagsCounterBadge.textContent = `${groupedFlags.length} Detected`;

  if (groupedFlags.length === 0) {
    const cleanChip = document.createElement("div");
    cleanChip.className = "flag-chip";

    const iconSpan = document.createElement("span");
    iconSpan.className = "chip-icon";
    iconSpan.setAttribute("aria-hidden", "true");
    iconSpan.textContent = "🛡️";

    const idSpan = document.createElement("span");
    idSpan.className = "chip-rule-id font-mono";
    idSpan.textContent = "NO_RISK_FLAGS";

    const dotSpan = document.createElement("span");
    dotSpan.className = "chip-severity-dot dot-low";
    dotSpan.setAttribute("aria-hidden", "true");

    cleanChip.append(iconSpan, idSpan, dotSpan);
    flagsChipsWrap.appendChild(cleanChip);
    return;
  }

  groupedFlags.forEach((group) => {
    const ruleId = group.rule_id;
    const severityRaw = String(group.severity || "Medium").toLowerCase();

    let dotClass = "dot-medium";
    let icon = "⚠";
    if (severityRaw.includes("high") || severityRaw === "2" || severityRaw === "3") {
      dotClass = "dot-high";
    } else if (severityRaw.includes("low") || severityRaw === "0") {
      dotClass = "dot-low";
      icon = "ℹ";
    }

    const chipBtn = document.createElement("button");
    chipBtn.type = "button";
    chipBtn.className = "flag-chip font-mono";
    chipBtn.setAttribute("role", "button");
    chipBtn.setAttribute("aria-expanded", "false");
    chipBtn.setAttribute("aria-controls", "flag-accordion-card");
    chipBtn.setAttribute("data-rule-id", ruleId);

    const iconSpan = document.createElement("span");
    iconSpan.className = "chip-icon";
    iconSpan.setAttribute("aria-hidden", "true");
    iconSpan.textContent = icon;

    const idSpan = document.createElement("span");
    idSpan.className = "chip-rule-id font-mono";
    idSpan.textContent = ruleId;

    const dotSpan = document.createElement("span");
    dotSpan.className = `chip-severity-dot ${dotClass}`;
    dotSpan.setAttribute("aria-hidden", "true");

    const chevronSpan = document.createElement("span");
    chevronSpan.className = "chip-chevron";
    chevronSpan.setAttribute("aria-hidden", "true");
    chevronSpan.textContent = "▶";

    chipBtn.append(iconSpan, idSpan, dotSpan, chevronSpan);

    chipBtn.addEventListener("click", () => {
      toggleFlagAccordion(ruleId, group, chipBtn);
    });

    flagsChipsWrap.appendChild(chipBtn);
  });
}

// Accordion Toggle Behavior (Only 1 open at a time)
function toggleFlagAccordion(ruleId, group, chipElement) {
  if (currentActiveFlagId === ruleId) {
    collapseAccordion();
    return;
  }

  // Deactivate existing
  document.querySelectorAll(".flag-chip").forEach((c) => {
    c.classList.remove("chip-active");
    c.setAttribute("aria-expanded", "false");
  });

  currentActiveFlagId = ruleId;
  chipElement.classList.add("chip-active");
  chipElement.setAttribute("aria-expanded", "true");

  const meta = RULE_METADATA[ruleId] || {
    name: ruleId.replace(/_/g, " "),
    desc: group.detail || "Deterministic heuristic rule triggered on suspicious phrasing."
  };

  const severityText = getSeverityLabel(group.severity);
  let severityBadgeClass = "badge-suspicious";
  if (severityText === "High" || severityText === "Critical") severityBadgeClass = "badge-scam";
  if (severityText === "Low") severityBadgeClass = "badge-safe";

  accordionRuleName.textContent = meta.name;
  accordionSeverityBadge.textContent = severityText;
  accordionSeverityBadge.className = `severity-badge font-mono ${severityBadgeClass}`;

  const matchedDisplay = group.matched_phrases && group.matched_phrases.length > 0
    ? group.matched_phrases.map((p) => `"${p}"`).join(", ")
    : group.matched_text
    ? `"${group.matched_text}"`
    : "(Pattern match detected in message context)";
  accordionMatchedText.textContent = matchedDisplay;
  accordionRuleExplanation.textContent = group.detail || meta.desc;

  flagAccordionCard.classList.remove("hidden");
}

function collapseAccordion() {
  currentActiveFlagId = null;
  if (flagAccordionCard) flagAccordionCard.classList.add("hidden");
  document.querySelectorAll(".flag-chip").forEach((c) => {
    c.classList.remove("chip-active");
    c.setAttribute("aria-expanded", "false");
  });
}

function getSeverityLabel(severity) {
  if (severity === undefined || severity === null) return "Medium";
  const str = String(severity).toLowerCase();
  if (str === "3" || str.includes("crit")) return "Critical";
  if (str === "2" || str.includes("high")) return "High";
  if (str === "1" || str.includes("med")) return "Medium";
  if (str === "0" || str.includes("low")) return "Low";
  return String(severity);
}

// Explanation & Recommended Action Panel (Section 3.6)
function renderExplanation(explanation, recommendedAction) {
  analysisExplanationText.textContent = explanation || "Heuristic pattern analysis completed.";
  recommendedActionContent.textContent = recommendedAction || "Never share one-time passwords, passwords, or personal banking information via SMS.";
}

// Message Preview with Highlighting & Toggle (Section 3.7)
function renderMessagePreview() {
  if (!currentRawMessage) {
    renderMessagePreviewToDOM(messagePreviewContainer, "", []);
    return;
  }

  // Collect all matched phrases from flags
  const matchedPhrases = [];
  if (currentAnalysisData && Array.isArray(currentAnalysisData.flags)) {
    currentAnalysisData.flags.forEach((f) => {
      if (f.matched_text && typeof f.matched_text === "string" && f.matched_text.trim()) {
        matchedPhrases.push(f.matched_text.trim());
      }
    });
  }

  if (currentPreviewFilter === "flagged" && matchedPhrases.length > 0) {
    // Split message into sentence blocks
    const sentences = currentRawMessage.split(/(?<=[.!?\n])\s+/);
    const flaggedSentences = sentences.filter((sentence) => {
      return matchedPhrases.some((phrase) => sentence.toLowerCase().includes(phrase.toLowerCase()));
    });

    if (flaggedSentences.length > 0) {
      const filteredText = flaggedSentences.join(" ");
      renderMessagePreviewToDOM(messagePreviewContainer, filteredText, matchedPhrases);
      return;
    }
  }

  // Default: Show full original message with DOM-based highlights
  renderMessagePreviewToDOM(messagePreviewContainer, currentRawMessage, matchedPhrases);
}

// Finds and merges overlapping or adjacent match ranges for given phrases in text (Word Boundaries Aware)
function findMergedMatchRanges(text, phrases) {
  if (!text || !phrases || phrases.length === 0) return [];

  const rawRanges = [];
  const lowerText = text.toLowerCase();

  for (const phrase of phrases) {
    if (!phrase || typeof phrase !== "string") continue;
    const trimmed = phrase.trim();
    if (!trimmed) continue;
    const lowerPhrase = trimmed.toLowerCase();

    // Word boundary checks: if boundary char is a word character [A-Za-z0-9_]
    const checkStartBoundary = /^\w/.test(trimmed);
    const checkEndBoundary = /\w$/.test(trimmed);

    let startPos = 0;
    while ((startPos = lowerText.indexOf(lowerPhrase, startPos)) !== -1) {
      const endPos = startPos + lowerPhrase.length;

      // Word-boundary safety: prevent matching inside larger words (e.g. "ED" in "CREDITED", "SBI" in "USBIP")
      let valid = true;
      if (checkStartBoundary && startPos > 0 && /\w/.test(text[startPos - 1])) {
        valid = false;
      }
      if (checkEndBoundary && endPos < text.length && /\w/.test(text[endPos])) {
        valid = false;
      }

      if (valid) {
        rawRanges.push({
          start: startPos,
          end: endPos
        });
      }

      startPos += 1;
    }
  }

  if (rawRanges.length === 0) return [];

  // Sort by start index ascending, then end index descending
  rawRanges.sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    return b.end - a.end;
  });

  // Merge overlapping or adjacent ranges
  const merged = [{ start: rawRanges[0].start, end: rawRanges[0].end }];
  for (let i = 1; i < rawRanges.length; i++) {
    const prev = merged[merged.length - 1];
    const curr = rawRanges[i];
    if (curr.start <= prev.end) {
      prev.end = Math.max(prev.end, curr.end);
    } else {
      merged.push({ start: curr.start, end: curr.end });
    }
  }

  return merged;
}

// Safe DOM-based phrase highlighting (Zero innerHTML, XSS-immune, handles overlapping phrases)
function renderMessagePreviewToDOM(container, text, phrases) {
  container.replaceChildren();

  if (!text) {
    const emptySpan = document.createElement("span");
    emptySpan.className = "text-secondary font-mono";
    emptySpan.textContent = "No content to preview.";
    container.appendChild(emptySpan);
    return;
  }

  const mergedRanges = findMergedMatchRanges(text, phrases);

  if (mergedRanges.length === 0) {
    container.appendChild(document.createTextNode(text));
    return;
  }

  let lastIndex = 0;
  for (const range of mergedRanges) {
    // Append plain text before match
    if (range.start > lastIndex) {
      container.appendChild(document.createTextNode(text.substring(lastIndex, range.start)));
    }
    // Append merged highlighted match element
    const mark = document.createElement("mark");
    mark.className = "matched-phrase-highlight font-mono";
    mark.textContent = text.substring(range.start, range.end);
    container.appendChild(mark);
    lastIndex = range.end;
  }

  // Append remaining plain text
  if (lastIndex < text.length) {
    container.appendChild(document.createTextNode(text.substring(lastIndex)));
  }
}

// ARIA Live Announcer Helper
function announceScreenReader(message) {
  const existing = document.getElementById("sr-announcer");
  if (existing) existing.remove();

  const announcer = document.createElement("div");
  announcer.id = "sr-announcer";
  announcer.className = "sr-only";
  announcer.setAttribute("aria-live", "polite");
  announcer.setAttribute("aria-atomic", "true");
  announcer.textContent = message;
  document.body.appendChild(announcer);

  setTimeout(() => announcer.remove(), 1000);
}

// Floating Toast Notification (Auto-dismisses in 5s, DOM-based textContent)
function showToast(message, durationMs = 5000, type = "error") {
  const toast = document.createElement("div");
  toast.className = `toast font-mono ${type === "info" ? "toast-info" : ""}`;
  toast.setAttribute("role", "alert");

  const iconSpan = document.createElement("span");
  iconSpan.className = "toast-icon";
  iconSpan.setAttribute("aria-hidden", "true");
  iconSpan.textContent = type === "info" ? "ℹ" : "⚠";

  const msgSpan = document.createElement("span");
  msgSpan.textContent = String(message);

  toast.append(iconSpan, msgSpan);
  toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transition = "opacity 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  }, durationMs);
}

// Backend Health Check
async function checkBackendHealth() {
  try {
    const res = await fetch(`${API_BASE_URL}/health`);
    if (res.ok) {
      updateBackendStatus(true);
    } else {
      updateBackendStatus(false);
    }
  } catch (_) {
    updateBackendStatus(false);
  }
}

function updateBackendStatus(isOnline) {
  const apiStatusText = document.getElementById("api-status-text");
  const apiStatusDot = document.getElementById("api-status-dot");
  if (!apiStatusText || !apiStatusDot) return;

  if (isOnline) {
    apiStatusText.textContent = "API: Online";
    apiStatusDot.className = "status-dot-pulse";
  } else {
    apiStatusText.textContent = "API: Offline";
    apiStatusDot.className = "status-dot dot-red";
  }
}

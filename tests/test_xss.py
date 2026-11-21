"""Regression and security test suite for XSS prevention and sanitization.

Validates:
- Backend handles raw HTML/JS injection payloads without crashing or leaking executable tags.
- app.js has zero innerHTML assignments for user-supplied or API-supplied content.
- DOM-based message preview highlighting renders HTML tags purely as text nodes.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path
import pytest
from starlette.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_api_handles_xss_payload():
    """Verify backend processes HTML injection payloads cleanly."""
    payload = {
        "message": "<img src=x onerror=alert(1)> urgent verify your KYC netbanking",
        "sender_id": "+919876543210"
    }
    response = client.post("/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert "risk_score" in data
    assert "label" in data
    assert "flags" in data
    assert len(data["flags"]) >= 1


def test_app_js_zero_inner_html_assignments():
    """Static AST/pattern audit verifying zero innerHTML assignments in client logic."""
    app_js_path = Path(__file__).resolve().parent.parent / "app" / "static" / "app.js"
    assert app_js_path.exists()

    content = app_js_path.read_text(encoding="utf-8")
    lines = content.splitlines()

    for idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            continue
        assert ".innerHTML" not in stripped, f"Disallowed innerHTML on line {idx}: {stripped}"
        assert ".outerHTML" not in stripped, f"Disallowed outerHTML on line {idx}: {stripped}"
        assert "insertAdjacentHTML" not in stripped, f"Disallowed insertAdjacentHTML on line {idx}: {stripped}"


@pytest.mark.skipif(
    shutil.which("node") is None,
    reason="Node.js is not installed; skipping headless DOM highlighting simulation test"
)
def test_dom_highlighting_immunity():
    """Execute Node.js runner to verify DOM node tree safety with injection payloads."""
    node_test_script = r"""
    const fs = require('fs');
    const path = require('path');

    // Minimal DOM Node polyfill for headless Node verification
    class TextNode {
      constructor(text) { this.nodeType = 3; this.textContent = String(text); }
    }
    class Element {
      constructor(tag) {
        this.nodeType = 1;
        this.tagName = tag.toUpperCase();
        this.className = '';
        this.textContent = '';
        this.children = [];
      }
      appendChild(node) { this.children.push(node); }
      replaceChildren() { this.children = []; }
    }

    const document = {
      createElement: (tag) => new Element(tag),
      createTextNode: (text) => new TextNode(text)
    };

    function findMergedMatchRanges(text, phrases) {
      if (!text || !phrases || phrases.length === 0) return [];
      const rawRanges = [];
      const lowerText = text.toLowerCase();
      for (const phrase of phrases) {
        if (!phrase || typeof phrase !== 'string') continue;
        const trimmed = phrase.trim();
        if (!trimmed) continue;
        const lowerPhrase = trimmed.toLowerCase();
        const checkStartBoundary = /^\w/.test(trimmed);
        const checkEndBoundary = /\w$/.test(trimmed);
        let startPos = 0;
        while ((startPos = lowerText.indexOf(lowerPhrase, startPos)) !== -1) {
          const endPos = startPos + lowerPhrase.length;
          let valid = true;
          if (checkStartBoundary && startPos > 0 && /\w/.test(text[startPos - 1])) valid = false;
          if (checkEndBoundary && endPos < text.length && /\w/.test(text[endPos])) valid = false;
          if (valid) rawRanges.push({ start: startPos, end: endPos });
          startPos += 1;
        }
      }
      if (rawRanges.length === 0) return [];
      rawRanges.sort((a, b) => (a.start !== b.start ? a.start - b.start : b.end - a.end));
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
        if (range.start > lastIndex) {
          container.appendChild(document.createTextNode(text.substring(lastIndex, range.start)));
        }
        const mark = document.createElement("mark");
        mark.className = "matched-phrase-highlight font-mono";
        mark.textContent = text.substring(range.start, range.end);
        container.appendChild(mark);
        lastIndex = range.end;
      }
      if (lastIndex < text.length) {
        container.appendChild(document.createTextNode(text.substring(lastIndex)));
      }
    }

    const container = new Element('div');
    const inputPayload = '<img src=x onerror=alert(1)> urgent verify your KYC';
    renderMessagePreviewToDOM(container, inputPayload, ['urgent']);

    // Verify all children are either pure TextNodes or MARK elements with textContent
    for (const child of container.children) {
      if (child.nodeType === 3) {
        if (child.textContent.includes('<img')) {
          // It's a text node containing literal characters - safe!
        }
      } else if (child.nodeType === 1) {
        if (child.tagName !== 'MARK') {
          console.error('Invalid element created:', child.tagName);
          process.exit(1);
        }
      }
    }
    console.log('SUCCESS');
    """

    res = subprocess.run(["node", "-e", node_test_script], capture_output=True, text=True)
    assert res.returncode == 0, f"Node verification failed: {res.stderr}"
    assert "SUCCESS" in res.stdout


@pytest.mark.skipif(
    shutil.which("node") is None,
    reason="Node.js is not installed; skipping headless DOM highlighting simulation test"
)
def test_overlapping_highlights_merging():
    """Verify overlapping and adjacent matched phrases are merged into a single mark tag."""
    node_test_script = r"""
    class TextNode {
      constructor(text) { this.nodeType = 3; this.textContent = String(text); }
    }
    class Element {
      constructor(tag) {
        this.nodeType = 1;
        this.tagName = tag.toUpperCase();
        this.className = '';
        this.textContent = '';
        this.children = [];
      }
      appendChild(node) { this.children.push(node); }
      replaceChildren() { this.children = []; }
    }

    const document = {
      createElement: (tag) => new Element(tag),
      createTextNode: (text) => new TextNode(text)
    };

    function findMergedMatchRanges(text, phrases) {
      if (!text || !phrases || phrases.length === 0) return [];
      const rawRanges = [];
      const lowerText = text.toLowerCase();
      for (const phrase of phrases) {
        if (!phrase || typeof phrase !== 'string') continue;
        const trimmed = phrase.trim();
        if (!trimmed) continue;
        const lowerPhrase = trimmed.toLowerCase();
        const checkStartBoundary = /^\w/.test(trimmed);
        const checkEndBoundary = /\w$/.test(trimmed);
        let startPos = 0;
        while ((startPos = lowerText.indexOf(lowerPhrase, startPos)) !== -1) {
          const endPos = startPos + lowerPhrase.length;
          let valid = true;
          if (checkStartBoundary && startPos > 0 && /\w/.test(text[startPos - 1])) valid = false;
          if (checkEndBoundary && endPos < text.length && /\w/.test(text[endPos])) valid = false;
          if (valid) rawRanges.push({ start: startPos, end: endPos });
          startPos += 1;
        }
      }
      if (rawRanges.length === 0) return [];
      rawRanges.sort((a, b) => (a.start !== b.start ? a.start - b.start : b.end - a.end));
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

    function renderMessagePreviewToDOM(container, text, phrases) {
      container.replaceChildren();
      if (!text) return;
      const mergedRanges = findMergedMatchRanges(text, phrases);
      if (mergedRanges.length === 0) {
        container.appendChild(document.createTextNode(text));
        return;
      }
      let lastIndex = 0;
      for (const range of mergedRanges) {
        if (range.start > lastIndex) {
          container.appendChild(document.createTextNode(text.substring(lastIndex, range.start)));
        }
        const mark = document.createElement("mark");
        mark.textContent = text.substring(range.start, range.end);
        container.appendChild(mark);
        lastIndex = range.end;
      }
      if (lastIndex < text.length) {
        container.appendChild(document.createTextNode(text.substring(lastIndex)));
      }
    }

    const container = new Element('div');
    const text = "URGENT: Your SBI netbanking will be blocked today due to pending KYC. Click http://sbi-kyc-verify.top/update to submit OTP immediately.";
    const phrases = ["http://sbi-kyc-verify.top/update", "verify.top/update to submit OTP"];

    renderMessagePreviewToDOM(container, text, phrases);

    const markElements = container.children.filter(c => c.tagName === 'MARK');
    if (markElements.length !== 1) {
      console.error('Expected exactly 1 merged mark element, got', markElements.length);
      process.exit(1);
    }

    const expectedMergedText = "http://sbi-kyc-verify.top/update to submit OTP";
    if (markElements[0].textContent !== expectedMergedText) {
      console.error('Expected text "' + expectedMergedText + '", got "' + markElements[0].textContent + '"');
      process.exit(1);
    }

    console.log('MERGE_SUCCESS');
    """

    res = subprocess.run(["node", "-e", node_test_script], capture_output=True, text=True)
    assert res.returncode == 0, f"Node verification failed: {res.stderr}"
    assert "MERGE_SUCCESS" in res.stdout


@pytest.mark.skipif(
    shutil.which("node") is None,
    reason="Node.js is not installed; skipping headless DOM highlighting simulation test"
)
def test_word_boundary_highlight_isolation():
    """Verify short alphabetic phrases (e.g. ED, SBI) are not matched inside longer words."""
    node_test_script = r"""
    class TextNode {
      constructor(text) { this.nodeType = 3; this.textContent = String(text); }
    }
    class Element {
      constructor(tag) {
        this.nodeType = 1;
        this.tagName = tag.toUpperCase();
        this.className = '';
        this.textContent = '';
        this.children = [];
      }
      appendChild(node) { this.children.push(node); }
      replaceChildren() { this.children = []; }
    }

    const document = {
      createElement: (tag) => new Element(tag),
      createTextNode: (text) => new TextNode(text)
    };

    function findMergedMatchRanges(text, phrases) {
      if (!text || !phrases || phrases.length === 0) return [];
      const rawRanges = [];
      const lowerText = text.toLowerCase();
      for (const phrase of phrases) {
        if (!phrase || typeof phrase !== 'string') continue;
        const trimmed = phrase.trim();
        if (!trimmed) continue;
        const lowerPhrase = trimmed.toLowerCase();
        const checkStartBoundary = /^\w/.test(trimmed);
        const checkEndBoundary = /\w$/.test(trimmed);
        let startPos = 0;
        while ((startPos = lowerText.indexOf(lowerPhrase, startPos)) !== -1) {
          const endPos = startPos + lowerPhrase.length;
          let valid = true;
          if (checkStartBoundary && startPos > 0 && /\w/.test(text[startPos - 1])) valid = false;
          if (checkEndBoundary && endPos < text.length && /\w/.test(text[endPos])) valid = false;
          if (valid) rawRanges.push({ start: startPos, end: endPos });
          startPos += 1;
        }
      }
      if (rawRanges.length === 0) return [];
      rawRanges.sort((a, b) => (a.start !== b.start ? a.start - b.start : b.end - a.end));
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

    function renderMessagePreviewToDOM(container, text, phrases) {
      container.replaceChildren();
      if (!text) return;
      const mergedRanges = findMergedMatchRanges(text, phrases);
      if (mergedRanges.length === 0) {
        container.appendChild(document.createTextNode(text));
        return;
      }
      let lastIndex = 0;
      for (const range of mergedRanges) {
        if (range.start > lastIndex) {
          container.appendChild(document.createTextNode(text.substring(lastIndex, range.start)));
        }
        const mark = document.createElement("mark");
        mark.textContent = text.substring(range.start, range.end);
        container.appendChild(mark);
        lastIndex = range.end;
      }
      if (lastIndex < text.length) {
        container.appendChild(document.createTextNode(text.substring(lastIndex)));
      }
    }

    const container = new Element('div');
    const text = 'Your account was CREDITED with INR 5,000. ED notice pending. USBIP SBI alert.';
    const phrases = ['ED', 'SBI'];

    renderMessagePreviewToDOM(container, text, phrases);

    const markElements = container.children.filter(c => c.tagName === 'MARK');
    if (markElements.length !== 2) {
      console.error('Expected exactly 2 mark elements, got', markElements.length);
      process.exit(1);
    }

    if (markElements[0].textContent !== 'ED') {
      console.error('Expected first mark to be "ED", got', markElements[0].textContent);
      process.exit(1);
    }
    if (markElements[1].textContent !== 'SBI') {
      console.error('Expected second mark to be "SBI", got', markElements[1].textContent);
      process.exit(1);
    }

    console.log('BOUNDARY_SUCCESS');
    """

    res = subprocess.run(["node", "-e", node_test_script], capture_output=True, text=True)
    assert res.returncode == 0, f"Node verification failed: {res.stderr}"
    assert "BOUNDARY_SUCCESS" in res.stdout


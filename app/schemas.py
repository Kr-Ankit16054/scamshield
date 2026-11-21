"""Pydantic schemas for ScamShield API request and response validation.

Security & Validation:
- Message length strictly capped at 2000 characters.
- Sender ID validated against safe alphanumeric/phone-like identifier patterns.
- Pydantic v2 validation guarantees type safety and rejects malformed inputs.
"""

from typing import List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


class Flag(BaseModel):
    """Represents a suspicious pattern flagged by the heuristic engine."""
    model_config = ConfigDict(frozen=True)

    id: str = Field(..., description="Unique identifier for the heuristic rule family.")
    rule_id: Optional[str] = Field(default=None, description="Heuristic rule identifier alias matching UI specification.")
    severity: int = Field(..., ge=1, le=3, description="Severity rating from 1 (low) to 3 (critical).")
    detail: str = Field(..., description="Explanation of why this pattern is suspicious.")
    matched_text: str = Field(..., description="Specific text snippet that triggered this flag.")

    def __init__(self, **data):
        if "id" in data and "rule_id" not in data:
            data["rule_id"] = data["id"]
        elif "rule_id" in data and "id" not in data:
            data["id"] = data["rule_id"]
        super().__init__(**data)


class AnalyzeRequest(BaseModel):
    """Request payload for message analysis."""
    model_config = ConfigDict(str_strip_whitespace=True)

    message: str = Field(
        ...,
        min_length=1,
        max_length=2000,
        description="The raw message text to analyze (max 2000 characters)."
    )
    sender_id: Optional[str] = Field(
        default=None,
        max_length=15,
        description="Optional sender ID, shortcode, or phone number."
    )

    @field_validator("message")
    @classmethod
    def validate_message_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Message cannot be empty or only whitespace.")
        import re
        # Reject null bytes and ASCII control characters (excluding standard whitespace \t, \n, \r)
        # Note: Bidi control characters (\u200e, \u200f, \u202a-\u202e, \u2066-\u2069) are preserved.
        if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", v):
            raise ValueError("Message contains forbidden control characters or null bytes.")
        return v

    @field_validator("sender_id")
    @classmethod
    def validate_sender_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        import re
        if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", v):
            raise ValueError("Sender ID contains forbidden control characters or null bytes.")
        # Sender ID should be an alphanumeric shortcode, phone number, or header (e.g. AX-HDFCBK, +919876543210)
        # Length 2-15 characters, allowing alphanumeric, +, -, _
        if not re.fullmatch(r"^[A-Za-z0-9+\-_]{2,15}$", v):
            raise ValueError("Invalid sender_id format. Must be 2-15 characters of letters, digits, '+', '-', or '_'.")
        return v


class AnalyzeResponse(BaseModel):
    """Analysis result returned to client."""
    risk_score: int = Field(..., ge=0, le=100, description="Computed risk score between 0 and 100.")
    label: Literal["SAFE", "SUSPICIOUS", "SCAM"] = Field(..., description="Risk tier label.")
    flags: List[Flag] = Field(default_factory=list, description="List of detected heuristic flags.")
    explanation: str = Field(..., description="Plain-English explanation of risk factors.")
    recommended_action: str = Field(..., description="Actionable safety guidance for the recipient.")


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field("ok", description="Service health status.")

"""DATA 790 - Security gateway for a retrieval-augmented generation pipeline.

Educational demonstration; NOT a production security certification.

Threat boundaries:
- User input and retrieved content are untrusted.
- Caller roles and authorized document IDs MUST come from a trusted application
  authentication layer; do not derive them from a prompt or model output.
- Source text and model output are screened separately. No regex list detects all
  prompt injections or all forms of personally identifiable information (PII).
- Logs contain no raw prompts, source documents, answers, or identifiers.
"""
from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

MAX_QUESTION_CHARS = 2000
MAX_SOURCE_CHARS = 8000
MAX_CONTEXT_CHUNKS = 8

# Match malicious instruction *phrases*, not isolated terms such as "system".
# This is an illustrative detector, not a complete prompt-injection firewall.
_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (label, re.compile(pattern, re.IGNORECASE | re.DOTALL))
    for label, pattern in [
        ("instruction_override", r"\bignore\s+(?:all\s+)?(?:previous|prior|above|system|developer)\s+(?:\w+\s+){0,2}instructions?\b"),
        ("instruction_override", r"\bdisregard\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:\w+\s+){0,2}instructions?\b"),
        ("instruction_override", r"\boverride\s+(?:the\s+)?(?:system|developer)\s+(?:prompt|instructions?)\b"),
        ("prompt_extraction", r"\b(?:reveal|print|show|dump|repeat|expose|leak)\s+(?:me\s+)?(?:your\s+|the\s+)?(?:hidden|secret|system|developer)\s+(?:prompt|message|instructions?)\b"),
        ("prompt_extraction", r"\b(?:what\s+are\s+your\s+exact\s+instructions|output\s+the\s+above\s+text)\b"),
        ("role_spoof", r"\byou\s+are\s+now\s+(?:in\s+)?(?:developer|admin|system|dan|unrestricted)\b"),
        ("role_spoof", r"\b(?:act\s+as|pretend\s+to\s+be|roleplay\s+as)\s+(?:the\s+|an?\s+)?(?:system|developer|administrator|root)\b"),
        ("role_spoof", r"\[\s*(?:im_start|start_header_id)\s*\]|<\|(?:im_start|start_header_id)\|>"),
        ("role_spoof", r"\b(?:system|developer)\s*:\s*(?:ignore|override|reveal|you\s+must|new\s+rule)\b"),
        ("jailbreak", r"\b(?:jailbreak|bypass\s+(?:all\s+)?(?:safety|security|guardrails?|rules))\b"),
        ("exfiltration", r"\b(?:send|upload|post|forward)\s+(?:all\s+)?(?:secrets?|api\s*keys?|credentials?|private\s+data|system\s+prompt)\s+to\b"),
        ("retrieval_control", r"\b(?:ignore|skip|discard)\s+(?:the\s+)?(?:retrieved\s+)?(?:context|sources?|documents?)\s+and\b"),
        ("retrieval_control", r"\b(?:the\s+)?(?:retrieved\s+)?document\s+(?:now\s+)?(?:instructs|orders|commands)\s+you\s+to\b"),
    ]
)

# Suspicious markup is not normal sports-statistics prose. Check before sending
# text to the LLM, rather than stripping tags that may hide a directive.
_HTML_TAG = re.compile(r"<\s*/?\s*[a-z][\w:-]*(?:\s|/?>)", re.IGNORECASE)
_BASE64_RUN = re.compile(r"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{28,}={0,2})(?![A-Za-z0-9+/])")
_HEX_RUN = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){24,}(?![0-9A-Fa-f])")

# Synthetic examples exercise recognition; not a complete PII taxonomy.
_SSN = re.compile(r"(?<!\d)(?:\d{3}[- ]\d{2}[- ]\d{4})(?!\d)")
_EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])")
_PHONE = re.compile(r"(?<!\w)(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}(?!\d)")
_DOB = re.compile(r"\b(?:DOB|date\s+of\s+birth)\s*[:=]\s*(?:\d{4}[-/]\d{2}[-/]\d{2}|\d{1,2}[-/]\d{1,2}[-/]\d{4})\b", re.I)
_STUDENT_ID = re.compile(r"\b(?:student\s*id|athlete\s*id)\s*[:=#]\s*[A-Za-z0-9-]{6,18}\b", re.I)
# Context-labelled personal data only; do NOT indiscriminately redact public
# player names, since names can be necessary for legitimate sports retrieval.
_LABELED_NAME = re.compile(r"\b(?:student|athlete|patient)\s+name\s*[:=]\s*[A-Z][a-z]+(?:[- ][A-Z][a-z]+){1,3}\b")
_HOME_ADDRESS = re.compile(r"\b(?:home\s+address|residential\s+address)\s*[:=]\s*\d{1,5}\s+[A-Za-z0-9 .-]{3,65}?(?:\b(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Boulevard|Dr|Drive|Ln|Lane)\b\.?)", re.I)
_API_SECRET = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|github_pat_[A-Za-z0-9_]{12,}|ghp_[A-Za-z0-9]{16,})\b")
_CARD_CANDIDATE = re.compile(r"(?<!\w)(?:\d[ -]?){13,19}(?!\w)")


def _luhn_valid(value: str) -> bool:
    digits = [int(x) for x in re.sub(r"\D", "", value)]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _pii_spans(text: str) -> list[tuple[int, int, str]]:
    """Collect spans and avoid overlapping replacements (e.g., phone inside card)."""
    spans: list[tuple[int, int, str]] = []
    detectors = [("API_SECRET", _API_SECRET), ("SSN", _SSN),
                 ("EMAIL", _EMAIL), ("PHONE", _PHONE),
                 ("DOB", _DOB), ("STUDENT_ID", _STUDENT_ID),
                 ("LABELED_NAME", _LABELED_NAME), ("HOME_ADDRESS", _HOME_ADDRESS)]
    for label, regex in detectors:
        spans.extend((m.start(), m.end(), label) for m in regex.finditer(text))
    spans.extend((m.start(), m.end(), "PAYMENT_CARD") for m in _CARD_CANDIDATE.finditer(text)
                 if _luhn_valid(m.group()))
    # Prefer the longest match at a given position; skip all overlaps.
    spans.sort(key=lambda span: (span[0], -(span[1] - span[0])))
    result: list[tuple[int, int, str]] = []
    for span in spans:
        if not result or span[0] >= result[-1][1]:
            result.append(span)
    return result


def detect_pii_types(text: str) -> tuple[str, ...]:
    """Return detected categories, never actual sensitive values."""
    if not isinstance(text, str):
        return ()
    return tuple(sorted({label for _, _, label in _pii_spans(text)}))


def redact_pii(text: str) -> tuple[str, tuple[str, ...]]:
    """Replace recognizable PII with category tokens before external processing."""
    if not isinstance(text, str):
        raise TypeError("PII redaction requires text")
    spans = _pii_spans(text)
    for start, end, label in reversed(spans):
        text = text[:start] + f"[REDACTED:{label}]" + text[end:]
    return text, tuple(sorted({label for _, _, label in spans}))


def _encoded_injection(text: str) -> bool:
    """Inspect bounded Base64/hex candidates; never execute decoded content."""
    for match in list(_BASE64_RUN.finditer(text))[:8]:
        raw = match.group(0)
        if len(raw) > 2048:
            continue
        try:
            decoded = base64.b64decode(raw, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError, binascii.Error):
            continue
        if _direct_injection(decoded):
            return True
    for match in list(_HEX_RUN.finditer(text))[:8]:
        raw = match.group(0)
        if len(raw) > 4096:
            continue
        try:
            decoded = bytes.fromhex(raw).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _direct_injection(decoded):
            return True
    return False


def _direct_injection(text: str) -> str | None:
    for label, pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            return label
    return None


def detect_injection(text: str) -> str | None:
    """Return a rule category, if detected. Absence does NOT mean safe."""
    if not isinstance(text, str):
        return "invalid_text"
    normalized = unicodedata.normalize("NFKC", text)
    # Check both variants to avoid losing evidence during normalization.
    return _direct_injection(normalized) or (
        "encoded_injection" if _encoded_injection(normalized) else None
    )


def _has_disallowed_chars(text: str) -> bool:
    # Cc/Cf includes spoofing / invisible tag characters. Allow tabs/newlines.
    return any(unicodedata.category(ch) in {"Cc", "Cf"} and ch not in "\n\t\r" for ch in text)


@dataclass(frozen=True)
class ValidationResult:
    allowed: bool
    text: str = ""
    reason: str = "OK"
    pii_types: tuple[str, ...] = ()


def validate_user_question(raw: Any) -> ValidationResult:
    """Fail closed on malformed input; send only normalized/redacted text onward."""
    if not isinstance(raw, str):
        return ValidationResult(False, reason="invalid_type")
    # Limit BEFORE doing expensive Unicode normalization or encoded inspection.
    if len(raw) > MAX_QUESTION_CHARS:
        return ValidationResult(False, reason="too_long")
    if not raw.strip():
        return ValidationResult(False, reason="empty_input")
    if _has_disallowed_chars(raw):
        return ValidationResult(False, reason="invisible_or_control_characters")
    normalized = unicodedata.normalize("NFKC", raw).strip()
    if _HTML_TAG.search(normalized):
        return ValidationResult(False, reason="markup_not_supported")
    flag = detect_injection(normalized)
    if flag:
        return ValidationResult(False, reason=f"prompt_injection:{flag}")
    cleaned, categories = redact_pii(normalized)
    return ValidationResult(True, cleaned, "OK", categories)


@dataclass(frozen=True)
class AuthContext:
    """Trusted app-issued context; never parse role from the natural-language query."""
    role: str = "public"
    authorized_doc_ids: frozenset[str] = field(default_factory=frozenset)


def is_authorized(metadata: Mapping[str, Any], actor: AuthContext) -> bool:
    """Server-side document authorization; missing classification -> DENY.

    - Public corpus: accessible to all roles.
    - Internal: only coach/trainer/staff accounts.
    - Restricted: only trainer AND explicit per-document authorization.
    Real deployments must bind actor to verified identity and institutional policy.
    """
    classification = metadata.get("classification")
    doc_id = str(metadata.get("doc_id", ""))
    if classification == "public":
        return True
    if classification == "internal":
        return actor.role in {"coach", "trainer", "staff"}
    if classification == "restricted":
        return actor.role == "trainer" and doc_id in actor.authorized_doc_ids
    return False


class SecurityAuditLogger:
    """Minimal structured event logger; no prompts, output text, names or doc IDs."""
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self.events: list[dict[str, Any]] = []

    def record(self, stage: str, action: str, reason: str, categories: Iterable[str] = ()) -> None:
        event = {
            "ts_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "stage": stage,
            "action": action,
            "reason": reason,
            "categories": list(sorted(set(categories))),
        }
        self.events.append(event)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, separators=(",", ":")) + "\n")


class SecurityGateway:
    """Input -> authorization -> source inspection -> output redaction.

    All retrieved records should be screened before constructing the LLM prompt.
    No externally trusted auth context or document provenance is created here.
    """
    def __init__(self, logger: SecurityAuditLogger | None = None) -> None:
        self.audit = logger or SecurityAuditLogger()

    def prepare_question(self, raw: Any) -> ValidationResult:
        result = validate_user_question(raw)
        self.audit.record("input", "allow" if result.allowed else "block",
                          result.reason, result.pii_types)
        return result

    def filter_context(self, items: list[dict[str, Any]],
                       actor: AuthContext) -> tuple[list[dict[str, Any]], dict[str, int]]:
        """Never forward unauthorized, ambiguous-provenance, or poisoned chunks."""
        kept: list[dict[str, Any]] = []
        stats = {"accepted": 0, "access_denied": 0, "quarantined": 0, "redacted": 0}
        for item in items[:MAX_CONTEXT_CHUNKS]:
            metadata = item.get("metadata")
            content = item.get("text")
            if not isinstance(metadata, Mapping) or not isinstance(content, str):
                stats["quarantined"] += 1
                self.audit.record("retrieval", "quarantine", "malformed_chunk")
                continue
            if not is_authorized(metadata, actor):
                stats["access_denied"] += 1
                self.audit.record("retrieval", "deny", "document_access_denied")
                continue
            if not content.strip() or len(content) > MAX_SOURCE_CHARS or _has_disallowed_chars(content):
                stats["quarantined"] += 1
                self.audit.record("retrieval", "quarantine", "invalid_document_text")
                continue
            if _HTML_TAG.search(content):
                stats["quarantined"] += 1
                self.audit.record("retrieval", "quarantine", "untrusted_markup")
                continue
            flag = detect_injection(content)
            if flag:
                stats["quarantined"] += 1
                self.audit.record("retrieval", "quarantine", f"injection:{flag}")
                continue
            # Metadata fields are not authoritative instructions. Avoid forwarding
            # unscreened titles/section labels into prompts or source responses.
            section = metadata.get("section", "unknown")
            if not isinstance(section, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", section):
                stats["quarantined"] += 1
                self.audit.record("retrieval", "quarantine", "invalid_metadata")
                continue
            cleaned, categories = redact_pii(content)
            if categories:
                stats["redacted"] += 1
                self.audit.record("retrieval", "redact", "pii", categories)
            safe = dict(item)
            safe["text"] = cleaned
            safe["metadata"] = {
                "doc_id": str(metadata.get("doc_id", "")),
                "section": section,
                "classification": metadata["classification"],
            }
            safe["chunk_id"] = str(item.get("chunk_id", ""))[:64]
            kept.append(safe)
            stats["accepted"] += 1
        return kept, stats

    def protect_output(self, raw_answer: Any) -> ValidationResult:
        if not isinstance(raw_answer, str):
            self.audit.record("output", "block", "invalid_output_type")
            return ValidationResult(False, reason="invalid_output_type")
        # Fail closed on likely model obedience to an injection instruction.
        flag = detect_injection(raw_answer)
        if flag:
            self.audit.record("output", "block", f"unsafe_model_output:{flag}")
            return ValidationResult(False, reason="unsafe_model_output")
        cleaned, pii = redact_pii(raw_answer)
        self.audit.record("output", "redact" if pii else "allow", "PII" if pii else "OK", pii)
        return ValidationResult(True, cleaned, "OK", pii)


def stats_json_safe(logger: SecurityAuditLogger) -> dict[str, int]:
    """Summarize event counts without storing raw user data."""
    counts: dict[str, int] = {}
    for entry in logger.events:
        key = f"{entry['stage']}:{entry['action']}"
        counts[key] = counts.get(key, 0) + 1
    return counts

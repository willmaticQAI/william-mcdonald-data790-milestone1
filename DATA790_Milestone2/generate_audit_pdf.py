"""Generate the Milestone 2 audit PDF from measured OFFLINE test totals.

This report does not claim that any UNC API-backed red-team tests were run.
Re-run run_security_eval.py after modifying controls. If live testing is later
conducted, add a separately measured, verified section rather than inventing it.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate, Frame, KeepTogether, PageTemplate, Paragraph,
    Spacer, Table, TableStyle, PageBreak, HRFlowable
)

ROOT = Path(__file__).resolve().parent
RESULTS = json.loads((ROOT / "reports" / "security_test_results.json").read_text())
OUT = ROOT / "reports" / "Milestone_2_Security_Audit.pdf"
NAVY = colors.HexColor("#152D4B")
BLUE = colors.HexColor("#2E6DA4")
SLATE = colors.HexColor("#48566A")
LIGHT = colors.HexColor("#F1F5F9")
BORDER = colors.HexColor("#D7E1EA")
WHITE = colors.white

style = getSampleStyleSheet()
style.add(ParagraphStyle(name="AuditTitle", parent=style["Title"], fontName="Helvetica-Bold", fontSize=19, leading=24, textColor=NAVY, spaceAfter=11, alignment=TA_LEFT))
style.add(ParagraphStyle(name="AuditSection", parent=style["Heading2"], fontName="Helvetica-Bold", fontSize=11.2, leading=16, textColor=NAVY, spaceBefore=14, spaceAfter=6))
style.add(ParagraphStyle(name="AuditBody", parent=style["BodyText"], fontName="Helvetica", fontSize=9, leading=13.4, textColor=SLATE, spaceAfter=7))
style.add(ParagraphStyle(name="AuditSmall", parent=style["BodyText"], fontName="Helvetica", fontSize=7.6, leading=11, textColor=SLATE, spaceAfter=4))
style.add(ParagraphStyle(name="AuditTable", parent=style["BodyText"], fontName="Helvetica", fontSize=8, leading=11.4, textColor=NAVY))
style.add(ParagraphStyle(name="AuditWhite", parent=style["BodyText"], fontName="Helvetica-Bold", fontSize=8, leading=11.5, textColor=WHITE))
style.add(ParagraphStyle(name="AuditSubtitle", parent=style["BodyText"], fontName="Helvetica", fontSize=10.2, leading=15, textColor=BLUE, spaceAfter=12))


def p(txt, sty="AuditBody"):
    return Paragraph(txt, style[sty])


def heading(txt):
    return p(txt, "AuditSection")


def table(headers, rows, widths, shade_first=False):
    data = [[p(h, "AuditWhite") for h in headers]]
    for row in rows:
        data.append([p(str(t), "AuditTable") for t in row])
    t = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    commands = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, 0), 9),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 9),
        ("TOPPADDING", (0, 1), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 8),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, BORDER),
    ]
    if shade_first:
        commands += [("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT])]
    t.setStyle(TableStyle(commands))
    return t


class AuditDoc(BaseDocTemplate):
    def __init__(self, path):
        super().__init__(str(path), pagesize=(612, 792),
                         leftMargin=45, rightMargin=45, topMargin=67,
                         bottomMargin=53, title="DATA 790 - Milestone 2 Security Audit",
                         author="William McDonald", subject="Security-Hardened RAG - Offline Audit")
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id="normal", showBoundary=0)
        self.addPageTemplates([PageTemplate(id="content", frames=frame, onPage=self._header_footer)])

    def _header_footer(self, canvas, doc):
        canvas.saveState()
        canvas.setFillColor(NAVY)
        canvas.rect(0, 758, 612, 34, stroke=0, fill=1)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.setFillColor(WHITE)
        canvas.drawString(45, 771, "DATA 790  /  SECURITY AUDIT")
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(567, 771, "MILESTONE 2")
        canvas.setStrokeColor(BORDER)
        canvas.line(45, 42, 567, 42)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(SLATE)
        canvas.drawString(45, 29, "William McDonald  |  Offline controls audit  |  26 October 2026")
        canvas.drawRightString(567, 29, f"Page {doc.page}")
        canvas.restoreState()


story = []
story += [p("Security Audit Report", "AuditTitle"),
          p("Milestone 2 | Security-Hardened Retrieval-Augmented Generation System", "AuditSubtitle")]
story += [p("<b>Prepared for:</b> DATA 790 - Advanced AI Frameworks in Production &nbsp;&nbsp; <b>Student:</b> William McDonald"),
          p("<b>Assessment date:</b> October 26, 2026 &nbsp;&nbsp; <b>Evidence:</b> Offline unit/adversarial tests; source-code review of the uploaded Milestone 1 notebook"),
          HRFlowable(width="100%", thickness=0.8, color=BORDER, spaceAfter=10)]

story += [heading("1. Executive summary")]
counts=RESULTS["totals"]
story += [p(
    "Milestone 2 extends the existing course-topic RAG baseline with an input-security gateway, "
    "retrieval-time source screening and authorization, PII redaction at input/retrieval/output, "
    "privacy-conscious audit events, and automated adversarial regression tests. "
    f"<b>{counts['passed']} of {counts['executed']} local deterministic tests passed; "
    f"{counts['failed']} failed and {counts['skipped']} were skipped.</b> "
    "No live model-backed prompt-injection tests were performed as part of this build. "
    "These results do not establish production safety or compliance with data-protection law."
)]

story += [heading("2. Assessed assets and scope")]
story += [p(
    "<b>In scope:</b> one Jupyter-based RAG workflow, the Python policy module, retrieved-context "
    "screens, synthetic athlete records, application-side document class rules, output screening, "
    "and offline pytest evidence. The existing source corpus is ten course-focused knowledge sections."
)]
story += [p(
    "<b>Out of scope:</b> real athlete or patient records; institutional SSO; hosting/network controls; "
    "multi-user isolation; live UNC AI Gateway penetration tests; formal legal/compliance review; "
    "external security scanning; and independent red-team assessment."
)]

story += [heading("3. Trust boundaries")]
story += [table(
    ["Boundary", "Enforcement / behavior"],
    [
      ("User -> query", "Reject malformed/control-character/HTML inputs; screen known direct and encoded injection; redact detectable PII before embeddings or prompts."),
      ("Vector store -> evidence", "Filter permitted classification at query time and check each returned document again; quarantine known injection text and unsafe metadata."),
      ("Evidence -> model", "Present inspected source JSON as untrusted context in a user message; system message forbids treating sources as instructions."),
      ("Model -> user", "Redact detectable PII and selected secrets; refuse obvious instruction-like unsafe model responses."),
      ("Actor -> access", "Access is determined in application code; demo role is not authenticated. Missing document classification is denied."),
    ], [135, 387], True)]

story += [PageBreak(), heading("4. Threat model and controls")]
story += [table(
    ["ID / threat", "Attack scenario / potential impact", "Implemented safeguard and status"],
    [
      ("T1: Direct injection", "User tries to override system policy or reveal privileged instructions.", "Bounded keyword/phrase rules, Unicode checks, source isolation. <b>Tested offline</b>."),
      ("T2: Indirect / RAG poisoning", "Poisoned retrieved page instructs the model to ignore the user task or exfiltrate data.", "Quarantine screened source text/metadata and pass only inspected data. <b>Tested offline</b>."),
      ("T3: Sensitive data leakage", "Email, phone, ID, card or API token travels into model context or output.", "Detectors and category-specific redaction at three boundaries. <b>Tested on synthetic strings</b>."),
      ("T4: Unauthorized document", "Coach/public user retrieves a private team or synthetic medical note.", "Classification filtering + Python ACL; restricted requires trainer and explicit document allowlist. <b>Policy tested offline</b>."),
      ("T5: Output misuse", "Generated answer repeats a malicious instruction or recognizable secret.", "Post-generation scan, redaction and controlled refusal. <b>Tested offline</b>."),
      ("T6: Abuse / resource limits", "Very long user inputs or oversized retrieved text exhaust resources.", "Caps on questions, source text and context chunk count. No service-level rate limits. <b>Partially tested</b>."),
    ], [113, 193, 216], True)]

story += [heading("5. Vulnerabilities identified in Milestone 1 and changes")]
for text in [
    "<b>Minimal user-input screening:</b> Milestone 1 checked length, empty strings, and a small regex denylist. Updated to normalized, typed, bounded input inspection and known encoded-pattern detection.",
    "<b>No retrieved-document safeguards:</b> Milestone 1 directly built model context from Chroma results. Updated to document authorization, poisoned-source quarantine, metadata checks, and retrieval redaction.",
    "<b>No dedicated PII or output protection:</b> Milestone 1 returned generation results directly. Updated to common-format redaction, output screening and non-content-bearing audit events.",
    "<b>Limited security evidence:</b> Milestone 1 contained four simple security prompts. Updated with repeatable offline automated adversarial, PII, permission and false-positive tests.",
]:
    story.append(p("&#8226; " + text))

story += [PageBreak(), heading("6. Measured offline security testing")]
story += [p(
    "The included Python regression suite executes against deterministic gateway functions and mock "
    "retrieved records. It does not call an embedding service or chat model. Case expectations are "
    "fixed prior to the test run; the resulting JSON includes counts and category totals, not raw prompts."
)]
name_labels={
    "input_validation":"Input validation / malformed content",
    "direct_prompt_injection":"Direct + Base64/hex injection rules",
    "indirect_prompt_injection":"Indirect / document poisoning",
    "pii_protection":"Synthetic PII redaction",
    "access_control":"Application-side document access",
    "benign_false_positives":"Legitimate-query acceptance",
    "other_guardrail_tests":"Output / audit / integration checks",
}
rows=[]
for key, label in name_labels.items():
    m=RESULTS['categories'][key]
    rows.append((label,str(m['executed']),str(m['passed']),str(m['failed'])))
rows.append(("<b>TOTAL</b>",f"<b>{counts['executed']}</b>", f"<b>{counts['passed']}</b>",f"<b>{counts['failed']}</b>"))
story += [table(["Control/test group", "Cases", "Passed", "Failed"], rows, [306,72,72,72], True)]
story += [Spacer(1,11),p(
    f"<b>Observed selected-case pass rate:</b> {counts['passed']}/{counts['executed']} = "
    f"{counts['passed']/counts['executed']*100:.1f}% (offline, known cases only). "
    "This does <b>not</b> estimate open-world attack detection rate or LLM attack success rate. "
    "The finite benign set also does not establish population-wide false-positive rates."
)]
story += [heading("7. Security test limitations")]
for text in [
    "No adversarial calls to the configured UNC AI Gateway were executed; live output resistance, quality and token overhead remain unmeasured.",
    "Rule-based injection screening cannot detect every semantic, multilingual, typoglycemic, nested-encoding, or multimodal attack.",
    "PII patterns omit many identifiers and contextual medical information. Use dedicated regulated-data review before production.",
    "Synthetic access controls assume trusted upstream identity and source classification; they are not an identity-management system.",
    "Stored Chroma collection is ephemeral and the demonstration does not implement per-user rate limiting, tenant isolation or operational incident response.",
]:
    story.append(p("&#8226; " + text))

story += [PageBreak(), heading("8. OWASP LLM Top 10 risk-to-control mapping")]
story += [p("Mapping is to 2025 OWASP LLM risk names. These are <b>design alignments, not certification or proof of complete mitigation</b>.")]
story += [table(["OWASP category", "Milestone 2 measure / remaining gap"], [
    ("LLM01 - Prompt Injection", "Question and source checks; quarantines and output screening. Novel/model-level attacks remain."),
    ("LLM02 - Sensitive Information Disclosure", "Synthetic PII/secrets redaction and minimal audit logging. No real PHI compliance validation."),
    ("LLM04 - Data and Model Poisoning", "Known malicious retrieved text quarantined. No independent third-party corpus provenance validation."),
    ("LLM05 - Improper Output Handling", "Output controls for text, but no comprehensive HTML/SQL/UI sink controls."),
    ("LLM07 - System Prompt Leakage", "Specific extraction patterns and refusals; no guarantees against alternative prompts."),
    ("LLM08 - Vector and Embedding Weaknesses", "Metadata classification and double ACL check; no enterprise multi-tenant vector-store controls."),
    ("LLM10 - Unbounded Consumption", "String/source/chunk limits; rate limiting, quotas and spending alerts not implemented."),
], [187,335], True)]

story += [heading("9. Priority remediation plan")]
for text in [
    "<b>Before grading/submission:</b> run the full notebook with the owner's valid credentials and record real safe-query and attack outcomes; verify the end-to-end source provenance and re-run baseline quality/cost metrics.",
    "<b>Before any deployment:</b> integrate trusted campus identity, centrally managed permissions, logging and incident response, quotas, persistent vector-store security, and human review of private data access.",
    "<b>Before regulated datasets:</b> seek formal institutional review; replace synthetic demonstrations with approved workflows, dedicated PII/PHI controls and independently evaluated defenses.",
]: story.append(p("&#8226; " + text))

story += [heading("10. Evidence, reproducibility and references")]
story += [p(
    "<b>Source files:</b> `william_mcdonald_milestone_2_security_hardened.ipynb`, "
    "`milestone2_security/pipeline.py`, `tests/test_security_controls.py`, "
    "`run_security_eval.py`, `reports/security_test_results.json`. "
    "To reproduce offline counts run `python run_security_eval.py` from the project root. "
    "To regenerate this document run `python generate_audit_pdf.py`."
)]
story += [p(
    "<b>References:</b> OWASP LLM Prompt Injection Prevention Cheat Sheet: "
    "https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html "
    "and OWASP LLM Top 10: https://genai.owasp.org/llm-top-10/", "AuditSmall"
)]
story += [p("<b>Audit conclusion:</b> A tested educational baseline has been implemented. "
            "Live evaluation, authorization integration and broader assurance remain open work; "
            "the system should not be characterized as production secure.")]

AuditDoc(OUT).build(story)
print(f"Created {OUT}")

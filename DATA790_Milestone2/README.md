# DATA 790 | Milestone 2: Security-Hardened RAG System

**Student:** William McDonald  
**Course:** DATA 790 - Advanced AI Frameworks in Production  
**Milestone:** 2 - Security-Hardened AI System (15% of course grade)

This project extends the original [Milestone 1 production-style RAG baseline](https://github.com/willmaticQAI/william-mcdonald-data790-milestone1) with **multilayer input validation, prompt-injection defenses, PII screening and redaction, authorization rules, privacy-safe auditing, and a reproducible adversarial test suite**. It preserves the original notebook's chunking experiments, vector retrieval, question answering, answer-quality evaluation, and cost projection.

> **Current scope:** The RAG corpus still contains **10 course-focused knowledge sections**, not real collegiate sports data. The collegiate athletics intelligence system is our *intended application*. Only synthetic football statistics and restricted-document placeholders are provided as security examples. **No authentic athlete medical records should be added to this demonstration.**

> **Security status:** Educational proof of concept, **not certified for production deployment**. The offline suite passes, but live end-to-end model-backed tests and integration with institutional authentication are outstanding. A passed regex test does not demonstrate comprehensive resistance to prompt injection.

## Architecture

```text
 User question + app-verified identity and role
         |
         v
  INPUT GATEWAY
  - type / length / Unicode / markup validation
  - direct and bounded encoded-injection screening
  - PII detection and redaction
         |
         v
  Sanitized question -> embeddings -> Chroma top-k search
         |                         (metadata ACL prefilter)
         v
  RETRIEVAL GATEWAY
  - document classification + application-side authorization
  - indirect-injection + metadata screening
  - retrieved-content PII redaction
  - quarantine / deny suspicious records
         |
         v
  Structured untrusted source evidence (JSON)
         |
         v
  gpt-4o-mini generation + optional evidence-support judge
         |
         v
  OUTPUT GATEWAY
  - re-screen dangerous instruction text
  - redact recognizable PII and secrets
         |
         v
  Answer + permitted source IDs, or safe refusal
         |
         +--> privacy-safe event counters (no raw text)
         +--> offline adversarial tests + security audit PDF
```

### Security boundaries and explicit limitations

1. **Role-based document access:** Chroma queries receive an application-provided classification filter; every retrieved record is then checked again with `is_authorized()`. Documents **without classification are denied**. Public users see `public`; coaches/staff can see `public` and `internal`; trainers can see `public`/`internal`, with a document-specific allowlist additionally required for `restricted` records. The caller identity, role and document allowlist must be sourced from a **trusted authentication service**. The notebook's hardcoded demonstration role is **not authentication**.
2. **Injection defense:** The gateway screens known direct, encoded (bounded Base64/hex), and document-borne injection patterns. A document that matches is quarantined before LLM context is built. Model prompts label context as untrusted data. No pattern list, prompt instruction or JSON delimiter guarantees resistance to semantic, multilingual, multimodal or novel prompt injection.
3. **PII:** Redaction supports common email, US phone, SSN-like strings, labeled DOB/student/athlete IDs, labeled personal names and home addresses, checksum-valid card numbers, and selected API token formats. False negatives, false positives, context-specific and medical PII are expected. Do not use with real regulated records without specialized DLP, access controls, legal review and institutional approval.
4. **Output controls:** Answers are redacted before return. Obvious instruction-looking outputs trigger a controlled refusal. This is not an exhaustive exfiltration detector. Do not render untrusted LLM output as executable HTML, shell commands, or SQL.
5. **Logging:** `SecurityAuditLogger` records timestamp, stage, action, rule reason and PII category only. **No raw questions, document text, answers, names, credentials or document IDs**. Logging data still requires lifecycle and access policies in a deployment.
6. **Evaluation:** Offline tests validate deterministic code behavior, not real model compliance. Live LLM adversarial success rates, document corpus monitoring and independent red-team review remain necessary.

## Rubric coverage

| Milestone 2 requirement | Added implementation | Evidence |
|---|---|---|
| **Input Validation** (25 pts) | Multilayer type/length/Unicode/markup checks, normalization, bounded encoded inspection | `validate_user_question`; input and benign tests |
| **Prompt Injection Defense** (25 pts) | Direct attacks, encoded attempts, indirect source quarantine, untrusted context boundaries, output control | `detect_injection`, `filter_context`; direct + indirect attack tests |
| **PII Protection** (20 pts) | Input/retrieval/output redaction, format detectors, least-data logging | `redact_pii`; synthetic PII tests |
| **Security Testing** (20 pts) | Automated adversarial/benign suite, measured JSON summary, no-network regression | `tests/`, `run_security_eval.py` |
| **Documentation and Compliance** (10 pts) | Threat model, OWASP risk mapping, residual risks, evaluation scope | This README + `reports/Milestone_2_Security_Audit.pdf` |

Rubric coverage describes implementation, **not an assigned grade**.

## Repository layout

```text
DATA790_Milestone2/
├── README.md
├── .gitignore
├── .env.example
├── requirements.txt
├── william_mcdonald_milestone_2_security_hardened.ipynb
├── milestone2_security/
│   ├── __init__.py
│   └── pipeline.py
├── tests/
│   └── test_security_controls.py
├── data/
│   └── synthetic_athlete_records.json
├── run_security_eval.py
├── generate_audit_pdf.py
└── reports/
    ├── security_test_results.json
    └── Milestone_2_Security_Audit.pdf
```

## Quick start (Python 3.12 recommended)

```bash
# From this project folder
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt

# Offline security tests - no API key needed
python run_security_eval.py

# Run the model-backed RAG notebook (requires credentials)
cp .env.example .env
# Edit .env and set UNC_AI_API_KEY; do not commit it.
jupyter lab
```

Open `william_mcdonald_milestone_2_security_hardened.ipynb` and run **top to bottom** from the project directory. It imports the sibling `milestone2_security` package. The notebook includes `%pip install` for classroom convenience, but reproducible setup should use the `requirements.txt` above.

**UNC AI Gateway:** Notebook is configured for `https://azureaiapi.cloud.unc.edu/openai/v1`, using `text-embedding-3-small` and `UNC_CHAT_MODEL` (default: `gpt-4o-mini`). Model calls, tokens and latency depend on the user's credentials, provider access and current environment. **No gateway calls were made during this offline package build.**

**Security:** Never paste real secrets into the notebook or upload `.env`. Avoid running this educational prototype with authentic athlete medical records.

## Offline adversarial test evidence

Run:

```bash
python run_security_eval.py
# Or:
python -m pytest -q tests/
```

**Measured local run (October 26, 2026): 98 passed, 0 failed, 0 skipped.** All are offline Python tests; **0 live model attack tests** were executed in that run.

| Tested category | Passed / executed |
|---|---:|
| Input validation | 12 / 12 |
| Direct + encoded injection | 22 / 22 |
| Indirect / retrieved document injection | 12 / 12 |
| Synthetic PII detection and screening | 22 / 22 |
| Document authorization | 14 / 14 |
| Benign false-positive examples | 10 / 10 |
| Other output/audit/integration checks | 6 / 6 |
| **Total** | **98 / 98** |

Machine-readable summary: `reports/security_test_results.json` (contains only aggregate counts and scope caveats). Tests were written before execution. A **100% pass rate on these selected cases is not a 100% real-world detection rate**. Examples are known patterns, and the negative test set is limited.

## What to test with your UNC credentials (not yet completed)

Once the notebook runs successfully through the UNC gateway, record **actual measured outcomes** for:

1. A legitimate course question that is answered using correct source IDs and contains no unnecessary redactions.
2. A blocked direct prompt-injection query, verifying the generator was not called.
3. A benign question with a synthetic email/ID, verifying sanitized text is what reaches the embedding model and generation model.
4. A retrieved document with a known malicious instruction, verifying that it is quarantined and no malicious instruction reaches the model.
5. An access-denied synthetic restricted note, verifying it cannot enter context for a public or coach role.
6. A simulated malicious model response, verifying output redaction or refusal.
7. Measured per-case false negatives, false positives and latency before and after hardening.

**Important:** Only after these are actually run should the audit PDF be updated to include live attack results. Do not report hypothetical results as measurements. Store case IDs and outcome statuses, not raw sensitive prompts or model completions.

## Historical Milestone 1 results (baseline only)

The original notebook evaluated a 22-question **course-topic** golden set using a 10-section corpus. Prior recorded results: top-3 hit rate **1.0**, precision@3 **0.485**, average LLM judge score **0.841**, generation latency approximately **869 ms**, and estimated primary answer-generation cost approximately **$0.0000385/query**. These are **historical Milestone 1 observations**, not new Milestone 2 measurements. Hardening may change latency, retrieval behavior, token cost and answer quality; re-run model-backed evaluations to establish new figures.

## OWASP mapping (2025 LLM Top 10 terminology)

- **LLM01 - Prompt Injection:** screening at input and retrieval, source quarantine, structured prompts, regression attacks.
- **LLM02 - Sensitive Information Disclosure:** PII redaction, least-data context, privacy-safe logging.
- **LLM04 - Data and Model Poisoning:** quarantine of malicious retrieved text; trusted source ingestion remains future work.
- **LLM05 - Improper Output Handling:** output policy and redaction (not a substitute for safe HTML/UI handling).
- **LLM07 - System Prompt Leakage:** specific extraction patterns and policy-driven refusals.
- **LLM08 - Vector and Embedding Weaknesses:** explicit document classes and search-time + application-side ACLs.
- **LLM10 - Unbounded Consumption:** input length and document count/size limits; per-user quotas and rate limiting remain future work.

References:
- [OWASP LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
- [OWASP GenAI Security Project - LLM Top 10](https://genai.owasp.org/llm-top-10/)

Mappings are **design correspondences**, not claims of certification, regulatory compliance, or complete mitigation.

## Threat model and remaining risks

**Assets:** instructions, retrieved knowledge, future sports records, PII, API credentials, model outputs and audit logs.  
**Adversaries:** untrusted users and actors able to modify external/retrieved sources.  
**Entry points:** user prompts, query encodings, document text, document metadata and generated answers.  
**Trust boundaries:** user -> validation; vector store -> source ACL/poison scanner; source data -> model; model output -> user; app identity -> document authorization.

Outstanding concerns:

- Unknown/multilingual/semantic prompt injections bypass simple rules; no trained classifier or red-team evaluation is included.
- PII rules don't cover names, all national formats, contextual health data or every credential format.
- This notebook does not implement institutional SSO, service-level rate limiting, tenant isolation, audit log retention or real access provisioning.
- The current Chroma client is ephemeral and locally scoped; persisted multi-user deployments need separate controls.
- The initial corpus is author-controlled; untrusted third-party ingestion, document provenance and supply-chain safeguards remain future work.
- The LLM support judge remains advisory, not a trusted security control.

## Submission checklist

- [x] Updated Milestone 2 RAG notebook with extensive comments
- [x] Multilayer security gateway with direct/indirect injection screening
- [x] Synthetic PII screening and document authorization demonstrations
- [x] Offline adversarial test suite with actual counts
- [x] Security audit report PDF based on **offline evidence only**
- [ ] Re-run the complete notebook using your own UNC credentials
- [ ] Complete and document live end-to-end security tests
- [ ] Review the audit report and update it with actual live findings
- [ ] Commit files to a GitHub repo (without `.env` or real restricted data)
- [ ] Submit repository URL plus the final security audit PDF

The notebook also includes an optional `RUN_LIVE_SECURITY_PROBES = False` cell; enable it only after the UNC-backed notebook runs successfully. It records four selected live smoke-test outcomes without saving the raw input or model text.

The full PDF report and the notebook are **included**, but **not all final submission steps are complete** until you execute the credentialed tests and push the code.

## Future athletics intelligence roadmap

Once security is validated, replace the course corpus with approved public collegiate football datasets, add stable athlete IDs/team/season metadata, establish player-name disambiguation, introduce verified programmatic aggregation for yards-per-game and similar statistics, and test controlled access to *synthetic* restricted records. That expansion is beyond the evidence currently included in the Milestone 2 report.

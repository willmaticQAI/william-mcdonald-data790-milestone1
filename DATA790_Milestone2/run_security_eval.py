"""Run offline pytest cases, store machine-readable aggregate evidence.

No raw prompts or PII are written to the report JSON. The JUnit XML is an
intermediate local artifact and intentionally excluded from distribution.
"""
import json
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPORT = ROOT / "reports" / "security_test_results.json"

with tempfile.TemporaryDirectory(prefix="data790_pytest_") as temp:
    xml = Path(temp) / "tests.xml"
    args = [sys.executable, "-m", "pytest", "-q", "tests/", f"--junitxml={xml}"]
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True, check=False)
    print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    parsed = ET.parse(xml).getroot() if xml.exists() else None
    cases = list(parsed.iter("testcase")) if parsed is not None else []
    totals = {
        "executed": len(cases),
        "passed": sum(not any(t.tag in {"failure", "error", "skipped"} for t in c) for c in cases),
        "failed": sum(any(t.tag in {"failure", "error"} for t in c) for c in cases),
        "skipped": sum(any(t.tag == "skipped" for t in c) for c in cases),
    }
    category_prefixes = {
        "input_validation": ("test_input_validation",),
        "direct_prompt_injection": ("test_direct_prompt", "test_encoded_"),
        "indirect_prompt_injection": ("test_indirect_",),
        "pii_protection": ("test_pii_", "test_input_pii", "test_context_protects_pii", "test_output_redacts"),
        "access_control": ("test_application_side", "test_no_classification", "test_missing_auth"),
        "benign_false_positives": ("test_legitimate_",),
        "other_guardrail_tests": (),
    }
    by_category = {}
    classified = set()
    for category, prefixes in category_prefixes.items():
        if not prefixes:
            matches = [c for c in cases if id(c) not in classified]
        else:
            matches = [c for c in cases if any(c.attrib.get("name", "").startswith(p) for p in prefixes)]
        classified.update(id(c) for c in matches)
        by_category[category] = {
            "executed": len(matches),
            "passed": sum(not any(t.tag in {"failure", "error", "skipped"} for t in c) for c in matches),
            "failed": sum(any(t.tag in {"failure", "error"} for t in c) for c in matches),
        }
    output = {
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "suite": "deterministic_offline_unit_and_adversarial",
        "model_api_called": False,
        "scope": "Python controls and mock context only; no end-to-end LLM evidence",
        "totals": totals,
        "categories": by_category,
        "exit_code": result.returncode,
        "limitations": [
            "Rule-based detection cannot prove resistance to unseen, obfuscated, multilingual, or semantic attacks.",
            "Redaction rules cannot detect every type of PII or clinical information.",
            "Role context is trusted only if the host application authenticates the caller.",
            "Live retrieval and generation require a separately credentialed UNC gateway run.",
        ],
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {REPORT}")
    if result.returncode != 0:
        raise SystemExit(result.returncode)

# ============================================================
# app/pii/presidio_custom.py
# PASTE THIS ENTIRE FILE — replaces your existing one.
#
# KEY FIX: detect_pii() now accepts an optional `entities`
# parameter. This is required because main.py calls:
#   detect_pii(text, entities=active_entities)
# Without this fix it throws TypeError: unexpected keyword argument.
# ============================================================

from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from app.utils.config_loader import CFG

PII_THRESHOLD = CFG.get("pii_confidence_threshold", 0.40)
CNIC_SCORE    = CFG.get("cnic_pattern_score", 0.85)
STU_SCORE     = CFG.get("student_id_score", 0.88)
API_SCORE     = CFG.get("api_key_score", 0.90)
PHONE_SCORE   = CFG.get("pak_phone_score", 0.82)
ENTITIES      = CFG.get("entities_to_scan", [])


# ── CUSTOMIZATION 1: Pakistani CNIC ──────────────────────────
# Format: 35202-1234567-1
cnic_recognizer = PatternRecognizer(
    supported_entity="PAK_CNIC",
    patterns=[Pattern(
        name="pak_cnic",
        regex=r"\b\d{5}-\d{7}-\d{1}\b",
        score=CNIC_SCORE,
    )],
    context=["cnic", "identity", "id card", "national id",
             "identification", "شناختی", "قومی شناخت"],
)

# ── CUSTOMIZATION 2: Student ID ───────────────────────────────
# Format: FA21-BCS-123
student_id_recognizer = PatternRecognizer(
    supported_entity="STUDENT_ID",
    patterns=[Pattern(
        name="student_reg_id",
        regex=r"\b[A-Z]{2}\d{2}-[A-Z]{2,4}-\d{3,4}\b",
        score=STU_SCORE,
    )],
    context=["student id", "registration", "reg no",
             "roll no", "student number", "reg"],
)

# ── CUSTOMIZATION 3: API Key ──────────────────────────────────
api_key_recognizer = PatternRecognizer(
    supported_entity="API_KEY",
    patterns=[
        Pattern(
            name="openai_style_key",
            regex=r"\bsk-[A-Za-z0-9]{20,}\b",
            score=API_SCORE,
        ),
        Pattern(
            name="bearer_token",
            regex=r"\bBearer\s+[A-Za-z0-9\-_\.]{20,}\b",
            score=API_SCORE,
        ),
        Pattern(
            name="generic_api_key",
            regex=r"\b(?:api[_\-]?key|API[_\-]?KEY)\s*[:=]\s*[A-Za-z0-9\-_]{10,}\b",
            score=0.85,
        ),
    ],
    context=["api key", "api token", "bearer", "authorization",
             "secret key", "access token"],
)

# ── CUSTOMIZATION 4: Pakistani Phone ─────────────────────────
pak_phone_recognizer = PatternRecognizer(
    supported_entity="PAK_PHONE",
    patterns=[
        Pattern(
            name="pak_mobile_dashed",
            regex=r"\b03\d{2}-\d{7}\b",
            score=PHONE_SCORE,
        ),
        Pattern(
            name="pak_mobile_plain",
            regex=r"\b03\d{9}\b",
            score=PHONE_SCORE - 0.05,
        ),
    ],
    context=["phone", "mobile", "call", "contact",
             "number", "whatsapp", "فون", "موبائل"],
)

# ── CUSTOMIZATION 5: Composite Student PII ───────────────────
composite_student_recognizer = PatternRecognizer(
    supported_entity="COMPOSITE_STUDENT_PII",
    patterns=[Pattern(
        name="student_id_plus_email",
        regex=r"[A-Z]{2}\d{2}-[A-Z]{2,4}-\d{3,4}.{0,80}[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}",
        score=0.95,
    )],
)

# ── Build Analyzer and Anonymizer ────────────────────────────
analyzer  = AnalyzerEngine()
anonymizer = AnonymizerEngine()

analyzer.registry.add_recognizer(api_key_recognizer)
analyzer.registry.add_recognizer(student_id_recognizer)
analyzer.registry.add_recognizer(pak_phone_recognizer)
analyzer.registry.add_recognizer(cnic_recognizer)
analyzer.registry.add_recognizer(composite_student_recognizer)


# ── Detection Function ────────────────────────────────────────

def detect_pii(user_input: str, entities: list = None) -> list:
    """
    Run Presidio on the input text and return detected PII.

    PARAMETER: entities (optional list)
        If provided, only scan for these entity types.
        This allows main.py to dynamically remove PERSON for Urdu
        text to prevent spaCy hallucinating Urdu verb phrases as names.
        If not provided, scans all default entities from config.

    WHY THE entities PARAMETER IS NEW:
        Original function only took user_input. main.py was calling
        detect_pii(text, entities=active_entities) which would crash
        with TypeError. This fix makes the function accept it.
    """
    # Use provided entities or fall back to full config list
    scan_entities = entities if entities is not None else (ENTITIES + ["COMPOSITE_STUDENT_PII"])

    # Always include COMPOSITE if not already there and STUDENT_ID is present
    if "STUDENT_ID" in scan_entities and "COMPOSITE_STUDENT_PII" not in scan_entities:
        scan_entities = scan_entities + ["COMPOSITE_STUDENT_PII"]

    results = analyzer.analyze(
        text=user_input,
        language="en",
        entities=scan_entities,
        score_threshold=PII_THRESHOLD,
    )
    return results


def anonymize_text(user_input: str, results: list) -> str:
    """Replace detected PII with clear placeholder labels."""
    if not results:
        return user_input

    anonymized = anonymizer.anonymize(
        text=user_input,
        analyzer_results=results,
        operators={
            "PAK_CNIC":              OperatorConfig("replace", {"new_value": "<CNIC>"}),
            "STUDENT_ID":            OperatorConfig("replace", {"new_value": "<STUDENT_ID>"}),
            "API_KEY":               OperatorConfig("replace", {"new_value": "<API_KEY>"}),
            "PAK_PHONE":             OperatorConfig("replace", {"new_value": "<PHONE>"}),
            "EMAIL_ADDRESS":         OperatorConfig("replace", {"new_value": "<EMAIL>"}),
            "PHONE_NUMBER":          OperatorConfig("replace", {"new_value": "<PHONE>"}),
            "PERSON":                OperatorConfig("replace", {"new_value": "<PERSON>"}),
            "COMPOSITE_STUDENT_PII": OperatorConfig("replace", {"new_value": "<STUDENT_PII_BLOCK>"}),
        }
    )
    return anonymized.text


def pii_results_to_dict(results: list) -> list[dict]:
    """Convert Presidio results to plain dicts for JSON serialization."""
    return [
        {
            "type":  r.entity_type,
            "start": r.start,
            "end":   r.end,
            "score": round(r.score, 3),
        }
        for r in results
    ]


def check_for_secrets(results: list) -> bool:
    """Return True if detected PII includes API keys or composite blocks."""
    sensitive_types = {"API_KEY", "COMPOSITE_STUDENT_PII"}
    return any(r.entity_type in sensitive_types for r in results)

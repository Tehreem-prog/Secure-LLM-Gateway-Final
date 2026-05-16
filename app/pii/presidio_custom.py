# ============================================================
# app/pii/presidio_custom.py
# ─── IMPROVED FROM MID-LAB ──────────────────────────────────
#
# WHAT CHANGED FROM MID-LAB:
#   Mid-lab had 4 Presidio customizations (CNIC + composite + context + threshold)
#   Final-lab adds:
#     - STUDENT_ID recognizer (FA21-BCS-123 format) ← NEW
#     - PAK_PHONE recognizer (03XX-XXXXXXX format)  ← NEW
#     - API_KEY recognizer (sk-..., Bearer ...)      ← NEW
#     - Improved composite: student ID + email       ← NEW
#     - Better context words for each entity         ← IMPROVED
#
# CONCEPTS (for viva):
#   PatternRecognizer: Presidio class that detects entities using REGEX
#   Context words: Words near an entity that BOOST its confidence score
#   Composite entity: Detecting TWO entity types that appear together
#   Anonymization: Replacing detected values with <PLACEHOLDER> labels
#   score_threshold: Minimum confidence to report an entity (calibration)
# ============================================================

from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from app.utils.config_loader import CFG

# Load thresholds from config
PII_THRESHOLD = CFG.get("pii_confidence_threshold", 0.40)
CNIC_SCORE    = CFG.get("cnic_pattern_score", 0.85)
STU_SCORE     = CFG.get("student_id_score", 0.88)
API_SCORE     = CFG.get("api_key_score", 0.90)
PHONE_SCORE   = CFG.get("pak_phone_score", 0.82)
ENTITIES      = CFG.get("entities_to_scan", [])


# ══════════════════════════════════════════════════════════════
# CUSTOMIZATION 1: Pakistani CNIC Recognizer (SAME AS MID)
# Format: 35202-1234567-1  (5 digits - 7 digits - 1 digit)
# ══════════════════════════════════════════════════════════════
cnic_recognizer = PatternRecognizer(
    supported_entity="PAK_CNIC",
    patterns=[Pattern(
        name="pak_cnic",
        regex=r"\b\d{5}-\d{7}-\d{1}\b",
        score=CNIC_SCORE,
    )],
    # CUSTOMIZATION 2 (Context-Aware Scoring):
    # If any of these words appear NEAR the CNIC number,
    # Presidio boosts the confidence score.
    # This reduces false positives (random 5-7-1 digit patterns).
    context=["cnic", "identity", "id card", "national id", "identification", "شناختی", "قومی شناخت"],
)


# ══════════════════════════════════════════════════════════════
# CUSTOMIZATION 3: Student ID Recognizer ← NEW IN FINAL
# Format: FA21-BCS-123, SP22-BSE-456, etc.
# ══════════════════════════════════════════════════════════════
student_id_recognizer = PatternRecognizer(
    supported_entity="STUDENT_ID",
    patterns=[Pattern(
        name="student_reg_id",
        # Matches CUI-style IDs: 2 letters + 2 digits + hyphen + 3 letters + hyphen + 3 digits
        regex=r"\b[A-Z]{2}\d{2}-[A-Z]{2,4}-\d{3,4}\b",
        score=STU_SCORE,
    )],
    # Context words that indicate this is a student ID
    context=["student id", "registration", "reg no", "roll no", "student number", "reg"],
)


# ══════════════════════════════════════════════════════════════
# CUSTOMIZATION 4: API Key Recognizer ← NEW IN FINAL
# Catches: sk-xxxx (OpenAI), Bearer tokens, generic API keys
# ══════════════════════════════════════════════════════════════
api_key_recognizer = PatternRecognizer(
    supported_entity="API_KEY",
    patterns=[
        Pattern(
            name="openai_style_key",
            regex=r"\bsk-[A-Za-z0-9]{20,}\b",  # OpenAI-style: sk-...
            score=API_SCORE,
        ),
        Pattern(
            name="bearer_token",
            regex=r"\bBearer\s+[A-Za-z0-9\-_\.]{20,}\b",  # Bearer token
            score=API_SCORE,
        ),
        Pattern(
            name="generic_api_key",
            # Matches patterns like: api_key=XXXX or apiKey: XXXX
            regex=r"\b(?:api[_\-]?key|API[_\-]?KEY)\s*[:=]\s*[A-Za-z0-9\-_]{10,}\b",
            score=0.85,
        ),
    ],
    context=["api key", "api token", "bearer", "authorization", "secret key", "access token"],
)


# ══════════════════════════════════════════════════════════════
# CUSTOMIZATION 5: Pakistani Phone Recognizer ← NEW IN FINAL
# Format: 03XX-XXXXXXX or 03XXXXXXXXX
# ══════════════════════════════════════════════════════════════
pak_phone_recognizer = PatternRecognizer(
    supported_entity="PAK_PHONE",
    patterns=[
        Pattern(
            name="pak_mobile_dashed",
            regex=r"\b03\d{2}-\d{7}\b",   # 03XX-XXXXXXX
            score=PHONE_SCORE,
        ),
        Pattern(
            name="pak_mobile_plain",
            regex=r"\b03\d{9}\b",          # 03XXXXXXXXX (no dash)
            score=PHONE_SCORE - 0.05,      # slightly lower confidence
        ),
    ],
    context=["phone", "mobile", "call", "contact", "number", "whatsapp", "فون", "موبائل"],
)


# ══════════════════════════════════════════════════════════════
# CUSTOMIZATION 6: Composite Entity — Student ID + Email ← NEW
# Detects when a student ID and email appear together (high-risk combo)
# ══════════════════════════════════════════════════════════════
composite_student_recognizer = PatternRecognizer(
    supported_entity="COMPOSITE_STUDENT_PII",
    patterns=[Pattern(
        name="student_id_plus_email",
        # Matches: "FA21-BCS-123 ... ali@example.com" within ~80 chars
        regex=r"[A-Z]{2}\d{2}-[A-Z]{2,4}-\d{3,4}.{0,80}[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}",
        score=0.95,
    )],
)


# ── Build the Presidio Analyzer ──────────────────────────────
analyzer  = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# Register all custom recognizers
# ORDER MATTERS: more specific recognizers should be added first
analyzer.registry.add_recognizer(api_key_recognizer)
analyzer.registry.add_recognizer(student_id_recognizer)
analyzer.registry.add_recognizer(pak_phone_recognizer)
analyzer.registry.add_recognizer(cnic_recognizer)
analyzer.registry.add_recognizer(composite_student_recognizer)


# ── Detection Function ───────────────────────────────────────

def detect_pii(user_input: str) -> list:
    """
    Run Presidio on the input text and return detected PII entities.

    CUSTOMIZATION: Confidence Calibration (score_threshold)
    Only entities with confidence >= PII_THRESHOLD are returned.
    This is the key calibration step — prevents noisy false positives.

    Returns: list of RecognizerResult objects
    Each has: .entity_type, .start, .end, .score
    """
    all_entities = ENTITIES + ["COMPOSITE_STUDENT_PII"]

    results = analyzer.analyze(
        text=user_input,
        language="en",
        entities=all_entities,
        score_threshold=PII_THRESHOLD,   # Calibration threshold
    )
    return results


def anonymize_text(user_input: str, results: list) -> str:
    """
    Replace detected PII with clear placeholder labels.

    Examples:
      ali.khan@example.com     → <EMAIL_ADDRESS>
      35202-1234567-1          → <PAK_CNIC>
      FA21-BCS-123             → <STUDENT_ID>
      sk-abcdef123456789012    → <API_KEY>
      0312-3456789             → <PAK_PHONE>

    VIVA TIP: The anonymizer uses the start/end positions from
    the analyzer results to know WHERE to replace in the string.
    """
    if not results:
        return user_input

    anonymized = anonymizer.anonymize(
        text=user_input,
        analyzer_results=results,
        # Custom operators define HOW each entity type is replaced
        operators={
            "PAK_CNIC":             OperatorConfig("replace", {"new_value": "<CNIC>"}),
            "STUDENT_ID":           OperatorConfig("replace", {"new_value": "<STUDENT_ID>"}),
            "API_KEY":              OperatorConfig("replace", {"new_value": "<API_KEY>"}),
            "PAK_PHONE":            OperatorConfig("replace", {"new_value": "<PHONE>"}),
            "EMAIL_ADDRESS":        OperatorConfig("replace", {"new_value": "<EMAIL>"}),
            "PHONE_NUMBER":         OperatorConfig("replace", {"new_value": "<PHONE>"}),
            "PERSON":               OperatorConfig("replace", {"new_value": "<PERSON>"}),
            "COMPOSITE_STUDENT_PII": OperatorConfig("replace", {"new_value": "<STUDENT_PII_BLOCK>"}),
        }
    )
    return anonymized.text


def pii_results_to_dict(results: list) -> list[dict]:
    """
    Convert Presidio RecognizerResult objects to plain dicts for JSON output.
    Makes the API response serializable.
    """
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
    """
    Returns True if detected PII includes high-sensitivity secrets
    (API keys or composite blocks).
    Used by the policy engine to add extra risk weight.
    """
    sensitive_types = {"API_KEY", "COMPOSITE_STUDENT_PII"}
    return any(r.entity_type in sensitive_types for r in results)

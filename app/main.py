from fastapi import FastAPI
from pydantic import BaseModel
import time
import uuid

# Our own modules
from app.detectors.rule_detector     import calculate_rule_score
from app.detectors.semantic_detector import calculate_semantic_score, get_model_info
from app.pii.presidio_custom         import detect_pii, anonymize_text, pii_results_to_dict, check_for_secrets
from app.policy.policy_engine        import make_decision
from app.utils.language              import detect_language, is_mixed_language
from app.utils.logging               import write_audit_log
from app.utils.config_loader         import CFG  # Imported to read default configuration lists


# ── App Setup ────────────────────────────────────────────────
app = FastAPI(
    title="Robust Multilingual LLM Security Gateway",
    description=(
        "Final Lab — CSC 262. "
        "Hybrid injection detection (rule + semantic), "
        "multilingual support (EN/UR/KO), "
        "Presidio PII anonymization, auditable policy engine."
    ),
    version="2.0",
)


# ── Request Schema ───────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    input_id: str = ""         # optional: caller-supplied ID for tracking
    prompt:   str              # the user's input text


# ══════════════════════════════════════════════════════════════
# ENDPOINT 1: /analyze  (MAIN ENDPOINT — as per assignment spec)
# ══════════════════════════════════════════════════════════════
@app.post("/analyze")
async def analyze(request: AnalyzeRequest):
    start = time.time()

    # Generate input_id if not provided
    input_id = request.input_id or f"req_{uuid.uuid4().hex[:8]}"
    text = request.prompt

    # ── Step 1: Language Detection (NEW) ─────────────────────
    language = detect_language(text)
    mixed    = is_mixed_language(text)

    # ── Step 2: Rule-Based Detection (SAME AS MID + improved) ─
    rule_score, rule_codes = calculate_rule_score(text)

    # Add mixed-language code if applicable
    if mixed:
        rule_codes.append("MIXED_LANGUAGE_ATTACK")

    # ── Step 3: Semantic / ML Detection (NEW IN FINAL) ────────
    semantic_score, sem_codes = calculate_semantic_score(text)

    # ── Step 4: PII Detection with Language Calibration ──────
    # VIVA FIX: Extract scanned entities from your gateway_config.yaml file
    active_entities = CFG.get("entities_to_scan", []).copy()
    
    # If the text is Urdu, remove 'PERSON' dynamically to eliminate the 
    # out-of-distribution spaCy model hallucination on verb phrases like 'کریں'
    if language == "ur" and "PERSON" in active_entities:
        active_entities.remove("PERSON")

    # Pass the calibrated entity array to your detection function
    # Note: ensure your detect_pii function in presidio_custom.py accepts an entities list parameter if customized,
    # or pass active_entities directly into presidio's analyzer.
    pii_results = detect_pii(text, entities=active_entities)
    has_secrets = check_for_secrets(pii_results)
# ── Step 5: Policy Engine (IMPROVED IN FINAL) ─────────────
    decision, final_risk, reason_codes = make_decision(
        rule_score, semantic_score, pii_results,
        rule_codes, sem_codes, has_secrets
    )

    # ── THE MULTILINGUAL PRECISION FIX: Overcome OOD Embedding Bias ──
    # If the semantic model flags the text, but it's a non-English language 
    # with ZERO keyword rule violations, check for borderline script hallucinations.
    if language != "en" and rule_score == 0 and decision == "BLOCK":
        # Borderline zone where non-Latin scripts cluster tightly due to vector drift
        if semantic_score < 0.72:  
            decision = "ALLOW"
            final_risk = semantic_score * 0.4  # Dynamically demote risk weight
            
            # Clean up the audit logs and response schema codes
            if "SEMANTIC_INJECTION" in reason_codes:
                reason_codes.remove("SEMANTIC_INJECTION")
            
            # Log the specific language calibration for tracking transparency
            reason_codes.append(f"{language.upper()}_FALSE_POSITIVE_RECALIBRATION")
    # ─────────────────────────────────────────────────────────────────

    # ── Step 6: Build Safe Output ─────────────────────────────
    if decision == "MASK":
        safe_text = anonymize_text(text, pii_results)
    elif decision == "BLOCK":
        safe_text = None   # blocked — do not forward to LLM
    else:
        safe_text = text   # allow — pass through unchanged

    latency_ms = round((time.time() - start) * 1000, 1)

    # ── Step 7: Audit Logging (NEW IN FINAL) ──────────────────
    log_entry = {
        "input_id":      input_id,
        "language":      language,
        "mixed_lang":    mixed,
        "rule_score":    rule_score,
        "semantic_score": semantic_score,
        "pii_entities":  pii_results_to_dict(pii_results),
        "final_risk":    final_risk,
        "decision":      decision,
        "safe_text":     safe_text,
        "reason_codes":  reason_codes,
        "latency_ms":    latency_ms,
    }
    write_audit_log(log_entry)

    return log_entry


# ══════════════════════════════════════════════════════════════
# ENDPOINT 2: /health  (required by assignment)
# ══════════════════════════════════════════════════════════════
@app.get("/health")
def health():
    return {
        "status": "Gateway Online ✅",
        "version": "2.0 — Final Lab",
        "detectors": {
            "rule_based":   "Active (English + Urdu + Korean keywords)",
            "semantic_ml":  get_model_info(),
        },
        "pii_engine": "Microsoft Presidio (6 custom recognizers)",
        "audit_log":  "Active → results/audit_log.jsonl",
    }


# ══════════════════════════════════════════════════════════════
# ENDPOINT 3: /stats  (bonus — shows audit log summary)
# ══════════════════════════════════════════════════════════════
@app.get("/stats")
def stats():
    import json, os
    log_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "results", "audit_log.jsonl"
    )
    if not os.path.exists(log_path):
        return {"message": "No requests logged yet."}

    entries = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                entries.append(json.loads(line.strip()))
            except Exception:
                pass

    decisions = [e.get("decision") for e in entries]
    return {
        "total_requests": len(entries),
        "ALLOW":  decisions.count("ALLOW"),
        "MASK":   decisions.count("MASK"),
        "BLOCK":  decisions.count("BLOCK"),
        "avg_latency_ms": round(
            sum(e.get("latency_ms", 0) for e in entries) / max(len(entries), 1), 1
        ),
        "languages_seen": list(set(e.get("language", "?") for e in entries)),
    }

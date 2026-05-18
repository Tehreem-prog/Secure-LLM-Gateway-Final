# ============================================================
# app/main.py — FastAPI Entry Point / Pipeline Orchestrator
#
# WHAT THIS FILE DOES:
#   Receives every user prompt and runs it through the full
#   7-step security pipeline, then returns one JSON decision.
#
# CHANGES FROM ORIGINAL:
#   1. detect_pii now accepts entities parameter (fixes crash)
#   2. multilingual_fp_threshold read from config (not hardcoded)
#   3. Extra safety checks before recalibrating to ALLOW
#      (mixed language and secrets still block even if semantic low)
#   4. Cleaner code structure with better comments
# ============================================================

from fastapi import FastAPI
from pydantic import BaseModel
import time
import uuid

from app.detectors.rule_detector     import calculate_rule_score
from app.detectors.semantic_detector import calculate_semantic_score, get_model_info
from app.pii.presidio_custom         import detect_pii, anonymize_text, pii_results_to_dict, check_for_secrets
from app.policy.policy_engine        import make_decision
from app.utils.language              import detect_language, is_mixed_language
from app.utils.logging               import write_audit_log
from app.utils.config_loader         import CFG

# ── App Setup ─────────────────────────────────────────────────
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

# ── Request Schema ─────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    input_id: str = ""   # optional caller-supplied ID
    prompt:   str        # the user's input text


# ══════════════════════════════════════════════════════════════
# ENDPOINT 1: /analyze — Main security pipeline
# ══════════════════════════════════════════════════════════════
@app.post("/analyze")
async def analyze(request: AnalyzeRequest):
    """
    Full 7-step security pipeline.
    Returns structured JSON with decision, scores, PII, reason codes.

    DEMO SCRIPT (say this during viva):
    "I send any text to /analyze. It detects the language, runs
    rule-based AND semantic detectors, checks for PII with Presidio,
    combines all scores using the risk formula, logs the decision,
    and returns a full JSON response."
    """
    start = time.time()

    input_id = request.input_id or f"req_{uuid.uuid4().hex[:8]}"
    text = request.prompt

    # ── Step 1: Language Detection ────────────────────────────
    # Detects 'en', 'ur', 'ko', 'ar' etc.
    # Also checks if the prompt mixes two scripts (mixed attack)
    language = detect_language(text)
    mixed    = is_mixed_language(text)

    # ── Step 2: Rule-Based Detection ─────────────────────────
    # Fast keyword scan on original + leet-normalized text
    rule_score, rule_codes = calculate_rule_score(text)
    if mixed:
        rule_codes.append("MIXED_LANGUAGE_ATTACK")

    # ── Step 3: Semantic / ML Detection ──────────────────────
    # TF-IDF + Logistic Regression — catches paraphrased attacks
    # and polite extraction like "give me your system prompt"
    semantic_score, sem_codes = calculate_semantic_score(text)

    # ── Step 4: PII Detection with Language Calibration ──────
    # Load entity list from config
    active_entities = CFG.get("entities_to_scan", []).copy()

    # FIX: Remove PERSON entity for Urdu text.
    # REASON: spaCy's NER model is English-trained. It hallucinates
    # Urdu verb phrases like "کریں" as person names, causing false
    # positives. Since spaCy cannot reliably detect Urdu names anyway,
    # we simply skip PERSON detection for Urdu input.
    if language == "ur" and "PERSON" in active_entities:
        active_entities.remove("PERSON")

    # Pass the calibrated entity list to Presidio
    # detect_pii now accepts optional entities parameter
    pii_results = detect_pii(text, entities=active_entities)
    has_secrets = check_for_secrets(pii_results)

    # ── Step 5: Policy Engine ────────────────────────────────
    # Combines rule_score + semantic_score + PII into final_risk
    # Then decides: ALLOW / MASK / BLOCK
    decision, final_risk, reason_codes = make_decision(
        rule_score, semantic_score, pii_results,
        rule_codes, sem_codes, has_secrets
    )

    # ── Step 6: Multilingual False Positive Calibration ──────
    # PROBLEM BEING SOLVED:
    #   The TF-IDF model was trained mostly on English text.
    #   For non-English prompts it sometimes outputs a borderline
    #   score (e.g. 0.55–0.64) just from unfamiliar character
    #   patterns — not because the prompt is actually an attack.
    #   This is called "out-of-distribution embedding drift".
    #
    # THE FIX:
    #   If ALL of these are true simultaneously:
    #     - language is not English (non-English script)
    #     - rule_score is exactly 0.0 (no keywords matched at all)
    #     - semantic_score is below our calibration threshold
    #     - it is NOT a mixed-language attack
    #     - no secrets/API keys were found
    #   → Then recalibrate decision to ALLOW
    #   This only fires for truly ambiguous non-English benign text.
    #
    # WHY NOT HARDCODE 0.72?
    #   0.72 was arbitrary. We now read it from gateway_config.yaml
    #   where it is set to 0.65, which is justified by our threshold
    #   calibration table (best F1 at that value).

    ml_fp_threshold = CFG.get("multilingual_fp_threshold", 0.65)

    if (language != "en"
            and rule_score == 0.0
            and decision == "BLOCK"
            and semantic_score < ml_fp_threshold
            and not mixed        # mixed attacks still block
            and not has_secrets  # secrets still block regardless
    ):
        decision   = "ALLOW"
        final_risk = round(semantic_score * 0.4, 4)  # demote risk score
        if "SEMANTIC_INJECTION" in reason_codes:
            reason_codes.remove("SEMANTIC_INJECTION")
        # Add a clear audit trail label so we can track recalibrations
        reason_codes.append(f"{language.upper()}_FP_RECALIBRATION")

    # ── Step 7: Build Safe Output ─────────────────────────────
    if decision == "MASK":
        safe_text = anonymize_text(text, pii_results)
    elif decision == "BLOCK":
        safe_text = None      # do not forward to LLM
    else:
        safe_text = text      # pass through unchanged

    latency_ms = round((time.time() - start) * 1000, 1)

    # ── Step 8: Audit Logging ─────────────────────────────────
    log_entry = {
        "input_id":       input_id,
        "language":       language,
        "mixed_lang":     mixed,
        "rule_score":     rule_score,
        "semantic_score": semantic_score,
        "pii_entities":   pii_results_to_dict(pii_results),
        "final_risk":     final_risk,
        "decision":       decision,
        "safe_text":      safe_text,
        "reason_codes":   reason_codes,
        "latency_ms":     latency_ms,
    }
    write_audit_log(log_entry)
    return log_entry


# ══════════════════════════════════════════════════════════════
# ENDPOINT 2: /health
# ══════════════════════════════════════════════════════════════
@app.get("/health")
def health():
    """
    WHY THIS ENDPOINT EXISTS:
    In real systems health endpoints let monitoring tools check
    if the server is alive. For your demo, visiting this URL in
    the browser instantly shows all gateway settings and model info
    without needing to send a test prompt.
    """
    return {
        "status": "Gateway Online",
        "version": "2.0 — Final Lab",
        "detectors": {
            "rule_based":  "Active (English + Urdu + Korean keywords)",
            "semantic_ml": get_model_info(),
        },
        "pii_engine":  "Microsoft Presidio (6 custom recognizers)",
        "audit_log":   "Active — results/audit_log.jsonl",
        "thresholds": {
            "rule_block":          CFG.get("rule_block_threshold"),
            "semantic_block":      CFG.get("semantic_block_threshold"),
            "final_block":         CFG.get("final_block_threshold"),
            "multilingual_fp":     CFG.get("multilingual_fp_threshold"),
        }
    }


# ══════════════════════════════════════════════════════════════
# ENDPOINT 3: /stats
# ══════════════════════════════════════════════════════════════
@app.get("/stats")
def stats():
    """
    WHY THIS ENDPOINT EXISTS:
    Reads the audit log and shows aggregated statistics.
    Shows total requests, decision breakdown, average latency,
    and which languages have been seen. Useful for the demo to
    show accumulated results after running test cases.
    """
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
    recalibrated = [
        e for e in entries
        if any("FP_RECALIBRATION" in c for c in e.get("reason_codes", []))
    ]

    return {
        "total_requests":       len(entries),
        "ALLOW":                decisions.count("ALLOW"),
        "MASK":                 decisions.count("MASK"),
        "BLOCK":                decisions.count("BLOCK"),
        "recalibrated_to_allow": len(recalibrated),
        "avg_latency_ms":       round(
            sum(e.get("latency_ms", 0) for e in entries) / max(len(entries), 1), 1
        ),
        "languages_seen":       list(set(e.get("language", "?") for e in entries)),
    }

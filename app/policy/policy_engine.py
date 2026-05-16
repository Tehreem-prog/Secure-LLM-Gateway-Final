# ============================================================
# app/policy/policy_engine.py
# ─── IMPROVED FROM MID-LAB ──────────────────────────────────
#
# WHAT CHANGED FROM MID-LAB:
#   Mid-lab: Simple if/else — if score>=0.5 block, elif pii mask, else allow
#   Final:   Weighted risk FORMULA combining multiple signals
#              + reason_codes for auditability
#              + configurable weights
#              + handles secrets as extra-high-risk PII
#
# NEW CONCEPT: Risk Formula
#   final_risk = max(rule_score, semantic_score) + pii_weight + secret_weight
#
#   WHY max() not sum()?
#     If either detector is highly confident → that's enough to act.
#     We don't want to REQUIRE both detectors to agree.
#
#   pii_weight: added when any PII is found (even in benign text)
#   secret_weight: added when secrets (API keys) are found
#
# VIVA TIP: "Auditable" means every decision has a traceable
# reason_code so you can explain WHY a prompt was blocked.
# ============================================================

from app.utils.config_loader import CFG

# Thresholds from config
FINAL_BLOCK   = CFG.get("final_block_threshold", 0.60)
PII_WEIGHT    = CFG.get("pii_risk_weight", 0.15)
SECRET_WEIGHT = CFG.get("secret_risk_weight", 0.25)


def calculate_final_risk(
    rule_score: float,
    semantic_score: float,
    has_pii: bool,
    has_secrets: bool,
) -> float:
    """
    Combine all risk signals into one final_risk score (0.0–1.0+).

    Formula (documented as required by assignment):
      final_risk = max(rule_score, semantic_score) + pii_weight + secret_weight

    The formula is CONFIGURABLE: weights come from gateway_config.yaml.
    We cap the result at 1.0 to keep it interpretable as a probability.
    """
    base_risk = max(rule_score, semantic_score)    # take the more alarmed detector
    pii_addon    = PII_WEIGHT    if has_pii     else 0.0
    secret_addon = SECRET_WEIGHT if has_secrets else 0.0

    final_risk = base_risk + pii_addon + secret_addon
    return round(min(final_risk, 1.0), 4)


def make_decision(
    rule_score: float,
    semantic_score: float,
    pii_results: list,
    rule_codes: list,
    sem_codes: list,
    has_secrets: bool,
) -> tuple[str, float, list[str]]:
    """
    Make the final Allow / Mask / Block decision.

    Returns:
        decision    (str)        : "ALLOW" | "MASK" | "BLOCK"
        final_risk  (float)      : combined risk score
        reason_codes (list[str]) : all triggered reason codes

    DECISION LOGIC:
      BLOCK  → if final_risk >= FINAL_BLOCK threshold
               OR if either detector individually crossed its threshold
      MASK   → if benign text contains PII or secrets
      ALLOW  → everything else

    VIVA TIP: We check individual thresholds BEFORE the combined
    final_risk because a very high single score should block
    even if PII weight would otherwise push it down.
    """
    has_pii = len(pii_results) > 0

    # Collect ALL reason codes from both detectors
    all_reason_codes = list(set(rule_codes + sem_codes))

    # Calculate combined risk
    final_risk = calculate_final_risk(rule_score, semantic_score, has_pii, has_secrets)

    # ── Decision Tree ────────────────────────────────────────

    # BLOCK conditions:
    rule_threshold  = CFG.get("rule_block_threshold", 0.5)
    sem_threshold   = CFG.get("semantic_block_threshold", 0.55)

    is_injection = (
        rule_score  >= rule_threshold   or   # rule detector says attack
        semantic_score >= sem_threshold or   # ML detector says attack
        final_risk  >= FINAL_BLOCK           # combined risk is high
    )

    if is_injection:
        if not all_reason_codes:
            all_reason_codes.append("HIGH_RISK_SCORE")
        return "BLOCK", final_risk, all_reason_codes

    # MASK: benign text but contains PII / secrets
    if has_pii:
        all_reason_codes.append("PII_DETECTED")
        if has_secrets:
            all_reason_codes.append("SECRET_DETECTED")
        return "MASK", final_risk, all_reason_codes

    # ALLOW: safe and clean
    return "ALLOW", final_risk, ["CLEAN"]

# ============================================================
# tests/test_policy.py
# Quick tests for the policy engine.
# Run with: python -m pytest tests/ -v
# ============================================================

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.policy.policy_engine import make_decision, calculate_final_risk


def test_allow_clean():
    """Clean input with no PII and low scores → ALLOW"""
    decision, risk, codes = make_decision(0.0, 0.0, [], [], [], False)
    assert decision == "ALLOW"


def test_block_high_rule_score():
    """High rule score alone should trigger BLOCK"""
    decision, risk, codes = make_decision(0.9, 0.0, [], ["INSTRUCTION_OVERRIDE"], [], False)
    assert decision == "BLOCK"


def test_block_high_semantic_score():
    """High semantic score alone should trigger BLOCK"""
    decision, risk, codes = make_decision(0.0, 0.9, [], [], ["SEMANTIC_INJECTION"], False)
    assert decision == "BLOCK"


def test_mask_with_pii():
    """Low risk but PII present → MASK"""

    class FakePII:
        entity_type = "EMAIL_ADDRESS"

    decision, risk, codes = make_decision(0.0, 0.0, [FakePII()], [], [], False)
    assert decision == "MASK"


def test_block_overrides_pii():
    """Even if PII present, high risk → BLOCK (not MASK)"""

    class FakePII:
        entity_type = "EMAIL_ADDRESS"

    decision, risk, codes = make_decision(0.9, 0.9, [FakePII()], ["INSTRUCTION_OVERRIDE"], ["SEMANTIC_INJECTION"], False)
    assert decision == "BLOCK"


def test_final_risk_formula():
    """Test the risk formula values"""
    risk = calculate_final_risk(0.5, 0.4, True, False)
    # max(0.5, 0.4) + 0.15 = 0.65
    assert risk == 0.65

    risk2 = calculate_final_risk(0.3, 0.3, False, False)
    assert risk2 == 0.30


if __name__ == "__main__":
    # Run tests manually without pytest
    test_allow_clean();           print("✅ test_allow_clean")
    test_block_high_rule_score(); print("✅ test_block_high_rule_score")
    test_block_high_semantic_score(); print("✅ test_block_high_semantic_score")
    test_mask_with_pii();         print("✅ test_mask_with_pii")
    test_block_overrides_pii();   print("✅ test_block_overrides_pii")
    test_final_risk_formula();    print("✅ test_final_risk_formula")
    print("\nAll tests passed! ✅")

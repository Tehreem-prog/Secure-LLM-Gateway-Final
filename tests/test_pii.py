# ============================================================
# tests/test_pii.py
# Tests for Presidio PII detection and anonymization.
# ============================================================

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.pii.presidio_custom import detect_pii, anonymize_text


def test_cnic_detected():
    """Pakistani CNIC should be detected."""
    results = detect_pii("My CNIC is 35202-1234567-1")
    types = [r.entity_type for r in results]
    assert "PAK_CNIC" in types, f"Expected PAK_CNIC, got {types}"


def test_student_id_detected():
    """Student ID in CUI format should be detected."""
    results = detect_pii("My student ID is FA21-BCS-123")
    types = [r.entity_type for r in results]
    assert "STUDENT_ID" in types, f"Expected STUDENT_ID, got {types}"


def test_email_detected():
    """Email addresses should be detected."""
    results = detect_pii("Contact me at user@example.com")
    types = [r.entity_type for r in results]
    assert "EMAIL_ADDRESS" in types, f"Expected EMAIL_ADDRESS, got {types}"


def test_pak_phone_detected():
    """Pakistani mobile numbers should be detected."""
    results = detect_pii("Call me at 0312-3456789")
    types = [r.entity_type for r in results]
    assert "PAK_PHONE" in types, f"Expected PAK_PHONE, got {types}"


def test_api_key_detected():
    """API keys (sk- format) should be detected."""
    results = detect_pii("My API key is sk-abcdefghij1234567890abc")
    types = [r.entity_type for r in results]
    assert "API_KEY" in types, f"Expected API_KEY, got {types}"


def test_anonymization_replaces_cnic():
    """CNIC should be replaced with <CNIC> placeholder."""
    results = detect_pii("My CNIC is 35202-1234567-1")
    masked  = anonymize_text("My CNIC is 35202-1234567-1", results)
    assert "35202-1234567-1" not in masked
    assert "<CNIC>" in masked


def test_benign_not_flagged():
    """Clean text should return no PII."""
    results = detect_pii("Explain supervised learning with one example.")
    assert len(results) == 0, f"Expected no PII, got {[r.entity_type for r in results]}"


if __name__ == "__main__":
    test_cnic_detected();           print("✅ test_cnic_detected")
    test_student_id_detected();     print("✅ test_student_id_detected")
    test_email_detected();          print("✅ test_email_detected")
    test_pak_phone_detected();      print("✅ test_pak_phone_detected")
    test_api_key_detected();        print("✅ test_api_key_detected")
    test_anonymization_replaces_cnic(); print("✅ test_anonymization_replaces_cnic")
    test_benign_not_flagged();      print("✅ test_benign_not_flagged")
    print("\nAll PII tests passed! ✅")

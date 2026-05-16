# ============================================================
# app/utils/logging.py
# ─── NEW IN FINAL LAB ───────────────────────────────────────
#
# WHAT THIS FILE DOES:
#   Writes a structured JSON log entry for every request.
#   The mid-lab had NO audit logging — decisions were not
#   saved anywhere, making it impossible to review later.
#
# NEW CONCEPT: Audit Logging
#   An "audit log" records WHO sent WHAT, WHEN, and WHAT
#   decision was made. This is required in security systems
#   so you can go back and investigate suspicious activity.
#
# FORMAT: One JSON object per line (JSONL format).
#   This makes it easy to parse with Python or any log tool.
# ============================================================

import json
import os
from datetime import datetime

# Log file location
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_PATH = os.path.join(BASE_DIR, "results", "audit_log.jsonl")

# Make sure the results folder exists
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)


def write_audit_log(entry: dict) -> None:
    """
    Append one JSON log entry to the audit log file.

    Each entry includes:
      - timestamp      : when the request was processed
      - input_id       : unique request ID
      - language       : detected language of input
      - rule_score     : score from rule-based detector
      - semantic_score : score from ML detector (NEW in final)
      - pii_entities   : list of PII found
      - final_risk     : combined risk score
      - decision       : Allow / Mask / Block
      - reason_codes   : WHY the decision was made
      - latency_ms     : how long processing took

    VIVA TIP: The reason_codes field is what makes decisions
    "auditable" — you can trace back exactly which detector
    triggered the block/mask decision.
    """
    entry["timestamp"] = datetime.utcnow().isoformat() + "Z"
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

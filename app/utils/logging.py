# ============================================================
# app/utils/logging.py
# ─── WHAT THIS FILE DOES ─────────────────────────────────────
#
# Writes one JSON record to a log file for EVERY request.
# This is called "audit logging".
#
# WHAT IS AN AUDIT LOG?
#   An audit log is a permanent, append-only record of every
#   action a system took and WHY it took it.
#   Example: A bank keeps an audit log of every transaction.
#   If something goes wrong, you can go back and see exactly
#   what happened and when.
#
#   For our gateway: every prompt gets a log entry. If someone
#   later asks "why was this prompt blocked?", you open the
#   audit log and see the exact scores and reason codes.
#
# WHAT IS JSONL FORMAT?
#   JSON Lines (JSONL) = one complete JSON object per line.
#   Each line is independent and valid JSON on its own.
#   Example:
#     {"decision":"BLOCK","rule_score":1.0,...}
#     {"decision":"ALLOW","rule_score":0.0,...}
#   This is better than one big JSON array because:
#   - You can append one line at a time (fast, no file rewrite)
#   - You can read line by line without loading the whole file
#   - If the file gets corrupted mid-write, other lines are safe
#
# WHAT IS IN EACH LOG ENTRY?
#   timestamp      : exactly when the request was processed (UTC)
#   input_id       : unique ID for this request (for tracing)
#   language       : detected language code ('en', 'ur', 'ko')
#   mixed_lang     : True/False — was it a mixed-language prompt?
#   rule_score     : score from rule-based keyword detector (0–1)
#   semantic_score : score from ML detector (0–1)
#   pii_entities   : list of PII found (type, position, confidence)
#   final_risk     : combined risk score from policy formula
#   decision       : final verdict — ALLOW / MASK / BLOCK
#   safe_text      : the cleaned text (masked PII) or null if BLOCK
#   reason_codes   : WHY the decision was made — e.g.
#                    ["SEMANTIC_INJECTION", "SYSTEM_PROMPT_EXTRACTION"]
#   latency_ms     : how long the entire pipeline took in milliseconds
#
# WHY IS reason_codes THE MOST IMPORTANT FIELD?
#   It is what makes decisions "auditable" — you can trace back
#   exactly which detector triggered the block.
#   Without reason_codes, you only know the decision was BLOCK.
#   With reason_codes, you know it was blocked because the semantic
#   detector fired on a system-prompt extraction attempt.
#
# IMPROVEMENT IN THIS VERSION:
#   Added recalibrated_count tracking in /stats endpoint via
#   FP_RECALIBRATION reason code detection.
# ============================================================

import json
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_PATH = os.path.join(BASE_DIR, "results", "audit_log.jsonl")

# Create the results directory if it does not exist yet
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)


def write_audit_log(entry: dict) -> None:
    """
    Append one log entry to the audit log file.

    HOW IT WORKS:
        1. Add the current UTC timestamp to the entry
        2. Convert the Python dictionary to a JSON string
        3. Open the log file in APPEND mode ("a")
           → "a" means: add to the end, never overwrite existing content
        4. Write the JSON string + newline character
        5. File closes automatically (with statement handles this)

    WHY APPEND MODE?
        If we used write mode ("w") it would erase all previous logs
        on every request. Append mode ("a") keeps every entry forever.

    WHY ensure_ascii=False?
        Without this, Urdu and Korean characters would be converted to
        escaped Unicode like \u0633\u0633 instead of actual characters.
        ensure_ascii=False keeps them readable in the log file.
    """
    entry["timestamp"] = datetime.utcnow().isoformat() + "Z"

    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def read_audit_log() -> list[dict]:
    """
    Read all entries from the audit log and return as a list.
    Used by the /stats endpoint in main.py.

    WHY READ LINE BY LINE?
        The file is JSONL format — one JSON object per line.
        We cannot use json.load() on the whole file (that expects
        one big JSON structure). Instead we read line by line and
        parse each line separately.

    TRY/EXCEPT:
        If any line is corrupted (e.g. server crashed mid-write),
        we skip that line instead of crashing the entire stats call.
    """
    if not os.path.exists(LOG_PATH):
        return []

    entries = []
    with open(LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass  # skip corrupted lines
    return entries

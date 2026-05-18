# ============================================================
# app/utils/logging.py
# FIX: Audit log was not saving on Windows due to path issue.
# Now uses a hardcoded-relative path from project root that
# works correctly regardless of where Python is called from.
# ============================================================

import json
import os
from datetime import datetime

# Walk up from this file's location to find the project root
# This file is at: app/utils/logging.py
# So we go up twice: utils -> app -> project root
THIS_FILE    = os.path.abspath(__file__)
UTILS_DIR    = os.path.dirname(THIS_FILE)
APP_DIR      = os.path.dirname(UTILS_DIR)
PROJECT_ROOT = os.path.dirname(APP_DIR)

RESULTS_DIR = os.path.join(PROJECT_ROOT, "results")
LOG_PATH    = os.path.join(RESULTS_DIR, "audit_log.jsonl")

# Create results/ folder immediately when this module is imported
os.makedirs(RESULTS_DIR, exist_ok=True)

# Write a startup marker so you can verify the file is being created
_startup_marker = {
    "event":     "gateway_started",
    "log_path":  LOG_PATH,
    "timestamp": datetime.utcnow().isoformat() + "Z"
}
with open(LOG_PATH, "a", encoding="utf-8") as _f:
    _f.write(json.dumps(_startup_marker, ensure_ascii=False) + "\n")


def write_audit_log(entry: dict) -> None:
    """
    Append one JSON log entry to audit_log.jsonl.
    FIX: Uses absolute path from __file__ - works on Windows.
    Prints confirmation to terminal so you see it working live.
    """
    entry["timestamp"] = datetime.utcnow().isoformat() + "Z"

    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    print(f"[AUDIT] {entry.get('decision')} | "
          f"lang={entry.get('language')} | "
          f"risk={entry.get('final_risk')} | "
          f"id={entry.get('input_id')}")


def read_audit_log() -> list[dict]:
    """Read all entries from audit_log.jsonl and return as a list."""
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
                    pass
    return entries

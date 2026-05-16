# ============================================================
# app/utils/config_loader.py
# Reads gateway_config.yaml and exposes values as a dict.
# This means you NEVER need to hard-code thresholds in code.
# ============================================================

import yaml
import os

# Find the config file relative to this script's location
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "gateway_config.yaml")


def load_config() -> dict:
    """
    Load and return the YAML config as a Python dictionary.
    Called once at startup; re-call if you hot-reload config.
    """
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# Load once when module is imported (singleton pattern)
# Every other module does: from app.utils.config_loader import CFG
CFG = load_config()

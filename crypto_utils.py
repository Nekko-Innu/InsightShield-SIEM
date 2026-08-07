# crypto_utils.py
# Insight Shield — Fernet helpers for encrypted credential storage.
# Master key in .env as ENCRYPTION_KEY. Fail-loud at startup if missing or
# invalid: log a clear error and sys.exit(1). systemd reports the unit as
# failed and the operator sees the cause immediately.
#
# Round 3 design choice (2026-04-27, AskUserQuestion #2): refuse-to-start.
# Running with a broken key would silently emit empty/corrupt API keys to
# providers, which is worse than not running at all.
#
# No key rotation in v1 — losing ENCRYPTION_KEY makes every encrypted row
# unrecoverable. Documented in README.md and REBUILD_SPEC §3.

import os
import logging
import sys
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger("insightshield.crypto_utils")

_fernet: Optional[Fernet] = None


def get_master_key() -> Fernet:
    """
    Return the module-level Fernet singleton, initialising on first call.

    On first call:
      - Reads ENCRYPTION_KEY from os.environ.
      - If missing or not a valid Fernet key, logs a clear error pointing to
        the generation command and calls sys.exit(1).

    Subsequent calls return the cached singleton.
    """
    global _fernet
    if _fernet is not None:
        return _fernet

    raw = os.environ.get("ENCRYPTION_KEY", "").strip()
    if not raw:
        logger.error(
            "ENCRYPTION_KEY is missing from environment. Generate one with: "
            "python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\"  "
            "and add to .env. Refusing to start."
        )
        sys.exit(1)

    try:
        _fernet = Fernet(raw.encode())
    except (ValueError, TypeError) as e:
        logger.error(
            "ENCRYPTION_KEY is not a valid Fernet key (%s). "
            "A valid key is 32 url-safe base64-encoded bytes. Refusing to start.",
            e,
        )
        sys.exit(1)

    return _fernet


def encrypt_value(plaintext: str) -> str:
    """Return a Fernet-encrypted UTF-8 token for the plaintext.

    Empty / None inputs return the empty string — never raises so callers
    don't have to special-case missing values.
    """
    if not plaintext:
        return ""
    return get_master_key().encrypt(plaintext.encode()).decode()


def decrypt_value(ciphertext: str) -> Optional[str]:
    """Return the decrypted plaintext.

    Returns None on:
      - empty / None ciphertext
      - InvalidToken (corrupted row or rotated-then-not-rekeyed key)
      - malformed ciphertext that isn't even valid Fernet framing (bad
        base64, wrong type) — degrades the same way rather than raising

    Logs a warning so operators can spot rekey/corruption issues without
    crashing the request.
    """
    if not ciphertext:
        return None
    try:
        return get_master_key().decrypt(ciphertext.encode()).decode()
    except (InvalidToken, ValueError, TypeError) as e:
        logger.warning(
            "decrypt_value: %s — ciphertext is corrupted or was encrypted "
            "under a different ENCRYPTION_KEY. Returning None.",
            type(e).__name__,
        )
        return None

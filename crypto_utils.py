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
# Two separable keys, both optional to set:
#
#   ENCRYPTION_KEY         credentials at rest (api_keys, ai_providers)
#   BACKUP_ENCRYPTION_KEY  whole-database snapshots; falls back to
#                          ENCRYPTION_KEY when unset, so existing installs and
#                          existing .db.enc files keep working untouched
#
# They were one key doing both jobs, which meant a single disclosure yielded
# every credential the system holds AND every historical snapshot of the
# database those credentials live in. Splitting them is the whole point:
# the backup key can live somewhere the running app does not need it.
#
# Rotation: set ENCRYPTION_KEY_OLD (or BACKUP_ENCRYPTION_KEY_OLD) to the
# previous value and both are accepted for decryption while everything new is
# written under the current key, via MultiFernet. That gives a window to
# re-encrypt without a flag day. Losing the current key with no OLD set still
# makes rows unrecoverable — documented in README.md and REBUILD_SPEC §3.

import os
import logging
import sys
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

logger = logging.getLogger("insightshield.crypto_utils")

_fernet: Optional[MultiFernet] = None
_backup_fernet: Optional[MultiFernet] = None


def _build(primary_env: str, fallback_env: str | None = None) -> MultiFernet:
    """MultiFernet for `primary_env`, plus its _OLD value when one is set.

    MultiFernet encrypts with the FIRST key and decrypts with any of them, so
    ordering is load-bearing: current first, previous second.
    """
    raw = os.environ.get(primary_env, "").strip()
    source = primary_env
    if not raw and fallback_env:
        raw = os.environ.get(fallback_env, "").strip()
        source = fallback_env
    if not raw:
        logger.error(
            "%s is missing from environment. Generate one with: "
            "python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\"  "
            "and add to .env. Refusing to start.", primary_env,
        )
        sys.exit(1)

    keys = []
    try:
        keys.append(Fernet(raw.encode()))
    except (ValueError, TypeError) as e:
        logger.error(
            "%s is not a valid Fernet key (%s). A valid key is 32 url-safe "
            "base64-encoded bytes. Refusing to start.", source, type(e).__name__,
        )
        sys.exit(1)

    previous = os.environ.get(source + "_OLD", "").strip()
    if previous:
        try:
            keys.append(Fernet(previous.encode()))
            logger.info(
                "%s_OLD accepted: values written under the previous key still "
                "decrypt, everything new is written under the current one.",
                source,
            )
        except (ValueError, TypeError) as e:
            # Not fatal: the current key still works, and failing to start over
            # a stale rotation variable would be its own outage.
            logger.warning(
                "%s_OLD is not a valid Fernet key (%s); ignoring it. Anything "
                "encrypted under it will not decrypt.", source, type(e).__name__,
            )
    return MultiFernet(keys)


def get_master_key() -> MultiFernet:
    """
    Key for credentials at rest (api_keys, ai_providers).

    Reads ENCRYPTION_KEY, plus ENCRYPTION_KEY_OLD when a rotation is in
    progress. Missing or invalid means sys.exit(1) — running with a broken key
    would silently emit empty or corrupt credentials to providers, which is
    worse than not running at all (Round 3 design choice, 2026-04-27).

    Returns MultiFernet rather than Fernet now; the encrypt/decrypt surface
    used by callers is identical.
    """
    global _fernet
    if _fernet is None:
        _fernet = _build("ENCRYPTION_KEY")
    return _fernet


def get_backup_key() -> MultiFernet:
    """Key for whole-database snapshots.

    Falls back to ENCRYPTION_KEY when BACKUP_ENCRYPTION_KEY is unset, so this
    is a no-op for an existing install and every .db.enc already on disk still
    restores. Set BACKUP_ENCRYPTION_KEY to separate the two trust domains: the
    snapshots contain the encrypted credential rows, so one key covering both
    means a single disclosure opens everything, historical copies included.
    """
    global _backup_fernet
    if _backup_fernet is None:
        _backup_fernet = _build("BACKUP_ENCRYPTION_KEY",
                                fallback_env="ENCRYPTION_KEY")
    return _backup_fernet


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

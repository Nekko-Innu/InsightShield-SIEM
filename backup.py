# backup.py
# Insight Shield — SQLite Hot-Backup, Restore, Retention
# Purpose : WAL-safe online backup of insightshield.db. Daily cron at 02:00 PHT
#           via APScheduler, plus an IT-only "Run backup now" UI button and
#           a CLI entry point (`python -m backup`).
# Safety  : Uses sqlite3.Connection.backup() — reads take a shared lock but
#           concurrent writes in WAL mode continue uninterrupted.

import logging
import os
import shutil
import sqlite3
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import config
import crypto_utils
import db as dbmod

logger = logging.getLogger("insightshield.backup")

DEFAULT_BACKUP_DIR = Path("backups")
DEFAULT_KEEP = 14  # two weeks of daily snapshots


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def backup_db(target_dir: Path | str = DEFAULT_BACKUP_DIR) -> Path:
    """
    Snapshot insightshield.db to <target_dir>/insightshield-YYYYMMDD-HHMMSS.db.enc
    via SQLite's online backup API, then Fernet-encrypt the file in place.
    Returns the path of the encrypted file.

    Round E (§11.1b) — encrypts every snapshot with the existing master Fernet
    key (ENCRYPTION_KEY from .env). Single secret keeps the recovery story
    simple; LUKS-on-LVM in §13 still applies as a deployment-layer companion.

    WAL-safe: sqlite3.Connection.backup() uses the online backup protocol so
    other connections can read AND write during the copy.
    """
    target_dir = Path(target_dir)
    _ensure_dir(target_dir)

    ts = datetime.now(tz=config.PHT).strftime("%Y%m%d-%H%M%S")
    final_target = target_dir / f"insightshield-{ts}.db.enc"

    # Step 1: write a temp plaintext snapshot via the online backup API.
    # tempfile lives in the same directory so the encrypt step is a local read.
    tmp_fd, tmp_name = tempfile.mkstemp(
        prefix=f"insightshield-{ts}-", suffix=".db.tmp", dir=str(target_dir),
    )
    os.close(tmp_fd)  # we want sqlite3 to manage the file
    tmp_path = Path(tmp_name)
    try:
        src = dbmod._get_conn()  # live Flask DB connection (WAL mode)
        dest = sqlite3.connect(str(tmp_path))
        try:
            src.backup(dest)  # atomic; does not block writes
        finally:
            dest.close()

        # Step 2: encrypt the snapshot bytes with the master Fernet key.
        plaintext = tmp_path.read_bytes()
        fernet = crypto_utils.get_master_key()
        ciphertext = fernet.encrypt(plaintext)
        final_target.write_bytes(ciphertext)
    finally:
        # Always remove the plaintext temp, even on encryption failure — we
        # never want a plaintext snapshot lingering on disk.
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass

    size = final_target.stat().st_size
    logger.info(
        "Backup written: %s (%d bytes encrypted, plaintext was %d bytes)",
        final_target, size, len(plaintext),
    )
    return final_target


def list_backups(target_dir: Path | str = DEFAULT_BACKUP_DIR) -> list[dict]:
    """List existing backup files, newest first.

    Round E (§11.1b): finds both `.db.enc` (current) and `.db` (legacy
    plaintext from before the encryption commit). Both are listed so an
    operator can see and restore whichever is newest. The CLI distinguishes
    them by file extension; the restore_db() function auto-detects.
    """
    target_dir = Path(target_dir)
    if not target_dir.exists():
        return []
    rows = []
    paths = list(target_dir.glob("insightshield-*.db.enc")) + \
            list(target_dir.glob("insightshield-*.db"))
    for p in sorted(paths, key=lambda x: x.stat().st_mtime, reverse=True):
        stat = p.stat()
        rows.append({
            "name": p.name,
            "path": str(p),
            "size_bytes": stat.st_size,
            "mtime": datetime.fromtimestamp(stat.st_mtime, tz=config.PHT).isoformat(),
            "encrypted": p.suffix == ".enc",
        })
    return rows


def restore_db(backup_path: Path | str, db_path: Path | str = dbmod.DB_PATH) -> bool:
    """
    Restore insightshield.db from <backup_path>. Overwrites the current DB file.
    Caller should stop the Flask app first so no open connections corrupt the
    copy — this function does NOT shut down the app on its own.

    Round E (§11.1b): if <backup_path> ends with `.db.enc`, decrypt with the
    master Fernet key before writing. Legacy `.db` (plaintext) snapshots
    still restore via the original copy path.

    Returns True on success, False otherwise.
    """
    backup_path = Path(backup_path)
    db_path = Path(db_path)
    if not backup_path.exists():
        logger.error("Restore failed: %s does not exist", backup_path)
        return False

    # Paranoia copy of the current DB in case this restore is wrong.
    if db_path.exists():
        pre = db_path.with_suffix(db_path.suffix + ".pre-restore.bak")
        shutil.copy2(db_path, pre)
        logger.info("Pre-restore safety copy saved: %s", pre)

    if backup_path.suffix == ".enc":
        # Encrypted snapshot — decrypt with master key, write plaintext to db_path.
        try:
            ciphertext = backup_path.read_bytes()
            fernet = crypto_utils.get_master_key()
            plaintext = fernet.decrypt(ciphertext)
        except Exception as e:
            logger.error("Restore failed: decryption error on %s (%s)",
                         backup_path, e)
            return False
        db_path.write_bytes(plaintext)
        logger.warning(
            "Database restored from encrypted %s -> %s (%d bytes plaintext)",
            backup_path, db_path, len(plaintext),
        )
    else:
        # Legacy plaintext snapshot — direct copy (pre-encryption commit).
        shutil.copy2(backup_path, db_path)
        logger.warning("Database restored from plaintext %s -> %s",
                       backup_path, db_path)
    return True


def prune_old_backups(keep: int = DEFAULT_KEEP,
                      target_dir: Path | str = DEFAULT_BACKUP_DIR) -> int:
    """
    Keep the most-recent <keep> backup files, delete the rest.
    Returns the number of files removed.
    """
    rows = list_backups(target_dir)
    victims = rows[keep:]
    for r in victims:
        try:
            os.remove(r["path"])
            logger.info("Pruned old backup: %s", r["name"])
        except OSError as e:
            logger.warning("Failed to prune %s: %s", r["name"], e)
    return len(victims)


def run_daily_backup() -> None:
    """APScheduler entry point — create a backup then prune."""
    try:
        backup_db()
        prune_old_backups()
    except Exception as e:
        logger.error("Daily backup failed: %s", e)


# ── CLI ──────────────────────────────────────────────────────────────────────

def _cli_main(argv: list[str]) -> int:
    if not argv or argv[0] == "run":
        path = backup_db()
        print(f"Backup created: {path}")
        return 0
    if argv[0] == "list":
        rows = list_backups()
        if not rows:
            print("No backups found.")
            return 0
        for r in rows:
            print(f"{r['mtime']}  {r['size_bytes']:>10} bytes  {r['name']}")
        return 0
    if argv[0] == "restore" and len(argv) >= 2:
        ok = restore_db(argv[1])
        return 0 if ok else 1
    if argv[0] == "prune":
        keep = int(argv[1]) if len(argv) >= 2 else DEFAULT_KEEP
        removed = prune_old_backups(keep=keep)
        print(f"Pruned {removed} old backup(s), keeping newest {keep}.")
        return 0

    print("Usage: python -m backup [run|list|restore <path>|prune [keep]]")
    return 2


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    sys.exit(_cli_main(sys.argv[1:]))

# web/blueprints/admin_ops.py
# Backups and the audit log — IT_ADMIN only.

import logging

from flask import (
    Blueprint, Response, abort, flash, redirect, request, send_file, url_for,
)
from flask_login import current_user, login_required

import backup as backup_mod
import db
from decorators import role_required
from web.responses import csv_safe, reject_csv_flood

logger = logging.getLogger("insightshield.web.admin_ops")

bp = Blueprint("admin_ops", __name__)


# ── Admin: SQLite Backup/Restore (IT_ADMIN only) ────────────────────────────

@bp.route("/admin/backup", methods=["GET", "POST"])
@login_required
@role_required("IT_ADMIN")
def admin_backup():
    """
    Round 3: GET deep-link 302s into the Settings Backups tab. POST handlers
    (run / prune) keep working as before, then redirect to the Settings tab
    so the operator stays in the same UI.
    """
    if request.method == "POST":
        action = request.form.get("action", "run")
        if action == "run":
            try:
                path = backup_mod.backup_db()
                flash(f"Backup created: {path.name}", "success")
                db.log_audit(
                    action="BACKUP_RUN",
                    actor=current_user.username,
                    actor_role=current_user.role,
                    target=path.name,
                    ip=request.remote_addr,
                    details={"size_bytes": path.stat().st_size},
                )
            except Exception as e:
                logger.exception("Manual backup failed")
                # The exception text carries filesystem paths and, for a Fernet
                # failure, key state. The class name is enough to act on; the
                # detail is in the log and in Settings -> Errors.
                flash(
                    f"Backup failed ({type(e).__name__}) — see Settings → Errors.",
                    "error",
                )
        elif action == "prune":
            removed = backup_mod.prune_old_backups()
            flash(f"Pruned {removed} old backup(s).", "success")
            db.log_audit(
                action="BACKUP_PRUNE",
                actor=current_user.username,
                actor_role=current_user.role,
                target="backups/",
                ip=request.remote_addr,
                details={"removed": removed},
            )
        return redirect(url_for("admin_settings.admin_settings", tab="backups"))

    # GET: deep-link redirect
    return redirect(url_for("admin_settings.admin_settings", tab="backups"), code=302)

@bp.route("/admin/backup/download/<path:name>")
@login_required
@role_required("IT_ADMIN")
def admin_backup_download(name):
    """
    Download a single backup file.

    The old check was `if "/" in name or "\\" in name or ".." in name: abort(400)`,
    which misses the Windows drive-relative form. "C:.env" contains no separator
    and no "..", so it passed — and `Path("backups") / "C:.env"` evaluates to
    "C:.env", which Windows resolves against the current directory of drive C,
    i.e. the app's own CWD. That read ENCRYPTION_KEY and FLASK_SECRET_KEY;
    "C:insightshield.db" exfiltrated the live plaintext database, defeating the
    point of Fernet-encrypting the backups at all. Inert on the Linux target,
    live on a Windows dev host.

    Three checks now, in order of strength:
      1. The resolved path must sit inside the backup directory (kills traversal,
         drive-relative paths, and symlinks out of the directory).
      2. The name must match what backup.list_backups() actually offers, so the
         plaintext insightshield-*.db.tmp snapshot written mid-backup is not
         downloadable even if the process dies before unlinking it.
      3. It must exist.
    """
    backup_dir = backup_mod.DEFAULT_BACKUP_DIR.resolve()
    target = (backup_dir / name).resolve()

    if not target.is_relative_to(backup_dir):
        logger.warning(
            "Backup download rejected (escapes backup dir): name=%r resolved=%s actor=%s",
            name, target, getattr(current_user, "username", "?"),
        )
        abort(400)

    offered = {row["name"] for row in backup_mod.list_backups()}
    if target.name not in offered:
        logger.warning(
            "Backup download rejected (not an offered backup): name=%r actor=%s",
            name, getattr(current_user, "username", "?"),
        )
        abort(400)

    if not target.is_file():
        abort(404)
    return send_file(str(target), as_attachment=True, download_name=target.name)

# ── Admin: Audit Log (IT_ADMIN only) ────────────────────────────────────────

@bp.route("/admin/audit")
@login_required
@role_required("IT_ADMIN")
def admin_audit():
    """
    Round 3: deep-link compatibility. Audit Log moves into the Settings
    page as a tab; this route 302-redirects there with all query params
    preserved (audit search filters keep working from old bookmarks).
    /admin/audit.csv export is unchanged.
    """
    args = {"tab": "audit"}
    args.update(request.args.to_dict())
    return redirect(url_for("admin_settings.admin_settings", **args), code=302)

@bp.route("/admin/audit.csv")
@login_required
@role_required("IT_ADMIN")
def admin_audit_csv():
    """CSV export of the filtered audit view. Same query params as /admin/audit."""
    rejected = reject_csv_flood()
    if rejected:
        return rejected

    actor = (request.args.get("actor") or "").strip() or None
    action = (request.args.get("action") or "").strip() or None
    date_from = (request.args.get("from") or "").strip() or None
    date_to = (request.args.get("to") or "").strip() or None

    rows = db.search_audit(
        actor=actor,
        action=action,
        date_from=date_from,
        date_to=date_to,
        limit=5000,
    )

    import csv
    import io
    cols = ["id", "ts", "actor", "actor_role", "action",
            "target", "ip", "user_agent", "details"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([csv_safe(r.get(k, "")) for k in cols])

    # /export.csv has recorded an EXPORT_CSV row since it shipped; this route
    # recorded nothing. The one action that copies the audit trail out of the
    # system was the one action the audit trail did not contain — so an analyst
    # reviewing who saw what could not see this. The filters go in the row too:
    # "exported the audit log" and "exported every action by one user in one
    # week" are different events and the row has to tell them apart.
    db.log_audit(
        action="EXPORT_AUDIT_CSV",
        actor=current_user.username,
        actor_role=current_user.role,
        target="audit_log",
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", ""),
        details={
            "row_count": len(rows),
            "truncated": len(rows) >= 5000,
            "filters": {"actor": actor, "action": action,
                        "from": date_from, "to": date_to},
        },
    )

    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=insightshield-audit.csv"},
    )

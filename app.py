import os
import re
import json
import csv
import io
import copy
import shutil
from urllib.parse import quote
import html as html_module
import mimetypes
import secrets
import threading

try:
    from dotenv import load_dotenv

    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
except ImportError:
    pass

from flask import Flask, request, jsonify, send_from_directory, send_file, Response
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
import psycopg2
import psycopg2.extras
from datetime import datetime, timedelta, timezone

from ad_unlock import (
    ad_unlock_env_configured,
    set_local_ad_account_password,
    try_unlock_local_ad_account,
    validate_local_reset_password_policy,
)

from mail_service import (
    _parse_cc,
    outbound_identity_from_branding,
    send_agent_reply_email,
    send_customer_acknowledgment_email,
    send_customer_ad_password_reset_closed_email,
    send_customer_ad_unlock_closed_email,
    send_customer_ticket_view_otp_email,
    send_branded_multipart_email,
    send_email,
    send_forgot_password_agent_email,
    send_manager_approval_request_email,
    send_ticket_forward_email,
)
from email_templates import (
    apply_email_template_updates,
    default_email_branding,
    default_email_templates_dict,
    merge_stored_email_branding,
    merge_stored_email_templates,
    render_email_template,
    resolve_template_brand_name,
    template_brand_placeholders,
    templates_for_api_response,
)

app = Flask(__name__, static_folder='.', static_url_path='')
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
app.secret_key = os.environ.get("SECRET_KEY", "dev-ticket-portal-secret-change-in-production")


@app.errorhandler(psycopg2.OperationalError)
def _handle_psycopg2_operational_error(err):
    """Clearer API/HTML feedback when Postgres is unreachable or in recovery."""
    msg = str(err)
    app.logger.error("PostgreSQL operational error: %s", msg)
    detail = "Check DB_HOST / DB_PORT in .env and that PostgreSQL is running and accepting connections."
    if "recovery mode" in msg.lower():
        detail = (
            "The database server is in recovery mode (replica catch-up, crash recovery, or restore). "
            "Wait until it finishes, connect to the primary/write host instead, or change DB_HOST in .env."
        )
    wants_json = (request.accept_mimetypes.best or "").lower().find("json") >= 0
    if request.path.startswith("/api/") or wants_json:
        return jsonify({"success": False, "message": "Database unavailable. " + detail}), 503
    return (
        "<!DOCTYPE html><html><head><meta charset=utf-8><title>Database unavailable</title></head>"
        "<body style='font-family:system-ui;padding:2rem;max-width:40rem'>"
        "<h1>Database unavailable</h1>"
        f"<p>{html_module.escape(detail)}</p>"
        "<p style='color:#64748b;font-size:0.9rem'>Technical detail: "
        f"{html_module.escape(msg[:500])}</p></body></html>",
        503,
        {"Content-Type": "text/html; charset=utf-8"},
    )


_customer_otp_lock = threading.Lock()
_customer_otp_store = {}  # email_lower -> {"code": str, "expires": datetime}


def _utc_now_naive():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _normalize_public_lookup_email(value):
    return (value or "").strip().lower()


def normalize_staff_role(value):
    """Canonicalize role for login and user creation (avoids Agent vs agent dashboard lockouts)."""
    r = (value or "").strip().lower()
    if r == "manager":
        return "Manager"
    return "Agent"


_AGENT_ONLY_CLOUD_PWD_RE = re.compile(
    r"\n*--- Agent only: cloud password \(staff only\) ---.*?--- End agent only ---\s*",
    re.DOTALL,
)


def _strip_agent_only_cloud_password_from_description(text: str) -> str:
    """Remove staff-only cloud password section before returning ticket to the customer portal."""
    if not text:
        return text or ""
    t = _AGENT_ONLY_CLOUD_PWD_RE.sub("\n", text)
    return t.strip()


def _append_cloud_agent_only_password_block(description: str, data: dict) -> str:
    """
    Append cloud (Entra/M365) proposed password to ticket description for agents only.
    Customer portal strips this block via _strip_agent_only_cloud_password_from_description.
    """
    desc = description or ""
    if "--- Password reset ---" not in desc or "Local or cloud: Cloud" not in desc:
        return desc
    csp = (data.get("cloud_suggested_password") or "").strip()
    csc = (data.get("cloud_suggested_password_confirm") or "").strip()
    if not csp or not csc or csp != csc:
        return desc
    if "\n" in csp or "\r" in csp:
        return desc
    if len(csp) > 500:
        csp = csp[:500]
    block = (
        "\n\n--- Agent only: cloud password (staff only) ---\n"
        "Customer-proposed new password (apply manually in Entra ID / Microsoft 365):\n"
        f"{csp}\n"
        "--- End agent only ---\n"
    )
    return desc + block


def _otp_purge_expired():
    now = _utc_now_naive()
    dead = [k for k, v in list(_customer_otp_store.items()) if v["expires"] < now]
    for k in dead:
        _customer_otp_store.pop(k, None)


def _public_email_token_serializer():
    return URLSafeTimedSerializer(app.secret_key, salt="public-customer-ticket-email-v1")

UPLOAD_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads", "ticket_attachments")
os.makedirs(UPLOAD_ROOT, exist_ok=True)

# DB Config — set DB_HOST, DB_PORT, DB_USER, DB_PASS, DB_NAME (e.g. via Docker / .env)
DB_HOST = os.environ.get("DB_HOST", "202.164.150.222")
DB_PORT = os.environ.get("DB_PORT", "15044")
DB_USER = os.environ.get("DB_USER", "postgres")
DB_PASS = os.environ.get("DB_PASS", "123456")
DB_NAME = os.environ.get("DB_NAME", "junaiddb1")

def get_db():
    conn = psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        host=DB_HOST,
        port=DB_PORT
    )
    conn.autocommit = True
    return conn


def ensure_user_schema(cur):
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255),
            email VARCHAR(255) UNIQUE,
            password VARCHAR(255),
            role VARCHAR(50),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE")


def _row_field(row, key, tuple_index):
    """RealDictCursor returns dict; default cursor returns tuple."""
    if row is None:
        return None
    if isinstance(row, dict):
        return row.get(key)
    if isinstance(row, (list, tuple)) and len(row) > tuple_index:
        return row[tuple_index]
    return None


def manager_actor_ok(cur, manager_email):
    email = (manager_email or "").strip()
    if not email:
        return False
    ensure_user_schema(cur)
    cur.execute(
        """
        SELECT id, role FROM users
        WHERE LOWER(TRIM(email)) = LOWER(TRIM(%s)) AND COALESCE(is_active, TRUE) = TRUE
        """,
        (email,),
    )
    row = cur.fetchone()
    if not row:
        return False
    role = (_row_field(row, "role", 1) or "").strip().lower()
    return role == "manager"


def staff_actor_ok(cur, email):
    """Active agent or manager (for attachment download / view)."""
    if not email:
        return False
    ensure_user_schema(cur)
    cur.execute(
        "SELECT 1 FROM users WHERE email = %s AND COALESCE(is_active, TRUE) = TRUE",
        (email,),
    )
    return cur.fetchone() is not None


def staff_may_manage_ticket_approval(cur, staff_email, display_name, ticket):
    """Any active Agent or Manager may request/cancel/resend approvals."""
    if not staff_email:
        return False
    cur.execute(
        "SELECT role FROM users WHERE email = %s AND COALESCE(is_active, TRUE) = TRUE",
        (staff_email,),
    )
    row = cur.fetchone()
    r = _row_field(row, "role", 0) if row else None
    return bool(row) and (r or "") in ("Agent", "Manager")


def _emails_from_field(raw):
    if raw is None:
        return []
    if isinstance(raw, list):
        raw = ",".join(str(x) for x in raw if x)
    return _parse_cc(str(raw))


def _ticket_attachment_files_for_email(ticket_id, attachments_data):
    """Resolved ticket files on disk for outbound email (same rules as download)."""
    out = []
    if isinstance(attachments_data, str):
        try:
            attachments_data = json.loads(attachments_data)
        except json.JSONDecodeError:
            attachments_data = []
    if not isinstance(attachments_data, list):
        return out
    root_norm = os.path.normpath(UPLOAD_ROOT) + os.sep
    for item in attachments_data:
        rel = (item.get("path") or "").replace("\\", "/").strip()
        path_parts = [p for p in rel.split("/") if p]
        if len(path_parts) != 2 or path_parts[0] != str(ticket_id) or ".." in path_parts[1]:
            continue
        full = os.path.normpath(os.path.join(UPLOAD_ROOT, path_parts[0], path_parts[1]))
        if not full.startswith(root_norm) or not os.path.isfile(full):
            continue
        nm = item.get("name") or os.path.basename(path_parts[1]) or "attachment"
        mime = item.get("mime") or mimetypes.guess_type(nm)[0] or "application/octet-stream"
        out.append({"path": full, "filename": nm, "mime": mime})
    return out


def _forward_approvals_summary_text(approval_rows):
    lines = []
    for ap in approval_rows:
        d = dict(ap)
        st = d.get("status") or "—"
        lines.append(
            f"- [{st}] Approver: {d.get('manager_email') or '—'} | Requested by: {d.get('requested_by') or '—'}"
        )
        if d.get("reason"):
            lines.append(f"    Reason: {(d.get('reason') or '')[:500]}")
        if d.get("decided_at") and d.get("manager_comment"):
            lines.append(f"    Outcome note: {(d.get('manager_comment') or '')[:500]}")
    return "\n".join(lines) if lines else "(No approval records on this ticket.)"


def _build_forward_email_bodies(ticket, approval_rows, forwarder, note, portal_link):
    esc = html_module.escape
    pub_id = str(ticket.get("public_ticket_id") or ticket.get("id") or "")
    subj = f"Fwd: Ticket {pub_id} — {ticket.get('subject') or 'Support ticket'}"
    subj = subj[:900]
    cust = f"{ticket.get('customer_name') or ''} <{ticket.get('customer_email') or ''}>"
    appr_txt = _forward_approvals_summary_text(approval_rows)
    desc_plain = (ticket.get("description") or "—")[:12000]
    text_parts = [
        f"Forwarded by: {forwarder}",
        f"Ticket ID: {ticket.get('public_ticket_id')}",
        f"Subject: {ticket.get('subject')}",
        f"Status: {ticket.get('status')}",
        f"Priority: {ticket.get('priority')}",
        f"Assigned to: {ticket.get('assigned_to') or '—'}",
        f"Customer: {cust}",
        "",
        "Description:",
        desc_plain,
        "",
        "Manager approvals (summary):",
        appr_txt,
        "",
    ]
    if note:
        text_parts.extend(["Message from forwarder:", note, ""])
    text_parts.append(f"Workspace: {portal_link}")
    text_body = "\n".join(text_parts)
    desc_html = esc((ticket.get("description") or "—")[:8000])
    appr_html = esc(appr_txt).replace("\n", "<br>\n")
    note_block = (
        f'<div style="background:#eef2ff;border:1px solid #c7d2fe;border-radius:8px;padding:12px;margin:16px 0;white-space:pre-wrap;">'
        f"<strong>Note from forwarder</strong><br>{esc(note)}</div>"
        if note
        else ""
    )
    html_body = f"""<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="font-family:Segoe UI,system-ui,sans-serif;font-size:14px;color:#27272a;line-height:1.55;margin:16px;">
  <div style="font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:#71717a;">Forwarded enterprise case</div>
  <h1 style="font-size:18px;margin:8px 0 16px;">{esc(ticket.get('subject') or 'Support ticket')}</h1>
  <table style="width:100%;max-width:640px;border-collapse:collapse;font-size:13px;margin-bottom:16px;">
    <tr><td style="padding:6px 0;border-bottom:1px solid #e4e4e7;color:#71717a;width:120px;">Ticket ID</td>
        <td style="padding:6px 0;border-bottom:1px solid #e4e4e7;font-weight:600;">{esc(pub_id)}</td></tr>
    <tr><td style="padding:6px 0;border-bottom:1px solid #e4e4e7;color:#71717a;">Status</td>
        <td style="padding:6px 0;border-bottom:1px solid #e4e4e7;">{esc(str(ticket.get('status') or ''))}</td></tr>
    <tr><td style="padding:6px 0;border-bottom:1px solid #e4e4e7;color:#71717a;">Priority</td>
        <td style="padding:6px 0;border-bottom:1px solid #e4e4e7;">{esc(str(ticket.get('priority') or ''))}</td></tr>
    <tr><td style="padding:6px 0;border-bottom:1px solid #e4e4e7;color:#71717a;">Assignee</td>
        <td style="padding:6px 0;border-bottom:1px solid #e4e4e7;">{esc(str(ticket.get('assigned_to') or '—'))}</td></tr>
    <tr><td style="padding:6px 0;color:#71717a;">Customer</td>
        <td style="padding:6px 0;">{esc(cust)}</td></tr>
  </table>
  <p style="margin:0 0 6px;font-size:11px;text-transform:uppercase;letter-spacing:0.08em;color:#71717a;">Description</p>
  <div style="background:#fafafa;border:1px solid #e4e4e7;border-radius:8px;padding:12px;white-space:pre-wrap;">{desc_html}</div>
  <p style="margin:16px 0 6px;font-size:11px;text-transform:uppercase;letter-spacing:0.08em;color:#71717a;">Manager approvals</p>
  <div style="font-size:13px;color:#3f3f46;">{appr_html}</div>
  {note_block}
  <p style="margin-top:20px;"><a href="{esc(portal_link)}" style="color:#4f46e5;font-weight:600;">Open staff workspace →</a></p>
  <p style="font-size:11px;color:#a1a1aa;">Forwarded on behalf of your helpdesk team.</p>
</body></html>"""
    return subj, text_body, html_body


def _forward_ticket_section_text(ticket: dict, approval_rows) -> str:
    pub_id = str(ticket.get("public_ticket_id") or ticket.get("id") or "")
    cust = f"{ticket.get('customer_name') or ''} <{ticket.get('customer_email') or ''}>"
    appr_txt = _forward_approvals_summary_text(approval_rows)
    desc_plain = (ticket.get("description") or "—")[:12000]
    return "\n".join(
        [
            f"========== Ticket {pub_id} ==========",
            f"Subject: {ticket.get('subject')}",
            f"Status: {ticket.get('status')}",
            f"Priority: {ticket.get('priority')}",
            f"Assigned to: {ticket.get('assigned_to') or '—'}",
            f"Customer: {cust}",
            "",
            "Description:",
            desc_plain,
            "",
            "Manager approvals (summary):",
            appr_txt,
            "",
        ]
    )


def _forward_ticket_section_html(ticket: dict, approval_rows) -> str:
    esc = html_module.escape
    pub_id = str(ticket.get("public_ticket_id") or ticket.get("id") or "")
    cust = f"{ticket.get('customer_name') or ''} <{ticket.get('customer_email') or ''}>"
    appr_txt = _forward_approvals_summary_text(approval_rows)
    desc_html = esc((ticket.get("description") or "—")[:8000])
    appr_html = esc(appr_txt).replace("\n", "<br>\n")
    subj_esc = esc(ticket.get("subject") or "Support ticket")
    return f"""<div style="border:1px solid #e4e4e7;border-radius:12px;padding:16px;margin-bottom:20px;background:#fff;">
  <h2 style="font-size:15px;margin:0 0 12px;color:#18181b;">Ticket {esc(pub_id)} — {subj_esc}</h2>
  <table style="width:100%;max-width:640px;border-collapse:collapse;font-size:13px;margin-bottom:12px;">
    <tr><td style="padding:6px 0;border-bottom:1px solid #e4e4e7;color:#71717a;width:120px;">Ticket ID</td>
        <td style="padding:6px 0;border-bottom:1px solid #e4e4e7;font-weight:600;">{esc(pub_id)}</td></tr>
    <tr><td style="padding:6px 0;border-bottom:1px solid #e4e4e7;color:#71717a;">Status</td>
        <td style="padding:6px 0;border-bottom:1px solid #e4e4e7;">{esc(str(ticket.get('status') or ''))}</td></tr>
    <tr><td style="padding:6px 0;border-bottom:1px solid #e4e4e7;color:#71717a;">Priority</td>
        <td style="padding:6px 0;border-bottom:1px solid #e4e4e7;">{esc(str(ticket.get('priority') or ''))}</td></tr>
    <tr><td style="padding:6px 0;border-bottom:1px solid #e4e4e7;color:#71717a;">Assignee</td>
        <td style="padding:6px 0;border-bottom:1px solid #e4e4e7;">{esc(str(ticket.get('assigned_to') or '—'))}</td></tr>
    <tr><td style="padding:6px 0;color:#71717a;">Customer</td>
        <td style="padding:6px 0;">{esc(cust)}</td></tr>
  </table>
  <p style="margin:0 0 6px;font-size:11px;text-transform:uppercase;letter-spacing:0.08em;color:#71717a;">Description</p>
  <div style="background:#fafafa;border:1px solid #e4e4e7;border-radius:8px;padding:12px;white-space:pre-wrap;">{desc_html}</div>
  <p style="margin:12px 0 6px;font-size:11px;text-transform:uppercase;letter-spacing:0.08em;color:#71717a;">Manager approvals</p>
  <div style="font-size:13px;color:#3f3f46;">{appr_html}</div>
</div>"""


def _build_multi_forward_email_bodies(ticket_pairs, forwarder, note, portal_link):
    """ticket_pairs: list of (ticket_dict, approval_rows)."""
    esc = html_module.escape
    n = len(ticket_pairs)
    pub_ids = [str(dict(t).get("public_ticket_id") or dict(t).get("id") or "") for t, _ in ticket_pairs]
    id_summary = ", ".join(pub_ids[:12])
    if len(pub_ids) > 12:
        id_summary += f", … (+{len(pub_ids) - 12} more)"
    subj = f"Fwd: {n} tickets — {id_summary}"
    subj = subj[:900]
    text_parts = [
        f"Forwarded by: {forwarder}",
        "",
        f"This message contains {n} ticket(s): {', '.join(pub_ids)}",
        "",
    ]
    for tdict, approval_rows in ticket_pairs:
        text_parts.append(_forward_ticket_section_text(dict(tdict), approval_rows))
        text_parts.append("")
    if note:
        text_parts.extend(["Message from forwarder:", note, ""])
    text_parts.append(f"Workspace: {portal_link}")
    text_body = "\n".join(text_parts)
    note_block = (
        f'<div style="background:#eef2ff;border:1px solid #c7d2fe;border-radius:8px;padding:12px;margin:16px 0;white-space:pre-wrap;">'
        f"<strong>Note from forwarder</strong><br>{esc(note)}</div>"
        if note
        else ""
    )
    sections_html = "".join(
        _forward_ticket_section_html(dict(t), a) for t, a in ticket_pairs
    )
    html_body = f"""<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="font-family:Segoe UI,system-ui,sans-serif;font-size:14px;color:#27272a;line-height:1.55;margin:16px;">
  <div style="font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:#71717a;">Forwarded enterprise cases ({n})</div>
  <h1 style="font-size:18px;margin:8px 0 16px;">{n} tickets forwarded</h1>
  {sections_html}
  {note_block}
  <p style="margin-top:20px;"><a href="{esc(portal_link)}" style="color:#4f46e5;font-weight:600;">Open staff workspace →</a></p>
  <p style="font-size:11px;color:#a1a1aa;">Forwarded on behalf of your helpdesk team.</p>
</body></html>"""
    return subj, text_body, html_body


def save_ticket_uploaded_files(ticket_id, file_list):
    """Persist files under uploads/ticket_attachments/{ticket_id}/. Returns list of dicts for JSONB."""
    saved = []
    if not file_list:
        return saved
    tdir = os.path.join(UPLOAD_ROOT, str(ticket_id))
    os.makedirs(tdir, exist_ok=True)
    for f in file_list:
        if not f or not getattr(f, "filename", None):
            continue
        raw_name = os.path.basename(f.filename) or "file"
        safe = secure_filename(raw_name) or "file"
        uniq = secrets.token_hex(8)
        stored_name = f"{uniq}_{safe}"
        full_path = os.path.join(tdir, stored_name)
        f.save(full_path)
        rel = f"{ticket_id}/{stored_name}"
        mime, _ = mimetypes.guess_type(raw_name)
        saved.append(
            {
                "name": raw_name,
                "path": rel,
                "mime": mime or "application/octet-stream",
            }
        )
    return saved


def ensure_ticket_approvals_schema(cur):
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ticket_approvals (
            id SERIAL PRIMARY KEY,
            ticket_id INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
            requested_by VARCHAR(255) NOT NULL,
            manager_email VARCHAR(255) NOT NULL,
            cc_emails TEXT DEFAULT '',
            reason TEXT,
            message_to_manager TEXT,
            due_at TIMESTAMP,
            status VARCHAR(40) NOT NULL DEFAULT 'pending',
            manager_comment TEXT,
            decided_at TIMESTAMP,
            previous_ticket_status VARCHAR(255),
            secret_token VARCHAR(160) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    cur.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_ticket_approvals_token ON ticket_approvals (secret_token);"
    )


def _approval_json(row):
    d = dict(row)
    for k, v in list(d.items()):
        if hasattr(v, "isoformat"):
            d[k] = v.isoformat()
    d.pop("secret_token", None)
    return d


def _parse_approval_due_at(raw):
    if not raw or not str(raw).strip():
        return None
    s = str(raw).strip()
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo:
            dt = dt.replace(tzinfo=None)
        return dt
    except (TypeError, ValueError):
        return None


DEFAULT_PORTAL_SETTINGS = {
    "ticket": {
        "prefix": "TKT",
        "includeYear": True,
        "dateSegment": "year",
        "customDateSegment": "",
        "separator": "-",
        "padding": 4,
        "suffixRandom": False,
    },
    "sla": {
        "enabled": True,
        "priorities": [
            "Low",
            "Medium",
            "High",
            "Urgent",
            "Enterprise Critical",
        ],
        "responseHours": {
            "Low": 48,
            "Medium": 24,
            "High": 8,
            "Urgent": 4,
            "Enterprise Critical": 2,
        },
        "resolutionHours": {
            "Low": 168,
            "Medium": 72,
            "High": 48,
            "Urgent": 24,
            "Enterprise Critical": 8,
        },
        "defaultPriority": "Medium",
    },
    "assignment": {
        "mode": "off",
        "orderedUserNames": [],
        "lastAssignIndex": 0,
        "priorityRules": {},
        "lastAssignIndexByPriority": {},
    },
    "categories": [
        "Infrastructure",
        "Security",
        "Database",
        "Other",
    ],
    "defaultCategory": "Other",
}


def _normalize_ticket_categories(merged):
    """Ensure categories is a non-empty list of short strings."""
    default = DEFAULT_PORTAL_SETTINGS["categories"]
    cats = merged.get("categories")
    if not isinstance(cats, list):
        merged["categories"] = list(default)
        return merged
    cleaned = []
    for c in cats:
        s = str(c).strip()[:80]
        if s and s not in cleaned:
            cleaned.append(s)
    merged["categories"] = cleaned if cleaned else list(default)
    return merged


def _normalize_default_category(merged):
    cats = merged.get("categories")
    if not isinstance(cats, list) or not cats:
        return merged
    dc = merged.get("defaultCategory")
    if not isinstance(dc, str) or str(dc).strip() not in cats:
        merged["defaultCategory"] = (
            "Other" if "Other" in cats else cats[0]
        )
    else:
        merged["defaultCategory"] = str(dc).strip()[:80]
    return merged


def _normalize_sla_priority_maps(merged):
    """Ensure sla.priorities list drives response/resolution hour keys."""
    sla = merged.setdefault("sla", {})
    default_pri = DEFAULT_PORTAL_SETTINGS["sla"]["priorities"]
    pri = sla.get("priorities")
    if not isinstance(pri, list) or not pri:
        sla["priorities"] = list(default_pri)
        pri = sla["priorities"]
    else:
        cleaned = []
        for p in pri:
            s = str(p).strip()[:80]
            if s and s not in cleaned:
                cleaned.append(s)
        sla["priorities"] = cleaned if cleaned else list(default_pri)
        pri = sla["priorities"]
    rh = sla.setdefault("responseHours", {})
    res = sla.setdefault("resolutionHours", {})
    def_med_r = float(rh.get("Medium", 24))
    def_med_res = float(res.get("Medium", 72))
    for p in pri:
        try:
            if p not in rh:
                rh[p] = float(rh.get("Medium", def_med_r))
        except (TypeError, ValueError):
            rh[p] = 24.0
        try:
            if p not in res:
                res[p] = float(res.get("Medium", def_med_res))
        except (TypeError, ValueError):
            res[p] = 72.0
    for k in list(rh.keys()):
        if k not in pri:
            del rh[k]
    for k in list(res.keys()):
        if k not in pri:
            del res[k]
    if "enabled" not in sla:
        sla["enabled"] = True
    dp = sla.get("defaultPriority")
    if not isinstance(dp, str) or str(dp).strip() not in pri:
        sla["defaultPriority"] = "Medium" if "Medium" in pri else (pri[0] if pri else "Medium")
    else:
        sla["defaultPriority"] = str(dp).strip()[:80]
    return merged


def _normalize_assignment_block(merged):
    """Align priorityRules / lastAssignIndexByPriority with sla.priorities."""
    am = merged.setdefault(
        "assignment", copy.deepcopy(DEFAULT_PORTAL_SETTINGS["assignment"])
    )
    pri = (merged.get("sla") or {}).get("priorities") or []
    if not isinstance(pri, list):
        pri = list(DEFAULT_PORTAL_SETTINGS["sla"]["priorities"])
    raw_pr = am.get("priorityRules")
    if not isinstance(raw_pr, dict):
        raw_pr = {}
    new_pr = {}
    for p in pri:
        ps = str(p).strip()[:80]
        if not ps:
            continue
        slot = raw_pr.get(ps) or raw_pr.get(p) or {}
        if not isinstance(slot, dict):
            slot = {}
        ou = slot.get("orderedUserNames")
        if not isinstance(ou, list):
            ou = []
        names = [str(x).strip() for x in ou if str(x).strip()][:50]
        new_pr[ps] = {
            "enabled": bool(slot.get("enabled")),
            "orderedUserNames": names,
        }
    am["priorityRules"] = new_pr
    raw_idx = am.get("lastAssignIndexByPriority")
    if not isinstance(raw_idx, dict):
        raw_idx = {}
    new_idx = {}
    for p in new_pr:
        try:
            new_idx[p] = max(0, int(raw_idx.get(p, 0)))
        except (TypeError, ValueError):
            new_idx[p] = 0
    am["lastAssignIndexByPriority"] = new_idx
    return merged


def _finalize_portal_settings_dict(out):
    merged_sla = _normalize_sla_priority_maps(out)
    merged_cat = _normalize_ticket_categories(merged_sla)
    merged_dc = _normalize_default_category(merged_cat)
    return _normalize_assignment_block(merged_dc)


def merge_portal_settings(stored):
    out = copy.deepcopy(DEFAULT_PORTAL_SETTINGS)

    def _merge_done():
        et_src = (
            stored.get("emailTemplates") if isinstance(stored, dict) else None
        )
        out["emailTemplates"] = merge_stored_email_templates(
            default_email_templates_dict(), et_src
        )
        eb_src = (
            stored.get("emailBranding") if isinstance(stored, dict) else None
        )
        out["emailBranding"] = merge_stored_email_branding(
            default_email_branding(), eb_src
        )
        return _finalize_portal_settings_dict(out)

    if not stored:
        return _merge_done()
    if isinstance(stored, str):
        try:
            stored = json.loads(stored)
        except json.JSONDecodeError:
            return _merge_done()
    if not isinstance(stored, dict):
        return _merge_done()
    if "ticket" in stored and isinstance(stored["ticket"], dict):
        st = stored["ticket"]
        out["ticket"].update(st)
        if "dateSegment" not in st and "includeYear" in st:
            out["ticket"]["dateSegment"] = "year" if st.get("includeYear") else "none"
    if "sla" in stored and isinstance(stored["sla"], dict):
        for sk, sv in stored["sla"].items():
            if sk in ("responseHours", "resolutionHours") and isinstance(sv, dict):
                out["sla"].setdefault(sk, {}).update(sv)
            elif sk == "priorities" and isinstance(sv, list):
                out["sla"]["priorities"] = sv
            elif sk == "enabled":
                out["sla"]["enabled"] = bool(sv)
            elif sk in out["sla"] and isinstance(sv, dict):
                out["sla"][sk].update(sv)
            elif sk in out["sla"]:
                out["sla"][sk] = sv
    if "assignment" in stored and isinstance(stored["assignment"], dict):
        a = stored["assignment"]
        am = out.setdefault("assignment", copy.deepcopy(DEFAULT_PORTAL_SETTINGS["assignment"]))
        if "mode" in a:
            m = str(a.get("mode") or "off").lower()
            am["mode"] = m if m in ("off", "auto", "ordered") else "off"
        if "orderedUserNames" in a and isinstance(a["orderedUserNames"], list):
            am["orderedUserNames"] = [
                str(x).strip() for x in a["orderedUserNames"] if str(x).strip()
            ][:50]
        try:
            am["lastAssignIndex"] = max(0, int(a.get("lastAssignIndex", 0)))
        except (TypeError, ValueError):
            pass
        if isinstance(a.get("priorityRules"), dict):
            am["priorityRules"] = copy.deepcopy(a["priorityRules"])
        if isinstance(a.get("lastAssignIndexByPriority"), dict):
            cleaned_i = {}
            for k, v in a["lastAssignIndexByPriority"].items():
                ks = str(k).strip()[:80]
                if not ks:
                    continue
                try:
                    cleaned_i[ks] = max(0, int(v))
                except (TypeError, ValueError):
                    cleaned_i[ks] = 0
            am["lastAssignIndexByPriority"] = cleaned_i
    if "categories" in stored and isinstance(stored["categories"], list):
        cleaned_c = []
        for c in stored["categories"]:
            s = str(c).strip()[:80]
            if s and s not in cleaned_c:
                cleaned_c.append(s)
        out["categories"] = cleaned_c[:50]
    if "defaultCategory" in stored and isinstance(stored.get("defaultCategory"), str):
        out["defaultCategory"] = str(stored["defaultCategory"]).strip()[:80]
    return _merge_done()


def _status_is_closed_or_resolved(status):
    if not status:
        return False
    s = str(status).lower()
    return "resolved" in s or "closed" in s


def _customer_email_present(customer_email):
    """Require a non-empty requester email (with @) before resolved/closed transitions."""
    em = (customer_email or "").strip()
    return bool(em and "@" in em)


def _ticket_has_no_assignee(assigned_to):
    """NULL or empty/whitespace assigned_to counts as unassigned (matches UI 'Unassigned')."""
    if assigned_to is None:
        return True
    if isinstance(assigned_to, str):
        return not assigned_to.strip()
    return False


MIN_CLOSURE_CUSTOMER_NOTE_LEN = 3


def _closure_customer_note_from_data(data):
    """Customer-visible resolution text from JSON (update_status / assign_self)."""
    if not data:
        return ""
    return (data.get("customer_note") or data.get("resolution_note") or "").strip()


def _portal_base_url():
    env_base = (os.environ.get("PORTAL_PUBLIC_URL") or "").strip().rstrip("/")
    if env_base:
        return env_base
    try:
        return (request.url_root or "").rstrip("/")
    except RuntimeError:
        return ""


def _customer_ticket_view_url(portal_base, public_ticket_id):
    """HTTPS link to customer workspace; query param `t` pre-fills ticket lookup."""
    base = (portal_base or "").strip().rstrip("/")
    pid = str(public_ticket_id or "").strip()
    if not base or not pid:
        return ""
    return f"{base}/view-ticket.html?t={quote(pid, safe='')}"


def _staff_emails_for_notify(cur):
    ensure_user_schema(cur)
    cur.execute(
        """
        SELECT DISTINCT TRIM(email) AS em FROM users
        WHERE COALESCE(is_active, TRUE) = TRUE
          AND LOWER(TRIM(COALESCE(role, ''))) IN ('agent', 'manager')
          AND TRIM(COALESCE(email, '')) <> ''
        """
    )
    rows = cur.fetchall() or []
    out = []
    for r in rows:
        e = r[0] if r else None
        if e and "@" in e:
            out.append(e.strip())
    return out


def _branding_dict_for_email(merged_settings):
    b = (merged_settings or {}).get("emailBranding") or {}
    return {
        "companyName": resolve_template_brand_name(merged_settings),
        "logoUrl": (b.get("logoUrl") or "").strip()[:2000],
        "tagline": (b.get("tagline") or "").strip()[:200],
        "replyTo": (b.get("replyTo") or "").strip()[:254],
        "fromAddress": (b.get("fromAddress") or "").strip()[:254],
        "fromDisplayName": (b.get("fromDisplayName") or "").strip()[:120],
    }


def _ticket_mail_send_identity():
    """Portal outbound From / Reply-To for ticket-related SMTP (SMTP login still from .env)."""
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            ensure_portal_settings(cur)
            cur.execute("SELECT settings FROM portal_settings WHERE id = 1")
            row = cur.fetchone()
            merged = merge_portal_settings(row["settings"] if row else None)
            return outbound_identity_from_branding(_branding_dict_for_email(merged))
    finally:
        conn.close()


def _notify_staff_new_ticket_async(
    merged_settings,
    public_id,
    subject,
    priority,
    category,
    customer_name,
    customer_email,
    description,
    assigned_to_name,
    portal_base,
):
    def _run():
        tmpl = (merged_settings.get("emailTemplates") or {}).get("staff_new_ticket") or {}
        if not tmpl.get("enabled", True):
            return
        conn = get_db()
        try:
            with conn.cursor() as cur:
                staff = _staff_emails_for_notify(cur)
        finally:
            conn.close()
        if not staff:
            return
        preview = (description or "").strip().replace("\r\n", "\n")
        if len(preview) > 2000:
            preview = preview[:2000] + "…"
        ctx = {
            "ticket_id": public_id,
            "subject": subject or "—",
            "priority": priority or "—",
            "category": category or "—",
            "customer_name": customer_name or "Customer",
            "customer_email": customer_email or "—",
            "assigned_to": assigned_to_name or "Unassigned",
            "description_preview": preview or "—",
            "ticket_url": f"{portal_base}/agent-dashboard.html" if portal_base else "",
            "customer_portal_url": _customer_ticket_view_url(portal_base, public_id),
            **template_brand_placeholders(merged_settings),
        }
        subj = render_email_template(tmpl.get("subject"), ctx)[:200]
        body = render_email_template(tmpl.get("body"), ctx)
        bdict = _branding_dict_for_email(merged_settings)
        for em in staff:
            ok, err = send_branded_multipart_email([em], subj, body, bdict)
            if not ok:
                app.logger.warning("Staff new-ticket email to %s: %s", em, err)

    threading.Thread(target=_run, daemon=True).start()


def _notify_customer_ticket_assigned_from_payload_async(payload, portal_base):
    """
    Customer email for first assignment (same templates as ticket_action assign_self).
    payload keys: customer_email, customer_name, cc_emails, public_ticket_id,
    ticket_subject, etr, analysis, status, assignee_name, assignee_role_label, settings.
    """
    def _run():
        p = payload or {}
        settings = p.get("settings") or {}
        customer_portal_base = (portal_base or "").strip().rstrip("/")
        ce = (p.get("customer_email") or "").strip()
        if not ce or not (p.get("assignee_name") or "").strip():
            return
        tmpl = (settings.get("emailTemplates") or {}).get(
            "customer_ticket_assigned"
        ) or {}
        if tmpl.get("enabled", True) and (tmpl.get("subject") or "").strip():
            ctx = {
                "customer_name": p.get("customer_name") or "Customer",
                "subject": p.get("ticket_subject") or "Support ticket",
                "ticket_id": p.get("public_ticket_id"),
                "assignee_name": p.get("assignee_name") or "—",
                "assignee_role": p.get("assignee_role_label") or "Support staff",
                "expected_resolution": p.get("etr") or "—",
                "primary_analysis": p.get("analysis") or "—",
                "current_status": p.get("status") or "—",
                "ticket_url": _customer_ticket_view_url(
                    customer_portal_base, p.get("public_ticket_id")
                ),
                **template_brand_placeholders(settings),
            }
            subj = render_email_template(tmpl.get("subject"), ctx)[:200]
            body = render_email_template(tmpl.get("body"), ctx)
            if body.strip():
                ok, err = send_branded_multipart_email(
                    [ce],
                    subj,
                    body,
                    _branding_dict_for_email(settings),
                    cc_list=_parse_cc(p.get("cc_emails")),
                )
                if not ok:
                    app.logger.warning(
                        "Customer assignment email (on create) not sent: %s", err
                    )
                return
        bdict = _branding_dict_for_email(settings)
        ok, err = send_customer_acknowledgment_email(
            ce,
            p.get("customer_name"),
            p.get("public_ticket_id"),
            p.get("ticket_subject") or "Support ticket",
            p.get("etr"),
            p.get("analysis"),
            p.get("status"),
            p.get("cc_emails"),
            assignee_name=p.get("assignee_name"),
            assignee_role_label=p.get("assignee_role_label"),
            ticket_view_url=_customer_ticket_view_url(
                customer_portal_base, p.get("public_ticket_id")
            ),
            send_identity=outbound_identity_from_branding(bdict),
            branding_dict=bdict,
        )
        if not ok:
            app.logger.warning("Customer assignment email (on create) not sent: %s", err)

    threading.Thread(target=_run, daemon=True).start()


def _manager_approval_email_custom_content(
    ticket,
    ticket_id,
    agent_name,
    reason,
    message_to_manager,
    due_at,
    approval_id,
    token,
    base,
):
    """Returns (subject, text, html_or_none) from portal template, or (None, None, None) to use mail_service defaults."""
    from urllib.parse import quote as url_quote

    respond_page = f"{base}/approval-response.html"
    ticket_link = f"{base}/manager-dashboard.html"
    q = f"id={approval_id}&t={url_quote(token, safe='')}"
    link_approve = f"{respond_page}?{q}&a=approve"
    link_reject = f"{respond_page}?{q}&a=reject"
    link_rework = f"{respond_page}?{q}&a=rework"
    customer_label = (
        f"{ticket.get('customer_name') or 'Customer'} <{ticket.get('customer_email') or ''}>"
    )
    due_display = (
        due_at.strftime("%Y-%m-%d %H:%M")
        if hasattr(due_at, "strftime")
        else str(due_at or "—")
    )

    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            ensure_portal_settings(cur)
            cur.execute("SELECT settings FROM portal_settings WHERE id = 1")
            pr = cur.fetchone()
            merged = merge_portal_settings(pr["settings"] if pr else None)
    finally:
        conn.close()

    tmpl = (merged.get("emailTemplates") or {}).get("manager_approval_request") or {}
    if not tmpl.get("enabled", True):
        return None, None, None
    if not (tmpl.get("subject") or "").strip():
        return None, None, None

    ctx = {
        "ticket_id": str(ticket.get("public_ticket_id") or ticket_id),
        "subject": str(ticket.get("subject") or "Support ticket"),
        "customer_label": customer_label,
        "agent_name": agent_name,
        "reason": reason or "—",
        "message_to_manager": message_to_manager or "—",
        "priority": str(ticket.get("priority") or "Medium"),
        "due_display": due_display,
        "ticket_deep_link": ticket_link,
        "ticket_url": _customer_ticket_view_url(
            (base or "").strip().rstrip("/"), ticket.get("public_ticket_id")
        ),
        "link_approve": link_approve,
        "link_reject": link_reject,
        "link_rework": link_rework,
        **template_brand_placeholders(merged),
    }
    cs = render_email_template(tmpl.get("subject"), ctx)[:200]
    ct = render_email_template(tmpl.get("body"), ctx)
    ch = None
    if (tmpl.get("html") or "").strip():
        rend = render_email_template(tmpl.get("html"), ctx)
        if rend.strip():
            ch = rend
    return cs, ct, ch


def _notify_staff_ticket_reopened_async(ticket_row, reopen_note, portal_base):
    def _run():
        conn = get_db()
        try:
            with conn.cursor() as cur:
                ensure_portal_settings(cur)
                cur.execute("SELECT settings FROM portal_settings WHERE id = 1")
                row = cur.fetchone()
                merged = merge_portal_settings(row[0] if row else None)
                staff = _staff_emails_for_notify(cur)
        finally:
            conn.close()
        tmpl = (merged.get("emailTemplates") or {}).get("staff_ticket_reopened") or {}
        if not tmpl.get("enabled", True) or not staff:
            return
        ctx = {
            "ticket_id": ticket_row.get("public_ticket_id") or "—",
            "subject": ticket_row.get("subject") or "—",
            "customer_name": ticket_row.get("customer_name") or "Customer",
            "customer_email": ticket_row.get("customer_email") or "—",
            "reopen_note": (reopen_note or "").strip() or "—",
            "ticket_url": f"{portal_base}/agent-dashboard.html" if portal_base else "",
            "customer_portal_url": _customer_ticket_view_url(
                portal_base, ticket_row.get("public_ticket_id")
            ),
            **template_brand_placeholders(merged),
        }
        subj = render_email_template(tmpl.get("subject"), ctx)[:200]
        body = render_email_template(tmpl.get("body"), ctx)
        bdict = _branding_dict_for_email(merged)
        for em in staff:
            ok, err = send_branded_multipart_email([em], subj, body, bdict)
            if not ok:
                app.logger.warning("Staff reopen email to %s: %s", em, err)

    threading.Thread(target=_run, daemon=True).start()


def ensure_portal_settings(cur):
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS portal_settings (
            id INT PRIMARY KEY DEFAULT 1,
            CONSTRAINT portal_settings_single CHECK (id = 1),
            settings JSONB NOT NULL DEFAULT '{}'::jsonb,
            ticket_seq INT NOT NULL DEFAULT 999
        )
        """
    )
    cur.execute("SELECT 1 FROM portal_settings WHERE id = 1")
    if not cur.fetchone():
        cur.execute(
            "INSERT INTO portal_settings (id, settings, ticket_seq) VALUES (1, %s::jsonb, 999)",
            (json.dumps(DEFAULT_PORTAL_SETTINGS),),
        )


def ensure_tickets_table(cur):
    """Base tickets table (matches db_init.py). Required before ALTERs in ensure_ticket_sla_columns."""
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS tickets (
            id SERIAL PRIMARY KEY,
            public_ticket_id VARCHAR(50) UNIQUE NOT NULL,
            customer_name VARCHAR(255) NOT NULL,
            customer_email VARCHAR(255) NOT NULL,
            cc_emails TEXT,
            phone VARCHAR(50),
            priority VARCHAR(50),
            category VARCHAR(100),
            subject VARCHAR(255) NOT NULL,
            description TEXT NOT NULL,
            status VARCHAR(50) DEFAULT 'New',
            assigned_to VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            closed_at TIMESTAMP
        );
        """
    )


def ensure_ticket_sla_columns(cur):
    ensure_tickets_table(cur)
    cur.execute("ALTER TABLE tickets ADD COLUMN IF NOT EXISTS attachments_meta TEXT")
    cur.execute("ALTER TABLE tickets ADD COLUMN IF NOT EXISTS attachments_data JSONB DEFAULT '[]'::jsonb")
    cur.execute("ALTER TABLE tickets ADD COLUMN IF NOT EXISTS sla_first_response_due TIMESTAMP")
    cur.execute("ALTER TABLE tickets ADD COLUMN IF NOT EXISTS sla_resolution_due TIMESTAMP")
    cur.execute("ALTER TABLE tickets ADD COLUMN IF NOT EXISTS closed_at TIMESTAMP")
    cur.execute(
        "ALTER TABLE tickets ADD COLUMN IF NOT EXISTS expected_resolution VARCHAR(500)"
    )
    cur.execute("ALTER TABLE tickets ADD COLUMN IF NOT EXISTS primary_analysis TEXT")
    cur.execute(
        "ALTER TABLE tickets ADD COLUMN IF NOT EXISTS block_customer_reopen BOOLEAN DEFAULT FALSE"
    )
    cur.execute(
        "ALTER TABLE tickets ADD COLUMN IF NOT EXISTS project VARCHAR(200) DEFAULT ''"
    )


def ensure_ticket_replies_table(cur):
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ticket_replies (
            id SERIAL PRIMARY KEY,
            ticket_id INTEGER REFERENCES tickets(id),
            sender_type VARCHAR(50),
            sender_email VARCHAR(255),
            message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
    )


def _parse_local_ad_auto_unlock(data, description: str):
    """Return username to unlock if this is a validated local AD auto-unlock request."""
    flag = (str(data.get("local_ad_auto_unlock") or "")).strip().lower()
    if flag not in ("1", "true", "yes", "on"):
        return None
    user = (data.get("local_unlock_username") or "").strip()
    if not user or len(user) > 256:
        return None
    desc = description or ""
    if "--- Account unlock ---" not in desc:
        return None
    if "Local or cloud: Local" not in desc:
        return None
    return user


def _parse_local_ad_password_reset(data, description: str):
    """Return username to reset if this is a validated local AD auto password-reset request."""
    flag = (str(data.get("local_ad_auto_password_reset") or "")).strip().lower()
    if flag not in ("1", "true", "yes", "on"):
        return None
    user = (data.get("local_reset_username") or "").strip()
    if not user or len(user) > 256:
        return None
    desc = description or ""
    if "--- Password reset ---" not in desc:
        return None
    if "Local or cloud: Local" not in desc:
        return None
    return user


def _apply_local_ad_auto_unlock(cur, ticket_id: int, username: str, customer_notify=None):
    """
    Run AD unlock side effects. On success, sets ticket to Closed and returns customer_notify
    dict for sending email after commit; otherwise returns None.
    """
    ensure_ticket_replies_table(cur)
    host = (
        os.environ.get("AD_LDAP_HOST")
        or os.environ.get("LOCAL_AD_SERVER_IP")
        or "10.10.10.10"
    ).strip()
    if not ad_unlock_env_configured():
        cur.execute(
            "UPDATE tickets SET status = %s, assigned_to = NULL, updated_at = NOW() WHERE id = %s",
            ("🛠 Working on It", ticket_id),
        )
        cur.execute(
            "INSERT INTO ticket_replies (ticket_id, sender_type, sender_email, message) VALUES (%s, %s, %s, %s)",
            (
                ticket_id,
                "System",
                "",
                "[System] Local AD auto-unlock was requested, but AD bind is not configured on this server. "
                "IT should process the unlock manually using the details in the ticket description.",
            ),
        )
        return None
    ok, detail, outcome = try_unlock_local_ad_account(username)
    if ok and outcome in ("unlocked", "not_locked"):
        cur.execute(
            """
            UPDATE tickets
            SET status = %s, assigned_to = NULL, block_customer_reopen = TRUE,
                updated_at = NOW()
            WHERE id = %s
            """,
            ("🔒 Closed", ticket_id),
        )
        if outcome == "unlocked":
            sys_body = (
                f"[System] Local Active Directory lockout was cleared automatically (DC {host}). "
                f"Target account: {username}. Ticket closed; customer reopen is disabled. "
                f"Closure confirmation email queued for the requester."
            )
        else:
            sys_body = (
                f"[System] Active Directory reports no active sign-in lockout for {username} (DC {host}). "
                f"No directory unlock was required. Ticket closed; customer reopen is disabled. "
                f"Enterprise closure notice email queued for the requester."
            )
        cur.execute(
            "INSERT INTO ticket_replies (ticket_id, sender_type, sender_email, message) VALUES (%s, %s, %s, %s)",
            (ticket_id, "System", "", sys_body),
        )
        if customer_notify and (customer_notify.get("customer_email") or "").strip():
            merged = dict(customer_notify)
            merged["ad_outcome"] = outcome
            return merged
        return None
    cur.execute(
        "UPDATE tickets SET status = %s, assigned_to = NULL, updated_at = NOW() WHERE id = %s",
        ("🛠 Working on It", ticket_id),
    )
    cur.execute(
        "INSERT INTO ticket_replies (ticket_id, sender_type, sender_email, message) VALUES (%s, %s, %s, %s)",
        (
            ticket_id,
            "System",
            "",
            f"[System] Automatic AD unlock failed for '{username}': {detail}. Support will follow up.",
        ),
    )
    return None


def _apply_local_ad_password_reset(cur, ticket_id: int, username: str, new_password_plain: str, customer_notify=None):
    """
    Apply the requester's chosen password in AD, close ticket, queue confirmation email.
    Never writes the plain password to the database.
    """
    ensure_ticket_replies_table(cur)
    host = (
        os.environ.get("AD_LDAP_HOST")
        or os.environ.get("LOCAL_AD_SERVER_IP")
        or "10.10.10.10"
    ).strip()
    if not ad_unlock_env_configured():
        cur.execute(
            "UPDATE tickets SET status = %s, assigned_to = NULL, updated_at = NOW() WHERE id = %s",
            ("🛠 Working on It", ticket_id),
        )
        cur.execute(
            "INSERT INTO ticket_replies (ticket_id, sender_type, sender_email, message) VALUES (%s, %s, %s, %s)",
            (
                ticket_id,
                "System",
                "",
                "[System] Local AD password reset was requested, but AD bind is not configured on this server. "
                "IT should reset the password manually using the details in the ticket description.",
            ),
        )
        return None
    ok, detail = set_local_ad_account_password(username, new_password_plain)
    if ok:
        cur.execute(
            """
            UPDATE tickets
            SET status = %s, assigned_to = NULL, block_customer_reopen = TRUE,
                updated_at = NOW()
            WHERE id = %s
            """,
            ("🔒 Closed", ticket_id),
        )
        sys_body = (
            f"[System] The password you submitted was applied in Active Directory for {username} (DC {host}). "
            f"Sign-in should work immediately (no forced change-at-next-logon where directory policy allows). "
            f"Confirmation email queued for the requester. Ticket closed; customer reopen is disabled."
        )
        cur.execute(
            "INSERT INTO ticket_replies (ticket_id, sender_type, sender_email, message) VALUES (%s, %s, %s, %s)",
            (ticket_id, "System", "", sys_body),
        )
        if customer_notify and (customer_notify.get("customer_email") or "").strip():
            merged = dict(customer_notify)
            merged["customer_chose_password"] = True
            return merged
        return None
    cur.execute(
        "UPDATE tickets SET status = %s, assigned_to = NULL, updated_at = NOW() WHERE id = %s",
        ("🛠 Working on It", ticket_id),
    )
    cur.execute(
        "INSERT INTO ticket_replies (ticket_id, sender_type, sender_email, message) VALUES (%s, %s, %s, %s)",
        (
            ticket_id,
            "System",
            "",
            f"[System] Automatic AD password reset failed for '{username}': {detail}. Support will follow up.",
        ),
    )
    return None


def _ticket_id_date_segment(t):
    """none | year | ymd | custom — falls back to legacy includeYear."""
    seg = t.get("dateSegment")
    if seg in ("none", "year", "ymd", "custom"):
        return seg
    return "year" if t.get("includeYear", True) else "none"


def build_public_ticket_id(settings_merged, seq_int):
    t = settings_merged.get("ticket", {})
    if t.get("prefix") is None:
        prefix = "TKT"
    else:
        prefix = str(t.get("prefix", "")).strip()[:64]
    sep_raw = t.get("separator")
    sep = (str(sep_raw) if sep_raw is not None else "-")[:3]
    try:
        padding = int(t.get("padding") or 4)
    except (TypeError, ValueError):
        padding = 4
    padding = max(1, min(12, padding))
    now = datetime.now()
    date_seg = _ticket_id_date_segment(t)
    parts = []
    if prefix:
        parts.append(prefix)
    if date_seg == "year":
        parts.append(str(now.year))
    elif date_seg == "ymd":
        parts.append(now.strftime("%Y%m%d"))
    elif date_seg == "custom":
        cust = str(t.get("customDateSegment") or "").strip()[:16]
        if cust.isalnum():
            parts.append(cust)
    parts.append(str(int(seq_int)).zfill(padding))
    base = sep.join(parts)
    if t.get("suffixRandom"):
        base = base + sep + str(secrets.randbelow(9000) + 1000)
    return base


def sla_due_datetimes(settings_merged, priority, anchor_dt=None):
    sla = settings_merged.get("sla", {})
    if sla.get("enabled") is False:
        return None, None
    rh = sla.get("responseHours") or {}
    res_h_map = sla.get("resolutionHours") or {}
    p = priority or "Medium"
    try:
        resp = float(rh.get(p, rh.get("Medium", 24)))
    except (TypeError, ValueError):
        resp = 24.0
    try:
        resol = float(res_h_map.get(p, res_h_map.get("Medium", 72)))
    except (TypeError, ValueError):
        resol = 72.0
    if anchor_dt is not None:
        now = anchor_dt
        if getattr(now, "tzinfo", None):
            now = now.replace(tzinfo=None)
    else:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
    return now + timedelta(hours=resp), now + timedelta(hours=resol)


def _staff_creator_display_name(cur, staff_email):
    """Active Agent or Manager display name when staff logs a ticket for a customer."""
    em = (staff_email or "").strip()
    if not em:
        return None
    ensure_user_schema(cur)
    cur.execute(
        """
        SELECT name, role FROM users
        WHERE LOWER(TRIM(email)) = LOWER(TRIM(%s)) AND COALESCE(is_active, TRUE) = TRUE
        """,
        (em,),
    )
    row = cur.fetchone()
    if not row:
        return None
    role = str(_row_field(row, "role", 1) or "").strip()
    if role not in ("Agent", "Manager"):
        return None
    n = str(_row_field(row, "name", 0) or "").strip()
    return n if n else None


def _next_auto_assignee(cur, merged, ticket_priority=None):
    """
    Round-robin among active Agents and Managers. mode: off | auto (A–Z) | ordered (custom list, then rest).
    If assignment.priorityRules[priority].enabled with a non-empty ordered list, that list is used
    for that ticket priority with its own round-robin cursor (lastAssignIndexByPriority).
    """
    assign = copy.deepcopy(
        merged.get("assignment") or DEFAULT_PORTAL_SETTINGS["assignment"]
    )
    mode = str(assign.get("mode") or "off").lower()
    if mode not in ("auto", "ordered"):
        return None, assign
    cur.execute(
        """
        SELECT name FROM users
        WHERE LOWER(TRIM(COALESCE(role, ''))) IN ('agent', 'manager')
          AND COALESCE(is_active, TRUE) = TRUE
          AND name IS NOT NULL AND trim(name) != ''
        ORDER BY lower(trim(name))
        """
    )
    agents = [str(r["name"]).strip() for r in cur.fetchall()]
    if not agents:
        return None, assign
    agent_set = set(agents)

    sla = merged.get("sla") or {}
    pri_list = sla.get("priorities") or []
    if not isinstance(pri_list, list):
        pri_list = []
    raw_pri = str(ticket_priority or sla.get("defaultPriority") or "Medium").strip()[:80]
    pri = raw_pri if raw_pri in pri_list else str(sla.get("defaultPriority") or "Medium").strip()[:80]
    if pri not in pri_list and pri_list:
        pri = str(pri_list[0])

    pr_map = assign.get("priorityRules") or {}
    pr_slot = pr_map.get(pri) if isinstance(pr_map, dict) else None
    use_per_pri = False
    if isinstance(pr_slot, dict) and pr_slot.get("enabled"):
        ou = pr_slot.get("orderedUserNames")
        if isinstance(ou, list) and any(
            str(x).strip() in agent_set for x in ou
        ):
            use_per_pri = True

    pool = []
    if use_per_pri:
        seen = set()
        for n in pr_slot["orderedUserNames"]:
            n = str(n).strip()
            if n in agent_set and n not in seen:
                pool.append(n)
                seen.add(n)
        for a in sorted(agents, key=lambda x: x.lower()):
            if a not in seen:
                pool.append(a)
    elif mode == "auto":
        pool = sorted(agents, key=lambda x: x.lower())
    else:
        seen = set()
        for n in assign.get("orderedUserNames") or []:
            n = str(n).strip()
            if n in agent_set and n not in seen:
                pool.append(n)
                seen.add(n)
        for a in sorted(agents, key=lambda x: x.lower()):
            if a not in seen:
                pool.append(a)
    if not pool:
        return None, assign

    if use_per_pri:
        idxm = dict(assign.get("lastAssignIndexByPriority") or {})
        try:
            idx = int(idxm.get(pri, 0)) % len(pool)
        except (TypeError, ValueError):
            idx = 0
        chosen = pool[idx]
        idxm[pri] = idx + 1
        assign["lastAssignIndexByPriority"] = idxm
    else:
        try:
            idx = int(assign.get("lastAssignIndex") or 0) % len(pool)
        except (TypeError, ValueError):
            idx = 0
        chosen = pool[idx]
        assign["lastAssignIndex"] = idx + 1
    return chosen, assign


def _persist_assignment_state(cur, assignment_dict):
    cur.execute("SELECT settings FROM portal_settings WHERE id = 1")
    row = cur.fetchone()
    stored = merge_portal_settings(row["settings"] if row else None)
    stored["assignment"] = assignment_dict
    cur.execute(
        "UPDATE portal_settings SET settings = %s::jsonb WHERE id = 1",
        (json.dumps(stored),),
    )


@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/api/tickets', methods=['POST'])
def create_ticket():
    conn = get_db()
    prev_autocommit = conn.autocommit
    conn.autocommit = False
    public_id = None
    files = []
    ad_unlock_mail = None
    ad_password_reset_mail = None
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            ensure_portal_settings(cur)
            ensure_ticket_sla_columns(cur)

            ct = (request.content_type or "").lower()
            if "multipart/form-data" in ct:
                data = {
                    "name": request.form.get("name") or "Anonymous",
                    "email": (request.form.get("email") or "").strip(),
                    "cc": request.form.get("cc") or "",
                    "phone": request.form.get("phone") or "",
                    "priority": request.form.get("priority") or "Medium",
                    "category": request.form.get("category") or "Other",
                    "subject": (request.form.get("subject") or "").strip(),
                    "description": (request.form.get("description") or "").strip(),
                    "attachments_meta": request.form.get("attachments_meta") or "",
                    "local_ad_auto_unlock": request.form.get("local_ad_auto_unlock"),
                    "local_unlock_username": (request.form.get("local_unlock_username") or "").strip(),
                    "local_ad_auto_password_reset": request.form.get("local_ad_auto_password_reset"),
                    "local_reset_username": (request.form.get("local_reset_username") or "").strip(),
                    "local_reset_password": request.form.get("local_reset_password") or "",
                    "local_reset_password_confirm": request.form.get("local_reset_password_confirm") or "",
                    "cloud_suggested_password": request.form.get("cloud_suggested_password") or "",
                    "cloud_suggested_password_confirm": request.form.get(
                        "cloud_suggested_password_confirm"
                    )
                    or "",
                    "staff_email": (request.form.get("staff_email") or "").strip(),
                }
                files = list(request.files.getlist("files") or [])
            else:
                data = request.get_json(silent=True) or {}
                files = []

            email = (data.get("email") or "").strip()
            subject = (data.get("subject") or "").strip()
            description = (data.get("description") or "").strip()
            unlock_username = _parse_local_ad_auto_unlock(data, description)
            reset_username = (
                None if unlock_username else _parse_local_ad_password_reset(data, description)
            )
            local_reset_password_plain = None
            if reset_username:
                pwa = (data.get("local_reset_password") or "").strip()
                pwb = (data.get("local_reset_password_confirm") or "").strip()
                if not pwa or pwa != pwb:
                    conn.rollback()
                    conn.autocommit = prev_autocommit
                    conn.close()
                    return jsonify(
                        {
                            "success": False,
                            "message": "For local AD reset, enter and confirm your new password. Both fields must match.",
                        }
                    ), 400
                ok_pol, pol_err = validate_local_reset_password_policy(
                    pwa, data.get("name", ""), reset_username
                )
                if not ok_pol:
                    conn.rollback()
                    conn.autocommit = prev_autocommit
                    conn.close()
                    return jsonify({"success": False, "message": pol_err}), 400
                local_reset_password_plain = pwa
            description = _append_cloud_agent_only_password_block(description, data)
            if not email:
                conn.rollback()
                conn.autocommit = prev_autocommit
                conn.close()
                return jsonify({"success": False, "message": "Email is required."}), 400
            if not subject:
                conn.rollback()
                conn.autocommit = prev_autocommit
                conn.close()
                return jsonify({"success": False, "message": "Subject is required."}), 400
            if not description:
                conn.rollback()
                conn.autocommit = prev_autocommit
                conn.close()
                return jsonify({"success": False, "message": "Description is required."}), 400

            new_id = None
            public_id = None
            merged = None
            max_id_attempts = 48
            for _id_attempt in range(max_id_attempts):
                cur.execute(
                    "UPDATE portal_settings SET ticket_seq = ticket_seq + 1 WHERE id = 1 RETURNING ticket_seq, settings"
                )
                row = cur.fetchone()
                seq_num = int(row["ticket_seq"])
                merged = merge_portal_settings(row["settings"])
                public_id = build_public_ticket_id(merged, seq_num)
                sla_first, sla_res = sla_due_datetimes(
                    merged, data.get("priority", "Medium")
                )
                att_meta_initial = data.get("attachments_meta")
                cur.execute("SAVEPOINT sp_ticket_create_ins")
                try:
                    cur.execute(
                        """
                        INSERT INTO tickets (
                            public_ticket_id, customer_name, customer_email, cc_emails, phone,
                            priority, category, subject, description, status, attachments_meta,
                            sla_first_response_due, sla_resolution_due, attachments_data
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, '🆕 Submitted', %s, %s, %s, %s::jsonb)
                        RETURNING id;
                        """,
                        (
                            public_id,
                            data.get("name", "Anonymous"),
                            email,
                            data.get("cc", ""),
                            data.get("phone", ""),
                            data.get("priority", "Medium"),
                            data.get("category", "Other"),
                            subject,
                            description,
                            att_meta_initial,
                            sla_first,
                            sla_res,
                            json.dumps([]),
                        ),
                    )
                    new_id = cur.fetchone()["id"]
                    cur.execute("RELEASE SAVEPOINT sp_ticket_create_ins")
                    break
                except psycopg2.IntegrityError as ins_ex:
                    pcode = str(getattr(ins_ex, "pgcode", "") or "")
                    diag = getattr(ins_ex, "diag", None)
                    if diag is not None and getattr(diag, "sqlstate", None):
                        pcode = str(diag.sqlstate)
                    if pcode != "23505":
                        raise
                    cur.execute("ROLLBACK TO SAVEPOINT sp_ticket_create_ins")
            if new_id is None or public_id is None:
                conn.rollback()
                conn.autocommit = prev_autocommit
                conn.close()
                return jsonify(
                    {
                        "success": False,
                        "message": "Could not assign a unique ticket number after several attempts. Ask an admin to align ticket sequence in Ticket settings.",
                    }
                ), 409
            created_by_staff = False
            assignee_pick = None
            if not unlock_username and not reset_username:
                staff_creator = (data.get("staff_email") or "").strip()
                creator_name = _staff_creator_display_name(cur, staff_creator)
                if creator_name:
                    created_by_staff = True
                    assignee_pick = creator_name
                    cur.execute(
                        "UPDATE tickets SET assigned_to = %s WHERE id = %s",
                        (assignee_pick, new_id),
                    )
                else:
                    assignee_pick, new_assign = _next_auto_assignee(
                        cur, merged, data.get("priority", "Medium")
                    )
                    if assignee_pick:
                        cur.execute(
                            "UPDATE tickets SET assigned_to = %s WHERE id = %s",
                            (assignee_pick, new_id),
                        )
                        _persist_assignment_state(cur, new_assign)
            saved = save_ticket_uploaded_files(new_id, files)
            if saved:
                meta_csv = ",".join(s["name"] for s in saved)
                cur.execute(
                    "UPDATE tickets SET attachments_data = %s::jsonb, attachments_meta = %s WHERE id = %s",
                    (json.dumps(saved), meta_csv, new_id),
                )
            if unlock_username:
                ad_notify_ctx = {
                    "customer_email": email,
                    "customer_name": data.get("name", "Anonymous"),
                    "public_ticket_id": public_id,
                    "ticket_subject": subject,
                    "cc_emails": data.get("cc", ""),
                    "unlocked_username": unlock_username,
                }
                try:
                    ad_unlock_mail = _apply_local_ad_auto_unlock(
                        cur, new_id, unlock_username, ad_notify_ctx
                    )
                except Exception:
                    app.logger.exception(
                        "local_ad_auto_unlock failed after ticket insert (ticket id=%s)", new_id
                    )
                    ad_unlock_mail = None
                    try:
                        ensure_ticket_replies_table(cur)
                        cur.execute(
                            "UPDATE tickets SET status = %s, assigned_to = NULL, updated_at = NOW() WHERE id = %s",
                            ("🛠 Working on It", new_id),
                        )
                        cur.execute(
                            "INSERT INTO ticket_replies (ticket_id, sender_type, sender_email, message) VALUES (%s, %s, %s, %s)",
                            (
                                new_id,
                                "System",
                                "",
                                "[System] Your ticket was created, but the automatic unlock step failed on the server. "
                                "Support will unlock the account using the details you provided.",
                            ),
                        )
                    except Exception:
                        app.logger.exception(
                            "could not write fallback reply for AD unlock ticket id=%s", new_id
                        )
            elif reset_username:
                pwd_notify_ctx = {
                    "customer_email": email,
                    "customer_name": data.get("name", "Anonymous"),
                    "public_ticket_id": public_id,
                    "ticket_subject": subject,
                    "cc_emails": data.get("cc", ""),
                    "reset_account_username": reset_username,
                }
                try:
                    ad_password_reset_mail = _apply_local_ad_password_reset(
                        cur,
                        new_id,
                        reset_username,
                        local_reset_password_plain,
                        pwd_notify_ctx,
                    )
                except Exception:
                    app.logger.exception(
                        "local_ad_password_reset failed after ticket insert (ticket id=%s)", new_id
                    )
                    ad_password_reset_mail = None
                    try:
                        ensure_ticket_replies_table(cur)
                        cur.execute(
                            "UPDATE tickets SET status = %s, assigned_to = NULL, updated_at = NOW() WHERE id = %s",
                            ("🛠 Working on It", new_id),
                        )
                        cur.execute(
                            "INSERT INTO ticket_replies (ticket_id, sender_type, sender_email, message) VALUES (%s, %s, %s, %s)",
                            (
                                new_id,
                                "System",
                                "",
                                "[System] Your ticket was created, but the automatic password reset step failed on the server. "
                                "Support will reset the password using the details you provided.",
                            ),
                        )
                    except Exception:
                        app.logger.exception(
                            "could not write fallback reply for AD password reset ticket id=%s", new_id
                        )
            assign_ack_on_create = None
            cur.execute(
                """
                SELECT assigned_to, customer_email, cc_emails, public_ticket_id, subject,
                    customer_name, expected_resolution, primary_analysis, status
                FROM tickets WHERE id = %s
                """,
                (new_id,),
            )
            fin = cur.fetchone()
            if (
                fin
                and (fin.get("assigned_to") or "").strip()
                and (fin.get("customer_email") or "").strip()
            ):
                an = str(fin.get("assigned_to")).strip()
                assignee_role_label = "Support staff"
                cur.execute(
                    """
                    SELECT role FROM users
                    WHERE name = %s AND COALESCE(is_active, TRUE) = TRUE
                    ORDER BY id LIMIT 1
                    """,
                    (an,),
                )
                rr = cur.fetchone()
                if rr:
                    r0 = (rr.get("role") or "").strip()
                    if r0 == "Manager":
                        assignee_role_label = "Manager"
                    elif r0 == "Agent":
                        assignee_role_label = "Support agent"
                assign_ack_on_create = {
                    "customer_email": fin["customer_email"],
                    "customer_name": fin.get("customer_name") or "Customer",
                    "cc_emails": fin.get("cc_emails") or "",
                    "public_ticket_id": fin.get("public_ticket_id") or public_id,
                    "ticket_subject": fin.get("subject") or subject,
                    "etr": fin.get("expected_resolution"),
                    "analysis": fin.get("primary_analysis"),
                    "status": fin.get("status"),
                    "assignee_name": an,
                    "assignee_role_label": assignee_role_label,
                }
        conn.commit()
        portal_base = _portal_base_url()
        merged_snapshot = copy.deepcopy(merged)
        if not created_by_staff:
            _notify_staff_new_ticket_async(
                merged_snapshot,
                public_id,
                subject,
                data.get("priority", "Medium"),
                data.get("category", "Other"),
                data.get("name", "Anonymous"),
                email,
                description,
                assignee_pick,
                portal_base,
            )
        if assign_ack_on_create:
            assign_ack_on_create["settings"] = merged_snapshot
            _notify_customer_ticket_assigned_from_payload_async(
                assign_ack_on_create, portal_base
            )
    except Exception as ex:
        conn.rollback()
        conn.autocommit = prev_autocommit
        conn.close()
        app.logger.exception("create_ticket failed")
        msg = "Could not submit ticket. If this persists, contact support."
        if app.debug:
            msg += " " + str(ex)[:300]
        return jsonify({"success": False, "message": msg}), 500
    conn.autocommit = prev_autocommit
    conn.close()
    if ad_unlock_mail:

        def _send_ad_unlock_closed_email():
            p = ad_unlock_mail
            ok, err = send_customer_ad_unlock_closed_email(
                (p.get("customer_email") or "").strip(),
                p.get("customer_name"),
                p.get("public_ticket_id"),
                p.get("ticket_subject"),
                p.get("unlocked_username"),
                p.get("cc_emails"),
                ad_outcome=p.get("ad_outcome") or "unlocked",
            )
            if not ok:
                app.logger.warning("AD unlock closed-ticket email not sent: %s", err)

        threading.Thread(target=_send_ad_unlock_closed_email, daemon=True).start()
    if ad_password_reset_mail:

        def _send_ad_password_reset_email():
            p = ad_password_reset_mail
            ok, err = send_customer_ad_password_reset_closed_email(
                (p.get("customer_email") or "").strip(),
                p.get("customer_name"),
                p.get("public_ticket_id"),
                p.get("ticket_subject"),
                p.get("reset_account_username"),
                cc_raw=p.get("cc_emails"),
                customer_chose_password=p.get("customer_chose_password", True),
            )
            if not ok:
                app.logger.warning("AD password reset closed-ticket email not sent: %s", err)

        threading.Thread(target=_send_ad_password_reset_email, daemon=True).start()
    return jsonify({"success": True, "ticket_id": public_id})


@app.route("/api/tickets/<int:ticket_id>/attachments/<int:file_idx>", methods=["GET"])
def get_ticket_attachment(ticket_id, file_idx):
    staff_email = (request.args.get("staff_email") or "").strip()
    want_download = request.args.get("download", "").lower() in ("1", "true", "yes")
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            ensure_user_schema(cur)
            if not staff_actor_ok(cur, staff_email):
                return jsonify({"success": False, "message": "Staff sign-in required to open attachments."}), 403
            ensure_ticket_sla_columns(cur)
            cur.execute(
                "SELECT attachments_data FROM tickets WHERE id = %s",
                (ticket_id,),
            )
            row = cur.fetchone()
        if not row:
            return jsonify({"error": "Ticket not found"}), 404
        ad = row["attachments_data"]
        if isinstance(ad, str):
            try:
                ad = json.loads(ad)
            except json.JSONDecodeError:
                ad = []
        if not isinstance(ad, list) or file_idx < 0 or file_idx >= len(ad):
            return jsonify({"error": "Attachment not found"}), 404
        item = ad[file_idx]
        rel = (item.get("path") or "").replace("\\", "/").strip()
        path_parts = [p for p in rel.split("/") if p]
        if (
            len(path_parts) != 2
            or path_parts[0] != str(ticket_id)
            or ".." in path_parts[1]
        ):
            return jsonify({"error": "Invalid attachment path"}), 400
        full = os.path.normpath(os.path.join(UPLOAD_ROOT, path_parts[0], path_parts[1]))
        root_norm = os.path.normpath(UPLOAD_ROOT) + os.sep
        if not full.startswith(root_norm) or not os.path.isfile(full):
            return jsonify({"error": "File not found"}), 404
        mime = item.get("mime") or mimetypes.guess_type(item.get("name") or "")[0] or "application/octet-stream"
        dl_name = item.get("name") or "attachment"
        return send_file(
            full,
            mimetype=mime,
            as_attachment=want_download,
            download_name=dl_name if want_download else None,
        )
    finally:
        conn.close()


@app.route("/api/tickets/<int:ticket_id>/attachments", methods=["POST"])
def append_ticket_attachments(ticket_id):
    """Staff: append files to an existing ticket (multipart: staff_email, files)."""
    staff_email = (request.form.get("staff_email") or request.args.get("staff_email") or "").strip()
    files = list(request.files.getlist("files") or [])
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            ensure_user_schema(cur)
            if not staff_actor_ok(cur, staff_email):
                return jsonify({"success": False, "message": "Staff sign-in required."}), 403
            ensure_ticket_sla_columns(cur)
            cur.execute(
                "SELECT id, attachments_data FROM tickets WHERE id = %s",
                (ticket_id,),
            )
            row = cur.fetchone()
            if not row:
                return jsonify({"success": False, "message": "Ticket not found."}), 404
            ad = row["attachments_data"]
            if isinstance(ad, str):
                try:
                    ad = json.loads(ad)
                except json.JSONDecodeError:
                    ad = []
            if not isinstance(ad, list):
                ad = []
            new_saved = save_ticket_uploaded_files(ticket_id, files)
            if not new_saved:
                return jsonify({"success": False, "message": "No files received."}), 400
            merged = ad + new_saved
            meta_csv = ",".join(x["name"] for x in merged)
            cur.execute(
                "UPDATE tickets SET attachments_data = %s::jsonb, attachments_meta = %s WHERE id = %s",
                (json.dumps(merged), meta_csv, ticket_id),
            )
        return jsonify(
            {
                "success": True,
                "attachments_data": merged,
                "attachments_meta": meta_csv,
            }
        )
    finally:
        conn.close()


@app.route("/api/settings/tickets", methods=["GET"])
def get_ticket_settings():
    manager_email = (request.args.get("manager_email") or "").strip()
    staff_email = (request.args.get("staff_email") or "").strip()
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            ensure_user_schema(cur)
            allowed = False
            if manager_email and manager_actor_ok(cur, manager_email):
                allowed = True
            elif staff_email and staff_actor_ok(cur, staff_email):
                allowed = True
            if not allowed:
                return jsonify(
                    {"success": False, "message": "Manager or staff sign-in required."}
                ), 403
            ensure_portal_settings(cur)
            cur.execute("SELECT settings, ticket_seq FROM portal_settings WHERE id = 1")
            row = cur.fetchone()
        merged = merge_portal_settings(row["settings"] if row else None)
        return jsonify(
            {
                "success": True,
                "settings": merged,
                "ticket_seq": int(row["ticket_seq"]) if row else 999,
                "preview_next_id": build_public_ticket_id(
                    merged, int(row["ticket_seq"]) + 1 if row else 1000
                ),
                "emailTemplatesCatalog": templates_for_api_response(
                    merged.get("emailTemplates") or {}
                ),
            }
        )
    finally:
        conn.close()


@app.route("/api/settings/tickets", methods=["POST"])
def save_ticket_settings():
    data = request.json or {}
    manager_email = (data.get("manager_email") or "").strip()
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            ensure_user_schema(cur)
            if not manager_actor_ok(cur, manager_email):
                return jsonify(
                    {"success": False, "message": "Only managers can update ticket settings."}
                ), 403
            ensure_portal_settings(cur)
            cur.execute("SELECT settings, ticket_seq FROM portal_settings WHERE id = 1")
            row = cur.fetchone()
            current = merge_portal_settings(row["settings"] if row else None)
            ticket_in = data.get("ticket") or {}
            sla_in = data.get("sla") or {}
            if ticket_in:
                if "prefix" in ticket_in:
                    current["ticket"]["prefix"] = str(
                        ticket_in.get("prefix") or ""
                    ).strip()[:64]
                if "separator" in ticket_in:
                    s = str(ticket_in["separator"] if ticket_in["separator"] is not None else "-")[:3]
                    current["ticket"]["separator"] = s
                if "dateSegment" in ticket_in:
                    ds = str(ticket_in.get("dateSegment") or "year").lower()
                    if ds in ("none", "year", "ymd", "custom"):
                        current["ticket"]["dateSegment"] = ds
                        current["ticket"]["includeYear"] = ds == "year"
                elif "includeYear" in ticket_in:
                    iy = bool(ticket_in["includeYear"])
                    current["ticket"]["includeYear"] = iy
                    current["ticket"]["dateSegment"] = "year" if iy else "none"
                if "customDateSegment" in ticket_in:
                    c = str(ticket_in.get("customDateSegment") or "").strip()[:16]
                    current["ticket"]["customDateSegment"] = c if c.isalnum() else ""
                if "padding" in ticket_in:
                    try:
                        pad = int(ticket_in["padding"])
                        current["ticket"]["padding"] = max(1, min(12, pad))
                    except (TypeError, ValueError):
                        pass
                if "suffixRandom" in ticket_in:
                    current["ticket"]["suffixRandom"] = bool(ticket_in["suffixRandom"])
            if sla_in:
                if "enabled" in sla_in:
                    current["sla"]["enabled"] = bool(sla_in["enabled"])
                if isinstance(sla_in.get("priorities"), list):
                    current["sla"]["priorities"] = [
                        str(x).strip()[:80]
                        for x in sla_in["priorities"]
                        if str(x).strip()
                    ]
                if isinstance(sla_in.get("responseHours"), dict):
                    for k, v in sla_in["responseHours"].items():
                        try:
                            current["sla"]["responseHours"][k] = max(
                                0.25, min(8760, float(v))
                            )
                        except (TypeError, ValueError):
                            pass
                if isinstance(sla_in.get("resolutionHours"), dict):
                    for k, v in sla_in["resolutionHours"].items():
                        try:
                            current["sla"]["resolutionHours"][k] = max(
                                0.25, min(8760, float(v))
                            )
                        except (TypeError, ValueError):
                            pass
                if "defaultPriority" in sla_in:
                    dp = str(sla_in.get("defaultPriority") or "").strip()[:80]
                    if dp:
                        current["sla"]["defaultPriority"] = dp
            assign_in = data.get("assignment") or {}
            if assign_in:
                am = current.setdefault(
                    "assignment", copy.deepcopy(DEFAULT_PORTAL_SETTINGS["assignment"])
                )
                if "mode" in assign_in:
                    m = str(assign_in.get("mode") or "off").lower()
                    am["mode"] = m if m in ("off", "auto", "ordered") else "off"
                if isinstance(assign_in.get("orderedUserNames"), list):
                    am["orderedUserNames"] = [
                        str(x).strip() for x in assign_in["orderedUserNames"] if str(x).strip()
                    ][:50]
                if "lastAssignIndex" in assign_in:
                    try:
                        am["lastAssignIndex"] = max(0, int(assign_in["lastAssignIndex"]))
                    except (TypeError, ValueError):
                        pass
                if isinstance(assign_in.get("priorityRules"), dict):
                    pr_in = assign_in["priorityRules"]
                    merged_pr = copy.deepcopy(am.get("priorityRules") or {})
                    for pk, pv in pr_in.items():
                        ps = str(pk).strip()[:80]
                        if not ps or not isinstance(pv, dict):
                            continue
                        ou = pv.get("orderedUserNames")
                        names = (
                            [str(x).strip() for x in ou if str(x).strip()][:50]
                            if isinstance(ou, list)
                            else []
                        )
                        merged_pr[ps] = {
                            "enabled": bool(pv.get("enabled")),
                            "orderedUserNames": names,
                        }
                    am["priorityRules"] = merged_pr
                if isinstance(assign_in.get("lastAssignIndexByPriority"), dict):
                    idxm = dict(am.get("lastAssignIndexByPriority") or {})
                    for k, v in assign_in["lastAssignIndexByPriority"].items():
                        ks = str(k).strip()[:80]
                        if not ks:
                            continue
                        try:
                            idxm[ks] = max(0, int(v))
                        except (TypeError, ValueError):
                            pass
                    am["lastAssignIndexByPriority"] = idxm
            cats_in = data.get("categories")
            if cats_in is not None and isinstance(cats_in, list):
                cleaned_cats = [
                    str(x).strip()[:80]
                    for x in cats_in
                    if str(x).strip()
                ][:50]
                if cleaned_cats:
                    current["categories"] = cleaned_cats
            dc_in = data.get("defaultCategory")
            if dc_in is not None:
                dcv = str(dc_in).strip()[:80]
                if dcv:
                    current["defaultCategory"] = dcv
            et_in = data.get("emailTemplates")
            if isinstance(et_in, dict):
                current["emailTemplates"] = apply_email_template_updates(
                    current.get("emailTemplates")
                    or merge_stored_email_templates(
                        default_email_templates_dict(), None
                    ),
                    et_in,
                )
            eb_in = data.get("emailBranding")
            if isinstance(eb_in, dict):
                current["emailBranding"] = merge_stored_email_branding(
                    current.get("emailBranding") or default_email_branding(),
                    eb_in,
                )
            new_seq = row["ticket_seq"] if row else 999
            if "ticket_seq" in data and data["ticket_seq"] is not None:
                try:
                    new_seq = max(0, int(data["ticket_seq"]))
                except (TypeError, ValueError):
                    pass
            _normalize_sla_priority_maps(current)
            _normalize_ticket_categories(current)
            _normalize_default_category(current)
            cur.execute(
                "UPDATE portal_settings SET settings = %s::jsonb, ticket_seq = %s WHERE id = 1",
                (json.dumps(current), new_seq),
            )
        merged = merge_portal_settings(current)
        return jsonify(
            {
                "success": True,
                "settings": merged,
                "ticket_seq": new_seq,
                "preview_next_id": build_public_ticket_id(merged, new_seq + 1),
                "emailTemplatesCatalog": templates_for_api_response(
                    merged.get("emailTemplates") or {}
                ),
            }
        )
    finally:
        conn.close()

@app.route('/api/seed', methods=['POST'])
def seed_demo_data():
    return jsonify({"success": True, "message": "Demo data seeding disabled for production environment."})

@app.route('/api/profile/password', methods=['POST'])
def update_password():
    data = request.json
    email = data.get('email')
    old_pw = data.get('old_password')
    new_pw = data.get('new_password')
    if not email or not old_pw or not new_pw:
        return jsonify({"success": False, "message": "Email, current password, and new password are required."}), 400
    if len(new_pw) < 4:
        return jsonify({"success": False, "message": "New password must be at least 4 characters."}), 400

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM users WHERE email = %s AND password = %s", (email, old_pw))
        if not cur.fetchone():
            conn.close()
            return jsonify({"success": False, "message": "Incorrect current password."}), 401

        cur.execute("UPDATE users SET password = %s WHERE email = %s", (new_pw, email))
    conn.close()
    return jsonify({"success": True})


@app.route('/api/profile/settings', methods=['POST'])
def update_profile_settings():
    data = request.json
    email = data.get('email')
    name = (data.get('name') or '').strip()
    if not email or not name:
        return jsonify({"success": False, "message": "Email and display name are required."}), 400

    conn = get_db()
    with conn.cursor() as cur:
        ensure_user_schema(cur)
        cur.execute("UPDATE users SET name = %s WHERE email = %s RETURNING id", (name, email))
        row = cur.fetchone()
        if not row:
            conn.close()
            return jsonify({"success": False, "message": "User not found."}), 404
    conn.close()
    return jsonify({"success": True, "name": name})

@app.route('/api/tickets', methods=['GET'])
def get_tickets():
    queue_type = request.args.get('queue', 'unassigned') # 'unassigned' or 'myqueue'
    agent_id = (request.args.get('agent') or '').strip()
    sort_mode = (request.args.get('sort') or 'created').strip().lower()
    order_sql = "ORDER BY created_at DESC"
    if sort_mode == "sla_resolution":
        order_sql = "ORDER BY sla_resolution_due ASC NULLS LAST, created_at DESC"

    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        ensure_ticket_sla_columns(cur)
        if queue_type == 'unassigned':
            cur.execute(
                "SELECT * FROM tickets WHERE assigned_to IS NULL " + order_sql
            )
            records = cur.fetchall()
        elif queue_type == 'all':
            cur.execute("SELECT * FROM tickets " + order_sql)
            records = cur.fetchall()
        elif queue_type == 'escalated':
            cur.execute(
                "SELECT * FROM tickets WHERE priority IN ('High', 'Enterprise Critical', 'Urgent') "
                + order_sql
            )
            records = cur.fetchall()
        elif not agent_id:
            records = []
        else:
            cur.execute(
                "SELECT * FROM tickets WHERE assigned_to = %s " + order_sql,
                (agent_id,),
            )
            records = cur.fetchall()

    conn.close()
    return jsonify(records)


@app.route("/api/agent/customer-tickets", methods=["GET"])
def agent_customer_tickets():
    """Staff: search tickets by customer email (exact) or name/email substring."""
    staff_email = (request.args.get("staff_email") or "").strip()
    q = (request.args.get("q") or "").strip()
    if not staff_email or len(q) < 2:
        return jsonify({"success": False, "message": "staff_email and query (min 2 chars) required."}), 400
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            ensure_user_schema(cur)
            if not staff_actor_ok(cur, staff_email):
                return jsonify({"success": False, "message": "Staff sign-in required."}), 403
            ensure_ticket_sla_columns(cur)
            if "@" in q:
                cur.execute(
                    """
                    SELECT id, public_ticket_id, subject, status, priority, customer_name, customer_email,
                        assigned_to, created_at, updated_at
                    FROM tickets
                    WHERE LOWER(TRIM(customer_email)) = LOWER(TRIM(%s))
                    ORDER BY created_at DESC
                    LIMIT 200
                    """,
                    (q,),
                )
            else:
                like = f"%{q.lower()}%"
                cur.execute(
                    """
                    SELECT id, public_ticket_id, subject, status, priority, customer_name, customer_email,
                        assigned_to, created_at, updated_at
                    FROM tickets
                    WHERE LOWER(COALESCE(customer_name, '')) LIKE %s
                       OR LOWER(COALESCE(customer_email, '')) LIKE %s
                    ORDER BY created_at DESC
                    LIMIT 200
                    """,
                    (like, like),
                )
            rows = cur.fetchall()
        return jsonify({"success": True, "tickets": [dict(r) for r in rows]})
    finally:
        conn.close()


@app.route('/api/tickets/<int:ticket_id>/action', methods=['POST'])
def ticket_action(ticket_id):
    data = request.json
    action_type = data.get('action')
    agent_id = (data.get('agent') or '').strip() or 'Staff'
    reply_mail_payload = None
    assign_ack_mail = None
    closed_mail = None
    customer_portal_base = _portal_base_url().strip().rstrip("/")

    conn = get_db()
    with conn.cursor() as cur:
        ensure_ticket_sla_columns(cur)
        ensure_portal_settings(cur)
        cur.execute("SELECT settings FROM portal_settings WHERE id = 1")
        set_row = cur.fetchone()
        mail_tpl_snapshot = copy.deepcopy(
            merge_portal_settings(set_row[0] if set_row else None)
        )
        cur.execute("""
            CREATE TABLE IF NOT EXISTS ticket_replies (
                id SERIAL PRIMARY KEY,
                ticket_id INTEGER REFERENCES tickets(id),
                sender_type VARCHAR(50),
                sender_email VARCHAR(255),
                message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS ticket_audit_log (
                id SERIAL PRIMARY KEY,
                ticket_id INTEGER REFERENCES tickets(id),
                action TEXT,
                performed_by VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        if action_type == 'assign_self':
            cur.execute(
                """
                SELECT assigned_to, customer_email, cc_emails, public_ticket_id, subject,
                    customer_name, status
                FROM tickets WHERE id = %s
                """,
                (ticket_id,),
            )
            before = cur.fetchone()
            was_unassigned = bool(before and _ticket_has_no_assignee(before[0]))

            ex_r = (data.get("expected_resolution") or "").strip()[:500]
            prim = (data.get("primary_analysis") or "").strip()
            new_status = (data.get("status") or "").strip()

            if was_unassigned:
                st_val = new_status if new_status else "🛠 Working on It"
            else:
                st_val = new_status if new_status else (before[6] if before else "🛠 Working on It")

            closure_note_assign = None
            old_assign_status = (before[6] or "") if before else ""
            if _status_is_closed_or_resolved(st_val):
                ce = (before[1] or "").strip() if before else ""
                if not _customer_email_present(ce):
                    conn.close()
                    return jsonify(
                        {
                            "success": False,
                            "message": "Add a valid customer email on this ticket before setting status to resolved or closed.",
                        }
                    ), 400
                if not _status_is_closed_or_resolved(old_assign_status):
                    closure_note_assign = _closure_customer_note_from_data(data)
                    if len(closure_note_assign) < MIN_CLOSURE_CUSTOMER_NOTE_LEN:
                        conn.close()
                        return jsonify(
                            {
                                "success": False,
                                "message": "Add a customer-visible resolution note (at least 3 characters) before setting status to resolved or closed.",
                            }
                        ), 400

            set_parts = ["assigned_to = %s", "status = %s"]
            vals = [agent_id, st_val]
            if ex_r:
                set_parts.append("expected_resolution = %s")
                vals.append(ex_r)
            if prim:
                set_parts.append("primary_analysis = %s")
                vals.append(prim)
            set_parts.append("updated_at = NOW()")
            vals.append(ticket_id)
            cur.execute(
                "UPDATE tickets SET " + ", ".join(set_parts) + " WHERE id = %s",
                tuple(vals),
            )

            if closure_note_assign:
                ensure_ticket_replies_table(cur)
                cur.execute(
                    "INSERT INTO ticket_replies (ticket_id, sender_type, sender_email, message) VALUES (%s, %s, %s, %s)",
                    (ticket_id, "Agent", agent_id, closure_note_assign),
                )

            cust_em_assign = (before[1] or "").strip() if before else ""
            if was_unassigned and before and _customer_email_present(cust_em_assign):
                cur.execute(
                    """
                    SELECT status, expected_resolution, primary_analysis
                    FROM tickets WHERE id = %s
                    """,
                    (ticket_id,),
                )
                af = cur.fetchone()
                etr_d = (af[1] or ex_r or None) if af else None
                pan_d = (af[2] or prim or None) if af else None
                st_d = (af[0] if af else None) or st_val
                assignee_role_label = "Support staff"
                if agent_id:
                    cur.execute(
                        """
                        SELECT role FROM users
                        WHERE name = %s AND COALESCE(is_active, TRUE) = TRUE
                        ORDER BY id LIMIT 1
                        """,
                        (agent_id.strip(),),
                    )
                    rr = cur.fetchone()
                    if rr and rr[0] == "Manager":
                        assignee_role_label = "Manager"
                    elif rr and rr[0] == "Agent":
                        assignee_role_label = "Support agent"
                assign_ack_mail = {
                    "customer_email": cust_em_assign,
                    "customer_name": before[5],
                    "cc_emails": before[2],
                    "public_ticket_id": before[3],
                    "ticket_subject": before[4],
                    "etr": etr_d,
                    "analysis": pan_d,
                    "status": st_d,
                    "assignee_name": agent_id,
                    "assignee_role_label": assignee_role_label,
                    "settings": mail_tpl_snapshot,
                }

        elif action_type == 'update_status':
            new_status = data.get('status')
            cur.execute(
                """
                SELECT status, customer_email, cc_emails, public_ticket_id, subject, customer_name
                FROM tickets WHERE id = %s
                """,
                (ticket_id,),
            )
            prev = cur.fetchone()
            closure_note_upd = None
            old_s_for_note = (prev[0] or "") if prev else ""
            if new_status and _status_is_closed_or_resolved(new_status):
                cust_em = (prev[1] or "").strip() if prev else ""
                if not _customer_email_present(cust_em):
                    conn.close()
                    return jsonify(
                        {
                            "success": False,
                            "message": "Add a valid customer email on this ticket before marking it resolved or closed.",
                        }
                    ), 400
                if not _status_is_closed_or_resolved(old_s_for_note):
                    closure_note_upd = _closure_customer_note_from_data(data)
                    if len(closure_note_upd) < MIN_CLOSURE_CUSTOMER_NOTE_LEN:
                        conn.close()
                        return jsonify(
                            {
                                "success": False,
                                "message": "Add a customer-visible resolution note (at least 3 characters) before marking this ticket resolved or closed.",
                            }
                        ), 400
            cur.execute(
                "UPDATE tickets SET status = %s, updated_at = NOW() WHERE id = %s",
                (new_status, ticket_id),
            )
            if closure_note_upd:
                ensure_ticket_replies_table(cur)
                cur.execute(
                    "INSERT INTO ticket_replies (ticket_id, sender_type, sender_email, message) VALUES (%s, %s, %s, %s)",
                    (ticket_id, "Agent", agent_id, closure_note_upd),
                )
            if prev and new_status and prev[1]:
                old_s = prev[0] or ""
                if not _status_is_closed_or_resolved(
                    old_s
                ) and _status_is_closed_or_resolved(new_status):
                    closed_mail = {
                        "customer_email": prev[1],
                        "cc_emails": prev[2],
                        "public_ticket_id": prev[3],
                        "subject": prev[4],
                        "customer_name": prev[5],
                        "status": new_status,
                        "settings": mail_tpl_snapshot,
                    }

        elif action_type == 'add_reply':
            message = data.get('message')
            explicit_status = data.get('status', '⏳ Waiting for customer.')
            if _status_is_closed_or_resolved(explicit_status):
                msg_trim = (message or "").strip()
                if len(msg_trim) < MIN_CLOSURE_CUSTOMER_NOTE_LEN:
                    conn.close()
                    return jsonify(
                        {
                            "success": False,
                            "message": "When closing or resolving via reply, the reply text must be at least 3 characters (customer-visible resolution note).",
                        }
                    ), 400
                cur.execute(
                    "SELECT customer_email FROM tickets WHERE id = %s", (ticket_id,)
                )
                rem = cur.fetchone()
                ce = (rem[0] or "").strip() if rem else ""
                if not _customer_email_present(ce):
                    conn.close()
                    return jsonify(
                        {
                            "success": False,
                            "message": "Add a valid customer email on this ticket before marking it resolved or closed.",
                        }
                    ), 400
            cur.execute("INSERT INTO ticket_replies (ticket_id, sender_type, sender_email, message) VALUES (%s, 'Agent', %s, %s)", (ticket_id, agent_id, message))
            # Also update status
            cur.execute("UPDATE tickets SET status = %s, updated_at = NOW() WHERE id = %s", (explicit_status, ticket_id))
            cur.execute(
                "SELECT public_ticket_id, customer_email, cc_emails, subject FROM tickets WHERE id = %s",
                (ticket_id,),
            )
            row = cur.fetchone()
            if row and row[1]:
                reply_mail_payload = {
                    "public_ticket_id": row[0],
                    "customer_email": row[1],
                    "cc_emails": row[2],
                    "ticket_subject": row[3],
                    "message": message,
                    "agent": agent_id,
                    "settings": mail_tpl_snapshot,
                }

        elif action_type == 'add_work_log':
            # Store in audit log loosely for prototype
            worked_time = data.get('worked_time')
            note = data.get('note')
            explicit_status = data.get('status', None)
            if explicit_status and _status_is_closed_or_resolved(explicit_status):
                note_trim = (note or "").strip()
                if len(note_trim) < MIN_CLOSURE_CUSTOMER_NOTE_LEN:
                    conn.close()
                    return jsonify(
                        {
                            "success": False,
                            "message": "When resolving or closing from a work log, the note must be at least 3 characters (customer-visible resolution summary).",
                        }
                    ), 400
                cur.execute(
                    "SELECT customer_email FROM tickets WHERE id = %s",
                    (ticket_id,),
                )
                rce = cur.fetchone()
                ce = (rce[0] or "").strip() if rce else ""
                if not _customer_email_present(ce):
                    conn.close()
                    return jsonify(
                        {
                            "success": False,
                            "message": "Add a valid customer email on this ticket before setting status to resolved or closed.",
                        }
                    ), 400
            audit_msg = f"Logged {worked_time} | Note: {note}"
            cur.execute(
                "INSERT INTO ticket_audit_log (ticket_id, action, performed_by) VALUES (%s, %s, %s)",
                (ticket_id, audit_msg, agent_id),
            )
            if explicit_status:
                cur.execute(
                    "UPDATE tickets SET status = %s, updated_at = NOW() WHERE id = %s",
                    (explicit_status, ticket_id),
                )
                if _status_is_closed_or_resolved(explicit_status):
                    ensure_ticket_replies_table(cur)
                    cur.execute(
                        "INSERT INTO ticket_replies (ticket_id, sender_type, sender_email, message) VALUES (%s, %s, %s, %s)",
                        (ticket_id, "Agent", agent_id, (note or "").strip()),
                    )

    conn.close()

    if reply_mail_payload:

        def _notify_reply():
            p = reply_mail_payload
            settings = p.get("settings") or {}
            tmpl = (settings.get("emailTemplates") or {}).get("customer_ticket_reply") or {}
            if tmpl.get("enabled", True) and (tmpl.get("subject") or "").strip():
                ctx = {
                    "ticket_id": p["public_ticket_id"],
                    "subject": p["ticket_subject"] or "Support ticket",
                    "agent_name": p["agent"],
                    "reply_body": p["message"] or "—",
                    "ticket_url": _customer_ticket_view_url(
                        customer_portal_base, p["public_ticket_id"]
                    ),
                    **template_brand_placeholders(settings),
                }
                subj = render_email_template(tmpl.get("subject"), ctx)[:200]
                body = render_email_template(tmpl.get("body"), ctx)
                if body.strip():
                    ok, err = send_branded_multipart_email(
                        [p["customer_email"]],
                        subj,
                        body,
                        _branding_dict_for_email(settings),
                        cc_list=_parse_cc(p.get("cc_emails")),
                    )
                    if not ok:
                        app.logger.warning("Customer reply email not sent: %s", err)
                    return
            bdict = _branding_dict_for_email(settings)
            ok, err = send_agent_reply_email(
                p["customer_email"],
                p["public_ticket_id"],
                p["ticket_subject"] or "Support ticket",
                p["agent"],
                p["message"],
                p.get("cc_emails"),
                ticket_view_url=_customer_ticket_view_url(
                    customer_portal_base, p["public_ticket_id"]
                ),
                send_identity=outbound_identity_from_branding(bdict),
                branding_dict=bdict,
            )
            if not ok:
                app.logger.warning("Customer reply email not sent: %s", err)

        threading.Thread(target=_notify_reply, daemon=True).start()

    if assign_ack_mail:

        def _notify_assign_ack():
            try:
                p = assign_ack_mail
                settings = p.get("settings") or {}
                tmpl = (settings.get("emailTemplates") or {}).get(
                    "customer_ticket_assigned"
                ) or {}
                if tmpl.get("enabled", True) and (tmpl.get("subject") or "").strip():
                    ctx = {
                        "customer_name": p.get("customer_name") or "Customer",
                        "subject": p.get("ticket_subject") or "Support ticket",
                        "ticket_id": p.get("public_ticket_id"),
                        "assignee_name": p.get("assignee_name") or "—",
                        "assignee_role": p.get("assignee_role_label") or "Support staff",
                        "expected_resolution": p.get("etr") or "—",
                        "primary_analysis": p.get("analysis") or "—",
                        "current_status": p.get("status") or "—",
                        "ticket_url": _customer_ticket_view_url(
                            customer_portal_base, p.get("public_ticket_id")
                        ),
                        **template_brand_placeholders(settings),
                    }
                    subj = render_email_template(tmpl.get("subject"), ctx)[:200]
                    body = render_email_template(tmpl.get("body"), ctx)
                    if body.strip():
                        ok, err = send_branded_multipart_email(
                            [p["customer_email"]],
                            subj,
                            body,
                            _branding_dict_for_email(settings),
                            cc_list=_parse_cc(p.get("cc_emails")),
                        )
                        if not ok:
                            app.logger.warning(
                                "First-assignment customer email not sent: %s", err
                            )
                        return
                bdict = _branding_dict_for_email(settings)
                ok, err = send_customer_acknowledgment_email(
                    p["customer_email"],
                    p["customer_name"],
                    p["public_ticket_id"],
                    p["ticket_subject"] or "Support ticket",
                    p.get("etr"),
                    p.get("analysis"),
                    p.get("status"),
                    p.get("cc_emails"),
                    assignee_name=p.get("assignee_name"),
                    assignee_role_label=p.get("assignee_role_label"),
                    ticket_view_url=_customer_ticket_view_url(
                        customer_portal_base, p.get("public_ticket_id")
                    ),
                    send_identity=outbound_identity_from_branding(bdict),
                    branding_dict=bdict,
                )
                if not ok:
                    app.logger.warning(
                        "First-assignment customer email not sent: %s", err
                    )
            except Exception:
                app.logger.exception(
                    "First-assignment customer email thread failed (ticket_id=%s)",
                    ticket_id,
                )

        threading.Thread(target=_notify_assign_ack, daemon=True).start()

    if closed_mail:

        def _notify_closed():
            p = closed_mail
            settings = p.get("settings") or {}
            tmpl = (settings.get("emailTemplates") or {}).get(
                "customer_ticket_closed"
            ) or {}
            if not tmpl.get("enabled", True):
                return
            ctx = {
                "customer_name": p.get("customer_name") or "Customer",
                "ticket_id": p.get("public_ticket_id"),
                "subject": p.get("subject") or "—",
                "status": p.get("status") or "—",
                "ticket_url": _customer_ticket_view_url(
                    customer_portal_base, p.get("public_ticket_id")
                ),
                **template_brand_placeholders(settings),
            }
            subj = render_email_template(tmpl.get("subject"), ctx)[:200]
            body = render_email_template(tmpl.get("body"), ctx)
            if not body.strip():
                return
            ok, err = send_branded_multipart_email(
                [p["customer_email"]],
                subj,
                body,
                _branding_dict_for_email(settings),
                cc_list=_parse_cc(p.get("cc_emails")),
            )
            if not ok:
                app.logger.warning("Customer closed-ticket email not sent: %s", err)

        threading.Thread(target=_notify_closed, daemon=True).start()

    return jsonify({"success": True})


def _db_table_exists(cur, table_name):
    cur.execute(
        """
        SELECT EXISTS (
            SELECT FROM information_schema.tables
            WHERE table_schema = 'public' AND table_name = %s
        )
        """,
        (table_name,),
    )
    row = cur.fetchone()
    return bool(row and row[0])


def _delete_all_ticket_related_rows(cur):
    """
    Delete every row from ticket-related tables (safe order for FKs without CASCADE).
    """
    ensure_ticket_approvals_schema(cur)
    ensure_ticket_replies_table(cur)
    ensure_ticket_sla_columns(cur)
    if _db_table_exists(cur, "ticket_audit_log"):
        cur.execute("DELETE FROM ticket_audit_log")
    if _db_table_exists(cur, "ticket_attachments"):
        cur.execute("DELETE FROM ticket_attachments")
    cur.execute("DELETE FROM ticket_approvals")
    cur.execute("DELETE FROM ticket_replies")
    cur.execute("DELETE FROM tickets")


def _reset_portal_settings_to_defaults(cur):
    ensure_portal_settings(cur)
    cur.execute(
        "UPDATE portal_settings SET settings = %s::jsonb, ticket_seq = 999 WHERE id = 1",
        (json.dumps(DEFAULT_PORTAL_SETTINGS),),
    )


@app.route("/api/admin/purge-all-tickets", methods=["POST"])
def purge_all_tickets():
    """
    Permanently delete every ticket (all statuses) and related rows.
    Resets ticket_seq only (keeps existing portal JSON settings such as branding).
    Removes ticket attachment folders under UPLOAD_ROOT.
    """
    data = request.get_json(silent=True) or {}
    manager_email = (data.get("manager_email") or "").strip()
    confirm = (data.get("confirm") or "").strip()
    if confirm != "DELETE_ALL_TICKETS":
        return jsonify(
            {
                "success": False,
                "message": "Type the confirmation phrase exactly: DELETE_ALL_TICKETS",
            }
        ), 400

    conn = get_db()
    deleted = 0
    try:
        with conn.cursor() as cur:
            ensure_user_schema(cur)
            if not manager_actor_ok(cur, manager_email):
                return jsonify(
                    {"success": False, "message": "Manager access required."}
                ), 403
            cur.execute("SELECT COUNT(*) FROM tickets")
            deleted = int((cur.fetchone() or [0])[0] or 0)
            _delete_all_ticket_related_rows(cur)
            ensure_portal_settings(cur)
            cur.execute("UPDATE portal_settings SET ticket_seq = 999 WHERE id = 1")
    finally:
        conn.close()

    root = os.path.normpath(UPLOAD_ROOT)
    if os.path.isdir(root):
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if name.isdigit() and os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)

    app.logger.warning(
        "All tickets purged by manager %s (%s rows).", manager_email, deleted
    )
    return jsonify(
        {
            "success": True,
            "message": f"Removed {deleted} ticket(s). Attachment folders under ticket IDs were cleared.",
            "deleted_count": deleted,
        }
    )


@app.route("/api/admin/purge-full-database", methods=["POST"])
def purge_full_database():
    """
    Remove all application data: tickets + replies + approvals + audit (+ optional
    ticket_attachments), reset portal_settings to defaults, clear ticket upload dirs.

    Optional: delete all rows from users when remove_users=true and users_confirm
    is exactly DELETE_ALL_USERS (no one can sign in until accounts are recreated).
    """
    data = request.get_json(silent=True) or {}
    manager_email = (data.get("manager_email") or "").strip()
    confirm = (data.get("confirm") or "").strip()
    remove_users = bool(data.get("remove_users"))
    users_confirm = (data.get("users_confirm") or "").strip()

    if confirm != "PURGE_ALL_DATABASE_DATA":
        return jsonify(
            {
                "success": False,
                "message": "Type the confirmation phrase exactly: PURGE_ALL_DATABASE_DATA",
            }
        ), 400
    if remove_users and users_confirm != "DELETE_ALL_USERS":
        return jsonify(
            {
                "success": False,
                "message": "To remove staff accounts, send remove_users: true and users_confirm exactly: DELETE_ALL_USERS",
            }
        ), 400

    conn = get_db()
    ticket_count = 0
    user_count = 0
    users_deleted = 0
    try:
        with conn.cursor() as cur:
            ensure_user_schema(cur)
            if not manager_actor_ok(cur, manager_email):
                return jsonify(
                    {"success": False, "message": "Manager access required."}
                ), 403
            cur.execute("SELECT COUNT(*) FROM tickets")
            ticket_count = int((cur.fetchone() or [0])[0] or 0)
            _delete_all_ticket_related_rows(cur)
            _reset_portal_settings_to_defaults(cur)
            if remove_users:
                cur.execute("SELECT COUNT(*) FROM users")
                user_count = int((cur.fetchone() or [0])[0] or 0)
                cur.execute("DELETE FROM users")
                users_deleted = cur.rowcount or 0
    finally:
        conn.close()

    root = os.path.normpath(UPLOAD_ROOT)
    if os.path.isdir(root):
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if name.isdigit() and os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)

    app.logger.warning(
        "Full database purge by manager %s (tickets=%s, users_removed=%s).",
        manager_email,
        ticket_count,
        users_deleted,
    )
    msg = (
        f"Removed {ticket_count} ticket(s), reset portal settings to defaults, and cleared ticket files."
    )
    if remove_users:
        msg += f" Deleted {users_deleted} user account(s). You must recreate staff logins."
    return jsonify(
        {
            "success": True,
            "message": msg,
            "deleted_tickets": ticket_count,
            "deleted_users": users_deleted if remove_users else 0,
        }
    )


TICKET_CSV_COLUMNS = [
    "ticket_number",
    "project",
    "created_date",
    "resolved_date",
    "customer_name",
    "email",
    "cc",
    "category",
    "priority",
    "status",
    "subject",
    "description",
    "assigned_staff",
]

IMPORT_CSV_MAX_ROWS = 5000
IMPORT_CSV_MAX_BYTES = 12 * 1024 * 1024


def _normalize_ticket_csv_key(raw):
    if raw is None:
        return ""
    s = str(raw).strip().lower().replace("\ufeff", "")
    s = re.sub(r"[\s\-]+", "_", s)
    s = re.sub(r"[^a-z0-9_]", "", s)
    aliases = {
        "ticket_number": "ticket_number",
        "public_ticket_id": "ticket_number",
        "ticket_id": "ticket_number",
        "created_at": "created_date",
        "date_created": "created_date",
        "resolved_at": "resolved_date",
        "closed_at": "resolved_date",
        "date_resolved": "resolved_date",
        "resolution_date": "resolved_date",
        "customer_email": "email",
        "requester_email": "email",
        "name": "customer_name",
        "requester_name": "customer_name",
        "customer": "customer_name",
        "assigned_to": "assigned_staff",
        "assignee": "assigned_staff",
        "staff": "assigned_staff",
        "program": "project",
        "project_code": "project",
        "project_name": "project",
        "client_project": "project",
    }
    return aliases.get(s, s)


def _canonical_ticket_csv_row(dict_row):
    out = {k: "" for k in TICKET_CSV_COLUMNS}
    for k, v in (dict_row or {}).items():
        ck = _normalize_ticket_csv_key(k)
        if ck in TICKET_CSV_COLUMNS:
            out[ck] = ("" if v is None else str(v)).strip()
    return out


def _parse_import_csv_datetime(val):
    if val is None:
        return None
    s = str(val).strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo:
            dt = dt.replace(tzinfo=None)
        return dt
    except (TypeError, ValueError):
        pass
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",
        "%m/%d/%Y",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y",
    ):
        try:
            return datetime.strptime(s, fmt)
        except (TypeError, ValueError):
            continue
    return None


def _normalize_ticket_status_for_import(raw):
    s = (raw or "").strip()
    if not s:
        return "🆕 Submitted"
    if s in (
        "🆕 Submitted",
        "👀 Under Review",
        "🛠 Working on It",
        "⏳ Pending Manager Approval",
        "⏳ Waiting for customer.",
        "✅ Resolved",
        "🔁 Reopened",
        "🔒 Closed",
        "❌ Approval declined",
        "🔄 Approval rework requested",
    ):
        return s
    sl = s.lower()
    if "approval declined" in sl or sl == "declined":
        return "❌ Approval declined"
    if "rework" in sl and "approval" in sl:
        return "🔄 Approval rework requested"
    if "pending" in sl and "manager" in sl and "approval" in sl:
        return "⏳ Pending Manager Approval"
    if "reopened" in sl or "re-opened" in sl:
        return "🔁 Reopened"
    if "closed" in sl:
        return "🔒 Closed"
    if "resolved" in sl or sl in ("done", "complete", "completed"):
        return "✅ Resolved"
    if "waiting" in sl and "customer" in sl:
        return "⏳ Waiting for customer."
    if "working" in sl or "in progress" in sl or sl in ("wip", "active"):
        return "🛠 Working on It"
    if "review" in sl or sl in ("under_review", "under review"):
        return "👀 Under Review"
    if sl in ("new", "submitted", "open", "ticket"):
        return "🆕 Submitted"
    return s[:80]


def _export_resolved_datetime_for_csv(row):
    st = (row.get("status") or "").lower()
    if "resolved" not in st and "closed" not in st:
        return None
    ca = row.get("closed_at")
    if ca:
        if hasattr(ca, "replace") and not hasattr(ca, "hour"):
            return datetime.combine(ca, datetime.min.time())
        return ca
    ua = row.get("updated_at")
    if ua and hasattr(ua, "replace"):
        return ua
    return None


def _format_csv_datetime(val):
    if not val:
        return ""
    if hasattr(val, "strftime"):
        if hasattr(val, "hour"):
            return val.strftime("%Y-%m-%d %H:%M:%S")
        return val.strftime("%Y-%m-%d")
    return str(val)[:32]


def _sanitize_csv_public_ticket_id(raw):
    """Optional import: explicit public_ticket_id (max 50, DB column width)."""
    s = (raw or "").strip()
    if not s:
        return ""
    s = s[:50]
    if not re.match(r"^[\w.\-\s\/#+]+$", s, re.UNICODE):
        raise ValueError(
            "ticket_number: up to 50 chars — letters, digits, spaces, and . - _ / # + only"
        )
    return s


def _insert_ticket_from_import_row(cur, merged, rec):
    """Allocate public_ticket_id (or use CSV ticket_number when set), insert ticket; no emails."""
    email = (rec.get("email") or "").strip()
    subject = (rec.get("subject") or "").strip()
    description = (rec.get("description") or "").strip()
    if not email or "@" not in email:
        raise ValueError("valid email is required")
    if not subject:
        raise ValueError("subject is required")
    if not description:
        raise ValueError("description is required")

    created_raw = (rec.get("created_date") or "").strip()
    created_dt = _parse_import_csv_datetime(created_raw) or datetime.now()
    status = _normalize_ticket_status_for_import(rec.get("status"))
    resolved_raw = (rec.get("resolved_date") or "").strip()
    resolved_dt = _parse_import_csv_datetime(resolved_raw)
    if not _status_is_closed_or_resolved(status):
        resolved_dt = None
    elif not resolved_dt:
        resolved_dt = created_dt

    customer_name = (rec.get("customer_name") or "").strip() or "Customer"
    cc = (rec.get("cc") or "").strip()
    category = (rec.get("category") or "").strip() or "Other"
    priority = (rec.get("priority") or "").strip() or "Medium"
    assigned = (rec.get("assigned_staff") or "").strip() or None
    project = (rec.get("project") or "").strip()[:200]

    sla_first, sla_res = sla_due_datetimes(merged, priority, anchor_dt=created_dt)

    custom_pub = _sanitize_csv_public_ticket_id(rec.get("ticket_number") or "")

    def _do_insert(public_id):
        cur.execute(
            """
            INSERT INTO tickets (
                public_ticket_id, customer_name, customer_email, cc_emails, phone,
                priority, category, subject, description, status, attachments_meta,
                sla_first_response_due, sla_resolution_due, attachments_data,
                assigned_to, created_at, updated_at, closed_at, project
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s)
            RETURNING id;
            """,
            (
                public_id,
                customer_name,
                email,
                cc,
                "",
                priority[:50],
                category[:100],
                subject[:255],
                description,
                status[:80],
                "",
                sla_first,
                sla_res,
                json.dumps([]),
                assigned,
                created_dt,
                resolved_dt or created_dt,
                resolved_dt,
                project,
            ),
        )
        return cur.fetchone()["id"]

    new_id = None
    public_id = None

    if custom_pub:
        cur.execute("SAVEPOINT sp_csv_imp")
        try:
            new_id = _do_insert(custom_pub)
            public_id = custom_pub
            cur.execute("RELEASE SAVEPOINT sp_csv_imp")
        except psycopg2.IntegrityError as ins_ex:
            cur.execute("ROLLBACK TO SAVEPOINT sp_csv_imp")
            diag = getattr(ins_ex, "diag", None)
            cname = getattr(diag, "constraint_name", "") or ""
            if "public_ticket_id" in str(cname).lower() or "unique" in str(ins_ex).lower():
                raise ValueError(
                    f"ticket_number '{custom_pub}' is already used — leave blank to auto-assign"
                ) from ins_ex
            raise
    else:
        max_id_attempts = 48
        for _ in range(max_id_attempts):
            cur.execute(
                "UPDATE portal_settings SET ticket_seq = ticket_seq + 1 WHERE id = 1 RETURNING ticket_seq, settings"
            )
            row = cur.fetchone()
            seq_num = int(row["ticket_seq"])
            merged_row = merge_portal_settings(row["settings"])
            public_id = build_public_ticket_id(merged_row, seq_num)
            cur.execute("SAVEPOINT sp_csv_imp")
            try:
                new_id = _do_insert(public_id)
                cur.execute("RELEASE SAVEPOINT sp_csv_imp")
                break
            except psycopg2.IntegrityError as ins_ex:
                pcode = str(getattr(ins_ex, "pgcode", "") or "")
                diag = getattr(ins_ex, "diag", None)
                if diag is not None and getattr(diag, "sqlstate", None):
                    pcode = str(diag.sqlstate)
                if pcode != "23505":
                    raise
                cur.execute("ROLLBACK TO SAVEPOINT sp_csv_imp")
        if new_id is None:
            raise RuntimeError("could not allocate a unique ticket number")
    return new_id, public_id


def _tickets_csv_response(rows_dicts, filename):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(TICKET_CSV_COLUMNS)
    for r in rows_dicts:
        w.writerow([(r.get(c) or "") for c in TICKET_CSV_COLUMNS])
    payload = "\ufeff" + buf.getvalue()
    return Response(
        payload.encode("utf-8"),
        mimetype="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


@app.route("/api/admin/tickets/import-csv-template", methods=["GET"])
def download_ticket_import_csv_template():
    manager_email = (request.args.get("manager_email") or "").strip()
    conn = get_db()
    try:
        with conn.cursor() as cur:
            ensure_user_schema(cur)
            if not manager_actor_ok(cur, manager_email):
                return jsonify(
                    {"success": False, "message": "Manager access required."}
                ), 403
    finally:
        conn.close()
    sample_open = {
        "ticket_number": "",
        "project": "MIGRATION",
        "created_date": "2024-06-01 09:00:00",
        "resolved_date": "",
        "customer_name": "Jane Customer",
        "email": "jane@example.com",
        "cc": "cc1@example.com",
        "category": "Other",
        "priority": "Medium",
        "status": "New",
        "subject": "Sample imported ticket (open)",
        "description": "Set project for reporting. Leave ticket_number blank to auto-issue the next public ID.",
        "assigned_staff": "",
    }
    sample_closed = {
        "ticket_number": "LEGACY-4421",
        "project": "INFRA",
        "created_date": "2024-05-15 14:00:00",
        "resolved_date": "2024-05-16 10:30:00",
        "customer_name": "John Customer",
        "email": "john@example.com",
        "cc": "",
        "category": "Infrastructure",
        "priority": "High",
        "status": "Resolved",
        "subject": "Sample closed ticket",
        "description": "Optional: put an existing public ticket id in ticket_number (must be unique).",
        "assigned_staff": "Support Agent",
    }
    return _tickets_csv_response([sample_open, sample_closed], "ticket_import_template.csv")


@app.route("/api/admin/tickets/export-csv", methods=["GET"])
def export_tickets_csv():
    manager_email = (request.args.get("manager_email") or "").strip()
    db_rows = []
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            ensure_user_schema(cur)
            if not manager_actor_ok(cur, manager_email):
                return jsonify(
                    {"success": False, "message": "Manager access required."}
                ), 403
            ensure_ticket_sla_columns(cur)
            cur.execute(
                """
                SELECT public_ticket_id, COALESCE(project, '') AS project, created_at, updated_at, closed_at,
                    customer_name, customer_email, cc_emails, category, priority, status, subject, description,
                    assigned_to
                FROM tickets
                ORDER BY created_at ASC NULLS LAST, id ASC
                """
            )
            db_rows = cur.fetchall() or []
    finally:
        conn.close()
    out = []
    for r in db_rows:
        rd = _export_resolved_datetime_for_csv(r)
        out.append(
            {
                "ticket_number": r.get("public_ticket_id") or "",
                "project": r.get("project") or "",
                "created_date": _format_csv_datetime(r.get("created_at")),
                "resolved_date": _format_csv_datetime(rd) if rd else "",
                "customer_name": r.get("customer_name") or "",
                "email": r.get("customer_email") or "",
                "cc": r.get("cc_emails") or "",
                "category": r.get("category") or "",
                "priority": r.get("priority") or "",
                "status": r.get("status") or "",
                "subject": r.get("subject") or "",
                "description": (r.get("description") or "").replace("\r\n", "\n"),
                "assigned_staff": r.get("assigned_to") or "",
            }
        )
    return _tickets_csv_response(out, "tickets_export.csv")


@app.route("/api/admin/tickets/import-csv", methods=["POST"])
def import_tickets_csv():
    manager_email = (request.form.get("manager_email") or "").strip()
    if not manager_email:
        j = request.get_json(silent=True) or {}
        manager_email = (j.get("manager_email") or "").strip()
    up = request.files.get("file")
    if not up or not (up.filename or "").strip():
        return jsonify({"success": False, "message": "Upload a CSV file (field name: file)."}), 400
    raw = up.read()
    if len(raw) > IMPORT_CSV_MAX_BYTES:
        return jsonify(
            {"success": False, "message": f"File too large (max {IMPORT_CSV_MAX_BYTES // (1024*1024)} MB)."}
        ), 413
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return jsonify({"success": False, "message": "CSV must be UTF-8 encoded."}), 400

    conn = get_db()
    prev_ac = conn.autocommit
    conn.autocommit = False
    imported = 0
    errors = []
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            ensure_user_schema(cur)
            if not manager_actor_ok(cur, manager_email):
                conn.rollback()
                return jsonify(
                    {"success": False, "message": "Manager access required."}
                ), 403
            ensure_portal_settings(cur)
            ensure_ticket_sla_columns(cur)
            cur.execute("SELECT settings FROM portal_settings WHERE id = 1")
            pr = cur.fetchone()
            merged = merge_portal_settings(pr["settings"] if pr else None)
            reader = csv.DictReader(io.StringIO(text))
            if not reader.fieldnames:
                conn.rollback()
                return jsonify(
                    {"success": False, "message": "CSV has no header row."}
                ), 400
            for idx, row in enumerate(reader, start=2):
                if idx - 2 >= IMPORT_CSV_MAX_ROWS:
                    errors.append(
                        {
                            "row": idx,
                            "message": f"Stopped: more than {IMPORT_CSV_MAX_ROWS} data rows.",
                        }
                    )
                    break
                rec = _canonical_ticket_csv_row(row)
                if not any(
                    (
                        rec.get("email"),
                        rec.get("subject"),
                        rec.get("description"),
                        rec.get("customer_name"),
                    )
                ):
                    continue
                try:
                    cur.execute("SAVEPOINT csv_import_row")
                    _insert_ticket_from_import_row(cur, merged, rec)
                    cur.execute("RELEASE SAVEPOINT csv_import_row")
                    imported += 1
                except Exception as ex:
                    cur.execute("ROLLBACK TO SAVEPOINT csv_import_row")
                    errors.append({"row": idx, "message": str(ex)[:500]})
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.autocommit = prev_ac
        conn.close()

    app.logger.info(
        "CSV ticket import by %s: imported=%s errors=%s", manager_email, imported, len(errors)
    )
    return jsonify(
        {
            "success": True,
            "imported": imported,
            "errors": errors,
            "message": f"Imported {imported} ticket(s). No customer or staff notification emails were sent."
            + (f" {len(errors)} row(s) skipped with errors." if errors else ""),
        }
    )


@app.route("/api/reports/tickets-by-agent", methods=["GET"])
def report_tickets_by_agent():
    manager_email = (request.args.get("manager_email") or "").strip()
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            ensure_user_schema(cur)
            if not manager_actor_ok(cur, manager_email):
                return jsonify(
                    {"success": False, "message": "Manager access required."}
                ), 403
            ensure_ticket_sla_columns(cur)
            cur.execute(
                """
                SELECT id, public_ticket_id, subject, status, assigned_to,
                    expected_resolution, primary_analysis, priority, created_at
                FROM tickets
                WHERE assigned_to IS NOT NULL
                ORDER BY assigned_to ASC, created_at DESC
                """
            )
            rows = cur.fetchall()
        by_agent = {}
        for r in rows:
            ag = (r.get("assigned_to") or "Unknown").strip() or "Unknown"
            by_agent.setdefault(ag, []).append(dict(r))
        return jsonify(
            {
                "success": True,
                "by_agent": by_agent,
                "tickets": [dict(x) for x in rows],
            }
        )
    finally:
        conn.close()

@app.route('/api/tickets/<int:ticket_id>/history', methods=['GET'])
def get_ticket_history(ticket_id):
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        ensure_ticket_approvals_schema(cur)
        cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'ticket_replies')")
        replies_exist = cur.fetchone()['exists']

        cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'ticket_audit_log')")
        audit_exists = cur.fetchone()['exists']

        replies = []
        notes = []

        if replies_exist:
            cur.execute(
                "SELECT * FROM ticket_replies WHERE ticket_id = %s ORDER BY created_at ASC",
                (ticket_id,),
            )
            replies = cur.fetchall()

        if audit_exists:
            cur.execute(
                "SELECT * FROM ticket_audit_log WHERE ticket_id = %s ORDER BY created_at ASC",
                (ticket_id,),
            )
            notes = cur.fetchall()

        cur.execute(
            "SELECT * FROM ticket_approvals WHERE ticket_id = %s ORDER BY created_at ASC",
            (ticket_id,),
        )
        approval_rows = cur.fetchall()

    conn.close()
    approvals = [_approval_json(dict(r)) for r in approval_rows]
    return jsonify({"replies": replies, "notes": notes, "approvals": approvals})


def _ticket_audit_log(cur, ticket_id, action, performed_by):
    cur.execute(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'ticket_audit_log')"
    )
    if not cur.fetchone()['exists']:
        return
    cur.execute(
        "INSERT INTO ticket_audit_log (ticket_id, action, performed_by) VALUES (%s, %s, %s)",
        (ticket_id, action, performed_by),
    )


@app.route("/api/tickets/<int:ticket_id>/approval/request", methods=["POST"])
def ticket_approval_request(ticket_id):
    data = request.get_json(silent=True) or {}
    staff_email = (data.get("staff_email") or "").strip()
    agent_name = (data.get("agent") or "").strip()
    if not staff_email:
        return jsonify({"success": False, "message": "Staff sign-in required."}), 403
    manager_email = _normalize_public_lookup_email(data.get("manager_email"))
    if not manager_email or "@" not in manager_email:
        return jsonify({"success": False, "message": "Manager email is required."}), 400
    reason = (data.get("reason") or "").strip()
    message_to_manager = (data.get("message_to_manager") or data.get("message") or "").strip()
    if len(reason) < 3:
        return jsonify({"success": False, "message": "Approval reason is required."}), 400
    if len(message_to_manager) < 5:
        return jsonify({"success": False, "message": "Message to manager is required."}), 400
    cc_raw = data.get("cc_emails") or data.get("cc") or ""
    due_at = _parse_approval_due_at(data.get("due_at"))
    if not due_at:
        return jsonify({"success": False, "message": "Valid due date & time is required."}), 400

    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        ensure_ticket_approvals_schema(cur)
        ensure_user_schema(cur)
        if not staff_actor_ok(cur, staff_email):
            conn.close()
            return jsonify({"success": False, "message": "Staff sign-in required."}), 403
        cur.execute("SELECT * FROM tickets WHERE id = %s", (ticket_id,))
        ticket = cur.fetchone()
        if not ticket:
            conn.close()
            return jsonify({"success": False, "message": "Ticket not found."}), 404
        if not staff_may_manage_ticket_approval(cur, staff_email, agent_name, ticket):
            conn.close()
            return jsonify(
                {
                    "success": False,
                    "message": "Only active agents and managers can request approval.",
                }
            ), 403
        cur.execute(
            "SELECT id FROM ticket_approvals WHERE ticket_id = %s AND status = 'pending' LIMIT 1",
            (ticket_id,),
        )
        if cur.fetchone():
            conn.close()
            return jsonify(
                {"success": False, "message": "An approval is already pending for this ticket."}
            ), 400
        token = secrets.token_urlsafe(48)
        prev_status = ticket.get("status") or "🛠 Working on It"
        cc_store = (cc_raw or "").strip()[:2000]
        cur.execute(
            """
            INSERT INTO ticket_approvals (
                ticket_id, requested_by, manager_email, cc_emails, reason, message_to_manager,
                due_at, status, previous_ticket_status, secret_token
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending', %s, %s)
            RETURNING id;
            """,
            (
                ticket_id,
                agent_name,
                manager_email,
                cc_store,
                reason[:4000],
                message_to_manager[:8000],
                due_at,
                prev_status,
                token,
            ),
        )
        approval_id = cur.fetchone()["id"]
        cur.execute(
            "UPDATE tickets SET status = %s, updated_at = NOW() WHERE id = %s",
            ("⏳ Pending Manager Approval", ticket_id),
        )
        _ticket_audit_log(
            cur,
            ticket_id,
            f"Approval requested → {manager_email} (due {due_at.isoformat()})",
            agent_name,
        )
        cur.execute("SELECT * FROM ticket_approvals WHERE id = %s", (approval_id,))
        row = cur.fetchone()
    conn.close()

    base = (request.url_root or "").rstrip("/") or os.environ.get(
        "PORTAL_BASE_URL", "http://127.0.0.1:5000"
    )
    respond_page = f"{base}/approval-response.html"
    ticket_link = f"{base}/manager-dashboard.html"
    customer_label = f"{ticket.get('customer_name') or 'Customer'} <{ticket.get('customer_email') or ''}>"

    def _send_mail():
        cc_list = [x for x in (cc_store or "").replace(";", ",").split(",") if "@" in x]
        cs, ct, ch = _manager_approval_email_custom_content(
            dict(ticket),
            ticket_id,
            agent_name,
            reason,
            message_to_manager,
            due_at,
            approval_id,
            token,
            base,
        )
        conn2 = get_db()
        try:
            with conn2.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur2:
                ensure_portal_settings(cur2)
                cur2.execute("SELECT settings FROM portal_settings WHERE id = 1")
                pr2 = cur2.fetchone()
                merged2 = merge_portal_settings(pr2["settings"] if pr2 else None)
        finally:
            conn2.close()
        bdict = _branding_dict_for_email(merged2)
        ok, err = send_manager_approval_request_email(
            manager_email,
            cc_list,
            ticket.get("public_ticket_id") or str(ticket_id),
            ticket.get("subject") or "Support ticket",
            customer_label,
            agent_name,
            reason,
            message_to_manager,
            ticket.get("priority") or "Medium",
            due_at.strftime("%Y-%m-%d %H:%M"),
            ticket_link,
            respond_page,
            approval_id,
            token,
            custom_subject=cs,
            custom_text_body=ct,
            custom_html_body=ch,
            branding_dict=bdict,
            customer_portal_url=_customer_ticket_view_url(
                base.strip().rstrip("/"),
                ticket.get("public_ticket_id") or str(ticket_id),
            ),
        )
        if not ok:
            app.logger.warning("Manager approval email not sent: %s", err)

    threading.Thread(target=_send_mail, daemon=True).start()
    return jsonify({"success": True, "approval": _approval_json(row)})


@app.route("/api/tickets/<int:ticket_id>/approval/cancel", methods=["POST"])
def ticket_approval_cancel(ticket_id):
    data = request.get_json(silent=True) or {}
    staff_email = (data.get("staff_email") or "").strip()
    agent_name = (data.get("agent") or "").strip()
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        ensure_ticket_approvals_schema(cur)
        ensure_user_schema(cur)
        if not staff_actor_ok(cur, staff_email):
            conn.close()
            return jsonify({"success": False, "message": "Staff sign-in required."}), 403
        cur.execute("SELECT * FROM tickets WHERE id = %s", (ticket_id,))
        ticket = cur.fetchone()
        if not ticket:
            conn.close()
            return jsonify({"success": False, "message": "Ticket not found."}), 404
        if not staff_may_manage_ticket_approval(cur, staff_email, agent_name, ticket):
            conn.close()
            return jsonify(
                {"success": False, "message": "Only the assigned agent or a manager can cancel."}
            ), 403
        cur.execute(
            """
            SELECT * FROM ticket_approvals
            WHERE ticket_id = %s AND status = 'pending'
            ORDER BY id DESC LIMIT 1
            """,
            (ticket_id,),
        )
        ap = cur.fetchone()
        if not ap:
            conn.close()
            return jsonify({"success": False, "message": "No pending approval to cancel."}), 400
        cur.execute(
            """
            UPDATE ticket_approvals
            SET status = 'cancelled', decided_at = NOW(),
                manager_comment = 'Cancelled before manager decision.'
            WHERE id = %s
            """,
            (ap["id"],),
        )
        restore = ap.get("previous_ticket_status") or "🛠 Working on It"
        cur.execute(
            "UPDATE tickets SET status = %s, updated_at = NOW() WHERE id = %s",
            (restore, ticket_id),
        )
        _ticket_audit_log(cur, ticket_id, "Approval request cancelled", agent_name)
    conn.close()
    return jsonify({"success": True})


@app.route("/api/tickets/<int:ticket_id>/approval/resend", methods=["POST"])
def ticket_approval_resend(ticket_id):
    data = request.get_json(silent=True) or {}
    staff_email = (data.get("staff_email") or "").strip()
    agent_name = (data.get("agent") or "").strip()
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        ensure_ticket_approvals_schema(cur)
        ensure_user_schema(cur)
        if not staff_actor_ok(cur, staff_email):
            conn.close()
            return jsonify({"success": False, "message": "Staff sign-in required."}), 403
        cur.execute("SELECT * FROM tickets WHERE id = %s", (ticket_id,))
        ticket = cur.fetchone()
        if not ticket:
            conn.close()
            return jsonify({"success": False, "message": "Ticket not found."}), 404
        if not staff_may_manage_ticket_approval(cur, staff_email, agent_name, ticket):
            conn.close()
            return jsonify(
                {"success": False, "message": "Only active agents and managers can resend approval."}
            ), 403
        cur.execute(
            """
            SELECT * FROM ticket_approvals
            WHERE ticket_id = %s AND status = 'pending'
            ORDER BY id DESC LIMIT 1
            """,
            (ticket_id,),
        )
        ap = cur.fetchone()
        if not ap:
            conn.close()
            return jsonify({"success": False, "message": "No pending approval to resend."}), 400
        token = ap["secret_token"]
        approval_id = ap["id"]
        manager_email = ap["manager_email"]
        cc_store = ap.get("cc_emails") or ""
        reason = ap.get("reason") or ""
        message_to_manager = ap.get("message_to_manager") or ""
        due_at = ap.get("due_at")
    conn.close()

    base = (request.url_root or "").rstrip("/") or os.environ.get(
        "PORTAL_BASE_URL", "http://127.0.0.1:5000"
    )
    respond_page = f"{base}/approval-response.html"
    ticket_link = f"{base}/manager-dashboard.html"
    customer_label = f"{ticket.get('customer_name') or 'Customer'} <{ticket.get('customer_email') or ''}>"
    due_display = due_at.strftime("%Y-%m-%d %H:%M") if hasattr(due_at, "strftime") else str(due_at)

    def _send_mail():
        cc_list = [x for x in (cc_store or "").replace(";", ",").split(",") if "@" in x]
        cs, ct, ch = _manager_approval_email_custom_content(
            dict(ticket),
            ticket_id,
            agent_name,
            reason,
            message_to_manager,
            due_at,
            approval_id,
            token,
            base,
        )
        conn2 = get_db()
        try:
            with conn2.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur2:
                ensure_portal_settings(cur2)
                cur2.execute("SELECT settings FROM portal_settings WHERE id = 1")
                pr2 = cur2.fetchone()
                merged2 = merge_portal_settings(pr2["settings"] if pr2 else None)
        finally:
            conn2.close()
        bdict = _branding_dict_for_email(merged2)
        ok, err = send_manager_approval_request_email(
            manager_email,
            cc_list,
            ticket.get("public_ticket_id") or str(ticket_id),
            ticket.get("subject") or "Support ticket",
            customer_label,
            agent_name,
            reason,
            message_to_manager,
            ticket.get("priority") or "Medium",
            due_display,
            ticket_link,
            respond_page,
            approval_id,
            token,
            custom_subject=cs,
            custom_text_body=ct,
            custom_html_body=ch,
            branding_dict=bdict,
            customer_portal_url=_customer_ticket_view_url(
                base.strip().rstrip("/"),
                ticket.get("public_ticket_id") or str(ticket_id),
            ),
        )
        if not ok:
            app.logger.warning("Manager approval resend failed: %s", err)

    threading.Thread(target=_send_mail, daemon=True).start()
    return jsonify({"success": True})


@app.route("/api/tickets/<int:ticket_id>/forward", methods=["POST"])
def ticket_forward(ticket_id):
    """Staff: email ticket summary (incl. approvals) with To/CC; optional ticket files + uploaded extras."""
    staff_email = (request.form.get("staff_email") or "").strip()
    agent_name = (request.form.get("agent") or "").strip() or "Staff"
    to_list = _emails_from_field(request.form.get("to_emails") or request.form.get("to"))
    cc_list = _emails_from_field(request.form.get("cc_emails") or request.form.get("cc"))
    message = (request.form.get("message") or "").strip()[:8000]
    inc_raw = (request.form.get("include_ticket_attachments") or "").lower()
    include_ticket_files = inc_raw in ("1", "true", "yes", "on")

    if not staff_email:
        return jsonify({"success": False, "message": "Staff sign-in required."}), 403
    if not to_list:
        return jsonify({"success": False, "message": "Add at least one address in To."}), 400

    extra_files = list(request.files.getlist("forward_files") or request.files.getlist("files") or [])

    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            ensure_user_schema(cur)
            if not staff_actor_ok(cur, staff_email):
                return jsonify({"success": False, "message": "Staff sign-in required."}), 403
            ensure_ticket_sla_columns(cur)
            cur.execute("SELECT * FROM tickets WHERE id = %s", (ticket_id,))
            ticket = cur.fetchone()
            if not ticket:
                return jsonify({"success": False, "message": "Ticket not found."}), 404
            ensure_ticket_approvals_schema(cur)
            cur.execute(
                "SELECT * FROM ticket_approvals WHERE ticket_id = %s ORDER BY created_at ASC",
                (ticket_id,),
            )
            approval_rows = cur.fetchall()
    finally:
        conn.close()

    tdict = dict(ticket)
    att_payloads = []
    if include_ticket_files:
        att_payloads.extend(
            _ticket_attachment_files_for_email(ticket_id, tdict.get("attachments_data"))
        )

    extra_count = 0
    for f in extra_files:
        if not f or not getattr(f, "filename", None):
            continue
        raw = f.read()
        if len(raw) > 12 * 1024 * 1024:
            return jsonify(
                {"success": False, "message": "Each extra attachment must be 12 MB or smaller."}
            ), 400
        name = secure_filename(os.path.basename(f.filename)) or "file"
        mime, _ = mimetypes.guess_type(name)
        att_payloads.append(
            {"data": raw, "filename": name, "mime": mime or "application/octet-stream"}
        )
        extra_count += 1

    total_bytes = 0
    for a in att_payloads:
        if a.get("data") is not None:
            total_bytes += len(a["data"])
        else:
            p = a.get("path")
            if p and os.path.isfile(p):
                total_bytes += os.path.getsize(p)
    if total_bytes > 22 * 1024 * 1024:
        return jsonify(
            {
                "success": False,
                "message": "Combined attachments exceed the ~22 MB email limit. Uncheck some files or remove extras.",
            }
        ), 400

    fwd_mail_identity = _ticket_mail_send_identity()

    base = (request.url_root or "").rstrip("/") or os.environ.get(
        "PORTAL_BASE_URL", "http://127.0.0.1:5000"
    )
    portal_link = f"{base}/agent-dashboard.html"
    subj, text_body, html_body = _build_forward_email_bodies(
        tdict, approval_rows, agent_name, message, portal_link
    )

    audit_msg = f"[FORWARD] To: {', '.join(to_list[:8])}"
    if len(to_list) > 8:
        audit_msg += "…"
    if cc_list:
        audit_msg += f" | CC: {', '.join(cc_list[:6])}"
        if len(cc_list) > 6:
            audit_msg += "…"
    audit_msg += f" | Case files: {'yes' if include_ticket_files else 'no'}"
    audit_msg += f" | Extra files: {extra_count}"
    if message:
        audit_msg += f" | Note: {message[:200]}"

    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _ticket_audit_log(cur, ticket_id, audit_msg, agent_name)
    finally:
        conn.close()

    def _send_forward():
        ok, err = send_ticket_forward_email(
            to_list,
            cc_list,
            subj,
            text_body,
            html_body,
            attachments=att_payloads,
            reply_to=staff_email,
            send_identity=fwd_mail_identity,
        )
        if not ok:
            app.logger.warning("Ticket forward email failed: %s", err)

    threading.Thread(target=_send_forward, daemon=True).start()
    return jsonify({"success": True, "message": "Forward is being sent."})


def _forward_ticket_ids_from_request():
    raw_ids = []
    for x in request.form.getlist("ticket_ids"):
        for part in str(x).split(","):
            p = part.strip()
            if p.isdigit():
                raw_ids.append(int(p))
    if not raw_ids:
        one = (request.form.get("ticket_ids") or "").strip()
        for part in one.split(","):
            p = part.strip()
            if p.isdigit():
                raw_ids.append(int(p))
    out, seen = [], set()
    for i in raw_ids:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out[:25]


@app.route("/api/tickets/forward-batch", methods=["POST"])
def ticket_forward_batch():
    """Staff: forward multiple tickets in one email (summary + combined attachments)."""
    staff_email = (request.form.get("staff_email") or "").strip()
    agent_name = (request.form.get("agent") or "").strip() or "Staff"
    to_list = _emails_from_field(request.form.get("to_emails") or request.form.get("to"))
    cc_list = _emails_from_field(request.form.get("cc_emails") or request.form.get("cc"))
    message = (request.form.get("message") or "").strip()[:8000]
    inc_raw = (request.form.get("include_ticket_attachments") or "").lower()
    include_ticket_files = inc_raw in ("1", "true", "yes", "on")
    ticket_ids = _forward_ticket_ids_from_request()

    if not staff_email:
        return jsonify({"success": False, "message": "Staff sign-in required."}), 403
    if not to_list:
        return jsonify({"success": False, "message": "Add at least one address in To."}), 400
    if len(ticket_ids) < 1:
        return jsonify(
            {"success": False, "message": "Select at least one ticket (use the checkboxes in the queue)."}
        ), 400
    if len(ticket_ids) > 25:
        return jsonify({"success": False, "message": "You can forward at most 25 tickets at once."}), 400

    extra_files = list(request.files.getlist("forward_files") or request.files.getlist("files") or [])

    pairs = []
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            ensure_user_schema(cur)
            if not staff_actor_ok(cur, staff_email):
                return jsonify({"success": False, "message": "Staff sign-in required."}), 403
            ensure_ticket_sla_columns(cur)
            ensure_ticket_approvals_schema(cur)
            for tid in ticket_ids:
                cur.execute("SELECT * FROM tickets WHERE id = %s", (tid,))
                ticket = cur.fetchone()
                if not ticket:
                    return jsonify(
                        {"success": False, "message": f"Ticket #{tid} was not found."}
                    ), 404
                cur.execute(
                    "SELECT * FROM ticket_approvals WHERE ticket_id = %s ORDER BY created_at ASC",
                    (tid,),
                )
                approval_rows = cur.fetchall()
                pairs.append((dict(ticket), approval_rows))
    finally:
        conn.close()

    att_payloads = []
    if include_ticket_files:
        for tid, (tdict, _) in zip(ticket_ids, pairs):
            pub = str(tdict.get("public_ticket_id") or tid).replace("/", "_").replace("\\", "_")
            for a in _ticket_attachment_files_for_email(tid, tdict.get("attachments_data")):
                a2 = dict(a)
                base_fn = a2.get("filename") or "file"
                a2["filename"] = f"{pub}_{base_fn}"
                att_payloads.append(a2)

    extra_count = 0
    for f in extra_files:
        if not f or not getattr(f, "filename", None):
            continue
        raw = f.read()
        if len(raw) > 12 * 1024 * 1024:
            return jsonify(
                {"success": False, "message": "Each extra attachment must be 12 MB or smaller."}
            ), 400
        name = secure_filename(os.path.basename(f.filename)) or "file"
        mime, _ = mimetypes.guess_type(name)
        att_payloads.append(
            {"data": raw, "filename": name, "mime": mime or "application/octet-stream"}
        )
        extra_count += 1

    total_bytes = 0
    for a in att_payloads:
        if a.get("data") is not None:
            total_bytes += len(a["data"])
        else:
            p = a.get("path")
            if p and os.path.isfile(p):
                total_bytes += os.path.getsize(p)
    if total_bytes > 22 * 1024 * 1024:
        return jsonify(
            {
                "success": False,
                "message": "Combined attachments exceed the ~22 MB email limit. Uncheck ticket files or remove extras.",
            }
        ), 400

    base = (request.url_root or "").rstrip("/") or os.environ.get(
        "PORTAL_BASE_URL", "http://127.0.0.1:5000"
    )
    portal_link = f"{base}/agent-dashboard.html"
    subj, text_body, html_body = _build_multi_forward_email_bodies(pairs, agent_name, message, portal_link)

    pub_preview = [str(p[0].get("public_ticket_id") or p[0].get("id")) for p in pairs[:6]]
    audit_msg = (
        f"[FORWARD batch {len(ticket_ids)} tickets: {', '.join(pub_preview)}"
        + ("…" if len(ticket_ids) > 6 else "")
        + f"] To: {', '.join(to_list[:8])}"
    )
    if len(to_list) > 8:
        audit_msg += "…"
    if cc_list:
        audit_msg += f" | CC: {', '.join(cc_list[:6])}"
        if len(cc_list) > 6:
            audit_msg += "…"
    audit_msg += f" | Case files: {'yes' if include_ticket_files else 'no'}"
    audit_msg += f" | Extra files: {extra_count}"
    if message:
        audit_msg += f" | Note: {message[:200]}"

    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            for tid in ticket_ids:
                _ticket_audit_log(cur, tid, audit_msg, agent_name)
    finally:
        conn.close()

    fwd_mail_identity = _ticket_mail_send_identity()

    def _send_batch():
        ok, err = send_ticket_forward_email(
            to_list,
            cc_list,
            subj,
            text_body,
            html_body,
            attachments=att_payloads,
            reply_to=staff_email,
            send_identity=fwd_mail_identity,
        )
        if not ok:
            app.logger.warning("Ticket batch forward email failed: %s", err)

    threading.Thread(target=_send_batch, daemon=True).start()
    return jsonify(
        {
            "success": True,
            "message": f"Forward for {len(ticket_ids)} ticket(s) is being sent.",
            "count": len(ticket_ids),
        }
    )


@app.route("/api/approval/decision", methods=["POST"])
def approval_decision():
    data = request.get_json(silent=True) or {}
    try:
        approval_id = int(data.get("approval_id") or data.get("id") or 0)
    except (TypeError, ValueError):
        approval_id = 0
    token = (data.get("token") or "").strip()
    action = (data.get("action") or "").lower().strip()
    comment = (data.get("comment") or "").strip()
    if not approval_id or not token or action not in ("approve", "reject", "rework"):
        return jsonify({"success": False, "message": "Invalid request."}), 400
    if action in ("reject", "rework") and len(comment) < 3:
        return jsonify({"success": False, "message": "Please add a short comment for the agent."}), 400

    customer_portal_base = _portal_base_url().strip().rstrip("/")

    trow = None
    appr_mail_snap = None
    verb = ""
    new_status = ""
    ap_status = ""

    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        ensure_ticket_approvals_schema(cur)
        cur.execute(
            "SELECT * FROM ticket_approvals WHERE id = %s AND secret_token = %s",
            (approval_id, token),
        )
        ap = cur.fetchone()
        if not ap or ap["status"] != "pending":
            conn.close()
            return jsonify(
                {"success": False, "message": "Invalid or expired approval link."}
            ), 400
        tid = ap["ticket_id"]
        prev = ap.get("previous_ticket_status") or "🛠 Working on It"
        if action == "approve":
            new_status = prev
            ap_status = "approved"
        elif action == "reject":
            new_status = "❌ Approval declined"
            ap_status = "rejected"
        else:
            new_status = "🔄 Approval rework requested"
            ap_status = "rework"
        cur.execute(
            """
            UPDATE ticket_approvals
            SET status = %s, manager_comment = %s, decided_at = NOW()
            WHERE id = %s
            """,
            (ap_status, comment[:4000] if comment else None, approval_id),
        )
        cur.execute(
            "UPDATE tickets SET status = %s, updated_at = NOW() WHERE id = %s",
            (new_status, tid),
        )
        verb = {"approve": "Approved", "reject": "Rejected", "rework": "Rework requested"}[action]
        _ticket_audit_log(
            cur,
            tid,
            f"Manager approval {verb.lower()}" + (f": {comment[:200]}" if comment else ""),
            "Manager",
        )
        cur.execute(
            """
            SELECT customer_email, cc_emails, customer_name, public_ticket_id, subject
            FROM tickets WHERE id = %s
            """,
            (tid,),
        )
        trow = cur.fetchone()
        ensure_portal_settings(cur)
        cur.execute("SELECT settings FROM portal_settings WHERE id = 1")
        psrow = cur.fetchone()
        appr_mail_snap = copy.deepcopy(
            merge_portal_settings(psrow["settings"] if psrow else None)
        )
    conn.close()

    if trow and (trow.get("customer_email") or "").strip():

        def _notify_customer_approval_result():
            tmpl = (appr_mail_snap.get("emailTemplates") or {}).get(
                "customer_manager_approval_result"
            ) or {}
            if not tmpl.get("enabled", True):
                return
            ctx = {
                "customer_name": trow.get("customer_name") or "Customer",
                "ticket_id": trow.get("public_ticket_id") or "—",
                "subject": trow.get("subject") or "—",
                "decision": verb,
                "manager_comment": (comment or "—").strip(),
                "ticket_status": new_status or "—",
                "ticket_url": _customer_ticket_view_url(
                    customer_portal_base, trow.get("public_ticket_id")
                ),
                **template_brand_placeholders(appr_mail_snap),
            }
            subj = render_email_template(tmpl.get("subject"), ctx)[:200]
            body = render_email_template(tmpl.get("body"), ctx)
            if not body.strip():
                return
            ok, err = send_branded_multipart_email(
                [trow["customer_email"].strip()],
                subj,
                body,
                _branding_dict_for_email(appr_mail_snap),
                cc_list=_parse_cc(trow.get("cc_emails")),
            )
            if not ok:
                app.logger.warning("Customer approval-result email not sent: %s", err)

        threading.Thread(target=_notify_customer_approval_result, daemon=True).start()

    return jsonify({"success": True, "status": ap_status, "ticket_status": new_status})


def _email_from_public_access_token():
    auth = request.headers.get("Authorization", "") or ""
    token = None
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
    if not token:
        token = (request.args.get("token") or "").strip()
    if not token:
        return None
    try:
        data = _public_email_token_serializer().loads(token, max_age=86400)
        return _normalize_public_lookup_email(data.get("e"))
    except Exception:
        return None


@app.route("/api/public/otp/request", methods=["POST"])
def public_otp_request():
    data = request.get_json(silent=True) or {}
    email = _normalize_public_lookup_email(data.get("email"))
    if not email or "@" not in email:
        return jsonify({"success": False, "message": "A valid email address is required."}), 400
    code = f"{secrets.randbelow(900000) + 100000:06d}"
    with _customer_otp_lock:
        _otp_purge_expired()
        _customer_otp_store[email] = {
            "code": code,
            "expires": _utc_now_naive() + timedelta(minutes=10),
        }
    ok, err = send_customer_ticket_view_otp_email(email, code)
    if not ok:
        app.logger.warning("Customer ticket-view OTP email failed: %s", err)
        with _customer_otp_lock:
            _customer_otp_store.pop(email, None)
        return jsonify({"success": False, "message": "Could not send email. Check mail settings or try again later."}), 500
    return jsonify({"success": True})


@app.route("/api/public/otp/verify", methods=["POST"])
def public_otp_verify():
    data = request.get_json(silent=True) or {}
    email = _normalize_public_lookup_email(data.get("email"))
    raw_code = (data.get("code") or "").replace(" ", "").strip()
    if not email or not raw_code.isdigit() or len(raw_code) != 6:
        return jsonify({"success": False, "message": "Enter the 6-digit code from your email."}), 400
    with _customer_otp_lock:
        _otp_purge_expired()
        entry = _customer_otp_store.get(email)
        if not entry or entry["expires"] < _utc_now_naive():
            _customer_otp_store.pop(email, None)
            return jsonify({"success": False, "message": "Invalid or expired code. Request a new one."}), 400
        if entry["code"] != raw_code:
            return jsonify({"success": False, "message": "That code is not correct."}), 400
        _customer_otp_store.pop(email, None)
    token = _public_email_token_serializer().dumps({"e": email})
    return jsonify({"success": True, "access_token": token})


@app.route("/api/public/my-tickets", methods=["GET"])
def public_my_tickets():
    email = _email_from_public_access_token()
    if not email:
        return jsonify({"success": False, "message": "Sign in again with your email code."}), 401
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        ensure_ticket_sla_columns(cur)
        cur.execute(
            """
            SELECT id, public_ticket_id, subject, status, priority, created_at, updated_at, assigned_to
            FROM tickets
            WHERE LOWER(TRIM(customer_email)) = %s
            ORDER BY created_at DESC
            """,
            (email,),
        )
        rows = cur.fetchall()
    conn.close()
    tickets = []
    for r in rows:
        d = dict(r)
        for k, v in list(d.items()):
            if hasattr(v, "isoformat"):
                d[k] = v.isoformat()
        d.pop("attachments_data", None)
        tickets.append(d)
    return jsonify({"success": True, "tickets": tickets})


def _public_ticket_view_dict(ticket_row):
    """Serialize a ticket row for the customer portal; strip attachments and sensitive fields."""
    t = dict(ticket_row)
    t.pop("attachments_data", None)
    for k, v in list(t.items()):
        if hasattr(v, "isoformat"):
            t[k] = v.isoformat()
    for redact in ("customer_email", "cc_emails", "phone"):
        t.pop(redact, None)
    t["block_customer_reopen"] = bool(t.get("block_customer_reopen"))
    if t.get("description"):
        t["description"] = _strip_agent_only_cloud_password_from_description(t["description"])
    return t


def _ticket_status_allows_customer_reopen(status):
    if not status:
        return False
    s = str(status).lower()
    return "resolved" in s or "closed" in s


@app.route('/api/public/tickets/<public_id>/reopen', methods=['POST'])
def public_reopen_ticket(public_id):
    data = request.get_json(silent=True) or {}
    email = _normalize_public_lookup_email(data.get("email"))
    note = (data.get("message") or data.get("note") or "").strip()
    if not email or "@" not in email:
        return jsonify(
            {"success": False, "message": "Enter the email used when this ticket was submitted."}
        ), 400
    if len(note) < 10:
        return jsonify(
            {
                "success": False,
                "message": "Please describe the issue or what you still need (at least 10 characters).",
            }
        ), 400
    if len(note) > 8000:
        note = note[:8000]
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        ensure_ticket_sla_columns(cur)
        cur.execute("SELECT * FROM tickets WHERE public_ticket_id = %s", (public_id,))
        ticket = cur.fetchone()
        if not ticket:
            conn.close()
            return jsonify({"success": False, "message": "Ticket not found."}), 404
        if _normalize_public_lookup_email(ticket.get("customer_email")) != email:
            conn.close()
            return jsonify({"success": False, "message": "Email does not match this ticket."}), 403
        if ticket.get("block_customer_reopen"):
            conn.close()
            return jsonify(
                {
                    "success": False,
                    "message": "This ticket was completed automatically and cannot be reopened from the portal. "
                    "Contact the helpdesk if you still need assistance.",
                }
            ), 403
        st = ticket.get("status") or ""
        if not _ticket_status_allows_customer_reopen(st):
            conn.close()
            return jsonify(
                {"success": False, "message": "Only resolved or closed tickets can be reopened."}
            ), 400
        tid = ticket["id"]
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS ticket_replies (
                id SERIAL PRIMARY KEY,
                ticket_id INTEGER REFERENCES tickets(id),
                sender_type VARCHAR(50),
                sender_email VARCHAR(255),
                message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        stored_msg = f"[Reopened by customer — follow-up]\n\n{note}"
        cur.execute(
            "INSERT INTO ticket_replies (ticket_id, sender_type, sender_email, message) VALUES (%s, %s, %s, %s)",
            (tid, "Customer", email, stored_msg),
        )
        cur.execute(
            "UPDATE tickets SET status = %s, updated_at = NOW() WHERE id = %s",
            ("🔁 Reopened", tid),
        )
        cur.execute(
            "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'ticket_audit_log')"
        )
        if cur.fetchone()["exists"]:
            preview = note.replace("\n", " ")[:120]
            if len(note) > 120:
                preview += "…"
            cur.execute(
                "INSERT INTO ticket_audit_log (ticket_id, action, performed_by) VALUES (%s, %s, %s)",
                (
                    tid,
                    f"Customer reopened ticket (portal). Summary: {preview}",
                    "Customer",
                ),
            )
        cur.execute("SELECT * FROM tickets WHERE id = %s", (tid,))
        updated = cur.fetchone()
    conn.close()
    _notify_staff_ticket_reopened_async(
        dict(updated), note, _portal_base_url()
    )
    return jsonify({"success": True, "ticket": _public_ticket_view_dict(updated)})


@app.route('/api/public/tickets/<public_id>', methods=['GET'])
def get_public_ticket(public_id):
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        ensure_ticket_sla_columns(cur)
        cur.execute("SELECT * FROM tickets WHERE public_ticket_id = %s", (public_id,))
        ticket = cur.fetchone()

        if not ticket:
            conn.close()
            return jsonify({"error": "Ticket not found"}), 404

        ticket_public = _public_ticket_view_dict(ticket)

        cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'ticket_replies')")
        replies = []
        if cur.fetchone()["exists"]:
            cur.execute(
                "SELECT sender_type, message, created_at FROM ticket_replies WHERE ticket_id = %s ORDER BY created_at ASC",
                (ticket["id"],),
            )
            raw_replies = cur.fetchall()
            for r in raw_replies:
                rd = dict(r)
                for rk, rv in list(rd.items()):
                    if hasattr(rv, "isoformat"):
                        rd[rk] = rv.isoformat()
                replies.append(rd)

    conn.close()
    return jsonify({"ticket": ticket_public, "replies": replies})

@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        # 1. Avg Resolution Time
        cur.execute("""
            SELECT AVG(EXTRACT(EPOCH FROM (updated_at - created_at))) as avg_res_sec
            FROM tickets 
            WHERE status LIKE '%Resolved%' OR status LIKE '%Closed%'
        """)
        res_row = cur.fetchone()
        avg_res_time_hours = 0.0
        if res_row and res_row['avg_res_sec']:
            avg_res_time_hours = round(float(res_row['avg_res_sec']) / 3600.0, 1)

        # 2. Avg Response Time
        cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'ticket_replies')")
        replies_exist = cur.fetchone()['exists']
        
        avg_resp_time_mins = 0.0
        if replies_exist:
            cur.execute("""
                SELECT AVG(EXTRACT(EPOCH FROM (r.created_at - t.created_at))) as avg_resp_sec
                FROM tickets t
                JOIN (
                    SELECT ticket_id, MIN(created_at) as created_at
                    FROM ticket_replies
                    WHERE sender_type = 'Agent'
                    GROUP BY ticket_id
                ) r ON t.id = r.ticket_id
            """)
            resp_row = cur.fetchone()
            if resp_row and resp_row['avg_resp_sec']:
                avg_resp_time_mins = round(float(resp_row['avg_resp_sec']) / 60.0, 1)

        # 3. Productivity (Resolved / Assigned)
        cur.execute("SELECT COUNT(*) as count FROM tickets WHERE assigned_to IS NOT NULL")
        total_assigned = cur.fetchone()['count']
        
        cur.execute("SELECT COUNT(*) as count FROM tickets WHERE assigned_to IS NOT NULL AND (status LIKE '%%Resolved%%' OR status LIKE '%%Closed%%')")
        resolved_assigned = cur.fetchone()['count']
        
        productivity = 0
        if total_assigned > 0:
            productivity = round((resolved_assigned / total_assigned) * 100)

        # Not real survey CSAT — a simple 1–5 style index from resolve rate on assigned tickets only.
        # productivity 0% → 4.0, 100% → 4.9. Omit when nothing is assigned so we do not show a fake score.
        csat_score = None
        if total_assigned > 0:
            csat_score = round(4.0 + (productivity / 100.0) * 0.9, 1)

    conn.close()
    return jsonify({
        "avg_resolution_time_hours": avg_res_time_hours,
        "avg_response_time_mins": avg_resp_time_mins,
        "csat_score": csat_score,
        "productivity_percent": productivity
    })

@app.route('/api/users', methods=['GET'])
def get_users():
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        ensure_user_schema(cur)
        cur.execute("SELECT * FROM users ORDER BY created_at DESC")
        users = cur.fetchall()
        if not users:
            try:
                cur.execute(
                    "INSERT INTO users (name, email, password, role, is_active) VALUES ('Admin Manager', 'manager@nexus.ent', 'admin', 'Manager', TRUE) RETURNING id"
                )
                users = [{"id": cur.fetchone()["id"], "name": "Admin Manager", "email": "manager@nexus.ent", "role": "Manager", "is_active": True}]
            except Exception:
                pass
    conn.close()
    return jsonify(users)

@app.route('/api/users', methods=['POST'])
def create_user():
    data = request.json or {}
    password = (data.get('password') or 'password123').strip()
    if len(password) < 4:
        return jsonify({"success": False, "message": "Password must be at least 4 characters."}), 400
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()
    role = normalize_staff_role(data.get("role"))
    if not name or not email:
        return jsonify({"success": False, "message": "Name and email are required."}), 400
    conn = get_db()
    with conn.cursor() as cur:
        ensure_user_schema(cur)
        try:
            cur.execute(
                "INSERT INTO users (name, email, password, role, is_active) VALUES (%s, %s, %s, %s, TRUE)",
                (name, email, password, role),
            )
        except psycopg2.IntegrityError:
            conn.close()
            return jsonify({"success": False, "message": "A user with this email already exists."}), 409
    conn.close()
    return jsonify({"success": True})


@app.route("/api/users/<int:user_id>/password", methods=["POST"])
def manager_set_user_password(user_id):
    data = request.json or {}
    manager_email = data.get("manager_email")
    new_password = (data.get("new_password") or "").strip()
    if len(new_password) < 4:
        return jsonify({"success": False, "message": "New password must be at least 4 characters."}), 400

    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        ensure_user_schema(cur)
        if not manager_actor_ok(cur, manager_email):
            conn.close()
            return jsonify({"success": False, "message": "Only an active manager can reset passwords."}), 403
        cur.execute("UPDATE users SET password = %s WHERE id = %s RETURNING id", (new_password, user_id))
        if not cur.fetchone():
            conn.close()
            return jsonify({"success": False, "message": "User not found."}), 404
    conn.close()
    return jsonify({"success": True})


@app.route("/api/users/<int:user_id>/active", methods=["POST"])
def manager_set_user_active(user_id):
    data = request.json or {}
    manager_email = data.get("manager_email")
    disabled = bool(data.get("disabled"))

    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        ensure_user_schema(cur)
        if not manager_actor_ok(cur, manager_email):
            conn.close()
            return jsonify({"success": False, "message": "Only an active manager can change account status."}), 403
        cur.execute("SELECT id, email FROM users WHERE id = %s", (user_id,))
        target = cur.fetchone()
        if not target:
            conn.close()
            return jsonify({"success": False, "message": "User not found."}), 404
        cur.execute("SELECT id FROM users WHERE email = %s", (manager_email,))
        actor = cur.fetchone()
        if disabled and actor and actor["id"] == user_id:
            conn.close()
            return jsonify({"success": False, "message": "You cannot disable your own account."}), 400
        cur.execute(
            "UPDATE users SET is_active = %s WHERE id = %s",
            (not disabled, user_id),
        )
    conn.close()
    return jsonify({"success": True, "is_active": not disabled})


@app.route("/api/forgot-password", methods=["POST"])
def forgot_password():
    """
    Agent accounts only: if email exists as an active Agent, email the current password.
    Same response whether or not matched (no email enumeration).
    """
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip()
    generic = {
        "success": True,
        "message": "If this email is registered as an active agent, your password has been sent to that inbox.",
    }
    if not email or "@" not in email:
        return jsonify(generic)

    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            ensure_user_schema(cur)
            cur.execute(
                """
                SELECT email, password, name, role, is_active
                FROM users
                WHERE lower(trim(email)) = lower(trim(%s))
                """,
                (email,),
            )
            user = cur.fetchone()
        if (
            user
            and (user.get("role") or "").strip() == "Agent"
            and user.get("is_active") is not False
            and user.get("password")
        ):
            uemail = user["email"]
            uname = user.get("name")
            upw = user["password"]

            def _send_forgot():
                ok, err = send_forgot_password_agent_email(uemail, uname, upw)
                if not ok:
                    app.logger.warning("Forgot-password email not sent: %s", err)

            threading.Thread(target=_send_forgot, daemon=True).start()
    finally:
        conn.close()
    return jsonify(generic)


@app.route('/api/login', methods=['POST'])
def login():
    data = request.json or {}
    email = (data.get("email") or "").strip()
    password = data.get("password")
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        ensure_user_schema(cur)
        cur.execute("SELECT * FROM users WHERE email = %s AND password = %s", (email, password))
        user = cur.fetchone()
    conn.close()
    if user:
        if user.get("is_active") is False:
            return jsonify({"success": False, "message": "This account has been disabled. Contact your manager."}), 403
        canon_role = normalize_staff_role(user.get("role"))
        return jsonify(
            {"success": True, "name": user["name"], "role": canon_role, "email": user["email"]}
        )
    else:
        return jsonify({"success": False, "message": "Invalid password or email. Account not found."}), 401


def _reports_multival(key):
    vals = request.args.getlist(key)
    if vals:
        return [str(v).strip() for v in vals if v and str(v).strip()]
    raw = request.args.get(key, "")
    if not raw:
        return []
    return [x.strip() for x in str(raw).split(",") if x.strip()]


def _enterprise_range_bounds():
    range_key = (request.args.get("range") or "month").lower().strip()
    now = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    end = now + timedelta(days=1)
    if range_key == "today":
        start = now
    elif range_key == "week":
        start = end - timedelta(days=7)
    elif range_key == "month":
        start = now.replace(day=1)
    elif range_key == "quarter":
        start = end - timedelta(days=90)
    elif range_key == "year":
        start = end - timedelta(days=365)
    elif range_key == "custom":
        df = (request.args.get("date_from") or "").strip()[:10]
        dt = (request.args.get("date_to") or "").strip()[:10]
        try:
            start = datetime.strptime(df, "%Y-%m-%d") if df else end - timedelta(days=30)
        except ValueError:
            start = end - timedelta(days=30)
        try:
            end = datetime.strptime(dt, "%Y-%m-%d") + timedelta(days=1) if dt else now + timedelta(days=1)
        except ValueError:
            end = now + timedelta(days=1)
    else:
        start = end - timedelta(days=30)
    if start >= end:
        start = end - timedelta(days=1)
    return start, end, range_key


def _priority_db_values(tiers):
    mapping = {
        "low": ["Low"],
        "medium": ["Medium"],
        "high": ["High"],
        "urgent": ["Urgent", "Enterprise Critical"],
    }
    out = []
    for t in tiers:
        k = (t or "").lower().strip()
        out.extend(mapping.get(k, [t]))
    return list(dict.fromkeys(out))


def _json_safe_row(obj):
    if obj is None:
        return None
    if isinstance(obj, dict):
        return {k: _json_safe_row(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_json_safe_row(x) for x in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    tname = type(obj).__name__
    if tname == "Decimal":
        return float(obj)
    if tname == "date":
        return obj.isoformat()
    return obj


def _ticket_is_closed_sql(alias="t"):
    return (
        f"(COALESCE({alias}.status,'') ILIKE '%%Resolved%%' OR "
        f"COALESCE({alias}.status,'') ILIKE '%%Closed%%')"
    )


def _ticket_sla_breached_sql(alias="t"):
    closed = _ticket_is_closed_sql(alias)
    return f"""(
        {alias}.sla_resolution_due IS NOT NULL AND (
            ({closed} AND COALESCE({alias}.closed_at, {alias}.updated_at) > {alias}.sla_resolution_due)
            OR
            (NOT ({closed}) AND NOW() > {alias}.sla_resolution_due)
        )
    )"""


def _enterprise_ticket_filters(cur, start, end):
    """Returns (where_sql, params) for alias t."""
    parts = ["t.created_at >= %s", "t.created_at < %s"]
    params = [start, end]

    agents = _reports_multival("agent")
    if agents:
        parts.append("t.assigned_to = ANY(%s)")
        params.append(agents)

    mgr_emails = [x.lower() for x in _reports_multival("manager")]
    if mgr_emails:
        parts.append(
            """EXISTS (
                SELECT 1 FROM ticket_approvals ta0
                WHERE ta0.ticket_id = t.id
                AND LOWER(TRIM(ta0.manager_email)) = ANY(%s)
            )"""
        )
        params.append(mgr_emails)

    categories = _reports_multival("category")
    if categories:
        parts.append("t.category = ANY(%s)")
        params.append(categories)

    pri_tiers = _reports_multival("priority")
    if pri_tiers:
        pvals = _priority_db_values(pri_tiers)
        if pvals:
            parts.append("t.priority = ANY(%s)")
            params.append(pvals)

    status_sel = [s.lower().strip() for s in _reports_multival("status")]
    if status_sel:
        sub = []
        closed_sql = _ticket_is_closed_sql("t")
        for s in status_sel:
            if s == "open":
                sub.append(f"NOT ({closed_sql})")
            elif s == "closed":
                sub.append(f"({closed_sql})")
            elif s == "pending":
                sub.append("COALESCE(t.status,'') ILIKE '%%Pending%%'")
            elif s == "escalated":
                sub.append(
                    """(
                        t.priority IN ('High','Urgent','Enterprise Critical')
                        OR COALESCE(t.status,'') ILIKE '%%Escalat%%'
                        OR COALESCE(t.status,'') ILIKE '%%approval%%'
                    )"""
                )
        if sub:
            parts.append("(" + " OR ".join(sub) + ")")

    customers = _reports_multival("customer")
    if customers:
        parts.append(
            "(LOWER(TRIM(t.customer_email)) = ANY(%s) OR LOWER(TRIM(t.customer_name)) = ANY(%s))"
        )
        low = [c.lower() for c in customers]
        params.append(low)
        params.append(low)

    orgs = [o.lower().strip() for o in _reports_multival("organization")]
    if orgs:
        parts.append(
            "LOWER(TRIM(SPLIT_PART(COALESCE(t.customer_email,''), '@', 2))) = ANY(%s)"
        )
        params.append(orgs)

    return " AND ".join(parts), params


@app.route("/api/reports/enterprise-dashboard", methods=["GET"])
def enterprise_dashboard_report():
    manager_email = (request.args.get("manager_email") or "").strip()
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            ensure_user_schema(cur)
            if not manager_actor_ok(cur, manager_email):
                return jsonify(
                    {"success": False, "message": "Manager access required."}
                ), 403
            ensure_ticket_sla_columns(cur)
            ensure_ticket_approvals_schema(cur)

            start, end, range_key = _enterprise_range_bounds()
            base_where, base_params = _enterprise_ticket_filters(cur, start, end)
            breach_sql = _ticket_sla_breached_sql("t")
            closed_sql = _ticket_is_closed_sql("t")

            cur.execute(
                f"""
                SELECT
                    COUNT(*)::int AS total,
                    COUNT(*) FILTER (WHERE {closed_sql})::int AS closed_n,
                    COUNT(*) FILTER (WHERE NOT ({closed_sql}))::int AS open_n,
                    COUNT(*) FILTER (WHERE {breach_sql})::int AS sla_violated
                FROM tickets t
                WHERE {base_where}
                """,
                tuple(base_params),
            )
            summ = cur.fetchone() or {}
            total = int(summ.get("total") or 0)
            closed_n = int(summ.get("closed_n") or 0)
            violated = int(summ.get("sla_violated") or 0)
            compliance_pct = (
                round(100.0 * (total - violated) / total, 1) if total else 100.0
            )

            cur.execute(
                f"""
                SELECT t.assigned_to AS agent_name,
                    COUNT(*)::int AS tickets_assigned,
                    COUNT(*) FILTER (WHERE {closed_sql})::int AS tickets_closed,
                    COUNT(*) FILTER (WHERE {breach_sql})::int AS sla_violations,
                    ROUND(
                        AVG(
                            CASE WHEN {closed_sql}
                            THEN EXTRACT(EPOCH FROM (
                                COALESCE(t.closed_at, t.updated_at) - t.created_at
                            )) / 3600.0
                            END
                        )::numeric, 2
                    ) AS avg_resolution_hours
                FROM tickets t
                WHERE {base_where} AND COALESCE(t.assigned_to,'') <> ''
                GROUP BY t.assigned_to
                ORDER BY tickets_closed DESC, tickets_assigned DESC
                """,
                tuple(base_params),
            )
            agent_rows = [_json_safe_row(dict(r)) for r in cur.fetchall()]

            cur.execute(
                """
                SELECT name, email FROM users
                WHERE LOWER(TRIM(COALESCE(role,''))) = 'manager'
                AND COALESCE(is_active, TRUE) = TRUE
                ORDER BY name NULLS LAST
                """
            )
            mgr_users = cur.fetchall()

            mgr_perf = []
            for mu in mgr_users:
                em = (mu.get("email") or "").strip()
                if not em:
                    continue
                mwhere = base_where + " AND EXISTS (SELECT 1 FROM ticket_approvals ta1 WHERE ta1.ticket_id = t.id AND LOWER(TRIM(ta1.manager_email)) = %s)"
                mparams = list(base_params) + [em.lower()]
                cur.execute(
                    f"""
                    SELECT
                        COUNT(*)::int AS team_tickets,
                        COUNT(*) FILTER (WHERE {closed_sql})::int AS closed_tickets,
                        COUNT(*) FILTER (WHERE {breach_sql})::int AS sla_violations,
                        ROUND(
                            100.0 * COUNT(*) FILTER (WHERE {breach_sql})::numeric
                            / NULLIF(COUNT(*)::numeric, 0), 1
                        ) AS sla_violations_pct
                    FROM tickets t
                    WHERE {mwhere}
                    """,
                    tuple(mparams),
                )
                mp = cur.fetchone() or {}
                cur.execute(
                    """
                    SELECT COUNT(*)::int AS n FROM ticket_approvals ta
                    WHERE LOWER(TRIM(ta.manager_email)) = %s
                    AND COALESCE(ta.status,'') <> 'pending'
                    AND ta.decided_at >= %s AND ta.decided_at < %s
                    """,
                    (em.lower(), start, end),
                )
                esc = int((cur.fetchone() or {}).get("n") or 0)
                mgr_perf.append(
                    {
                        "manager_name": mu.get("name") or em,
                        "manager_email": em,
                        "team_tickets": int(mp.get("team_tickets") or 0),
                        "closed_tickets": int(mp.get("closed_tickets") or 0),
                        "sla_violations": int(mp.get("sla_violations") or 0),
                        "sla_violations_pct": float(mp.get("sla_violations_pct") or 0)
                        if mp.get("sla_violations_pct") is not None
                        else 0.0,
                        "escalations_handled": esc,
                    }
                )
            mgr_perf.sort(key=lambda x: x["closed_tickets"], reverse=True)

            cur.execute(
                f"""
                SELECT t.category AS category_name,
                    COUNT(*)::int AS total_tickets,
                    COUNT(*) FILTER (WHERE {closed_sql})::int AS closed_tickets,
                    COUNT(*) FILTER (WHERE {breach_sql})::int AS sla_violations,
                    ROUND(
                        AVG(
                            CASE WHEN {closed_sql}
                            THEN EXTRACT(EPOCH FROM (
                                COALESCE(t.closed_at, t.updated_at) - t.created_at
                            )) / 3600.0
                            END
                        )::numeric, 2
                    ) AS avg_resolution_hours
                FROM tickets t
                WHERE {base_where}
                GROUP BY t.category
                ORDER BY total_tickets DESC
                """,
                tuple(base_params),
            )
            category_rows = [_json_safe_row(dict(r)) for r in cur.fetchall()]

            cur.execute(
                f"""
                SELECT
                    t.public_ticket_id,
                    t.category,
                    t.assigned_to AS agent_name,
                    t.priority,
                    t.status,
                    t.sla_resolution_due,
                    COALESCE(t.closed_at, t.updated_at) AS effective_end,
                    t.created_at,
                    (SELECT ta2.manager_email FROM ticket_approvals ta2
                     WHERE ta2.ticket_id = t.id
                     ORDER BY ta2.decided_at DESC NULLS LAST, ta2.id DESC
                     LIMIT 1) AS manager_email
                FROM tickets t
                WHERE {base_where} AND {breach_sql}
                ORDER BY t.sla_resolution_due ASC NULLS LAST
                LIMIT 500
                """,
                tuple(base_params),
            )
            viol = []
            now = datetime.now()
            for r in cur.fetchall():
                d = dict(r)
                due = d.get("sla_resolution_due")
                eff = d.get("effective_end")
                breach_minutes = None
                if due and eff:
                    breach_minutes = max(
                        0, int((eff - due).total_seconds() / 60)
                    )
                elif due:
                    breach_minutes = max(0, int((now - due).total_seconds() / 60))
                critical = breach_minutes is not None and breach_minutes >= 24 * 60
                viol.append(
                    {
                        "ticket_id": d.get("public_ticket_id"),
                        "category": d.get("category"),
                        "assigned_agent": d.get("agent_name"),
                        "manager_email": d.get("manager_email"),
                        "priority": d.get("priority"),
                        "status": d.get("status"),
                        "sla_breach_minutes": breach_minutes,
                        "sla_resolution_due": _json_safe_row(d.get("sla_resolution_due")),
                        "critical": critical,
                    }
                )

            cur.execute(
                f"""
                SELECT
                    t.customer_name,
                    t.customer_email,
                    COUNT(*)::int AS total_raised,
                    COUNT(*) FILTER (WHERE {closed_sql})::int AS closed_tickets,
                    COUNT(*) FILTER (WHERE {breach_sql})::int AS sla_violations
                FROM tickets t
                WHERE {base_where}
                GROUP BY t.customer_name, t.customer_email
                ORDER BY total_raised DESC
                LIMIT 100
                """,
                tuple(base_params),
            )
            cust_summaries = cur.fetchall()

            cur.execute(
                f"""
                SELECT t.customer_email, t.category, COUNT(*)::int AS c
                FROM tickets t
                WHERE {base_where}
                GROUP BY t.customer_email, t.category
                """,
                tuple(base_params),
            )
            cat_by_email = {}
            for r in cur.fetchall():
                em = (r.get("customer_email") or "").strip()
                if not em:
                    continue
                cat_by_email.setdefault(em, []).append(
                    (r.get("category") or "—", int(r["c"] or 0))
                )
            for em in cat_by_email:
                cat_by_email[em].sort(key=lambda x: -x[1])
            cust_rows = []
            for d in cust_summaries:
                em = (d.get("customer_email") or "").strip()
                top_cats = [x[0] for x in (cat_by_email.get(em) or [])[:3]]
                cust_rows.append(
                    {
                        "customer_name": d.get("customer_name"),
                        "customer_email": d.get("customer_email"),
                        "total_raised": int(d.get("total_raised") or 0),
                        "closed_tickets": int(d.get("closed_tickets") or 0),
                        "sla_violations": int(d.get("sla_violations") or 0),
                        "top_categories": top_cats,
                    }
                )

            cur.execute(
                f"""
                WITH tm AS (
                    SELECT DISTINCT ON (t.id)
                        t.id,
                        t.category,
                        t.assigned_to,
                        LOWER(TRIM(ta.manager_email)) AS mgr
                    FROM tickets t
                    LEFT JOIN ticket_approvals ta ON ta.ticket_id = t.id
                        AND COALESCE(ta.status,'') <> 'pending'
                    WHERE {base_where}
                    ORDER BY t.id, ta.decided_at DESC NULLS LAST, ta.id DESC
                )
                SELECT tm.category, tm.assigned_to AS agent_name,
                    MAX(COALESCE(NULLIF(TRIM(u.name), ''), tm.mgr, '—')) AS manager_name,
                    COUNT(*)::int AS closed_tickets
                FROM tm
                JOIN tickets t ON t.id = tm.id
                LEFT JOIN users u ON LOWER(TRIM(u.email)) = tm.mgr
                WHERE {closed_sql}
                AND COALESCE(tm.assigned_to,'') <> ''
                GROUP BY tm.category, tm.assigned_to, COALESCE(tm.mgr, '')
                ORDER BY tm.category, closed_tickets DESC
                """,
                tuple(base_params),
            )
            matrix_rows = [_json_safe_row(dict(r)) for r in cur.fetchall()]

            cur.execute(
                f"""
                SELECT date_trunc('day', t.created_at)::date AS d,
                    t.category,
                    COUNT(*)::int AS c
                FROM tickets t
                WHERE {base_where}
                GROUP BY 1, 2
                ORDER BY 1 ASC, 2
                """,
                tuple(base_params),
            )
            trend_raw = cur.fetchall()
            day_labels = sorted({str(r["d"]) for r in trend_raw})
            cat_set = sorted({r["category"] or "—" for r in trend_raw})
            trend_series = []
            by_day_cat = {}
            for r in trend_raw:
                k = (str(r["d"]), r["category"] or "—")
                by_day_cat[k] = int(r["c"] or 0)
            for cat in cat_set:
                trend_series.append(
                    {
                        "label": cat,
                        "data": [by_day_cat.get((d, cat), 0) for d in day_labels],
                    }
                )

            cur.execute(
                f"""
                SELECT date_trunc('day', COALESCE(t.closed_at, t.updated_at))::date AS d,
                    COUNT(*)::int AS total_closed,
                    COUNT(*) FILTER (WHERE NOT ({breach_sql}))::int AS compliant
                FROM tickets t
                WHERE {base_where} AND {closed_sql}
                GROUP BY 1
                ORDER BY 1 ASC
                """,
                tuple(base_params),
            )
            sla_trend = []
            for r in cur.fetchall():
                tot = int(r["total_closed"] or 0)
                ok = int(r["compliant"] or 0)
                sla_trend.append(
                    {
                        "date": str(r["d"]),
                        "compliance_pct": round(100.0 * ok / tot, 1) if tot else 100.0,
                        "closed": tot,
                    }
                )

            cur.execute(
                f"""
                SELECT COALESCE(t.priority,'—') AS priority, COUNT(*)::int AS c
                FROM tickets t
                WHERE {base_where}
                GROUP BY t.priority
                ORDER BY c DESC
                """,
                tuple(base_params),
            )
            priority_pie = [
                {"priority": r["priority"], "count": int(r["c"] or 0)}
                for r in cur.fetchall()
            ]

            cur.execute(
                f"""
                SELECT t.assigned_to AS agent_name,
                    t.category,
                    COUNT(*) FILTER (WHERE {closed_sql})::int AS closed_n
                FROM tickets t
                WHERE {base_where}
                AND COALESCE(t.assigned_to,'') <> ''
                GROUP BY t.assigned_to, t.category
                ORDER BY t.assigned_to, t.category
                """,
                tuple(base_params),
            )
            heat_raw = cur.fetchall()
            h_agents = sorted(
                {r["agent_name"] for r in heat_raw if r.get("agent_name")}
            )
            h_cats = sorted({r["category"] or "—" for r in heat_raw})
            heatmap = []
            cell_map = {
                (r["agent_name"], r["category"] or "—"): int(r["closed_n"] or 0)
                for r in heat_raw
            }
            max_h = max(cell_map.values(), default=1)
            for ag in h_agents:
                row = {"agent": ag, "cells": []}
                for cat in h_cats:
                    v = cell_map.get((ag, cat), 0)
                    row["cells"].append(
                        {
                            "category": cat,
                            "value": v,
                            "intensity": round(v / max_h, 3) if max_h else 0,
                        }
                    )
                heatmap.append(row)

            cur.execute(
                """
                SELECT name FROM users
                WHERE LOWER(TRIM(COALESCE(role,''))) IN ('agent', 'manager')
                AND COALESCE(is_active, TRUE) = TRUE
                ORDER BY name NULLS LAST
                """
            )
            opt_agents = [r["name"] for r in cur.fetchall() if r.get("name")]

            cur.execute(
                """
                SELECT DISTINCT LOWER(TRIM(manager_email)) AS e
                FROM ticket_approvals WHERE COALESCE(manager_email,'') <> ''
                """
            )
            appr_emails = [r["e"] for r in cur.fetchall()]
            cur.execute(
                """
                SELECT email, name FROM users
                WHERE LOWER(TRIM(COALESCE(role,''))) = 'manager'
                AND COALESCE(is_active, TRUE) = TRUE
                """
            )
            mgr_map = {((r.get("email") or "").lower().strip()): r.get("name") for r in cur.fetchall()}
            opt_managers = []
            seen_m = set()
            for e in appr_emails + list(mgr_map.keys()):
                if not e or e in seen_m:
                    continue
                seen_m.add(e)
                opt_managers.append(
                    {"value": e, "label": mgr_map.get(e) or e}
                )
            opt_managers.sort(key=lambda x: (x["label"] or "").lower())

            cur.execute(
                "SELECT DISTINCT category FROM tickets WHERE COALESCE(category,'') <> '' ORDER BY category"
            )
            opt_categories = [r["category"] for r in cur.fetchall()]

            cur.execute(
                """
                SELECT DISTINCT customer_email, customer_name FROM tickets
                WHERE COALESCE(customer_email,'') <> ''
                ORDER BY customer_name NULLS LAST
                LIMIT 2000
                """
            )
            opt_customers = [
                {
                    "value": (r.get("customer_email") or "").strip(),
                    "label": f"{r.get('customer_name') or '—'} <{r.get('customer_email')}>",
                }
                for r in cur.fetchall()
            ]

            cur.execute(
                """
                SELECT DISTINCT LOWER(TRIM(SPLIT_PART(COALESCE(customer_email,''), '@', 2))) AS dom
                FROM tickets
                WHERE POSITION('@' IN COALESCE(customer_email,'')) > 1
                AND COALESCE(customer_email,'') <> ''
                ORDER BY 1
                LIMIT 500
                """
            )
            opt_orgs = [r["dom"] for r in cur.fetchall() if r.get("dom")]

            top_agent = (agent_rows[0]["agent_name"] if agent_rows else None) or "—"
            top_manager = (mgr_perf[0]["manager_name"] if mgr_perf else None) or "—"

        payload = {
            "success": True,
            "range": {
                "preset": range_key,
                "start": start.isoformat(),
                "end": (end - timedelta(seconds=1)).isoformat(),
            },
            "summary": {
                "total_tickets": total,
                "closed_tickets": closed_n,
                "open_tickets": int(summ.get("open_n") or 0),
                "sla_violated": violated,
                "sla_compliance_pct": compliance_pct,
                "top_agent": top_agent,
                "top_manager": top_manager,
            },
            "agent_performance": agent_rows,
            "manager_performance": mgr_perf,
            "category_report": category_rows,
            "sla_violations": viol,
            "top_customers": cust_rows,
            "category_agent_manager_matrix": matrix_rows,
            "tickets_by_category_over_time": {
                "labels": day_labels,
                "series": trend_series,
            },
            "sla_compliance_trend": sla_trend,
            "tickets_by_priority": priority_pie,
            "heatmap_agent_category": {
                "agents": h_agents,
                "categories": h_cats,
                "rows": heatmap,
            },
            "filter_options": {
                "agents": opt_agents,
                "managers": opt_managers,
                "categories": opt_categories,
                "priorities": [
                    {"value": "low", "label": "Low"},
                    {"value": "medium", "label": "Medium"},
                    {"value": "high", "label": "High"},
                    {"value": "urgent", "label": "Urgent"},
                ],
                "statuses": [
                    {"value": "open", "label": "Open"},
                    {"value": "closed", "label": "Closed"},
                    {"value": "pending", "label": "Pending"},
                    {"value": "escalated", "label": "Escalated"},
                ],
                "customers": opt_customers,
                "organizations": opt_orgs,
            },
        }
        return jsonify(_json_safe_row(payload))
    finally:
        conn.close()


@app.route('/api/reports/agents', methods=['GET'])
def agent_reports():
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        # Get users from DB
        ensure_user_schema(cur)
        cur.execute(
            "SELECT name FROM users WHERE role = 'Agent' AND COALESCE(is_active, TRUE) = TRUE"
        )
        agents = [row['name'] for row in cur.fetchall()]

        reports = []
        for agent in agents:
            # Total assigned
            cur.execute("SELECT COUNT(*) as cnt FROM tickets WHERE assigned_to = %s", (agent,))
            total = cur.fetchone()['cnt']
            
            # Resolved
            cur.execute("SELECT COUNT(*) as cnt FROM tickets WHERE assigned_to = %s AND (status LIKE '%%Resolved%%' OR status LIKE '%%Closed%%')", (agent,))
            resolved = cur.fetchone()['cnt']
            
            # Escalated (High/Critical priorities that are active)
            cur.execute("SELECT COUNT(*) as cnt FROM tickets WHERE assigned_to = %s AND priority IN ('High', 'Enterprise Critical', 'Urgent') AND status NOT LIKE '%%Resolved%%' AND status NOT LIKE '%%Closed%%'", (agent,))
            escalated = cur.fetchone()['cnt']
            
            # Open (Assigned - Resolved)
            open_active = total - resolved

            productivity = 0
            if total > 0:
                productivity = round((resolved / total) * 100)
            
            reports.append({
                "agent_name": agent,
                "total_assigned": total,
                "resolved": resolved,
                "open_active": open_active,
                "escalated_active": escalated,
                "productivity": productivity
            })
            
    conn.close()
    return jsonify(reports)


def _should_start_embedded_mail_poller():
    """Avoid Werkzeug reloader parent + match debug/reloader edge cases."""
    if os.environ.get("WERKZEUG_RUN_PARENT") == "true":
        return False
    v = (os.environ.get("MAIL_TO_TICKET_START_WITH_APP") or "1").strip().lower()
    if v in ("0", "false", "no", "off"):
        return False
    if not app.debug:
        return True
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        return True
    return (
        os.environ.get("WERKZEUG_RUN_MAIN") is None
        and os.environ.get("WERKZEUG_RUN_PARENT") is None
    )


if __name__ == '__main__':
    if _should_start_embedded_mail_poller():
        try:
            import mail_to_ticket

            mail_to_ticket.start_embedded_poller()
        except Exception:
            app.logger.exception("Could not start embedded mail-to-ticket IMAP poller")
    app.run(port=5000, debug=True)

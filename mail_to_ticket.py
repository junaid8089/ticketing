#!/usr/bin/env python3
"""
Mail-to-ticket worker: IMAP poller that creates tickets or appends customer replies,
deduplicates by Message-ID, moves messages to Processed/Failed folders, and writes audit trails.

Run (same .env as the Flask app):
  python mail_to_ticket.py

Configure IMAP and folders via environment variables (see .env.example).
"""

from __future__ import annotations

import copy
import email.policy
import html as html_module
import imaplib
import json
import logging
import mimetypes
import os
import re
import secrets
import sys
import threading
import time
from datetime import datetime, timezone
from email.header import decode_header, make_header
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime, parseaddr
from typing import Any, Dict, List, Optional, Tuple

import psycopg2

try:
    from dotenv import load_dotenv

    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
except ImportError:
    pass

log = logging.getLogger("mail_to_ticket")

# Import portal app after dotenv
import psycopg2.extras

from email_templates import render_email_template, template_brand_placeholders
from mail_service import outbound_identity_from_branding, send_branded_multipart_email

import app as portal_app

_MAX_INLINE_BYTES = 12 * 1024 * 1024
_MAX_TOTAL_FETCH = int(os.environ.get("MAIL_TO_TICKET_MAX_BYTES", str(24 * 1024 * 1024)))


def _env_bool(key: str, default: bool = False) -> bool:
    v = (os.environ.get(key) or "").strip().lower()
    if not v:
        return default
    return v in ("1", "true", "yes", "on")


def _decode_mime_header(raw: Optional[str]) -> str:
    if raw is None:
        return ""
    try:
        return str(make_header(decode_header(str(raw))))
    except Exception:
        return str(raw)


def _html_to_text(html: str) -> str:
    if not html:
        return ""
    t = re.sub(r"(?is)<script[^>]*>.*?</script>", "", html)
    t = re.sub(r"(?is)<style[^>]*>.*?</style>", "", t)
    t = re.sub(r"(?i)<br\s*/?>", "\n", t)
    t = re.sub(r"(?i)</p\s*>", "\n\n", t)
    t = re.sub(r"<[^>]+>", "", t)
    return html_module.unescape(t).strip()


def _strip_reply_noise(text: str) -> str:
    if not text:
        return ""
    t = text.replace("\r\n", "\n")
    t = re.sub(
        r"(?ms)^-----Original Message-----.*",
        "",
        t,
    )
    t = re.sub(
        r"(?ms)^Begin forwarded message:.*",
        "",
        t,
    )
    lines = t.split("\n")
    cut = len(lines)
    for i, line in enumerate(lines):
        ls = line.strip()
        if ls.startswith(">"):
            cut = i
            break
        if re.match(r"^On .+ wrote:\s*$", ls, re.I):
            cut = i
            break
        if re.match(r"^Le .+ a écrit\s*:\s*$", ls, re.I):
            cut = i
            break
        if re.match(r"^Am .+ schrieb.*:\s*$", ls, re.I):
            cut = i
            break
        if ls == "--":
            cut = i
            break
        if re.match(r"^_{3,}$", ls):
            cut = i
            break
        if "disclaimer" in ls.lower() and i > 5:
            cut = i
            break
    out = "\n".join(lines[:cut]).strip()
    out = re.sub(r"\n{3,}", "\n\n", out)
    return out.strip()


def _public_ticket_id_regexes(merged: dict) -> List[re.Pattern]:
    t = merged.get("ticket", {}) or {}
    prefix = re.escape(str(t.get("prefix") or "TKT").strip()[:64] or "TKT")
    sep_raw = t.get("separator")
    sep = re.escape((str(sep_raw) if sep_raw is not None else "-")[:3] or "-")
    ds = portal_app._ticket_id_date_segment(t)
    if ds == "none":
        mid = r"\d{1,12}"
    elif ds == "year":
        mid = r"\d{4}" + sep + r"\d{1,12}"
    elif ds == "ymd":
        mid = r"\d{8}" + sep + r"\d{1,12}"
    else:
        cust = re.escape(str(t.get("customDateSegment") or "").strip()[:16])
        mid = (cust + sep + r"\d{1,12}") if cust else r"\d{4}" + sep + r"\d{1,12}"
    core = prefix + sep + mid
    return [
        re.compile(r"\[\s*(" + core + r")\s*\]", re.I),
        re.compile(r"\b(" + core + r")\b", re.I),
    ]


def _extract_public_ids(subject: str, refs: str, in_reply_to: str, patterns: List[re.Pattern]) -> List[str]:
    hay = " ".join(
        x
        for x in (
            subject or "",
            refs or "",
            in_reply_to or "",
        )
        if x
    )
    found: List[str] = []
    seen = set()
    for pat in patterns:
        for m in pat.finditer(hay):
            pid = (m.group(1) or "").strip()
            if pid and pid.lower() not in seen:
                seen.add(pid.lower())
                found.append(pid)
    return found


def _normalize_subject(subj: str) -> str:
    s = _decode_mime_header(subj).strip()
    while True:
        ns = re.sub(r"(?i)^\s*(re|fwd|fw|aw|wg)\s*:\s*", "", s).strip()
        if ns == s:
            break
        s = ns
    return s[:255]


def _sender_identity(msg: Message) -> Tuple[str, str]:
    from_raw = msg.get("From") or ""
    name, addr = parseaddr(_decode_mime_header(from_raw))
    addr = (addr or "").strip().lower()
    name = (name or "").strip() or (addr.split("@")[0] if "@" in addr else "Customer")
    return name[:250], addr


def _collect_cc_emails(msg: Message) -> List[str]:
    raw = ", ".join(
        filter(
            None,
            [
                msg.get("Cc"),
                msg.get("To"),
            ],
        )
    )
    pairs = getaddresses([raw])
    out = []
    seen = set()
    drop = (os.environ.get("MAIL_IMAP_USER") or os.environ.get("MAIL_USER") or "").strip().lower()
    for _n, em in pairs:
        e = (em or "").strip().lower()
        if e and "@" in e and e not in seen and (not drop or e != drop):
            seen.add(e)
            out.append(e)
    return out


def _message_id(msg: Message) -> str:
    mid = (msg.get("Message-ID") or "").strip()
    if not mid:
        return ""
    return mid.strip("<>")[:998]


def _received_timestamp(msg: Message) -> datetime:
    for key in ("Date",):
        ds = msg.get(key)
        if not ds:
            continue
        try:
            dt = parsedate_to_datetime(ds)
            if dt.tzinfo:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
        except (TypeError, ValueError):
            continue
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _bounce_like(addr: str) -> bool:
    a = (addr or "").lower()
    if not a:
        return True
    if "mailer-daemon" in a or "postmaster" in a:
        return True
    if a.startswith("noreply") or a.startswith("no-reply"):
        return True
    return False


def _auto_submitted(msg: Message) -> bool:
    v = (msg.get("Auto-Submitted") or "").strip().lower()
    if v and v != "no":
        return True
    if (msg.get("Precedence") or "").strip().lower() in ("bulk", "list", "junk"):
        return True
    return False


def _extract_body_and_files(
    msg: Message,
) -> Tuple[str, List[Dict[str, Any]], Dict[str, str]]:
    """
    Returns (plain_text_for_ticket, attachment_specs, cid_to_filename).
    attachment_specs: {raw_bytes, filename, mime, is_inline}
    """
    plain_parts: List[str] = []
    html_parts: List[str] = []
    files: List[Dict[str, Any]] = []
    cid_map: Dict[str, str] = {}

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "multipart/alternative" or ctype.startswith("multipart/"):
                continue
            disp = (part.get_content_disposition() or "").lower()
            is_inline = disp == "inline"
            is_attachment = disp == "attachment"
            payload = part.get_payload(decode=True)
            if not isinstance(payload, (bytes, bytearray)):
                continue
            plen = len(payload)
            if plen > _MAX_INLINE_BYTES:
                log.warning("Skipping oversized part (%s bytes): %s", plen, ctype)
                continue
            if ctype == "text/plain" and not is_attachment:
                try:
                    plain_parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))
                except Exception:
                    plain_parts.append(payload.decode("utf-8", errors="replace"))
            elif ctype == "text/html" and not is_attachment:
                try:
                    html_parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))
                except Exception:
                    html_parts.append(payload.decode("utf-8", errors="replace"))
            elif ctype.startswith("image/") or is_inline or is_attachment:
                cid = (part.get("Content-ID") or "").strip("<>").lower()
                fname = part.get_filename()
                if fname:
                    fname = os.path.basename(_decode_mime_header(fname))[:220]
                else:
                    ext = mimetypes.guess_extension(ctype or "") or ".bin"
                    fname = f"part-{secrets.token_hex(4)}{ext}"
                files.append(
                    {
                        "raw": bytes(payload),
                        "filename": fname or "attachment",
                        "mime": ctype or "application/octet-stream",
                        "is_inline": is_inline or bool(cid),
                        "cid": cid,
                    }
                )
                if cid:
                    cid_map[cid] = fname
    else:
        payload = msg.get_payload(decode=True)
        ctype = msg.get_content_type()
        if isinstance(payload, (bytes, bytearray)):
            if ctype == "text/html":
                try:
                    html_parts.append(payload.decode(msg.get_content_charset() or "utf-8", errors="replace"))
                except Exception:
                    html_parts.append(payload.decode("utf-8", errors="replace"))
            else:
                try:
                    plain_parts.append(payload.decode(msg.get_content_charset() or "utf-8", errors="replace"))
                except Exception:
                    plain_parts.append(payload.decode("utf-8", errors="replace"))

    body = "\n\n".join(p for p in plain_parts if p.strip())
    if not body.strip() and html_parts:
        body = _html_to_text("\n".join(html_parts))
    # Replace cid: references in HTML-derived text with filenames
    for cid, fn in cid_map.items():
        body = re.sub(
            r"(?i)\bcid:" + re.escape(cid) + r"\b",
            f"[inline:{fn}]",
            body,
        )
    body = _strip_reply_noise(body)
    return body.strip() or "(No body text)", files, cid_map


def _save_bytes_attachments(ticket_id: int, specs: List[Dict[str, Any]]) -> List[dict]:
    """Same JSON shape as save_ticket_uploaded_files (path relative to UPLOAD_ROOT)."""
    saved: List[dict] = []
    if not specs:
        return saved
    tdir = os.path.join(portal_app.UPLOAD_ROOT, str(ticket_id))
    os.makedirs(tdir, exist_ok=True)
    from werkzeug.utils import secure_filename

    for spec in specs:
        raw = spec.get("raw")
        if not isinstance(raw, (bytes, bytearray)):
            continue
        raw_name = os.path.basename(str(spec.get("filename") or "file")) or "file"
        safe = secure_filename(raw_name) or "file"
        uniq = secrets.token_hex(8)
        stored_name = f"{uniq}_{safe}"
        full_path = os.path.join(tdir, stored_name)
        with open(full_path, "wb") as fh:
            fh.write(raw)
        rel = f"{ticket_id}/{stored_name}"
        mime = spec.get("mime") or mimetypes.guess_type(raw_name)[0] or "application/octet-stream"
        saved.append({"name": raw_name, "path": rel, "mime": mime})
    return saved


def _merge_cc_field(existing: str, new_addrs: List[str]) -> str:
    parts = portal_app._parse_cc(existing)
    seen = {p.lower() for p in parts}
    for a in new_addrs:
        al = a.lower()
        if al not in seen and "@" in al:
            seen.add(al)
            parts.append(a.strip())
    return ", ".join(parts) if parts else ""


def _is_waiting_on_customer(status: Optional[str]) -> bool:
    s = (status or "").lower()
    return "waiting" in s and "customer" in s


def ensure_inbound_mail_schema(cur) -> None:
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS inbound_email_log (
            id BIGSERIAL PRIMARY KEY,
            message_id VARCHAR(998) NOT NULL UNIQUE,
            ticket_id INTEGER REFERENCES tickets(id) ON DELETE SET NULL,
            outcome VARCHAR(32) NOT NULL,
            error_detail TEXT,
            from_address TEXT,
            subject_snapshot TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    cur.execute(
        "ALTER TABLE tickets ADD COLUMN IF NOT EXISTS last_customer_mail_at TIMESTAMP"
    )


def _ticket_audit_log(cur, ticket_id: int, action: str, performed_by: str) -> None:
    cur.execute(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'ticket_audit_log')"
    )
    row = cur.fetchone()
    ok = False
    if row:
        ok = row.get("exists") if isinstance(row, dict) else row[0]
    if not ok:
        return
    cur.execute(
        "INSERT INTO ticket_audit_log (ticket_id, action, performed_by) VALUES (%s, %s, %s)",
        (ticket_id, action[:2000], performed_by[:500]),
    )


def _assignee_notify_emails(cur, assignee_name: str) -> List[str]:
    an = (assignee_name or "").strip()
    if not an:
        return []
    cur.execute(
        """
        SELECT DISTINCT TRIM(email) FROM users
        WHERE LOWER(TRIM(name)) = LOWER(TRIM(%s))
          AND COALESCE(is_active, TRUE) = TRUE
          AND POSITION('@' IN TRIM(COALESCE(email, ''))) > 0
        """,
        (an,),
    )
    return [r[0].strip() for r in (cur.fetchall() or []) if r and r[0]]


def _notify_assignee_inbound_reply(
    merged: dict,
    ticket_row: dict,
    from_email: str,
    excerpt: str,
    portal_base: str,
) -> None:
    tmpl = (merged.get("emailTemplates") or {}).get("staff_inbound_customer_reply") or {}
    if not tmpl.get("enabled", True):
        return
    assignee = (ticket_row.get("assigned_to") or "").strip()
    conn = portal_app.get_db()
    try:
        with conn.cursor() as cur:
            portal_app.ensure_user_schema(cur)
            targets = _assignee_notify_emails(cur, assignee)
            if not targets:
                targets = portal_app._staff_emails_for_notify(cur)
    finally:
        conn.close()
    if not targets:
        return
    excerpt = (excerpt or "").strip()
    if len(excerpt) > 4000:
        excerpt = excerpt[:4000] + "…"
    ctx = {
        "ticket_id": ticket_row.get("public_ticket_id") or "—",
        "subject": ticket_row.get("subject") or "—",
        "from_email": from_email or "—",
        "assigned_to": assignee or "Unassigned",
        "mail_excerpt": excerpt or "—",
        "ticket_url": f"{portal_base}/agent-dashboard.html" if portal_base else "",
        "customer_portal_url": portal_app._customer_ticket_view_url(
            portal_base, ticket_row.get("public_ticket_id")
        ),
        **template_brand_placeholders(merged),
    }
    subj = render_email_template(tmpl.get("subject"), ctx)[:200]
    body = render_email_template(tmpl.get("body"), ctx)
    bdict = portal_app._branding_dict_for_email(merged)
    for em in targets:
        ok, err = send_branded_multipart_email([em], subj, body, bdict)
        if not ok:
            log.warning("Inbound-reply notify to %s failed: %s", em, err)


def _imap_connect() -> imaplib.IMAP4_SSL:
    host = (os.environ.get("MAIL_IMAP_HOST") or "").strip()
    port = int(os.environ.get("MAIL_IMAP_PORT") or "993")
    user = (os.environ.get("MAIL_IMAP_USER") or os.environ.get("MAIL_USER") or "").strip()
    password = os.environ.get("MAIL_IMAP_PASSWORD") or os.environ.get("MAIL_PASSWORD") or ""
    if not host or not user or not password:
        raise RuntimeError(
            "IMAP not configured: set MAIL_IMAP_HOST, MAIL_IMAP_USER, MAIL_IMAP_PASSWORD "
            "(or reuse MAIL_USER / MAIL_PASSWORD)."
        )
    imap = imaplib.IMAP4_SSL(host, port, timeout=120)
    imap.login(user, password)
    return imap


def _imap_utf7_mailbox(name: str) -> str:
    """
    Modified UTF-7 (RFC 3501) for IMAP mailbox names.
    Python 3.12+ registers ``utf-7-imap``; some builds omit it (e.g. certain Windows installs).
    ASCII-only names (INBOX, PortalProcessed) are valid without encoding.
    """
    if not name:
        return name
    for codec in ("utf-7-imap", "imap4-utf-7"):
        try:
            return name.encode(codec).decode("ascii")
        except LookupError:
            continue
    try:
        name.encode("ascii")
    except UnicodeEncodeError as ex:
        raise LookupError(
            "This Python build has no IMAP UTF-7 codec (utf-7-imap / imap4-utf-7). "
            "Use only ASCII characters in MAIL_IMAP_MAILBOX / folder names, or use Python 3.12+."
        ) from ex
    return name


def _imap_list_mailbox_names(imap: imaplib.IMAP4_SSL) -> List[str]:
    """Return decoded mailbox names from LIST (best-effort)."""
    out: List[str] = []
    typ, dat = imap.list()
    if typ != "OK" or not dat:
        return out
    for item in dat:
        if not isinstance(item, (bytes, bytearray)):
            continue
        try:
            s = bytes(item).decode("utf-8", errors="replace")
        except Exception:
            continue
        m = re.search(r'"\s*([^"]+)\s*"\s*$', s)
        if m:
            out.append(m.group(1).strip())
        else:
            parts = s.rsplit(None, 1)
            if len(parts) == 2 and parts[1] not in ("NIL", "nil"):
                out.append(parts[1].strip().strip('"'))
    return out


def _imap_folder_exists(imap: imaplib.IMAP4_SSL, logical: str) -> bool:
    logi = (logical or "").strip().lower()
    if not logi:
        return False
    for n in _imap_list_mailbox_names(imap):
        nl = n.lower()
        if nl == logi or nl.endswith("/" + logi) or nl.endswith("." + logi):
            return True
    return False


def _imap_destination_candidates(logical_name: str) -> List[str]:
    """
    Zoho (and others) often store user folders as INBOX.Subfolder; flat LIST may still work.
    Try logical name first, then INBOX.{name} / Inbox.{name}.
    """
    name = (logical_name or "").strip()
    if not name:
        return []
    cands = [name]
    low = name.lower()
    if not low.startswith("inbox."):
        for prefix in ("INBOX.", "Inbox."):
            cands.append(prefix + name)
    seen = set()
    out = []
    for c in cands:
        k = c.lower()
        if k not in seen:
            seen.add(k)
            out.append(c)
    extra = (os.environ.get("MAIL_IMAP_FOLDER_ALT_PATHS") or "").strip()
    if extra:
        for p in extra.split(","):
            p = p.strip()
            if p and p.lower() not in seen:
                seen.add(p.lower())
                out.append(p)
    return out


def _imap_ensure_folder(imap: imaplib.IMAP4_SSL, folder: str) -> None:
    folder = folder.strip()
    if not folder:
        return
    for cand in _imap_destination_candidates(folder):
        if _imap_folder_exists(imap, cand):
            return
        enc = _imap_utf7_mailbox(cand)
        typ, dat = imap.create(enc)
        if typ == "OK":
            return
        log.debug("IMAP CREATE %s: %s %s", cand, typ, dat)
    log.warning(
        "Could not create or find IMAP folder %r (tried %s). "
        "In Zoho: create the folder in webmail and enable it under Mail Accounts → IMAP → Folder settings.",
        folder,
        _imap_destination_candidates(folder),
    )


def _uid_str(uid) -> str:
    if isinstance(uid, bytes):
        return uid.decode("ascii", errors="replace").strip()
    return str(uid).strip()


def _imap_has_move(imap: imaplib.IMAP4_SSL) -> bool:
    try:
        typ, dat = imap.capability()
        if typ != "OK" or not dat:
            return False
        cap = dat[0]
        if isinstance(cap, bytes):
            return b"MOVE" in cap.upper()
        return "MOVE" in str(cap).upper()
    except Exception:
        return False


def _imap_move_append_fallback(
    imap: imaplib.IMAP4_SSL,
    uid,
    dest_encoded: str,
    raw_rfc822: bytes,
    source_mailbox_utf7: str,
) -> bool:
    """COPY+STORE failed — append full message to dest, then delete from source."""
    try:
        date_arg = imaplib.Time2Internaldate(time.time())
        typ, dat = imap.append(dest_encoded, None, date_arg, raw_rfc822)
        if typ != "OK":
            log.error("IMAP APPEND to %s failed: %s", dest_encoded, dat)
            return False
        typ, _ = imap.select(source_mailbox_utf7, readonly=False)
        if typ != "OK":
            log.error("IMAP re-select %s after APPEND failed", source_mailbox_utf7)
            return False
        uid_s = _uid_str(uid)
        typ, dat = imap.uid("STORE", uid_s, "+FLAGS.SILENT", r"(\Deleted)")
        if typ != "OK":
            log.error("IMAP STORE \\Deleted uid=%s failed: %s", uid_s, dat)
            return False
        imap.expunge()
        return True
    except Exception:
        log.exception("APPEND fallback move failed")
        return False


def _imap_move(
    imap: imaplib.IMAP4_SSL,
    uid,
    dest_folder: str,
    raw_rfc822: Optional[bytes] = None,
    source_mailbox_utf7: Optional[str] = None,
) -> bool:
    dest_folder = (dest_folder or "").strip()
    if not dest_folder:
        return False
    uid_s = _uid_str(uid)
    src = source_mailbox_utf7 or _imap_utf7_mailbox(
        (os.environ.get("MAIL_IMAP_MAILBOX") or "INBOX").strip()
    )

    last_err = None
    use_move = _imap_has_move(imap)
    for cand in _imap_destination_candidates(dest_folder):
        enc = _imap_utf7_mailbox(cand)
        if use_move:
            typ, dat = imap.uid("MOVE", uid_s, enc)
            if typ == "OK":
                return True
            last_err = dat
            log.warning("IMAP MOVE uid=%s to %s failed: %s", uid_s, cand, dat)
        typ, dat = imap.uid("COPY", uid_s, enc)
        if typ == "OK":
            typ2, dat2 = imap.uid("STORE", uid_s, "+FLAGS.SILENT", r"(\Deleted)")
            if typ2 != "OK":
                log.warning("IMAP STORE \\Deleted uid=%s: %s", uid_s, dat2)
            imap.expunge()
            return True
        last_err = dat
        log.warning("IMAP COPY uid=%s to %s failed: %s", uid_s, cand, dat)

    if raw_rfc822:
        for cand in _imap_destination_candidates(dest_folder):
            enc = _imap_utf7_mailbox(cand)
            if _imap_move_append_fallback(imap, uid_s, enc, raw_rfc822, src):
                log.info("Moved uid=%s to %s via APPEND fallback", uid_s, cand)
                return True

    log.error(
        "IMAP could not move uid=%s to %r (last server data: %s). "
        "Zoho: enable destination folders for IMAP in webmail settings, or set MAIL_IMAP_FOLDER_ALT_PATHS.",
        uid_s,
        dest_folder,
        last_err,
    )
    if _env_bool("MAIL_TO_TICKET_PURGE_ON_MOVE_FAIL", False):
        try:
            imap.select(src, readonly=False)
            typ, dat = imap.uid("STORE", uid_s, "+FLAGS.SILENT", r"(\Deleted)")
            if typ == "OK":
                imap.expunge()
                log.warning(
                    "MAIL_TO_TICKET_PURGE_ON_MOVE_FAIL: removed uid=%s from inbox after move failure",
                    uid_s,
                )
                return True
        except Exception:
            log.exception("purge-on-move-fail for uid=%s", uid_s)
    return False


def _portal_base() -> str:
    return (os.environ.get("PORTAL_PUBLIC_URL") or "").strip().rstrip("/")


def process_one_message_bytes(raw: bytes) -> Tuple[str, Optional[int], Optional[str]]:
    """
    Core processor: returns (outcome, ticket_id, error_message).
    outcome: success | duplicate | failed | skipped
    """
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    mid = _message_id(msg)
    if not mid:
        return "failed", None, "Missing Message-ID"

    from_name, from_addr = _sender_identity(msg)
    if _bounce_like(from_addr) or _auto_submitted(msg):
        return "skipped", None, "Auto-generated or bounce message"

    domain_allow = (os.environ.get("MAIL_TO_TICKET_DOMAIN_ALLOWLIST") or "").strip()
    if domain_allow:
        allowed = {d.strip().lower().lstrip("@") for d in domain_allow.split(",") if d.strip()}
        dom = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
        if dom not in allowed:
            return "skipped", None, f"Sender domain not in allowlist ({dom})"

    subject_raw = msg.get("Subject") or ""
    subject_dec = _decode_mime_header(subject_raw)
    refs = msg.get("References") or ""
    irt = msg.get("In-Reply-To") or ""
    recv_ts = _received_timestamp(msg)
    cc_list = _collect_cc_emails(msg)
    body, file_specs, _cid_map = _extract_body_and_files(msg)

    conn = None
    try:
        conn = portal_app.get_db()
    except Exception:
        log.exception("database connection failed")
        return "failed", None, "Database connection failed"

    prev_ac = conn.autocommit
    conn.autocommit = False
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            portal_app.ensure_portal_settings(cur)
            portal_app.ensure_ticket_sla_columns(cur)
            portal_app.ensure_ticket_replies_table(cur)
            ensure_inbound_mail_schema(cur)

            cur.execute(
                """
                INSERT INTO inbound_email_log (message_id, outcome, from_address, subject_snapshot)
                VALUES (%s, 'processing', %s, %s)
                ON CONFLICT (message_id) DO NOTHING
                RETURNING id
                """,
                (mid, from_addr, subject_dec[:500]),
            )
            row = cur.fetchone()
            if not row or row.get("id") is None:
                conn.rollback()
                conn.autocommit = prev_ac
                return "duplicate", None, None

            cur.execute("SELECT settings FROM portal_settings WHERE id = 1")
            srow = cur.fetchone()
            merged = portal_app.merge_portal_settings(srow["settings"] if srow else None)
            patterns = _public_ticket_id_regexes(merged)
            candidates = _extract_public_ids(subject_dec, refs, irt, patterns)

            ticket_row = None
            for pid in candidates:
                cur.execute(
                    "SELECT * FROM tickets WHERE public_ticket_id = %s LIMIT 1",
                    (pid,),
                )
                ticket_row = cur.fetchone()
                if ticket_row:
                    break

            if ticket_row:
                tid = int(ticket_row["id"])
                cust = (ticket_row.get("customer_email") or "").strip().lower()
                cc_field = (ticket_row.get("cc_emails") or "").strip().lower()
                cc_norm = [x.strip().lower() for x in portal_app._parse_cc(cc_field)]
                allowed = {cust} if cust and "@" in cust else set()
                allowed.update(cc_norm)
                if from_addr not in allowed:
                    raise ValueError(
                        f"Sender {from_addr} is not the ticket requester or CC for {ticket_row.get('public_ticket_id')}"
                    )

                reopen_note = None
                st = ticket_row.get("status") or ""
                new_status = st
                if portal_app._ticket_status_allows_customer_reopen(
                    st
                ) or portal_app._status_is_closed_or_resolved(st):
                    new_status = "🔁 Reopened"
                    reopen_note = body

                sla_first = ticket_row.get("sla_first_response_due")
                sla_res = ticket_row.get("sla_resolution_due")
                if _is_waiting_on_customer(st) or new_status == "🔁 Reopened":
                    sla_first, sla_res = portal_app.sla_due_datetimes(
                        merged,
                        ticket_row.get("priority") or "Medium",
                        anchor_dt=recv_ts,
                    )

                reply_header = "[Via email]\n"
                reply_header += f"From: {from_name} <{from_addr}>\n"
                if cc_list:
                    reply_header += "Cc: " + ", ".join(cc_list) + "\n"
                reply_header += f"Message-ID: <{mid}>\n\n"
                full_msg = reply_header + body

                cur.execute(
                    """
                    INSERT INTO ticket_replies (ticket_id, sender_type, sender_email, message)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (tid, "Customer", from_addr, full_msg[:500000]),
                )

                new_cc = _merge_cc_field(ticket_row.get("cc_emails") or "", cc_list)
                set_parts = [
                    "updated_at = NOW()",
                    "last_customer_mail_at = %s",
                    "cc_emails = %s",
                ]
                vals: List[Any] = [recv_ts, new_cc]
                if new_status != st:
                    set_parts.append("status = %s")
                    vals.append(new_status)
                if _is_waiting_on_customer(st) or new_status == "🔁 Reopened":
                    set_parts.append("sla_first_response_due = %s")
                    vals.append(sla_first)
                    set_parts.append("sla_resolution_due = %s")
                    vals.append(sla_res)
                vals.append(tid)
                cur.execute(
                    "UPDATE tickets SET " + ", ".join(set_parts) + " WHERE id = %s",
                    tuple(vals),
                )

                saved = _save_bytes_attachments(tid, file_specs)
                if saved:
                    ad = ticket_row.get("attachments_data")
                    if isinstance(ad, str):
                        try:
                            ad = json.loads(ad)
                        except json.JSONDecodeError:
                            ad = []
                    if not isinstance(ad, list):
                        ad = []
                    merged_att = ad + saved
                    meta_csv = ",".join(x["name"] for x in merged_att)
                    cur.execute(
                        "UPDATE tickets SET attachments_data = %s::jsonb, attachments_meta = %s WHERE id = %s",
                        (json.dumps(merged_att), meta_csv, tid),
                    )

                _ticket_audit_log(
                    cur,
                    tid,
                    f"Inbound email appended (Message-ID {mid}). Subject: {subject_dec[:200]}",
                    "Mail-to-ticket",
                )

                cur.execute(
                    """
                    UPDATE inbound_email_log
                    SET outcome = %s, ticket_id = %s, error_detail = NULL
                    WHERE message_id = %s
                    """,
                    ("success", tid, mid),
                )
                merged_snapshot = copy.deepcopy(merged)
                ticket_snapshot = dict(ticket_row)
                ticket_snapshot["status"] = new_status
                conn.commit()
                conn.autocommit = prev_ac

                if new_status == "🔁 Reopened" and reopen_note:
                    portal_app._notify_staff_ticket_reopened_async(
                        ticket_snapshot,
                        reopen_note,
                        _portal_base(),
                    )
                _notify_assignee_inbound_reply(
                    merged_snapshot,
                    ticket_snapshot,
                    from_addr,
                    body,
                    _portal_base(),
                )
                return "success", tid, None

            # New ticket
            subj = _normalize_subject(subject_dec) or "(No subject)"
            desc = body[:500000]
            max_attempts = 48
            new_id = None
            public_id = None
            for _ in range(max_attempts):
                cur.execute(
                    "UPDATE portal_settings SET ticket_seq = ticket_seq + 1 WHERE id = 1 RETURNING ticket_seq, settings"
                )
                row = cur.fetchone()
                seq_num = int(row["ticket_seq"])
                merged_row = portal_app.merge_portal_settings(row["settings"])
                public_id = portal_app.build_public_ticket_id(merged_row, seq_num)
                sla_first, sla_res = portal_app.sla_due_datetimes(
                    merged_row,
                    "Medium",
                    anchor_dt=recv_ts,
                )
                cur.execute("SAVEPOINT sp_m2t_create")
                try:
                    cur.execute(
                        """
                        INSERT INTO tickets (
                            public_ticket_id, customer_name, customer_email, cc_emails, phone,
                            priority, category, subject, description, status, attachments_meta,
                            sla_first_response_due, sla_resolution_due, attachments_data
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, '🆕 Submitted', %s, %s, %s, %s::jsonb)
                        RETURNING id
                        """,
                        (
                            public_id,
                            from_name,
                            from_addr,
                            ", ".join(cc_list) if cc_list else "",
                            "",
                            "Medium",
                            "Email",
                            subj,
                            desc,
                            "",
                            sla_first,
                            sla_res,
                            json.dumps([]),
                        ),
                    )
                    new_id = int(cur.fetchone()["id"])
                    cur.execute("RELEASE SAVEPOINT sp_m2t_create")
                    break
                except psycopg2.IntegrityError:
                    cur.execute("ROLLBACK TO SAVEPOINT sp_m2t_create")

            if new_id is None or not public_id:
                raise RuntimeError("Could not allocate unique ticket id")

            assignee_pick, new_assign = portal_app._next_auto_assignee(cur, merged_row, "Medium")
            if assignee_pick:
                cur.execute(
                    "UPDATE tickets SET assigned_to = %s WHERE id = %s",
                    (assignee_pick, new_id),
                )
                portal_app._persist_assignment_state(cur, new_assign)

            saved = _save_bytes_attachments(new_id, file_specs)
            if saved:
                meta_csv = ",".join(s["name"] for s in saved)
                cur.execute(
                    "UPDATE tickets SET attachments_data = %s::jsonb, attachments_meta = %s WHERE id = %s",
                    (json.dumps(saved), meta_csv, new_id),
                )

            cur.execute(
                "UPDATE tickets SET last_customer_mail_at = %s, updated_at = NOW() WHERE id = %s",
                (recv_ts, new_id),
            )

            _ticket_audit_log(
                cur,
                new_id,
                f"Ticket created from inbound email (Message-ID {mid}). Subject: {subj[:200]}",
                "Mail-to-ticket",
            )

            cur.execute(
                """
                UPDATE inbound_email_log
                SET outcome = %s, ticket_id = %s, error_detail = NULL
                WHERE message_id = %s
                """,
                ("success", new_id, mid),
            )

            merged_snapshot = copy.deepcopy(merged_row)
            portal_base = _portal_base()
            assign_ack = None
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
                and portal_app._customer_email_present((fin.get("customer_email") or "").strip())
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
                assign_ack = {
                    "customer_email": (fin.get("customer_email") or "").strip(),
                    "customer_name": fin.get("customer_name") or "Customer",
                    "cc_emails": fin.get("cc_emails") or "",
                    "public_ticket_id": fin.get("public_ticket_id") or public_id,
                    "ticket_subject": fin.get("subject") or subj,
                    "etr": fin.get("expected_resolution"),
                    "analysis": fin.get("primary_analysis"),
                    "status": fin.get("status"),
                    "assignee_name": an,
                    "assignee_role_label": assignee_role_label,
                    "settings": merged_snapshot,
                }

            conn.commit()
            conn.autocommit = prev_ac

            portal_app._notify_staff_new_ticket_async(
                merged_snapshot,
                public_id,
                subj,
                "Medium",
                "Email",
                from_name,
                from_addr,
                desc,
                assignee_pick,
                portal_base,
            )
            if assign_ack:
                portal_app._notify_customer_ticket_assigned_from_payload_async(
                    assign_ack, portal_base
                )

            return "success", new_id, None

    except Exception as ex:
        log.exception("process_one_message_bytes failed")
        try:
            conn.rollback()
        except Exception:
            pass
        try:
            conn.autocommit = prev_ac
            with conn.cursor() as cur:
                ensure_inbound_mail_schema(cur)
                cur.execute(
                    """
                    INSERT INTO inbound_email_log (message_id, outcome, error_detail, from_address, subject_snapshot)
                    VALUES (%s, 'failed', %s, %s, %s)
                    ON CONFLICT (message_id) DO UPDATE
                    SET outcome = EXCLUDED.outcome,
                        error_detail = EXCLUDED.error_detail
                    """,
                    (
                        mid,
                        str(ex)[:4000],
                        from_addr,
                        (subject_dec[:500] if isinstance(subject_dec, str) else ""),
                    ),
                )
            conn.commit()
        except Exception:
            log.exception("could not write inbound_email_log failure row")
        return "failed", None, str(ex)
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


_embedded_poller_thread: Optional[threading.Thread] = None
_embedded_poller_lock = threading.Lock()


def _embedded_poller_loop() -> None:
    interval = float(os.environ.get("MAIL_TO_TICKET_POLL_INTERVAL") or "60")
    while True:
        try:
            if not _env_bool("MAIL_TO_TICKET_ENABLED", True):
                time.sleep(interval)
                continue
            poll_once()
        except Exception:
            log.exception("poll_once error")
        time.sleep(max(5.0, interval))


def start_embedded_poller() -> None:
    """
    Run the IMAP poller in a daemon thread. Used when starting the API with ``python app.py``
    so mail-to-ticket runs in the same process. For production you can still use ``python mail_to_ticket.py``
    instead and set MAIL_TO_TICKET_START_WITH_APP=0 here.
    """
    global _embedded_poller_thread
    if not _env_bool("MAIL_TO_TICKET_START_WITH_APP", True):
        return
    if not _env_bool("MAIL_TO_TICKET_ENABLED", True):
        return
    if not (os.environ.get("MAIL_IMAP_HOST") or "").strip():
        try:
            portal_app.app.logger.info(
                "Mail-to-ticket: MAIL_IMAP_HOST not set; embedded poller not started."
            )
        except Exception:
            pass
        return
    with _embedded_poller_lock:
        if _embedded_poller_thread is not None and _embedded_poller_thread.is_alive():
            return
        _embedded_poller_thread = threading.Thread(
            target=_embedded_poller_loop,
            name="mail-to-ticket",
            daemon=True,
        )
        _embedded_poller_thread.start()
    try:
        portal_app.app.logger.info(
            "Mail-to-ticket: embedded IMAP poller thread started (interval %ss).",
            os.environ.get("MAIL_TO_TICKET_POLL_INTERVAL") or "60",
        )
    except Exception:
        log.info("Embedded mail-to-ticket poller thread started.")


def poll_once() -> None:
    mailbox = (os.environ.get("MAIL_IMAP_MAILBOX") or "INBOX").strip()
    processed = (os.environ.get("MAIL_IMAP_FOLDER_PROCESSED") or "PortalProcessed").strip()
    failed = (os.environ.get("MAIL_IMAP_FOLDER_FAILED") or "PortalFailed").strip()

    imap = _imap_connect()
    try:
        _imap_ensure_folder(imap, processed)
        _imap_ensure_folder(imap, failed)
        mb_utf7 = _imap_utf7_mailbox(mailbox)
        typ, _ = imap.select(mb_utf7, readonly=False)
        if typ != "OK":
            raise RuntimeError(f"IMAP cannot select mailbox {mailbox}")

        typ, data = imap.uid("SEARCH", None, "UNSEEN")
        if typ != "OK" or not data or not data[0]:
            return
        uids = data[0].split()
        for uid in uids:
            uid = uid.strip()
            if not uid:
                continue
            typ, dat = imap.uid("FETCH", uid, "(RFC822)")
            if typ != "OK" or not dat:
                log.error("FETCH failed for uid %s", uid)
                continue
            raw = None
            for part in dat:
                if isinstance(part, tuple) and len(part) >= 2 and isinstance(part[1], (bytes, bytearray)):
                    raw = bytes(part[1])
                    break
            if not raw:
                continue
            if len(raw) > _MAX_TOTAL_FETCH:
                log.warning("Skipping UID %s: message %s bytes exceeds MAIL_TO_TICKET_MAX_BYTES", uid, len(raw))
                _imap_move(imap, uid, failed, raw, mb_utf7)
                continue
            outcome, _tid, err = process_one_message_bytes(raw)
            dest = processed if outcome in ("success", "duplicate", "skipped") else failed
            if outcome == "failed":
                dest = failed
            ok = _imap_move(imap, uid, dest, raw, mb_utf7)
            if ok:
                log.info("UID %s -> %s (%s)", uid.decode() if isinstance(uid, bytes) else uid, dest, outcome)
            else:
                log.error("Could not move UID %s after outcome=%s err=%s", uid, outcome, err)
    finally:
        try:
            imap.logout()
        except Exception:
            pass


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    if not _env_bool("MAIL_TO_TICKET_ENABLED", True):
        log.info("MAIL_TO_TICKET_ENABLED is off; exiting.")
        return
    interval = float(os.environ.get("MAIL_TO_TICKET_POLL_INTERVAL") or "60")
    log.info("Mail-to-ticket worker started (poll %.1fs)", interval)
    while True:
        try:
            poll_once()
        except Exception:
            log.exception("poll_once error")
        time.sleep(max(5.0, interval))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)

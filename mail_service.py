import html as html_module
import logging
import os
import re
from urllib.parse import quote as url_quote
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr

logger = logging.getLogger(__name__)


def _mail_config():
    return {
        "host": (os.environ.get("MAIL_SMTP_HOST") or "smtp.zoho.in").strip(),
        "port": int(os.environ.get("MAIL_SMTP_PORT") or "587"),
        "user": (os.environ.get("MAIL_USER") or "").strip(),
        "password": os.environ.get("MAIL_PASSWORD") or "",
        "from_addr": (os.environ.get("MAIL_FROM") or os.environ.get("MAIL_USER") or "").strip(),
        "from_name": (os.environ.get("MAIL_FROM_NAME") or "PerfectDesk 360").strip(),
    }


def outbound_identity_from_branding(branding_dict):
    """
    Optional portal overrides for ticket-related mail (same keys as emailBranding in settings).
    Returns dict with from_addr, from_name, reply_to_default for send_email / send_html_email, or None.
    """
    if not isinstance(branding_dict, dict):
        return None
    out = {}
    fa = (branding_dict.get("fromAddress") or "").strip()
    if fa and "@" in fa:
        out["from_addr"] = fa[:254]
    fn = (branding_dict.get("fromDisplayName") or "").strip()
    if fn:
        out["from_name"] = fn[:120]
    rt = (branding_dict.get("replyTo") or "").strip()
    if rt and "@" in rt:
        out["reply_to_default"] = rt[:254]
    return out or None


def _effective_from_and_reply(cfg, send_identity, reply_to_param):
    """Resolve From / Reply-To. Accepts outbound dict or a full emailBranding-style dict (camelCase)."""
    idn = send_identity or {}
    raw_fa = (
        idn.get("from_addr")
        or idn.get("fromAddress")
        or ""
    )
    fa = (raw_fa or "").strip()
    if fa and "@" in fa:
        from_addr = fa[:320]
    else:
        from_addr = (cfg.get("from_addr") or "").strip()
    raw_fn = (idn.get("from_name") or idn.get("fromDisplayName") or "").strip()
    from_name = raw_fn or (cfg.get("from_name") or "").strip() or "PerfectDesk 360"
    default_rt = (
        (idn.get("reply_to_default") or idn.get("replyTo") or "").strip()
    )
    explicit = (reply_to_param or "").strip()
    effective_reply = explicit if explicit and "@" in explicit else (
        default_rt if default_rt and "@" in default_rt else None
    )
    return from_addr, from_name, effective_reply


def _parse_cc(raw):
    if not raw or not str(raw).strip():
        return []
    return [p.strip() for p in re.split(r"[,;\s]+", str(raw)) if p.strip() and "@" in p]


def send_email(to_list, subject, body, cc_list=None, reply_to=None, bcc_list=None, send_identity=None):
    """
    Send plain-text email via SMTP. to_list / cc_list / bcc_list: list of bare addresses.
    send_identity: optional dict from outbound_identity_from_branding() (from_addr, from_name, reply_to_default).
    Returns (True, None) on success, (False, error_message) on failure or skip.
    """
    cfg = _mail_config()
    from_addr, from_name, effective_reply = _effective_from_and_reply(
        cfg, send_identity, reply_to
    )
    if not cfg["user"] or not cfg["password"]:
        return False, "Mail not configured (set MAIL_USER / MAIL_PASSWORD in .env)"
    if not from_addr or "@" not in from_addr:
        return False, "Mail not configured: set MAIL_FROM or MAIL_USER in .env, or a valid From address under Email branding."

    recipients = [a.strip() for a in to_list if a and "@" in a]
    bcc_clean = [a.strip() for a in (bcc_list or []) if a and "@" in a]
    if not recipients and not bcc_clean:
        return False, "No valid recipient addresses"

    cc_clean = [a.strip() for a in (cc_list or []) if a and "@" in a]
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((from_name, from_addr))
    if recipients:
        msg["To"] = ", ".join(recipients)
    else:
        msg["To"] = formataddr((from_name, from_addr))
    if cc_clean:
        msg["Cc"] = ", ".join(cc_clean)
    if bcc_clean:
        msg["Bcc"] = ", ".join(bcc_clean)
    if effective_reply:
        msg["Reply-To"] = effective_reply
    msg.set_content(body)

    all_rcpt = list(dict.fromkeys(recipients + cc_clean + bcc_clean))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=30) as smtp:
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.ehlo()
            smtp.login(cfg["user"], cfg["password"])
            smtp.sendmail(from_addr, all_rcpt, msg.as_string())
        return True, None
    except Exception as e:
        logger.exception("SMTP send failed: %s", e)
        return False, str(e)


def send_html_email(
    to_list, subject, text_body, html_body, cc_list=None, reply_to=None, send_identity=None
):
    """Multipart alternative: plain text + HTML (for enterprise templates)."""
    cfg = _mail_config()
    from_addr, from_name, effective_reply = _effective_from_and_reply(
        cfg, send_identity, reply_to
    )
    if not cfg["user"] or not cfg["password"]:
        return False, "Mail not configured (set MAIL_USER / MAIL_PASSWORD in .env)"
    if not from_addr or "@" not in from_addr:
        return False, "Mail not configured: set MAIL_FROM or MAIL_USER in .env, or a valid From address under Email branding."

    recipients = [a.strip() for a in to_list if a and "@" in a]
    if not recipients:
        return False, "No valid recipient addresses"

    cc_clean = [a.strip() for a in (cc_list or []) if a and "@" in a]
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((from_name, from_addr))
    msg["To"] = ", ".join(recipients)
    if cc_clean:
        msg["Cc"] = ", ".join(cc_clean)
    if effective_reply:
        msg["Reply-To"] = effective_reply
    msg.set_content(text_body or "(no plain text)")
    msg.add_alternative(html_body, subtype="html")

    all_rcpt = list(dict.fromkeys(recipients + cc_clean))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=30) as smtp:
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.ehlo()
            smtp.login(cfg["user"], cfg["password"])
            smtp.sendmail(from_addr, all_rcpt, msg.as_string())
        return True, None
    except Exception as e:
        logger.exception("SMTP send failed: %s", e)
        return False, str(e)


def plain_text_to_email_html_fragment(text):
    """Escape plain text and preserve line breaks for HTML body fragment."""
    t = text if text is not None else ""
    return (
        '<div style="font-family:Segoe UI,Inter,system-ui,sans-serif;font-size:15px;'
        'line-height:1.65;color:#18181b;">'
        + html_module.escape(str(t)).replace("\n", "<br>\n")
        + "</div>"
    )


def wrap_email_html_with_company_brand(inner_html_fragment, branding_dict):
    """
    Full HTML document with header: optional logo image, company name, optional tagline.
    branding_dict: companyName, logoUrl (http/https only), tagline
    """
    cfg = _mail_config()
    b = branding_dict or {}
    display_name = (b.get("companyName") or "").strip() or cfg["from_name"]
    name_esc = html_module.escape(display_name)
    tag = html_module.escape((b.get("tagline") or "").strip())
    logo_raw = ((b.get("logoUrl") or "").strip())
    logo_blk = ""
    if logo_raw and logo_raw.lower().startswith(("http://", "https://")):
        logo_blk = (
            f'<img src="{html_module.escape(logo_raw)}" alt="{name_esc}" '
            'style="max-height:56px;max-width:280px;height:auto;width:auto;'
            'display:block;margin:0 0 10px 0;border:0;" />'
        )
    tag_row = (
        f'<p style="margin:6px 0 0 0;font-size:13px;color:#64748b;line-height:1.4;">{tag}</p>'
        if tag
        else ""
    )
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f1f5f9;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f1f5f9;padding:28px 16px;">
<tr><td align="center">
<table role="presentation" width="100%" style="max-width:640px;background:#ffffff;border-radius:14px;border:1px solid #e2e8f0;box-shadow:0 8px 30px rgba(15,23,42,0.06);overflow:hidden;">
<tr><td style="padding:22px 26px 18px 26px;background:linear-gradient(180deg,#fafbfc 0%,#fff 100%);border-bottom:1px solid #f1f5f9;">
{logo_blk}
<div style="font-size:21px;font-weight:700;color:#0f172a;letter-spacing:-0.03em;">{name_esc}</div>
{tag_row}
</td></tr>
<tr><td style="padding:26px 26px 28px 26px;">
{inner_html_fragment}
</td></tr>
<tr><td style="padding:14px 26px 20px 26px;border-top:1px solid #f1f5f9;font-size:11px;color:#94a3b8;text-align:center;">
{name_esc}
</td></tr>
</table>
</td></tr>
</table>
</body></html>"""


def merge_branding_banner_into_html_document(full_html, branding_dict):
    """Insert company logo/name/tagline block immediately after opening <body>."""
    b = branding_dict or {}
    cfg = _mail_config()
    display_name = (b.get("companyName") or "").strip() or cfg["from_name"]
    name_esc = html_module.escape(display_name)
    tag = html_module.escape((b.get("tagline") or "").strip())
    logo_raw = ((b.get("logoUrl") or "").strip())
    inner_parts = []
    if logo_raw and logo_raw.lower().startswith(("http://", "https://")):
        inner_parts.append(
            f'<img src="{html_module.escape(logo_raw)}" alt="{name_esc}" '
            'style="max-height:52px;max-width:260px;display:block;margin-bottom:10px;border:0;" />'
        )
    inner_parts.append(
        f'<div style="font-size:18px;font-weight:700;color:#0f172a;">{name_esc}</div>'
    )
    if tag:
        inner_parts.append(
            f'<p style="margin:8px 0 0 0;font-size:13px;color:#64748b;">{tag}</p>'
        )
    banner = (
        '<div style="margin:0 0 22px 0;padding:18px 20px;background:#fafbfc;'
        'border:1px solid #e2e8f0;border-radius:12px;">'
        + "".join(inner_parts)
        + "</div>"
    )
    m = re.search(r"(<body[^>]*>)", full_html, flags=re.I)
    if m:
        i = m.end()
        return full_html[:i] + banner + full_html[i:]
    return banner + full_html


def send_branded_multipart_email(
    to_list,
    subject,
    text_body,
    branding_dict,
    cc_list=None,
    reply_to=None,
    send_identity=None,
):
    """Multipart/alternative: same plain text + HTML with company header (logo/name/tagline)."""
    inner = plain_text_to_email_html_fragment(text_body)
    html_full = wrap_email_html_with_company_brand(inner, branding_dict)
    ident = send_identity or outbound_identity_from_branding(branding_dict or {})
    return send_html_email(
        to_list,
        subject,
        text_body,
        html_full,
        cc_list=cc_list,
        reply_to=reply_to,
        send_identity=ident,
    )


def send_ticket_forward_email(
    to_list,
    cc_list,
    subject,
    text_body,
    html_body,
    attachments=None,
    reply_to=None,
    send_identity=None,
):
    """
    Multipart HTML forward with optional binary attachments.
    attachments: list of dicts with keys path (absolute), filename, mime.
    """
    cfg = _mail_config()
    from_addr, from_name, effective_reply = _effective_from_and_reply(
        cfg, send_identity, reply_to
    )
    if not cfg["user"] or not cfg["password"]:
        return False, "Mail not configured (set MAIL_USER / MAIL_PASSWORD in .env)"
    if not from_addr or "@" not in from_addr:
        return False, "Mail not configured: set MAIL_FROM or MAIL_USER in .env, or a valid From address under Email branding."

    recipients = [a.strip() for a in to_list if a and "@" in a]
    if not recipients:
        return False, "No valid recipient addresses"

    cc_clean = [a.strip() for a in (cc_list or []) if a and "@" in a]
    msg = EmailMessage()
    msg["Subject"] = (subject or "Forwarded ticket")[:900]
    msg["From"] = formataddr((from_name, from_addr))
    msg["To"] = ", ".join(recipients)
    if cc_clean:
        msg["Cc"] = ", ".join(cc_clean)
    if effective_reply:
        msg["Reply-To"] = effective_reply
    msg.set_content(text_body or "(no plain text)")
    msg.add_alternative(html_body, subtype="html")

    attachments = attachments or []
    max_total = 22 * 1024 * 1024
    total = 0
    for att in attachments:
        fn = (att.get("filename") or "attachment").replace("\r", "").replace("\n", "")
        mime = (att.get("mime") or "application/octet-stream").strip()
        raw = att.get("data")
        if raw is not None:
            if not isinstance(raw, (bytes, bytearray)):
                continue
            data = bytes(raw)
        else:
            path = att.get("path")
            if not path or not os.path.isfile(path):
                continue
            with open(path, "rb") as f:
                data = f.read()
        total += len(data)
        if total > max_total:
            return False, "Combined attachments exceed ~22 MB (email limit)."
        maintype, sep, subtype = mime.partition("/")
        if not sep:
            maintype, subtype = "application", "octet-stream"
        msg.add_attachment(
            data, maintype=maintype.strip() or "application", subtype=subtype.strip() or "octet-stream", filename=fn
        )

    all_rcpt = list(dict.fromkeys(recipients + cc_clean))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=60) as smtp:
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.ehlo()
            smtp.login(cfg["user"], cfg["password"])
            smtp.sendmail(from_addr, all_rcpt, msg.as_string())
        return True, None
    except Exception as e:
        logger.exception("SMTP forward failed: %s", e)
        return False, str(e)


DESK_BRAND = "PerfectDesk 360"


def _modern_assignment_ack_body(
    customer_name,
    ticket_subject,
    public_ticket_id,
    expected_resolution,
    primary_analysis,
    current_ticket_status,
    assignee_name=None,
    assignee_role_label=None,
    ticket_view_url=None,
):
    """
    Plain-text layout: short intro, then a bordered status block at the bottom
    (ticket id, assignee role/name, SLA-style fields, status).
    """
    name = customer_name or "Customer"
    subj = (ticket_subject or "Support request").strip() or "Support request"
    etr = (expected_resolution or "1 Day").strip() or "1 Day"
    pan = (primary_analysis or "We will check and update.").strip() or "We will check and update."
    st = (current_ticket_status or "🛠 Working on It").strip() or "🛠 Working on It"
    an = (assignee_name or "").strip()
    rl = (assignee_role_label or "Support staff").strip() or "Support staff"
    assignee_display = an if an else "—"

    url_line = (ticket_view_url or "").strip()
    url_block = (
        f"\n\nView your ticket online\n  {url_line}\n"
        if url_line
        else ""
    )
    return f"""Hi {name},

Thank you for contacting {DESK_BRAND}. Your request has been assigned to a team member and is being actively worked.

Subject
  {subj}

╔════════════════════════════════════════════════════════════╗
║  TICKET STATUS                                             ║
╚════════════════════════════════════════════════════════════╝

Ticket Number
  {public_ticket_id}

Assigned to ({rl})
  {assignee_display}

Expected time of resolution
  {etr}

Primary Analysis
  {pan}

Current Ticket Status
  {st}{url_block}
────────────────────────────────────────────────────────────
{DESK_BRAND}
"""


def send_customer_ad_unlock_closed_email(
    customer_email,
    customer_name,
    public_ticket_id,
    ticket_subject,
    unlocked_username,
    cc_raw=None,
    ad_outcome="unlocked",
):
    """
    Notify customer after automatic on-prem AD path; ticket is closed.
    ad_outcome: 'unlocked' (lockout cleared) or 'not_locked' (no active AD lockout).
    """
    tid = public_ticket_id or "—"
    subj = (ticket_subject or "Support ticket").strip()
    acct = (unlocked_username or "").strip() or "your account"
    outcome = (ad_outcome or "unlocked").strip().lower()

    if outcome == "not_locked":
        body = f"""Your on-premises account unlock request has been reviewed by Enterprise Identity Services.

Ticket Reference: {tid}
Subject: {subj}
Account reviewed: {acct}

Active Directory indicates that this account does not currently have an active sign-in lockout. No unlock action was required from directory services.

The ticket has now been marked as Closed.

If you remain unable to sign in, the cause may be unrelated to account lockout (for example password policy, expired password, or workstation connectivity). Please contact the IT Help Desk and reference your ticket number for expedited assistance.

— {DESK_BRAND}
"""
        subject = f"[Ticket {tid}] No active AD lockout — ticket closed"[:200]
    else:
        body = f"""Your on-premises account unlock request has been completed successfully.

Ticket Reference: {tid}
Subject: {subj}
Unlocked Account: {acct}

The ticket has now been marked as Closed.

If you are still unable to sign in, please contact the IT Help Desk and mention your ticket reference for faster assistance.

— {DESK_BRAND}
"""
        subject = f"[Ticket {tid}] Account unlocked — ticket closed"[:200]

    cc = _parse_cc(cc_raw)
    return send_email([customer_email], subject, body, cc_list=cc)


def send_customer_ad_password_reset_closed_email(
    customer_email,
    customer_name,
    public_ticket_id,
    ticket_subject,
    account_username,
    cc_raw=None,
    customer_chose_password=True,
):
    """
    Notify customer after on-prem AD password reset; ticket is closed.
    When the customer supplied the password on the form, the email does not repeat it.
    """
    tid = public_ticket_id or "—"
    subj_line = (ticket_subject or "Support ticket").strip()
    acct = (account_username or "").strip() or "your account"

    if customer_chose_password:
        body = f"""Your on-premises password reset request has been completed by Enterprise Identity Services.

Ticket Reference: {tid}
Subject: {subj_line}
Account: {acct}

The new password you entered on the secure form has been applied in Active Directory. You can sign in with that password now. The ticket has been marked as Closed.

We attempted to clear the "must change password at next logon" flag so you are not prompted to change it immediately; your organization's policy may still require a change later.

Use HTTPS only when accessing the portal. If you did not request this reset, contact the IT Help Desk immediately and reference your ticket number.

— {DESK_BRAND}
"""
    else:
        body = f"""Your on-premises password reset request has been completed by Enterprise Identity Services.

Ticket Reference: {tid}
Subject: {subj_line}
Account: {acct}

The ticket has now been marked as Closed.

— {DESK_BRAND}
"""
    subject = f"[Ticket {tid}] Password reset complete — ticket closed"[:200]
    cc = _parse_cc(cc_raw)
    return send_email([customer_email], subject, body, cc_list=cc)


def send_customer_acknowledgment_email(
    customer_email,
    customer_name,
    public_ticket_id,
    ticket_subject,
    expected_resolution,
    primary_analysis,
    current_ticket_status,
    cc_raw=None,
    assignee_name=None,
    assignee_role_label=None,
    ticket_view_url=None,
    send_identity=None,
    branding_dict=None,
):
    body = _modern_assignment_ack_body(
        customer_name,
        ticket_subject,
        public_ticket_id,
        expected_resolution,
        primary_analysis,
        current_ticket_status,
        assignee_name=assignee_name,
        assignee_role_label=assignee_role_label,
        ticket_view_url=ticket_view_url,
    )
    subject = f"[Ticket {public_ticket_id}] Assigned: {ticket_subject}"[:200]
    cc = _parse_cc(cc_raw)
    if branding_dict is not None:
        ident = send_identity or outbound_identity_from_branding(branding_dict)
        return send_branded_multipart_email(
            [customer_email],
            subject,
            body,
            branding_dict,
            cc_list=cc,
            send_identity=ident,
        )
    return send_email(
        [customer_email], subject, body, cc_list=cc, send_identity=send_identity
    )


def send_agent_reply_email(
    customer_email,
    public_ticket_id,
    ticket_subject,
    agent_label,
    reply_body,
    cc_raw=None,
    ticket_view_url=None,
    send_identity=None,
    branding_dict=None,
):
    url_line = (ticket_view_url or "").strip()
    url_extra = (
        f"\n\nView your ticket online:\n{url_line}\n"
        if url_line
        else ""
    )
    body = f"""Hello,

There is an update on your support ticket.

Ticket ID: {public_ticket_id}
Subject: {ticket_subject}

Message from support ({agent_label}):
---
{reply_body or "(no message body)"}
---{url_extra}
— {DESK_BRAND}
"""
    subject = f"Re: [Ticket {public_ticket_id}] {ticket_subject}"[:200]
    cc = _parse_cc(cc_raw)
    if branding_dict is not None:
        ident = send_identity or outbound_identity_from_branding(branding_dict)
        return send_branded_multipart_email(
            [customer_email],
            subject,
            body,
            branding_dict,
            cc_list=cc,
            send_identity=ident,
        )
    return send_email(
        [customer_email], subject, body, cc_list=cc, send_identity=send_identity
    )


def send_customer_ticket_view_otp_email(recipient_email, otp_code):
    """One-time code for customer portal: list tickets by verified email."""
    code = (otp_code or "").strip()
    body = f"""Hi,

You requested to view your support tickets on {DESK_BRAND}.

Your verification code is:

  {code}

This code expires in 10 minutes. If you did not request this, you can ignore this email.

— {DESK_BRAND}
"""
    subject = "Your ticket portal verification code"
    return send_email([recipient_email], subject, body, cc_list=None)


def send_manager_approval_request_email(
    manager_email,
    cc_list,
    ticket_public_id,
    ticket_subject,
    customer_label,
    agent_name,
    reason,
    message_to_manager,
    priority,
    due_display,
    ticket_deep_link,
    respond_base_url,
    approval_id,
    secret_token,
    custom_subject=None,
    custom_text_body=None,
    custom_html_body=None,
    branding_dict=None,
    customer_portal_url=None,
):
    """HTML email with Approve / Reject / Rework links (token-gated response page)."""
    esc = html_module.escape
    cust_view = (customer_portal_url or "").strip()
    cust_view_esc = esc(cust_view) if cust_view else ""
    cust_portal_text = (
        f"\nCustomer portal: {cust_view}\n" if cust_view else ""
    )
    cust_portal_html = (
        f"""        <tr><td style="padding:8px 0;border-bottom:1px solid #f4f4f5;color:#71717a;">Customer portal</td>
            <td style="padding:8px 0;border-bottom:1px solid #f4f4f5;"><a href="{cust_view_esc}" style="color:#4f46e5;font-weight:600;">Open customer workspace →</a></td></tr>
"""
        if cust_view
        else ""
    )
    subj = (
        (custom_subject or f"Approval Required — {ticket_public_id}") or ""
    )[:200]
    q = f"id={approval_id}&t={url_quote(secret_token, safe='')}"
    link_approve = f"{respond_base_url}?{q}&a=approve"
    link_reject = f"{respond_base_url}?{q}&a=reject"
    link_rework = f"{respond_base_url}?{q}&a=rework"

    if custom_text_body is not None and str(custom_text_body).strip():
        text_body = custom_text_body
    else:
        text_body = f"""Manager approval requested — {ticket_public_id}

Ticket: {ticket_public_id}
Subject: {ticket_subject}
Customer: {customer_label}{cust_portal_text}
Priority: {priority}
Due: {due_display}
Agent: {agent_name}

Reason:
{reason or '—'}

Message:
{message_to_manager or '—'}

Open in workspace:
{ticket_deep_link}

Respond (use links in HTML version if available):
Approve: {link_approve}
Reject: {link_reject}
Request rework: {link_rework}

— {DESK_BRAND}
"""

    if custom_html_body is not None and str(custom_html_body).strip():
        html_body = custom_html_body
    else:
        html_body = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="font-family:Segoe UI,Inter,system-ui,sans-serif;background:#f4f4f5;margin:0;padding:24px;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:640px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 12px 40px rgba(79,70,229,0.12);border:1px solid #e4e4e7;">
    <tr><td style="background:linear-gradient(90deg,#4f46e5,#7c3aed);padding:20px 24px;color:#fff;">
      <div style="font-size:11px;letter-spacing:0.12em;text-transform:uppercase;opacity:0.9;">Enterprise approval</div>
      <div style="font-size:20px;font-weight:700;margin-top:4px;">Action required</div>
    </td></tr>
    <tr><td style="padding:24px;color:#27272a;font-size:14px;line-height:1.55;">
      <p style="margin:0 0 16px;">You have a pending approval for support ticket <strong>{esc(ticket_public_id)}</strong>.</p>
      <table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:20px;">
        <tr><td style="padding:8px 0;border-bottom:1px solid #f4f4f5;color:#71717a;width:140px;">Subject</td>
            <td style="padding:8px 0;border-bottom:1px solid #f4f4f5;font-weight:600;">{esc(ticket_subject)}</td></tr>
        <tr><td style="padding:8px 0;border-bottom:1px solid #f4f4f5;color:#71717a;">Customer</td>
            <td style="padding:8px 0;border-bottom:1px solid #f4f4f5;">{esc(customer_label)}</td></tr>
{cust_portal_html}        <tr><td style="padding:8px 0;border-bottom:1px solid #f4f4f5;color:#71717a;">Priority</td>
            <td style="padding:8px 0;border-bottom:1px solid #f4f4f5;">{esc(priority)}</td></tr>
        <tr><td style="padding:8px 0;border-bottom:1px solid #f4f4f5;color:#71717a;">Due</td>
            <td style="padding:8px 0;border-bottom:1px solid #f4f4f5;">{esc(due_display)}</td></tr>
        <tr><td style="padding:8px 0;border-bottom:1px solid #f4f4f5;color:#71717a;">Agent</td>
            <td style="padding:8px 0;border-bottom:1px solid #f4f4f5;">{esc(agent_name)}</td></tr>
      </table>
      <p style="margin:0 0 6px;font-size:11px;text-transform:uppercase;letter-spacing:0.08em;color:#71717a;">Approval reason</p>
      <div style="background:#fafafa;border:1px solid #e4e4e7;border-radius:8px;padding:12px;margin-bottom:16px;white-space:pre-wrap;">{esc(reason or '—')}</div>
      <p style="margin:0 0 6px;font-size:11px;text-transform:uppercase;letter-spacing:0.08em;color:#71717a;">Message from agent</p>
      <div style="background:#eef2ff;border:1px solid #c7d2fe;border-radius:8px;padding:12px;margin-bottom:22px;white-space:pre-wrap;">{esc(message_to_manager or '—')}</div>
      <p style="margin:0 0 12px;"><a href="{esc(ticket_deep_link)}" style="color:#4f46e5;font-weight:600;">Open ticket in portal →</a></p>
      <table role="presentation" cellspacing="0" cellpadding="0" style="margin-top:8px;"><tr>
        <td style="padding:4px 8px 4px 0;"><a href="{esc(link_approve)}" style="display:inline-block;background:#16a34a;color:#fff!important;text-decoration:none;padding:12px 20px;border-radius:8px;font-weight:700;font-size:13px;">Approve</a></td>
        <td style="padding:4px 8px 4px 0;"><a href="{esc(link_reject)}" style="display:inline-block;background:#dc2626;color:#fff!important;text-decoration:none;padding:12px 20px;border-radius:8px;font-weight:700;font-size:13px;">Reject</a></td>
        <td style="padding:4px 8px;"><a href="{esc(link_rework)}" style="display:inline-block;background:#ca8a04;color:#fff!important;text-decoration:none;padding:12px 20px;border-radius:8px;font-weight:700;font-size:13px;">Rework</a></td>
      </tr></table>
      <p style="font-size:11px;color:#a1a1aa;margin-top:20px;">If you did not expect this message, ignore it or contact your IT security team.</p>
    </td></tr>
  </table>
  <p style="text-align:center;font-size:11px;color:#a1a1aa;margin-top:16px;">{esc(DESK_BRAND)}</p>
</body></html>"""

    if branding_dict:
        html_body = merge_branding_banner_into_html_document(html_body, branding_dict)

    ident = outbound_identity_from_branding(branding_dict or {})
    return send_html_email(
        [manager_email],
        subj,
        text_body,
        html_body,
        cc_list=cc_list or None,
        send_identity=ident,
    )


def send_forgot_password_agent_email(recipient_email, display_name, password_plain):
    """Email current password to an agent (DB stores plaintext in this app)."""
    name = (display_name or "").strip() or "Agent"
    pw = password_plain or ""
    body = f"""Hi {name},

You requested a reminder for your PerfectDesk 360 support workspace login.

Registered email: {recipient_email}
Your password: {pw}

Use the staff login page with this email and password. If you did not request this, inform your manager and change your password after signing in.

— {DESK_BRAND}
"""
    subject = "Your agent workspace login password"
    return send_email([recipient_email], subject, body, cc_list=None)

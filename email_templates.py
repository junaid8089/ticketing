"""
Enterprise-standard notification templates (subject/body/HTML placeholders).
Placeholders use braces, e.g. {ticket_id}, {subject}. Unknown placeholders stay literal.
"""

import copy
import os


def default_email_branding():
    """Company display name, logo URL (https), tagline — used in HTML headers for template mail."""
    return {
        "companyName": "",
        "logoUrl": "",
        "tagline": "",
        "replyTo": "",
        "fromAddress": "",
        "fromDisplayName": "",
    }


def merge_stored_email_branding(defaults, stored):
    out = copy.deepcopy(defaults)
    if not isinstance(stored, dict):
        return out
    if isinstance(stored.get("companyName"), str):
        out["companyName"] = stored["companyName"].strip()[:120]
    if isinstance(stored.get("logoUrl"), str):
        u = stored["logoUrl"].strip()[:2000]
        lu = u.lower()
        if lu.startswith("https://") or lu.startswith("http://"):
            out["logoUrl"] = u
        else:
            out["logoUrl"] = ""
    if isinstance(stored.get("tagline"), str):
        out["tagline"] = stored["tagline"].strip()[:200]
    for key, maxlen in (
        ("replyTo", 254),
        ("fromAddress", 254),
        ("fromDisplayName", 120),
    ):
        if isinstance(stored.get(key), str):
            v = stored[key].strip()[:maxlen]
            if key in ("replyTo", "fromAddress") and v and "@" not in v:
                v = ""
            out[key] = v
    return out


def resolve_template_brand_name(merged_settings):
    """Portal company name for templates, else MAIL_FROM_NAME."""
    b = (merged_settings or {}).get("emailBranding") or {}
    n = (b.get("companyName") or "").strip()
    if n:
        return n[:120]
    return (os.environ.get("MAIL_FROM_NAME") or "PerfectDesk 360").strip()


def template_brand_placeholders(merged_settings):
    """Extra placeholders for plain-text templates: logo URL and tagline."""
    b = (merged_settings or {}).get("emailBranding") or {}
    return {
        "brand_name": resolve_template_brand_name(merged_settings),
        "logo_url": (b.get("logoUrl") or "").strip(),
        "company_tagline": (b.get("tagline") or "").strip(),
    }


def render_email_template(template_str, context):
    if template_str is None:
        return ""
    s = str(template_str)
    for key, val in (context or {}).items():
        rep = "" if val is None else str(val)
        s = s.replace("{" + str(key) + "}", rep)
    return s


def default_email_templates_dict():
    """Built-in enterprise template set; managers may edit via portal settings."""
    return {
        "staff_new_ticket": {
            "label": "Staff — New ticket created",
            "description": "Sent to every active agent and manager when a ticket is created (public or staff). Placeholders: {ticket_url} (agent workspace), {customer_portal_url} (customer view-ticket page).",
            "enabled": True,
            "subject": "[{ticket_id}] New ticket — {subject}",
            "body": """Hello,

A new support ticket was logged in the portal.

Ticket ID: {ticket_id}
Subject: {subject}
Priority: {priority}
Category: {category}
Customer: {customer_name} <{customer_email}>
Customer portal (same ticket): {customer_portal_url}
Currently assigned to: {assigned_to}

Description (preview):
{description_preview}

Open in workspace: {ticket_url}

— {brand_name}
""",
        },
        "staff_ticket_reopened": {
            "label": "Staff — Customer reopened ticket",
            "description": "Sent to all active agents and managers when a customer reopens a resolved/closed ticket. {ticket_url} = agent workspace; {customer_portal_url} = customer portal link.",
            "enabled": True,
            "subject": "[{ticket_id}] Ticket reopened by customer",
            "body": """Hello,

A customer reopened a ticket from the self-service portal.

Ticket ID: {ticket_id}
Subject: {subject}
Customer: {customer_name} <{customer_email}>
Customer portal: {customer_portal_url}

Customer message:
{reopen_note}

View ticket: {ticket_url}

— {brand_name}
""",
        },
        "staff_inbound_customer_reply": {
            "label": "Staff — Customer reply (mail-to-ticket)",
            "description": "Sent to the ticket assignee (if they have an email on file) when a customer message arrives via the monitored support mailbox. Falls back to all staff if no assignee email. Use {mail_excerpt} for a short plain-text preview.",
            "enabled": True,
            "subject": "[{ticket_id}] Customer reply by email",
            "body": """Hello,

A customer sent a message that was attached to an existing ticket via the mail-to-ticket processor.

Ticket ID: {ticket_id}
Subject: {subject}
From: {from_email}
Assigned to: {assigned_to}

Preview:
{mail_excerpt}

Customer portal: {customer_portal_url}
Open in workspace: {ticket_url}

— {brand_name}
""",
        },
        "customer_ticket_assigned": {
            "label": "Customer — Ticket assigned to you",
            "description": "Sent to the requester (and CC) when an agent first picks up an unassigned ticket. Use {ticket_url} for the customer portal link (pre-fills this ticket).",
            "enabled": True,
            "subject": "[{ticket_id}] Assigned: {subject}",
            "body": """Hi {customer_name},

Thank you for contacting {brand_name}. Your request has been assigned and is being worked.

Subject
  {subject}

Ticket Number
  {ticket_id}

View your ticket
  {ticket_url}

Assigned to ({assignee_role})
  {assignee_name}

Expected time of resolution
  {expected_resolution}

Primary analysis
  {primary_analysis}

Current ticket status
  {current_status}

— {brand_name}
""",
        },
        "customer_ticket_reply": {
            "label": "Customer — New reply on ticket",
            "description": "Sent when an agent posts a public reply on the ticket. Use {ticket_url} for the customer portal link.",
            "enabled": True,
            "subject": "Re: [{ticket_id}] {subject}",
            "body": """Hello,

There is an update on your support ticket.

Ticket ID: {ticket_id}
Subject: {subject}

View your ticket: {ticket_url}

Message from support ({agent_name}):
---
{reply_body}
---

— {brand_name}
""",
        },
        "customer_ticket_closed": {
            "label": "Customer — Ticket resolved or closed",
            "description": "Sent when status changes to resolved or closed (once per closure). Use {ticket_url} for the customer portal link.",
            "enabled": True,
            "subject": "[{ticket_id}] Ticket update: {status}",
            "body": """Hi {customer_name},

Your support ticket status has been updated.

Ticket ID: {ticket_id}
Subject: {subject}
New status: {status}

View your ticket: {ticket_url}

If you still need help, you may be able to reopen this ticket from the portal (unless it was closed automatically for security).

— {brand_name}
""",
        },
        "customer_manager_approval_result": {
            "label": "Customer — Manager approval decision",
            "description": "Sent when a manager approves, rejects, or requests rework on an approval request. Use {ticket_url} for the customer portal link.",
            "enabled": True,
            "subject": "[{ticket_id}] Approval {decision}",
            "body": """Hi {customer_name},

There is an update regarding manager approval on your ticket.

Ticket ID: {ticket_id}
Subject: {subject}
Decision: {decision}

View your ticket: {ticket_url}

Manager comment:
{manager_comment}

Current ticket status: {ticket_status}

— {brand_name}
""",
        },
        "manager_approval_request": {
            "label": "Manager — Approval request",
            "description": "Sent to the approver with action links. Keep approve/reject/rework and {ticket_deep_link}; {ticket_url} is the customer-facing portal link for this ticket.",
            "enabled": True,
            "subject": "Approval Required — {ticket_id}",
            "body": """Manager approval requested — {ticket_id}

Ticket: {ticket_id}
Subject: {subject}
Customer: {customer_label}
Customer portal (read-only view): {ticket_url}
Priority: {priority}
Due: {due_display}
Agent: {agent_name}

Reason:
{reason}

Message from agent:
{message_to_manager}

Open ticket: {ticket_deep_link}

Approve: {link_approve}
Reject: {link_reject}
Request rework: {link_rework}

— {brand_name}
""",
            "html": """<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="font-family:Segoe UI,Inter,system-ui,sans-serif;background:#f4f4f5;margin:0;padding:24px;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:640px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 12px 40px rgba(79,70,229,0.12);border:1px solid #e4e4e7;">
    <tr><td style="background:linear-gradient(90deg,#4f46e5,#7c3aed);padding:20px 24px;color:#fff;">
      <div style="font-size:11px;letter-spacing:0.12em;text-transform:uppercase;opacity:0.9;">Enterprise approval</div>
      <div style="font-size:20px;font-weight:700;margin-top:4px;">Action required</div>
    </td></tr>
    <tr><td style="padding:24px;color:#27272a;font-size:14px;line-height:1.55;">
      <p style="margin:0 0 16px;">You have a pending approval for support ticket <strong>{ticket_id}</strong>.</p>
      <table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:20px;">
        <tr><td style="padding:8px 0;border-bottom:1px solid #f4f4f5;color:#71717a;width:140px;">Subject</td>
            <td style="padding:8px 0;border-bottom:1px solid #f4f4f5;font-weight:600;">{subject}</td></tr>
        <tr><td style="padding:8px 0;border-bottom:1px solid #f4f4f5;color:#71717a;">Customer</td>
            <td style="padding:8px 0;border-bottom:1px solid #f4f4f5;">{customer_label}</td></tr>
        <tr><td style="padding:8px 0;border-bottom:1px solid #f4f4f5;color:#71717a;">Customer portal</td>
            <td style="padding:8px 0;border-bottom:1px solid #f4f4f5;"><a href="{ticket_url}" style="color:#4f46e5;font-weight:600;">Open customer workspace →</a></td></tr>
        <tr><td style="padding:8px 0;border-bottom:1px solid #f4f4f5;color:#71717a;">Priority</td>
            <td style="padding:8px 0;border-bottom:1px solid #f4f4f5;">{priority}</td></tr>
        <tr><td style="padding:8px 0;border-bottom:1px solid #f4f4f5;color:#71717a;">Due</td>
            <td style="padding:8px 0;border-bottom:1px solid #f4f4f5;">{due_display}</td></tr>
        <tr><td style="padding:8px 0;border-bottom:1px solid #f4f4f5;color:#71717a;">Agent</td>
            <td style="padding:8px 0;border-bottom:1px solid #f4f4f5;">{agent_name}</td></tr>
      </table>
      <p style="margin:0 0 6px;font-size:11px;text-transform:uppercase;letter-spacing:0.08em;color:#71717a;">Approval reason</p>
      <div style="background:#fafafa;border:1px solid #e4e4e7;border-radius:8px;padding:12px;margin-bottom:16px;white-space:pre-wrap;">{reason}</div>
      <p style="margin:0 0 6px;font-size:11px;text-transform:uppercase;letter-spacing:0.08em;color:#71717a;">Message from agent</p>
      <div style="background:#eef2ff;border:1px solid #c7d2fe;border-radius:8px;padding:12px;margin-bottom:22px;white-space:pre-wrap;">{message_to_manager}</div>
      <p style="margin:0 0 12px;"><a href="{ticket_deep_link}" style="color:#4f46e5;font-weight:600;">Open ticket in portal →</a></p>
      <table role="presentation" cellspacing="0" cellpadding="0" style="margin-top:8px;"><tr>
        <td style="padding:4px 8px 4px 0;"><a href="{link_approve}" style="display:inline-block;background:#16a34a;color:#fff!important;text-decoration:none;padding:12px 20px;border-radius:8px;font-weight:700;font-size:13px;">Approve</a></td>
        <td style="padding:4px 8px 4px 0;"><a href="{link_reject}" style="display:inline-block;background:#dc2626;color:#fff!important;text-decoration:none;padding:12px 20px;border-radius:8px;font-weight:700;font-size:13px;">Reject</a></td>
        <td style="padding:4px 8px;"><a href="{link_rework}" style="display:inline-block;background:#ca8a04;color:#fff!important;text-decoration:none;padding:12px 20px;border-radius:8px;font-weight:700;font-size:13px;">Rework</a></td>
      </tr></table>
      <p style="font-size:11px;color:#a1a1aa;margin-top:20px;">If you did not expect this message, ignore it or contact your IT security team.</p>
    </td></tr>
  </table>
  <p style="text-align:center;font-size:11px;color:#a1a1aa;margin-top:16px;">{brand_name}</p>
</body></html>""",
        },
    }


def merge_stored_email_templates(defaults, stored):
    """Deep-merge stored manager overrides into defaults (by template key)."""
    out = copy.deepcopy(defaults)
    if not isinstance(stored, dict):
        return out
    for key, val in stored.items():
        if key not in out or not isinstance(val, dict):
            continue
        slot = out[key]
        if "enabled" in val:
            slot["enabled"] = bool(val["enabled"])
        if isinstance(val.get("subject"), str):
            slot["subject"] = val["subject"][:500]
        if isinstance(val.get("body"), str):
            slot["body"] = val["body"][:50000]
        if isinstance(val.get("html"), str):
            slot["html"] = val["html"][:200000]
    return out


def apply_email_template_updates(merged_full, updates):
    """Patch manager edits onto the merged template dict (from portal settings)."""
    if not isinstance(updates, dict):
        return merged_full
    out = copy.deepcopy(merged_full) if merged_full else default_email_templates_dict()
    for k, v in updates.items():
        if k not in out or not isinstance(v, dict):
            continue
        slot = out[k]
        if "enabled" in v:
            slot["enabled"] = bool(v["enabled"])
        if isinstance(v.get("subject"), str):
            slot["subject"] = v["subject"][:500]
        if isinstance(v.get("body"), str):
            slot["body"] = v["body"][:50000]
        if isinstance(v.get("html"), str):
            slot["html"] = v["html"][:200000]
    return out


def templates_for_api_response(merged_dict):
    """Strip internal noise if any; return serializable list for UI."""
    d = merged_dict or {}
    rows = []
    for key, meta in d.items():
        if not isinstance(meta, dict):
            continue
        rows.append(
            {
                "id": key,
                "label": meta.get("label") or key,
                "description": meta.get("description") or "",
                "enabled": meta.get("enabled", True),
                "subject": meta.get("subject") or "",
                "body": meta.get("body") or "",
                "html": meta.get("html") or "",
            }
        )
    order = list(default_email_templates_dict().keys())
    rows.sort(key=lambda r: order.index(r["id"]) if r["id"] in order else 99)
    return rows

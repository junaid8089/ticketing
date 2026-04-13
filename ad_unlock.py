"""
Optional Active Directory account unlock (clear lockout) and password reset via LDAP.

Credentials and search base MUST be supplied via environment variables — never hardcode
passwords in source. See .env.example.

Password reset sets unicodePwd and requires an encrypted LDAP session (LDAPS or STARTTLS).
"""

from __future__ import annotations

import os
import re
import string
from typing import Any, Optional, Tuple

from ldap3 import SUBTREE, MODIFY_REPLACE, Server, Connection
from ldap3.extend.microsoft.unlockAccount import ad_unlock_account
from ldap3.utils.conv import escape_filter_chars


def ad_unlock_env_configured() -> bool:
    user = (os.environ.get("AD_BIND_USER") or os.environ.get("AD_BIND_DN") or "").strip()
    password = (os.environ.get("AD_BIND_PASSWORD") or "").strip()
    return bool(user and password)


def _normalize_unlock_identity(raw: str) -> str:
    """Turn DOMAIN\\user into user; trim whitespace."""
    s = (raw or "").strip()
    if "\\" in s:
        s = s.split("\\", 1)[-1].strip()
    return s


# Local self-service reset: length, classes, capped specials, no name/account substring.
_LOCAL_RESET_ALLOWED = set(string.ascii_letters + string.digits + "!@#$")
_LOCAL_RESET_SPECIALS = set("!@#$")


def validate_local_reset_password_policy(
    password: str,
    customer_name: str,
    account_username: str,
) -> tuple[bool, str]:
    """
    Enforce portal password rules before AD apply:
    - Length 14–127
    - At least one upper, one lower, one digit
    - Only letters, digits, and !@#$; exactly 1–2 special characters from !@#$
    - Must not contain customer name (word tokens ≥3 chars) or account identity (≥3 chars)
    """
    pw = password or ""
    if len(pw) < 14:
        return False, "Password must be at least 14 characters."
    if len(pw) > 127:
        return False, "Password must be at most 127 characters."
    if '"' in pw or "\x00" in pw:
        return False, "Password cannot contain double quotes or null characters."
    if any(c not in _LOCAL_RESET_ALLOWED for c in pw):
        return False, "Use only letters, digits, and at most two symbols from: ! @ # $"
    if not any(c.isupper() for c in pw):
        return False, "Password must include at least one uppercase letter."
    if not any(c.islower() for c in pw):
        return False, "Password must include at least one lowercase letter."
    if not any(c.isdigit() for c in pw):
        return False, "Password must include at least one digit."
    spec_count = sum(1 for c in pw if c in _LOCAL_RESET_SPECIALS)
    if spec_count < 1 or spec_count > 2:
        return False, "Include 1 or 2 special characters from ! @ # $ (not more)."

    low = pw.lower()
    raw_name = (customer_name or "").strip()
    for token in re.split(r"\s+", raw_name):
        t = token.strip(".,;:-_")
        if len(t) >= 3 and t.lower() in low:
            return False, "Password must not contain your name."

    acc_raw = (account_username or "").strip()
    if "@" in acc_raw:
        acc_key = acc_raw.split("@", 1)[0].strip()
    elif "\\" in acc_raw:
        acc_key = acc_raw.split("\\", 1)[-1].strip()
    else:
        acc_key = acc_raw
    if len(acc_key) >= 3 and acc_key.lower() in low:
        return False, "Password must not contain your account name."

    return True, ""


def _entry_lockout_time_int(entry) -> int:
    """AD lockoutTime: 0 when not locked; large value when locked (Windows time)."""
    try:
        if "lockoutTime" not in entry:
            return 0
        v = entry.lockoutTime.value
        if v is None:
            return 0
        return int(v)
    except (TypeError, ValueError, AttributeError, KeyError):
        return 0


def _ldap_connection_encrypted(conn: Connection, use_ssl: bool) -> bool:
    """Active Directory requires TLS for unicodePwd changes."""
    if use_ssl:
        return True
    if (os.environ.get("AD_START_TLS") or "").lower() in ("1", "true", "yes"):
        return bool(getattr(conn, "tls_started", False))
    return False


def _ad_ldap_open_and_find_entry(
    username: str,
) -> Tuple[Optional[Connection], Any, str, Optional[str]]:
    """
    Bind and locate account by sAMAccountName or UPN.
    Returns (conn, entry, host, error). On error, conn is None or already unbound.
    Caller must unbind conn on success when finished.
    """
    if not username or not str(username).strip():
        return None, None, "", "Empty username"
    if not ad_unlock_env_configured():
        return None, None, "", "AD bind credentials not configured (set AD_BIND_USER and AD_BIND_PASSWORD)"

    host = (
        os.environ.get("AD_LDAP_HOST")
        or os.environ.get("LOCAL_AD_SERVER_IP")
        or "10.10.10.10"
    ).strip()
    try:
        port = int(os.environ.get("AD_LDAP_PORT") or "389")
    except ValueError:
        port = 389
    use_ssl = (os.environ.get("AD_USE_SSL") or "").lower() in ("1", "true", "yes")
    base = (os.environ.get("AD_SEARCH_BASE") or "").strip()
    if not base:
        return None, None, host, "AD_SEARCH_BASE is not set (e.g. DC=perfectclt,DC=com)"

    bind_user = (os.environ.get("AD_BIND_USER") or os.environ.get("AD_BIND_DN") or "").strip()
    bind_password = os.environ.get("AD_BIND_PASSWORD") or ""

    account_key = _normalize_unlock_identity(username)
    safe = escape_filter_chars(account_key)
    search_filter = f"(|(sAMAccountName={safe})(userPrincipalName={safe}))"

    try:
        server = Server(host, port=port, use_ssl=use_ssl)
        try:
            recv_to = float(os.environ.get("AD_LDAP_RECEIVE_TIMEOUT", "20"))
        except ValueError:
            recv_to = 20.0
        conn = Connection(
            server,
            user=bind_user,
            password=bind_password,
            auto_bind=True,
            receive_timeout=recv_to,
        )
        if (os.environ.get("AD_START_TLS") or "").lower() in ("1", "true", "yes") and not use_ssl:
            if not conn.start_tls():
                conn.unbind()
                return None, None, host, "STARTTLS failed: " + str(conn.result)

        conn.search(
            base,
            search_filter,
            search_scope=SUBTREE,
            attributes=[
                "distinguishedName",
                "sAMAccountName",
                "userPrincipalName",
                "lockoutTime",
            ],
        )
        if not conn.entries:
            conn.unbind()
            return None, None, host, "No matching account in Active Directory for that name"

        return conn, conn.entries[0], host, None
    except Exception as ex:
        return None, None, host, str(ex)[:500]


def try_unlock_local_ad_account(username: str) -> tuple[bool, str, str]:
    """
    Clear AD lockout for the given sAMAccountName or UPN when locked.

    Returns (success, message, outcome):
      outcome "unlocked"     — lockout was cleared
      outcome "not_locked"  — account found, no active lockout (ticket may still close)
      outcome "error"       — success is False
    """
    try:
        conn, entry, host, err = _ad_ldap_open_and_find_entry(username)
        if err:
            return False, err, "error"
        assert conn is not None and entry is not None

        dn = entry.entry_dn
        lockout = _entry_lockout_time_int(entry)

        if lockout == 0:
            conn.unbind()
            return (
                True,
                f"No active lockout on {host}",
                "not_locked",
            )

        res = ad_unlock_account(conn, dn)
        if res is True:
            try:
                conn.modify(dn, {"badPwdCount": [(MODIFY_REPLACE, ["0"])]})
            except Exception:
                pass
            conn.unbind()
            return True, f"Unlocked on {host}", "unlocked"

        if isinstance(res, dict):
            detail = (
                res.get("message")
                or res.get("description")
                or str(res.get("result", res))
            )
            conn.unbind()
            return False, str(detail)[:500], "error"

        conn.unbind()
        return False, str(res)[:500], "error"
    except Exception as ex:
        return False, str(ex)[:500], "error"


def set_local_ad_account_password(username: str, new_password: str) -> tuple[bool, str]:
    """
    Set the given plaintext password on the AD account (admin reset over LDAP).

    After a successful unicodePwd change, attempts pwdLastSet = -1 so the user is not
    forced to change password at next logon (common helpdesk expectation).

    Requires LDAPS or successful STARTTLS. Password must not contain \" or null bytes.
    """
    pw = new_password or ""
    if not pw:
        return False, "Empty password"
    if len(pw) > 127:
        return False, "Password exceeds Active Directory maximum length (127)"
    if '"' in pw or "\x00" in pw:
        return False, "Password cannot contain double quotes or null characters"

    use_ssl = (os.environ.get("AD_USE_SSL") or "").lower() in ("1", "true", "yes")
    try:
        conn, entry, host, err = _ad_ldap_open_and_find_entry(username)
        if err:
            return False, err
        assert conn is not None and entry is not None

        if not _ldap_connection_encrypted(conn, use_ssl):
            conn.unbind()
            return (
                False,
                "Password reset requires an encrypted LDAP session. Set AD_USE_SSL=true or AD_START_TLS=true.",
            )

        dn = entry.entry_dn
        quoted = '"' + pw.replace('"', "") + '"'
        enc_pwd = quoted.encode("utf-16-le")

        ok = conn.modify(dn, {"unicodePwd": [(MODIFY_REPLACE, [enc_pwd])]})
        if not ok:
            r = conn.result
            detail = ""
            if isinstance(r, dict):
                detail = (
                    str(r.get("message") or r.get("description") or r.get("result") or r)[:500]
                )
            else:
                detail = str(r)[:500]
            conn.unbind()
            return False, detail or "LDAP password modify failed"

        try:
            conn.modify(dn, {"pwdLastSet": [(MODIFY_REPLACE, [-1])]})
        except Exception:
            pass

        conn.unbind()
        return True, f"Password reset on {host}"
    except Exception as ex:
        return False, str(ex)[:500]

from __future__ import annotations

import asyncio
import copy
import inspect
import io
import re
import secrets
import string
from datetime import datetime, timedelta
from typing import Any, Callable, Optional
from zoneinfo import ZoneInfo

import discord
from discord import app_commands
from discord.ext import commands
import pyotp
import qrcode

from dc_bot_core.utils import *
import config

DATA_FILE = config.DATA_FILES["accounts"]

LOCK_DAYS = 3
CODE_EXPIRE_MINUTES = 10
VERIFIED_ROLE_NAME = "已驗證gm"

try:
    TAIPEI_TZ = ZoneInfo("Asia/Taipei")
except Exception:
    TAIPEI_TZ = None


# 預設資料結構
DEFAULT_STRUCTURE = {
    "accounts": {},
    "sessions": {},
    "pending_2fa": {},
    "locks": {}
}


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _now() -> datetime:
    if TAIPEI_TZ is not None:
        return datetime.now(TAIPEI_TZ)
    return datetime.now()


def _dt_from_iso(value: str) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None and TAIPEI_TZ is not None:
            dt = dt.replace(tzinfo=TAIPEI_TZ)
        return dt
    except Exception:
        return None


def _to_iso(dt: Optional[datetime] = None) -> str:
    dt = dt or _now()
    return dt.isoformat(timespec="minutes")


def _format_created_at(dt: Optional[datetime] = None) -> str:
    dt = dt or _now()
    return dt.strftime("%Y-%m-%d %H:%M")


def _format_month(dt: Optional[datetime] = None) -> str:
    dt = dt or _now()
    return dt.strftime("%m")


def _format_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days} 天")
    if hours:
        parts.append(f"{hours} 小時")
    if minutes or not parts:
        parts.append(f"{minutes} 分鐘")
    return "、".join(parts)


def _deep_default_structure() -> dict:
    return copy.deepcopy(DEFAULT_STRUCTURE)


def _is_email(value: str) -> bool:
    return bool(EMAIL_RE.match((value or "").strip()))


def _email_domain(email: str) -> str:
    value = (email or "").strip().lower()
    if "@" not in value:
        return ""
    return value.rsplit("@", 1)[1]


def _normalize_account_name(value: str) -> str:
    return (value or "").strip()


def _make_code(length: int = 6, digits_only: bool = True) -> str:
    alphabet = string.digits if digits_only else (string.ascii_letters + string.digits)
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _make_suggestions(base: str, accounts: dict[str, Any], limit: int = 5) -> list[str]:
    base = _normalize_account_name(base)
    if not base:
        base = "name"

    suggestions: list[str] = []
    idx = 1
    while len(suggestions) < limit:
        candidate = f"{base}_{idx}"
        if candidate not in accounts and candidate not in suggestions:
            suggestions.append(candidate)
        idx += 1
    return suggestions


def _sanitize_account_record(account: str, info: dict[str, Any]) -> dict[str, Any]:
    info = info if isinstance(info, dict) else {}
    info.setdefault("password", "")
    info.setdefault("initial_password", info.get("password", ""))
    info.setdefault("gmail", "")
    info.setdefault("2fa_enabled", False)
    info.setdefault("secret", "")
    info.setdefault("created_at", _format_created_at())
    info.setdefault("created_month", _format_month())
    info.setdefault("server_history", {})
    return info


def _is_expired(iso_value: str) -> bool:
    dt = _dt_from_iso(iso_value)
    if dt is None:
        return True
    return _now() >= dt


async def _maybe_await(value):
    if inspect.isawaitable(value):
        return await value
    return value


async def load_account_data():
    try:
        data = await load_json(DATA_FILE)
    except Exception as e:
        log.DcBot_main.warning(f"[警告] 讀取檔案失敗：{DATA_FILE}，原因：{e}")
        log.DcBot_main.error("❌ 發生例外", exc_info=True)
        return _deep_default_structure()

    if not isinstance(data, dict):
        log.DcBot_main.warning("[警告] 資料格式錯誤，非 dict，回傳預設結構")
        return _deep_default_structure()

    # 舊格式轉換
    if "accounts" not in data:
        log.DcBot_main.info("[INFO] 檢測到舊格式資料，正在轉換並儲存")
        log.DcBot_main.debug(f"[DEBUG] data type: {type(data)}")
        log.DcBot_main.debug(f"[DEBUG] data content: {data}")

        migrated = _deep_default_structure()
        for username, info in data.items():
            if not isinstance(info, dict):
                continue
            migrated["accounts"][username] = {
                "password": info.get("password", ""),
                "initial_password": info.get("password", ""),
                "gmail": info.get("gmail", ""),
                "2fa_enabled": info.get("2fa_enabled", False),
                "secret": info.get("secret", ""),
                "created_at": info.get("created_at", _format_created_at()),
                "created_month": info.get("created_month", _format_month()),
                "server_history": info.get("server_history", {})
            }

        await save_json(DATA_FILE, migrated)
        return migrated

    for key in DEFAULT_STRUCTURE:
        data.setdefault(key, {})

    if not isinstance(data["accounts"], dict):
        data["accounts"] = {}
    if not isinstance(data["sessions"], dict):
        data["sessions"] = {}
    if not isinstance(data["pending_2fa"], dict):
        data["pending_2fa"] = {}
    if not isinstance(data["locks"], dict):
        data["locks"] = {}

    for account, info in list(data["accounts"].items()):
        data["accounts"][account] = _sanitize_account_record(account, info)

    _cleanup_expired_state(data)
    return data


def _cleanup_expired_state(data: dict[str, Any]) -> None:
    now = _now()

    pending_root = data.get("pending_2fa", {})
    if isinstance(pending_root, dict):
        for guild_id, guild_pending in list(pending_root.items()):
            if not isinstance(guild_pending, dict):
                pending_root.pop(guild_id, None)
                continue
            for user_id, pending in list(guild_pending.items()):
                if not isinstance(pending, dict):
                    guild_pending.pop(user_id, None)
                    continue
                expire_at = pending.get("expires_at")
                dt = _dt_from_iso(expire_at) if isinstance(expire_at, str) else None
                if dt is None or now >= dt:
                    guild_pending.pop(user_id, None)
            if not guild_pending:
                pending_root.pop(guild_id, None)

    lock_root = data.get("locks", {})
    if isinstance(lock_root, dict):
        for guild_id, guild_locks in list(lock_root.items()):
            if not isinstance(guild_locks, dict):
                lock_root.pop(guild_id, None)
                continue
            for user_id, lock_info in list(guild_locks.items()):
                if not isinstance(lock_info, dict):
                    guild_locks.pop(user_id, None)
                    continue
                until = lock_info.get("until")
                dt = _dt_from_iso(until) if isinstance(until, str) else None
                if dt is None or now >= dt:
                    guild_locks.pop(user_id, None)
            if not guild_locks:
                lock_root.pop(guild_id, None)


def _guild_bucket(data: dict[str, Any], root_key: str, guild_id: str) -> dict[str, Any]:
    root = data.setdefault(root_key, {})
    if not isinstance(root, dict):
        data[root_key] = {}
        root = data[root_key]
    bucket = root.setdefault(str(guild_id), {})
    if not isinstance(bucket, dict):
        root[str(guild_id)] = {}
        bucket = root[str(guild_id)]
    return bucket


# --- Session management ---
def get_user_session(data, guild_id: str, user_id: str):
    guild_bucket = data.get("sessions", {})
    if isinstance(guild_bucket, dict):
        sess = guild_bucket.get(str(guild_id), {}).get(str(user_id))
        if isinstance(sess, dict):
            return sess
        if isinstance(sess, str):
            return {"account": sess}
        if str(user_id) in guild_bucket and isinstance(guild_bucket.get(str(user_id)), str):
            return {"account": guild_bucket.get(str(user_id))}
    return None


def set_user_session(data, guild_id: str, user_id: str, account: str):
    sessions = data.setdefault("sessions", {})
    if not isinstance(sessions, dict):
        data["sessions"] = {}
        sessions = data["sessions"]
    sessions.setdefault(str(guild_id), {})[str(user_id)] = {
        "account": account,
        "guild_id": str(guild_id),
        "logged_at": _to_iso(),
        "updated_at": _to_iso()
    }


def clear_user_session(data, guild_id: str, user_id: str):
    sessions = data.get("sessions", {})
    if not isinstance(sessions, dict):
        return
    guild_bucket = sessions.get(str(guild_id))
    if isinstance(guild_bucket, dict):
        guild_bucket.pop(str(user_id), None)
        if not guild_bucket:
            sessions.pop(str(guild_id), None)
    elif str(user_id) in sessions:
        sessions.pop(str(user_id), None)


def iter_all_sessions(data: dict[str, Any]):
    sessions = data.get("sessions", {})
    if not isinstance(sessions, dict):
        return
    for guild_id, guild_sessions in sessions.items():
        if not isinstance(guild_sessions, dict):
            continue
        for user_id, info in guild_sessions.items():
            if isinstance(info, dict):
                yield str(guild_id), str(user_id), info
            elif isinstance(info, str):
                yield str(guild_id), str(user_id), {"account": info}


def _record_server_history(data: dict[str, Any], account: str, guild_id: str, user_id: str):
    info = data["accounts"].setdefault(account, _sanitize_account_record(account, {}))
    history = info.setdefault("server_history", {})
    if not isinstance(history, dict):
        history = {}
        info["server_history"] = history

    guild_key = str(guild_id)
    entry = history.setdefault(guild_key, {})
    if not isinstance(entry, dict):
        entry = {}
        history[guild_key] = entry

    entry.setdefault("first_seen_at", _format_created_at())
    entry["last_seen_at"] = _format_created_at()
    entry["last_user_id"] = str(user_id)
    entry["login_count"] = int(entry.get("login_count", 0)) + 1
    entry["guild_id"] = guild_key


def _get_role(guild: discord.Guild | None) -> Optional[discord.Role]:
    if guild is None:
        return None
    return discord.utils.get(guild.roles, name=VERIFIED_ROLE_NAME)


async def _apply_verified_role(bot: commands.Bot, guild_id: str, user_id: str, add: bool):
    try:
        guild = bot.get_guild(int(guild_id))
        if guild is None:
            return

        member = guild.get_member(int(user_id))
        if member is None:
            try:
                member = await guild.fetch_member(int(user_id))
            except Exception:
                member = None

        if member is None:
            return

        role = _get_role(guild)
        if role is None:
            log.DcBot_main.warning(f"[警告] 找不到身分組：{VERIFIED_ROLE_NAME}，guild={guild_id}")
            return

        if add:
            if role not in member.roles:
                await member.add_roles(role, reason="account login verified")
        else:
            if role in member.roles:
                await member.remove_roles(role, reason="account logout / revoke")
    except Exception:
        log.DcBot_main.error("❌ 身分組更新失敗", exc_info=True)


async def _revoke_sessions_for_account(bot: commands.Bot, data: dict[str, Any], account: str, exclude: Optional[tuple[str, str]] = None):
    affected: list[tuple[str, str]] = []
    for guild_id, user_id, sess in list(iter_all_sessions(data)):
        if sess.get("account") != account:
            continue
        if exclude and (guild_id, user_id) == exclude:
            continue
        clear_user_session(data, guild_id, user_id)
        affected.append((guild_id, user_id))

    for guild_id, user_id in affected:
        await _apply_verified_role(bot, guild_id, user_id, add=False)

    return affected


def _get_pending(data: dict[str, Any], guild_id: str, user_id: str) -> Optional[dict[str, Any]]:
    guild_pending = _guild_bucket(data, "pending_2fa", guild_id)
    pending = guild_pending.get(str(user_id))
    return pending if isinstance(pending, dict) else None


def _set_pending(data: dict[str, Any], guild_id: str, user_id: str, payload: dict[str, Any]):
    _guild_bucket(data, "pending_2fa", guild_id)[str(user_id)] = payload


def _clear_pending(data: dict[str, Any], guild_id: str, user_id: str):
    _guild_bucket(data, "pending_2fa", guild_id).pop(str(user_id), None)


def _get_lock(data: dict[str, Any], guild_id: str, user_id: str) -> Optional[dict[str, Any]]:
    lock = _guild_bucket(data, "locks", guild_id).get(str(user_id))
    if not isinstance(lock, dict):
        return None
    until = lock.get("until")
    dt = _dt_from_iso(until) if isinstance(until, str) else None
    if dt is None or _now() >= dt:
        _guild_bucket(data, "locks", guild_id).pop(str(user_id), None)
        return None
    return lock


def _clear_lock(data: dict[str, Any], guild_id: str, user_id: str):
    _guild_bucket(data, "locks", guild_id).pop(str(user_id), None)


def _lock_user(data: dict[str, Any], guild_id: str, user_id: str, reason: str, attempts: int):
    until = _now() + timedelta(days=LOCK_DAYS)
    _guild_bucket(data, "locks", guild_id)[str(user_id)] = {
        "until": _to_iso(until),
        "reason": reason,
        "attempts": attempts,
        "guild_id": str(guild_id),
        "user_id": str(user_id)
    }


def _register_failure(data: dict[str, Any], guild_id: str, user_id: str, reason: str) -> tuple[bool, int]:
    lock_bucket = _guild_bucket(data, "locks", guild_id)
    lock = lock_bucket.get(str(user_id))
    attempts = 0
    if isinstance(lock, dict):
        attempts = int(lock.get("attempts", 0))
    attempts += 1
    if attempts >= 3:
        _lock_user(data, guild_id, user_id, reason, attempts)
        return True, attempts

    lock_bucket[str(user_id)] = {
        "attempts": attempts,
        "reason": reason,
        "guild_id": str(guild_id),
        "user_id": str(user_id),
        "updated_at": _to_iso()
    }
    return False, attempts


def _lock_message(lock_info: dict[str, Any]) -> str:
    until = lock_info.get("until")
    dt = _dt_from_iso(until) if isinstance(until, str) else None
    if dt is None:
        return "❌ 你的 /account 指令已被鎖定。"
    remaining = dt - _now()
    if remaining.total_seconds() <= 0:
        return "❌ 你的 /account 指令已被鎖定。"
    return f"❌ 你的 /account 指令已被鎖定，剩餘 {_format_duration(remaining.total_seconds())}。"


async def _send_gmail_safe(to_email: str, title: str, content: str):
    try:
        await _maybe_await(gmail_send(to_email=to_email, title=title, content=content))
    except Exception:
        log.DcBot_main.error("❌ 發送 Gmail 失敗", exc_info=True)
        raise


def _ensure_account_exists(data: dict[str, Any], account: str) -> Optional[dict[str, Any]]:
    info = data["accounts"].get(account)
    if info is None:
        return None
    if not isinstance(info, dict):
        return None
    data["accounts"][account] = _sanitize_account_record(account, info)
    return data["accounts"][account]


def _account_matches_email(info: dict[str, Any], email: str) -> bool:
    stored = (info.get("gmail") or "").strip().lower()
    return stored and stored == (email or "").strip().lower()


def _prepare_register_pending(
    data: dict[str, Any],
    guild_id: str,
    user_id: str,
    account: str,
    password: str,
    gmail: str
) -> dict[str, Any]:
    code = _make_code(6, digits_only=True)
    payload = {
        "action": "register",
        "account": account,
        "password": password,
        "initial_password": password,
        "gmail": gmail,
        "code": code,
        "attempts": 0,
        "created_at": _format_created_at(),
        "created_month": _format_month(),
        "expires_at": _to_iso(_now() + timedelta(minutes=CODE_EXPIRE_MINUTES))
    }
    _set_pending(data, guild_id, user_id, payload)
    return payload


def _prepare_login_2fa_pending(
    data: dict[str, Any],
    guild_id: str,
    user_id: str,
    account: str
) -> dict[str, Any]:
    payload = {
        "action": "login_2fa",
        "account": account,
        "attempts": 0,
        "expires_at": _to_iso(_now() + timedelta(minutes=CODE_EXPIRE_MINUTES))
    }
    _set_pending(data, guild_id, user_id, payload)
    return payload


def _prepare_enable_2fa_pending(
    data: dict[str, Any],
    guild_id: str,
    user_id: str,
    account: str,
    secret: str
) -> dict[str, Any]:
    payload = {
        "action": "enable_2fa",
        "account": account,
        "secret": secret,
        "attempts": 0,
        "expires_at": _to_iso(_now() + timedelta(minutes=CODE_EXPIRE_MINUTES))
    }
    _set_pending(data, guild_id, user_id, payload)
    return payload


def _prepare_email_code_pending(
    data: dict[str, Any],
    guild_id: str,
    user_id: str,
    action: str,
    account: str,
    email: str,
    extra: Optional[dict[str, Any]] = None,
    length: int = 6
) -> dict[str, Any]:
    code = _make_code(length, digits_only=False if length > 6 else True)
    payload = {
        "action": action,
        "account": account,
        "gmail": email,
        "code": code,
        "attempts": 0,
        "expires_at": _to_iso(_now() + timedelta(minutes=CODE_EXPIRE_MINUTES))
    }
    if extra:
        payload.update(extra)
    _set_pending(data, guild_id, user_id, payload)
    return payload


async def _send_login_notice(bot: commands.Bot, info: dict[str, Any], account: str, guild: discord.Guild | None, user: discord.abc.User):
    email = (info.get("gmail") or "").strip()
    if not email:
        return

    guild_text = f"{guild.name} ({guild.id})" if guild else "未知伺服器"
    content = (
        f"帳號：{account}\n"
        f"登入時間：{_format_created_at()}\n"
        f"伺服器：{guild_text}\n"
        f"使用者：{user} ({user.id})\n\n"
        f"若這不是你本人操作，請立即更改密碼並檢查帳號安全。"
    )
    await _send_gmail_safe(email, "新的登入通知", content)


async def _send_register_thanks(info: dict[str, Any], account: str):
    email = (info.get("gmail") or "").strip()
    if not email:
        return

    content = (
        f"帳號：{account}\n"
        f"註冊月份：{info.get('created_month', _format_month())}\n\n"
        f"感謝你的註冊。"
    )
    await _send_gmail_safe(email, "註冊完成通知", content)


async def _send_recovery_code_email(info: dict[str, Any], action_title: str, code: str, extra: str = ""):
    email = (info.get("gmail") or "").strip()
    if not email:
        raise ValueError("帳號未綁定 gmail")
    content = (
        f"帳號：{extra or info.get('account_name', '')}\n"
        f"驗證碼：{code}\n\n"
        f"這封信是為了 {action_title}。若非本人操作，請忽略。"
    )
    await _send_gmail_safe(email, action_title, content)


def _build_qr_file(secret: str, account: str) -> tuple[discord.File, str]:
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=account, issuer_name="虛擬網站登入系統")
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return discord.File(buf, filename="qrcode.png"), uri


class RetryCodeView(discord.ui.View):
    def __init__(self, modal_factory: Callable[[], discord.ui.Modal], cancel_callback: Optional[Callable[[discord.Interaction], Any]] = None, timeout: int = 120):
        super().__init__(timeout=timeout)
        self.modal_factory = modal_factory
        self.cancel_callback = cancel_callback

    @discord.ui.button(label="重新輸入", style=discord.ButtonStyle.primary)
    async def retry(self, interaction: discord.Interaction, button: discord.ui.Button):
        try:
            await interaction.response.send_modal(self.modal_factory())
        except Exception:
            log.DcBot_main.error("❌ 重新輸入 modal 發送失敗", exc_info=True)
            if not interaction.response.is_done():
                await interaction.response.send_message("❌ 無法重新開啟輸入視窗。", ephemeral=True)

    @discord.ui.button(label="取消", style=discord.ButtonStyle.danger)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        try:
            if self.cancel_callback is not None:
                await _maybe_await(self.cancel_callback(interaction))
            else:
                await interaction.response.send_message("🚫 已取消。", ephemeral=True)
            self.stop()
        except Exception:
            log.DcBot_main.error("❌ 取消流程失敗", exc_info=True)
            if not interaction.response.is_done():
                await interaction.response.send_message("❌ 取消失敗。", ephemeral=True)


class LogoutConfirmView(discord.ui.View):
    def __init__(self, cog: "AccountCog", guild_id: str, user_id: str, timeout: int = 60):
        super().__init__(timeout=timeout)
        self.cog = cog
        self.guild_id = str(guild_id)
        self.user_id = str(user_id)

    @discord.ui.button(label="登出", style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        try:
            data = await load_account_data()
            sess = get_user_session(data, self.guild_id, self.user_id)
            acct = sess.get("account") if isinstance(sess, dict) else None
            clear_user_session(data, self.guild_id, self.user_id)
            _clear_pending(data, self.guild_id, self.user_id)
            _clear_lock(data, self.guild_id, self.user_id)
            await save_json(DATA_FILE, data)

            if acct:
                await _apply_verified_role(self.cog.bot, self.guild_id, self.user_id, add=False)

            await interaction.response.send_message("✅ 已成功登出。", ephemeral=True)
            self.stop()
        except Exception:
            log.DcBot_main.error("❌ 登出失敗", exc_info=True)
            if not interaction.response.is_done():
                await interaction.response.send_message("❌ 登出失敗，請稍後再試。", ephemeral=True)


class CanAccess2FAView(discord.ui.View):
    def __init__(self, cog: "AccountCog", guild_id: str, user_id: str, account: str, timeout: int = 60):
        super().__init__(timeout=timeout)
        self.cog = cog
        self.guild_id = str(guild_id)
        self.user_id = str(user_id)
        self.account = account

    @discord.ui.button(label="可以", style=discord.ButtonStyle.success)
    async def yes(self, interaction: discord.Interaction, button: discord.ui.Button):
        try:
            await interaction.response.send_modal(Disable2FATOTPModal(self.cog, self.guild_id, self.user_id, self.account))
        except Exception:
            log.DcBot_main.error("❌ 開啟停用 2FA modal 失敗", exc_info=True)
            if not interaction.response.is_done():
                await interaction.response.send_message("❌ 無法開啟輸入視窗。", ephemeral=True)

    @discord.ui.button(label="不行", style=discord.ButtonStyle.danger)
    async def no(self, interaction: discord.Interaction, button: discord.ui.Button):
        try:
            await interaction.response.send_message(
                "你已進入帳號恢復流程，請前往進階模式完成後續操作。",
                view=AdvancedEntryView(self.cog, self.guild_id, self.user_id),
                ephemeral=True
            )
        except Exception:
            log.DcBot_main.error("❌ 進階模式入口失敗", exc_info=True)
            if not interaction.response.is_done():
                await interaction.response.send_message("❌ 無法進入進階模式。", ephemeral=True)


class AdvancedEntryView(discord.ui.View):
    def __init__(self, cog: "AccountCog", guild_id: str, user_id: str, timeout: int = 120):
        super().__init__(timeout=timeout)
        self.cog = cog
        self.guild_id = str(guild_id)
        self.user_id = str(user_id)

    @discord.ui.button(label="進入進階模式", style=discord.ButtonStyle.primary)
    async def enter(self, interaction: discord.Interaction, button: discord.ui.Button):
        try:
            data = await load_account_data()
            sess = get_user_session(data, self.guild_id, self.user_id)
            account = sess.get("account") if isinstance(sess, dict) else None
            if not account:
                await interaction.response.send_message("❌ 你目前尚未登入。", ephemeral=True)
                return
            await interaction.response.send_modal(AdvancedActionModal(self.cog, self.guild_id, self.user_id, account))
        except Exception:
            log.DcBot_main.error("❌ 進階模式開啟失敗", exc_info=True)
            if not interaction.response.is_done():
                await interaction.response.send_message("❌ 無法進入進階模式。", ephemeral=True)


class SettingActionModal(discord.ui.Modal):
    def __init__(self, cog: "AccountCog", guild_id: str, user_id: str):
        super().__init__(title="請在此設定", timeout=180)
        self.cog = cog
        self.guild_id = str(guild_id)
        self.user_id = str(user_id)

        self.choice = discord.ui.Select(
            placeholder="點我選擇一項",
            min_values=1,
            max_values=1,
            options=[]
        )
        self.account_q2 = discord.ui.TextInput(label="請輸入帳號", placeholder="只在進階模式需要", required=False)
        self.password_q3 = discord.ui.TextInput(label="請輸入帳號密碼", placeholder="只在進階模式需要", required=False, style=discord.TextStyle.short)

        self.add_item(self.choice)
        self.add_item(self.account_q2)
        self.add_item(self.password_q3)

    def _set_options(self, enabled: bool):
        self.choice.options = [
            discord.SelectOption(label="登出", description="登出目前的帳號", emoji="🚪", value="logout"),
            discord.SelectOption(label=("關閉" if enabled else "開啟") + " 2FA", description="為帳號多一層保護", emoji="⚙️", value="toggle_2fa"),
            discord.SelectOption(label="進階設定", description="查看更進階的設定", emoji="🛠️", value="advanced"),
        ]

    async def on_submit(self, interaction: discord.Interaction):
        try:
            data = await load_account_data()
            sess = get_user_session(data, self.guild_id, self.user_id)
            account = sess.get("account") if isinstance(sess, dict) else None
            if not account:
                await interaction.response.send_message("❌ 你目前尚未登入。", ephemeral=True)
                return

            info = _ensure_account_exists(data, account)
            if not info:
                await interaction.response.send_message("❌ 帳號資料不存在。", ephemeral=True)
                return

            self._set_options(bool(info.get("2fa_enabled", False)))
            choice = self.choice.values[0] if self.choice.values else None
            if not choice:
                await interaction.response.send_message("❌ 請先選擇設定項目。", ephemeral=True)
                return

            if self.account_q2.value.strip() and self.account_q2.value.strip() != account:
                await interaction.response.send_message("❌ 進階模式帳號不符目前登入帳號。", ephemeral=True)
                return

            if self.password_q3.value.strip():
                if info.get("password", "") != self.password_q3.value.strip():
                    await interaction.response.send_message("❌ 進階模式密碼錯誤。", ephemeral=True)
                    return

            if choice == "logout":
                await interaction.response.send_message(
                    f"你目前登入帳號：{account}\n請確認後再按下登出，否則請忽略此訊息。",
                    view=LogoutConfirmView(self.cog, self.guild_id, self.user_id),
                    ephemeral=True
                )
                return

            if choice == "toggle_2fa":
                if info.get("2fa_enabled"):
                    await interaction.response.send_message(
                        "你已啟用 2FA，請選擇是否能存取 6 位驗證碼。",
                        view=CanAccess2FAView(self.cog, self.guild_id, self.user_id, account),
                        ephemeral=True
                    )
                else:
                    await interaction.response.send_modal(Enable2FAPasswordModal(self.cog, self.guild_id, self.user_id, account))
                return

            if choice == "advanced":
                await interaction.response.send_modal(AdvancedActionModal(self.cog, self.guild_id, self.user_id, account))
                return

            await interaction.response.send_message("❌ 無效選項！", ephemeral=True)
        except Exception:
            log.DcBot_main.error("❌ 設定流程失敗", exc_info=True)
            if not interaction.response.is_done():
                await interaction.response.send_message("❌ 發生錯誤，請稍後再試。", ephemeral=True)


class AdvancedActionModal(discord.ui.Modal):
    def __init__(self, cog: "AccountCog", guild_id: str, user_id: str, account: str):
        super().__init__(title="進階設定", timeout=180)
        self.cog = cog
        self.guild_id = str(guild_id)
        self.user_id = str(user_id)
        self.account = account

        self.action = discord.ui.Select(
            placeholder="請選擇進階操作",
            min_values=1,
            max_values=1,
            options=[
                discord.SelectOption(label="更改密碼", description="需要知道目前密碼", value="change_password"),
                discord.SelectOption(label="關閉2FA", description="帳號恢復流程", value="disable_2fa"),
                discord.SelectOption(label="透過電子郵件強制恢復帳號", description="最危險的手段，但至少電子郵件不能改", value="force_recovery"),
                discord.SelectOption(label="刪除帳號", description="請三思", value="delete_account"),
            ]
        )
        self.account_q2 = discord.ui.TextInput(label="請輸入帳號", placeholder="只在進階模式需要", required=False)
        self.password_q3 = discord.ui.TextInput(label="請輸入帳號密碼", placeholder="只在進階模式需要", required=False, style=discord.TextStyle.short)

        self.add_item(self.action)
        self.add_item(self.account_q2)
        self.add_item(self.password_q3)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            data = await load_account_data()
            info = _ensure_account_exists(data, self.account)
            if not info:
                await interaction.response.send_message("❌ 帳號資料不存在。", ephemeral=True)
                return

            if self.account_q2.value.strip() and self.account_q2.value.strip() != self.account:
                await interaction.response.send_message("❌ 進階模式帳號不符目前登入帳號。", ephemeral=True)
                return

            if self.password_q3.value.strip() and info.get("password", "") != self.password_q3.value.strip():
                await interaction.response.send_message("❌ 進階模式密碼錯誤。", ephemeral=True)
                return

            choice = self.action.values[0] if self.action.values else None
            if not choice:
                await interaction.response.send_message("❌ 請先選擇進階操作。", ephemeral=True)
                return

            if choice == "change_password":
                await interaction.response.send_modal(ChangePasswordModal(self.cog, self.guild_id, self.user_id, self.account))
                return

            if choice == "disable_2fa":
                if not info.get("2fa_enabled"):
                    await interaction.response.send_message("❌ 目前帳號尚未啟用 2FA。", ephemeral=True)
                    return

                pending = _prepare_email_code_pending(
                    data,
                    self.guild_id,
                    self.user_id,
                    action="disable_2fa",
                    account=self.account,
                    email=info.get("gmail", ""),
                    extra={}
                )
                await save_json(DATA_FILE, data)
                await _send_gmail_safe(
                    info.get("gmail", ""),
                    "關閉 2FA 驗證碼",
                    f"帳號：{self.account}\n驗證碼：{pending['code']}\n\n若非本人操作請忽略。"
                )
                await interaction.response.send_modal(Disable2FAEmailModal(self.cog, self.guild_id, self.user_id, self.account))
                return

            if choice == "force_recovery":
                pending = _prepare_email_code_pending(
                    data,
                    self.guild_id,
                    self.user_id,
                    action="force_recovery",
                    account=self.account,
                    email=info.get("gmail", ""),
                    length=80,
                    extra={
                        "reversed_code": None,
                        "created_at": info.get("created_at", _format_created_at())
                    }
                )
                pending["reversed_code"] = pending["code"][::-1]
                await save_json(DATA_FILE, data)
                await _send_gmail_safe(
                    info.get("gmail", ""),
                    "帳號強制恢復驗證碼",
                    f"帳號：{self.account}\n驗證碼：{pending['code']}\n\n請妥善保存。"
                )
                await interaction.response.send_modal(ForceRecoveryModal(self.cog, self.guild_id, self.user_id, self.account))
                return

            if choice == "delete_account":
                pending = _prepare_email_code_pending(
                    data,
                    self.guild_id,
                    self.user_id,
                    action="delete_account",
                    account=self.account,
                    email=info.get("gmail", ""),
                    extra={}
                )
                await save_json(DATA_FILE, data)
                await _send_gmail_safe(
                    info.get("gmail", ""),
                    "刪除帳號驗證碼",
                    f"帳號：{self.account}\n驗證碼：{pending['code']}\n\n若非本人操作請忽略。"
                )
                await interaction.response.send_modal(DeleteAccountModal(self.cog, self.guild_id, self.user_id, self.account))
                return

            await interaction.response.send_message("❌ 無效選項！", ephemeral=True)
        except Exception:
            log.DcBot_main.error("❌ 進階設定流程失敗", exc_info=True)
            if not interaction.response.is_done():
                await interaction.response.send_message("❌ 發生錯誤，請稍後再試。", ephemeral=True)


class RegisterRenameModal(discord.ui.Modal):
    def __init__(self, cog: "AccountCog", guild_id: str, user_id: str, password: str, gmail: str, suggestions: list[str]):
        super().__init__(title="註冊帳號", timeout=180)
        self.cog = cog
        self.guild_id = str(guild_id)
        self.user_id = str(user_id)
        self.password = password
        self.gmail = gmail
        placeholder = "你可以考慮 " + " 或 ".join(suggestions[:2]) if suggestions else "請輸入新的帳號名稱"
        self.account = discord.ui.TextInput(label="帳號", placeholder=placeholder, min_length=3)
        self.add_item(self.account)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            data = await load_account_data()
            account = _normalize_account_name(self.account.value)
            if not account:
                await interaction.response.send_message("❌ 帳號不能為空。", ephemeral=True)
                return
            if account in data["accounts"]:
                suggestions = _make_suggestions(account, data["accounts"])
                await interaction.response.send_message(
                    f"❌ 帳號已存在，請重新輸入。\n建議：{', '.join(suggestions)}",
                    view=RetryCodeView(lambda: RegisterRenameModal(self.cog, self.guild_id, self.user_id, self.password, self.gmail, suggestions)),
                    ephemeral=True
                )
                return

            pending = _prepare_register_pending(data, self.guild_id, self.user_id, account, self.password, self.gmail)
            await save_json(DATA_FILE, data)
            await _send_gmail_safe(
                self.gmail,
                "註冊驗證碼",
                f"帳號：{account}\n驗證碼：{pending['code']}\n\n若非本人操作請忽略。"
            )
            await interaction.response.send_message(
                "✅ 驗證碼已寄出，請輸入 6 位數驗證碼。",
                view=RetryCodeView(lambda: RegisterCodeModal(self.cog, self.guild_id, self.user_id)),
                ephemeral=True
            )
        except Exception:
            log.DcBot_main.error("❌ 註冊名稱確認失敗", exc_info=True)
            if not interaction.response.is_done():
                await interaction.response.send_message("❌ 發生錯誤，請稍後再試。", ephemeral=True)


class RegisterCodeModal(discord.ui.Modal):
    def __init__(self, cog: "AccountCog", guild_id: str, user_id: str):
        super().__init__(title="註冊驗證", timeout=180)
        self.cog = cog
        self.guild_id = str(guild_id)
        self.user_id = str(user_id)
        self.code = discord.ui.TextInput(label="驗證碼(6位)", max_length=6, min_length=6, style=discord.TextStyle.short)
        self.add_item(self.code)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            data = await load_account_data()
            pending = _get_pending(data, self.guild_id, self.user_id)
            if not pending or pending.get("action") != "register":
                await interaction.response.send_message("❌ 驗證已失效，請重新註冊。", ephemeral=True)
                return
            if pending.get("expires_at") and _is_expired(pending["expires_at"]):
                _clear_pending(data, self.guild_id, self.user_id)
                await save_json(DATA_FILE, data)
                await interaction.response.send_message("❌ 驗證碼已過期，請重新註冊。", ephemeral=True)
                return

            if self.code.value.strip() != pending.get("code"):
                locked, attempts = _register_failure(data, self.guild_id, self.user_id, "register")
                if locked:
                    _clear_pending(data, self.guild_id, self.user_id)
                await save_json(DATA_FILE, data)
                if locked:
                    lock_info = _get_lock(data, self.guild_id, self.user_id) or {}
                    await interaction.response.send_message(_lock_message(lock_info), ephemeral=True)
                    return
                await interaction.response.send_message(
                    f"❌ 驗證碼錯誤！剩餘嘗試次數：{3 - attempts}",
                    view=RetryCodeView(lambda: RegisterCodeModal(self.cog, self.guild_id, self.user_id)),
                    ephemeral=True
                )
                return

            account = pending["account"]
            gmail = pending["gmail"]
            password = pending["password"]
            created_at = pending.get("created_at", _format_created_at())
            created_month = pending.get("created_month", _format_month())

            data["accounts"][account] = _sanitize_account_record(account, {
                "password": password,
                "initial_password": pending.get("initial_password", password),
                "gmail": gmail,
                "2fa_enabled": False,
                "secret": "",
                "created_at": created_at,
                "created_month": created_month,
                "server_history": data["accounts"].get(account, {}).get("server_history", {})
            })

            _clear_pending(data, self.guild_id, self.user_id)
            _clear_lock(data, self.guild_id, self.user_id)
            _record_server_history(data, account, self.guild_id, self.user_id)
            await save_json(DATA_FILE, data)

            await _send_register_thanks(data["accounts"][account], account)
            await interaction.response.send_message(f"✅ {account} 註冊成功，請重新登入。", ephemeral=True)
        except Exception:
            log.DcBot_main.error("❌ 註冊驗證失敗", exc_info=True)
            if not interaction.response.is_done():
                await interaction.response.send_message("❌ 發生錯誤，請稍後再試。", ephemeral=True)


class LoginRetryModal(discord.ui.Modal):
    def __init__(self, cog: "AccountCog", guild_id: str, user_id: str):
        super().__init__(title="登入", timeout=180)
        self.cog = cog
        self.guild_id = str(guild_id)
        self.user_id = str(user_id)
        self.account = discord.ui.TextInput(label="帳號")
        self.password = discord.ui.TextInput(label="密碼", style=discord.TextStyle.short)
        self.add_item(self.account)
        self.add_item(self.password)

    async def on_submit(self, interaction: discord.Interaction):
        await self.cog._handle_login_submission(interaction, self.account.value, self.password.value, retry_modal=True, retry_factory=lambda: LoginRetryModal(self.cog, self.guild_id, self.user_id))


class Login2FAModal(discord.ui.Modal):
    def __init__(self, cog: "AccountCog", guild_id: str, user_id: str, account: str):
        super().__init__(title="雙步驟驗證", timeout=180)
        self.cog = cog
        self.guild_id = str(guild_id)
        self.user_id = str(user_id)
        self.account = account
        self.code = discord.ui.TextInput(label="驗證碼(6位)", max_length=6, min_length=6, style=discord.TextStyle.short)
        self.add_item(self.code)

    async def on_submit(self, interaction: discord.Interaction):
        await self.cog._handle_login_2fa_submission(
            interaction,
            self.account,
            self.code.value.strip(),
            retry_factory=lambda: Login2FAModal(self.cog, self.guild_id, self.user_id, self.account),
        )


class Enable2FAPasswordModal(discord.ui.Modal):
    def __init__(self, cog: "AccountCog", guild_id: str, user_id: str, account: str):
        super().__init__(title="雙步驟驗證設定", timeout=180)
        self.cog = cog
        self.guild_id = str(guild_id)
        self.user_id = str(user_id)
        self.account = account
        self.pwd = discord.ui.TextInput(label="目前密碼", style=discord.TextStyle.short)
        self.add_item(self.pwd)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            data = await load_account_data()
            info = _ensure_account_exists(data, self.account)
            if not info:
                await interaction.response.send_message("❌ 帳號資料不存在。", ephemeral=True)
                return
            if info.get("password", "") != self.pwd.value:
                locked, attempts = _register_failure(data, self.guild_id, self.user_id, "enable_2fa_password")
                await save_json(DATA_FILE, data)
                if locked:
                    lock_info = _get_lock(data, self.guild_id, self.user_id) or {}
                    await interaction.response.send_message(_lock_message(lock_info), ephemeral=True)
                    return
                await interaction.response.send_message(
                    f"❌ 密碼錯誤！剩餘嘗試次數：{3 - attempts}",
                    view=RetryCodeView(lambda: Enable2FAPasswordModal(self.cog, self.guild_id, self.user_id, self.account)),
                    ephemeral=True
                )
                return

            secret = pyotp.random_base32()
            _prepare_enable_2fa_pending(data, self.guild_id, self.user_id, self.account, secret)
            await save_json(DATA_FILE, data)

            file, uri = _build_qr_file(secret, self.account)
            await interaction.response.send_message(
                f"✅ 2FA 已準備完成，請先掃描 QR Code。\n手動密鑰：`{secret}`",
                file=file,
                view=Enable2FAProceedView(self.cog, self.guild_id, self.user_id, self.account),
                ephemeral=True
            )
        except Exception:
            log.DcBot_main.error("❌ 啟用 2FA 起始失敗", exc_info=True)
            if not interaction.response.is_done():
                await interaction.response.send_message("❌ 發生錯誤，請稍後再試。", ephemeral=True)


class Enable2FAProceedView(discord.ui.View):
    def __init__(self, cog: "AccountCog", guild_id: str, user_id: str, account: str, timeout: int = 180):
        super().__init__(timeout=timeout)
        self.cog = cog
        self.guild_id = str(guild_id)
        self.user_id = str(user_id)
        self.account = account

    @discord.ui.button(label="輸入 6 位驗證碼", style=discord.ButtonStyle.success)
    async def enter_code(self, interaction: discord.Interaction, button: discord.ui.Button):
        try:
            await interaction.response.send_modal(Enable2FACodeModal(self.cog, self.guild_id, self.user_id, self.account))
        except Exception:
            log.DcBot_main.error("❌ 開啟 2FA 驗證 modal 失敗", exc_info=True)
            if not interaction.response.is_done():
                await interaction.response.send_message("❌ 無法開啟驗證視窗。", ephemeral=True)


class Enable2FACodeModal(discord.ui.Modal):
    def __init__(self, cog: "AccountCog", guild_id: str, user_id: str, account: str):
        super().__init__(title="雙步驟驗證", timeout=180)
        self.cog = cog
        self.guild_id = str(guild_id)
        self.user_id = str(user_id)
        self.account = account
        self.code = discord.ui.TextInput(label="驗證碼(6位)", max_length=6, min_length=6, style=discord.TextStyle.short)
        self.add_item(self.code)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            data = await load_account_data()
            pending = _get_pending(data, self.guild_id, self.user_id)
            info = _ensure_account_exists(data, self.account)
            if not pending or pending.get("action") != "enable_2fa" or pending.get("account") != self.account:
                await interaction.response.send_message("❌ 驗證已失效，請重新啟用 2FA。", ephemeral=True)
                return
            if pending.get("expires_at") and _is_expired(pending["expires_at"]):
                _clear_pending(data, self.guild_id, self.user_id)
                await save_json(DATA_FILE, data)
                await interaction.response.send_message("❌ 驗證碼已過期，請重新啟用 2FA。", ephemeral=True)
                return

            secret = pending.get("secret", "")
            if not secret or not pyotp.TOTP(secret).verify(self.code.value.strip(), valid_window=1):
                locked, attempts = _register_failure(data, self.guild_id, self.user_id, "enable_2fa_code")
                await save_json(DATA_FILE, data)
                if locked:
                    lock_info = _get_lock(data, self.guild_id, self.user_id) or {}
                    _clear_pending(data, self.guild_id, self.user_id)
                    await save_json(DATA_FILE, data)
                    await interaction.response.send_message(_lock_message(lock_info), ephemeral=True)
                    return
                await interaction.response.send_message(
                    f"❌ 驗證碼錯誤！剩餘嘗試次數：{3 - attempts}",
                    view=RetryCodeView(lambda: Enable2FACodeModal(self.cog, self.guild_id, self.user_id, self.account)),
                    ephemeral=True
                )
                return

            info["secret"] = secret
            info["2fa_enabled"] = True

            _clear_pending(data, self.guild_id, self.user_id)
            _clear_lock(data, self.guild_id, self.user_id)
            await _revoke_sessions_for_account(self.cog.bot, data, self.account, exclude=(self.guild_id, self.user_id))
            await save_json(DATA_FILE, data)

            await interaction.response.send_message("✅ 2FA 已啟用。", ephemeral=True)
        except Exception:
            log.DcBot_main.error("❌ 2FA 啟用驗證失敗", exc_info=True)
            if not interaction.response.is_done():
                await interaction.response.send_message("❌ 發生錯誤，請稍後再試。", ephemeral=True)


class Login2FAProceedView(discord.ui.View):
    def __init__(self, cog: "AccountCog", guild_id: str, user_id: str, account: str, timeout: int = 120):
        super().__init__(timeout=timeout)
        self.cog = cog
        self.guild_id = str(guild_id)
        self.user_id = str(user_id)
        self.account = account

    @discord.ui.button(label="輸入 2FA 驗證碼", style=discord.ButtonStyle.success)
    async def enter(self, interaction: discord.Interaction, button: discord.ui.Button):
        try:
            await interaction.response.send_modal(Login2FAModal(self.cog, self.guild_id, self.user_id, self.account))
        except Exception:
            log.DcBot_main.error("❌ 開啟登入 2FA modal 失敗", exc_info=True)
            if not interaction.response.is_done():
                await interaction.response.send_message("❌ 無法開啟驗證視窗。", ephemeral=True)


class Disable2FATOTPModal(discord.ui.Modal):
    def __init__(self, cog: "AccountCog", guild_id: str, user_id: str, account: str):
        super().__init__(title="關閉 2FA", timeout=180)
        self.cog = cog
        self.guild_id = str(guild_id)
        self.user_id = str(user_id)
        self.account = account
        self.pwd = discord.ui.TextInput(label="目前密碼", style=discord.TextStyle.short)
        self.code = discord.ui.TextInput(label="2FA 驗證碼", style=discord.TextStyle.short)
        self.add_item(self.pwd)
        self.add_item(self.code)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            data = await load_account_data()
            info = _ensure_account_exists(data, self.account)
            if not info:
                await interaction.response.send_message("❌ 帳號資料不存在。", ephemeral=True)
                return

            if info.get("password", "") != self.pwd.value:
                locked, attempts = _register_failure(data, self.guild_id, self.user_id, "disable_2fa_pwd")
                await save_json(DATA_FILE, data)
                if locked:
                    lock_info = _get_lock(data, self.guild_id, self.user_id) or {}
                    await interaction.response.send_message(_lock_message(lock_info), ephemeral=True)
                    return
                await interaction.response.send_message(
                    f"❌ 密碼錯誤！剩餘嘗試次數：{3 - attempts}",
                    view=RetryCodeView(lambda: Disable2FATOTPModal(self.cog, self.guild_id, self.user_id, self.account)),
                    ephemeral=True
                )
                return

            if not info.get("2fa_enabled"):
                await interaction.response.send_message("❌ 尚未啟用 2FA。", ephemeral=True)
                return

            secret = info.get("secret", "")
            if not secret or not pyotp.TOTP(secret).verify(self.code.value.strip(), valid_window=1):
                locked, attempts = _register_failure(data, self.guild_id, self.user_id, "disable_2fa_code")
                await save_json(DATA_FILE, data)
                if locked:
                    lock_info = _get_lock(data, self.guild_id, self.user_id) or {}
                    await interaction.response.send_message(_lock_message(lock_info), ephemeral=True)
                    return
                await interaction.response.send_message(
                    f"❌ 驗證碼錯誤！剩餘嘗試次數：{3 - attempts}",
                    view=RetryCodeView(lambda: Disable2FATOTPModal(self.cog, self.guild_id, self.user_id, self.account)),
                    ephemeral=True
                )
                return

            info["2fa_enabled"] = False
            info["secret"] = ""
            _clear_lock(data, self.guild_id, self.user_id)
            await save_json(DATA_FILE, data)

            await interaction.response.send_message("✅ 2FA 已關閉。", ephemeral=True)
        except Exception:
            log.DcBot_main.error("❌ 關閉 2FA 失敗", exc_info=True)
            if not interaction.response.is_done():
                await interaction.response.send_message("❌ 發生錯誤，請稍後再試。", ephemeral=True)


class Disable2FAEmailModal(discord.ui.Modal):
    def __init__(self, cog: "AccountCog", guild_id: str, user_id: str, account: str):
        super().__init__(title="關閉 2FA", timeout=180)
        self.cog = cog
        self.guild_id = str(guild_id)
        self.user_id = str(user_id)
        self.account = account
        self.pwd = discord.ui.TextInput(label="目前密碼", style=discord.TextStyle.short)
        self.code = discord.ui.TextInput(label="收到的 6 位數驗證碼", style=discord.TextStyle.short, max_length=6, min_length=6)
        self.add_item(self.pwd)
        self.add_item(self.code)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            data = await load_account_data()
            info = _ensure_account_exists(data, self.account)
            if not info:
                await interaction.response.send_message("❌ 帳號資料不存在。", ephemeral=True)
                return

            pending = _get_pending(data, self.guild_id, self.user_id)
            if not pending or pending.get("action") != "disable_2fa" or pending.get("account") != self.account:
                await interaction.response.send_message("❌ 驗證已失效，請重新開始關閉 2FA。", ephemeral=True)
                return

            if info.get("password", "") != self.pwd.value:
                locked, attempts = _register_failure(data, self.guild_id, self.user_id, "disable_2fa_email_pwd")
                await save_json(DATA_FILE, data)
                if locked:
                    lock_info = _get_lock(data, self.guild_id, self.user_id) or {}
                    await interaction.response.send_message(_lock_message(lock_info), ephemeral=True)
                    return
                await interaction.response.send_message(
                    f"❌ 密碼錯誤！剩餘嘗試次數：{3 - attempts}",
                    view=RetryCodeView(lambda: Disable2FAEmailModal(self.cog, self.guild_id, self.user_id, self.account)),
                    ephemeral=True
                )
                return

            if self.code.value.strip() != pending.get("code"):
                locked, attempts = _register_failure(data, self.guild_id, self.user_id, "disable_2fa_email_code")
                await save_json(DATA_FILE, data)
                if locked:
                    lock_info = _get_lock(data, self.guild_id, self.user_id) or {}
                    _clear_pending(data, self.guild_id, self.user_id)
                    await save_json(DATA_FILE, data)
                    await interaction.response.send_message(_lock_message(lock_info), ephemeral=True)
                    return
                await interaction.response.send_message(
                    f"❌ 驗證碼錯誤！剩餘嘗試次數：{3 - attempts}",
                    view=RetryCodeView(lambda: Disable2FAEmailModal(self.cog, self.guild_id, self.user_id, self.account)),
                    ephemeral=True
                )
                return

            info["2fa_enabled"] = False
            info["secret"] = ""
            _clear_pending(data, self.guild_id, self.user_id)
            _clear_lock(data, self.guild_id, self.user_id)
            await save_json(DATA_FILE, data)

            await interaction.response.send_message("✅ 2FA 已關閉。", ephemeral=True)
        except Exception:
            log.DcBot_main.error("❌ 關閉 2FA (email) 失敗", exc_info=True)
            if not interaction.response.is_done():
                await interaction.response.send_message("❌ 發生錯誤，請稍後再試。", ephemeral=True)


class ForceRecoveryModal(discord.ui.Modal):
    def __init__(self, cog: "AccountCog", guild_id: str, user_id: str, account: str):
        super().__init__(title="帳號恢復", timeout=180)
        self.cog = cog
        self.guild_id = str(guild_id)
        self.user_id = str(user_id)
        self.account = account
        self.reverse_code = discord.ui.TextInput(label="反著輸入發到 gmail 的 80 位驗證碼", style=discord.TextStyle.short)
        self.created_at = discord.ui.TextInput(label='帳號創建日期(yyyy-mm-dd hh:mm)', style=discord.TextStyle.short)
        self.add_item(self.reverse_code)
        self.add_item(self.created_at)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            data = await load_account_data()
            info = _ensure_account_exists(data, self.account)
            if not info:
                await interaction.response.send_message("❌ 帳號資料不存在。", ephemeral=True)
                return

            pending = _get_pending(data, self.guild_id, self.user_id)
            if not pending or pending.get("action") != "force_recovery" or pending.get("account") != self.account:
                await interaction.response.send_message("❌ 驗證已失效，請重新進行帳號恢復。", ephemeral=True)
                return

            expected_rev = pending.get("reversed_code", "")
            expected_created = info.get("created_at", "")
            if self.reverse_code.value.strip() != expected_rev or self.created_at.value.strip() != expected_created:
                locked, attempts = _register_failure(data, self.guild_id, self.user_id, "force_recovery")
                await save_json(DATA_FILE, data)
                if locked:
                    lock_info = _get_lock(data, self.guild_id, self.user_id) or {}
                    _clear_pending(data, self.guild_id, self.user_id)
                    await save_json(DATA_FILE, data)
                    await interaction.response.send_message(_lock_message(lock_info), ephemeral=True)
                    return
                await interaction.response.send_message(
                    f"❌ 驗證失敗！剩餘嘗試次數：{3 - attempts}",
                    view=RetryCodeView(lambda: ForceRecoveryModal(self.cog, self.guild_id, self.user_id, self.account)),
                    ephemeral=True
                )
                return

            info["2fa_enabled"] = False
            info["secret"] = ""

            _clear_pending(data, self.guild_id, self.user_id)
            _clear_lock(data, self.guild_id, self.user_id)
            await _revoke_sessions_for_account(self.cog.bot, data, self.account, exclude=None)
            await save_json(DATA_FILE, data)

            await interaction.response.send_message("✅ 帳號恢復完成，所有登入已登出。", ephemeral=True)
        except Exception:
            log.DcBot_main.error("❌ 帳號恢復失敗", exc_info=True)
            if not interaction.response.is_done():
                await interaction.response.send_message("❌ 發生錯誤，請稍後再試。", ephemeral=True)


class DeleteAccountModal(discord.ui.Modal):
    def __init__(self, cog: "AccountCog", guild_id: str, user_id: str, account: str):
        super().__init__(title="刪除帳號 (請謹慎)", timeout=180)
        self.cog = cog
        self.guild_id = str(guild_id)
        self.user_id = str(user_id)
        self.account = account
        self.email_code = discord.ui.TextInput(label="gmail 的 6 位驗證碼", style=discord.TextStyle.short, max_length=6, min_length=6)
        self.code2fa = discord.ui.TextInput(label="2FA 驗證碼 (如果有)", style=discord.TextStyle.short, required=False)
        self.domain = discord.ui.TextInput(label="電子郵件網域", style=discord.TextStyle.short, placeholder="例如 gmail.com")
        self.current_pwd = discord.ui.TextInput(label="目前密碼", style=discord.TextStyle.short)
        self.initial_pwd = discord.ui.TextInput(label="註冊帳號時設定的密碼", style=discord.TextStyle.short)
        self.add_item(self.email_code)
        self.add_item(self.code2fa)
        self.add_item(self.domain)
        self.add_item(self.current_pwd)
        self.add_item(self.initial_pwd)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            data = await load_account_data()
            info = _ensure_account_exists(data, self.account)
            if not info:
                await interaction.response.send_message("❌ 帳號資料不存在。", ephemeral=True)
                return

            pending = _get_pending(data, self.guild_id, self.user_id)
            if not pending or pending.get("action") != "delete_account" or pending.get("account") != self.account:
                await interaction.response.send_message("❌ 驗證已失效，請重新開始刪除流程。", ephemeral=True)
                return

            if self.email_code.value.strip() != pending.get("code"):
                locked, attempts = _register_failure(data, self.guild_id, self.user_id, "delete_account_email")
                await save_json(DATA_FILE, data)
                if locked:
                    lock_info = _get_lock(data, self.guild_id, self.user_id) or {}
                    _clear_pending(data, self.guild_id, self.user_id)
                    await save_json(DATA_FILE, data)
                    await interaction.response.send_message(_lock_message(lock_info), ephemeral=True)
                    return
                await interaction.response.send_message(
                    f"❌ Gmail 驗證碼錯誤！剩餘嘗試次數：{3 - attempts}",
                    view=RetryCodeView(lambda: DeleteAccountModal(self.cog, self.guild_id, self.user_id, self.account)),
                    ephemeral=True
                )
                return

            stored_domain = _email_domain(info.get("gmail", ""))
            if stored_domain != self.domain.value.strip().lower():
                await interaction.response.send_message("❌ 電子郵件網域不符。", ephemeral=True)
                return

            if info.get("password", "") != self.current_pwd.value:
                await interaction.response.send_message("❌ 目前密碼錯誤。", ephemeral=True)
                return

            if info.get("initial_password", "") != self.initial_pwd.value:
                await interaction.response.send_message("❌ 註冊時的密碼錯誤。", ephemeral=True)
                return

            if info.get("2fa_enabled"):
                if not self.code2fa.value.strip():
                    await interaction.response.send_message("❌ 此帳號已啟用 2FA，請輸入驗證碼。", ephemeral=True)
                    return
                secret = info.get("secret", "")
                if not secret or not pyotp.TOTP(secret).verify(self.code2fa.value.strip(), valid_window=1):
                    await interaction.response.send_message("❌ 2FA 驗證失敗。", ephemeral=True)
                    return

            account_name = self.account
            data["accounts"].pop(account_name, None)
            _clear_pending(data, self.guild_id, self.user_id)
            _clear_lock(data, self.guild_id, self.user_id)
            await _revoke_sessions_for_account(self.cog.bot, data, account_name, exclude=None)
            await save_json(DATA_FILE, data)

            await interaction.response.send_message("🚨 帳號已刪除！", ephemeral=True)
        except Exception:
            log.DcBot_main.error("❌ 刪除帳號失敗", exc_info=True)
            if not interaction.response.is_done():
                await interaction.response.send_message("❌ 發生錯誤，請稍後再試。", ephemeral=True)


class ChangePasswordModal(discord.ui.Modal):
    def __init__(self, cog: "AccountCog", guild_id: str, user_id: str, account: str):
        super().__init__(title="變更密碼", timeout=180)
        self.cog = cog
        self.guild_id = str(guild_id)
        self.user_id = str(user_id)
        self.account = account
        self.old = discord.ui.TextInput(label="目前密碼", style=discord.TextStyle.short)
        self.new = discord.ui.TextInput(label="新密碼", style=discord.TextStyle.short, min_length=6)
        self.confirm = discord.ui.TextInput(label="確認更改的密碼", style=discord.TextStyle.short, min_length=6)
        self.add_item(self.old)
        self.add_item(self.new)
        self.add_item(self.confirm)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            data = await load_account_data()
            info = _ensure_account_exists(data, self.account)
            if not info:
                await interaction.response.send_message("❌ 帳號資料不存在。", ephemeral=True)
                return

            sess = get_user_session(data, self.guild_id, self.user_id)
            if not sess or sess.get("account") != self.account:
                await interaction.response.send_message("❌ 你目前尚未登入。", ephemeral=True)
                return

            if info.get("password", "") != self.old.value:
                await interaction.response.send_message("❌ 密碼錯誤！", ephemeral=True)
                return

            if self.new.value != self.confirm.value:
                await interaction.response.send_message("❌ 新密碼與確認密碼不一致。", ephemeral=True)
                return

            info["password"] = self.new.value
            await _revoke_sessions_for_account(self.cog.bot, data, self.account, exclude=(self.guild_id, self.user_id))
            _clear_lock(data, self.guild_id, self.user_id)
            await save_json(DATA_FILE, data)

            await interaction.response.send_message("✅ 密碼已更新，你的登入將保留，其他登入已登出。", ephemeral=True)
        except Exception:
            log.DcBot_main.error("❌ 變更密碼失敗", exc_info=True)
            if not interaction.response.is_done():
                await interaction.response.send_message("❌ 發生錯誤，請稍後再試。", ephemeral=True)


class LoginRecoveryModal(discord.ui.Modal):
    def __init__(self, cog: "AccountCog", guild_id: str, user_id: str):
        super().__init__(title="登入", timeout=180)
        self.cog = cog
        self.guild_id = str(guild_id)
        self.user_id = str(user_id)
        self.account = discord.ui.TextInput(label="帳號")
        self.password = discord.ui.TextInput(label="密碼", style=discord.TextStyle.short)
        self.add_item(self.account)
        self.add_item(self.password)

    async def on_submit(self, interaction: discord.Interaction):
        await self.cog._handle_login_submission(
            interaction,
            self.account.value.strip(),
            self.password.value,
            retry_modal=True,
            retry_factory=lambda: LoginRecoveryModal(self.cog, self.guild_id, self.user_id)
        )


class RegisterCodeRetryModal(discord.ui.Modal):
    def __init__(self, cog: "AccountCog", guild_id: str, user_id: str):
        super().__init__(title="註冊驗證", timeout=180)
        self.cog = cog
        self.guild_id = str(guild_id)
        self.user_id = str(user_id)
        self.code = discord.ui.TextInput(label="驗證碼(6位)", max_length=6, min_length=6, style=discord.TextStyle.short)
        self.add_item(self.code)

    async def on_submit(self, interaction: discord.Interaction):
        await RegisterCodeModal(self.cog, self.guild_id, self.user_id).on_submit(interaction)


class RegisterAccountModal(discord.ui.Modal):
    def __init__(self, cog: "AccountCog", guild_id: str, user_id: str, password: str, gmail: str):
        super().__init__(title="註冊帳號", timeout=180)
        self.cog = cog
        self.guild_id = str(guild_id)
        self.user_id = str(user_id)
        self.password = password
        self.gmail = gmail
        self.account = discord.ui.TextInput(label="帳號", placeholder="請輸入新的帳號名稱", min_length=3)
        self.add_item(self.account)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            account = _normalize_account_name(self.account.value)
            if not account:
                await interaction.response.send_message("❌ 帳號不能為空。", ephemeral=True)
                return
            data = await load_account_data()
            if account in data["accounts"]:
                suggestions = _make_suggestions(account, data["accounts"])
                await interaction.response.send_message(
                    f"❌ 帳號已存在，請重新輸入。\n建議：{', '.join(suggestions)}",
                    view=RetryCodeView(lambda: RegisterAccountModal(self.cog, self.guild_id, self.user_id, self.password, self.gmail)),
                    ephemeral=True
                )
                return

            pending = _prepare_register_pending(data, self.guild_id, self.user_id, account, self.password, self.gmail)
            await save_json(DATA_FILE, data)
            await _send_gmail_safe(
                self.gmail,
                "註冊驗證碼",
                f"帳號：{account}\n驗證碼：{pending['code']}\n\n若非本人操作請忽略。"
            )
            await interaction.response.send_message(
                "✅ 驗證碼已寄出，請輸入 6 位數驗證碼。",
                view=RetryCodeView(lambda: RegisterCodeModal(self.cog, self.guild_id, self.user_id)),
                ephemeral=True
            )
        except Exception:
            log.DcBot_main.error("❌ 註冊流程失敗", exc_info=True)
            if not interaction.response.is_done():
                await interaction.response.send_message("❌ 發生錯誤，請稍後再試。", ephemeral=True)


class AccountCog(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    async def _handle_login_submission(self, interaction: discord.Interaction, account: str, password: str, retry_modal: bool = False, retry_factory: Optional[Callable[[], discord.ui.Modal]] = None):
        try:
            guild_id = str(interaction.guild_id or "")
            user_id = str(interaction.user.id)
            data = await load_account_data()

            lock = _get_lock(data, guild_id, user_id)
            if lock:
                await interaction.response.send_message(_lock_message(lock), ephemeral=True)
                return

            info = _ensure_account_exists(data, account)
            if not info or info.get("password", "") != password:
                locked, attempts = _register_failure(data, guild_id, user_id, "login")
                await save_json(DATA_FILE, data)
                if locked:
                    lock_info = _get_lock(data, guild_id, user_id) or {}
                    await interaction.response.send_message(_lock_message(lock_info), ephemeral=True)
                    return
                await interaction.response.send_message(
                    f"❌ 帳號或密碼錯誤！剩餘嘗試次數：{3 - attempts}",
                    view=RetryCodeView(retry_factory or (lambda: LoginRetryModal(self, guild_id, user_id))),
                    ephemeral=True
                )
                return

            sess = get_user_session(data, guild_id, user_id)
            if sess and sess.get("account"):
                await interaction.response.send_message("❌ 你在這個伺服器已登入一個帳號，請先登出。", ephemeral=True)
                return

            if info.get("2fa_enabled"):
                _prepare_login_2fa_pending(data, guild_id, user_id, account)
                await save_json(DATA_FILE, data)
                await interaction.response.send_message(
                    "🔐 密碼正確，但啟用了雙步驟驗證。\n請點選以下按鈕完成驗證。",
                    view=Login2FAProceedView(self, guild_id, user_id, account),
                    ephemeral=True
                )
                return

            set_user_session(data, guild_id, user_id, account)
            _record_server_history(data, account, guild_id, user_id)
            _clear_lock(data, guild_id, user_id)
            await save_json(DATA_FILE, data)

            await _apply_verified_role(self.bot, guild_id, user_id, add=True)
            await _send_login_notice(self.bot, info, account, interaction.guild, interaction.user)
            await interaction.response.send_message(f"✅ {account} 登入成功。", ephemeral=True)
        except Exception:
            log.DcBot_main.error("❌ 登入流程失敗", exc_info=True)
            if not interaction.response.is_done():
                await interaction.response.send_message("❌ 發生錯誤，請稍後再試。", ephemeral=True)

    async def _handle_login_2fa_submission(self, interaction: discord.Interaction, account: str, code: str, retry_factory: Optional[Callable[[], discord.ui.Modal]] = None):
        try:
            guild_id = str(interaction.guild_id or "")
            user_id = str(interaction.user.id)
            data = await load_account_data()

            pending = _get_pending(data, guild_id, user_id)
            info = _ensure_account_exists(data, account)
            if not pending or pending.get("action") != "login_2fa" or pending.get("account") != account:
                await interaction.response.send_message("❌ 驗證已失效，請重新登入。", ephemeral=True)
                return

            if not info or not info.get("2fa_enabled"):
                await interaction.response.send_message("❌ 帳號未啟用 2FA。", ephemeral=True)
                return

            if pending.get("expires_at") and _is_expired(pending["expires_at"]):
                _clear_pending(data, guild_id, user_id)
                await save_json(DATA_FILE, data)
                await interaction.response.send_message("❌ 驗證碼已過期，請重新登入。", ephemeral=True)
                return

            secret = info.get("secret", "")
            if not secret or not pyotp.TOTP(secret).verify(code, valid_window=1):
                locked, attempts = _register_failure(data, guild_id, user_id, "login_2fa")
                await save_json(DATA_FILE, data)
                if locked:
                    lock_info = _get_lock(data, guild_id, user_id) or {}
                    _clear_pending(data, guild_id, user_id)
                    await save_json(DATA_FILE, data)
                    await interaction.response.send_message(_lock_message(lock_info), ephemeral=True)
                    return
                await interaction.response.send_message(
                    f"❌ 2FA 驗證碼錯誤！剩餘嘗試次數：{3 - attempts}",
                    view=RetryCodeView(retry_factory or (lambda: Login2FAModal(self, guild_id, user_id, account))),
                    ephemeral=True
                )
                return

            set_user_session(data, guild_id, user_id, account)
            _record_server_history(data, account, guild_id, user_id)
            _clear_pending(data, guild_id, user_id)
            _clear_lock(data, guild_id, user_id)
            await save_json(DATA_FILE, data)

            await _apply_verified_role(self.bot, guild_id, user_id, add=True)
            await _send_login_notice(self.bot, info, account, interaction.guild, interaction.user)
            await interaction.response.send_message(f"✅ {account} 2FA 驗證成功，登入完成。", ephemeral=True)
        except Exception:
            log.DcBot_main.error("❌ 2FA 登入驗證失敗", exc_info=True)
            if not interaction.response.is_done():
                await interaction.response.send_message("❌ 發生錯誤，請稍後再試。", ephemeral=True)

    @app_commands.command(name="account", description="管理虛擬帳號系統")
    @app_commands.guild_only()
    @app_commands.choices(action=[
        app_commands.Choice(name="註冊", value="register"),
        app_commands.Choice(name="登入", value="login"),
        app_commands.Choice(name="設定", value="setting"),
        app_commands.Choice(name="帳號恢復", value="recovery"),
    ])
    @app_commands.describe(account="帳號", password="密碼", gmail="gmail")
    async def account_cmd(
        self,
        interaction: discord.Interaction,
        action: app_commands.Choice[str],
        account: Optional[str] = None,
        password: Optional[str] = None,
        gmail: Optional[str] = None
    ):
        try:
            if interaction.guild_id is None:
                await interaction.response.send_message("❌ 這個指令只能在伺服器中使用。", ephemeral=True)
                return

            guild_id = str(interaction.guild_id)
            user_id = str(interaction.user.id)
            data = await load_account_data()

            lock = _get_lock(data, guild_id, user_id)
            if lock:
                await interaction.response.send_message(_lock_message(lock), ephemeral=True)
                return

            selected = action.value

            if selected == "register":
                if not account or not password or not gmail:
                    await interaction.response.send_message("❌ 缺少參數：註冊需要帳號、密碼、gmail。", ephemeral=True)
                    return
                if not _is_email(gmail):
                    await interaction.response.send_message("❌ gmail 格式錯誤。", ephemeral=True)
                    return

                account = _normalize_account_name(account)
                if account in data["accounts"]:
                    suggestions = _make_suggestions(account, data["accounts"])
                    await interaction.response.send_modal(RegisterRenameModal(self, guild_id, user_id, password, gmail, suggestions))
                    return

                pending = _prepare_register_pending(data, guild_id, user_id, account, password, gmail)
                await save_json(DATA_FILE, data)
                await _send_gmail_safe(
                    gmail,
                    "註冊驗證碼",
                    f"帳號：{account}\n驗證碼：{pending['code']}\n\n若非本人操作請忽略。"
                )
                await interaction.response.send_modal(RegisterCodeModal(self, guild_id, user_id))
                return

            if selected == "login":
                if not account or not password:
                    await interaction.response.send_message("❌ 缺少參數：登入需要帳號與密碼。", ephemeral=True)
                    return
                await self._handle_login_submission(interaction, _normalize_account_name(account), password, retry_factory=lambda: LoginRetryModal(self, guild_id, user_id))
                return

            if selected == "setting":
                sess = get_user_session(data, guild_id, user_id)
                if not sess or not sess.get("account"):
                    await interaction.response.send_message("❌ 請先登入後再設定。", ephemeral=True)
                    return
                account_name = sess["account"]
                info = _ensure_account_exists(data, account_name)
                if not info:
                    await interaction.response.send_message("❌ 帳號資料不存在。", ephemeral=True)
                    return
                modal = SettingActionModal(self, guild_id, user_id)
                modal._set_options(bool(info.get("2fa_enabled", False)))
                await interaction.response.send_modal(modal)
                return

            if selected == "recovery":
                if not account or not gmail:
                    await interaction.response.send_message("❌ 缺少參數：帳號恢復需要帳號與 gmail。", ephemeral=True)
                    return
                account = _normalize_account_name(account)
                info = _ensure_account_exists(data, account)
                if not info:
                    await interaction.response.send_message("❌ 帳號不存在。", ephemeral=True)
                    return
                if not _account_matches_email(info, gmail):
                    await interaction.response.send_message("❌ gmail 不符帳號綁定資料。", ephemeral=True)
                    return

                pending = _prepare_email_code_pending(
                    data,
                    guild_id,
                    user_id,
                    action="force_recovery",
                    account=account,
                    email=gmail,
                    length=80,
                    extra={
                        "reversed_code": None,
                        "created_at": info.get("created_at", _format_created_at())
                    }
                )
                pending["reversed_code"] = pending["code"][::-1]
                await save_json(DATA_FILE, data)
                await _send_gmail_safe(
                    gmail,
                    "帳號恢復驗證碼",
                    f"帳號：{account}\n驗證碼：{pending['code']}\n\n請妥善保存。"
                )
                await interaction.response.send_modal(ForceRecoveryModal(self, guild_id, user_id, account))
                return

            await interaction.response.send_message("❌ 無效選項。", ephemeral=True)
        except Exception:
            log.DcBot_main.error("❌ /account 指令失敗", exc_info=True)
            if not interaction.response.is_done():
                await interaction.response.send_message("❌ 發生錯誤，請稍後再試。", ephemeral=True)


async def setup(bot: commands.Bot):
    await bot.add_cog(AccountCog(bot))

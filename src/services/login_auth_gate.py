"""Pure helpers for the headed Goofish login entry.

These functions do not log cookie/token values, account profile text, or
login URLs with query strings. They do not call unpublished site APIs.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

from src.services.session_state_persist import (
    merge_storage_state_for_save,
    persist_playwright_storage_state,
    session_state_is_persistable,
    source_file_has_changed,
    write_json_atomically,
)


ACCOUNT_ID_RE = re.compile(r"^acc_[A-Za-z0-9]{1,32}$")
DEFAULT_ACCOUNT_ID = "acc_1"
DEFAULT_STATE_DIRNAME = "state"
DEFAULT_STATUS_RELATIVE = Path("logs") / "login-helper-status.json"
OFFICIAL_HOME_URL = "https://www.goofish.com/"
ALLOWED_STATUS = {
    "starting",
    "waiting_for_user",
    "checking",
    "saved",
    "unconfirmed",
    "cancelled",
    "timeout",
    "error",
    "blocked_busy",
}
SESSION_COOKIE_NAMES = {
    "cookie2",
    "unb",
    "_m_h5_tk",
    "sgcookie",
    "tracknick",
    "_tb_token_",
    "cna",
}
_HK = ZoneInfo("Asia/Hong_Kong")


def now_hk() -> str:
    return datetime.now(_HK).strftime("%Y-%m-%d %H:%M:%S Asia/Hong_Kong")


def redact_url(url: str) -> str:
    if not url:
        return ""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    return f"{parsed.scheme or 'https'}://{host}{path}"


def is_login_url(url: str) -> bool:
    if not url:
        return False
    lowered = url.lower()
    return "passport.goofish.com" in lowered or "mini_login" in lowered


def is_official_goofish_url(url: str) -> bool:
    if not url or is_login_url(url):
        return False
    host = (urlparse(url).hostname or "").lower()
    if host == "goofish.com" or host.endswith(".goofish.com"):
        return "passport" not in host
    return False


def sanitize_account_id(account_id: Optional[str]) -> str:
    raw = (account_id or DEFAULT_ACCOUNT_ID).strip()
    if not ACCOUNT_ID_RE.match(raw):
        raise ValueError("账号 ID 不合法，仅允许 acc_ 加字母数字，例如 acc_1")
    return raw


def resolve_state_directory(project_root: Path, state_dir: Optional[str] = None) -> Path:
    root = project_root.resolve()
    raw = (state_dir or os.getenv("ACCOUNT_STATE_DIR") or DEFAULT_STATE_DIRNAME).strip().strip('"').strip("'")
    if not raw:
        raw = DEFAULT_STATE_DIRNAME
    candidate = Path(raw)
    if candidate.is_absolute() or ".." in candidate.parts or candidate.anchor:
        raise ValueError("状态目录不合法，只允许项目内相对目录")
    resolved = (root / candidate).resolve()
    if resolved != root and not str(resolved).startswith(str(root) + os.sep):
        raise ValueError("状态目录超出项目范围")
    return resolved


def resolve_account_state_path(
    project_root: Path,
    account_id: Optional[str] = None,
    state_dir: Optional[str] = None,
) -> Path:
    account = sanitize_account_id(account_id)
    directory = resolve_state_directory(project_root, state_dir)
    path = (directory / f"{account}.json").resolve()
    if path.parent != directory or path.name != f"{account}.json":
        raise ValueError("状态文件路径不合法")
    if not str(path).startswith(str(directory) + os.sep) and path != directory:
        raise ValueError("状态文件超出状态目录")
    return path


def default_status_path(project_root: Path) -> Path:
    path = (project_root.resolve() / DEFAULT_STATUS_RELATIVE).resolve()
    root = project_root.resolve()
    if not str(path).startswith(str(root) + os.sep):
        raise ValueError("状态报告路径不合法")
    return path


def write_status_file(path: Path, **fields: Any) -> None:
    status = str(fields.get("status") or "error")
    if status not in ALLOWED_STATUS:
        status = "error"
    payload = {
        "status": status,
        "account_id": fields.get("account_id") or DEFAULT_ACCOUNT_ID,
        "state_file": fields.get("state_file") or "",
        "updated_at": now_hk(),
        "message": str(fields.get("message") or ""),
        "login_confirmed": bool(fields.get("login_confirmed")),
        "saved": bool(fields.get("saved")),
        "timed_out": bool(fields.get("timed_out")),
        "cancelled": bool(fields.get("cancelled")),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = {
        "status": payload["status"],
        "account_id": payload["account_id"],
        "state_file": payload["state_file"],
        "updated_at": payload["updated_at"],
        "message": payload["message"],
        "login_confirmed": payload["login_confirmed"],
        "saved": payload["saved"],
        "timed_out": payload["timed_out"],
        "cancelled": payload["cancelled"],
    }
    write_json_atomically(str(path), tmp)


def read_status_file(path: Path) -> Optional[dict]:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def cookies_support_login(cookie_names: Iterable[str], cookie_count: int) -> bool:
    if cookie_count < 3:
        return False
    names = {str(name) for name in cookie_names if name}
    return len(names & SESSION_COOKIE_NAMES) >= 2


@dataclass(frozen=True)
class LoginGateResult:
    confirmed: bool
    reason: str
    on_login_page: bool = False
    official_page: bool = False
    has_logged_in_ui: bool = False
    has_sufficient_cookies: bool = False


def evaluate_login_evidence(
    *,
    current_url: str = "",
    on_login_page: Optional[bool] = None,
    official_page: Optional[bool] = None,
    has_logged_in_ui: bool = False,
    logged_out_cta_visible: bool = False,
    cookie_names: Optional[Iterable[str]] = None,
    cookie_count: int = 0,
) -> LoginGateResult:
    """Require official-page UI evidence plus cookies. Leaving passport is not enough."""
    login_page = bool(on_login_page) if on_login_page is not None else is_login_url(current_url)
    official = bool(official_page) if official_page is not None else is_official_goofish_url(current_url)
    cookies_ok = cookies_support_login(cookie_names or [], cookie_count)

    if login_page:
        return LoginGateResult(
            False,
            "当前在登录页，尚未确认已登录，未保存",
            on_login_page=True,
            official_page=False,
            has_logged_in_ui=has_logged_in_ui,
            has_sufficient_cookies=cookies_ok,
        )
    if not official:
        return LoginGateResult(
            False,
            "当前不在闲鱼官方页面，尚未确认已登录，未保存",
            official_page=False,
            has_logged_in_ui=has_logged_in_ui,
            has_sufficient_cookies=cookies_ok,
        )
    if not has_logged_in_ui:
        return LoginGateResult(
            False,
            "未检测到已登录界面标识，尚未确认已登录，未保存",
            official_page=True,
            has_logged_in_ui=False,
            has_sufficient_cookies=cookies_ok,
        )
    if logged_out_cta_visible and not has_logged_in_ui:
        return LoginGateResult(
            False,
            "仍看到未登录入口，尚未确认已登录，未保存",
            official_page=True,
            has_logged_in_ui=False,
            has_sufficient_cookies=cookies_ok,
        )
    if not cookies_ok:
        return LoginGateResult(
            False,
            "会话还不完整，尚未确认已登录，未保存",
            official_page=True,
            has_logged_in_ui=has_logged_in_ui,
            has_sufficient_cookies=False,
        )
    return LoginGateResult(
        True,
        "已确认登录标识与会话，可以保存",
        official_page=True,
        has_logged_in_ui=True,
        has_sufficient_cookies=True,
    )


def cookie_names_from_storage_state(storage_state: Any) -> list[str]:
    if not isinstance(storage_state, Mapping):
        return []
    cookies = storage_state.get("cookies")
    if not isinstance(cookies, list):
        return []
    names = []
    for item in cookies:
        if isinstance(item, Mapping) and item.get("name"):
            names.append(str(item.get("name")))
    return names


async def save_confirmed_login_state(
    context: Any,
    state_file: Path,
    *,
    existing_snapshot: Any,
    expected_fingerprint: Optional[tuple[int, int]],
    confirmed: bool,
    cancelled: bool = False,
    timed_out: bool = False,
) -> tuple[bool, str]:
    if cancelled:
        return False, "已取消，未修改登录态文件"
    if timed_out:
        return False, "等待超时，未修改登录态文件"
    if not confirmed:
        return False, "未确认已登录，未修改登录态文件"

    target = Path(state_file)
    if target.exists() and not target.is_file():
        return False, "登录态路径不是普通文件，未保存"
    if target.exists() and source_file_has_changed(str(target), expected_fingerprint):
        return False, "源登录态文件已变化，跳过写回以免覆盖更新"

    storage_state = await context.storage_state()
    if not session_state_is_persistable(storage_state):
        return False, "当前会话 cookie 不完整，未修改原文件"

    if target.is_file():
        return await persist_playwright_storage_state(
            context,
            str(target),
            existing_snapshot=existing_snapshot,
            expected_fingerprint=expected_fingerprint,
        )

    merged = merge_storage_state_for_save(existing_snapshot, storage_state)
    target.parent.mkdir(parents=True, exist_ok=True)
    write_json_atomically(str(target), merged)
    return True, "已安全保存登录态"


def existing_snapshot_or_none(state_file: Path) -> Any:
    if not state_file.is_file():
        return None
    try:
        return json.loads(state_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

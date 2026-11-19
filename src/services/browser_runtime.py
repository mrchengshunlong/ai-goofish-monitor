"""Shared headed/headless Chrome launch for login and scraping.

Uses the official Playwright persistent context with an isolated project
profile directory. It never points at the daily Chrome/Edge user data
directories, never copies those profiles, and never injects a hardcoded
mobile UA or stealth scripts.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional

from src.services.login_auth_gate import sanitize_account_id


BROWSER_PROFILES_DIRNAME = "browser-profiles"
UNSAFE_BROWSER_FLAG_SNIPPETS = (
    "--disable-blink-features=AutomationControlled",
    "--disable-web-security",
    "IsolateOrigins",
    "site-per-process",
)
FORBIDDEN_CONTEXT_KEYS = {
    "user_agent",
    "viewport",
    "is_mobile",
    "has_touch",
    "device_scale_factor",
    "geolocation",
    "storage_state",
}
FORBIDDEN_USER_DATA_MARKERS = (
    "/google/chrome/user data",
    "/google/chrome beta/user data",
    "/google/chrome/beta/user data",
    "/microsoft/edge/user data",
    "/.config/google-chrome",
    "/.config/chromium",
    "/library/application support/google/chrome",
)


class ProfileBusyError(RuntimeError):
    pass


class UnsafeBrowserProfileError(ValueError):
    pass


def project_root_from(path: Optional[Path] = None) -> Path:
    if path is not None:
        return Path(path).resolve()
    return Path(__file__).resolve().parents[2]


def normalize_fs_path(path: Path | str) -> str:
    return str(Path(path).resolve()).replace("\\", "/").lower()


def is_forbidden_external_browser_dir(path: Path | str) -> bool:
    text = normalize_fs_path(path)
    return any(marker in text for marker in FORBIDDEN_USER_DATA_MARKERS)


def launch_args_are_safe(args: Optional[list[str]]) -> bool:
    joined = " ".join(args or [])
    return not any(snippet in joined for snippet in UNSAFE_BROWSER_FLAG_SNIPPETS)


def context_options_are_safe(options: dict) -> bool:
    return not any(key in options for key in FORBIDDEN_CONTEXT_KEYS)


def resolve_browser_channel(*, login_is_edge: bool, running_in_docker: bool) -> str:
    if running_in_docker:
        return "chromium"
    return "msedge" if login_is_edge else "chrome"


def shared_browser_context_options() -> dict:
    return {"no_viewport": True}


def build_chromium_launch_args(crash_dumps_dir: str, *, docker: bool = False) -> list[str]:
    if not docker:
        return []
    return [
        "--disable-dev-shm-usage",
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-breakpad",
        "--disable-crash-reporter",
        "--disable-features=Crashpad",
        f"--crash-dumps-dir={crash_dumps_dir}",
    ]


def prepare_shared_launch_args(*, running_in_docker: bool) -> list[str]:
    import tempfile

    crash_dumps_dir = os.path.join(tempfile.gettempdir(), "chromium-crashpad")
    if running_in_docker:
        os.makedirs(crash_dumps_dir, exist_ok=True)
    args = build_chromium_launch_args(crash_dumps_dir, docker=running_in_docker)
    if not launch_args_are_safe(args):
        raise UnsafeBrowserProfileError("共享启动参数包含不安全标志，已拒绝")
    return args


def shared_launch_kwargs(
    *,
    headless: bool,
    login_is_edge: bool,
    running_in_docker: bool,
    proxy_server: Optional[str] = None,
) -> dict:
    kwargs = {
        "headless": bool(headless),
        "channel": resolve_browser_channel(
            login_is_edge=login_is_edge, running_in_docker=running_in_docker
        ),
        "args": prepare_shared_launch_args(running_in_docker=running_in_docker),
        **shared_browser_context_options(),
    }
    if proxy_server:
        kwargs["proxy"] = {"server": proxy_server}
    if not context_options_are_safe(kwargs):
        raise UnsafeBrowserProfileError("共享上下文选项包含被禁止的覆盖项，已拒绝")
    return kwargs


def account_id_from_state_file(state_file: Path | str) -> str:
    name = Path(str(state_file).replace("\\", "/")).name
    if not name.endswith(".json"):
        raise UnsafeBrowserProfileError("无法安全解析账号绑定，已停止以免使用错误配置")
    try:
        return sanitize_account_id(name[: -len(".json")])
    except ValueError as exc:
        raise UnsafeBrowserProfileError(
            "无法安全解析账号绑定，已停止以免使用错误配置"
        ) from exc


def resolve_account_profile_dir(project_root: Path, account_id: str) -> Path:
    account = sanitize_account_id(account_id)
    root = Path(project_root).resolve()
    base = (root / BROWSER_PROFILES_DIRNAME).resolve()
    if is_forbidden_external_browser_dir(base):
        raise UnsafeBrowserProfileError("浏览器配置目录不合法")
    if base != root / BROWSER_PROFILES_DIRNAME and not str(base).startswith(str(root) + os.sep):
        raise UnsafeBrowserProfileError("浏览器配置目录超出项目范围")
    candidate = base / account
    if candidate.exists() or candidate.is_symlink():
        resolved = candidate.resolve()
        if not str(resolved).startswith(str(base) + os.sep):
            raise UnsafeBrowserProfileError("浏览器配置目录存在符号链接或路径逃逸，已拒绝")
        if is_forbidden_external_browser_dir(resolved):
            raise UnsafeBrowserProfileError("浏览器配置目录不合法")
        return resolved
    return Path(str(base / account))


def ensure_account_profile_dir(project_root: Path, account_id: str) -> Path:
    path = resolve_account_profile_dir(project_root, account_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.mkdir(parents=False, exist_ok=True)
    resolved = path.resolve()
    base = (Path(project_root).resolve() / BROWSER_PROFILES_DIRNAME).resolve()
    if not str(resolved).startswith(str(base) + os.sep):
        raise UnsafeBrowserProfileError("浏览器配置目录超出项目范围")
    if is_forbidden_external_browser_dir(resolved):
        raise UnsafeBrowserProfileError("浏览器配置目录不合法")
    return resolved


def pid_is_running(pid: int) -> bool:
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


class AccountProfileLock:
    """Exclusive per-account lock for login and scrape. Never kills processes."""

    def __init__(self, project_root: Path, account_id: str, purpose: str):
        self.account_id = sanitize_account_id(account_id)
        self.purpose = purpose
        base = (Path(project_root).resolve() / BROWSER_PROFILES_DIRNAME)
        self.lock_path = (base / f"{self.account_id}.lock").resolve()
        parent = self.lock_path.parent.resolve()
        root = Path(project_root).resolve()
        if not str(parent).startswith(str(root) + os.sep):
            raise UnsafeBrowserProfileError("锁文件路径不合法")
        self._owned = False

    def acquire(self) -> None:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "pid": os.getpid(),
            "purpose": self.purpose,
            "account_id": self.account_id,
        }
        encoded = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
        for _ in range(2):
            try:
                fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                try:
                    os.write(fd, encoded)
                finally:
                    os.close(fd)
                self._owned = True
                return
            except FileExistsError:
                if self._recover_stale():
                    continue
                holder = self._read_holder()
                holder_pid = holder.get("pid") if holder else "未知"
                holder_purpose = holder.get("purpose") if holder else "未知"
                raise ProfileBusyError(
                    f"账号 {self.account_id} 正在被其他本项目进程使用（{holder_purpose}, pid={holder_pid}），"
                    "已拒绝同时打开同一配置，以免互相覆盖。未结束其他浏览器。"
                )
        raise ProfileBusyError(f"账号 {self.account_id} 无法取得配置锁")

    def _read_holder(self) -> Optional[dict]:
        try:
            data = json.loads(self.lock_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def _recover_stale(self) -> bool:
        holder = self._read_holder()
        if not holder:
            return False
        try:
            pid = int(holder.get("pid"))
        except (TypeError, ValueError):
            return False
        if pid_is_running(pid):
            return False
        try:
            self.lock_path.unlink()
            return True
        except OSError:
            return False

    def release(self) -> None:
        if not self._owned:
            return
        holder = self._read_holder()
        if holder and holder.get("pid") == os.getpid():
            try:
                self.lock_path.unlink()
            except OSError:
                pass
        self._owned = False

    def __enter__(self) -> "AccountProfileLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()


async def launch_shared_persistent_context(
    playwright: Any,
    *,
    user_data_dir: Path,
    headless: bool,
    login_is_edge: bool,
    running_in_docker: bool,
    proxy_server: Optional[str] = None,
) -> Any:
    if is_forbidden_external_browser_dir(user_data_dir):
        raise UnsafeBrowserProfileError("拒绝使用日常浏览器用户数据目录")
    kwargs = shared_launch_kwargs(
        headless=headless,
        login_is_edge=login_is_edge,
        running_in_docker=running_in_docker,
        proxy_server=proxy_server,
    )
    if "storage_state" in kwargs:
        raise UnsafeBrowserProfileError("禁止把旧登录快照导入持久配置")
    context = await playwright.chromium.launch_persistent_context(
        str(user_data_dir), **kwargs
    )
    return context


async def first_page(context: Any) -> Any:
    pages = getattr(context, "pages", None)
    if pages:
        return pages[0]
    return await context.new_page()


async def close_persistent_context(context: Any) -> None:
    """A persistent context owns the browser; do not also call browser.close()."""
    if context is None:
        return
    closer = getattr(context, "close", None)
    if closer is not None:
        await closer()

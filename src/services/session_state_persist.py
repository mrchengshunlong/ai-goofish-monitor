"""Safely write a refreshed Playwright storage state back to an account file.

This does not log in, refresh tokens over the network, or create new account
files. Callers must first confirm a logged-in session (real parsed search
results). A write is skipped when the source file changed mid-run, the
session looks empty/invalid, or persistence fails — the original file is kept.
This is not a guarantee that the platform will keep the session valid.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Mapping, Optional


ENHANCED_SNAPSHOT_KEYS = ("env", "headers", "page", "storage")
_PLAYWRIGHT_STATE_KEYS = ("cookies", "origins")


def file_fingerprint(path: str) -> Optional[tuple[int, int]]:
    try:
        stat = os.stat(path)
    except OSError:
        return None
    return (stat.st_mtime_ns, stat.st_size)


def is_enhanced_snapshot(data: Any) -> bool:
    return isinstance(data, dict) and any(key in data for key in ENHANCED_SNAPSHOT_KEYS)


def session_state_is_persistable(storage_state: Any) -> bool:
    if not isinstance(storage_state, dict):
        return False
    cookies = storage_state.get("cookies")
    if not isinstance(cookies, list) or not cookies:
        return False
    origins = storage_state.get("origins", [])
    if origins is None:
        origins = []
    if not isinstance(origins, list):
        return False
    return True


def should_persist_session_state(
    *,
    confirmed_search_item_count: int,
    error: Optional[BaseException] = None,
    on_login_page: bool = False,
    cancelled: bool = False,
) -> tuple[bool, str]:
    """Conservative gate: require real parsed search items, not merely 'no login wall'."""
    if cancelled:
        return False, "任务已取消或浏览器已关闭，跳过写回登录态"
    if error is not None:
        return False, "本次运行出现异常或登录/风控问题，跳过写回登录态"
    if on_login_page:
        return False, "当前处于登录页，跳过写回登录态以免覆盖原文件"
    if confirmed_search_item_count <= 0:
        return False, "未抓到真实搜索结果，跳过写回登录态"
    return True, "会话已确认，准备写回登录态"


def merge_storage_state_for_save(
    existing_snapshot: Any, playwright_state: Mapping[str, Any]
) -> dict:
    cookies = list(playwright_state.get("cookies") or [])
    origins = list(playwright_state.get("origins") or [])
    if is_enhanced_snapshot(existing_snapshot):
        merged = dict(existing_snapshot)
        merged["cookies"] = cookies
        merged["origins"] = origins
        return merged
    return {"cookies": cookies, "origins": origins}


def source_file_has_changed(
    path: str, expected_fingerprint: Optional[tuple[int, int]]
) -> bool:
    current = file_fingerprint(path)
    if expected_fingerprint is None or current is None:
        return True
    return current != expected_fingerprint


def write_json_atomically(path: str, data: dict) -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".state-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


async def persist_playwright_storage_state(
    context: Any,
    state_file: str,
    *,
    existing_snapshot: Any,
    expected_fingerprint: Optional[tuple[int, int]],
) -> tuple[bool, str]:
    if not state_file or not os.path.isfile(state_file):
        return False, "登录态文件不存在或不是普通文件，跳过写回"
    if source_file_has_changed(state_file, expected_fingerprint):
        return False, "源登录态文件已变化，跳过写回以免覆盖更新"
    storage_state = await context.storage_state()
    if not session_state_is_persistable(storage_state):
        return False, "当前会话 cookie 不完整，跳过写回以免覆盖原文件"
    merged = merge_storage_state_for_save(existing_snapshot, storage_state)
    write_json_atomically(state_file, merged)
    return True, "已安全写回刷新后的登录态"


__all__ = [
    "ENHANCED_SNAPSHOT_KEYS",
    "file_fingerprint",
    "is_enhanced_snapshot",
    "merge_storage_state_for_save",
    "persist_playwright_storage_state",
    "session_state_is_persistable",
    "should_persist_session_state",
    "source_file_has_changed",
    "write_json_atomically",
    "_PLAYWRIGHT_STATE_KEYS",
]

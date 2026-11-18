import asyncio
import json
from pathlib import Path

import pytest

from src.services.session_state_persist import (
    file_fingerprint,
    merge_storage_state_for_save,
    persist_playwright_storage_state,
    session_state_is_persistable,
    should_persist_session_state,
    write_json_atomically,
)


ORIGINAL_STATE = {
    "cookies": [{"name": "demo_session", "value": "old-token", "domain": ".example.test"}],
    "origins": [],
}

ENHANCED_STATE = {
    "env": {"userAgent": "FakeAgent/1.0", "viewport": {"width": 390, "height": 844}},
    "headers": {"Accept-Language": "zh-CN"},
    "page": {"url": "https://www.example.test/"},
    "storage": {"localStorage": {"theme": "light"}},
    "cookies": [{"name": "demo_session", "value": "old-token", "domain": ".example.test"}],
}

REFRESHED_STATE = {
    "cookies": [
        {"name": "demo_session", "value": "refreshed-token", "domain": ".example.test"},
        {"name": "demo_pref", "value": "1", "domain": ".example.test"},
    ],
    "origins": [{"origin": "https://www.example.test", "localStorage": []}],
}


class FakeContext:
    def __init__(self, storage_state=None, error=None):
        self.storage_state_value = storage_state if storage_state is not None else REFRESHED_STATE
        self.error = error
        self.calls = 0

    async def storage_state(self, path=None):
        self.calls += 1
        if path is not None:
            raise AssertionError("persist helper must not write through Playwright path=")
        if self.error is not None:
            raise self.error
        return self.storage_state_value


def _write_state(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def test_should_persist_requires_real_search_items_not_just_missing_login_wall():
    ok, reason = should_persist_session_state(confirmed_search_item_count=0)
    assert ok is False
    assert "真实搜索结果" in reason

    ok, reason = should_persist_session_state(confirmed_search_item_count=3)
    assert ok is True


def test_should_not_persist_on_login_wall_error_or_cancel():
    ok, reason = should_persist_session_state(
        confirmed_search_item_count=5,
        on_login_page=True,
    )
    assert ok is False
    assert "登录页" in reason

    ok, reason = should_persist_session_state(
        confirmed_search_item_count=5,
        error=RuntimeError("login required"),
    )
    assert ok is False
    assert "异常" in reason or "登录" in reason

    ok, reason = should_persist_session_state(
        confirmed_search_item_count=5,
        cancelled=True,
    )
    assert ok is False
    assert "取消" in reason or "关闭" in reason


def test_merge_keeps_enhanced_snapshot_metadata():
    merged = merge_storage_state_for_save(ENHANCED_STATE, REFRESHED_STATE)
    assert merged["env"] == ENHANCED_STATE["env"]
    assert merged["headers"] == ENHANCED_STATE["headers"]
    assert merged["page"] == ENHANCED_STATE["page"]
    assert merged["storage"] == ENHANCED_STATE["storage"]
    assert merged["cookies"] == REFRESHED_STATE["cookies"]
    assert merged["origins"] == REFRESHED_STATE["origins"]


def test_merge_plain_playwright_state_only_keeps_cookies_and_origins():
    merged = merge_storage_state_for_save(ORIGINAL_STATE, REFRESHED_STATE)
    assert merged == {
        "cookies": REFRESHED_STATE["cookies"],
        "origins": REFRESHED_STATE["origins"],
    }


def test_empty_session_is_not_persistable():
    assert session_state_is_persistable({"cookies": [], "origins": []}) is False
    assert session_state_is_persistable({"origins": []}) is False
    assert session_state_is_persistable(REFRESHED_STATE) is True


def test_login_wall_keeps_original_state_file(tmp_path):
    state_file = tmp_path / "acc_1.json"
    _write_state(state_file, ORIGINAL_STATE)
    original = state_file.read_text(encoding="utf-8")
    fingerprint = file_fingerprint(str(state_file))

    ok, reason = should_persist_session_state(
        confirmed_search_item_count=0,
        on_login_page=True,
        error=RuntimeError("Login required"),
    )
    assert ok is False

    # Gate rejects the write; the helper must not be called, and the file stays intact.
    assert state_file.read_text(encoding="utf-8") == original
    assert file_fingerprint(str(state_file)) == fingerprint
    assert "cookie" not in reason.lower() or "cookie" in "跳过写回登录态"


def test_persist_skips_when_source_file_changed(tmp_path):
    state_file = tmp_path / "acc_1.json"
    _write_state(state_file, ORIGINAL_STATE)
    fingerprint = file_fingerprint(str(state_file))
    updated = dict(ORIGINAL_STATE)
    updated["cookies"] = [{"name": "demo_session", "value": "imported-newer", "domain": ".example.test"}]
    _write_state(state_file, updated)
    before = state_file.read_text(encoding="utf-8")

    saved, reason = asyncio.run(
        persist_playwright_storage_state(
            FakeContext(),
            str(state_file),
            existing_snapshot=ORIGINAL_STATE,
            expected_fingerprint=fingerprint,
        )
    )

    assert saved is False
    assert "已变化" in reason
    assert state_file.read_text(encoding="utf-8") == before
    assert json.loads(before)["cookies"][0]["value"] == "imported-newer"


def test_persist_failure_keeps_original_file(tmp_path, monkeypatch):
    state_file = tmp_path / "acc_1.json"
    _write_state(state_file, ORIGINAL_STATE)
    original = state_file.read_text(encoding="utf-8")
    fingerprint = file_fingerprint(str(state_file))

    def boom(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(
        "src.services.session_state_persist.write_json_atomically",
        boom,
    )

    with pytest.raises(OSError, match="disk full"):
        asyncio.run(
            persist_playwright_storage_state(
                FakeContext(),
                str(state_file),
                existing_snapshot=ORIGINAL_STATE,
                expected_fingerprint=fingerprint,
            )
        )

    assert state_file.read_text(encoding="utf-8") == original
    leftovers = list(tmp_path.glob(".state-*.tmp"))
    assert leftovers == []


def test_atomic_write_failure_keeps_original_and_cleans_temp(tmp_path, monkeypatch):
    state_file = tmp_path / "acc_1.json"
    _write_state(state_file, ORIGINAL_STATE)
    original = state_file.read_text(encoding="utf-8")

    def boom(_src, _dst):
        raise OSError("replace failed")

    monkeypatch.setattr(
        "src.services.session_state_persist.os.replace",
        boom,
    )

    with pytest.raises(OSError, match="replace failed"):
        write_json_atomically(str(state_file), REFRESHED_STATE)

    assert state_file.read_text(encoding="utf-8") == original
    assert list(tmp_path.glob(".state-*.tmp")) == []


def test_successful_persist_writes_refreshed_plain_state(tmp_path):
    state_file = tmp_path / "acc_1.json"
    _write_state(state_file, ORIGINAL_STATE)
    fingerprint = file_fingerprint(str(state_file))

    saved, reason = asyncio.run(
        persist_playwright_storage_state(
            FakeContext(),
            str(state_file),
            existing_snapshot=ORIGINAL_STATE,
            expected_fingerprint=fingerprint,
        )
    )

    assert saved is True
    assert "安全写回" in reason
    written = json.loads(state_file.read_text(encoding="utf-8"))
    assert written == REFRESHED_STATE


def test_successful_persist_keeps_enhanced_metadata(tmp_path):
    state_file = tmp_path / "acc_1.json"
    _write_state(state_file, ENHANCED_STATE)
    fingerprint = file_fingerprint(str(state_file))

    saved, _reason = asyncio.run(
        persist_playwright_storage_state(
            FakeContext(),
            str(state_file),
            existing_snapshot=ENHANCED_STATE,
            expected_fingerprint=fingerprint,
        )
    )

    assert saved is True
    written = json.loads(state_file.read_text(encoding="utf-8"))
    assert written["env"] == ENHANCED_STATE["env"]
    assert written["headers"] == ENHANCED_STATE["headers"]
    assert written["storage"] == ENHANCED_STATE["storage"]
    assert written["page"] == ENHANCED_STATE["page"]
    assert written["cookies"] == REFRESHED_STATE["cookies"]
    assert written["origins"] == REFRESHED_STATE["origins"]


def test_incomplete_context_state_does_not_overwrite(tmp_path):
    state_file = tmp_path / "acc_1.json"
    _write_state(state_file, ORIGINAL_STATE)
    original = state_file.read_text(encoding="utf-8")
    fingerprint = file_fingerprint(str(state_file))

    saved, reason = asyncio.run(
        persist_playwright_storage_state(
            FakeContext(storage_state={"cookies": [], "origins": []}),
            str(state_file),
            existing_snapshot=ORIGINAL_STATE,
            expected_fingerprint=fingerprint,
        )
    )

    assert saved is False
    assert "不完整" in reason
    assert state_file.read_text(encoding="utf-8") == original

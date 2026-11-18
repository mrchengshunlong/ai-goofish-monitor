import asyncio
import json
from pathlib import Path

import pytest

from src.login_helper import inspect_and_maybe_save, run_login_session
from src.services.login_auth_gate import (
    evaluate_login_evidence,
    resolve_account_state_path,
    save_confirmed_login_state,
    write_status_file,
)


ORIGINAL_STATE = {
    "cookies": [{"name": "demo_session", "value": "old-token", "domain": ".example.test"}],
    "origins": [],
}

ENHANCED_STATE = {
    "env": {"userAgent": "FakeAgent/1.0"},
    "headers": {"Accept-Language": "zh-CN"},
    "page": {"url": "https://www.example.test/"},
    "storage": {"localStorage": {"theme": "light"}},
    "cookies": [{"name": "demo_session", "value": "old-token", "domain": ".example.test"}],
}

VALID_STATE = {
    "cookies": [
        {"name": "cookie2", "value": "new-token", "domain": ".goofish.com"},
        {"name": "unb", "value": "1", "domain": ".goofish.com"},
        {"name": "_m_h5_tk", "value": "tk", "domain": ".goofish.com"},
        {"name": "cna", "value": "x", "domain": ".goofish.com"},
    ],
    "origins": [{"origin": "https://www.goofish.com", "localStorage": []}],
}

EMPTY_STATE = {"cookies": [], "origins": []}


class FakeContext:
    def __init__(self, storage_state=None, error=None):
        self.storage_state_value = storage_state if storage_state is not None else VALID_STATE
        self.error = error

    async def storage_state(self, path=None):
        if path is not None:
            raise AssertionError("must not write through Playwright path=")
        if self.error is not None:
            raise self.error
        return self.storage_state_value

    async def close(self):
        return None


class FakePage:
    def __init__(self, url="https://www.goofish.com/"):
        self.url = url


def _write(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def test_evaluate_login_evidence_requires_ui_and_cookies_not_just_leaving_passport():
    result = evaluate_login_evidence(
        current_url="https://www.goofish.com/",
        has_logged_in_ui=False,
        cookie_names=["cookie2", "unb", "_m_h5_tk"],
        cookie_count=5,
    )
    assert result.confirmed is False
    assert "登录界面" in result.reason

    result = evaluate_login_evidence(
        current_url="https://www.goofish.com/",
        has_logged_in_ui=True,
        cookie_names=["cookie2", "unb", "_m_h5_tk"],
        cookie_count=5,
    )
    assert result.confirmed is True


def test_evaluate_login_evidence_rejects_login_page_even_with_cookies():
    result = evaluate_login_evidence(
        current_url="https://passport.goofish.com/mini_login.htm?foo=1",
        has_logged_in_ui=True,
        cookie_names=["cookie2", "unb", "_m_h5_tk"],
        cookie_count=5,
    )
    assert result.confirmed is False
    assert "登录页" in result.reason


def test_evaluate_login_evidence_rejects_empty_cookies():
    result = evaluate_login_evidence(
        current_url="https://www.goofish.com/",
        has_logged_in_ui=True,
        cookie_names=[],
        cookie_count=0,
    )
    assert result.confirmed is False
    assert "会话" in result.reason


def test_resolve_account_state_path_rejects_traversal(tmp_path):
    project = tmp_path / "proj"
    (project / "state").mkdir(parents=True)
    resolve_account_state_path(project, "acc_1")
    with pytest.raises(ValueError):
        resolve_account_state_path(project, "../acc_1")
    with pytest.raises(ValueError):
        resolve_account_state_path(project, "acc_1/../../secret")
    with pytest.raises(ValueError):
        resolve_account_state_path(project, "acc_1.json")
    with pytest.raises(ValueError):
        resolve_account_state_path(project, str(tmp_path / "acc_1"))
    with pytest.raises(ValueError):
        resolve_account_state_path(project, "acc_1", state_dir="..")
    with pytest.raises(ValueError):
        resolve_account_state_path(project, "acc_1", state_dir=str(tmp_path))


def test_save_skips_login_unconfirmed_empty_cancel_and_timeout(tmp_path):
    state_file = tmp_path / "acc_1.json"
    _write(state_file, ORIGINAL_STATE)
    original = state_file.read_text(encoding="utf-8")
    from src.services.session_state_persist import file_fingerprint

    fingerprint = file_fingerprint(str(state_file))
    context = FakeContext()

    saved, reason = asyncio.run(
        save_confirmed_login_state(
            context,
            state_file,
            existing_snapshot=ORIGINAL_STATE,
            expected_fingerprint=fingerprint,
            confirmed=False,
        )
    )
    assert saved is False
    assert "未确认" in reason
    assert state_file.read_text(encoding="utf-8") == original

    saved, reason = asyncio.run(
        save_confirmed_login_state(
            context,
            state_file,
            existing_snapshot=ORIGINAL_STATE,
            expected_fingerprint=fingerprint,
            confirmed=True,
            cancelled=True,
        )
    )
    assert saved is False
    assert "取消" in reason
    assert state_file.read_text(encoding="utf-8") == original

    saved, reason = asyncio.run(
        save_confirmed_login_state(
            context,
            state_file,
            existing_snapshot=ORIGINAL_STATE,
            expected_fingerprint=fingerprint,
            confirmed=True,
            timed_out=True,
        )
    )
    assert saved is False
    assert "超时" in reason
    assert state_file.read_text(encoding="utf-8") == original

    saved, reason = asyncio.run(
        save_confirmed_login_state(
            FakeContext(EMPTY_STATE),
            state_file,
            existing_snapshot=ORIGINAL_STATE,
            expected_fingerprint=fingerprint,
            confirmed=True,
        )
    )
    assert saved is False
    assert "不完整" in reason
    assert state_file.read_text(encoding="utf-8") == original


def test_save_skips_when_source_file_changed(tmp_path):
    state_file = tmp_path / "acc_1.json"
    _write(state_file, ORIGINAL_STATE)
    from src.services.session_state_persist import file_fingerprint

    fingerprint = file_fingerprint(str(state_file))
    updated = dict(ORIGINAL_STATE)
    updated["cookies"] = [{"name": "demo_session", "value": "imported-newer", "domain": ".example.test"}]
    _write(state_file, updated)
    before = state_file.read_text(encoding="utf-8")

    saved, reason = asyncio.run(
        save_confirmed_login_state(
            FakeContext(),
            state_file,
            existing_snapshot=ORIGINAL_STATE,
            expected_fingerprint=fingerprint,
            confirmed=True,
        )
    )
    assert saved is False
    assert "已变化" in reason
    assert state_file.read_text(encoding="utf-8") == before


def test_successful_save_preserves_enhanced_metadata(tmp_path):
    state_file = tmp_path / "acc_1.json"
    _write(state_file, ENHANCED_STATE)
    from src.services.session_state_persist import file_fingerprint

    fingerprint = file_fingerprint(str(state_file))
    saved, reason = asyncio.run(
        save_confirmed_login_state(
            FakeContext(),
            state_file,
            existing_snapshot=ENHANCED_STATE,
            expected_fingerprint=fingerprint,
            confirmed=True,
        )
    )
    assert saved is True
    assert "保存" in reason or "写回" in reason
    written = json.loads(state_file.read_text(encoding="utf-8"))
    assert written["env"] == ENHANCED_STATE["env"]
    assert written["headers"] == ENHANCED_STATE["headers"]
    assert written["storage"] == ENHANCED_STATE["storage"]
    assert written["page"] == ENHANCED_STATE["page"]
    assert written["cookies"] == VALID_STATE["cookies"]
    assert written["origins"] == VALID_STATE["origins"]


def test_inspect_and_maybe_save_on_login_page_does_not_overwrite(tmp_path):
    state_file = tmp_path / "acc_1.json"
    _write(state_file, ORIGINAL_STATE)
    original = state_file.read_text(encoding="utf-8")
    from src.services.session_state_persist import file_fingerprint

    async def observe(_page):
        return {
            "current_url": "https://passport.goofish.com/mini_login.htm",
            "on_login_page": True,
            "official_page": False,
            "has_logged_in_ui": False,
            "logged_out_cta_visible": True,
        }

    saved, reason, gate = asyncio.run(
        inspect_and_maybe_save(
            context=FakeContext(),
            page=FakePage("https://passport.goofish.com/mini_login.htm"),
            state_file=state_file,
            existing_snapshot=ORIGINAL_STATE,
            expected_fingerprint=file_fingerprint(str(state_file)),
            cancelled=False,
            timed_out=False,
            observe=observe,
        )
    )
    assert saved is False
    assert gate is not None and gate.confirmed is False
    assert "登录页" in reason
    assert state_file.read_text(encoding="utf-8") == original


def test_inspect_and_maybe_save_success(tmp_path):
    state_file = tmp_path / "acc_1.json"
    _write(state_file, ORIGINAL_STATE)
    from src.services.session_state_persist import file_fingerprint

    async def observe(_page):
        return {
            "current_url": "https://www.goofish.com/",
            "on_login_page": False,
            "official_page": True,
            "has_logged_in_ui": True,
            "logged_out_cta_visible": False,
        }

    saved, reason, gate = asyncio.run(
        inspect_and_maybe_save(
            context=FakeContext(),
            page=FakePage(),
            state_file=state_file,
            existing_snapshot=ORIGINAL_STATE,
            expected_fingerprint=file_fingerprint(str(state_file)),
            cancelled=False,
            timed_out=False,
            observe=observe,
        )
    )
    assert saved is True
    assert gate is not None and gate.confirmed is True
    written = json.loads(state_file.read_text(encoding="utf-8"))
    assert written["cookies"] == VALID_STATE["cookies"]


def test_run_login_session_cancel_and_timeout_do_not_overwrite(tmp_path, monkeypatch):
    project = tmp_path / "proj"
    state_dir = project / "state"
    state_dir.mkdir(parents=True)
    state_file = state_dir / "acc_1.json"
    _write(state_file, ORIGINAL_STATE)
    original = state_file.read_text(encoding="utf-8")
    status = project / "logs" / "login-helper-status.json"
    monkeypatch.setattr("src.login_helper.collection_tasks_are_running", lambda: False)

    async def factory():
        return None, FakeBrowser(), FakeContext(), FakePage()

    class FakeBrowser:
        def is_connected(self):
            return True

        async def close(self):
            return None

    async def cancel_wait(_timeout, is_browser_open=None):
        return "cancel"

    code = asyncio.run(
        run_login_session(
            account_id="acc_1",
            timeout_sec=30,
            project_dir=project,
            status_path=status,
            wait_action=cancel_wait,
            browser_factory=factory,
        )
    )
    assert code == 4
    assert state_file.read_text(encoding="utf-8") == original
    payload = json.loads(status.read_text(encoding="utf-8"))
    assert payload["status"] == "cancelled"
    assert payload["saved"] is False
    assert "cookie" not in json.dumps(payload).lower() or "cookie" not in payload["message"].lower()

    async def timeout_wait(_timeout, is_browser_open=None):
        return "timeout"

    code = asyncio.run(
        run_login_session(
            account_id="acc_1",
            timeout_sec=30,
            project_dir=project,
            status_path=status,
            wait_action=timeout_wait,
            browser_factory=factory,
        )
    )
    assert code == 3
    assert state_file.read_text(encoding="utf-8") == original
    payload = json.loads(status.read_text(encoding="utf-8"))
    assert payload["status"] == "timeout"
    assert payload["saved"] is False


def test_status_file_omits_secrets(tmp_path):
    path = tmp_path / "login-helper-status.json"
    write_status_file(
        path,
        status="waiting_for_user",
        account_id="acc_1",
        state_file="state/acc_1.json",
        message="已打开独立登录窗口",
    )
    raw = path.read_text(encoding="utf-8")
    payload = json.loads(raw)
    assert payload["status"] == "waiting_for_user"
    assert payload["saved"] is False
    assert "cookie2" not in raw
    assert "token" not in raw.lower()
    assert "?" not in payload["message"]

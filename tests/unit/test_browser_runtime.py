import asyncio
import inspect
import json
import os
from pathlib import Path

import pytest

from src.login_helper import run_login_session
from src.services.browser_runtime import (
    AccountProfileLock,
    ProfileBusyError,
    UnsafeBrowserProfileError,
    account_id_from_state_file,
    close_persistent_context,
    context_options_are_safe,
    ensure_account_profile_dir,
    is_forbidden_external_browser_dir,
    launch_args_are_safe,
    launch_shared_persistent_context,
    resolve_account_profile_dir,
    shared_browser_context_options,
    shared_launch_kwargs,
)


def test_shared_options_have_no_ua_mobile_viewport_or_unsafe_flags():
    options = shared_browser_context_options()
    assert context_options_are_safe(options)
    assert "user_agent" not in options
    assert "viewport" not in options
    assert "is_mobile" not in options
    assert "has_touch" not in options
    assert "device_scale_factor" not in options
    assert "geolocation" not in options
    assert "storage_state" not in options
    assert options.get("no_viewport") is True

    kwargs = shared_launch_kwargs(
        headless=False, login_is_edge=False, running_in_docker=False
    )
    assert kwargs["channel"] == "chrome"
    assert kwargs["headless"] is False
    assert kwargs["args"] == []
    assert launch_args_are_safe(kwargs["args"])
    assert context_options_are_safe(kwargs)
    assert "storage_state" not in kwargs


def test_docker_and_edge_channels_stay_on_shared_kwargs():
    docker = shared_launch_kwargs(
        headless=True, login_is_edge=True, running_in_docker=True
    )
    assert docker["channel"] == "chromium"
    assert launch_args_are_safe(docker["args"])
    local_edge = shared_launch_kwargs(
        headless=False, login_is_edge=True, running_in_docker=False
    )
    assert local_edge["channel"] == "msedge"
    assert local_edge["args"] == []


def test_login_helper_and_scraper_use_same_shared_launch_path():
    import src.login_helper as login_helper
    import src.scraper as scraper

    helper_src = inspect.getsource(login_helper)
    scrape_src = inspect.getsource(scraper)
    default_factory = inspect.getsource(login_helper.run_login_session)
    assert "launch_shared_persistent_context" in helper_src
    assert "launch_shared_persistent_context" in scrape_src
    assert "add_init_script" not in helper_src
    assert "add_init_script" not in scrape_src
    assert "storage_state=" not in scrape_src
    assert "Chrome/131" not in helper_src and "Chrome/131" not in scrape_src
    assert "AutomationControlled" not in helper_src and "AutomationControlled" not in scrape_src
    assert "disable-web-security" not in helper_src and "disable-web-security" not in scrape_src
    assert "await browser.close()" not in scrape_src
    assert "close_persistent_context" in scrape_src
    assert "close_persistent_context" in default_factory
    assert "shared_browser_context_options" in inspect.getsource(scraper._default_context_options)


def test_profile_directory_is_project_isolated_and_rejects_escape(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    path = resolve_account_profile_dir(project, "acc_1")
    assert path == project / "browser-profiles" / "acc_1"
    created = ensure_account_profile_dir(project, "acc_1")
    assert created.is_dir()
    assert created.resolve().is_relative_to((project / "browser-profiles").resolve())

    other = ensure_account_profile_dir(project, "acc_2")
    assert other != created
    assert other.name == "acc_2"

    with pytest.raises((UnsafeBrowserProfileError, ValueError)):
        resolve_account_profile_dir(project, "../acc_1")
    with pytest.raises((UnsafeBrowserProfileError, ValueError)):
        resolve_account_profile_dir(project, "acc_1/../../etc")
    with pytest.raises((UnsafeBrowserProfileError, ValueError)):
        account_id_from_state_file("xianyu_state.json")
    with pytest.raises((UnsafeBrowserProfileError, ValueError)):
        account_id_from_state_file("not-an-account")
    assert account_id_from_state_file("state/acc_1.json") == "acc_1"
    assert account_id_from_state_file(r"C:\proj\state\acc_2.json") == "acc_2"

    chrome_paths = [
        r"C:\Users\demo\AppData\Local\Google\Chrome\User Data",
        r"C:\Users\demo\AppData\Local\Microsoft\Edge\User Data",
        "/home/demo/.config/google-chrome",
        "/Users/demo/Library/Application Support/Google/Chrome",
    ]
    for raw in chrome_paths:
        assert is_forbidden_external_browser_dir(raw)

    outside = tmp_path / "outside-profile"
    outside.mkdir()
    profiles = project / "browser-profiles"
    profiles.mkdir(exist_ok=True)
    escaped = profiles / "acc_9"
    escaped.symlink_to(outside, target_is_directory=True)
    with pytest.raises(UnsafeBrowserProfileError):
        resolve_account_profile_dir(project, "acc_9")


@pytest.mark.asyncio
async def test_launch_persistent_context_rejects_daily_chrome_and_skips_storage_state(tmp_path):
    recorded = {}

    class Chromium:
        async def launch_persistent_context(self, user_data_dir, **kwargs):
            recorded["user_data_dir"] = user_data_dir
            recorded["kwargs"] = kwargs
            return {"ok": True}

    class Playwright:
        def __init__(self):
            self.chromium = Chromium()

    daily = tmp_path / "Google" / "Chrome" / "User Data"
    daily.mkdir(parents=True)
    with pytest.raises(UnsafeBrowserProfileError):
        await launch_shared_persistent_context(
            Playwright(),
            user_data_dir=daily,
            headless=False,
            login_is_edge=False,
            running_in_docker=False,
        )

    safe = tmp_path / "proj" / "browser-profiles" / "acc_1"
    safe.mkdir(parents=True)
    result = await launch_shared_persistent_context(
        Playwright(),
        user_data_dir=safe,
        headless=False,
        login_is_edge=False,
        running_in_docker=False,
        proxy_server=None,
    )
    assert result == {"ok": True}
    assert "storage_state" not in recorded["kwargs"]
    assert recorded["kwargs"]["channel"] == "chrome"
    assert launch_args_are_safe(recorded["kwargs"]["args"])
    assert context_options_are_safe(recorded["kwargs"])


@pytest.mark.asyncio
async def test_close_persistent_context_does_not_call_browser_close():
    class Browser:
        def __init__(self):
            self.closed = 0

        async def close(self):
            self.closed += 1

    class Context:
        def __init__(self):
            self.closed = 0
            self.browser = Browser()

        async def close(self):
            self.closed += 1

    context = Context()
    await close_persistent_context(context)
    assert context.closed == 1
    assert context.browser.closed == 0


def test_same_account_lock_rejects_and_releases_without_killing(tmp_path, monkeypatch):
    project = tmp_path / "proj"
    project.mkdir()
    killed = []

    real_kill = os.kill

    def guarded_kill(pid, sig):
        killed.append((pid, sig))
        if sig != 0:
            raise AssertionError("lock must not send a terminating signal")
        return real_kill(pid, sig)

    monkeypatch.setattr(os, "kill", guarded_kill)

    first = AccountProfileLock(project, "acc_1", purpose="login")
    first.acquire()
    try:
        with pytest.raises(ProfileBusyError) as excinfo:
            AccountProfileLock(project, "acc_1", purpose="scrape").acquire()
        assert "acc_1" in str(excinfo.value)
        # another account remains available
        second = AccountProfileLock(project, "acc_2", purpose="scrape")
        second.acquire()
        second.release()
        assert not (project / "browser-profiles" / "acc_2.lock").exists()
    finally:
        first.release()
    assert not (project / "browser-profiles" / "acc_1.lock").exists()

    # stale lock from a dead pid is recoverable
    stale = project / "browser-profiles" / "acc_1.lock"
    stale.write_text(json.dumps({"pid": 99999999, "purpose": "login", "account_id": "acc_1"}), encoding="utf-8")
    recovered = AccountProfileLock(project, "acc_1", purpose="scrape")
    recovered.acquire()
    recovered.release()
    assert all(sig == 0 for _pid, sig in killed)


def test_run_login_session_busy_lock_and_cancel_do_not_overwrite(tmp_path, monkeypatch):
    project = tmp_path / "proj"
    state_dir = project / "state"
    state_dir.mkdir(parents=True)
    state_file = state_dir / "acc_1.json"
    original = json.dumps({"cookies": [{"name": "keep", "value": "old"}]}, ensure_ascii=False)
    state_file.write_text(original, encoding="utf-8")
    status = project / "logs" / "login-helper-status.json"
    monkeypatch.setattr("src.login_helper.collection_tasks_are_running", lambda: False)

    holder = AccountProfileLock(project, "acc_1", purpose="scrape")
    holder.acquire()
    try:
        code = asyncio.run(
            run_login_session(
                account_id="acc_1",
                timeout_sec=30,
                project_dir=project,
                status_path=status,
                wait_action=lambda *_args, **_kwargs: "cancel",
                browser_factory=lambda: (_ for _ in ()).throw(AssertionError("must not launch")),
            )
        )
    finally:
        holder.release()
    assert code == 2
    payload = json.loads(status.read_text(encoding="utf-8"))
    assert payload["status"] == "blocked_busy"
    assert payload["saved"] is False
    assert state_file.read_text(encoding="utf-8") == original

    class TrackingContext:
        def __init__(self):
            self.closed = 0

        async def close(self):
            self.closed += 1

        async def storage_state(self, path=None):
            raise AssertionError("cancel must not export storage")

    class TrackingBrowser:
        def __init__(self):
            self.closed = 0

        def is_connected(self):
            return True

        async def close(self):
            self.closed += 1

    context = TrackingContext()
    browser = TrackingBrowser()

    async def factory():
        return None, browser, context, type("Page", (), {"url": "https://www.goofish.com/"})()

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
    assert context.closed == 1
    assert browser.closed == 0
    payload = json.loads(status.read_text(encoding="utf-8"))
    assert payload["status"] == "cancelled"
    assert payload["saved"] is False

"""User-triggered headed login helper for a local Goofish account file.

Open an independent Playwright window on the official homepage. The user
logs in there (QR / captcha / account UI). This process never asks for a
password or code on the command line, never attaches to the daily browser,
and never prints cookie or token values.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

from src.services.login_auth_gate import (
    DEFAULT_ACCOUNT_ID,
    OFFICIAL_HOME_URL,
    cookie_names_from_storage_state,
    default_status_path,
    evaluate_login_evidence,
    existing_snapshot_or_none,
    is_login_url,
    is_official_goofish_url,
    redact_url,
    resolve_account_state_path,
    save_confirmed_login_state,
    write_status_file,
)

# file_fingerprint is in session_state_persist; I'll alias in gate or import here.
from src.services.session_state_persist import file_fingerprint


# Keep this identical to src.scraper scrape context init.
SCRAPER_CONTEXT_INIT_SCRIPT = """
                // 移除webdriver标识
                Object.defineProperty(navigator, 'webdriver', {get: () => undefined});

                // 模拟真实移动设备的navigator属性
                Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
                Object.defineProperty(navigator, 'languages', {get: () => ['zh-CN', 'zh', 'en-US', 'en']});

                // 添加chrome对象
                window.chrome = {runtime: {}, loadTimes: function() {}, csi: function() {}};

                // 模拟触摸支持
                Object.defineProperty(navigator, 'maxTouchPoints', {get: () => 5});

                // 覆盖permissions查询（避免暴露自动化）
                const originalQuery = window.navigator.permissions.query;
                window.navigator.permissions.query = (parameters) => (
                    parameters.name === 'notifications' ?
                        Promise.resolve({state: Notification.permission}) :
                        originalQuery(parameters)
                );
            """

DEFAULT_TIMEOUT_SEC = 15 * 60
PAGE_GOTO_TIMEOUT_MS = 60 * 1000

USER_INSTRUCTIONS = """
================================ 闲鱼专用登录窗口 ================================
将打开一个独立的闲鱼浏览器窗口（不会读取或附着你日常使用的 Chrome/Edge）。

请在那个窗口里自行完成登录（可用闲鱼 App 扫码，或按页面提示做验证码）。
不要在这个黑色控制台里输入账号、密码或验证码。

登录成功后，回到【这个控制台窗口】，按回车键保存登录态。
如果要放弃，输入 cancel 再回车。

说明：
- 登录态只保存在本机账号文件，不会发到别处。
- 不能保证登录会一直有效；失效后可再运行本工具登录一次。
- 请不要关闭刚刚打开的浏览器窗口，直到这里提示保存完成或已取消。
- 最长等待约 15 分钟；超时会结束且不会覆盖原文件。
================================================================================
""".strip()


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def collection_tasks_are_running(api_url: str = "http://127.0.0.1:8000/api/tasks") -> bool:
    try:
        import urllib.request

        req = urllib.request.Request(api_url, method="GET")
        with urllib.request.urlopen(req, timeout=2) as resp:
            raw = resp.read()
        payload = json.loads(raw.decode("utf-8"))
        tasks = payload if isinstance(payload, list) else payload.get("tasks") or []
        return any(bool(task.get("is_running")) for task in tasks if isinstance(task, dict))
    except Exception:
        return False


async def observe_page(page: Any) -> dict:
    url = ""
    try:
        url = page.url or ""
    except Exception:
        url = ""

    frame_login = False
    try:
        for frame in page.frames:
            frame_url = getattr(frame, "url", "") or ""
            if is_login_url(frame_url):
                frame_login = True
                break
    except Exception:
        pass

    signals = {
        "has_logged_in_ui": False,
        "logged_out_cta_visible": False,
    }
    try:
        signals = await page.evaluate(
            """
            () => {
              const visible = (el) => {
                if (!el) return false;
                const style = window.getComputedStyle(el);
                if (!style || style.display === 'none' || style.visibility === 'hidden') return false;
                const rect = el.getBoundingClientRect();
                return rect.width > 0 && rect.height > 0;
              };
              const clickables = Array.from(document.querySelectorAll('a,button,span,div'));
              let loggedOutCta = false;
              for (const el of clickables) {
                const text = (el.innerText || el.textContent || '').replace(/\\s+/g, '');
                if (!visible(el)) continue;
                if (text === '登录' || text === '登入' || text === '手机号登录' || text === '账号登录' || text === '快速登录') {
                  loggedOutCta = true;
                  break;
                }
              }
              const logout = clickables.some((el) => {
                const text = (el.innerText || el.textContent || '').replace(/\\s+/g, '');
                return visible(el) && (text === '退出登录' || text === '退出账号');
              });
              const avatar = Array.from(document.querySelectorAll(
                'img[class*="avatar"], [class*="avatar"] img, [class*="userInfo"] img, [class*="UserInfo"] img, [class*="header-avatar"], [class*="user-avatar"]'
              )).some(visible);
              const userEntry = Array.from(document.querySelectorAll(
                '[class*="nickName"], [class*="nickname"], [class*="userName"], [class*="user-name"], [class*="userInfo"], [class*="UserInfo"]'
              )).some(visible);
              return {
                has_logged_in_ui: Boolean(logout || avatar || userEntry),
                logged_out_cta_visible: loggedOutCta,
              };
            }
            """
        )
    except Exception:
        signals = {"has_logged_in_ui": False, "logged_out_cta_visible": False}

    return {
        "current_url": url,
        "on_login_page": is_login_url(url) or frame_login,
        "official_page": is_official_goofish_url(url) and not frame_login,
        "has_logged_in_ui": bool(signals.get("has_logged_in_ui")),
        "logged_out_cta_visible": bool(signals.get("logged_out_cta_visible")),
    }


def _read_console_action(result: dict) -> None:
    try:
        line = input()
    except EOFError:
        result["action"] = "cancel"
        return
    text = (line or "").strip().lower()
    if text in {"cancel", "c", "q", "quit", "exit"}:
        result["action"] = "cancel"
    else:
        result["action"] = "save"


async def wait_for_console_action(
    timeout_sec: int,
    *,
    is_browser_open: Optional[Callable[[], Any]] = None,
    input_reader: Optional[Callable[[dict], None]] = None,
) -> str:
    result: dict = {"action": None}
    thread = threading.Thread(target=input_reader or _read_console_action, args=(result,), daemon=True)
    thread.start()
    deadline = time.monotonic() + max(1, int(timeout_sec))
    while time.monotonic() < deadline:
        if result["action"]:
            return result["action"]
        if is_browser_open is not None:
            try:
                open_flag = is_browser_open()
                if asyncio.iscoroutine(open_flag):
                    open_flag = await open_flag
                if open_flag is False:
                    return "cancel"
            except Exception:
                return "cancel"
        await asyncio.sleep(0.25)
    return "timeout"


async def inspect_and_maybe_save(
    *,
    context: Any,
    page: Any,
    state_file: Path,
    existing_snapshot: Any,
    expected_fingerprint: Any,
    cancelled: bool,
    timed_out: bool,
    observe=observe_page,
) -> tuple[bool, str, Any]:
    if cancelled:
        return False, "已取消，未修改登录态文件", None
    if timed_out:
        return False, "等待超时，未修改登录态文件", None

    observations = await observe(page)
    storage_state = await context.storage_state()
    names = cookie_names_from_storage_state(storage_state)
    cookie_count = len(storage_state.get("cookies") or []) if isinstance(storage_state, dict) else 0
    gate = evaluate_login_evidence(
        current_url=observations.get("current_url") or "",
        on_login_page=observations.get("on_login_page"),
        official_page=observations.get("official_page"),
        has_logged_in_ui=bool(observations.get("has_logged_in_ui")),
        logged_out_cta_visible=bool(observations.get("logged_out_cta_visible")),
        cookie_names=names,
        cookie_count=cookie_count,
    )
    if not gate.confirmed:
        return False, gate.reason, gate

    saved, reason = await save_confirmed_login_state(
        context,
        state_file,
        existing_snapshot=existing_snapshot,
        expected_fingerprint=expected_fingerprint,
        confirmed=True,
    )
    return saved, reason, gate


async def run_login_session(
    *,
    account_id: str = DEFAULT_ACCOUNT_ID,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    project_dir: Optional[Path] = None,
    status_path: Optional[Path] = None,
    wait_action=None,
    browser_factory=None,
) -> int:
    root = (project_dir or project_root()).resolve()
    state_file = resolve_account_state_path(root, account_id)
    status = status_path or default_status_path(root)
    relative_state = str(state_file.relative_to(root)).replace("\\", "/")

    def status_update(**fields: Any) -> None:
        write_status_file(
            status,
            account_id=account_id,
            state_file=relative_state,
            **fields,
        )

    if collection_tasks_are_running():
        message = "有采集任务正在运行，已取消本次登录，以免同时写登录态"
        print(message)
        status_update(status="blocked_busy", message=message)
        return 2

    existing_snapshot = existing_snapshot_or_none(state_file)
    expected_fingerprint = file_fingerprint(str(state_file)) if state_file.is_file() else None
    status_update(status="starting", message="正在打开独立登录窗口")
    print(USER_INSTRUCTIONS)
    print(f"将保存到本机账号文件: {relative_state}")
    print("本次使用干净的独立浏览器配置，不会导入日常浏览器或旧的失效登录态。")
    print("登录完成后请回到这里按回车保存；输入 cancel 取消。")

    async def _default_browser_factory():
        from src.scraper import (
            _clean_kwargs,
            _default_context_options,
            _resolve_browser_channel,
            prepare_chromium_launch_args,
        )
        from playwright.async_api import async_playwright

        playwright = await async_playwright().start()
        launch_kwargs = {
            "headless": False,
            "args": prepare_chromium_launch_args(),
            "channel": _resolve_browser_channel(),
        }
        browser = await playwright.chromium.launch(**launch_kwargs)
        context = await browser.new_context(**_clean_kwargs(_default_context_options()))
        await context.add_init_script(SCRAPER_CONTEXT_INIT_SCRIPT)
        page = await context.new_page()
        await page.goto(OFFICIAL_HOME_URL, wait_until="domcontentloaded", timeout=PAGE_GOTO_TIMEOUT_MS)
        return playwright, browser, context, page

    factory = browser_factory or _default_browser_factory
    playwright = browser = context = page = None
    exit_code = 1
    try:
        playwright, browser, context, page = await factory()
        status_update(status="waiting_for_user", message="已打开独立登录窗口，等待用户在窗口内登录后回控制台确认")
        print("已打开闲鱼官方首页，请在弹出的窗口中完成登录。")

        async def _browser_still_open() -> bool:
            try:
                if browser is None:
                    return False
                is_closed = getattr(browser, "is_connected", None)
                if callable(is_closed):
                    return bool(browser.is_connected())
                return True
            except Exception:
                return False

        remaining = max(1, int(timeout_sec))
        deadline = time.monotonic() + remaining
        while True:
            left = int(deadline - time.monotonic())
            if left <= 0:
                print("等待超时，未修改原登录态文件。")
                status_update(status="timeout", message="等待超时，未修改原登录态文件", timed_out=True)
                exit_code = 3
                break
            action = await (wait_action or wait_for_console_action)(left, is_browser_open=_browser_still_open)
            if action == "timeout":
                print("等待超时，未修改原登录态文件。")
                status_update(status="timeout", message="等待超时，未修改原登录态文件", timed_out=True)
                exit_code = 3
                break
            if action == "cancel":
                print("已取消，未修改原登录态文件。")
                status_update(status="cancelled", message="已取消，未修改原登录态文件", cancelled=True)
                exit_code = 4
                break

            status_update(status="checking", message="正在确认是否已登录，不会记录账号或会话内容")
            saved, reason, _gate = await inspect_and_maybe_save(
                context=context,
                page=page,
                state_file=state_file,
                existing_snapshot=existing_snapshot,
                expected_fingerprint=expected_fingerprint,
                cancelled=False,
                timed_out=False,
            )
            print(reason)
            if saved:
                status_update(status="saved", message=reason, login_confirmed=True, saved=True)
                exit_code = 0
                break
            status_update(status="unconfirmed", message=reason + "。窗口仍保持打开，可继续登录后按回车，或输入 cancel 取消")
            print("尚未确认登录，窗口会继续保持。请完成登录后再按回车，或输入 cancel 取消。")
    except Exception as exc:
        message = f"登录窗口启动或运行失败（{type(exc).__name__}），未修改原登录态文件"
        print(message)
        status_update(status="error", message=message)
        exit_code = 1
    finally:
        for closer in (context, browser):
            if closer is None:
                continue
            try:
                await closer.close()
            except Exception:
                pass
        if playwright is not None:
            try:
                await playwright.stop()
            except Exception:
                pass
    return exit_code


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="在独立浏览器窗口登录闲鱼并安全保存本机登录态。不要在此输入密码或验证码。"
    )
    parser.add_argument(
        "--account-id",
        default=DEFAULT_ACCOUNT_ID,
        help="仅接受 acc_ 加字母数字的账号 ID，默认 acc_1",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=DEFAULT_TIMEOUT_SEC,
        help="最长等待秒数，默认 900（15 分钟）",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    try:
        resolve_account_state_path(project_root(), args.account_id)
    except ValueError as exc:
        print(str(exc))
        try:
            write_status_file(
                default_status_path(project_root()),
                status="error",
                account_id=DEFAULT_ACCOUNT_ID,
                message=str(exc),
            )
        except Exception:
            pass
        return 2
    timeout = args.timeout_seconds if args.timeout_seconds and args.timeout_seconds > 0 else DEFAULT_TIMEOUT_SEC
    return asyncio.run(
        run_login_session(account_id=args.account_id, timeout_sec=timeout)
    )


if __name__ == "__main__":
    sys.exit(main())

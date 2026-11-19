import importlib


def _load_scraper(monkeypatch, *, login_is_edge: bool, running_in_docker: bool):
    monkeypatch.setenv("LOGIN_IS_EDGE", "true" if login_is_edge else "false")
    monkeypatch.setenv("RUNNING_IN_DOCKER", "true" if running_in_docker else "false")

    import src.config as config_module
    import src.scraper as scraper_module

    importlib.reload(config_module)
    reloaded_scraper = importlib.reload(scraper_module)
    reloaded_scraper.EDGE_DOCKER_WARNING_PRINTED = False
    return reloaded_scraper


def test_resolve_browser_channel_uses_chromium_in_docker_even_when_edge_requested(monkeypatch, capsys):
    scraper = _load_scraper(monkeypatch, login_is_edge=True, running_in_docker=True)

    assert scraper._resolve_browser_channel() == "chromium"
    assert "Docker 镜像未内置 Edge" in capsys.readouterr().out


def test_resolve_browser_channel_uses_msedge_locally_when_requested(monkeypatch):
    scraper = _load_scraper(monkeypatch, login_is_edge=True, running_in_docker=False)

    assert scraper._resolve_browser_channel() == "msedge"


def test_chromium_launch_args_are_safe_and_pin_dump_dir_only_in_docker():
    from src.scraper import build_chromium_launch_args
    from src.services.browser_runtime import launch_args_are_safe

    assert build_chromium_launch_args("/tmp/chromium-crashpad") == []
    assert launch_args_are_safe(build_chromium_launch_args("/tmp/chromium-crashpad"))

    args = build_chromium_launch_args("/tmp/chromium-crashpad", docker=True)
    assert "--disable-breakpad" in args
    assert "--disable-crash-reporter" in args
    assert "--crash-dumps-dir=/tmp/chromium-crashpad" in args
    assert "--disable-features=Crashpad" in args
    joined = " ".join(args)
    assert "AutomationControlled" not in joined
    assert "disable-web-security" not in joined
    assert "IsolateOrigins" not in joined
    assert "site-per-process" not in joined
    assert launch_args_are_safe(args)

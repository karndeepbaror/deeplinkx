import os

import pytest

from fixtures.sample_apps import build_vulnerable_apk


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("DEEPLINKX_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("DEEPLINKX_API_TOKEN", raising=False)
    monkeypatch.setenv("NO_COLOR", "1")


@pytest.fixture(scope="session")
def vuln_apk(tmp_path_factory):
    return build_vulnerable_apk(tmp_path_factory.mktemp("apks") / "shop-demo.apk")

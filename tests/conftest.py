"""Minimal Home Assistant stubs, a fake clock and a fake hass for unit tests.

The integration only touches a small slice of HA (DataUpdateCoordinator and a
few exceptions), so the tests stub that slice instead of installing HA.
"""

import asyncio
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _install_ha_stubs() -> None:
    if "homeassistant" in sys.modules:
        return
    ha = types.ModuleType("homeassistant")
    core = types.ModuleType("homeassistant.core")
    exceptions = types.ModuleType("homeassistant.exceptions")
    helpers = types.ModuleType("homeassistant.helpers")
    uc = types.ModuleType("homeassistant.helpers.update_coordinator")

    class HomeAssistantError(Exception):
        pass

    class ConfigEntryAuthFailed(HomeAssistantError):
        pass

    class UpdateFailed(HomeAssistantError):
        pass

    class DataUpdateCoordinator:
        def __init__(self, hass, logger, name, update_interval):
            self.hass = hass
            self.logger = logger
            self.name = name
            self.update_interval = update_interval
            self.data = None
            self.last_update_success = True
            self.refresh_requests = 0

        async def async_refresh(self):
            try:
                self.data = await self._async_update_data()
                self.last_update_success = True
            except UpdateFailed:
                self.last_update_success = False

        async def async_request_refresh(self):
            self.refresh_requests += 1

        def async_set_updated_data(self, data):
            self.data = data
            self.last_update_success = True

        def async_update_listeners(self):
            pass

    class CoordinatorEntity:
        def __init__(self, coordinator):
            self.coordinator = coordinator

    class _Enum:
        def __getattr__(self, name):
            return name

    components = types.ModuleType("homeassistant.components")
    cover = types.ModuleType("homeassistant.components.cover")
    cover.CoverDeviceClass = _Enum()
    cover.CoverEntityFeature = types.SimpleNamespace(OPEN=1, CLOSE=2)
    cover.CoverEntity = type("CoverEntity", (), {})
    config_entries = types.ModuleType("homeassistant.config_entries")
    config_entries.ConfigEntry = object
    entity_platform = types.ModuleType("homeassistant.helpers.entity_platform")
    entity_platform.AddEntitiesCallback = object
    uc.CoordinatorEntity = CoordinatorEntity
    sys.modules.update({
        "homeassistant.components": components,
        "homeassistant.components.cover": cover,
        "homeassistant.config_entries": config_entries,
        "homeassistant.helpers.entity_platform": entity_platform,
    })

    core.HomeAssistant = object
    core.callback = lambda f: f
    exceptions.HomeAssistantError = HomeAssistantError
    exceptions.ConfigEntryAuthFailed = ConfigEntryAuthFailed
    uc.DataUpdateCoordinator = DataUpdateCoordinator
    uc.UpdateFailed = UpdateFailed
    for name, mod in {
        "homeassistant": ha,
        "homeassistant.core": core,
        "homeassistant.exceptions": exceptions,
        "homeassistant.helpers": helpers,
        "homeassistant.helpers.update_coordinator": uc,
    }.items():
        sys.modules[name] = mod


_install_ha_stubs()


class FakeClock:
    """Stands in for the `time` module: monotonic() and time() advance together."""

    def __init__(self, start_wall: float = 1_800_000_000.0):
        self._mono = 1000.0
        self._wall = start_wall

    def monotonic(self) -> float:
        return self._mono

    def time(self) -> float:
        return self._wall

    def advance(self, seconds: float) -> None:
        self._mono += seconds
        self._wall += seconds


class FakeLoop:
    def __init__(self):
        self.later = []

    def call_soon_threadsafe(self, fn, *args):
        fn(*args)

    def call_later(self, delay, fn, *args):
        handle = types.SimpleNamespace(delay=delay, fn=fn, args=args, cancelled=False)
        handle.cancel = lambda: setattr(handle, "cancelled", True)
        self.later.append(handle)
        return handle


class FakeHass:
    """Runs executor jobs inline and collects created tasks for the test to run."""

    def __init__(self):
        self.loop = FakeLoop()
        self.tasks = []
        self.service_calls = []
        self.services = types.SimpleNamespace(async_call=self._async_call)

    async def _async_call(self, domain, service, data):
        self.service_calls.append((domain, service, data))

    async def async_add_executor_job(self, fn, *args):
        return fn(*args)

    def async_create_task(self, coro):
        self.tasks.append(coro)

    async def run_tasks(self):
        while self.tasks:
            await self.tasks.pop(0)


@pytest.fixture
def clock(monkeypatch):
    from custom_components.wayzn import coordinator as coord_mod

    fake = FakeClock()
    monkeypatch.setattr(coord_mod, "time", fake)
    return fake


@pytest.fixture
def hass():
    fake = FakeHass()
    yield fake
    for coro in fake.tasks:  # tasks a test chose not to run
        coro.close()


@pytest.fixture
def run():
    def _run(coro):
        return asyncio.run(coro)
    return _run

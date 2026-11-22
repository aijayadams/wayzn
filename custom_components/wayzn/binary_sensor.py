"""Binary sensor entities for Wayzn door settings (read-only)."""

from typing import Any, Dict, Optional

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_track_time_change

from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import CONF_DEVICE_ID, CONF_DEVICE_LABEL, CONF_MODE, DOMAIN, MODE_LOCAL
from .entity import WayznSettingEntity
from .wayzn_client import wayzn_core as core

# (settings key, name, icon, entity category)
_FLAGS = (
    ("auto_open", "Auto-open on motion (home)", "mdi:motion-sensor", None),
    ("auto_open_pet_tag", "Auto-open on pet tag (home)", "mdi:tag", None),
    ("away_auto_open", "Auto-open on motion (away)", "mdi:motion-sensor", None),
    ("away_auto_open_pet_tag", "Auto-open on pet tag (away)", "mdi:tag", None),
    ("away_mode", "Away mode", "mdi:home-export-outline", None),
    ("schedule_enabled", "Schedule enabled", "mdi:calendar-check", None),
    ("obstruction_detection", "Obstruction detection", "mdi:alert-octagon-outline", None),
    ("button_enabled", "Physical button", "mdi:gesture-tap-button", None),
    ("allow_location_automation", "Location automation", "mdi:map-marker-radius", EntityCategory.DIAGNOSTIC),
)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up Wayzn settings binary sensors."""
    coordinator = hass.data[DOMAIN][entry.entry_id]
    if entry.data.get(CONF_MODE) == MODE_LOCAL:
        async_add_entities([
            LocalDetectionSensor(coordinator, entry, "presence", "Presence", BinarySensorDeviceClass.MOTION,
                                 "mdi:dog-side"),
            LocalDetectionSensor(coordinator, entry, "occupied", "Obstruction", BinarySensorDeviceClass.OCCUPANCY,
                                 "mdi:shield-alert-outline"),
            LocalFaultSensor(coordinator, entry),
        ])
        return
    entities: list = [WayznFlagSensor(coordinator, entry, *flag) for flag in _FLAGS]
    entities.append(WayznScheduleWindowSensor(coordinator, entry))
    entities.append(WayznPetTagReceiverSensor(coordinator, entry))
    async_add_entities(entities)


class WayznFlagSensor(WayznSettingEntity, BinarySensorEntity):
    def __init__(self, coordinator, entry: ConfigEntry, key: str, name: str, icon: str, category) -> None:
        super().__init__(coordinator, entry, key)
        self._attr_name = name
        self._attr_icon = icon
        self._attr_entity_category = category

    @property
    def is_on(self) -> Optional[bool]:
        return self.setting


class WayznScheduleWindowSensor(WayznSettingEntity, BinarySensorEntity):
    """On while the clock is inside one of today's schedule windows.

    Computed locally from the schedule and the device time zone, re-evaluated
    every minute. It says nothing about whether the schedule is enabled; see
    the "Schedule enabled" sensor.
    """

    _attr_name = "In schedule window"
    _attr_icon = "mdi:calendar-clock"

    def __init__(self, coordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "schedule")
        self._attr_unique_id = f"{self._attr_unique_id}_window"

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(async_track_time_change(self.hass, self._handle_tick, second=0))

    @callback
    def _handle_tick(self, _now) -> None:
        self.async_write_ha_state()

    @property
    def is_on(self) -> Optional[bool]:
        schedule = self.setting
        return core.schedule_window_active(schedule) if schedule else None

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        schedule = self.setting
        if not schedule:
            return {}
        today = core.schedule_today(schedule)
        return {"day": today["name"], "windows": [f"{w['start']}–{w['end']}" for w in today["active_times"]]}


class WayznPetTagReceiverSensor(WayznSettingEntity, BinarySensorEntity):
    _attr_name = "Pet tag receiver"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "pet_tag_receiver_connected")

    @property
    def is_on(self) -> Optional[bool]:
        return self.setting


# A detection seen this recently by the door counts as "on", so a short visit that starts and
# ends between two polls (1 s apart) still shows up in HA.
SEEN_WITHIN_MS = 1500


class LocalDetectionSensor(CoordinatorEntity, BinarySensorEntity):
    """The door's own view of its doorway (local mode, Grid-EYE).

    Presence: a dog wants out (what triggers auto-open). Obstruction: the doorway is not
    clear (the door won't close, and a closing door reverses). Unknown when the door's state
    isn't fresh or its sensor isn't reading.
    """

    _attr_has_entity_name = True

    def __init__(self, coordinator, entry: ConfigEntry, key: str, name: str, device_class, icon: str) -> None:
        super().__init__(coordinator)
        self._key = key
        device_id = entry.data[CONF_DEVICE_ID]
        self._attr_unique_id = f"{device_id}_{key}_detected"
        self._attr_name = name
        self._attr_device_class = device_class
        self._attr_icon = icon
        self._attr_device_info = {
            "identifiers": {(DOMAIN, device_id)},
            "name": entry.data[CONF_DEVICE_LABEL],
            "manufacturer": "Wayzn",
            "model": "Smart Pet Door",
        }

    @property
    def is_on(self) -> Optional[bool]:
        if self.coordinator.stale:
            return None
        b = (self.coordinator.data or {}).get("brain") or {}
        if not b.get("grideye_ok", False):
            return None
        if b.get(self._key):
            return True
        age = b.get(f"{self._key}_age_ms")
        return isinstance(age, (int, float)) and 0 <= age < SEEN_WITHIN_MS


class LocalFaultSensor(CoordinatorEntity, BinarySensorEntity):
    """On while the door has a latched fault (reason in the `reason` attribute). The door then
    holds itself open and refuses closes until the fault is cleared; if its open failed too, it may
    be stuck closed. Unknown when the door's state isn't fresh: never a silent "off"."""

    _attr_has_entity_name = True
    _attr_name = "Fault"
    _attr_device_class = BinarySensorDeviceClass.PROBLEM

    def __init__(self, coordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator)
        device_id = entry.data[CONF_DEVICE_ID]
        self._attr_unique_id = f"{device_id}_fault"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, device_id)},
            "name": entry.data[CONF_DEVICE_LABEL],
            "manufacturer": "Wayzn",
            "model": "Smart Pet Door",
        }

    def _brain(self) -> Optional[Dict[str, Any]]:
        if self.coordinator.stale:
            return None
        return (self.coordinator.data or {}).get("brain") or None

    @property
    def is_on(self) -> Optional[bool]:
        b = self._brain()
        return None if b is None else bool(b.get("fault"))

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        b = self._brain() or {}
        return {"reason": b.get("fault"), "door": b.get("detail")}

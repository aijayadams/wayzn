"""Binary sensor entities for Wayzn door settings (read-only)."""

from typing import Any, Dict, Optional

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_track_time_change

from .const import DOMAIN
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

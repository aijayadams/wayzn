"""Sensor entities for Wayzn door settings (read-only)."""

from typing import Any, Dict, Optional

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE, EntityCategory, UnitOfLength
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_track_time_change

from homeassistant.components.sensor import SensorStateClass
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import CONF_DEVICE_ID, CONF_DEVICE_LABEL, CONF_MODE, DOMAIN, MODE_LOCAL
from .entity import WayznSettingEntity
from .wayzn_client import wayzn_core as core


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up Wayzn settings sensors."""
    coordinator = hass.data[DOMAIN][entry.entry_id]
    if entry.data.get(CONF_MODE) == MODE_LOCAL:
        # Replaced: motor current in the controller's raw units, and travel in encoder counts.
        registry = er.async_get(hass)
        for old in ("motor_current", "last_move_peak_current", "travel_counts"):
            old_id = registry.async_get_entity_id("sensor", DOMAIN, f"{entry.data[CONF_DEVICE_ID]}_{old}")
            if old_id:
                registry.async_remove(old_id)
        async_add_entities([
            LocalBrainSensor(coordinator, entry, "last_move_effort", "Last move effort", "mdi:arm-flex",
                             unit=PERCENTAGE, attrs={"current": "effort_current", "limit": "effort_limit",
                                                     "peak_current": "last_move_peak_current"}),
            LocalBrainSensor(coordinator, entry, "travel_inches", "Travel", "mdi:ruler",
                             unit=UnitOfLength.INCHES, device_class=SensorDeviceClass.DISTANCE),
        ])
        return
    async_add_entities(
        [
            WayznDogSizeSensor(coordinator, entry),
            WayznSensitivitySensor(coordinator, entry),
            WayznOpenDistanceSensor(coordinator, entry),
            WayznHoldOpenSensor(coordinator, entry),
            WayznScheduleTodaySensor(coordinator, entry),
            WayznFirmwareSensor(coordinator, entry, "firmware_imp", "Firmware (Imp)"),
            WayznFirmwareSensor(coordinator, entry, "firmware_stm", "Firmware (motor controller)"),
            WayznFirmwareSensor(coordinator, entry, "firmware_pet_tag_receiver", "Firmware (pet tag receiver)"),
        ]
    )


class WayznDogSizeSensor(WayznSettingEntity, SensorEntity):
    _attr_name = "Dog size"
    _attr_icon = "mdi:dog"
    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = list(core.DOG_SIZE_BY_COUNT.values())

    def __init__(self, coordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "dog_size")

    @property
    def native_value(self) -> Optional[str]:
        return self.setting


class WayznSensitivitySensor(WayznSettingEntity, SensorEntity):
    _attr_name = "Motion sensitivity"
    _attr_icon = "mdi:motion-sensor"
    _attr_native_unit_of_measurement = PERCENTAGE

    def __init__(self, coordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "motion_sensitivity_pct")

    @property
    def native_value(self) -> Optional[int]:
        return self.setting

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        return {"detection_threshold": self.settings.get("grideye_detection_threshold")}


class WayznOpenDistanceSensor(WayznSettingEntity, SensorEntity):
    _attr_name = "Open distance"
    _attr_icon = "mdi:arrow-expand-horizontal"
    _attr_device_class = SensorDeviceClass.DISTANCE
    _attr_native_unit_of_measurement = UnitOfLength.INCHES

    def __init__(self, coordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "open_distance_in")

    @property
    def native_value(self) -> Optional[float]:
        return self.setting

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        return {
            "max_open_distance_in": self.settings.get("max_open_distance_in"),
            "open_to_counts": self.settings.get("open_to_counts"),
        }


class WayznHoldOpenSensor(WayznSettingEntity, SensorEntity):
    _attr_name = "Hold open time"
    _attr_icon = "mdi:timer-outline"

    def __init__(self, coordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "open_wait")

    @property
    def native_value(self) -> Optional[str]:
        return self.setting

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        return {"seconds": self.settings.get("open_wait_s")}


class WayznScheduleTodaySensor(WayznSettingEntity, SensorEntity):
    """Today's motion/auto-open windows; attributes carry the whole week."""

    _attr_name = "Schedule today"
    _attr_icon = "mdi:calendar-clock"

    def __init__(self, coordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "schedule")

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        # "Today" changes at midnight without any coordinator update.
        self.async_on_remove(
            async_track_time_change(self.hass, self._handle_tick, hour=0, minute=0, second=1)
        )

    @callback
    def _handle_tick(self, _now) -> None:
        self.async_write_ha_state()

    @property
    def native_value(self) -> Optional[str]:
        schedule = self.setting
        if not schedule:
            return None
        windows = core.schedule_today(schedule)["active_times"]
        return ", ".join(f"{w['start']}–{w['end']}" for w in windows) or "No windows"

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        schedule = self.setting
        if not schedule:
            return {}
        return {
            "enabled": schedule["enabled"],
            "timezone": schedule["timezone"],
            **{
                day["name"]: ", ".join(f"{w['start']}–{w['end']}" for w in day["active_times"]) or "No windows"
                for day in schedule["days"]
            },
        }


class WayznFirmwareSensor(WayznSettingEntity, SensorEntity):
    _attr_icon = "mdi:chip"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator, entry: ConfigEntry, key: str, name: str) -> None:
        super().__init__(coordinator, entry, key)
        self._attr_name = name

    @property
    def native_value(self) -> Optional[Any]:
        return self.setting


class LocalBrainSensor(CoordinatorEntity, SensorEntity):
    """A live reading from the door (local mode). Unknown when the door isn't fresh.

    Last move effort: the motor current as a % of the motor controller's own current limit at that
    moment (the limit follows the door's learned effort profile; over 100 % for ~350 ms is the
    controller's own obstruction reversal), the highest of the move. The current's scale in amps
    isn't known, so the raw values are attributes only."""

    _attr_has_entity_name = True
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator, entry: ConfigEntry, key: str, name: str, icon: str, unit=None,
                 device_class=None, attrs: Optional[Dict[str, str]] = None) -> None:
        super().__init__(coordinator)
        self._key = key
        self._attrs = attrs or {}
        device_id = entry.data[CONF_DEVICE_ID]
        self._attr_unique_id = f"{device_id}_{key}"
        self._attr_name = name
        self._attr_icon = icon
        self._attr_native_unit_of_measurement = unit
        self._attr_device_class = device_class
        self._attr_device_info = {
            "identifiers": {(DOMAIN, device_id)},
            "name": entry.data[CONF_DEVICE_LABEL],
            "manufacturer": "Wayzn",
            "model": "Smart Pet Door",
        }

    @property
    def _brain(self) -> Dict[str, Any]:
        return (self.coordinator.data or {}).get("brain") or {}

    @property
    def native_value(self) -> Optional[float]:
        if self.coordinator.stale:
            return None
        v = self._brain.get(self._key)
        return None if v is None or v < 0 else v

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        return {name: self._brain.get(key) for name, key in self._attrs.items()}

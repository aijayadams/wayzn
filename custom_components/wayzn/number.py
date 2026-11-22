"""Number entities: the door's tunable settings (local mode only)."""

from typing import Optional

from homeassistant.components.number import NumberEntity, NumberMode
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import CONF_MODE, DOMAIN, MODE_LOCAL
from .local_entity import LocalSettingEntity

# key, name, min, max, step, unit, mode, icon, unique-id suffix. Ranges mirror the door's own validation
# (wayzn-afterlife docs/API.md); the door rejects anything outside them.
LOCAL_NUMBERS = [
    ("hold_s", "Hold open time", 3, 600, 1, "s", NumberMode.BOX, "mdi:timer-outline", None),
    # Inches of door opening (the door converts at 767 encoder counts per inch). Keeps the
    # unique id of the earlier percent entity, so the entity id stays the same.
    ("open_inches", "Open position", 2.7, 16.8, 0.1, "in", NumberMode.SLIDER, "mdi:arrow-expand-horizontal",
     "open_percent"),
    ("presence_threshold", "Presence threshold", 0.3, 10, 0.1, None, NumberMode.BOX, "mdi:motion-sensor", None),
    ("occupied_threshold", "Occupied threshold", 0.2, 5, 0.05, None, NumberMode.BOX, "mdi:shield-alert-outline", None),
]


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    if entry.data.get(CONF_MODE) != MODE_LOCAL:
        return
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(LocalSettingNumber(coordinator, entry, *n) for n in LOCAL_NUMBERS)


class LocalSettingNumber(LocalSettingEntity, NumberEntity):
    """Open position is in inches of door opening; thresholds are the Grid-EYE
    detector's summed-excess scores (lower = more sensitive). Occupied (the safety level
    that blocks and reverses closing) must not exceed presence; the door enforces it."""

    def __init__(self, coordinator, entry, key, name, lo, hi, step, unit, mode, icon, uid) -> None:
        super().__init__(coordinator, entry, key, name, uid)
        self._attr_native_min_value = lo
        self._attr_native_max_value = hi
        self._attr_native_step = step
        self._attr_native_unit_of_measurement = unit
        self._attr_mode = mode
        self._attr_icon = icon

    @property
    def native_value(self) -> Optional[float]:
        return self.setting

    async def async_set_native_value(self, value: float) -> None:
        await self._set(int(value) if self._key == "hold_s" else round(float(value), 2))

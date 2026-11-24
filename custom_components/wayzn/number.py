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
    # The door's full travel in inches, as a check and a reference: a calibration that measures more
    # than 2 % off is rejected and retried, and it lets the door zero itself as closed when its motor
    # controller restarts at the closed end mid-calibration. 0 = none. Set it from a good calibration
    # ("Travel" sensor). Keeps the unique id of the earlier counts entity.
    ("expected_travel_inches", "Expected travel", 0, 52.1, 0.01, "in", NumberMode.BOX, "mdi:ruler",
     "expected_travel"),
    # When a power-up calibration ends by stalling at the closed end, the door is jammed into the frame
    # there; it is zeroed this far further closed, so later closes stop short of it instead of
    # overcurrent-reversing at the very end. 0.039 in (30 counts) verified on our door 2026-11-24.
    ("stall_allowance_inches", "Calibration stall allowance", 0, 0.26, 0.001, "in", NumberMode.BOX,
     "mdi:arrow-collapse-horizontal", None),
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
        if self._key == "hold_s":
            await self._set(int(value))
        else:
            await self._set(round(float(value), 3 if self._key == "stall_allowance_inches" else 2))

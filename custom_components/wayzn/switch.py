"""Switch entities for the Wayzn motion detection area (one per cell)."""

from typing import Any, Dict, Optional

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import WayznSettingEntity
from .wayzn_client import wayzn_core as core


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up one switch per detection cell."""
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        WayznDetectionCellSwitch(coordinator, entry, row, col)
        for row in range(1, core.MASK_ROWS + 1)
        for col in range(1, core.MASK_COLUMNS + 1)
    )


class WayznDetectionCellSwitch(WayznSettingEntity, SwitchEntity):
    """On = the cell is enabled for motion detection.

    Rows count from the top and columns from the door, as on the app's grid.
    Turning a cell on/off sends the app's updateMask command and waits for the
    door to report the change (up to 30s); if it doesn't, the action fails
    and a persistent notification explains why.
    """

    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator, entry: ConfigEntry, row: int, col: int) -> None:
        super().__init__(coordinator, entry, "detection_mask")
        self._cell = core.mask_cell_index(row, col)
        self._attr_unique_id = f"{self._attr_unique_id}_cell_{self._cell}"
        self._attr_name = f"Detection cell row {row} col {col}"

    @property
    def _value(self) -> Optional[int]:
        mask = self.setting
        return mask[self._cell] if mask and self._cell < len(mask) else None

    @property
    def is_on(self) -> Optional[bool]:
        value = self._value
        return bool(value & 1) if value is not None else None

    @property
    def icon(self) -> str:
        return "mdi:square" if self.is_on else "mdi:square-outline"

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        value = self._value
        return {"motion_now": bool(value & 2) if value is not None else None}

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self.coordinator.async_set_mask_cell(self._cell, True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.coordinator.async_set_mask_cell(self._cell, False)

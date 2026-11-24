"""Button entities (local mode): clear a latched fault, recalibrate, relearn the Grid-EYE background."""

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import CONF_DEVICE_ID, CONF_DEVICE_LABEL, CONF_MODE, DOMAIN, MODE_LOCAL


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    if entry.data.get(CONF_MODE) != MODE_LOCAL:
        return
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([
        LocalClearFaultButton(coordinator, entry),
        LocalMaintenanceButton(coordinator, entry, "calibrate", "Recalibrate", "mdi:ruler-square-compass"),
        LocalMaintenanceButton(coordinator, entry, "relearn", "Relearn doorway background", "mdi:thermometer-auto"),
    ])


class _LocalButton(CoordinatorEntity, ButtonEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator, entry: ConfigEntry, key: str) -> None:
        super().__init__(coordinator)
        device_id = entry.data[CONF_DEVICE_ID]
        self._attr_unique_id = f"{device_id}_{key}"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, device_id)},
            "name": entry.data[CONF_DEVICE_LABEL],
            "manufacturer": "Wayzn",
            "model": "Smart Pet Door",
        }


class LocalClearFaultButton(_LocalButton):
    """Clears the door's latched fault (it holds itself open until then). Check the door first."""

    _attr_name = "Clear fault"
    _attr_icon = "mdi:alert-remove-outline"

    def __init__(self, coordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "clear_fault")

    async def async_press(self) -> None:
        await self.coordinator.async_clear_fault()


class LocalMaintenanceButton(_LocalButton):
    """Recalibrate: the door runs auto_zero now (~90 s; it moves: refused unless the door is still,
    the doorway clear and no fault latched). Relearn: the Grid-EYE detectors take the next 2 s as the
    empty doorway (press only with the doorway clear)."""

    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator, entry: ConfigEntry, action: str, name: str, icon: str) -> None:
        super().__init__(coordinator, entry, action)
        self._action = action
        self._attr_name = name
        self._attr_icon = icon

    async def async_press(self) -> None:
        await self.coordinator.async_maintenance(self._action)

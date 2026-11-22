"""Button entities (local mode): clear a latched fault on the dog door."""

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import CONF_DEVICE_ID, CONF_DEVICE_LABEL, CONF_MODE, DOMAIN, MODE_LOCAL


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    if entry.data.get(CONF_MODE) != MODE_LOCAL:
        return
    async_add_entities([LocalClearFaultButton(hass.data[DOMAIN][entry.entry_id], entry)])


class LocalClearFaultButton(CoordinatorEntity, ButtonEntity):
    """Clears the door's latched fault (it holds itself open until then). Check the door first."""

    _attr_has_entity_name = True
    _attr_name = "Clear fault"
    _attr_icon = "mdi:alert-remove-outline"

    def __init__(self, coordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator)
        device_id = entry.data[CONF_DEVICE_ID]
        self._attr_unique_id = f"{device_id}_clear_fault"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, device_id)},
            "name": entry.data[CONF_DEVICE_LABEL],
            "manufacturer": "Wayzn",
            "model": "Smart Pet Door",
        }

    async def async_press(self) -> None:
        await self.coordinator.async_clear_fault()

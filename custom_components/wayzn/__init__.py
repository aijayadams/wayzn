"""Wayzn integration for Home Assistant."""

import logging

from .const import CONF_MODE, DOMAIN, LOCAL_PLATFORMS, MODE_LOCAL, PLATFORMS

_LOGGER = logging.getLogger(__name__)


def _platforms(entry):
    return LOCAL_PLATFORMS if entry.data.get(CONF_MODE) == MODE_LOCAL else PLATFORMS


async def async_setup_entry(hass, entry) -> bool:
    """Set up Wayzn from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    # Create coordinator: local (wayzn-brain on the door) or the original cloud client
    if entry.data.get(CONF_MODE) == MODE_LOCAL:
        from .local_coordinator import LocalBrainCoordinator

        coordinator = LocalBrainCoordinator(hass, entry)
    else:
        from .coordinator import WayznDataUpdateCoordinator

        coordinator = WayznDataUpdateCoordinator(hass, entry)

    # Perform first refresh (poll)
    try:
        await coordinator.async_config_entry_first_refresh()
    except Exception as e:
        from homeassistant.exceptions import ConfigEntryAuthFailed
        if isinstance(e, ConfigEntryAuthFailed):
            return False
        raise

    # Store coordinator in hass.data
    hass.data[DOMAIN][entry.entry_id] = coordinator

    # Start SSE streaming for real-time state updates
    await hass.async_add_executor_job(coordinator.start_streaming)

    # Forward setup to platforms
    await hass.config_entries.async_forward_entry_setups(entry, _platforms(entry))

    # Register update listener
    entry.async_on_unload(entry.add_update_listener(async_reload_entry))

    return True


async def async_unload_entry(hass, entry) -> bool:
    """Unload a config entry."""
    # Stop SSE streaming
    coordinator = hass.data[DOMAIN].get(entry.entry_id)
    if coordinator:
        await hass.async_add_executor_job(coordinator.stop_streaming)

    # Unload platforms
    unload_ok = await hass.config_entries.async_unload_platforms(entry, _platforms(entry))

    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok


async def async_reload_entry(hass, entry) -> None:
    """Reload config entry."""
    await async_unload_entry(hass, entry)
    await async_setup_entry(hass, entry)

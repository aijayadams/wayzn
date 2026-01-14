"""Constants for Wayzn integration."""

DOMAIN = "wayzn"

# Config entry keys
CONF_EMAIL = "email"
CONF_PASSWORD = "password"
CONF_API_KEY = "api_key"
CONF_QR_CODE = "qr_code"
CONF_DEVICE_ID = "device_id"
CONF_DEVICE_LABEL = "label"
CONF_WKEY = "wkey"
CONF_KNUM = "knum"
CONF_AGENTURL = "agenturl"

# Defaults
DEFAULT_POLL_INTERVAL = 30  # seconds
DEFAULT_TIMEOUT = 20  # seconds

# Platforms
PLATFORMS = ["cover"]

# Error messages
ERROR_AUTH_FAILED = "auth_failed"
ERROR_INVALID_QR = "invalid_qr"
ERROR_DEVICE_NOT_FOUND = "device_not_found"
ERROR_CANNOT_CONNECT = "cannot_connect"

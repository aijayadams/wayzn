# Wayzn Client 🚪🐕

A Python CLI and Home Assistant integration for controlling Wayzn smart petdoors via Firebase and Electric Imp.

## Overview

### Python CLI
- 🔐 Authenticate with Firebase
- 📱 Register devices from QR codes
- 🔍 Check device status
- 🔓 Open/close your petdoor remotely
- 🗓️ Read the door's schedule
- ⚙️ Change settings (dog size so far), verified by read-back
- 🔬 Debug Firebase RTDB directly

### Home Assistant Integration
- 🏠 Integrate Wayzn devices as cover entities in Home Assistant
- 🔐 Config flow for easy setup
- 📊 Real-time status updates
- 🎛️ Open/close controls from Home Assistant UI
- 🔌 Support for multiple devices

## Installation

### Python CLI

#### Requirements
- Python 3.7+
- Dependencies: `click`, `requests`

```bash
pip install -r requirements.txt
```

#### Optional Tools
- `zbarimg` - For scanning QR codes from images (Debian/Ubuntu: `apt install zbar-tools`)

### Home Assistant Integration

#### Installation

1. Copy the `custom_components/wayzn/` directory to your Home Assistant `config/custom_components/` directory
2. Restart Home Assistant
3. Go to Settings → Integrations → Add Integration
4. Search for "Wayzn"
5. Follow the config flow to add your device

#### Configuration
The integration uses a config flow UI - no manual config file needed!
You'll need:
- **Email**: Your Wayzn account email
- **Password**: Your Wayzn account password
- **Firebase API Key**: Get from Wayzn's Firebase console
- **QR Code**: Scan the QR code from your device (format: `QR-Code:base64key:knum:device_id:label`)

## Configuration

### Python CLI Setup

1. **Create config file:**
   ```bash
   cp wayzn_config.json.sample wayzn_config.json
   ```

2. **Edit `wayzn_config.json` with your details:**
   ```json
   {
     "firebase": {
       "email": "your-email@gmail.com",
       "password": "your-wayzn-password",
       "api_key": "AIza......"
     },
     "device_registry": {}
   }
   ```

   Where:
   - **email/password**: Wayzn account credentials
   - **api_key**: [Wayzn Firebase Project ID](https://firebase.google.com/docs/projects/api-keys), Wayzn ship this in `GoogleService-Info.plist`.
   - **device_registry**: Auto-populated when you import devices (see below)

## Quick Start

### Login
```bash
python wayzn.py login
```

Shows your Firebase auth token and user ID. The token is cached for future commands.

### Register a Device 📝

1. **Get the QR code from your device**

2. **Extract QR data from an image:**
   ```bash
   zbarimg your_qr_photo.png
   ```
   This outputs something like: `QR-Code:base64key:2:400000001234abcd:Dog Door`

3. **Import the device:**
   ```bash
   python wayzn.py import-qr --qr "QR-Code:base64key:2:400000001234abcd:Dog Door"
   ```

   This:
   - Parses the QR code
   - Authenticates with Firebase
   - Fetches the agent URL from the nonce database
   - Stores the device in your local registry

### List Devices 📋
```bash
python wayzn.py devices
```

Shows all registered devices with IDs and labels.

### Check Status 📊
```bash
python wayzn.py status
```

Shows current device status (open, closed, opening, closing).

Use `--verbose` for the full Firebase response:
```bash
python wayzn.py status --verbose
```

### Control Devices 🎛️

**Open the petdoor:**
```bash
python wayzn.py control open
```

**Close the petdoor:**
```bash
python wayzn.py control close
```

If you have multiple devices, specify one:
```bash
python wayzn.py control open --device-id 4000000012345abcd
```

### Read the Schedule 🗓️
```bash
python wayzn.py schedule          # human-readable
python wayzn.py schedule --json   # structured
```

Shows, per day (Sun–Sat), the windows during which the door operates via
motion detection and connected devices. Outside every window it does not
auto-open. Read-only. Format details: [docs/PROTOCOL.md](docs/PROTOCOL.md#schedule).

### Change Settings ⚙️
```bash
python wayzn.py settings dog-size small    # small | medium | large
```

Each setter sends a signed command to the door, then polls the device state
until the field reads back as written; it exits non-zero if it doesn't within
30s, and stops without retrying if the agent reports a bad key (a bad key can
cost one of the door's 20 key slots). Only allowlisted setters exist; see
[docs/PROTOCOL.md](docs/PROTOCOL.md#commands) for which commands are verified.

## Advanced Usage 🔧

### Debug Commands

Inspect Firebase RTDB directly:

```bash
# Shallow query (keys only)
python wayzn.py debug scan --login-local

# Get specific path
python wayzn.py debug get <token> app /devices

# Patch (update) data
python wayzn.py debug patch <token> app /path '{"key": "value"}'

# Capture all device-related data
python wayzn.py debug discover --login-local --outdir captures
```

### Force Re-authentication

Bypass cache and log in again:
```bash
python wayzn.py --force-login login
```

### Custom Config Path

Use a different config file:
```bash
python wayzn.py --config /path/to/custom_config.json devices
```

## Architecture 🏗️

- **custom_components/wayzn/**: The Home Assistant integration. Its
  `wayzn_client/` package is the shared library (`wayzn_core.py`) and CLI
  (`cli.py`), so the CLI and HA always run the same code.
- **wayzn.py**: Convenience entrypoint for the CLI
- **AGENTS.md**: Governing principles (state honesty, bias to open); read before changing the integration
- **docs/PROTOCOL.md**: What we know about the Wayzn cloud/device protocol
- **wayzn_config.json**: Static configuration (credentials, device registry)
- **.wayzn_auth_cache.json**: Auto-managed auth token cache (do not edit)

## How It Works

### Device Control Flow 🔄

1. **Parse QR Code** → Extract device ID, encryption key, etc.
2. **Authenticate** → Get Firebase ID token (cached for reuse)
3. **Fetch Agent URL** → Query nonce database for device's Electric Imp agent URL
4. **Resolve Context** → Load device properties and current nonce from Firebase
5. **Sign Command** → Compute HMAC-SHA256 signature of command with nonce
6. **Send Request** → POST to agent URL with signed headers
7. **Get Response** → Device executes command and returns status

### Deployment

Home Assistant on hass.in.waveb.io is deployed from this repo by the `hass`
role in waveb-priv (`./waveb ansible run --limit hass.in.waveb.io --tags hass-wayzn`).

### Authentication 🔐

- Uses Firebase Identity Toolkit (email/password)
- Tokens cached locally with expiry tracking
- Auto-refreshes when expired

## Troubleshooting

### "No ID token or credentials found"
- Check `wayzn_config.json` exists and has `firebase.email`/`firebase.password`
- Try `--force-login` to clear cache and re-authenticate

### "No Firebase API key found in config"
- Add `api_key` to the `firebase` section of `wayzn_config.json`
- Get it from Firebase Console → Project Settings → Web API Key

### "No agenturl found in nonce DB"
- Device may not be properly registered with Wayzn backend
- Try importing the QR code again

### "HTTP 401" on control commands
- Token may have expired or be invalid
- Try `--force-login` to refresh authentication

## Requirements

Create a `requirements.txt`:
```
click>=8.0.0
requests>=2.25.0
```

Or install directly:
```bash
pip install click requests
```

## Thank you

Built for smart home control for friends with paws. Use responsibly! 🏠

---

Made with ❤️ for petdoor enthusiasts 🐱🐶

# Wayzn protocol notes

What we know about how the Wayzn app talks to the door, and how sure we are.
Sources: static analysis of the Android app (Flutter; blutter decompile in the
`wayzn-reverse-engineering` repo, `apks/blutter_out/`), Frida captures from
January 2026, and live reads/writes from this client.

Status key: **verified** = exercised live by this client; **code** = seen in
the decompiled app but never sent by us; **inferred** = educated guess.

## Architecture

- The door's radio is an Electric Imp (imp004m). It only connects outbound;
  there is no local/LAN control path. Bluetooth is used only for pairing.
- Auth is Firebase email/password (Identity Toolkit REST).
- **Reads** come from Firebase Realtime Database `wayzn-app-tokens`, node
  `/<device_id>` (REST GET or SSE stream). The app itself reads via a rotating
  session token (`/<token>`, obtained with the `token:` command); the
  `/<device_id>` node carries the same state and is what we use. (verified)
- **Writes** never go through Firebase. Every action, including settings, is a
  signed POST to the device's Electric Imp agent URL (verified for `open`,
  `close`, `GrideyeCountThreshold:`):
  - body: the command string, e.g. `open` or `GrideyeCountThreshold:1`
  - `Authorization`: base64(HMAC-SHA256(wKey, "<command>,<nonce>"))
  - `x-WayznKNum`: key slot number
  - nonce and agent URL come from `wayzn-app-nonce` at `/<device_id>`
  - success reply: HTTP 200, empty body
  - failure path in the app: "Bad Key" / "KEY DELETED". The door has 20 key
    slots, so do not experiment with signing.

## Device state (`tokens:/<device_id>`)

| Field | Example | Meaning |
|---|---|---|
| `ControlState` | 14 | Door state; see `CONTROLSTATE_LABELS` in `wayzn_core.py` |
| `LastControlState` | 14 | Previous `ControlState` |
| `TimeStamp` | 1792514908 | Last device update (epoch s); used for staleness |
| `Position`, `TargetDestination` | -74, -50 | Motor position in counts |
| `OpenTo` | -6136 | Open distance in counts, negative; inches = -OpenTo / 767 (code) |
| `DoorOffset` | 13572 | Full travel in counts; max open inches = DoorOffset / 767 (code) |
| `OpenWait` | -1 | Hold-open seconds; -1 = remain open (inferred) |
| `AutoOpen`, `AutoOpenPetTag` | true, false | Home mode: open on motion / on pet tag |
| `AwayAutoOpen`, `AwayAutoOpenPetTag` | false, false | Same, for Away mode |
| `AwaySettings` | false | Away mode active (inferred polarity) |
| `AllowLocationAutomation` | false | Phone-location home/away switching |
| `GrideyeCountThreshold` | 1 | Dog size: 1 small, 2 medium, 4 large (code; write verified) |
| `GrideyeDetectionThreshold` | 1.085 | Motion sensitivity, 0–3.5, lower = more sensitive; app slider = 1 - t/3.5 (code) |
| `Mask` | 20 ints | Thermal-sensor detection area, 1 = cell enabled (layout inferred 4×5) |
| `ObstructionDetection` | true | Obstruction detection on/off |
| `ButtonOperation` | 1 | Physical button enabled |
| `InstallOrientation`, `Orientation` | 1, 3 | Mounting orientation |
| `LedBrightness` | 0.01 | LED brightness |
| `Schedule`, `ScheduleEnabled`, `ScheduleTickSec` | | See [Schedule](#schedule) |
| `TimeZone`, `Offset`, `ImpOffset` | "America/Los_Angeles", -25200 | Device time zone (IANA) and offsets in seconds |
| `IMP_V`, `STM_V`, `BUILD_V`, `STM_App_on_WSPD`, `Bridge_App_on_WSPD` | 171, 480 | Firmware versions (Imp, motor controller, pet-tag receiver) |
| `Bridge` | object | Pet-tag receiver: `Connected`, `Configured`, `ReceiverMode`, `ReceiverModeTimeout` |
| `X`, `Y`, `Z` | ≈0, 0, -1 | Accelerometer |
| `Zerod`, `StrokesLeft`, `SafeToClose`, `Current` | | Motor calibration/safety telemetry |
| `Connected`, `disconnectCount` | | Cloud connection |

The app shows no battery, Wi-Fi RSSI, temperature, cycle-count or event-history
data; none of it exists in the state either.

## Schedule

```json
"Schedule": {"schedule": [
  {"day": 0, "active_times": [{"start": 1635145200, "end": 1635165000}, ...]},
  ... one entry per day, 0 = Sunday ... 6 = Saturday
]}
```

- A window is when the door "operates via motion detection and connected
  devices" (app wording). (code)
- `start`/`end` are epoch seconds of a wall-clock time on the fixed anchor date
  2021-10-25 in the device `TimeZone`; only the time of day matters. Decode
  with `datetime.fromtimestamp(v, ZoneInfo(TimeZone))`, as the app does.
  Values have been seen as both ints and strings. (verified)
- Day 0 = Sunday comes from the app's day picker. (code)
- The app's editor applies one set of windows to every selected day (other days
  get `[]`), and cannot express windows that cross midnight. (code)
- No app command toggles `ScheduleEnabled`. (code)
- Write (code, not yet used): command `schedule_update`, with the compact JSON
  `{"schedule": [...]}` in an `x-wayznschedule` request header; the HMAC covers
  only `schedule_update,<nonce>`.

## Commands

| Command | Status | Notes |
|---|---|---|
| `open`, `close` | verified | |
| `GrideyeCountThreshold:<1\|2\|4>` | verified (same-value write) | Dog size; CLI `settings dog-size` |
| `GrideyeDetectionThreshold:<t>` | code | Sensitivity, 0–3.5 |
| `updateMask:<bit>:<n>` | code | Detection-area cell; second argument meaning unknown |
| `AutoOpen:`, `AutoOpenPetTag:`, `AwayAutoOpen:`, `AwayAutoOpenPetTag:` `<0\|1>` | code | Auto-open policy |
| `ObstructionDetection:<0\|1>` | code | |
| `set_open_to:<counts>` | code | Negative counts, -(inches × 767) |
| `set_open_wait:<s>` | code | 2, 4, 7, 15, 30, 60, 120, 300, 900, 1800, or -1 (remain open) |
| `set_button_op:<0\|1>` | code | Physical button |
| `install_orientation:<n>` | code | |
| `timezone:<name>`, `offset:<s>` | code | Sent by the app before saving a schedule |
| `schedule_update` + `x-wayznschedule` header | code | See [Schedule](#schedule) |
| `device_home`, `device_away`, `user_home`, `user_away`, `allow_location_automation:<0\|1>`, `set_location:` | code | Home/away |
| `token:<prev>` | code | Rotates the state-session token (`token:first` initially) |
| `poke_dog`, `ping` | code | Keep-alive / speeds up state streaming |
| `auto_zero` | code | Calibrate. Moves the door |
| Pet tags: `tag_mapping_save:`, `tag_name_update:`, `tag_remove:`, `tag_set_sensitivity:`, `loitering_enable:` | code | |
| `clear_device`, `bless`, `revoke:<n>`, `start_log`, `shake_clock` | code | Destructive or dev-only. **Do not send.** |

Adding a setter: confirm the exact string in the decompile first, add it to the
`settings` group in `cli.py` via `_set_and_verify`, test against the door, then
move its row here to **verified**.

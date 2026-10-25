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
| `TimeStamp` | 1792514908 | Refreshed about every 10s even when idle, apparently by the Imp **cloud agent**, not the door: it stayed fresh while the door was unplugged (2026-10-25). Used for staleness; see [Liveness](#liveness-and-the-2026-10-24-freeze) |
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
| `Mask` | 20 ints | Thermal-sensor detection area; see [Detection area](#detection-area) |
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

## Detection area

`Mask` is 20 cells of the thermal sensor, row-major, 4 columns × 5 rows, top
row first, as drawn on the app's Motion Detection screen with the door on the
left (`InstallOrientation` 1). Layout verified against the app on our door.

Each cell holds two bits (from the app's `buildPixelColor`, code):

| Value | Meaning | App colour |
|---|---|---|
| 0 | disabled | grey 200 `#EEEEEE` |
| 1 | enabled for detection | green 400 `#66BB6A` |
| 2 | disabled, motion detected now | grey 700 `#616161` |
| 3 | enabled, motion detected now | orange 400 `#FFA726` |

Bit 1 is transient. The door pushes it without any prompting: whenever the
sensor sees motion it sends `Mask` patches at `/` (several per second, each
with its own `TimeStamp`, sometimes out of order) over the normal SSE stream.
(verified 2026-10-21; the app's `poke_dog` every 20s on its motion screen was
not needed.)

The app's tap handler sends `updateMask:<current XOR 1>:<4*row + col>`, value
first, cell index second; the change reads back within ~5s. (verified)

## Commands

| Command | Status | Notes |
|---|---|---|
| `open`, `close` | verified | |
| `GrideyeCountThreshold:<1\|2\|4>` | verified (same-value write) | Dog size; CLI `settings dog-size` |
| `GrideyeDetectionThreshold:<t>` | code | Sensitivity, 0–3.5 |
| `updateMask:<value>:<cell>` | verified | Set one detection-area cell; send its current value XOR 1. CLI `settings detection-cell`, HA cell switches. See [Detection area](#detection-area) |
| `AutoOpen:`, `AutoOpenPetTag:`, `AwayAutoOpen:`, `AwayAutoOpenPetTag:` `<0\|1>` | code | Auto-open policy |
| `ObstructionDetection:<0\|1>` | code | |
| `set_open_to:<counts>` | code | Negative counts, -(inches × 767) |
| `set_open_wait:<s>` | code | 2, 4, 7, 15, 30, 60, 120, 300, 900, 1800, or -1 (remain open) |
| `set_button_op:<0\|1>` | code | Physical button |
| `install_orientation:<n>` | code | |
| `timezone:<name>`, `offset:<s>` | code | Sent by the app before saving a schedule |
| `schedule_update` + `x-wayznschedule` header | code | See [Schedule](#schedule) |
| `device_home`, `device_away`, `user_home`, `user_away`, `allow_location_automation:<0\|1>`, `set_location:` | code | Home/away |
| `token:<prev>` | code | Rotates the state-session token (`token:first` initially). The app's token renewer (`WayznDevice.start` → `_startTokenRenewer`, `Timer.periodic`) sends it on open and whenever `shouldRenewToken` is true, which includes its data being more than 180s old. Likely what woke the door after the 2026-10-24 power cycle; not yet tested |
| `poke_dog` | code | Sent on opening the app's Motion Detection screen and every 20s while it is open; presumably makes the door publish live motion bits |
| `ping` | code | Keep-alive |
| `auto_zero` | code | Calibrate. Moves the door |
| Pet tags: `tag_mapping_save:`, `tag_name_update:`, `tag_remove:`, `tag_set_sensitivity:`, `loitering_enable:` | code | |
| `clear_device`, `bless`, `revoke:<n>`, `start_log`, `shake_clock` | code | Destructive or dev-only. **Do not send.** |

Adding a setter: confirm the exact string in the decompile first, add it to the
`settings` group in `cli.py` via `_set_and_verify`, test against the door, then
move its row here to **verified**.

## Liveness and the 2026-10-24 freeze

**What happened (2026-10-24, PDT).**
- `TimeStamp` froze at 12:27:44, 35s after a close, during a run of
  oscillation alerts.
- From 12:32:54 to 15:41:04 the integration marked the door stale. Its own link
  was healthy throughout: polls every 10s, a live stream, and hourly token
  refreshes.
- Wayzn's app showed the door connected, and the Imp had an established TCP
  session to its cloud.
- Reporting resumed at 15:41 when the user **opened the Wayzn app**.
- The user had power-cycled the door around 12:27.
- In the 10 days of HA recorder history before this, `TimeStamp` age never
  exceeded 24s, apart from one 112s blip on 2026-10-20.

**Repro attempts (2026-10-25, app not opened). Neither froze.**
1. Power cycle; the new Imp TCP session to 52.10.174.82:31314 came up at about
   07:14:45. `TimeStamp` never went above 11s old.
2. Unplugged for about 3 minutes (roughly 07:35 to 07:39). The door has **no
   battery**.
   - `TimeStamp` stayed fresh (≤12s old) the whole time.
   - `ControlState` read 15 (open) from 07:35:44 to 07:39:33.
   - A new Imp TCP session came up at 07:39:29; reporting continued, and
     `ControlState` read 14 (closed) from 07:39:50.

**What this means.**
- An unpowered door can't write, so `TimeStamp` (and evidently `ControlState`)
  are refreshed by the Imp **cloud agent**, not the door.
- The 10-24 freeze was most likely an agent stall on Wayzn's side, not a door
  reboot.
- The app's launch-time `token:` command (below) plausibly un-stalls the agent.
  This is unproven.

**Manual workaround:** open the Wayzn app.

**Open question: telling when the door itself is offline.**
- A fresh `TimeStamp` proves the agent is alive, not the door. A powered-off
  door can look fresh while its `ControlState` is stale, which is an honesty
  risk: a stale "open" or "closed" shown as current.
- Possible device-sourced signals:
  - the door's Imp TCP session (pfSense states for its LAN address);
  - fields that only the device can change.
- Not implemented.

**The app-open command (decompile, not yet captured).**
- `WayznDevice.start` → `_startTokenRenewer` (a `Timer.periodic`) →
  `_tokenTimer` → `shouldRenewToken` → `renewDeviceToken`.
- `renewDeviceToken` sends `token:<previous session token>` through
  `sendCommand` (signed with the same HMAC as `open`/`close`).
- `shouldRenewToken` is true when, among other conditions, the app's token
  data is more than 180s old.
- The app also `print`s `Sending Command: <cmd>`, so `adb logcat` shows the
  exact string.
- The capture is ready to run whenever the exact format is wanted for an
  automatic nudge:
  - the scratch repo's `Pixel6` emulator has the official app (4.60.0), logged in;
  - launch it once with logcat running, then do one background/foreground
    cycle after 3+ minutes;
  - redact session tokens and nonces.
- Until a capture confirms the exact argument, this client does not send
  `token:`. A bad signature can delete a key slot.


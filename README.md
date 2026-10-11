# KEFAR 2.4 GHz Barcode Scanner — USB HID Reverse Engineering

Read-only reverse engineering of a KEFAR-branded 2.4 GHz wireless barcode scanner
and its USB receiver dongle, performed on Windows 10 (19045) with **no vendor
software, no kernel drivers, no USB capture hardware, no elevation and no reboot**.

Everything below was obtained exclusively through the stock Windows HID stack
(`hid.dll` via `ctypes`) and the open-source [hidapi](https://github.com/libusb/hidapi)
library.

---

## TL;DR — what this device is

| | Scanner (wired USB) | Receiver (2.4 GHz dongle) |
|---|---|---|
| USB VID:PID | `FFFF:0035` | `FFFF:0035` (same!) |
| bcdDevice | `0x0200` | `0x0200` |
| iProduct | `STM32 Custm HID` | `USB HID Keyboard` |
| iManufacturer | `STMicroelectronics` | `ARM CM0` |
| iSerial | `0123456789AB` (placeholder) | `0123456789AB` (placeholder) |
| Interfaces | `MI_00` boot keyboard + `MI_01` vendor `0xFFA0` | same |
| MCU | ST part (CubeMX template, see the `"Custm"` typo) | generic ARM Cortex-M0 |

Key facts:

- **Both units share the same VID/PID and the same placeholder serial.** Plug both
  in and Windows creates duplicate instance IDs → the well-known Event 56 noise.
  The fix is simply to keep the receiver in the same physical USB port.
- The "Bluetooth adapter" is **not Bluetooth** — it is a 2.4 GHz proprietary
  radio dongle.
- The two units run **different silicon** (ST vs Cortex-M0) yet expose
  **byte-identical HID descriptors** (see below).

## The vendor interface (`MI_01`)

A single Application collection on vendor page `0xFFA0`, usage `0x0001`, with
**three feature reports**, each 255 data bytes + 1 report-ID byte = 256:

```
06 A0 FF        Usage Page (0xFFA0, vendor-defined)
09 01           Usage (0x01)
A1 01           Collection (Application)
  85 01           Report ID (1)
  09 08           Usage (0x08)
  15 00           Logical Minimum (0)
  26 FF 00        Logical Maximum (255)
  75 08           Report Size (8)
  95 FF           Report Count (255)
  B1 02           Feature (Data, Variable, Absolute)
  85 02 09 08 15 00 26 FF 00 75 08 95 FF B1 02     <- Report ID (2), same layout
  85 03 09 08 15 00 26 FF 00 75 08 95 FF B1 02     <- Report ID (3), same layout
C0              End Collection
```

The skeleton is recognisably the **ST Custom-HID CubeMX template** with report
buffers grown to 256 bytes and a third report ID added.

### GET_REPORT behaviour — the key asymmetry

| Request | Receiver | Scanner |
|---|---|---|
| Feature report 1 / 2 / 3 | **OK** — identical 15-byte transfer every time | **STALL** (`ERROR_GEN_FAILURE`) |
| Feature report 0 / 4+ | `err=87`, rejected by the driver before any USB traffic | same |

The receiver's response (report-ID byte **always `0x03`** regardless of which
report was requested — a firmware quirk):

```
03 00 00 00 00 00 00 00 AA 00 02 01 8F 8C BB
└─ report ID (device-forced)  │  └─ 14-byte payload ─────────────┘
```

The payload is **static** (no counter, no timestamp) and only the first 15 bytes
of the 256-byte report are ever transferred. The meaning of
`00*7 AA 00 02 01 8F 8C BB` is unknown — possibly a pairing/device ID, possibly
a CRC. **Deliberately not probed further**: no `SET_REPORT` was ever sent, since
blind writes to a production scanner could wipe its symbology/suffix settings.

The scanner's STALL on GET_REPORT matches ST's USB Middleware changelog:
**v2.11.0 (Oct 2022): "USB CustomHID Class: Add support of Get Report control
request"** — this firmware appears to predate that fix.

## Why this matters beyond this device

### 1. The raw HID report descriptor is unobtainable from user mode… except it isn't

Three approaches were tested exhaustively on Windows 10 19045:

1. **`HidD_GetReportDescriptor` — does not exist.** Not in the export table of
   `hid.dll` (44 exports dumped and listed in [RESEARCH.md](RESEARCH.md) §4.1),
   not even as a string in the binary image.
2. **`IOCTL_HID_GET_REPORT_DESCRIPTOR` via `DeviceIoControl` — unreachable.**
   A full sweep of `DeviceType [0x00..0x7F] × Function [0..31] × Method [0..3] × Access [0..3]`
   = **4096/4096 `ERROR_INVALID_FUNCTION`**. Reason: `IOCTL_HID_*` are handled
   under `IRP_MJ_INTERNAL_DEVICE_CONTROL`; user-mode `DeviceIoControl` issues
   `IRP_MJ_DEVICE_CONTROL`. Dead end by design.
3. **✔ hidapi's reconstruction from preparsed data — works.** hidapi implements
   `hid_get_report_descriptor()` on Windows as
   `hid_winapi_descriptor_reconstruct_pp_data()`, rebuilding a valid descriptor
   byte stream from the opaque `PHIDP_PREPARSED_DATA` blob. No drivers, no
   elevation, no reboot. Caveat: it is a reconstruction, not the literal wire
   bytes — but it round-trips through the HID parser to identical caps.

If you need a Windows HID descriptor and cannot install USBPcap — this is the way.

### 2. An MSDN signature bug worth knowing

`HidP_GetValueCaps` / `HidP_GetButtonCaps` are documented as taking the
`HIDP_CAPS` structure returned by `HidP_GetCaps` as their last parameter.
**That always returns `HIDP_STATUS_INVALID_PREPARSED_DATA`.** The actual last
parameter must be the **preparsed-data handle** from `HidD_GetPreparsedData`.
Also, the capability records on this OS are **72 bytes**, not the 76 bytes the
textbook `HIDP_VALUE_CAPS` layout produces.

### 3. Strings invisible to the WinAPI

`HidD_GetProductString` / `HidD_GetManufacturerString` / `HidD_GetSerialNumberString`
return **empty strings** for this device, yet the descriptors above show real
values. The strings are recoverable via hidapi (which falls back to PnP device
properties). Don't trust empty `HidD_Get*String` results.

---

## Repository layout

```
README.md            this file
RESEARCH.md          the full technical report (negative results included)
tools/
  hid_caps.py        dump HIDP_CAPS + capability records via raw ctypes
  get_descriptor.py  reconstruct report descriptors via hidapi + decode them
  get_feature.py     GET_REPORT probe (report-ID existence, payload length,
                     static-vs-changing check) — strictly read-only
```

All tools are **read-only**: they never call `HidD_SetFeature`,
`HidD_SetOutputReport` or `hid_write`.

## Running the tools

Requires Python 3 on Windows (tested 3.12) and, for `get_descriptor.py`,
the hidapi wheel:

```bat
pip install --target <some-temp-dir> hidapi
set PYTHONPATH=<some-temp-dir>
python tools\get_descriptor.py
```

No administrator rights needed. Devices are opened with
`dwDesiredAccess = 0` — `GENERIC_READ|GENERIC_WRITE` is not required and can
actually make `HidD_GetPreparsedData` fail on the keyboard interfaces.

## Known unknowns (honest list)

| Item | Status |
|---|---|
| Meaning of the 14-byte receiver payload | unknown (speculation: pairing ID / CRC) |
| Which SET_REPORT commands the vendor interface accepts | deliberately not probed |
| Wireless protocol (scanner ↔ dongle, 2.4 GHz) | out of scope — needs an SDR |
| Firmware image | does not exist publicly; no DFU/bootloader, no VCP — SWD only |

## Credits & license

Research performed with read-only tooling on a live production device.
Methodology references: [hidapi](https://github.com/libusb/hidapi)
(descriptor reconstruction), ST USB Middleware changelog (GET_REPORT history).

Text and scripts: MIT. See [LICENSE](LICENSE).

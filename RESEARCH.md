# KEFAR 2.4 GHz USB HID Scanner — Protocol Reverse Engineering

**Target:** KEFAR-branded 2.4 GHz wireless barcode scanner + USB receiver (Windows host, no vendor software available)
**Method:** read-only probing of the Windows HID stack (`ctypes` → `hid.dll`, plus `hidapi` for descriptor reconstruction)
**Safety:** no writes (`HidD_SetFeature` / `SET_REPORT`) were issued at any point — the device is in production use.

---

## 1. Device identity and topology

Both units enumerate with the **same VID/PID** (`FFFF:0035`, `bcdDevice 0x0200`) and are a **composite HID device with two interfaces**:

| Interface | Usage Page / Usage | Reports | Report byte lengths |
|---|---|---|---|
| `MI_00` | `0x0001` Generic Desktop / `0x0006` Keyboard | Input, Output | in = 9*, out = 2*, feature = 0 |
| `MI_01` | `0xFFA0` (vendor) / `0x0001` | Feature only | in = 0, out = 0, **feature = 256** |

\* Windows always adds a report-ID byte (0x00) even when report IDs are unused; the descriptor itself declares 8-byte input / 1-byte output.

String descriptors (empty via `HidD_GetProductString` et al., but recoverable through hidapi / PnP properties):

| Unit | iProduct | iManufacturer | iSerial |
|---|---|---|---|
| Scanner (wired) | `STM32 Custm HID` | `STMicroelectronics` | `0123456789AB` (placeholder) |
| Receiver (2.4 GHz dongle) | `USB HID Keyboard` | `ARM CM0` | `0123456789AB` (placeholder) |

**Firmware version** (by scanning the "Get firmware version" configuration barcode from the manual, section 1.3):

```
MH32_WX_2.4GBT_V1.1b-240711
```

Read as: `MH32` (device family) · `WX` (wireless) · `2.4GBT` (2.4 GHz radio) · `V1.1b`, build `2024-07-11`. Notably this is a **2024 build that still STALLs GET_REPORT** — the vendor never adopted the ST USB Middleware v2.11.0 fix; the CubeMX-era CustomHID template was carried forward.

**Product manual** (KEFAR KR-H4 / KR-H4W User Guide, 68 pp.) documents the OEM scan engine inside: the **M22 2D imager module by Think-out**. The manual is a settings-barcode reference (symbologies, prefix/suffix, trigger modes, USB-HID / virtual-COM / TTL / HID-TTL / PS2 output modes) — it does **not** document the battery or the vendor `0xFFA0` interface, so the reverse-engineered findings below remain the only source on those.

**The two units are built on different MCUs**: the scanner on an ST part (the `"STM32 Custm HID"` typo suggests an unmodified CubeMX template), the receiver on a generic ARM Cortex-M0. Both share the placeholder serial `0123456789AB`, which is what produces the duplicate-instance-ID noise (Event 56) when both are connected.

- `MI_00` is a plain boot keyboard: scan data is injected as keystrokes.
- `MI_01` is the **vendor control channel** — a single Application collection, **1 link-collection node** (`LinkUsage=0x0001`, `LinkUsagePage=0xFFA0`).
- The "Bluetooth adapter" is in fact a **2.4 GHz USB receiver**, not a Bluetooth device (0 Bluetooth nodes on the host, `bthserv` stopped).

USB locations:
- Scanner ("STM32 Custm HID") — `Port_#0001.Hub_#0003`
- Receiver ("USB HID Keyboard") — `Port_#0002.Hub_#0003`

---

## 2. Raw HID report descriptors

Obtained **without any kernel driver or USB capture** — reconstructed from the HID class driver's preparsed data via hidapi's `hid_get_report_descriptor()` (see §4.1c). Byte-identical between the scanner and the receiver.

### `MI_01` vendor interface — 53 bytes

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

Three feature reports, each **255 data bytes + 1 report-ID byte = 256**. Every byte of each report is a single opaque `0x00..0xFF` value (usage `0x08` on page `0xFFA0`).

The layout is a recognisably **enlarged ST Custom-HID CubeMX template** (same page/usage skeleton, report buffers grown to 256 bytes, a third report ID added).

### `MI_00` keyboard interface — 66 bytes

The standard boot-keyboard descriptor: 8 modifier bits (`0xE0..0xE7`), 1 reserved byte, 6 keycodes (in = 8 bytes + forced report-ID byte = 9), 5 LED bits + 3 padding (out = 1 byte + forced report-ID byte = 2). Report ID `0x00` (numbered reports not used).

Cross-check against the capability data collected independently (`HidP_GetValueCaps`): 3 feature value caps, page `0xFFA0`, `BitSize=8`, `ReportCount=255`, logical range `0..255` — exact match.

---

## 3. GET_REPORT behaviour — the key asymmetry

Buffer pre-filled with `0x55`, 256 bytes, so untouched bytes are measurable.

### Receiver (2.4 GHz dongle) — implements GET_REPORT

Requests for **report IDs 1, 2 and 3 all succeed** and return an **identical 15-byte transfer**:

```
03 00 00 00 00 00 00 00 AA 00 02 01 8F 8C BB
```

- Only bytes `0..14` are modified; bytes `15..255` keep the `0x55` fill → the device performs a **short control read of 15 bytes** despite the declared 256-byte feature report.
- **Byte 0 (`0x03`) is written by the device, not by the host**: pre-setting `buffer[0] = 0x01 / 0x02 / 0x03 / 0x77 / 0x55` always yields `0x03` afterwards. Since byte 0 is the report-ID byte of the response, the firmware **always answers as report ID 3** no matter which report was requested — a firmware quirk, consistent with "firmware ignores the requested report ID".
- The actual payload is therefore 14 bytes: `00 00 00 00 00 00 00 AA 00 02 01 8F 8C BB`.
- The payload is **static**: 6 consecutive reads, 1 s apart, produced 1 distinct value. No counter, no timestamp.
- Requesting IDs `0x77` or `0x55` fails with `err=87` — the HID driver validates the report ID against the caps *before* issuing the control transfer.

### Scanner (wired) — does **not** implement GET_REPORT

- Report IDs 1, 2, 3 → **`err=31` (`ERROR_GEN_FAILURE`, i.e. USB STALL)**
- Report IDs 0, 4, 5 → `err=87` (invalid ID, as above)

So the scanner firmware accepts the vendor interface in its descriptor but does not answer `GET_REPORT`. The firmware build string `MH32_WX_2.4GBT_V1.1b-240711` (from the manual's version-query barcode) shows this behaviour survived into a **July 2024 build** — the vendor never picked up ST's USB Middleware **v2.11.0** (Oct 2022) changelog line *"USB CustomHID Class: Add support of Get Report control request"*. Note the product string typo `"STM32 Custm HID"`, consistent with an untouched CubeMX template.

---

## 4. Negative results (reproducible methodology)

### 4.1 Getting the raw report descriptor on Windows — what works and what doesn't

**(a) `HidD_GetReportDescriptor` — not exported.** PE export-table dump of `C:\WINDOWS\system32\hid.dll` (44 exports total):

```
HidD_* : FlushQueue, FreePreparsedData, GetAttributes, GetConfiguration, GetFeature,
         GetHidGuid, GetIndexedString, GetInputReport, GetManufacturerString,
         GetMsGenreDescriptor, GetNumInputBuffers, GetPhysicalDescriptor,
         GetPreparsedData, GetProductString, GetSerialNumberString, Hello,
         SetConfiguration, SetFeature, SetNumInputBuffers, SetOutputReport

HidP_* : GetButtonCaps, GetCaps, GetData, GetExtendedAttributes, GetLinkCollectionNodes,
         GetScaledUsageValue, GetSpecificButtonCaps, GetSpecificValueCaps, GetUsageValue,
         GetUsageValueArray, GetUsages, GetUsagesEx, GetValueCaps,
         InitializeReportForID, MaxDataListLength, MaxUsageListLength, SetData,
         SetScaledUsageValue, SetUsageValue, SetUsageValueArray, SetUsages,
         TranslateUsagesToI8042ScanCodes, UnsetUsages, UsageListDifference
```

`HidD_GetReportDescriptor`, `HidP_GetInputCaps`, `HidP_GetOutputCaps` and `HidP_GetFeatureCaps` are **absent both from the export table and from the binary image** (string search).

**(b) `IOCTL_HID_GET_REPORT_DESCRIPTOR` via `DeviceIoControl` — all variants rejected.** Sweep of `DeviceType ∈ [0x00,0x7F] × Function ∈ [0,31] × Method ∈ [0,3] × Access ∈ [0,3]` on the vendor interface: **4096/4096 returned `ERROR_INVALID_FUNCTION (1)`**. Restricted to `FILE_DEVICE_KEYBOARD (0x0B)` the same sweep produces only `ERROR_ACCESS_DENIED (5)` for `Access ≠ 0`, which is the ordinary handle access check and not an IOCTL result.

> Explanation: `IOCTL_HID_*` are handled under **`IRP_MJ_INTERNAL_DEVICE_CONTROL`**, whereas `DeviceIoControl()` from user mode issues `IRP_MJ_DEVICE_CONTROL`. Internal IOCTLs are unreachable from user mode by design.

**(c) ✔ Reconstruction from preparsed data — this is what works.** hidapi implements `hid_get_report_descriptor()` on Windows as `hid_winapi_descriptor_reconstruct_pp_data()`: it takes the opaque `PHIDP_PREPARSED_DATA` blob returned by `HidD_GetPreparsedData()` and **rebuilds a valid report descriptor byte stream from it**. No kernel driver, no USBPcap, no reboot, no elevation — and usable from Python via the `hidapi` package (`pip install --target <tmp> hidapi`, then `hid.device().open_path(path).get_report_descriptor()`).

Caveat: the result is a *reconstruction*, not the literal bytes off the wire. It is functionally equivalent (same usages, report sizes, counts, logical ranges) and round-trips through the HID parser to the same caps, but item ordering could in principle differ from the device's original descriptor. For this device the reconstruction passes every cross-check we have (§2).

Note that **USBPcap was deliberately not used**: installing it requires a reboot (the filter only attaches to the root hubs after restart) and there are documented cases of it breaking USB input devices — unacceptable on a machine where the scanner is in production use.

### 4.2 No firmware, no manual, no prior public work

Searches for the vendor, the models **KR-S8** and **H4W**, the typo string `"STM32 Custm HID"`, `VID_FFFF`/`PID_0035` and the placeholder serial `0123456789AB` returned **no firmware images, no update utility, no protocol documentation and no existing reverse-engineering work** on GitHub or elsewhere. The device has **no DFU/STM32 bootloader** (`VID_0483`/`PID_DF11` absent) and **no virtual COM port** — firmware cannot be flashed over USB; a physical SWD attach would be required.

---

## 5. A usable API quirk (worth documenting)

`HidP_GetValueCaps` / `HidP_GetButtonCaps` are the only capability APIs exported, and their documented signature is:

```c
NTSTATUS HidP_GetValueCaps(HIDP_REPORT_TYPE, PHIDP_VALUE_CAPS, PUSHORT, PHIDP_CAPS);
```

MSDN states the last argument is the **`HIDP_CAPS` returned by `HidP_GetCaps`**. Supplying that yields `HIDP_STATUS_INVALID_PREPARSED_DATA (0xC0110001)` for every report type. **The actual last parameter must be the preparsed-data handle** returned by `HidD_GetPreparsedData` — with that, `rt=2` (FEATURE) returns `HIDP_STATUS_SUCCESS` and the capability records correctly.

Also note: the `HidP_*` capability records on this OS are **72 bytes** (not the 76 produced by the textbook `HIDP_VALUE_CAPS` layout), which matters when decoding the array manually.

---

## 6. What is still unknown

| Item | Status |
|---|---|
| Meaning of the 14-byte GET_REPORT payload | **Unknown** — `00 00 00 00 00 00 00 AA 00 02 01 8F 8C BB` (plus the device-forced report-ID byte `0x03`). `AA 00 02 01 8F 8C BB` could be a pairing/device ID, `8F 8C` a CRC. Speculative only. |
| Which SET_REPORT commands the vendor interface accepts | **Deliberately not probed** — writes could alter symbology/suffix settings on a production scanner |
| Wireless link protocol (scanner ↔ receiver over 2.4 GHz) | Untouched — would require an SDR or a protocol trace |
| Scanner configuration / settings barcodes | Not enumerated (not touched, to avoid changing production behaviour) |

---

## 7. Reproduction notes

- Runs entirely from user mode; **no elevation required**.
- Open HID interface paths with `dwDesiredAccess = 0` (`GENERIC_READ|GENERIC_WRITE` is *not* required, and on the keyboard interfaces can even make `HidD_GetPreparsedData` fail).
- Interface path pattern: `\\?\HID#<VID&PID&MI>#<instance>#{4D1E55B2-F16F-11CF-88CB-001111000030}`
- Device discovery: `Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like 'HID\VID_FFFF&PID_0035*' }`
- Descriptor reconstruction: `pip install --target <tmpdir> hidapi`, then enumerate via `hid.enumerate(0xFFFF, 0x0035)` and call `get_report_descriptor()` on each open path. This also recovers the string descriptors that `HidD_Get*String` returns empty.

"""
GET_REPORT probe for the KEFAR vendor interface (usage page 0xFFA0).

Strictly read-only: only HidD_GetFeature is ever called. HidD_SetFeature /
HidD_SetOutputReport are never touched -- blind writes to a production
scanner could wipe its symbology/suffix configuration.

What it measures:
  1. which feature report IDs exist (valid IDs are answered or STALLed,
     invalid ones are rejected by the HID driver with err=87 before any
     USB traffic);
  2. the exact transfer length, using a 0x55 pre-fill so untouched bytes
     are distinguishable from real data;
  3. whether byte 0 of the response is written by the device (the KEFAR
     receiver always answers 0x03 there regardless of the requested ID);
  4. whether the payload changes over time (counter/timestamp check).

Usage:
    python get_feature.py [HID instance id ...]

Without arguments, all vendor (MI_01) interfaces of VID_FFFF&PID_0035 are
probed: the scanner (STALLs) and the receiver (answers).
"""

import ctypes
import subprocess
import sys
import time
from ctypes import wintypes

GENERIC_NONE = 0
FILE_SHARE_RW = 3
OPEN_EXISTING = 3
INVALID_HANDLE = ctypes.c_void_p(-1).value
REPORT_LEN = 256          # FeatureReportByteLength for this device
FILL = 0x55

hid = ctypes.WinDLL("hid.dll", use_last_error=True)
k32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                            wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                            wintypes.HANDLE]
k32.CreateFileW.restype = wintypes.HANDLE
k32.CloseHandle.argtypes = [wintypes.HANDLE]
hid.HidD_GetFeature.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.ULONG]
hid.HidD_GetFeature.restype = wintypes.BOOL


def interface_path(instance_id):
    parts = instance_id.split("\\")
    return "\\\\?\\HID#%s#%s#{4D1E55B2-F16F-11CF-88CB-001111000030}" % (parts[1], parts[2])


def discover():
    out = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like 'HID\\VID_FFFF&PID_0035*MI_01*' } "
         "| ForEach-Object { $_.InstanceId }"],
        capture_output=True, text=True)
    return [l.strip() for l in out.stdout.splitlines() if l.strip()]


def get_feature(handle, report_id):
    b = ctypes.create_string_buffer(REPORT_LEN)
    ctypes.memset(b, FILL, REPORT_LEN)
    b[0] = bytes([report_id])
    ok = hid.HidD_GetFeature(handle, b, REPORT_LEN)
    if not ok:
        return None, ctypes.get_last_error()
    d = b.raw
    last = -1
    for i in range(1, REPORT_LEN):
        if d[i] != FILL:
            last = i
    return d[:last + 1], 0


def main():
    ids = sys.argv[1:] or discover()
    if not ids:
        print("no matching vendor interfaces found")
        return 1

    for iid in ids:
        print("\n### %s" % iid)
        h = k32.CreateFileW(interface_path(iid), GENERIC_NONE, FILE_SHARE_RW,
                            None, OPEN_EXISTING, 0, None)
        if h in (INVALID_HANDLE, None, 0):
            print("  open failed err=%d" % ctypes.get_last_error())
            continue

        print("  -- report-ID existence (err=87 => rejected by driver, no USB traffic) --")
        answered = []
        for rid in range(0, 8):
            data, err = get_feature(h, rid)
            if data is not None:
                answered.append(rid)
                print("    ID=%d OK   %d bytes  %s"
                      % (rid, len(data), " ".join("%02X" % b for b in data[:16])))
            else:
                print("    ID=%d FAIL err=%d" % (rid, err))

        if not answered:
            print("  device does not implement GET_REPORT (all valid IDs STALL)")
            k32.CloseHandle(h)
            continue

        print("  -- byte 0 ownership (pre-set to different values) --")
        for pre in (0x01, 0x02, 0x03, 0x77):
            b = ctypes.create_string_buffer(REPORT_LEN)
            ctypes.memset(b, FILL, REPORT_LEN)
            b[0] = bytes([pre])
            ok = hid.HidD_GetFeature(h, b, REPORT_LEN)
            if ok:
                print("    requested=0x%02X -> byte0=0x%02X%s"
                      % (pre, b.raw[0],
                         "   (device-forced)" if b.raw[0] != pre else ""))
            else:
                print("    requested=0x%02X -> FAIL err=%d" % (pre, ctypes.get_last_error()))

        print("  -- static vs changing payload (5 reads, 1 s apart) --")
        seen = set()
        for _ in range(5):
            data, _ = get_feature(h, 1)
            if data:
                seen.add(data)
            time.sleep(1.0)
        print("    distinct payloads: %d%s"
              % (len(seen), "  (static)" if len(seen) == 1 else "  (VARIES)"))

        k32.CloseHandle(h)
    return 0


if __name__ == "__main__":
    sys.exit(main())

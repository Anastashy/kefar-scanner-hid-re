"""
Dump HIDP_CAPS and the capability records of a HID device via raw ctypes.

Strictly read-only. No writes of any kind are issued.

Usage:
    python hid_caps.py [HID instance id ...]

Without arguments, all HID interfaces of VID_FFFF&PID_0035 are enumerated
through Get-PnpDevice (PowerShell is used only for discovery; all HID access
is native).

Notes discovered the hard way (see RESEARCH.md section 5):
  * HidP_GetValueCaps / HidP_GetButtonCaps take the PREPARSED DATA HANDLE as
    their last argument, NOT the HIDP_CAPS structure as MSDN documents.
  * The capability record size on Windows 10 19045 is 72 bytes, not 76.
  * HidP_GetInputCaps / HidP_GetOutputCaps / HidP_GetFeatureCaps are NOT
    exported by hid.dll; only the ReportType-parameterised old API exists.
"""

import ctypes
import subprocess
import sys
from ctypes import wintypes

GENERIC_NONE = 0
FILE_SHARE_RW = 3
OPEN_EXISTING = 3
INVALID_HANDLE = ctypes.c_void_p(-1).value

HIDP_INPUT_REPORT = 0
HIDP_OUTPUT_REPORT = 1
HIDP_FEATURE_REPORT = 2
HIDP_STATUS_SUCCESS = 0x00110000

# Empirical capability-record layout (72 bytes) on Windows 10 19045.
# Offsets differ from the textbook HIDP_VALUE_CAPS: there is no HasNull/Reserved
# pair before BitSize, so BitSize sits at 18, not 20.
REC_SIZE = 72
OFF_USAGE_PAGE = 0
OFF_USAGE = 2
OFF_REPORT_ID = 4
OFF_LINK_COLLECTION = 8
OFF_IS_RANGE = 14
OFF_IS_ABSOLUTE = 17
OFF_BIT_SIZE = 18
OFF_REPORT_COUNT = 20
OFF_LOGICAL_MIN = 40
OFF_LOGICAL_MAX = 44
OFF_PHYSICAL_MIN = 48
OFF_PHYSICAL_MAX = 52
OFF_USAGE_MIN = 56
OFF_USAGE_MAX = 58
OFF_DATA_INDEX_MIN = 68
OFF_DATA_INDEX_MAX = 70


class HIDP_CAPS(ctypes.Structure):
    _fields_ = [
        ("Usage", ctypes.c_uint16), ("UsagePage", ctypes.c_uint16),
        ("InputReportByteLength", ctypes.c_uint16),
        ("OutputReportByteLength", ctypes.c_uint16),
        ("FeatureReportByteLength", ctypes.c_uint16),
        ("Reserved", ctypes.c_uint16 * 17),
        ("NumberLinkCollectionNodes", ctypes.c_uint16),
        ("NumberInputButtonCaps", ctypes.c_uint16),
        ("NumberInputValueCaps", ctypes.c_uint16),
        ("NumberInputDataIndices", ctypes.c_uint16),
        ("NumberOutputButtonCaps", ctypes.c_uint16),
        ("NumberOutputValueCaps", ctypes.c_uint16),
        ("NumberOutputDataIndices", ctypes.c_uint16),
        ("NumberFeatureButtonCaps", ctypes.c_uint16),
        ("NumberFeatureValueCaps", ctypes.c_uint16),
        ("NumberFeatureDataIndices", ctypes.c_uint16),
    ]


hid = ctypes.WinDLL("hid.dll", use_last_error=True)
k32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                            wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                            wintypes.HANDLE]
k32.CreateFileW.restype = wintypes.HANDLE
k32.CloseHandle.argtypes = [wintypes.HANDLE]

hid.HidD_GetPreparsedData.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_void_p)]
hid.HidD_GetPreparsedData.restype = wintypes.BOOL
hid.HidD_FreePreparsedData.argtypes = [ctypes.c_void_p]
hid.HidD_FreePreparsedData.restype = wintypes.BOOL
hid.HidP_GetCaps.argtypes = [ctypes.c_void_p, ctypes.POINTER(HIDP_CAPS)]
hid.HidP_GetCaps.restype = ctypes.c_long

# The REAL exported API: ReportType comes FIRST, the PREPARSED HANDLE comes LAST.
hid.HidP_GetValueCaps.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                  ctypes.POINTER(ctypes.c_uint16), ctypes.c_void_p]
hid.HidP_GetValueCaps.restype = ctypes.c_long
hid.HidP_GetButtonCaps.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                   ctypes.POINTER(ctypes.c_uint16), ctypes.c_void_p]
hid.HidP_GetButtonCaps.restype = ctypes.c_long

STATUS = {0x00110000: "SUCCESS", 0xC0110001: "INVALID_PREPARSED_DATA",
          0xC0110002: "INVALID_REPORT_TYPE", 0xC0110003: "INVALID_REPORT_LENGTH",
          0xC0110004: "USAGE_NOT_FOUND", 0xC0110005: "VALUE_OUT_OF_RANGE",
          0xC0110007: "BUFFER_TOO_SMALL", 0xC0110010: "REPORT_DOES_NOT_EXIST"}


def status_name(v):
    return STATUS.get(v & 0xFFFFFFFF, "0x%08X" % (v & 0xFFFFFFFF))


def u16(buf, off):
    return buf[off] | (buf[off + 1] << 8)


def i32(buf, off):
    return int.from_bytes(buf[off:off + 4], "little", signed=True)


def dump_caps(prep, label, report_type, count, getter):
    if count == 0:
        print("      %-7s none" % label)
        return
    buf = ctypes.create_string_buffer(count * REC_SIZE)
    n = ctypes.c_uint16(count)
    st = getter(report_type, buf, ctypes.byref(n), prep)
    print("      %-7s %s, %d records" % (label, status_name(st), n.value))
    for i in range(n.value):
        o = i * REC_SIZE
        page = u16(buf.raw, o + OFF_USAGE_PAGE)
        if page == 0:
            continue
        is_range = buf.raw[o + OFF_IS_RANGE]
        usage = ("0x%04X..0x%04X" % (u16(buf.raw, o + OFF_USAGE_MIN),
                                     u16(buf.raw, o + OFF_USAGE_MAX))
                 if is_range else "0x%04X" % u16(buf.raw, o + OFF_USAGE_MIN))
        print("        #%d ReportID=%d page=0x%04X %s bits=%d count=%d "
              "logical=[%d..%d] abs=%d linkColl=%d dataIndex=%d"
              % (i, buf.raw[o + OFF_REPORT_ID], page, usage,
                 u16(buf.raw, o + OFF_BIT_SIZE), u16(buf.raw, o + OFF_REPORT_COUNT),
                 i32(buf.raw, o + OFF_LOGICAL_MIN), i32(buf.raw, o + OFF_LOGICAL_MAX),
                 buf.raw[o + OFF_IS_ABSOLUTE], u16(buf.raw, o + OFF_LINK_COLLECTION),
                 u16(buf.raw, o + OFF_DATA_INDEX_MIN)))


def interface_path(instance_id):
    parts = instance_id.split("\\")
    return "\\\\?\\HID#%s#%s#{4D1E55B2-F16F-11CF-88CB-001111000030}" % (parts[1], parts[2])


def discover():
    out = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like 'HID\\VID_FFFF&PID_0035*' } "
         "| ForEach-Object { $_.InstanceId }"],
        capture_output=True, text=True)
    return [l.strip() for l in out.stdout.splitlines() if l.strip()]


def main():
    ids = sys.argv[1:] or discover()
    if not ids:
        print("no matching HID interfaces found")
        return 1

    for iid in ids:
        print("\n### %s" % iid)
        h = k32.CreateFileW(interface_path(iid), GENERIC_NONE, FILE_SHARE_RW,
                            None, OPEN_EXISTING, 0, None)
        if h in (INVALID_HANDLE, None, 0):
            print("  open failed err=%d" % ctypes.get_last_error())
            continue

        prep = ctypes.c_void_p()
        if not hid.HidD_GetPreparsedData(h, ctypes.byref(prep)):
            print("  HidD_GetPreparsedData failed err=%d" % ctypes.get_last_error())
            k32.CloseHandle(h)
            continue

        caps = HIDP_CAPS()
        st = hid.HidP_GetCaps(prep, ctypes.byref(caps))
        print("  HidP_GetCaps: %s" % status_name(st))
        print("  collection: page=0x%04X usage=0x%04X" % (caps.UsagePage, caps.Usage))
        print("  report lengths: in=%d out=%d feature=%d"
              % (caps.InputReportByteLength, caps.OutputReportByteLength,
                 caps.FeatureReportByteLength))

        dump_caps(prep, "input", HIDP_INPUT_REPORT, caps.NumberInputValueCaps,
                  hid.HidP_GetValueCaps)
        dump_caps(prep, "output", HIDP_OUTPUT_REPORT, caps.NumberOutputValueCaps,
                  hid.HidP_GetValueCaps)
        dump_caps(prep, "feature", HIDP_FEATURE_REPORT, caps.NumberFeatureValueCaps,
                  hid.HidP_GetValueCaps)
        dump_caps(prep, "btn-in", HIDP_INPUT_REPORT, caps.NumberInputButtonCaps,
                  hid.HidP_GetButtonCaps)

        hid.HidD_FreePreparsedData(prep)
        k32.CloseHandle(h)
    return 0


if __name__ == "__main__":
    sys.exit(main())

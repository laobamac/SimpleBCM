#!/usr/bin/env python3
#
#  collect.py
#  SimpleBCM
#
#  Created by laobamac on 2026/9/11.
#  Copyright © 2026 laobamac. All rights reserved.
#

import argparse
import json
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path


IDENTIFIERS = ["cn.laobamac.SimpleBCM", "as.vit9696.Lilu", "as.lvs1974.AirportBrcmFixup",
               "com.apple.iokit.IO80211Family", "com.apple.iokit.IOSkywalkFamily", "com.apple.iokit.IO80211FamilyLegacy", "com.apple.driver.AirPort.BrcmNIC"]


def capture(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        return {"command": command, "exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"command": command, "error": str(error)}


def corecaptures(output):
    root = Path("/Library/Logs/CrashReporter/CoreCapture")
    result = []
    total = 0
    try:
        captures = sorted(root.glob("*AXIWrapRdFail*"), reverse=True)[:3]
        for folder in captures:
            files = list(folder.glob("Data/*/DriverLogs/*.gz"))
            files += list(folder.glob("Data/*/StateSnapshots/IDX*.bin"))
            files += list(folder.glob("Metadata/*.plist"))
            for source in sorted(files):
                if source.is_symlink() or not source.is_file():
                    continue
                size = source.stat().st_size
                if size > 8 * 1024 * 1024 or total + size > 32 * 1024 * 1024:
                    result.append({"source": str(source), "error": "capture size limit"})
                    continue
                destination = output / "CoreCapture" / folder.name / source.relative_to(folder)
                destination.parent.mkdir(parents=True, exist_ok=True)
                try:
                    shutil.copy2(source, destination)
                    total += size
                    result.append({"source": str(source), "file": str(destination.relative_to(output)), "bytes": size})
                except OSError as error:
                    result.append({"source": str(source), "error": str(error)})
    except OSError as error:
        result.append({"source": str(root), "error": str(error)})
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path.cwd() / ("SimpleBCM-diagnostics-" + datetime.now().strftime("%Y%m%d-%H%M%S")))
    parser.add_argument("--interface", action="append", help="Wireless BSD interface; defaults to bcmprobe discovery")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    commands = [
        ["sw_vers"],
        ["sysctl", "-n", "kern.osversion", "kern.osrelease", "kern.boottime"],
        ["ioreg", "-r", "-c", "SimpleBCM", "-l"],
        ["ioreg", "-r", "-c", "AirPort_BrcmNIC", "-l", "-d", "2"],
        ["ioreg", "-r", "-c", "IO80211APIUserClient", "-l"],
        ["ioreg", "-r", "-c", "BCMLegacyInterface", "-l"],
        ["ioreg", "-r", "-c", "BCMNativeInterface", "-l"],
        ["ioreg", "-p", "IOPower", "-r", "-c", "AirPort_BrcmNIC", "-l"],
        ["ioreg", "-p", "IOPower", "-r", "-c", "IOSkywalkNetworkBSDClient", "-l"],
        ["ioreg", "-r", "-c", "IO80211AsyncEventUserClient", "-l"],
        ["networksetup", "-listallhardwareports"],
        ["networksetup", "-listnetworkserviceorder"],
        ["scutil", "--nwi"],
        ["scutil", "--dns"],
        ["scutil", "--proxy"],
        ["route", "-n", "get", "default"],
        ["ifconfig", "-a"],
        ["ifconfig", "awdl0"],
        ["netstat", "-I", "awdl0", "-b", "-n"],
        ["/usr/bin/log", "show", "--last", "5m", "--style", "compact", "--info", "--debug", "--predicate", '(process == "airportd" OR process == "wifip2pd" AND (subsystem == "com.apple.awdl" OR eventMessage CONTAINS "IOCTL" OR eventMessage CONTAINS "parse event")) OR (process == "sharingd" AND category CONTAINS "AirDrop") OR (process == "mDNSResponder" AND (eventMessage CONTAINS "awdl0" OR eventMessage CONTAINS "airdrop"))'],
        ["/usr/bin/log", "show", "--last", "boot", "--style", "compact", "--info", "--debug", "--predicate", 'process == "kernel" AND (eventMessage CONTAINS "SimpleBCM" OR eventMessage CONTAINS "IO80211APIUserClient" OR eventMessage CONTAINS "IOSkywalkFamily" OR eventMessage CONTAINS "IO80211FamilyLegacy" OR eventMessage CONTAINS "AirPort.BrcmNIC")'],
    ]
    loaded = ["kmutil", "showloaded", "--list-only"]
    for identifier in IDENTIFIERS:
        loaded += ["--optional-identifier", identifier]
    commands.append(loaded)
    folder = Path(__file__).resolve().parent
    candidates = [folder / "bcmprobe", folder.parent / "bcmprobe"]
    candidates += [folder.parent / "build/DerivedData/Build/Products" / configuration / "bcmprobe"
                   for configuration in ("Release", "Debug")]
    probe = next((path for path in candidates if path.is_file()), None)
    results = []
    interfaces = args.interface or []
    if probe is not None:
        result = capture([str(probe)])
        results.append(result)
        if not args.interface and result.get("exit") == 0:
            try:
                interfaces = [item["name"] for item in json.loads(result["stdout"])["interfaces"]]
            except (ValueError, KeyError, TypeError):
                pass
    interfaces = {name for name in interfaces if isinstance(name, str) and re.fullmatch(r"en\d+", name)}
    for name in sorted(interfaces):
        commands += [["ipconfig", "getpacket", name], ["netstat", "-I", name, "-b", "-n"]]
    results.extend(capture(command) for command in commands)
    report = {"copyright": "Copyright © 2026 laobamac. All rights reserved.", "results": results,
              "corecaptures": corecaptures(args.output)}
    (args.output / "diagnostics.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(args.output.resolve())


if __name__ == "__main__":
    main()

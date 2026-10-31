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
import subprocess
from datetime import datetime
from pathlib import Path


IDENTIFIERS = ["cn.laobamac.SimpleBCM", "as.vit9696.Lilu", "as.lvs1974.AirportBrcmFixup",
               "com.apple.iokit.IOSkywalkFamily", "com.apple.iokit.IO80211FamilyLegacy", "com.apple.driver.AirPort.BrcmNIC"]


def capture(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        return {"command": command, "exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"command": command, "error": str(error)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path.cwd() / ("SimpleBCM-diagnostics-" + datetime.now().strftime("%Y%m%d-%H%M%S")))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    commands = [
        ["sw_vers"],
        ["sysctl", "-n", "kern.osversion", "kern.osrelease"],
        ["ioreg", "-r", "-c", "SimpleBCM", "-l"],
        ["ioreg", "-r", "-c", "IO80211APIUserClient", "-l"],
        ["ifconfig", "awdl0"],
        ["netstat", "-I", "awdl0", "-b", "-n"],
        ["/usr/bin/log", "show", "--last", "5m", "--style", "compact", "--info", "--debug", "--predicate", '(process == "wifip2pd" AND (subsystem == "com.apple.awdl" OR eventMessage CONTAINS "IOCTL" OR eventMessage CONTAINS "parse event")) OR (process == "sharingd" AND category CONTAINS "AirDrop") OR (process == "mDNSResponder" AND (eventMessage CONTAINS "awdl0" OR eventMessage CONTAINS "airdrop"))'],
        ["/usr/bin/log", "show", "--last", "boot", "--style", "compact", "--info", "--debug", "--predicate", 'process == "kernel" AND (eventMessage CONTAINS "SimpleBCM" OR eventMessage CONTAINS "IO80211APIUserClient" OR eventMessage CONTAINS "IOSkywalkFamily" OR eventMessage CONTAINS "IO80211FamilyLegacy" OR eventMessage CONTAINS "AirPort.BrcmNIC")'],
    ]
    loaded = ["kmutil", "showloaded", "--list-only"]
    for identifier in IDENTIFIERS:
        loaded += ["--optional-identifier", identifier]
    commands.append(loaded)
    folder = Path(__file__).resolve().parent
    candidates = [folder / "bcmprobe", folder.parent / "bcmprobe"]
    candidates += [folder.parent / "build" / tree / "Build/Products" / configuration / "bcmprobe"
                   for tree in ("Standalone", "DerivedData") for configuration in ("Release", "Debug")]
    probe = next((path for path in candidates if path.is_file()), None)
    if probe is not None:
        commands.append([str(probe)])
    results = [capture(command) for command in commands]
    report = {"copyright": "Copyright © 2026 laobamac. All rights reserved.", "results": results}
    (args.output / "diagnostics.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(args.output.resolve())


if __name__ == "__main__":
    main()

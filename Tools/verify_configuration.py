#!/usr/bin/env python3
#
#  verify_configuration.py
#  SimpleBCM
#
#  Created by laobamac on 2026/9/8.
#  Copyright © 2026 laobamac. All rights reserved.
#

import copy
import hashlib
import json
import plistlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from configure import AIRPORT_ORIGINAL, AIRPORT_TAHOE, APPLE_NVRAM, FIXUP, INJECTOR, SYSTEMS, drivers, fragment, merge
from preflight import check_configuration, enabled


def verify():
    checks = 0
    with tempfile.TemporaryDirectory(prefix="SimpleBCM-Config-") as temporary:
        oc = Path(temporary)
        for bundle, identifier, executable, _ in drivers(True):
            folder = oc / "Kexts" / bundle / "Contents"
            folder.mkdir(parents=True, exist_ok=True)
            if executable:
                (folder / "MacOS").mkdir(exist_ok=True)
                (folder / "MacOS" / executable).write_bytes(b"configuration fixture")
            (folder / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": identifier,
                "CFBundleVersion": "1.7.1" if bundle == "Lilu.kext" else "1.0.0"}))

        def issues(config, running=(25, 6, 0), manifest=None):
            (oc / "config.plist").write_bytes(plistlib.dumps(config))
            return check_configuration(oc, running, manifest)[0]

        def active(config, running):
            return [entry["BundlePath"] for entry in config["Kernel"]["Add"] if enabled(entry, running)]

        versions = [(major, minor, patch) for major in SYSTEMS.values() for minor, patch in [(0, 0), (1, 0), (6, 0), (99, 99)]]
        for optional in [False, True]:
            config = fragment(optional)
            assert "NVRAM" not in config
            for running in versions:
                assert active(config, running) == [entry[0] for entry in drivers(optional, running[0])]
                assert not issues(config, running), issues(config, running)
                checks += 1
            for running in [(22, 99, 99), (26, 0, 0)]:
                assert not active(config, running)
                assert issues(config, running)
                checks += 1

        old_fragment = fragment()
        for entry in old_fragment["Kernel"]["Add"]:
            entry.update(MinKernel="25.6.0", MaxKernel="25.6.0")
        upgraded = merge(old_fragment)
        for running in versions:
            assert not issues(upgraded, running), issues(upgraded, running)
            checks += 1

        original = fragment()
        original["Kernel"]["Add"] = original["Kernel"]["Add"][:2]
        original["Misc"] = {"Boot": {"PickerMode": "External"}}
        original["NVRAM"] = {"Add": {APPLE_NVRAM: {"boot-args": b"-v keepsyms=0 alcid=1\0"}}}
        before = copy.deepcopy(original)
        migrated = merge(original, True)
        assert original == before
        assert migrated["Misc"] == original["Misc"] and migrated["NVRAM"] == original["NVRAM"]
        assert merge(migrated) == migrated
        for running in versions:
            assert not issues(migrated, running), issues(migrated, running)
            checks += 1

        original = fragment(True)
        for entry in original["Kernel"]["Add"][2:]:
            entry.update(MinKernel="", MaxKernel="")
        original["Kernel"]["Add"].append(copy.deepcopy(original["Kernel"]["Add"][3]))
        migrated = merge(original)
        for running in versions:
            assert not issues(migrated, running), issues(migrated, running)
            assert active(migrated, running) == [entry[0] for entry in drivers(True, running[0])]
            checks += 1
        assert merge(migrated) == migrated
        assert AIRPORT_ORIGINAL[0] in active(migrated, (22, 6, 0))
        assert AIRPORT_TAHOE[0] in active(migrated, (26, 0, 0))
        checks += 1

        legacy_only = fragment()
        legacy_only["Kernel"]["Add"].append(dict(fragment(True)["Kernel"]["Add"][2], MinKernel="", MaxKernel="22.99.99"))
        migrated = merge(legacy_only)
        assert FIXUP[0] not in active(migrated, (23, 6, 0))
        assert FIXUP[0] not in active(migrated, (24, 6, 0))
        assert FIXUP[0] not in active(migrated, (25, 6, 0))
        assert merge(migrated) == migrated
        checks += 1

        for major in SYSTEMS.values():
            for mutation in ["duplicate-lilu", "old-lilu", "no-block", "missing-skywalk", "duplicate-skywalk",
                             "wrong-airport", "bad-path", "lilu-order", "missing-injector", "orphan-injector"]:
                config = fragment(mutation == "missing-injector")
                additions = config["Kernel"]["Add"]
                if mutation == "duplicate-lilu":
                    additions.append(copy.deepcopy(additions[0]))
                elif mutation == "old-lilu":
                    path = oc / "Kexts/Lilu.kext/Contents/Info.plist"
                    saved = path.read_bytes()
                    info = plistlib.loads(saved)
                    info["CFBundleVersion"] = "1.7.0"
                    path.write_bytes(plistlib.dumps(info))
                elif mutation == "no-block":
                    config["Kernel"]["Block"] = []
                elif mutation == "missing-skywalk":
                    additions.pop(2)
                elif mutation == "duplicate-skywalk":
                    additions.append(copy.deepcopy(additions[2]))
                elif mutation == "wrong-airport":
                    wrong = AIRPORT_TAHOE if major in (23, 24) else AIRPORT_ORIGINAL
                    entry = next(e for e in additions if e['BundlePath'] == wrong[0])
                    entry.update(MinKernel="23.0.0", MaxKernel="25.99.99")
                elif mutation == "bad-path":
                    additions[1]["ExecutablePath"] = "Contents/MacOS/Other"
                elif mutation == "lilu-order":
                    additions.reverse()
                elif mutation == "missing-injector":
                    additions.pop()
                elif mutation == "orphan-injector":
                    additions.append(fragment(True)["Kernel"]["Add"][-1])
                assert issues(config, (major, 6, 0)), (major, mutation)
                if mutation == "old-lilu":
                    path.write_bytes(saved)
                checks += 1

        manifest = {"files": {}}
        for path in (oc / "Kexts").rglob("*"):
            if path.is_file():
                rel = path.relative_to(oc / "Kexts").as_posix()
                prefix = "Extra/Optional/" if rel.startswith("AirportBrcmFixup.kext/") else "EFI/OC/Kexts/"
                manifest["files"][prefix + rel] = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest_path = oc / "manifest.json"
        manifest_path.write_text(json.dumps(manifest))
        for major in SYSTEMS.values():
            assert not issues(fragment(True), (major, 6, 0), manifest_path)
            path = oc / 'Kexts' / (AIRPORT_ORIGINAL if major in (23, 24) else AIRPORT_TAHOE)[0] / 'Contents/MacOS/AirPortBrcmNIC'
            saved = path.read_bytes()
            path.write_bytes(b"changed")
            assert any("SHA-256" in issue for issue in issues(fragment(), (major, 6, 0), manifest_path))
            path.write_bytes(saved)
            checks += 2

        for major in SYSTEMS.values():
            config = fragment()
            backend = AIRPORT_ORIGINAL if major in (23, 24) else AIRPORT_TAHOE
            alias = f'Renamed{major}.kext'
            shutil.copytree(oc / 'Kexts' / backend[0], oc / 'Kexts' / alias)
            entry = dict(next(e for e in config['Kernel']['Add'] if e['BundlePath'] == backend[0]))
            entry['BundlePath'] = alias
            config['Kernel']['Add'].append(entry)
            assert any('Bundle ID' in issue for issue in issues(config, (major, 6, 0)))
            checks += 1

        config = fragment()
        config["Kernel"]["Add"][0]["BundlePath"] = "Shared/Lilu.kext"
        shared = oc / "Kexts/Shared"
        shared.mkdir()
        (oc / "Kexts/Lilu.kext").rename(shared / "Lilu.kext")
        for major in SYSTEMS.values():
            assert not issues(merge(config), (major, 6, 0))
            checks += 1
        for system, major in SYSTEMS.items():
            other = 25 if major in (23, 24) else 24
            for optional in [False, True]:
                config = fragment(optional, major)
                assert active(config, (major, 6, 0)) == [entry[0] for entry in drivers(optional, major)]
                assert all(not active(config, (version, 6, 0)) for version in SYSTEMS.values() if version != major)
                for entry in config['Kernel']['Add'] + config['Kernel']['Block']:
                    assert entry['MinKernel'] == f'{major}.0.0' and entry['MaxKernel'] == f'{major}.99.99'
                config['Kernel']['Add'][0]['BundlePath'] = 'Shared/Lilu.kext'
                assert not issues(config, (major, 6, 0))
                checks += 1
            original = fragment(True)
            original['Kernel']['Add'][0]['BundlePath'] = 'Shared/Lilu.kext'
            migrated = merge(original, kernel_version=major)
            assert all(active(migrated, (version, 6, 0)) == active(original, (version, 6, 0))
                       for version in SYSTEMS.values() if version != major)
            assert not issues(migrated, (major, 6, 0))
            assert merge(migrated, kernel_version=major) == migrated
            checks += 1
            manifest['system'] = system
            manifest_path.write_text(json.dumps(manifest))
            assert any('发布包面向' in issue for issue in issues(original, (other, 6, 0), manifest_path))
            extra = oc / system / 'Extra'
            (extra / 'Tools').mkdir(parents=True)
            shutil.copy2(Path(__file__).with_name('configure.py'), extra / 'Tools/configure.py')
            (extra / 'manifest.json').write_text(json.dumps({'system': system}))
            output = extra / 'generated.plist'
            subprocess.run([sys.executable, '-B', str(extra / 'Tools/configure.py'), '--output', str(output),
                            '--airportbrcmfixup'], check=True, capture_output=True)
            assert plistlib.loads(output.read_bytes()) == fragment(True, major)
            checks += 2
        for invalid in [22, 26]:
            try:
                fragment(kernel=invalid)
            except ValueError:
                checks += 1
            else:
                raise AssertionError('Unsupported package kernel accepted')

        for broken in [[], [fragment()["Kernel"]["Add"][0]] * 2]:
            try:
                merge({"Kernel": {"Add": broken}})
            except ValueError:
                checks += 1
            else:
                raise AssertionError("Invalid Lilu input accepted")
    return {"checks": checks, "kernelRange": "23.0.0–25.99.99", "driverLoading": "external",
            "exclusiveAirPortBackends": True, "optionalAirportBrcmFixup": True,
            "migrationIdempotent": True, "bootArgumentsPreserved": True}


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2, ensure_ascii=False))

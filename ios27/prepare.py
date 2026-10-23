#!/usr/bin/env python3
"""Prepare real iOS 27 RecoveryOS core and an exec-admission APFS probe.

This does not build a complete iOS 27 system image or implement ARM64e_X1 in XNU.
"""
import argparse
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile

from abi import inspect_file
import fetch

ROOT = Path(__file__).resolve().parents[1]


def check_version(root, target):
    version = plistlib.loads((root / "System/Library/CoreServices/SystemVersion.plist").read_bytes())
    if version.get("ProductVersion") != target["version"] or version.get("ProductBuildVersion") != target["build"]:
        raise ValueError("extracted SystemVersion does not match the target")
    if version.get("ReleaseType") != "Darwin Recovery":
        raise ValueError("this preparation path expects RecoveryOS, not the complete iOS rootfs")
    return {key: version.get(key) for key in ("ProductVersion", "ProductBuildVersion", "ReleaseType")}


def build_probe(root, session):
    probe = session / "probe-root"
    directories = ("sbin", "usr/lib", "dev", "tmp", "private/var")
    for directory in directories:
        (probe / directory).mkdir(parents=True, exist_ok=True)
    for name in ("sbin/launchd", "usr/lib/dyld"):
        shutil.copyfile(root / name, probe / name)
    manifest = "".join(f"40755\t0\t0\t{name}\n" for name in ("sbin", "usr", "usr/lib", "dev", "tmp", "private", "private/var"))
    manifest += "100755\t0\t0\tsbin/launchd\n100755\t0\t0\tusr/lib/dyld\n"
    (session / "probe.manifest").write_text(manifest, encoding="utf-8", newline="\n")
    subprocess.run([sys.executable, str(ROOT / "tools/apfs/mkapfs.py"), "-o", "probe.apfs",
                    "iOS27Probe=probe-root,manifest=probe.manifest"], cwd=session, check=True, timeout=60)
    return session / "probe.apfs"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipsw-tool", required=True, type=Path)
    parser.add_argument("--sevenzip", required=True, type=Path)
    parser.add_argument("--cache", type=Path, default=fetch.HERE / "artifacts/recovery")
    args = parser.parse_args(argv)
    target = fetch.load_target(fetch.HERE / "target.json")
    ipsw, sevenzip = args.ipsw_tool.resolve(), args.sevenzip.resolve()
    if not ipsw.is_file() or not sevenzip.is_file():
        raise ValueError("ipsw-tool and sevenzip must be existing executables")
    report = json.loads((args.cache / "inventory.json").read_text(encoding="utf-8"))
    if report["target"] != target:
        raise ValueError("cached inventory belongs to a different target")
    identity = next((item for item in report["identities"] if item["index"] == report["selected_identity"]), None)
    if identity is None or identity["variant"] != "Recovery Customer Install":
        raise ValueError("cache must be fetched with --identity 4 (Recovery Customer Install)")
    os_component = next((item for item in report["extracted"] if item["component"] == "OS"), None)
    if os_component is None:
        raise ValueError("RecoveryOS component is not extracted; run fetch.py --identity 4 --component OS")
    source = Path(os_component["path"]).resolve()
    if fetch.file_sha256(source) != os_component["sha256"]:
        raise ValueError("cached RecoveryOS differs from the verified download")
    out = ROOT / "out"
    out.mkdir(exist_ok=True)
    session = Path(tempfile.mkdtemp(prefix="ios27-core-", dir=out))
    decrypted, root = session / "decrypted", session / "rootfs"
    decrypted.mkdir()
    subprocess.run([str(ipsw), "fw", "aea", str(source), "--output", str(decrypted)], check=True, timeout=180)
    images = list(decrypted.glob("*.dmg"))
    if len(images) != 1:
        raise ValueError("AEA decryption did not produce exactly one DMG")
    subprocess.run([str(sevenzip), "x", "-y", f"-o{root}", str(images[0]),
                    "sbin/launchd", "usr/lib/dyld", "System/Library/CoreServices/SystemVersion.plist"],
                   check=True, timeout=180, stdout=subprocess.DEVNULL)
    system = check_version(root, target)
    binaries = {name: inspect_file(root / name) for name in ("sbin/launchd", "usr/lib/dyld")}
    probe = build_probe(root, session)
    result = {"target": target, "system": system, "binaries": binaries,
              "probe_image": str(probe), "probe_sha256": fetch.file_sha256(probe),
              "image_kind": "exec_admission_probe_not_complete_ios", "ios27_boot_verified": False,
              "blockers": ["XNU 8796 baseline has no ARM64e_X1 user-process ABI",
                           "Complete iOS 27 frameworks, shared-cache setup and launchd services are not integrated"]}
    (session / "core.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"iOS 27 core prepared, not boot-verified: {session / 'core.json'}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, StopIteration, subprocess.SubprocessError) as error:
        sys.exit(f"prepare.py: {error}")

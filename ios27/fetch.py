#!/usr/bin/env python3
"""Fetch pinned iOS 27 metadata/components, not an iOS 16 image with a new label.

python ios27/fetch.py [--ipsw LOCAL_IPSW] [--component OS|KernelCache|...]
Downloads stay in ignored ios27/artifacts. No images are declared bootable here.
"""
import argparse
from contextlib import ExitStack
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import shutil
import sys
import tempfile
import urllib.parse
import urllib.request
import zipfile
import zlib

HERE = Path(__file__).resolve().parent
MAX_RANGE = 64 << 20
MAX_METADATA = 32 << 20
MAX_ENTRIES = 100000
TIMEOUT = 60
CHUNK = 16 << 20


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def apple_url(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in
            ("updates.cdn-apple.com", "appldnld.apple.com") or
            parsed.username or parsed.password or parsed.port not in (None, 443)):
        raise ValueError("IPSW URL must use HTTPS on Apple's firmware CDN")
    return url


class RangeFile(io.RawIOBase):
    """Seekable HTTP object for stdlib ZipFile, with strict range and size checks."""
    def __init__(self, url, size):
        super().__init__()
        self.url = apple_url(url)
        if not isinstance(size, int) or size <= 0:
            raise ValueError("invalid IPSW size")
        self.size, self.position, self.etag = size, 0, None
        self.bytes_fetched = 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=io.SEEK_SET):
        bases = {io.SEEK_SET: 0, io.SEEK_CUR: self.position, io.SEEK_END: self.size}
        if whence not in bases or not 0 <= bases[whence] + offset <= self.size:
            raise ValueError("seek outside IPSW")
        self.position = bases[whence] + offset
        return self.position

    def read(self, size=-1):
        if self.closed:
            raise ValueError("read from closed IPSW")
        size = min(self.size - self.position, size if size >= 0 else self.size - self.position)
        if size > MAX_RANGE:
            raise ValueError("range exceeds 64 MiB; refusing an unbounded archive read")
        if size == 0:
            return b""
        start, end = self.position, self.position + size - 1
        headers = {"Range": f"bytes={start}-{end}", "Accept-Encoding": "identity"}
        if self.etag:
            headers["If-Range"] = self.etag
        request = urllib.request.Request(self.url, headers=headers)
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            apple_url(response.geturl())
            if response.status != 206:
                raise ValueError(f"CDN ignored Range (HTTP {response.status}); not downloading the whole IPSW")
            if response.headers.get("Content-Range") != f"bytes {start}-{end}/{self.size}":
                raise ValueError("CDN returned a different range or archive size")
            if response.headers.get("Content-Encoding", "identity") != "identity":
                raise ValueError("encoded HTTP response is not byte-addressable")
            etag = response.headers.get("ETag")
            if self.etag and etag != self.etag:
                raise ValueError("IPSW changed between range requests")
            self.etag = etag
            data = response.read(size + 1)
            if len(data) != size:
                raise ValueError("truncated or oversized range response")
        self.position += size
        self.bytes_fetched += size
        return data


def load_target(path):
    target = json.loads(path.read_text(encoding="utf-8"))
    apple_url(target["url"])
    if not re.fullmatch(r"[0-9a-f]{64}", target["ipsw_sha256"]):
        raise ValueError("target lacks a valid catalog SHA256")
    if not isinstance(target["size"], int) or target["size"] <= 0:
        raise ValueError("target lacks a valid archive size")
    for key in ("product", "board", "version", "build"):
        if not isinstance(target[key], str) or not target[key]:
            raise ValueError(f"target lacks {key}")
    return target


def metadata(archive, name):
    info = archive.getinfo(name)
    if info.file_size > MAX_METADATA:
        raise ValueError(f"metadata exceeds {MAX_METADATA} bytes: {name}")
    data = archive.read(info)  # ZipFile checks uncompressed length/CRC.
    value = plistlib.loads(data)
    if not isinstance(value, dict):
        raise ValueError(f"metadata root is not a dictionary: {name}")
    return data, value


def inventory(archive, target):
    entries = archive.infolist()
    if len(entries) > MAX_ENTRIES or len({entry.filename for entry in entries}) != len(entries):
        raise ValueError("too many ZIP entries or duplicate member names")
    manifest_bytes, manifest = metadata(archive, "BuildManifest.plist")
    restore_bytes, restore = metadata(archive, "Restore.plist")
    if (manifest.get("ProductVersion") != target["version"] or
            manifest.get("ProductBuildVersion") != target["build"] or
            target["product"] not in manifest.get("SupportedProductTypes", [])):
        raise ValueError("BuildManifest does not match the pinned product/version/build")
    identities = []
    for index, identity in enumerate(manifest.get("BuildIdentities", [])):
        info = identity.get("Info", {})
        if info.get("DeviceClass", "").lower() != target["board"].lower():
            continue
        components = {}
        for name, component in identity.get("Manifest", {}).items():
            path = component.get("Info", {}).get("Path")
            if not isinstance(path, str):
                continue
            member = archive.NameToInfo.get(path)
            components[name] = {"path": path, "present": member is not None,
                                "size": member.file_size if member else None,
                                "compressed_size": member.compress_size if member else None,
                                "aea_name": path.endswith(".aea")}
        identities.append({"index": index, "board": info.get("DeviceClass"),
                           "variant": info.get("Variant"), "restore_behavior": info.get("RestoreBehavior"),
                           "components": components})
    if not identities:
        raise ValueError("BuildManifest has no identity for the pinned board")
    selected = next((item for item in identities if item["restore_behavior"] == "Erase"), identities[0])
    report = {"target": target, "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
              "restore_sha256": hashlib.sha256(restore_bytes).hexdigest(), "archive_entries": len(entries),
              "selected_identity": selected["index"], "identities": identities,
              "full_ipsw_sha256_verified": False, "userland_abi_inspected": False,
              "ios27_boot_verified": False, "ready_for_boot": False}
    return report, {"BuildManifest.plist": manifest_bytes, "Restore.plist": restore_bytes}


def extract_component(archive, identity, component, destination):
    item = identity["components"].get(component)
    if not item or not item["present"]:
        raise ValueError(f"component missing from selected ZIP identity: {component}")
    info = archive.getinfo(item["path"])
    if info.file_size > shutil.disk_usage(destination).free:
        raise ValueError("not enough free space for component")
    member_path = PurePosixPath(item["path"])
    if (member_path.is_absolute() or ".." in member_path.parts or
            "\\" in item["path"] or ":" in item["path"] or not member_path.name):
        raise ValueError("unsafe component name")
    output = destination / member_path.name
    if output.exists():
        if not output.is_file() or output.stat().st_size != info.file_size:
            raise ValueError(f"output differs; preserving it: {output}")
        checksum, digest, count = 0, hashlib.sha256(), 0
        with output.open("rb") as stream:
            for block in iter(lambda: stream.read(CHUNK), b""):
                count += len(block)
                checksum = zlib.crc32(block, checksum)
                digest.update(block)
        if count != info.file_size or checksum != info.CRC:
            raise ValueError(f"output differs; preserving it: {output}")
        return {"component": component, "path": str(output.resolve()), "size": count,
                "sha256": digest.hexdigest(), "zip_crc32_verified": True, "reused": True}
    fd, temporary = tempfile.mkstemp(prefix=".component-", dir=destination)
    digest, count = hashlib.sha256(), 0
    try:
        with os.fdopen(fd, "wb") as stream, archive.open(info) as source:
            while block := source.read(CHUNK):
                count += len(block)
                if count > info.file_size:
                    raise ValueError("component exceeds its ZIP length")
                stream.write(block)
                digest.update(block)
        if count != info.file_size:
            raise ValueError("component length mismatch")
        os.link(temporary, output)  # Exclusive publication: never replace a concurrent user's file.
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {"component": component, "path": str(output.resolve()), "size": count,
            "sha256": digest.hexdigest(), "zip_crc32_verified": True, "reused": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=HERE / "target.json")
    parser.add_argument("--ipsw", type=Path, help="read a local archive instead of HTTP Range")
    parser.add_argument("--output", type=Path, default=HERE / "artifacts")
    parser.add_argument("--identity", type=int, help="BuildIdentity index; default: board's erase identity")
    parser.add_argument("--component", action="append", default=[], help="extract this exact manifest component")
    args = parser.parse_args(argv)
    target = load_target(args.target)
    with ExitStack() as stack:
        source = stack.enter_context(args.ipsw.open("rb") if args.ipsw else RangeFile(target["url"], target["size"]))
        archive = stack.enter_context(zipfile.ZipFile(source))
        report, plists = inventory(archive, target)
        if args.identity is not None:
            if not any(item["index"] == args.identity for item in report["identities"]):
                raise ValueError("identity does not belong to the pinned board")
            report["selected_identity"] = args.identity
        selected = next(item for item in report["identities"] if item["index"] == report["selected_identity"])
        args.output.mkdir(parents=True, exist_ok=True)
        for name, data in plists.items():
            path = args.output / name
            if path.exists() and path.read_bytes() != data:
                raise ValueError(f"preserving different existing metadata: {path}")
            path.write_bytes(data)
        report["extracted"] = [extract_component(archive, selected, component, args.output)
                               for component in args.component]
        report["range_bytes_fetched"] = source.bytes_fetched if isinstance(source, RangeFile) else 0
        (args.output / "inventory.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"iOS {target['version']} ({target['build']}), {target['product']}: "
              f"{len(report['identities'])} identities, {report['range_bytes_fetched']} range bytes; "
              f"boot_verified=false; {args.output / 'inventory.json'}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, RuntimeError) as error:
        sys.exit(f"fetch.py: {error}")

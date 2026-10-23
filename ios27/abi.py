"""Bounded inspection of thin Mach-O headers and chained-fixup layouts, not an ABI translator."""
import hashlib
import mmap
from pathlib import Path
import struct

ARM64 = 0x0100000C
SUBTYPES = {0: "arm64", 1: "arm64_v8", 2: "arm64e", 12: "arm64e_x1"}


def span(data, offset, size):
    if offset < 0 or size < 0 or offset > len(data) - size:
        raise ValueError("Mach-O field extends beyond file")
    return data[offset:offset + size]


def version(value):
    return f"{value >> 16}.{(value >> 8) & 255}.{value & 255}"


def cstring(command, offset):
    if offset < 8 or offset >= len(command):
        raise ValueError("invalid Mach-O string offset")
    data = bytes(command[offset:])
    end = data.find(b"\0")
    if end < 0:
        raise ValueError("unterminated Mach-O string")
    return data[:end].decode("utf-8")


def fixups(data, offset, size):
    if size > 64 << 20:
        raise ValueError("chained-fixup data exceeds 64 MiB")
    blob = span(data, offset, size)
    if size < 28:
        raise ValueError("truncated chained-fixup header")
    format_version, starts, imports, symbols, count, import_format, symbol_format = struct.unpack_from("<7I", blob)
    if format_version != 0 or starts < 28:
        raise ValueError("unsupported chained-fixup header")
    span(blob, starts, 4)
    segments, = struct.unpack_from("<I", blob, starts)
    if segments > 128:
        raise ValueError("too many chained-fixup segments")
    span(blob, starts + 4, segments * 4)
    layouts = []
    for index in range(segments):
        relative, = struct.unpack_from("<I", blob, starts + 4 + index * 4)
        if relative == 0:
            continue
        if relative < 4 + segments * 4:
            raise ValueError("chained-fixup segment overlaps its table")
        position = starts + relative
        span(blob, position, 22)
        length, page_size, pointer_format, segment_offset, max_pointer, pages = struct.unpack_from("<IHHQIH", blob, position)
        if length < 22 + pages * 2:
            raise ValueError("truncated chained-fixup page starts")
        span(blob, position, length)
        layouts.append({"segment": index, "page_size": page_size,
                        "pointer_format": pointer_format, "page_count": pages})
    return {"version": format_version, "imports_count": count, "imports_format": import_format,
            "symbols_format": symbol_format, "layouts": layouts, "bindings_decoded": False}


def inspect_image(data):
    span(data, 0, 32)
    magic, cpu, subtype, kind, count, length, flags, reserved = struct.unpack_from("<8I", data)
    if magic != 0xFEEDFACF:
        raise ValueError("expected a thin little-endian 64-bit Mach-O")
    if count > 4096 or length > 16 << 20:
        raise ValueError("Mach-O load-command limit exceeded")
    span(data, 32, length)
    base_subtype = subtype & 0x00FFFFFF
    report = {"cpu_type": cpu, "cpu_subtype": subtype, "cpu_subtype_base": base_subtype,
              "cpu_capabilities": subtype & 0xFF000000,
              "architecture": SUBTYPES.get(base_subtype, f"unknown_{base_subtype}") if cpu == ARM64 else f"cpu_{cpu}",
              "file_type": kind, "flags": flags, "dylibs": [], "build_versions": [],
              "dyld": None, "chained_fixups": [], "boot_compatibility_verified": False}
    position, end = 32, 32 + length
    for _ in range(count):
        if position + 8 > end:
            raise ValueError("truncated Mach-O load command")
        command, size = struct.unpack_from("<II", data, position)
        if size < 8 or size % 8 or position + size > end:
            raise ValueError("invalid Mach-O command size")
        entry = span(data, position, size)
        if command == 0x32:
            if size < 24:
                raise ValueError("truncated build-version command")
            platform, minimum, sdk, tools = struct.unpack_from("<4I", entry, 8)
            if 24 + tools * 8 > size:
                raise ValueError("truncated build tool table")
            report["build_versions"].append({"platform": platform, "minimum": version(minimum), "sdk": version(sdk)})
        elif command == 0xE:
            if size < 12:
                raise ValueError("truncated dyld command")
            report["dyld"] = cstring(entry, struct.unpack_from("<I", entry, 8)[0])
        elif command in (0xC, 0x18 | 0x80000000, 0x1F | 0x80000000, 0x23 | 0x80000000):
            if size < 24:
                raise ValueError("truncated dylib command")
            report["dylibs"].append(cstring(entry, struct.unpack_from("<I", entry, 8)[0]))
        elif command == 0x80000034:
            if size != 16:
                raise ValueError("invalid chained-fixup command")
            report["chained_fixups"].append(fixups(data, *struct.unpack_from("<II", entry, 8)))
        position += size
    if position != end:
        raise ValueError("load-command count does not cover sizeofcmds")
    return report


def inspect_file(path):
    path = Path(path)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
        if stream.tell() < 32:
            raise ValueError("Mach-O file is empty or truncated")
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            report = inspect_image(data)
    return {"path": str(path), "size": path.stat().st_size, "sha256": digest.hexdigest(), **report}

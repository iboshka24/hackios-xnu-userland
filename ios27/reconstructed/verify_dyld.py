#!/usr/bin/env python3
"""Batch differential verification of 19 reconstructed dyld methods against their original bytes."""
import argparse
import ctypes
import hashlib
import itertools
import json
from pathlib import Path
import random
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X30, UC_ARM64_REG_PC
from verify_grade import commands, require

HERE = Path(__file__).resolve().parent
CODE, STOP, OBJECT, DATA, OTHER = 0x100000, 0x101000, 0x200000, 0x201000, 0x202000
ARM64, ARM64_32, X86_64 = 0x0100000C, 0x0200000C, 0x01000007
TYPES = (0, 7, 12, ARM64, ARM64_32, X86_64, 0xFFFFFFFF)
SUBTYPES = (0, 1, 2, 12, 0x80000002, 0x8000000C, 0x81000002, 0xFF00000C, 0xFFFFFFFF)
# (family, C operation, original ABI, symbol). Names come from this dyld's nlist table.
METHODS = [
    ("header", 1, "span", "__ZNK6mach_o6Header4is64Ev"),
    ("header", 2, "span", "__ZNK6mach_o6Header7isDylibEv"),
    ("header", 3, "span", "__ZNK6mach_o6Header8isBundleEv"),
    ("header", 4, "span", "__ZNK6mach_o6Header13isDyldManagedEv"),
    ("header", 5, "span", "__ZNK6mach_o6Header11pointerSizeEv"),
    ("header", 6, "span", "__ZNK6mach_o6Header12usesWeakDefsEv"),
    ("header", 7, "span", "__ZNK6mach_o6Header17mayHaveTextFixupsEv"),
    ("header", 8, "raw", "__ZNK6mach_o12UnsafeHeader12uses16KPagesEv"),
    ("header", 9, "raw", "__ZNK6mach_o12UnsafeHeader12isObjectFileEv"),
    ("header", 10, "raw", "__ZNK6mach_o12UnsafeHeader25headerAndLoadCommandsSizeEv"),
    ("arch", 1, "arch", "__ZNK6mach_o12Architecture21usesArm64AuthPointersEv"),
    ("arch", 2, "arch", "__ZNK6mach_o12ArchitectureeqERKS0_"),
    ("arch", 3, "arch", "__ZNK6mach_o12Architecture21usesArm64InstructionsEv"),
    ("arch", 4, "arch", "__ZNK6mach_o12Architecture22usesx86_64InstructionsEv"),
    ("chain", 1, "next", "__ZNK6mach_o33PointerFormat_DYLD_CHAINED_PTR_6412nextLocationEPKv"),
    ("chain", 2, "next", "__ZNK6mach_o46PointerFormat_DYLD_CHAINED_PTR_64_KERNEL_CACHE12nextLocationEPKv"),
    ("chain", 3, "next", "__ZNK6mach_o46PointerFormat_DYLD_CHAINED_PTR_SHARED_CACHE_V212nextLocationEPKv"),
    ("chain", 4, "word", "__ZNK6mach_o25ChainedFixupPointerOnDisk9Generic6414unpackedTargetEv"),
    ("chain", 5, "word", "__ZNK6mach_o25ChainedFixupPointerOnDisk9Generic6418signExtendedAddendEv"),
]


def uleb_starts(blob, base):
    starts, offset, address = [], 0, base
    while offset < len(blob):
        value, shift = 0, 0
        while True:
            if offset >= len(blob) or shift >= 64:
                raise ValueError("truncated or overflowing function-start delta")
            part = blob[offset]
            offset += 1
            if shift == 63 and part & 0x7E:
                raise ValueError("function-start delta exceeds uint64")
            value |= (part & 127) << shift
            shift += 7
            if not part & 128:
                break
        if value == 0:
            return starts
        address += value
        if address >= 1 << 64 or len(starts) >= 100000:
            raise ValueError("function-start table exceeds limits")
        starts.append(address)
    raise ValueError("function-start table has no terminator")


def load_methods(data, profile):
    if hashlib.sha256(data).hexdigest() != profile["sha256"]:
        raise ValueError("wrong dyld SHA256")
    segments, tables, start_tables = [], [], []
    for command, at, size in commands(data, 0):
        if command == 0x19:
            if size < 72:
                raise ValueError("truncated segment")
            name = data[at + 8:at + 24].rstrip(b"\0")
            vm, _, offset, length = struct.unpack_from("<4Q", data, at + 24)
            protection, = struct.unpack_from("<i", data, at + 60)
            require(data, offset, length)
            segments.append((name, vm, offset, length, protection))
        elif command == 2:
            if size < 24:
                raise ValueError("truncated symtab command")
            tables.append(struct.unpack_from("<4I", data, at + 8))
        elif command == 0x26:
            if size < 16:
                raise ValueError("truncated function-start command")
            start_tables.append(struct.unpack_from("<II", data, at + 8))
    texts = [segment for segment in segments if segment[0] == b"__TEXT"]
    if len(tables) != 1 or len(start_tables) != 1 or len(texts) != 1:
        raise ValueError("dyld metadata is absent or ambiguous")
    sym, count, strings, string_size = tables[0]
    if count > 100000:
        raise ValueError("too many symbols")
    require(data, sym, count * 16)
    require(data, strings, string_size)
    symbols = {}
    wanted = {method[3] for method in METHODS}
    for index in range(count):
        name_at, kind, _, _, va = struct.unpack_from("<IBBHQ", data, sym + index * 16)
        if kind & 0xE0 or kind & 0x0E != 0x0E:
            continue
        if name_at >= string_size:
            raise ValueError("symbol name outside string table")
        end = data.find(b"\0", strings + name_at, strings + string_size)
        if end < 0:
            raise ValueError("unterminated symbol")
        name = data[strings + name_at:end].decode("utf-8")
        if name in wanted:
            if name in symbols:
                raise ValueError("ambiguous selected symbol")
            symbols[name] = va
    offset, size = start_tables[0]
    require(data, offset, size)
    starts = uleb_starts(data[offset:offset + size], texts[0][1])
    ends = dict(zip(starts, starts[1:]))
    methods = []
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for family, operation, abi, symbol in METHODS:
        if symbol not in symbols or symbols[symbol] not in ends:
            raise ValueError(f"function boundary unavailable: {symbol}")
        va = symbols[symbol]
        length = ends[va] - va
        regions = [seg for seg in segments if seg[4] & 4 and va >= seg[1] and va - seg[1] + length <= seg[3]]
        if len(regions) != 1 or length <= 0 or length > 4096 or length % 4:
            raise ValueError("selected function has an invalid executable extent")
        segment = regions[0]
        file_offset = segment[2] + va - segment[1]
        code = data[file_offset:file_offset + length]
        instructions = list(decoder.disasm(code, va))
        if len(instructions) * 4 != length:
            raise ValueError(f"undecoded instruction: {symbol}")
        if any(item.mnemonic in ("bl", "blr", "blraa", "adr", "adrp") for item in instructions):
            raise ValueError("selected unit needs external execution context")
        methods.append(dict(family=family, operation=operation, abi=abi, symbol=symbol, va=va,
                            file_offset=file_offset, code=code, instructions=instructions,
                            sha256=hashlib.sha256(code).hexdigest()))
    return methods


def header_cases(random_cases, checked):
    def row(cpu=ARM64, subtype=0, kind=2, magic=0xFEEDFACF, flags=4, size=0, length=32):
        return struct.pack("<8I", magic, cpu, subtype, kind, 0, size, flags, 0).ljust(64, b"\0"), length
    for cpu, kind, flags in itertools.product(TYPES, (0, 1, 2, 6, 7, 8, 11, 0xFFFFFFFF), (0, 4, 0x10000, 0x10004, 0xFFFFFFFF)):
        yield row(cpu=cpu, kind=kind, flags=flags)
    for cpu, subtype in itertools.product(TYPES, SUBTYPES):
        yield row(cpu=cpu, subtype=subtype)
    for magic, size in itertools.product((0, 0xFEEDFACF, 0xFEEDFACE, 0xCFFAEDFE), (0, 1, 0xFFFFFFDF, 0xFFFFFFE0, 0xFFFFFFFF)):
        yield row(magic=magic, size=size)
    for length in range(0 if checked else 28, 33):
        yield row(length=length)
    rng = random.Random(27062)
    for _ in range(random_cases):
        yield row(cpu=rng.choice(TYPES), subtype=rng.choice(SUBTYPES), kind=rng.randrange(16),
                  magic=rng.choice((0xFEEDFACF, rng.getrandbits(32))), flags=rng.getrandbits(32),
                  size=rng.getrandbits(32), length=rng.randrange(65) if checked else 32)


def arch_cases(random_cases):
    arches = list(itertools.product(TYPES, SUBTYPES))
    yield from (left + right for left, right in itertools.product(arches, repeat=2))
    rng = random.Random(27062)
    for _ in range(random_cases):
        cpu, subtype = rng.choice(TYPES), rng.getrandbits(32)
        right = (cpu, subtype) if rng.randrange(2) else (rng.choice(TYPES), rng.getrandbits(32))
        yield cpu, subtype, *right


def word_cases(operation, random_cases):
    mask = (1 << 64) - 1
    rng = random.Random(27062)
    yield 0
    yield mask
    for bit in range(64):
        yield 1 << bit
        yield mask ^ (1 << bit)
    if operation in (1, 2, 3):
        shift, width = (40, 16) if operation == 3 else (51, 12)
        field = ((1 << width) - 1) << shift
        for value in range(1 << width):
            yield (rng.getrandbits(64) & ~field) | (value << shift)
    elif operation == 5:
        for value in range(256):
            yield (rng.getrandbits(64) & ~(255 << 24)) | (value << 24)
    for _ in range(random_cases):
        yield rng.getrandbits(64)


def verify_method(method, library, random_cases):
    machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    machine.mem_map(CODE, 0x2000)
    machine.mem_write(CODE, method["code"])
    machine.mem_map(OBJECT, 0x4000)
    visited, traps = set(), []
    def track(_machine, address, _size, _user):
        visited.add(address - CODE)
    def interrupt(uc, number, _user):
        traps.append(number)
        uc.emu_stop()
    machine.hook_add(UC_HOOK_CODE, track)
    machine.hook_add(UC_HOOK_INTR, interrupt)
    family, operation = method["family"], method["operation"]
    if family == "header":
        inputs = header_cases(random_cases, method["abi"] == "span")
    elif family == "arch":
        inputs = arch_cases(random_cases)
    else:
        inputs = word_cases(operation, random_cases)
    total = rejected = 0
    for value in inputs:
        traps.clear()
        output = ctypes.c_uint64(0xBAD)
        if family == "header":
            data, length = value
            machine.mem_write(DATA, data)
            machine.mem_write(OBJECT, struct.pack("<QQ", DATA, length))
            first, second = (OBJECT if method["abi"] == "span" else DATA), 0
            buffer = ctypes.create_string_buffer(data)
            valid = library.ios27_header_query(operation, buffer, length, ctypes.byref(output))
            actual = output.value
        elif family == "arch":
            cpu, subtype, other_cpu, other_subtype = value
            machine.mem_write(OBJECT, struct.pack("<II", cpu, subtype))
            machine.mem_write(OTHER, struct.pack("<II", other_cpu, other_subtype))
            first, second = OBJECT, OTHER
            valid = 1
            actual = library.ios27_arch_query(operation, *value)
        else:
            location = DATA + (total % 8)
            machine.mem_write(location, struct.pack("<Q", value))
            first, second = (OBJECT, location) if method["abi"] == "next" else (location, 0)
            valid = library.ios27_chain_query(operation, value, location, ctypes.byref(output))
            actual = output.value
        machine.reg_write(UC_ARM64_REG_X0, first)
        machine.reg_write(UC_ARM64_REG_X1, second)
        machine.reg_write(UC_ARM64_REG_X30, STOP)
        machine.emu_start(CODE, STOP, count=200)
        if traps:
            if traps != [7] or valid != 0 or actual != 0:
                raise ValueError(f"trap/status mismatch: {method['symbol']} {traps} {value}")
            rejected += 1
        else:
            if machine.reg_read(UC_ARM64_REG_PC) != STOP:
                raise ValueError("original method did not return within its instruction budget")
            expected = machine.reg_read(UC_ARM64_REG_X0)
            if valid != 1 or actual != expected:
                raise ValueError(f"value mismatch: {method['symbol']}, input={value}, binary={expected}, C={actual}")
        total += 1
    expected = set(range(0, len(method["code"]), 4))
    if visited != expected:
        raise ValueError(f"instruction coverage gap: {method['symbol']} {sorted(expected - visited)}")
    return dict(symbol=method["symbol"], family=family, operation=operation, va=hex(method["va"]),
                file_offset=method["file_offset"], sha256=method["sha256"], cases=total,
                rejections_compared=rejected, mismatches=0, instructions=len(expected),
                visited_instructions=len(visited))


def open_library(path):
    library = ctypes.CDLL(str(path.resolve()))
    library.ios27_header_query.argtypes = (ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint64))
    library.ios27_header_query.restype = ctypes.c_int
    library.ios27_arch_query.argtypes = (ctypes.c_uint32,) * 5
    library.ios27_arch_query.restype = ctypes.c_uint32
    library.ios27_chain_query.argtypes = (ctypes.c_uint32, ctypes.c_uint64, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64))
    library.ios27_chain_query.restype = ctypes.c_int
    return library


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dyld", type=Path, required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--random-cases", type=int, default=2048)
    args = parser.parse_args()
    if not 0 <= args.random_cases <= 100000:
        parser.error("--random-cases must be 0..100000")
    profile = json.loads((HERE / "dyld_profile.json").read_text())
    methods = load_methods(args.dyld.read_bytes(), profile)
    library = open_library(args.library)
    results = []
    for method in methods:
        result = verify_method(method, library, args.random_cases)
        results.append(result)
        print(f"PASS {method['symbol']}: {result['cases']} cases, {result['instructions']} instructions", flush=True)
    report = dict(profile=profile, methods=results, cases=sum(row["cases"] for row in results),
                  reconstructed_methods=len(results), distinct_bodies=len({row["sha256"] for row in results}),
                  mismatches=0, instructions=sum(row["instructions"] for row in results),
                  c_entry_points=3, invalid_span_adapter="original BRK -> C status 0",
                  random_cases_per_method=args.random_cases, whole_dyld_reconstructed=False,
                  whole_ios_reconstructed=False, library_sha256=hashlib.sha256(args.library.read_bytes()).hexdigest())
    args.output.mkdir(parents=True, exist_ok=True)
    for method in methods:
        (args.output / f"{method['family']}-{method['operation']}.asm").write_text("\n".join(
            f"{item.address:#x}: {item.mnemonic} {item.op_str}" for item in method["instructions"]) + "\n")
    (args.output / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS BATCH: {len(results)} methods, {report['cases']} cases, 0 mismatches", flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Compare reconstructed C with the unmodified ARM64 function bytes, not another C model."""
import argparse
from collections import Counter
import ctypes
import hashlib
import itertools
import json
from pathlib import Path
import random
import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import (UC_ARM64_REG_PC, UC_ARM64_REG_TPIDR_EL1,
                                UC_ARM64_REG_W0, UC_ARM64_REG_W1, UC_ARM64_REG_W2,
                                UC_ARM64_REG_W3, UC_ARM64_REG_X30)

HERE = Path(__file__).resolve().parent
CODE, STOP, THREAD, CPU = 0x100000, 0x101000, 0x200000, 0x201000
ARM64 = 0x0100000C
SEED = 27


def require(data, offset, size):
    if offset < 0 or size < 0 or offset > len(data) - size:
        raise ValueError("Mach-O range outside input")


def commands(data, base):
    require(data, base, 32)
    magic, = struct.unpack_from("<I", data, base)
    count, length = struct.unpack_from("<II", data, base + 16)
    if magic != 0xFEEDFACF or count > 4096 or length > 16 << 20:
        raise ValueError("invalid Mach-O header")
    require(data, base + 32, length)
    position, end = base + 32, base + 32 + length
    for _ in range(count):
        require(data, position, 8)
        command, size = struct.unpack_from("<II", data, position)
        if size < 8 or size % 8 or position + size > end:
            raise ValueError("invalid Mach-O load command")
        yield command, position, size
        position += size
    if position != end:
        raise ValueError("Mach-O sizeofcmds mismatch")


def function_bytes(data, profile):
    if hashlib.sha256(data).hexdigest() != profile["kernel_sha256"]:
        raise ValueError("wrong kernel SHA256; this reconstruction is build-specific")
    entries = []
    for command, position, size in commands(data, 0):
        if command != 0x80000035:
            continue
        if size < 32:
            raise ValueError("truncated fileset entry")
        _, offset, name_at, _ = struct.unpack_from("<QQII", data, position + 8)
        if not 32 <= name_at < size:
            raise ValueError("invalid fileset name offset")
        name = data[position + name_at:position + size].split(b"\0", 1)[0].decode("utf-8")
        if name == profile["fileset_entry"]:
            entries.append(offset)
    if len(entries) != 1:
        raise ValueError("kernel fileset entry is absent or ambiguous")
    va, length = int(profile["function_va"], 16), profile["function_size"]
    if length < 4 or length > 4096 or length % 4 or va % 4:
        raise ValueError("invalid function extent")
    matches = []
    for command, position, size in commands(data, entries[0]):
        if command != 0x19:
            continue
        if size < 72:
            raise ValueError("truncated segment")
        vm, _, offset, file_size = struct.unpack_from("<4Q", data, position + 24)
        initial_protection, = struct.unpack_from("<i", data, position + 60)
        if initial_protection & 4 and va >= vm and va - vm + length <= file_size:
            start = offset + va - vm
            require(data, start, length)
            matches.append((start, data[start:start + length]))
    if len(matches) != 1:
        raise ValueError("function is not in exactly one executable segment")
    offset, code = matches[0]
    if hashlib.sha256(code).hexdigest() != profile["function_sha256"]:
        raise ValueError("wrong function fingerprint")
    return offset, code


def cases(random_cases):
    hosts = (0, 1, 2, 12, 3, 20, 0xFFFFFFFF)
    types = (ARM64, 12, 0x0200000C, 0x01000007, 0, 0xFFFFFFFF)
    subtypes = (0, 1, 2, 12, 3, 11, 20, 0x00FFFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF)
    flags = [version << 24 | high for version in range(16) for high in (0, 0x80000000)]
    flags += [0xFFFFFFFF, 0x7FFFFFFF, 0x80000001, 0x80000010, 0x880000AA]
    for host, cpu_type, subtype, features in itertools.product(hosts, types, subtypes, flags):
        yield host, cpu_type, subtype, features
    rng = random.Random(SEED)
    for _ in range(random_cases):
        yield (rng.choice(hosts), rng.choice(types[:2]),
               rng.choice(subtypes) if rng.randrange(2) else rng.getrandbits(32), rng.getrandbits(32))


def verify(code, profile, library_path, random_cases):
    library = ctypes.CDLL(str(library_path.resolve()))
    reconstructed = library.ios27_arch_grade
    reconstructed.argtypes = (ctypes.c_uint32, ctypes.c_int32, ctypes.c_uint32, ctypes.c_uint32)
    reconstructed.restype = ctypes.c_int
    machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    machine.mem_map(CODE, 0x2000)
    machine.mem_write(CODE, code)
    machine.mem_map(THREAD, 0x2000)
    pointer_offset, subtype_offset = profile["thread_cpu_pointer_offset"], profile["cpu_subtype_offset"]
    if not 0 <= pointer_offset <= 0xFF8 or not 0 <= subtype_offset <= 0xFFC:
        raise ValueError("per-CPU test environment offset out of range")
    machine.mem_write(THREAD + pointer_offset, struct.pack("<Q", CPU))
    machine.reg_write(UC_ARM64_REG_TPIDR_EL1, THREAD)
    visited, results, total = set(), Counter(), 0
    def track(_machine, address, _size, _user):
        visited.add(address - CODE)
    machine.hook_add(UC_HOOK_CODE, track)
    for host, cpu_type, subtype, features in cases(random_cases):
        machine.mem_write(CPU + subtype_offset, struct.pack("<I", host))
        for register, value in ((UC_ARM64_REG_W0, cpu_type), (UC_ARM64_REG_W1, subtype),
                                (UC_ARM64_REG_W2, features), (UC_ARM64_REG_W3, total & 1),
                                (UC_ARM64_REG_X30, STOP)):
            machine.reg_write(register, value)
        # The pinned function has no calls: an instruction budget bounds every path without a timer thread per case.
        machine.emu_start(CODE, STOP, count=200)
        if machine.reg_read(UC_ARM64_REG_PC) != STOP:
            raise ValueError("original ARM64 function failed to return within its budget")
        expected = machine.reg_read(UC_ARM64_REG_W0)
        actual = reconstructed(cpu_type, subtype, features, host)
        if expected != actual:
            raise ValueError(f"mismatch: host={host}, type={cpu_type:#x}, subtype={subtype:#x}, "
                             f"features={features:#x}, binary={expected}, C={actual}")
        total += 1
        results[expected] += 1
    expected_offsets = set(range(0, len(code), 4))
    if visited != expected_offsets:
        raise ValueError(f"instruction coverage gap: {sorted(expected_offsets - visited)}")
    return {"cases": total, "mismatches": 0, "visited_instructions": len(visited),
            "total_instructions": len(code) // 4, "random_seed": SEED,
            "random_cases": random_cases, "grade_histogram": dict(sorted(results.items())),
            "emulation": "original bytes relocated without edits; per-CPU memory supplied by harness",
            "original_source_recovered": False, "whole_ios_reconstructed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--profile", type=Path, default=HERE / "profile.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--random-cases", type=int, default=16384)
    args = parser.parse_args()
    if not 0 <= args.random_cases <= 100000:
        parser.error("--random-cases must be 0..100000")
    profile = json.loads(args.profile.read_text())
    offset, code = function_bytes(args.kernel.read_bytes(), profile)
    report = verify(code, profile, args.library, args.random_cases)
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    va = int(profile["function_va"], 16)
    instructions = list(decoder.disasm(code, va))
    if len(instructions) * 4 != len(code):
        raise ValueError("disassembler did not account for every instruction")
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "original.asm").write_text("\n".join(
        f"{item.address:#018x}  {item.bytes.hex():8s}  {item.mnemonic:8s} {item.op_str}"
        for item in instructions) + "\n")
    report.update(profile=profile, function_file_offset=offset,
                  library_sha256=hashlib.sha256(args.library.read_bytes()).hexdigest())
    (args.output / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {report['cases']} cases, 0 mismatches, "
          f"{report['visited_instructions']}/{report['total_instructions']} instructions covered")


if __name__ == "__main__":
    main()

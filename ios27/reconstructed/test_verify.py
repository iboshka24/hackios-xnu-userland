import hashlib
import struct
import unittest

import verify_grade as recovery


def sample():
    name = b"com.apple.kernel\0"
    size = (32 + len(name) + 7) & ~7
    entry = struct.pack("<IIQQII", 0x80000035, size, 0, 0x100, 32, 0) + name.ljust(size - 32, b"\0")
    segment = struct.pack("<II16sQQQQiiII", 0x19, 72, b"__TEXT_EXEC", 0x8000, 0x1000,
                          0x1000, 4, 5, 5, 0, 0)
    def header(kind, length):
        return struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, kind, 1, length, 0, 0)
    data = bytearray(0x1004)
    data[:32 + size] = header(12, size) + entry
    data[0x100:0x100 + 104] = header(2, 72) + segment
    code = bytes.fromhex("c0035fd6")  # Synthetic RET fixture, not extracted Apple code.
    data[0x1000:] = code
    data = bytes(data)
    profile = {"kernel_sha256": hashlib.sha256(data).hexdigest(), "fileset_entry": "com.apple.kernel",
               "function_va": "0x8000", "function_size": 4, "function_sha256": hashlib.sha256(code).hexdigest()}
    return data, profile


class RecoveryTests(unittest.TestCase):
    def test_fileset_and_virtual_address_mapping(self):
        data, profile = sample()
        self.assertEqual(recovery.function_bytes(data, profile), (0x1000, bytes.fromhex("c0035fd6")))

    def test_kernel_and_function_fingerprints_are_mandatory(self):
        data, profile = sample()
        with self.assertRaisesRegex(ValueError, "kernel SHA256"):
            recovery.function_bytes(data + b"x", profile)
        profile["function_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            recovery.function_bytes(data, profile)

    def test_absent_entry_and_invalid_extent_fail(self):
        data, profile = sample()
        profile["fileset_entry"] = "absent"
        with self.assertRaisesRegex(ValueError, "absent"):
            recovery.function_bytes(data, profile)
        profile["fileset_entry"] = "com.apple.kernel"
        profile["function_size"] = 5000
        with self.assertRaisesRegex(ValueError, "extent"):
            recovery.function_bytes(data, profile)
        profile["function_size"], profile["function_va"] = 4, "0x9000"
        with self.assertRaisesRegex(ValueError, "executable segment"):
            recovery.function_bytes(data, profile)

    def test_malformed_command_is_not_scanned_past_its_bounds(self):
        data, _ = sample()
        data = bytearray(data)
        struct.pack_into("<I", data, 36, 0)
        with self.assertRaisesRegex(ValueError, "load command"):
            list(recovery.commands(data, 0))


if __name__ == "__main__":
    unittest.main()

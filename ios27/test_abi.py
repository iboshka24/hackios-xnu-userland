from pathlib import Path
import plistlib
import struct
import tempfile
import unittest

import abi
import prepare


def macho(commands=(), subtype=0x8000000C, tail=b""):
    body = b"".join(commands)
    return struct.pack("<8I", 0xFEEDFACF, abi.ARM64, subtype, 2,
                       len(commands), len(body), 0, 0) + body + tail


def build_version():
    return struct.pack("<6I", 0x32, 24, 2, 27 << 16, 27 << 16, 0)


class AbiTests(unittest.TestCase):
    def test_x1_is_not_mislabeled_as_ordinary_arm64(self):
        result = abi.inspect_image(macho([build_version()]))
        self.assertEqual(result["architecture"], "arm64e_x1")
        self.assertEqual(result["cpu_subtype_base"], 12)
        self.assertEqual(result["cpu_capabilities"], 0x80000000)
        self.assertEqual(result["build_versions"][0]["minimum"], "27.0.0")
        self.assertFalse(result["boot_compatibility_verified"])

    def test_unknown_subtype_stays_unknown(self):
        self.assertEqual(abi.inspect_image(macho(subtype=99))["architecture"], "unknown_99")

    def test_dyld_path(self):
        command = struct.pack("<3I", 0xE, 32, 12) + b"/usr/lib/dyld\0".ljust(20, b"\0")
        self.assertEqual(abi.inspect_image(macho([command]))["dyld"], "/usr/lib/dyld")

    def test_malformed_headers_and_commands_fail(self):
        cases = (b"", b"\0" * 32, macho([struct.pack("<II", 0, 0)]),
                 macho([struct.pack("<II", 0, 16)]), macho([struct.pack("<II", 0, 9) + b"x"]))
        for data in cases:
            with self.subTest(data=data[:8]), self.assertRaises(ValueError):
                abi.inspect_image(data)

    def test_unterminated_dyld_path_fails(self):
        command = struct.pack("<3I", 0xE, 16, 12) + b"abcd"
        with self.assertRaisesRegex(ValueError, "unterminated"):
            abi.inspect_image(macho([command]))

    def test_chained_layout_is_inspected_not_claimed_translated(self):
        layout = struct.pack("<IHHQIH", 24, 16384, 12, 0, 0, 1) + struct.pack("<H", 0)
        blob = struct.pack("<7I", 0, 28, 60, 60, 0, 1, 0) + struct.pack("<II", 1, 8) + layout
        command = struct.pack("<4I", 0x80000034, 16, 48, len(blob))
        result = abi.inspect_image(macho([command], tail=blob))["chained_fixups"][0]
        self.assertEqual(result["layouts"][0]["pointer_format"], 12)
        self.assertEqual(result["layouts"][0]["page_size"], 16384)
        self.assertFalse(result["bindings_decoded"])

    def test_chained_layout_bounds(self):
        with self.assertRaises(ValueError):
            abi.fixups(b"\0" * 28, 0, 28)
        blob = struct.pack("<7I", 0, 28, 0, 0, 0, 0, 0) + struct.pack("<I", 129)
        with self.assertRaisesRegex(ValueError, "segments"):
            abi.fixups(blob, 0, len(blob))

    def test_file_inspection_and_malformed_mmap_cleanup(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "launchd"
            path.write_bytes(macho([build_version()]))
            self.assertEqual(abi.inspect_file(path)["size"], path.stat().st_size)
            path.write_bytes(macho([struct.pack("<II", 0, 0)]))
            with self.assertRaises(ValueError):
                abi.inspect_file(path)


class PreparationTests(unittest.TestCase):
    def test_system_version_and_recovery_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root / "System/Library/CoreServices/SystemVersion.plist"
            path.parent.mkdir(parents=True)
            value = {"ProductVersion": "27.0.1", "ProductBuildVersion": "24A446", "ReleaseType": "Darwin Recovery"}
            path.write_bytes(plistlib.dumps(value))
            self.assertEqual(prepare.check_version(root, {"version": "27.0.1", "build": "24A446"}), value)
            with self.assertRaises(ValueError):
                prepare.check_version(root, {"version": "16.5", "build": "20F66"})
            value["ReleaseType"] = "User"
            path.write_bytes(plistlib.dumps(value))
            with self.assertRaisesRegex(ValueError, "RecoveryOS"):
                prepare.check_version(root, {"version": "27.0.1", "build": "24A446"})

    def test_real_apfs_probe_builder_with_synthetic_binaries(self):
        with tempfile.TemporaryDirectory() as folder:
            session, root = Path(folder) / "session", Path(folder) / "root"
            session.mkdir()
            for name in ("sbin/launchd", "usr/lib/dyld"):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(macho([build_version()]))
            image = prepare.build_probe(root, session)
            with image.open("rb") as stream:
                stream.seek(32)
                self.assertEqual(stream.read(4), b"NXSB")
            self.assertEqual((session / "probe-root/sbin/launchd").read_bytes(), (root / "sbin/launchd").read_bytes())


if __name__ == "__main__":
    unittest.main()

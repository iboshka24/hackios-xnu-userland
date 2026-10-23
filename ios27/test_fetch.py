import io
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest import mock
import zipfile

import fetch

TARGET = {"product": "iPhone19,2", "board": "v63ap", "version": "27.0.1", "build": "24A446"}
URL = "https://updates.cdn-apple.com/test.ipsw"


def fixture(version="27.0.1", board="v63ap", duplicate=False):
    stream = io.BytesIO()
    manifest = {"ProductVersion": version, "ProductBuildVersion": "24A446",
                "SupportedProductTypes": ["iPhone19,2"], "BuildIdentities": [
                    {"Info": {"DeviceClass": board, "RestoreBehavior": "Erase"},
                     "Manifest": {"OS": {"Info": {"Path": "root.dmg.aea"}}}}]}
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("BuildManifest.plist", plistlib.dumps(manifest))
        archive.writestr("Restore.plist", plistlib.dumps({"ProductVersion": version}))
        archive.writestr("root.dmg.aea", b"synthetic component, not Apple firmware")
        if duplicate:
            archive.writestr("root.dmg.aea", b"duplicate")
    stream.seek(0)
    return stream


class Response(io.BytesIO):
    def __init__(self, data, start, end, total, status=206, **headers):
        super().__init__(data)
        self.status = status
        self.headers = {"Content-Range": f"bytes {start}-{end}/{total}", **headers}

    def geturl(self):
        return URL


class RangeTests(unittest.TestCase):
    def test_seek_and_exact_range(self):
        source = fetch.RangeFile(URL, 100)
        source.seek(-4, io.SEEK_END)
        response = Response(b"test", 96, 99, 100, ETag='"same"')
        with mock.patch.object(fetch.urllib.request, "urlopen", return_value=response) as open_url:
            self.assertEqual(source.read(4), b"test")
            self.assertEqual(open_url.call_args.args[0].get_header("Range"), "bytes=96-99")
        self.assertEqual((source.tell(), source.bytes_fetched, source.etag), (100, 4, '"same"'))
        self.assertEqual(source.read(), b"")

    def test_ignored_range_rejected_without_reading_full_body(self):
        response = Response(b"whole archive", 0, 3, 100, status=200)
        with mock.patch.object(fetch.urllib.request, "urlopen", return_value=response), \
                mock.patch.object(response, "read") as read:
            with self.assertRaisesRegex(ValueError, "ignored Range"):
                fetch.RangeFile(URL, 100).read(4)
            read.assert_not_called()

    def test_wrong_range_and_short_response_are_rejected(self):
        for response in (Response(b"test", 1, 4, 100), Response(b"tes", 0, 3, 100),
                         Response(b"extra", 0, 3, 100)):
            with mock.patch.object(fetch.urllib.request, "urlopen", return_value=response):
                with self.assertRaises(ValueError):
                    fetch.RangeFile(URL, 100).read(4)

    def test_changed_etag_rejected(self):
        source = fetch.RangeFile(URL, 100)
        source.etag = '"old"'
        with mock.patch.object(fetch.urllib.request, "urlopen", return_value=Response(b"test", 0, 3, 100, ETag='"new"')):
            with self.assertRaisesRegex(ValueError, "changed"):
                source.read(4)

    def test_bounds_and_urls(self):
        source = fetch.RangeFile(URL, 100)
        for offset, whence in ((-1, 0), (101, 0), (1, 7)):
            with self.assertRaises(ValueError):
                source.seek(offset, whence)
        with self.assertRaises(ValueError):
            fetch.RangeFile(URL, fetch.MAX_RANGE + 1).read()
        for url in ("http://updates.cdn-apple.com/a", "https://evil.test/a",
                    "https://updates.cdn-apple.com.evil.test/a", "https://user@updates.cdn-apple.com/a"):
            with self.assertRaises(ValueError):
                fetch.apple_url(url)

    def test_zipfile_reads_remote_seekable_fixture(self):
        data = fixture().getvalue()

        def open_range(request, **kwargs):
            start, end = map(int, request.get_header("Range")[6:].split("-"))
            return Response(data[start:end + 1], start, end, len(data))

        with mock.patch.object(fetch.urllib.request, "urlopen", side_effect=open_range), \
                zipfile.ZipFile(fetch.RangeFile(URL, len(data))) as archive:
            report, plists = fetch.inventory(archive, TARGET)
        self.assertEqual(report["target"]["build"], "24A446")
        self.assertIn("BuildManifest.plist", plists)
        self.assertFalse(report["ios27_boot_verified"])


class InventoryTests(unittest.TestCase):
    def test_exact_identity_and_no_boot_claim(self):
        with zipfile.ZipFile(fixture()) as archive:
            report, plists = fetch.inventory(archive, TARGET)
        self.assertEqual(report["selected_identity"], 0)
        self.assertTrue(report["identities"][0]["components"]["OS"]["aea_name"])
        self.assertFalse(report["ready_for_boot"])
        self.assertFalse(report["full_ipsw_sha256_verified"])
        self.assertEqual(len(report["manifest_sha256"]), 64)

    def test_wrong_version_or_board_fail(self):
        for source in (fixture(version="16.5"), fixture(board="d22ap")):
            with zipfile.ZipFile(source) as archive, self.assertRaises(ValueError):
                fetch.inventory(archive, TARGET)

    def test_duplicate_names_fail(self):
        with self.assertWarns(UserWarning):
            source = fixture(duplicate=True)
        with zipfile.ZipFile(source) as archive, self.assertRaisesRegex(ValueError, "duplicate"):
            fetch.inventory(archive, TARGET)

    def test_component_extraction_and_existing_file_preservation(self):
        with tempfile.TemporaryDirectory() as folder, zipfile.ZipFile(fixture()) as archive:
            report, _ = fetch.inventory(archive, TARGET)
            identity = report["identities"][0]
            extracted = fetch.extract_component(archive, identity, "OS", Path(folder))
            path = Path(extracted["path"])
            self.assertEqual(path.read_bytes(), b"synthetic component, not Apple firmware")
            self.assertTrue(extracted["zip_crc32_verified"])
            reused = fetch.extract_component(archive, identity, "OS", Path(folder))
            self.assertTrue(reused["reused"])
            self.assertEqual(reused["sha256"], extracted["sha256"])
            path.write_bytes(b"user work")
            with self.assertRaisesRegex(ValueError, "preserving"):
                fetch.extract_component(archive, identity, "OS", Path(folder))
            self.assertEqual(path.read_bytes(), b"user work")
            self.assertEqual(len(list(Path(folder).iterdir())), 1)

    def test_missing_and_unsafe_components_fail(self):
        with tempfile.TemporaryDirectory() as folder, zipfile.ZipFile(fixture()) as archive:
            report, _ = fetch.inventory(archive, TARGET)
            identity = report["identities"][0]
            with self.assertRaisesRegex(ValueError, "missing"):
                fetch.extract_component(archive, identity, "Absent", Path(folder))
            identity["components"]["OS"]["path"] = "../root.dmg.aea"
            archive.NameToInfo["../root.dmg.aea"] = archive.getinfo("root.dmg.aea")
            with self.assertRaisesRegex(ValueError, "unsafe"):
                fetch.extract_component(archive, identity, "OS", Path(folder))


if __name__ == "__main__":
    unittest.main()

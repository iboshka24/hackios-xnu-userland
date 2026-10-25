import unittest

import verify_dyld as recovery


class DyldRecoveryTests(unittest.TestCase):
    def test_function_start_deltas(self):
        self.assertEqual(recovery.uleb_starts(bytes((16, 128, 1, 0)), 0x1000), [0x1010, 0x1090])
        for blob in (b"\x80", b"\x01", b"\xff" * 9 + b"\x02\0"):
            with self.assertRaises(ValueError):
                recovery.uleb_starts(blob, 0)

    def test_method_inventory_is_explicit_and_unique(self):
        self.assertEqual(len(recovery.METHODS), 19)
        self.assertEqual(len({row[3] for row in recovery.METHODS}), 19)
        self.assertEqual(len({row[:2] for row in recovery.METHODS}), 19)
        self.assertEqual(sum(row[0] == "header" for row in recovery.METHODS), 10)

    def test_header_domains_include_checked_rejection_and_respect_unsafe_preconditions(self):
        checked = list(recovery.header_cases(0, True))
        unsafe = list(recovery.header_cases(0, False))
        self.assertTrue(any(length < 28 for _, length in checked))
        self.assertTrue(all(length >= 28 and len(data) >= length for data, length in unsafe))

    def test_next_fields_cover_their_entire_delta_domains(self):
        for operation, shift, width in ((1, 51, 12), (2, 51, 12), (3, 40, 16)):
            values = {(word >> shift) & ((1 << width) - 1) for word in recovery.word_cases(operation, 0)}
            self.assertEqual(values, set(range(1 << width)))

    def test_case_generators_are_reproducible(self):
        for make in (lambda: recovery.arch_cases(3), lambda: recovery.header_cases(3, True),
                     lambda: recovery.word_cases(4, 3)):
            self.assertEqual(list(make()), list(make()))

    def test_wrong_dyld_is_rejected_before_parsing(self):
        with self.assertRaisesRegex(ValueError, "SHA256"):
            recovery.load_methods(b"not dyld", {"sha256": "0" * 64})


if __name__ == "__main__":
    unittest.main()

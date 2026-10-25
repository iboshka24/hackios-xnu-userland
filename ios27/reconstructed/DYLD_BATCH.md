# dyld-27062: batch recovery

`dyld_macho.c` / `.h` reconstruct the behavior of **19 original C++ methods**
behind three explicit C entry points. This is not 19 newly exported C functions,
not Apple's source, and not a complete dyld reconstruction.

Input: the unchanged iPhone19,2 iOS 27.0.1 / 24A446 RecoveryOS `/usr/lib/dyld`.
Its SHA256 is pinned in `dyld_profile.json`. Unlike the stripped kernel grader,
these methods have actual names in the binary's nlist table. Their boundaries
are resolved from `LC_FUNCTION_STARTS` and checked against executable segments.
No file offsets or instruction words are embedded in the C implementation.

Recovered groups:

| Original methods | Count | C entry point |
|---|---:|---|
| Header / UnsafeHeader classification, pointer size, flags, page policy and command size | 10 | `ios27_header_query` |
| Architecture PAC classification, equality and instruction-family predicates | 4 | `ios27_arch_query` |
| 64-bit, 64-bit kernel-cache and shared-cache-v2 chain next-location methods | 3 | `ios27_chain_query` |
| Generic64 target unpacking and addend extraction | 2 | `ios27_chain_query` |

The operation enums are this C adapter's API, **not Mach-O CPU subtypes or
DYLD_CHAINED_PTR wire-format numbers**. The verifier records the exact original
symbol corresponding to every operation.

## Validation performed on Windows

```text
19 methods / 18 distinct machine-code bodies
133298 differential cases
0 mismatches
190/190 original instructions covered across the selected methods
```

Unicorn executes original bytes relocated without edits. Header and architecture
object layouts and pointer-loaded words are supplied as explicit test context.
No X1 instruction lowering or replacements are used in this batch.
One pair of original next-location methods has identical bytes; both named
methods are checked independently and the distinct-body count is reported.

All 4,096 hop counts of each selected 12-bit chain and all 65,536 hop counts
of the selected 16-bit chain are exercised, along with bit boundaries and random
words. All 256 Generic64 addend byte values are exercised. This is not exhaustive
verification over every possible 64-bit word or execution on Apple hardware.

Checked Header methods reject short spans with BRK; the C adapter represents
that rejection as status 0 and clears the result. UnsafeHeader methods are
compared only with their required readable-header precondition. The adapter
additionally guards its own public input pointers and lengths.

Two observed details are retained rather than "corrected":

- `Generic64::signExtendedAddend` zero-extends its byte in this binary.
- `UnsafeHeader::headerAndLoadCommandsSize` uses wrapping 32-bit addition.
  Its result must not be used as a trusted allocation size without separate
  checked arithmetic and file-bound validation.

The previous kernel-grade recovery also passes against the combined DLL:
33,478 cases, 0 mismatches. Total differential cases across both sets: 166,776.

## Build and reproduce

From the HackiOS workspace root, using the existing tool paths:

```powershell
$tools = 'C:\Users\ibrohim\AppData\Local\Temp\opencode\hackios-tools'
$zig = "$tools\zig\zig-x86_64-windows-0.17.0\zig.exe"
$python = "$tools\recovery-python\Scripts\python.exe"
& $zig cc -std=c11 -O2 -Wall -Wextra -Werror -shared ios27/reconstructed/arch_grade.c ios27/reconstructed/dyld_macho.c -o out/reconstructed-ios27/ios27_reconstructed.dll
& $python ios27/reconstructed/verify_dyld.py --dyld ios27/artifacts/recovery/rootfs/usr/lib/dyld --library out/reconstructed-ios27/ios27_reconstructed.dll --output out/reconstructed-ios27/dyld-batch
& $zig cc -std=c11 -O2 -Wall -Wextra -Werror ios27/reconstructed/arch_grade.c ios27/reconstructed/dyld_macho.c ios27/reconstructed/test_dyld_api.c -o out/reconstructed-ios27/test_dyld_api.exe
& .\out\reconstructed-ios27\test_dyld_api.exe
& $python -m unittest discover -s ios27/reconstructed -p 'test_*.py' -v
```

The original per-method assembly, addresses, function hashes, case counts and
rejection counts remain local in `out/reconstructed-ios27/dyld-batch/`.
The source commit contains no Apple binary or extracted original instruction bytes.

X1-authenticated methods, the full chained-fixup parser, actual fixup application,
dyld process bootstrap, kernel integration and iOS UI boot are not provided by
this batch. The C entry points are format/architecture primitives, not CPU emulators.

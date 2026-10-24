# iOS 27 architecture grading: behavioral reconstruction

**This is reconstructed C behavior, not Apple's original source and not a complete iOS reconstruction.**

## Input and identification

Input: iPhone19,2 / iOS 27.0.1 / 24A446,
`kernelcache.release.v6x-pandia.decompressed`, XNU `13432.2.10~2`.
The fileset's `com.apple.kernel` has no usable symbol name for this function.
Its identity as `ml_grade_binary` is a **source/control-flow correlation**, not a recovered symbol.

The public older XNU implementation at the URL in `profile.json` defines the
grading API and ordinary ARM64/ARM64e behavior. The new X1 path was recovered
from the actual iOS 27 instructions, not copied from that older source.

- Original virtual range: `0xfffffe000b2936f8..0xfffffe000b2937c4` (end exclusive).
- Original file offset: `0x428f6f8`; size: **204 bytes / 51 instructions**.
- Kernel and function SHA256 fingerprints are pinned in `profile.json`.
- The original reads TPIDR_EL1, follows the pointer at thread offset `0x1b8`,
  and reads a subtype at offset `8`. Calling it the host CPU subtype is a
  source-backed interpretation; the offsets and loads are directly observed.

The scanner used during discovery searched executable code for subtype-2 and
subtype-12 comparisons and the grading return values, then examined the complete
leaf function. The reproducible verifier uses the pinned range and fingerprints;
it is **not an automatic general-purpose decompiler**.

## Recovered behavior

All CPU types except `0x0100000c` are rejected with grade 0.

| Host subtype | Requested 0 / ARM64 | Requested 1 / V8 | Requested 2 / ARM64e | Requested 12 / X1 |
|---|---:|---:|---:|---:|
| 1 | 9 | 10 | 0 | 0 |
| 2 | 9 | 10 | 11 or 12 | 0 |
| 12 | 9 | 10 | 11 or 12 | 13 or 14 |
| Other | 0 | 0 | 0 | 0 |

For ARM64e/X1, bit 31 of the separately supplied feature flags must be set.
Otherwise the grade is 0. With `features & 0x0f000000 == 0`, the higher grade is
returned; other version bits select the lower grade. A positive grade expresses
a preference, not proof that exec, PAC or shared-region setup will succeed.

`arch_grade.c` makes the environment explicit as `host_subtype`. **Its fourth
argument is not the original function's fourth argument**: the public grading
signature has an unused simulator-policy boolean, while the original obtains
its host subtype from per-CPU memory. This C interface is not a drop-in XNU patch.
The requested subtype and feature flags are separate inputs: a Mach-O value
`0x8000000c` is represented as subtype `12` and features `0x80000000`, not passed
whole as the signed subtype argument.

## Differential validation actually performed

On Windows, the C implementation was compiled to a native DLL using Zig 0.17.0
with `-std=c11 -O2 -Wall -Wextra -Werror`.
Unicorn 2.1.4 executed the original function bytes, relocated to a low virtual
address **without changing any instruction**. All branches are local; there are
no calls or absolute code references in this function. The harness supplies
TPIDR_EL1 and the two observed memory loads. Each run is limited to 200 instructions.

Result:

```text
PASS: 33478 cases, 0 mismatches, 51/51 instructions covered
```

The total is 17,094 boundary combinations plus 16,384 deterministic random cases
(seed 27). Grades 0, 9, 10, 11, 12, 13 and 14 were all observed. This is a
differential test and complete instruction coverage, **not exhaustive proof over
every 32-bit input or validation on an Apple CPU**.

The assembly and full result are local, ignored artifacts:

```text
out/reconstructed-ios27/original.asm
out/reconstructed-ios27/verification.json
out/reconstructed-ios27/arch_grade.dll
```

No kernelcache, extracted function bytes, Apple header or original disassembly
is added to the source commit.

## Reproduce from the workspace root

```powershell
$tools = 'C:\Users\ibrohim\AppData\Local\Temp\opencode\hackios-tools'
$python = "$tools\recovery-python\Scripts\python.exe"
$zig = "$tools\zig\zig-x86_64-windows-0.17.0\zig.exe"
New-Item -ItemType Directory -Path out/reconstructed-ios27 -Force
& $zig cc -std=c11 -O2 -Wall -Wextra -Werror -shared ios27/reconstructed/arch_grade.c -o out/reconstructed-ios27/arch_grade.dll
& $python -m unittest discover -s ios27/reconstructed -p test_verify.py -v
& $python ios27/reconstructed/verify_grade.py --kernel ios27/artifacts/recovery/kernelcache.raw/kernelcache.release.v6x-pandia.decompressed --library out/reconstructed-ios27/arch_grade.dll --output out/reconstructed-ios27
```

The recovery Python environment uses the versions in `requirements.txt`.
For a new environment install that file with pip/uv before running the verifier.
On Linux, build a shared `.so` instead and pass its path as `--library`;
that host configuration has not been tested here.

## What remains

Only this function's stable-input behavior has been reconstructed. The iOS 27
exec implementation, PAC key management, task state, authenticated shared regions,
dyld, launchd and SpringBoard have not been reconstructed by this change.
The standalone C model does not modify the existing XNU image or make it boot iOS 27.

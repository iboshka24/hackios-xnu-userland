/* Keep the test active when the compiler's optimized preset defines NDEBUG. */
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include "dyld_macho.h"

static void
put32(uint8_t *bytes, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) {
        bytes[i] = (uint8_t)(value >> (i * 8));
    }
}

int
main(void)
{
    uint8_t header[32] = {0};
    uint64_t result = 123;
    put32(header, UINT32_C(0xfeedfacf));
    put32(header + 4, IOS27_CPU_ARM64);
    put32(header + 8, UINT32_C(0x8000000c));
    put32(header + 12, 2);
    put32(header + 24, 4);
    assert(ios27_header_query(IOS27_HEADER_IS64, header, 32, &result) && result == 1);
    assert(ios27_header_query(IOS27_HEADER_POINTER_SIZE, header, 32, &result) && result == 8);
    assert(ios27_header_query(IOS27_HEADER_IS_DYLD_MANAGED, header, 32, &result) && result == 1);
    assert(ios27_header_query(IOS27_HEADER_IS_DYLIB, header, 32, &result) && result == 0);
    assert(ios27_header_query(IOS27_HEADER_USES_16K_PAGES, header, 32, &result) && result == 1);
    put32(header + 20, UINT32_C(0xfffffff0));
    assert(ios27_header_query(IOS27_HEADER_AND_COMMANDS_SIZE, header, 32, &result) && result == 16);
    put32(header + 24, UINT32_C(0x00010000));
    assert(ios27_header_query(IOS27_HEADER_USES_WEAK_DEFS, header, 32, &result) && result == 1);
    assert(!ios27_header_query(IOS27_HEADER_IS64, header, 27, &result) && result == 0);
    assert(!ios27_header_query(IOS27_HEADER_IS64, NULL, 32, &result) && result == 0);
    assert(!ios27_header_query(99, header, 32, &result) && result == 0);
    assert(!ios27_header_query(IOS27_HEADER_IS64, header, 32, NULL));
    assert(ios27_arch_query(IOS27_ARCH_USES_AUTH, IOS27_CPU_ARM64, UINT32_C(0x8000000c), 0, 0));
    assert(!ios27_arch_query(IOS27_ARCH_USES_AUTH, UINT32_C(0x0200000c), 12, 0, 0));
    assert(!ios27_arch_query(IOS27_ARCH_EQUAL, IOS27_CPU_ARM64, 2, IOS27_CPU_ARM64, UINT32_C(0x80000002)));
    assert(ios27_arch_query(IOS27_ARCH_EQUAL, 7, 2, 7, UINT32_C(0x80000002)));
    assert(ios27_chain_query(IOS27_CHAIN_NEXT_64, UINT64_C(5) << 51, 0x1000, &result) && result == 0x1014);
    assert(ios27_chain_query(IOS27_CHAIN_NEXT_64, UINT64_C(1) << 63, 0x1000, &result) && result == 0);
    assert(ios27_chain_query(IOS27_CHAIN_NEXT_SHARED_V2, UINT64_C(65535) << 40, 0x1000, &result) && result == 0x40ffc);
    uint64_t pointer = UINT64_C(0x123456789) | (UINT64_C(0xa5) << 36);
    assert(ios27_chain_query(IOS27_CHAIN_UNPACK_TARGET_64, pointer, 0, &result) && result == UINT64_C(0xa500000123456789));
    assert(ios27_chain_query(IOS27_CHAIN_ADDEND_64, UINT64_C(255) << 24, 0, &result) && result == 255);
    assert(!ios27_chain_query(99, 0, 0, &result) && result == 0);
    assert(!ios27_chain_query(IOS27_CHAIN_NEXT_64, 0, 0, NULL));
    puts("PASS reconstructed dyld C API: header guards, architecture flags, chains, overflow and addends");
    return 0;
}

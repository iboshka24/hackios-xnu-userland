/* Behavioral reconstruction of 19 symbol-identified methods in dyld-27062.
 * Not original Apple source; original C++ methods are grouped behind three C entry points.
 */
#include "dyld_macho.h"

#define MACH64_MAGIC UINT32_C(0xfeedfacf)
#define CPU_ARM64_32 UINT32_C(0x0200000c)
#define CPU_X86_64 UINT32_C(0x01000007)

static uint32_t
read32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

int
ios27_header_query(uint32_t operation, const void *bytes, size_t length,
                   uint64_t *result)
{
    if (result == NULL) {
        return 0;
    }
    *result = 0;
    if (bytes == NULL || length < 28) {
        return 0;
    }
    const uint8_t *data = bytes;
    uint32_t magic = read32(data), cpu = read32(data + 4);
    uint32_t subtype = read32(data + 8), kind = read32(data + 12);
    uint32_t commands_size = read32(data + 20), flags = read32(data + 24);
    switch (operation) {
    case IOS27_HEADER_IS64:
        *result = magic == MACH64_MAGIC;
        break;
    case IOS27_HEADER_IS_DYLIB:
        *result = kind == 6;
        break;
    case IOS27_HEADER_IS_BUNDLE:
        *result = kind == 8;
        break;
    case IOS27_HEADER_IS_DYLD_MANAGED:
        *result = kind == 6 || kind == 8 || (kind == 2 && (flags & 4) != 0);
        break;
    case IOS27_HEADER_POINTER_SIZE:
        *result = magic == MACH64_MAGIC ? 8 : 4;
        break;
    case IOS27_HEADER_USES_WEAK_DEFS:
        *result = (flags >> 16) & 1;
        break;
    case IOS27_HEADER_MAY_HAVE_TEXT_FIXUPS:
        *result = cpu == 7 || (cpu == CPU_X86_64 && kind == 11);
        break;
    case IOS27_HEADER_USES_16K_PAGES:
        *result = cpu == IOS27_CPU_ARM64 || cpu == CPU_ARM64_32 ||
                  (cpu == 12 && subtype == 12);
        break;
    case IOS27_HEADER_IS_OBJECT:
        *result = kind == 1;
        break;
    case IOS27_HEADER_AND_COMMANDS_SIZE:
        /* The original UnsafeHeader method performs a 32-bit wrapping addition. */
        *result = (uint32_t)(commands_size + (magic == MACH64_MAGIC ? 32u : 28u));
        break;
    default:
        return 0;
    }
    return 1;
}

uint32_t
ios27_arch_query(uint32_t operation, uint32_t cpu, uint32_t subtype,
                 uint32_t other_cpu, uint32_t other_subtype)
{
    uint32_t base = subtype & UINT32_C(0x00ffffff);
    switch (operation) {
    case IOS27_ARCH_USES_AUTH:
        return cpu == IOS27_CPU_ARM64 && (base == 2 || base == 12);
    case IOS27_ARCH_EQUAL:
        return cpu == other_cpu && base == (other_subtype & UINT32_C(0x00ffffff)) &&
               (cpu != IOS27_CPU_ARM64 || subtype == other_subtype);
    case IOS27_ARCH_USES_ARM64:
        return cpu == IOS27_CPU_ARM64 || cpu == CPU_ARM64_32;
    case IOS27_ARCH_USES_X86_64:
        return cpu == CPU_X86_64;
    default:
        return 0;
    }
}

int
ios27_chain_query(uint32_t operation, uint64_t word, uint64_t location,
                  uint64_t *result)
{
    if (result == NULL) {
        return 0;
    }
    *result = 0;
    uint64_t next;
    switch (operation) {
    case IOS27_CHAIN_NEXT_64:
    case IOS27_CHAIN_NEXT_KERNEL_64:
        next = (word >> 51) & UINT64_C(0xfff);
        *result = next == 0 ? 0 : location + next * 4;
        break;
    case IOS27_CHAIN_NEXT_SHARED_V2:
        next = (word >> 40) & UINT64_C(0xffff);
        *result = next == 0 ? 0 : location + next * 4;
        break;
    case IOS27_CHAIN_UNPACK_TARGET_64:
        *result = (word & UINT64_C(0xfffffffff)) | (((word >> 36) & 255) << 56);
        break;
    case IOS27_CHAIN_ADDEND_64:
        /* The observed method zero-extends this byte despite its C++ name. */
        *result = (word >> 24) & 255;
        break;
    default:
        return 0;
    }
    return 1;
}

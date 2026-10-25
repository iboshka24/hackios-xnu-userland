#ifndef IOS27_RECONSTRUCTED_DYLD_MACHO_H
#define IOS27_RECONSTRUCTED_DYLD_MACHO_H
#include <stddef.h>
#include "arch_grade.h"

enum ios27_header_operation {
    IOS27_HEADER_IS64 = 1, IOS27_HEADER_IS_DYLIB, IOS27_HEADER_IS_BUNDLE,
    IOS27_HEADER_IS_DYLD_MANAGED, IOS27_HEADER_POINTER_SIZE,
    IOS27_HEADER_USES_WEAK_DEFS, IOS27_HEADER_MAY_HAVE_TEXT_FIXUPS,
    IOS27_HEADER_USES_16K_PAGES, IOS27_HEADER_IS_OBJECT,
    IOS27_HEADER_AND_COMMANDS_SIZE
};
enum ios27_arch_operation {
    IOS27_ARCH_USES_AUTH = 1, IOS27_ARCH_EQUAL,
    IOS27_ARCH_USES_ARM64, IOS27_ARCH_USES_X86_64
};
enum ios27_chain_operation {
    IOS27_CHAIN_NEXT_64 = 1, IOS27_CHAIN_NEXT_KERNEL_64,
    IOS27_CHAIN_NEXT_SHARED_V2, IOS27_CHAIN_UNPACK_TARGET_64,
    IOS27_CHAIN_ADDEND_64
};

/* C status 0 represents rejected input; checked dyld span guards use BRK instead. */
IOS27_EXPORT int ios27_header_query(uint32_t operation, const void *bytes,
                                   size_t length, uint64_t *result);
IOS27_EXPORT uint32_t ios27_arch_query(uint32_t operation, uint32_t cpu,
                                      uint32_t subtype, uint32_t other_cpu,
                                      uint32_t other_subtype);
/* location and word make the original pointer load explicit, without dereferencing a host pointer. */
IOS27_EXPORT int ios27_chain_query(uint32_t operation, uint64_t word,
                                  uint64_t location, uint64_t *result);
#endif

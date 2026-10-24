#ifndef IOS27_RECONSTRUCTED_ARCH_GRADE_H
#define IOS27_RECONSTRUCTED_ARCH_GRADE_H
#include <stdint.h>

#define IOS27_CPU_ARM64 UINT32_C(0x0100000c)
#define IOS27_PTRAUTH_ABI UINT32_C(0x80000000)
#define IOS27_PTRAUTH_VERSION_MASK UINT32_C(0x0f000000)

#if defined(_WIN32)
#define IOS27_EXPORT __declspec(dllexport)
#else
#define IOS27_EXPORT __attribute__((visibility("default")))
#endif

/* host_subtype substitutes the original function's per-CPU read, not its fourth argument. */
IOS27_EXPORT int ios27_arch_grade(uint32_t cpu_type, int32_t subtype,
                                 uint32_t features, uint32_t host_subtype);
#endif

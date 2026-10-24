/* Behavioral reconstruction from iOS 27.0.1 machine code; NOT Apple's original source.
 * Evidence, attribution limits and differential validation: README.md and profile.json.
 */
#include "arch_grade.h"

int
ios27_arch_grade(uint32_t cpu_type, int32_t subtype, uint32_t features,
                 uint32_t host_subtype)
{
    if (cpu_type != IOS27_CPU_ARM64) {
        return 0;
    }
    if (host_subtype != 1 && host_subtype != 2 && host_subtype != 12) {
        return 0;
    }
    if (subtype == 0) {
        return 9;
    }
    if (subtype == 1) {
        return 10;
    }
    if (host_subtype == 1) {
        return 0;
    }
    if (subtype != 2 && !(host_subtype == 12 && subtype == 12)) {
        return 0;
    }
    if ((features & IOS27_PTRAUTH_ABI) == 0) {
        return 0;
    }
    int grade = subtype == 12 ? 13 : 11;
    return grade + ((features & IOS27_PTRAUTH_VERSION_MASK) == 0);
}

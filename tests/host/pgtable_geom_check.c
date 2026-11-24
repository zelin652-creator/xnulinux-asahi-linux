// SPDX-License-Identifier: GPL-2.0-only
/*
 * Host-compiled check of arm64 16 KiB / 48-bit VA page-table geometry against a
 * configured Linux build tree's generated headers (autoconf.h + asm/pgtable-hwdef.h).
 *
 * Build against a configured Linux output tree O and source tree S:
 *   cc -Wall -Wextra -Werror \
 *      -I "$O/include" -I "$S/arch/arm64/include" -I "$S/include" -I "$S/include/uapi" \
 *      -o pgtable_geom_check tests/host/pgtable_geom_check.c
 */
#include <generated/autoconf.h>

#define __ASSEMBLER__
#include <asm/pgtable-hwdef.h>
#undef __ASSEMBLER__

#include <stdint.h>
#include <stdio.h>

#if !defined(CONFIG_ARM64_16K_PAGES) || (CONFIG_ARM64_VA_BITS != 48)
#error "pgtable_geom_check requires CONFIG_ARM64_16K_PAGES=y and CONFIG_ARM64_VA_BITS=48"
#endif

/* Page granule and table stride */
_Static_assert(PAGE_SHIFT == 14, "PAGE_SHIFT must be 14 (16 KiB)");
_Static_assert(PAGE_SIZE == 16384UL, "PAGE_SIZE must be 16384");
_Static_assert((PAGE_SIZE - 1) == 0x3fffUL, "page offset mask must be 0x3fff");
_Static_assert(PTDESC_ORDER == 3, "8-byte descriptors (order 3)");
_Static_assert(PTDESC_TABLE_SHIFT == 11, "16 KiB granule resolves 11 VA bits per table level");

/* Depth: 4 levels (L0..L3) for 16 KiB pages with 48-bit VA */
_Static_assert(VA_BITS == 48, "VA_BITS must be 48");
_Static_assert(CONFIG_PGTABLE_LEVELS == 4, "16 KiB / 48-bit VA uses 4 translation levels");
_Static_assert(ARM64_HW_PGTABLE_LEVELS(VA_BITS) == 4, "ARM64_HW_PGTABLE_LEVELS(48) must be 4");

/* Level 0 (PGD): top-level table pointed to by TTBR1_EL1 */
_Static_assert(ARM64_HW_PGTABLE_LEVEL_SHIFT(0) == 47, "L0 shift must be 47");
_Static_assert(PGDIR_SHIFT == 47, "PGDIR_SHIFT must be 47");
_Static_assert(PGDIR_SIZE == (1UL << 47), "L0 entry covers 128 TiB");
_Static_assert(PTRS_PER_PGD == 2, "L0 has 2 entries for 48-bit VA on 16 KiB granule");

/* Level 1 (PUD) */
_Static_assert(ARM64_HW_PGTABLE_LEVEL_SHIFT(1) == 36, "L1 shift must be 36");
_Static_assert(PUD_SHIFT == 36, "PUD_SHIFT must be 36");
_Static_assert(PUD_SIZE == (1UL << 36), "L1 entry covers 64 GiB");
_Static_assert(PTRS_PER_PUD == 2048, "L1 has 2048 entries");

/* Level 2 (PMD): block-mapping level (32 MiB blocks on 16 KiB granule) */
_Static_assert(ARM64_HW_PGTABLE_LEVEL_SHIFT(2) == 25, "L2 shift must be 25");
_Static_assert(PMD_SHIFT == 25, "PMD_SHIFT must be 25");
_Static_assert(PMD_SIZE == (32UL << 20), "L2 block size must be 32 MiB");
_Static_assert(PMD_MASK == ~((32UL << 20) - 1), "PMD_MASK must align to 32 MiB");
_Static_assert(PTRS_PER_PMD == 2048, "L2 has 2048 entries");

/* Level 3 (PTE): leaf page level */
_Static_assert(ARM64_HW_PGTABLE_LEVEL_SHIFT(3) == PAGE_SHIFT, "L3 shift must equal PAGE_SHIFT (14)");
_Static_assert(PTRS_PER_PTE == 2048, "L3 has 2048 entries");

/* Physical address mask for 48-bit PA table descriptors ([47:PAGE_SHIFT]) */
#define FKI_PA_MASK_48 (((1ULL << 48) - 1) & ~((1ULL << PAGE_SHIFT) - 1))
_Static_assert(FKI_PA_MASK_48 == 0x0000ffffffffc000ULL, "table PA mask must cover bits [47:14]");

/* Top-level index calculation used by fki_window_l1 */
#define FKI_PGD_INDEX(va) (((uint64_t)(va) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
_Static_assert(FKI_PGD_INDEX(0xffff000000000000ULL) == 0, "low TTBR1 half maps to L0[0]");
_Static_assert(FKI_PGD_INDEX(0xffff800000000000ULL) == 1, "high TTBR1 half maps to L0[1]");
_Static_assert(FKI_PGD_INDEX(0xffffffe000000000ULL) == 1, "kernel high VA maps to L0[1]");

/* Cross-check against xnu-12377.121.6 osfmk/arm64/proc_reg.h (16K granule) */
_Static_assert(PGDIR_SHIFT == 47 && PGDIR_SIZE == 0x0000800000000000ULL, "matches ARM_16K_TT_L0");
_Static_assert(PUD_SHIFT   == 36 && PUD_SIZE   == 0x0000001000000000ULL, "matches ARM_16K_TT_L1");
_Static_assert(PMD_SHIFT   == 25 && PMD_SIZE   == 0x0000000002000000ULL, "matches ARM_16K_TT_L2 (32 MiB block)");
_Static_assert(PAGE_SHIFT  == 14 && PAGE_SIZE  == 0x0000000000004000ULL, "matches ARM_16K_TT_L3");

int main(void)
{
	printf("Linux arm64 geometry verified (16 KiB / 48-bit VA, %d levels):\n", CONFIG_PGTABLE_LEVELS);
	printf("  PAGE_SHIFT=%d PAGE_SIZE=%lu PTDESC_TABLE_SHIFT=%d\n",
	    PAGE_SHIFT, (unsigned long)PAGE_SIZE, PTDESC_TABLE_SHIFT);
	printf("  L0 (PGD): shift=%d size=0x%lx ptrs=%d\n",
	    PGDIR_SHIFT, (unsigned long)PGDIR_SIZE, PTRS_PER_PGD);
	printf("  L1 (PUD): shift=%d size=0x%lx ptrs=%d\n",
	    PUD_SHIFT, (unsigned long)PUD_SIZE, PTRS_PER_PUD);
	printf("  L2 (PMD): shift=%d size=0x%lx (%lu MiB block) ptrs=%d\n",
	    PMD_SHIFT, (unsigned long)PMD_SIZE, (unsigned long)(PMD_SIZE >> 20), PTRS_PER_PMD);
	printf("  L3 (PTE): shift=%d size=0x%lx (%lu KiB page) ptrs=%d\n",
	    ARM64_HW_PGTABLE_LEVEL_SHIFT(3), (unsigned long)PAGE_SIZE, (unsigned long)(PAGE_SIZE >> 10), PTRS_PER_PTE);
	printf("  PA mask [47:PAGE_SHIFT]=0x%016llx\n", (unsigned long long)FKI_PA_MASK_48);
	printf("  PGD_INDEX(0xffffffe000000000)=%llu PGD_INDEX(0xfffffe0000000000)=%llu\n",
	    (unsigned long long)FKI_PGD_INDEX(0xffffffe000000000ULL),
	    (unsigned long long)FKI_PGD_INDEX(0xfffffe0000000000ULL));
	return 0;
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Foreign kernel interface, version 0: see include/linux/fki.h.
 *
 * Exports are plain EXPORT_SYMBOL on purpose: this file defines a narrow,
 * stable, semantic interface of its own, and nothing behind it is
 * re-exported.
 */
#include "fki.h"
#include "fki_internal.h"
#include <linux/firmware.h>
#include <linux/gfp.h>
#include <linux/irqflags.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/efi.h>
#include <linux/ioport.h>
#include <linux/module.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/sched.h>
#include <linux/cpumask.h>
#include <linux/vmalloc.h>
#include <asm/arch_timer.h>
#include <asm/neon.h>
#include <asm/pgtable-hwdef.h>
#include <asm/sysreg.h>
#include <asm/tlbflush.h>
#include <asm/barrier.h>
#include <linux/kprobes.h>
#include <linux/hrtimer.h>
#include <linux/kthread.h>
#include <linux/smp.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <asm/stacktrace.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>

int fki_version(void)
{
	return FKI_VERSION;
}
EXPORT_SYMBOL(fki_version);

void fki_log(const char *s, unsigned long len)
{
	pr_info("fki: %.*s\n", (int)len, s);
}
EXPORT_SYMBOL(fki_log);
/* what an operator must see even with the console quiet (an XNU panic, a CPU gone silent): KERN_ALERT */
void fki_log_alert(const char *s, unsigned long len)
{
	pr_alert("fki: %.*s\n", (int)len, s);
}
EXPORT_SYMBOL(fki_log_alert);


/*
 * Out-of-tree form only: stock kernels do not export set_memory_x(). The in-tree FKI
 * patch calls it directly; here it is found once through kallsyms (via a kprobe).
 */
typedef int (*set_memory_fn)(unsigned long addr, int numpages);
typedef struct page *(*alloc_contig_fn)(unsigned long nr_pages, gfp_t gfp, int nid, nodemask_t *nodemask);
typedef void (*free_contig_fn)(unsigned long pfn, unsigned long nr_pages);
static alloc_contig_fn p_alloc_contig;
static free_contig_fn p_free_contig;
struct cma;
static struct cma **p_cma_area;	/* the default CMA area (cma= on the command line), if any */
static struct page *(*p_cma_alloc)(struct cma *, unsigned long, unsigned int, bool);	/* not exported on every kernel */
static bool (*p_cma_release)(struct cma *, const struct page *, unsigned long);
static set_memory_fn p_set_memory_x, p_set_memory_nx;
static const char *p_alloc_name;
static int fki_have_lookup;
static unsigned long p_stext, p_end;
static u64 *p_kimage_voffset;
static int (*p_efi_mem_type)(unsigned long);	/* the firmware's memory map: is the carve-out RAM at all */

static int fki_resolve(void)
{
	static unsigned long (*lookup)(const char *);
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };

	if (p_set_memory_x)
		return 0;
	if (!lookup) {
		if (register_kprobe(&kp))
			return -ENOENT;
		lookup = (void *)kp.addr;
		unregister_kprobe(&kp);
		fki_have_lookup = 1;
	}
	p_set_memory_x = (set_memory_fn)lookup("set_memory_x");
	p_alloc_contig = (alloc_contig_fn)lookup("alloc_contig_pages_noprof");
	p_alloc_name = "alloc_contig_pages_noprof";
	if (!p_alloc_contig) {
		p_alloc_contig = (alloc_contig_fn)lookup("alloc_contig_pages");
		p_alloc_name = "alloc_contig_pages";
	}
	p_free_contig = (free_contig_fn)lookup("free_contig_range");
	p_cma_area = (struct cma **)lookup("dma_contiguous_default_area");
	p_cma_alloc = (void *)lookup("cma_alloc");
	p_cma_release = (void *)lookup("cma_release");
	p_set_memory_nx = (set_memory_fn)lookup("set_memory_nx");
	p_stext = lookup("_stext");
	p_end = lookup("_end");
	p_kimage_voffset = (u64 *)lookup("kimage_voffset");
	p_efi_mem_type = (void *)lookup("efi_mem_type");
	return p_set_memory_x && p_set_memory_nx ? 0 : -ENOENT;
}

int fki_region_alloc(unsigned long size, struct fki_region *r)
{
	unsigned long n = PAGE_ALIGN(size) >> PAGE_SHIFT;
	void *va;
	int err;

	/* vmap() memory is never executable on current kernels; vmalloc + set_memory_x is (out-of-tree form). */
	err = fki_resolve();
	if (err)
		return err;
	va = vzalloc(n << PAGE_SHIFT);
	if (!va)
		return -ENOMEM;
	err = p_set_memory_x((unsigned long)va, n);
	if (err) {
		vfree(va);
		return err;
	}
	r->va = va;
	r->pa = page_to_phys(vmalloc_to_page(va));
	r->size = n << PAGE_SHIFT;
	r->handle = NULL;
	return 0;
}
EXPORT_SYMBOL(fki_region_alloc);

void fki_region_free(struct fki_region *r)
{
	p_set_memory_nx((unsigned long)r->va, r->size >> PAGE_SHIFT);
	vfree(r->va);
}
EXPORT_SYMBOL(fki_region_free);

int fki_blob_get(const char *name, const void **data, unsigned long *size, void **handle)
{
	const struct firmware *fw;
	int err = request_firmware(&fw, name, NULL);

	if (err)
		return err;
	*data = fw->data;
	*size = fw->size;
	*handle = (void *)fw;
	return 0;
}
EXPORT_SYMBOL(fki_blob_get);

void fki_blob_put(void *handle)
{
	release_firmware(handle);
}
EXPORT_SYMBOL(fki_blob_put);

#define FKI_SCTLR_EN (SCTLR_ELx_ENIA | SCTLR_ELx_ENIB | SCTLR_ELx_ENDA | SCTLR_ELx_ENDB)


static __always_inline void keys_read(struct fki_pac_keys *k)
{
	k->ia[0] = read_sysreg_s(SYS_APIAKEYLO_EL1); k->ia[1] = read_sysreg_s(SYS_APIAKEYHI_EL1);
	k->ib[0] = read_sysreg_s(SYS_APIBKEYLO_EL1); k->ib[1] = read_sysreg_s(SYS_APIBKEYHI_EL1);
	k->da[0] = read_sysreg_s(SYS_APDAKEYLO_EL1); k->da[1] = read_sysreg_s(SYS_APDAKEYHI_EL1);
	k->db[0] = read_sysreg_s(SYS_APDBKEYLO_EL1); k->db[1] = read_sysreg_s(SYS_APDBKEYHI_EL1);
	k->ga[0] = read_sysreg_s(SYS_APGAKEYLO_EL1); k->ga[1] = read_sysreg_s(SYS_APGAKEYHI_EL1);
	k->sctlr_en = read_sysreg(sctlr_el1) & FKI_SCTLR_EN;
}

static __always_inline void keys_write(const struct fki_pac_keys *k)
{
	write_sysreg_s(k->ia[0], SYS_APIAKEYLO_EL1); write_sysreg_s(k->ia[1], SYS_APIAKEYHI_EL1);
	write_sysreg_s(k->ib[0], SYS_APIBKEYLO_EL1); write_sysreg_s(k->ib[1], SYS_APIBKEYHI_EL1);
	write_sysreg_s(k->da[0], SYS_APDAKEYLO_EL1); write_sysreg_s(k->da[1], SYS_APDAKEYHI_EL1);
	write_sysreg_s(k->db[0], SYS_APDBKEYLO_EL1); write_sysreg_s(k->db[1], SYS_APDBKEYHI_EL1);
	write_sysreg_s(k->ga[0], SYS_APGAKEYLO_EL1); write_sysreg_s(k->ga[1], SYS_APGAKEYHI_EL1);
	sysreg_clear_set(sctlr_el1, FKI_SCTLR_EN, k->sctlr_en & FKI_SCTLR_EN);
	isb();
}

/*
 * The foreign kernel uses the FP/SIMD registers (its user threads' state, its own SIMD code) without Linux knowing.
 * Linux skips reloading a task's FP/SIMD state when it believes this CPU's registers still hold it, so a task that ran
 * here before would come back with the foreign kernel's register contents (random user-space crashes on the hosted
 * kernel's CPU). Before the foreign kernel runs (on entry, and each time it resumes after Linux ran), save the current
 * task's state and make Linux forget whose state the registers hold: an empty kernel-mode NEON section does both.
 * Nothing of the foreign kernel's needs keeping across that: its kernel code does not keep FP/SIMD values across calls
 * into the host, and it saves its user threads' registers on each exception.
 */
static void fki_fpsimd_forget(void)
{
	struct user_fpsimd_state scratch;	/* where Linux would save a kernel-mode state over a context switch: none here */

	kernel_neon_begin(&scratch);
	kernel_neon_end(&scratch);
}

__attribute__((target("branch-protection=none"))) unsigned long fki_enter(const struct fki_pac_keys *foreign, struct fki_pac_keys *saved)
{
	unsigned long flags;

	fki_fpsimd_forget();
	preempt_disable();
	local_irq_save(flags);
	keys_read(saved);
	keys_write(foreign);
	return flags;
}
EXPORT_SYMBOL(fki_enter);

__attribute__((target("branch-protection=none"))) void fki_leave(unsigned long cookie, const struct fki_pac_keys *saved)
{
	keys_write(saved);
	local_irq_restore(cookie);
	preempt_enable();
}
EXPORT_SYMBOL(fki_leave);

__attribute__((target("branch-protection=none"))) void fki_pac_swap(const struct fki_pac_keys *load, struct fki_pac_keys *save)
{
	keys_read(save);
	keys_write(load);
}
EXPORT_SYMBOL(fki_pac_swap);

fki_u64 fki_counter_frequency(void)
{
	return arch_timer_get_cntfrq();
}
EXPORT_SYMBOL(fki_counter_frequency);

fki_u64 fki_counter(void)
{
	return __arch_counter_get_cntvct();
}
EXPORT_SYMBOL(fki_counter);

void fki_random(void *buf, unsigned long len)
{
	get_random_bytes(buf, len);
}
EXPORT_SYMBOL(fki_random);

int fki_bind_cpu(int cpu)
{
	if (cpu < 0 || cpu >= nr_cpu_ids || !cpu_online(cpu))
		return -EINVAL;
	return set_cpus_allowed_ptr(current, cpumask_of(cpu));
}
EXPORT_SYMBOL(fki_bind_cpu);

void *fki_thread_start(int (*fn)(void *), void *arg, int cpu, const char *name)
{
	struct task_struct *t;

	if (cpu < 0 || cpu >= nr_cpu_ids || !cpu_online(cpu))
		return NULL;
	t = kthread_create(fn, arg, "%s", name);
	if (IS_ERR(t))
		return NULL;
	kthread_bind(t, cpu);
	get_task_struct(t);
	wake_up_process(t);
	return t;
}
EXPORT_SYMBOL(fki_thread_start);

void fki_thread_stop(void *thread)
{
	if (thread) {
		kthread_stop(thread);
		put_task_struct(thread);
	}
}
EXPORT_SYMBOL(fki_thread_stop);

int fki_thread_should_stop(void)
{
	return kthread_should_stop();
}
EXPORT_SYMBOL(fki_thread_should_stop);

void fki_thread_wait(const volatile unsigned long *flag)
{
	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (READ_ONCE(*flag) || kthread_should_stop())
			break;
		schedule();
	}
	__set_current_state(TASK_RUNNING);
}
EXPORT_SYMBOL(fki_thread_wait);

void fki_thread_wake(void *thread)
{
	if (thread)
		wake_up_process(thread);
}
EXPORT_SYMBOL(fki_thread_wake);

void fki_msleep(unsigned int ms)
{
	msleep(ms);
}
EXPORT_SYMBOL(fki_msleep);

/*
 * Foreign kernel faults. Out of tree, the hook is a kprobe on __do_kernel_fault(far, esr, regs), where Linux's abort path
 * goes for a kernel address it has no mapping for (do_mem_abort and do_translation_fault cannot be probed). When
 * the handler resolves the fault, __do_kernel_fault is skipped (return to its caller), and the exception returns to retry
 * the access. The in-tree patch calls the hook from do_translation_fault/do_page_fault directly.
 */
static unsigned long fki_fault_lo, fki_fault_hi;
static int (*fki_fault_handler)(unsigned long far, unsigned long esr, void *regs);

static int fki_fault_pre(struct kprobe *p, struct pt_regs *kregs)
{
	unsigned long far = kregs->regs[0], esr = kregs->regs[1];
	struct pt_regs *regs = (struct pt_regs *)kregs->regs[2];
	int (*h)(unsigned long, unsigned long, void *) = READ_ONCE(fki_fault_handler);

	if (!h || user_mode(regs))
		return 0;
	if ((far < fki_fault_lo || far >= fki_fault_hi) &&
	    (instruction_pointer(regs) < fki_fault_lo || instruction_pointer(regs) >= fki_fault_hi))
		return 0;
	if (h(far, esr, regs))
		return 0;
	instruction_pointer_set(kregs, kregs->regs[30]);	/* __do_kernel_fault returns at once */
	return 1;
}
NOKPROBE_SYMBOL(fki_fault_pre);

unsigned long fki_regs_pc(void *regs) { return instruction_pointer((struct pt_regs *)regs); }
EXPORT_SYMBOL(fki_regs_pc);
unsigned long fki_regs_lr(void *regs) { return ((struct pt_regs *)regs)->regs[30]; }
EXPORT_SYMBOL(fki_regs_lr);
unsigned long fki_regs_pstate(void *regs) { return ((struct pt_regs *)regs)->pstate; }
EXPORT_SYMBOL(fki_regs_pstate);
void fki_regs_set_pc(void *regs, unsigned long pc) { instruction_pointer_set((struct pt_regs *)regs, pc); }
EXPORT_SYMBOL(fki_regs_set_pc);
void fki_regs_set_reg(void *regs, unsigned int n, unsigned long v) { if (n < 31) ((struct pt_regs *)regs)->regs[n] = v; }
EXPORT_SYMBOL(fki_regs_set_reg);
unsigned long fki_regs_reg(void *regs, unsigned int n) { return n < 31 ? ((struct pt_regs *)regs)->regs[n] : 0; }
EXPORT_SYMBOL(fki_regs_reg);

static struct kprobe fki_fault_kp = { .symbol_name = "__do_kernel_fault", .pre_handler = fki_fault_pre };
static int fki_fault_registered;

/*
 * Other kernel-mode exceptions the foreign kernel takes (an FPAC authentication failure, an undefined instruction, a
 * BTI fault) end in die(str, regs, err): offered to the same handler with far 0 and the ESR, before Linux oopses.
 */
static int fki_die_pre(struct kprobe *p, struct pt_regs *kregs)
{
	struct pt_regs *regs = (struct pt_regs *)kregs->regs[1];
	unsigned long esr = kregs->regs[2];
	int (*h)(unsigned long, unsigned long, void *) = READ_ONCE(fki_fault_handler);

	if (!h || !regs || user_mode(regs))
		return 0;
	if (instruction_pointer(regs) < fki_fault_lo || instruction_pointer(regs) >= fki_fault_hi)
		return 0;
	if (h(0, esr, regs))
		return 0;
	instruction_pointer_set(kregs, kregs->regs[30]);	/* die returns at once */
	return 1;
}
NOKPROBE_SYMBOL(fki_die_pre);
static struct kprobe fki_die_kp = { .symbol_name = "die", .pre_handler = fki_die_pre };
static int fki_die_registered;

int fki_fault_register(unsigned long lo, unsigned long hi, int (*handler)(unsigned long far, unsigned long esr, void *regs))
{
	int err;

	if (fki_fault_registered)
		return -EBUSY;
	fki_fault_lo = lo;
	fki_fault_hi = hi;
	WRITE_ONCE(fki_fault_handler, handler);
	err = register_kprobe(&fki_fault_kp);
	if (err) {
		WRITE_ONCE(fki_fault_handler, NULL);
		return err;
	}
	fki_fault_registered = 1;
	fki_die_registered = register_kprobe(&fki_die_kp) == 0;	/* best effort */
	if (!fki_die_registered)
		pr_warn("fki: no die() probe: foreign non-abort exceptions oops\n");
	return 0;
}
EXPORT_SYMBOL(fki_fault_register);

void fki_fault_unregister(void)
{
	if (!fki_fault_registered)
		return;
	unregister_kprobe(&fki_fault_kp);
	if (fki_die_registered) {
		unregister_kprobe(&fki_die_kp);
		fki_die_registered = 0;
		memset(&fki_die_kp, 0, sizeof(fki_die_kp));
		fki_die_kp.symbol_name = "die";
		fki_die_kp.pre_handler = fki_die_pre;
	}
	WRITE_ONCE(fki_fault_handler, NULL);
	fki_fault_registered = 0;
	/* a fresh kprobe struct for the next registration */
	memset(&fki_fault_kp, 0, sizeof(fki_fault_kp));
	fki_fault_kp.symbol_name = "__do_kernel_fault";
	fki_fault_kp.pre_handler = fki_fault_pre;
}
EXPORT_SYMBOL(fki_fault_unregister);

fki_u64 fki_phys_peek(fki_u64 pa)
{
	if (!pfn_valid(PHYS_PFN(pa)))
		return ~0ULL;
	return READ_ONCE(*(u64 *)phys_to_virt(pa & ~7ULL));
}
EXPORT_SYMBOL(fki_phys_peek);

/* ---- contiguous memory and the top foreign window ---- */

#if !defined(CONFIG_ARM64_16K_PAGES) || (CONFIG_ARM64_VA_BITS != 48)
#error "fki.ko requires CONFIG_ARM64_16K_PAGES=y and CONFIG_ARM64_VA_BITS=48"
#endif

#define FKI_BLOCK_SIZE		PMD_SIZE
#define FKI_PA_MASK_48		GENMASK_ULL(47, PAGE_SHIFT)
#define FKI_PGD_INDEX(va)	(((va) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))

static_assert(PAGE_SHIFT == 14);
static_assert(PAGE_SIZE == 16384UL);
static_assert(CONFIG_PGTABLE_LEVELS == 4);
static_assert(PGDIR_SHIFT == 47 && PTRS_PER_PGD == 2);
static_assert(FKI_BLOCK_SIZE == (32UL << 20));

/*
 * The foreign kernel's DRAM, one physically contiguous block of GBs, from the first that works of:
 *  - carve_base/carve_mb: RAM the host kernel does not manage at all (its command line limits it with mem=, the rest is
 *    left for us), mapped here with memremap. Nothing of Linux's ever lands in it: the block is always there.
 *  - reserve_mb: taken from the CMA area when fki loads early in the host's boot. A single page pinned in the area
 *    (a file system's buffer-head page of the block device, allocated movable during the boot) can already be there
 *    and split the area, so this is best effort.
 *  - a CMA or alloc_contig_pages allocation at the time of the call.
 */
static unsigned long carve_base, carve_mb, reserve_mb;
module_param(carve_base, ulong, 0444);
module_param(carve_mb, ulong, 0444);
module_param(reserve_mb, ulong, 0444);
static struct page *resv_pg;
static unsigned long resv_cnt;
static bool resv_used, carve_used;

static void fki_reserve(void)
{
	unsigned long cnt = ALIGN(reserve_mb << 20, FKI_BLOCK_SIZE) >> PAGE_SHIFT;

	if (carve_mb)
		pr_info("fki: %lu MiB at %#lx for the foreign kernel's DRAM (outside the host's memory)\n", carve_mb, carve_base);
	if (!reserve_mb || fki_resolve() || !p_cma_area || !*p_cma_area || !p_cma_alloc)
		return;
	resv_pg = p_cma_alloc(*p_cma_area, cnt, get_order(FKI_BLOCK_SIZE), true);
	if (resv_pg)
		resv_cnt = cnt;
	pr_info("fki: %lu MiB for the foreign kernel's DRAM %s\n", reserve_mb, resv_pg ? "reserved" : "NOT reserved (CMA)");
}

static int fki_carve_check(unsigned long base, unsigned long len)
{
	unsigned long end = base + len;

	if (end < base) {
		pr_err("fki: carve-out [%#lx, %#lx) overflows physical address space\n", base, end);
		return -EINVAL;
	}
	/* RAM in the firmware's map, every 2 MiB of it: a carve-out past the end of the VM's memory (carve_base from a
	 * bigger VM) would map addresses with nothing behind them */
	if (p_efi_mem_type && p_efi_mem_type(base) >= 0) {	/* < 0: no EFI memory map (not an EFI boot) */
		unsigned long a;

		for (a = base; a < end; a += SZ_2M) {
			int t = p_efi_mem_type(a);

			/* free RAM once Linux runs: loader and boot-services code and data, conventional memory */
			if (t != EFI_LOADER_CODE && t != EFI_LOADER_DATA && t != EFI_BOOT_SERVICES_CODE &&
			    t != EFI_BOOT_SERVICES_DATA && t != EFI_CONVENTIONAL_MEMORY) {
				pr_err("fki: carve-out [%#lx, %#lx) is not all RAM (EFI type %d at %#lx); refusing to map (check carve_base, carve_mb and the VM's memory size)\n",
				       base, end, t, a);
				return -EINVAL;
			}
		}
	}
	if (p_stext && p_end && p_kimage_voffset) {
		unsigned long k_start = p_stext - *p_kimage_voffset;
		unsigned long k_end = p_end - *p_kimage_voffset;

		if (base < k_end && k_start < end) {
			pr_err("fki: carve-out [%#lx, %#lx) overlaps Linux kernel image [%#lx, %#lx); refusing to map (boot with nokaslr or adjust carve_base)\n",
			       base, end, k_start, k_end);
			return -EBUSY;
		}
	}
	if (region_intersects(base, len, IORESOURCE_SYSTEM_RAM, IORES_DESC_NONE) != REGION_DISJOINT) {
		pr_err("fki: carve-out [%#lx, %#lx) overlaps IORESOURCE_SYSTEM_RAM; refusing to map (check mem= and carve_base)\n",
		       base, end);
		return -EBUSY;
	}
	if (region_intersects(base, len, IORESOURCE_MEM, IORES_DESC_NONE) != REGION_DISJOINT) {
		pr_err("fki: carve-out [%#lx, %#lx) overlaps busy/reserved IORESOURCE_MEM; refusing to map (check /proc/iomem and carve_base)\n",
		       base, end);
		return -EBUSY;
	}
	return 0;
}

int fki_contig_alloc(unsigned long size, struct fki_region *r)
{
	unsigned long n = 1;
	struct page *pg;
	int err = fki_resolve();

	if (err)
		return err;
	if (carve_mb && !carve_used && ALIGN(size, FKI_BLOCK_SIZE) <= carve_mb << 20 && !(carve_base & (FKI_BLOCK_SIZE - 1))) {
		unsigned long clen = ALIGN(size, FKI_BLOCK_SIZE);
		void *va;

		err = fki_carve_check(carve_base, clen);
		if (err)
			return err;
		va = memremap(carve_base, clen, MEMREMAP_WB);
		if (va) {
			carve_used = true;
			r->va = va;
			r->size = clen;
			memset(r->va, 0, r->size);
			r->pa = carve_base;
			r->handle = (void *)4UL;	/* bit 2: the carve-out */
			return 0;
		}
		pr_warn("fki: carve-out at %#lx not mappable\n", carve_base);
	}
	if (resv_pg && !resv_used && ALIGN(size, FKI_BLOCK_SIZE) >> PAGE_SHIFT <= resv_cnt) {
		resv_used = true;
		r->va = page_address(resv_pg);
		r->size = ALIGN(size, FKI_BLOCK_SIZE);
		memset(r->va, 0, r->size);
		r->pa = page_to_phys(resv_pg);
		r->handle = (void *)((unsigned long)resv_pg | 2);	/* bit 1: the reservation, kept when freed */
		return 0;
	}
	/*
	 * Large blocks (a hosted kernel's DRAM, GBs) come from the CMA area when there is one: a long-running host
	 * fragments its memory with unmovable pages and alloc_contig_pages then fails. CMA blocks are aligned and
	 * sized to FKI_BLOCK_SIZE (PMD_SIZE, 32 MiB on 16 KiB pages); a CMA block's handle has bit 0 set.
	 */
	if (size >= (64UL << 20) && p_cma_area && *p_cma_area && p_cma_alloc && p_cma_release) {
		unsigned long cnt = ALIGN(size, FKI_BLOCK_SIZE) >> PAGE_SHIFT;
		pg = p_cma_alloc(*p_cma_area, cnt, get_order(FKI_BLOCK_SIZE), true);
		if (pg) {
			r->va = page_address(pg);
			memset(r->va, 0, cnt << PAGE_SHIFT);
			r->pa = page_to_phys(pg);
			r->size = cnt << PAGE_SHIFT;
			r->handle = (void *)((unsigned long)pg | 1);
			return 0;
		}
	}
	if (!p_alloc_contig)
		return -ENOENT;
	while ((n << PAGE_SHIFT) < size)
		n <<= 1;
	pg = p_alloc_contig(n, GFP_KERNEL | __GFP_NOWARN, numa_node_id(), NULL);
	if (!pg)
		return -ENOMEM;
	r->va = page_address(pg);
	memset(r->va, 0, n << PAGE_SHIFT);
	r->pa = page_to_phys(pg);
	r->size = n << PAGE_SHIFT;
	r->handle = pg;
	return 0;
}
EXPORT_SYMBOL(fki_contig_alloc);

void fki_contig_free(struct fki_region *r)
{
	if ((unsigned long)r->handle == 4) {
		memunmap(r->va);
		carve_used = false;
		return;
	}
	if ((unsigned long)r->handle & 2) {
		resv_used = false;	/* back to the reservation, for the next run */
		return;
	}
	if ((unsigned long)r->handle & 1) {
		p_cma_release(*p_cma_area, (struct page *)((unsigned long)r->handle & ~1UL), r->size >> PAGE_SHIFT);
		return;
	}
	if (p_free_contig)
		p_free_contig(page_to_pfn((struct page *)r->handle), r->size >> PAGE_SHIFT);
}
EXPORT_SYMBOL(fki_contig_free);

int fki_window_l1(unsigned long va, unsigned long long **l1_va, fki_u64 *l1_pa)
{
	u64 ttbr1 = read_sysreg(ttbr1_el1) & GENMASK_ULL(47, 1);
	u64 *l0 = phys_to_virt(ttbr1 & PAGE_MASK);
	u64 e = READ_ONCE(l0[FKI_PGD_INDEX(va)]);

	if ((e & PGD_TYPE_MASK) != PGD_TYPE_TABLE)
		return -ENOENT;
	*l1_pa = e & FKI_PA_MASK_48;
	*l1_va = phys_to_virt(*l1_pa);
	return 0;
}
EXPORT_SYMBOL(fki_window_l1);

void fki_window_set(unsigned long long *slot, fki_u64 desc)
{
	WRITE_ONCE(*slot, desc);
	dsb(ishst);
	__tlbi(vmalle1is);
	dsb(ish);
	isb();
}
EXPORT_SYMBOL(fki_window_set);

/*
 * Letting Linux run (IRQs on, maybe a reschedule) from inside fki_enter() happens on whatever stack the foreign kernel
 * is on. Linux's exception entry takes a stack whose bit THREAD_SHIFT is set at sp for an overflow and panics, so
 * from a stack that is not this task's, the work runs on a stack of our own laid out like Linux's (the lower half of a
 * 2 * THREAD_SIZE aligned block, which the linear map gives an order-aligned page block).
 */
static void *fki_alt_stack[NR_CPUS];	/* allocated at load: an order-3 atomic allocation can fail once memory is fragmented */
#define FKI_ALT_STACK_ORDER get_order(2 * THREAD_SIZE)

asm(
"	.pushsection .text\n"
"	.type	fki_run_on_stack, %function\n"
"fki_run_on_stack:\n"
"	hint	#34\n"
"	stp	x29, x30, [sp, #-16]!\n"
"	mov	x29, sp\n"
"	mov	x9, sp\n"
"	mov	sp, x2\n"
"	stp	x9, xzr, [sp, #-16]!\n"
"	mov	x9, x0\n"
"	mov	x0, x1\n"
"	blr	x9\n"
"	ldp	x9, xzr, [sp], #16\n"
"	mov	sp, x9\n"
"	ldp	x29, x30, [sp], #16\n"
"	ret\n"
"	.size	fki_run_on_stack, . - fki_run_on_stack\n"
"	.popsection\n");
void fki_run_on_stack(void (*fn)(void *), void *arg, void *top);	/* x0 = fn, x1 = arg, x2 = stack top */

static void fki_linux_runs_body(void (*fn)(void *), void *arg);

/*
 * Linux runs with SError (PSTATE.A) unmasked; the foreign kernel keeps D, A, I and F masked and asserts so in its
 * idle loop. Give it back exactly the exception mask it called with.
 */
struct fki_runs {
	void (*fn)(void *);
	void *arg;
};

/* fn runs with interrupts on and turns them off again; then, before the foreign kernel resumes, fki_fpsimd_forget */
static void fki_runs_then_forget(void *p)
{
	struct fki_runs *r = p;

	r->fn(r->arg);
	local_irq_enable();
	fki_fpsimd_forget();
	local_irq_disable();
}

static void fki_linux_runs(void (*fn)(void *), void *arg)
{
	unsigned long daif = read_sysreg(daif);
	struct fki_runs r = { fn, arg };

	fki_linux_runs_body(fki_runs_then_forget, &r);
	write_sysreg(daif, daif);
}

void fki_linux_runs_ext(void (*fn)(void *), void *arg)
{
	fki_linux_runs(fn, arg);
}

static void fki_linux_runs_body(void (*fn)(void *), void *arg)
{
	unsigned long sp = current_stack_pointer;
	int cpu = smp_processor_id();

	if (on_task_stack(current, sp, 1)) {
		fn(arg);
		return;
	}
	fki_run_on_stack(fn, arg, (char *)fki_alt_stack[cpu] + THREAD_SIZE);
}

struct fki_idle_args { fki_u64 ns; const volatile unsigned int *wake; };

static struct task_struct *fki_idle_task[NR_CPUS];	/* the task sleeping in fki_idle_until on each CPU, for wakeups */

static void fki_idle_body(void *p)
{
	struct fki_idle_args *a = p;
	ktime_t t = ns_to_ktime(a->ns);

	local_irq_enable();
	preempt_enable();
	set_current_state(TASK_UNINTERRUPTIBLE);
	WRITE_ONCE(fki_idle_task[smp_processor_id()], current);
	smp_mb();	/* pairs with fki_kick_cpu: it sees this task, or this sees the word it set first */
	if (!a->wake || !READ_ONCE(*a->wake))
		schedule_hrtimeout_range(&t, 50000, HRTIMER_MODE_REL);
	__set_current_state(TASK_RUNNING);
	WRITE_ONCE(fki_idle_task[smp_processor_id()], NULL);
	preempt_disable();
	local_irq_disable();
}

static void fki_yield_body(void *p)
{
	local_irq_enable();
	preempt_enable();
	cond_resched();
	preempt_disable();
	local_irq_disable();
}

void fki_idle_until(fki_u64 counter_deadline, fki_u64 max_ns, const volatile unsigned int *wake)
{
	u64 now = __arch_counter_get_cntvct(), freq = arch_timer_get_cntfrq(), ns;
	struct fki_idle_args a;

	if (counter_deadline <= now) {
		/* already due: still let Linux take its interrupts and reschedule (an idle loop that never sleeps starves it) */
		fki_linux_runs(fki_yield_body, NULL);
		return;
	}
	ns = div64_u64((counter_deadline - now) * 1000000ULL, freq) * 1000ULL;
	if (ns > max_ns)
		ns = max_ns;
	a.ns = ns;
	a.wake = wake;
	fki_linux_runs(fki_idle_body, &a);
}
EXPORT_SYMBOL(fki_idle_until);

void fki_yield(void)
{
	fki_linux_runs(fki_yield_body, NULL);
}
EXPORT_SYMBOL(fki_yield);

/*
 * Make the foreign kernel on a CPU look at what another CPU left for it: wake it if it sleeps in fki_idle_until,
 * otherwise interrupt that CPU (its user code runs with interrupts on; its kernel looks where it enables its own).
 * Callable with interrupts off.
 */
/*
 * One csd per target CPU, shared by every sender: smp_call_function_single_async's -EBUSY check is not atomic, so two
 * CPUs kicking the same one at once would both queue the same csd, and the doubly linked llist entry loops the target
 * forever in its IPI handler with interrupts off (three or more hosted CPUs: two can kick a third). A sender claims the
 * target's csd first; the target's handler releases it (an async csd is unlocked before its function runs).
 */
static atomic_t fki_kick_claimed[NR_CPUS];
static void fki_kick_fn(void *unused) { atomic_set_release(&fki_kick_claimed[smp_processor_id()], 0); }
static DEFINE_PER_CPU(call_single_data_t, fki_kick_csd);

void fki_kick_cpu(int cpu)
{
	struct task_struct *t;

	if (cpu < 0 || cpu >= nr_cpu_ids)
		return;
	smp_mb();	/* the caller's pending word before the idle task: pairs with fki_idle_body */
	t = READ_ONCE(fki_idle_task[cpu]);
	if (t)
		wake_up_process(t);
	else if (cpu != smp_processor_id() && atomic_cmpxchg_acquire(&fki_kick_claimed[cpu], 0, 1) == 0) {
		/* irq_work_queue_on is not exported; an IPI already on its way (claimed) is just as good */
		if (smp_call_function_single_async(cpu, per_cpu_ptr(&fki_kick_csd, cpu)))
			atomic_set_release(&fki_kick_claimed[cpu], 0);
	}
}
EXPORT_SYMBOL(fki_kick_cpu);

static void fki_read_mpidr(void *p) { *(u64 *)p = read_cpuid_mpidr(); }

int fki_cpu_mpidr(int cpu, fki_u64 *mpidr)
{
	u64 v = 0;
	int err;

	if (cpu < 0 || cpu >= nr_cpu_ids || !cpu_online(cpu))
		return -EINVAL;
	err = smp_call_function_single(cpu, fki_read_mpidr, &v, 1);
	*mpidr = v;
	return err;
}
EXPORT_SYMBOL(fki_cpu_mpidr);

int fki_num_cpus(void)
{
	return num_online_cpus();
}
EXPORT_SYMBOL(fki_num_cpus);

void fki_realtime(fki_u64 *sec, fki_u64 *nsec)
{
	struct timespec64 ts;

	ktime_get_real_ts64(&ts);
	*sec = ts.tv_sec;
	*nsec = ts.tv_nsec;
}
EXPORT_SYMBOL(fki_realtime);

/*
 * A virtual Ethernet link to the foreign kernel: the Linux netdev "xnu0". What Linux transmits on xnu0 is queued for
 * the foreign kernel (fki_net_recv); what the foreign kernel sends (fki_net_send) arrives on xnu0 as received frames.
 */
#define FKI_NET_QLEN 1024
static struct net_device *fki_netdev;
static struct sk_buff_head fki_net_rxq;	/* Linux -> foreign */

static netdev_tx_t fki_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct task_struct *t;

	if (skb_queue_len(&fki_net_rxq) >= FKI_NET_QLEN) {
		dev->stats.tx_dropped++;
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}
	dev->stats.tx_packets++;
	dev->stats.tx_bytes += skb->len;
	skb_queue_tail(&fki_net_rxq, skb);
	t = READ_ONCE(fki_idle_task[0]);
	if (t)
		wake_up_process(t);	/* the foreign kernel's first CPU is idle: let it see the frame now */
	return NETDEV_TX_OK;
}

static int fki_net_up(struct net_device *dev) { netif_start_queue(dev); return 0; }
static int fki_net_down(struct net_device *dev) { netif_stop_queue(dev); return 0; }

static const struct net_device_ops fki_net_ops = {
	.ndo_open = fki_net_up,
	.ndo_stop = fki_net_down,
	.ndo_start_xmit = fki_net_xmit,
	.ndo_set_mac_address = eth_mac_addr,
	.ndo_validate_addr = eth_validate_addr,
};

struct fki_net_io { const void *in; void *out; unsigned long len; long result; };

static void fki_net_send_body(void *p)
{
	struct fki_net_io *io = p;
	struct sk_buff *skb;

	io->result = -ENODEV;
	if (!fki_netdev || io->len < ETH_HLEN || io->len > ETH_FRAME_LEN + 4)
		return;
	skb = netdev_alloc_skb(fki_netdev, io->len + NET_IP_ALIGN);
	if (!skb) {
		fki_netdev->stats.rx_dropped++;
		io->result = -ENOMEM;
		return;
	}
	skb_reserve(skb, NET_IP_ALIGN);
	skb_put_data(skb, io->in, io->len);
	skb->protocol = eth_type_trans(skb, fki_netdev);
	fki_netdev->stats.rx_packets++;
	fki_netdev->stats.rx_bytes += io->len;
	local_irq_enable();	/* netif_rx re-enables bottom halves, which must not happen with interrupts off */
	netif_rx(skb);
	local_irq_disable();
	io->result = io->len;
}

/* The foreign kernel sends one Ethernet frame (header included, no FCS) out of its link: it arrives on xnu0. */
long fki_net_send(const void *frame, unsigned long len)
{
	struct fki_net_io io = { .in = frame, .len = len };

	fki_linux_runs(fki_net_send_body, &io);
	return io.result;
}
EXPORT_SYMBOL(fki_net_send);

static void fki_net_recv_body(void *p)
{
	struct fki_net_io *io = p;
	struct sk_buff *skb = skb_dequeue(&fki_net_rxq);

	io->result = 0;
	if (!skb)
		return;
	if (skb->len > io->len) {
		io->result = -EMSGSIZE;
	} else if (skb_copy_bits(skb, 0, io->out, skb->len) == 0) {
		io->result = skb->len;
	} else {
		io->result = -EIO;
	}
	dev_consume_skb_any(skb);
}

/* The next frame Linux sent on xnu0 into buf (at most len bytes): its length, 0 when none is waiting. */
long fki_net_recv(void *buf, unsigned long len)
{
	struct fki_net_io io = { .out = buf, .len = len };

	fki_linux_runs(fki_net_recv_body, &io);
	return io.result;
}
EXPORT_SYMBOL(fki_net_recv);

/* Frames waiting for the foreign kernel. */
long fki_net_pending(void)
{
	return skb_queue_len(&fki_net_rxq);
}
EXPORT_SYMBOL(fki_net_pending);

static void fki_free_alt_stacks(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		if (fki_alt_stack[cpu])
			free_pages((unsigned long)fki_alt_stack[cpu], FKI_ALT_STACK_ORDER);
		fki_alt_stack[cpu] = NULL;
	}
}

/* insmod fki.ko survey=1: which fki_resolve() symbols this kernel has, and which L0[1] L1 slots are empty.
 * L0[1] is the high TTBR1 half (VA 0xffff800000000000, 2048 slots of 64 GiB on 16 KiB / 48-bit). */
static bool survey;
module_param(survey, bool, 0444);
MODULE_PARM_DESC(survey, "log fki_resolve symbols and free L1 slots under TTBR1 L0[1]");

static void fki_log_sym(const char *name, const void *p)
{
	if (p)
		pr_info("fki: symbol %s ok\n", name);
	else
		pr_warn("fki: symbol %s MISSING\n", name);
}

static void fki_survey_l1(void)
{
	unsigned long long *l1;
	fki_u64 l1pa;
	unsigned int i, run = 0, prev = 0;
	int err = fki_window_l1(0xffff800000000000UL, &l1, &l1pa);
	static const char *const kind_name[] = { "free", "block", "other", "table" };

	if (err) {
		pr_err("fki: L0[1] has no L1 table (%d)\n", err);
		return;
	}
	pr_info("fki: L0[1] L1 table at phys %#llx\n", l1pa);
	for (i = 0; i <= 2048; i++) {
		unsigned int kind = 4;
		u64 ent = 0;

		if (i < 2048) {
			ent = READ_ONCE(l1[i]);
			if (!ent)
				kind = 0;
			else if ((ent & 3) == 1)
				kind = 1;
			else if ((ent & 3) == 3)
				kind = 3;
			else
				kind = 2;
		}
		if (i == 0) {
			prev = kind;
			continue;
		}
		if (kind == prev)
			continue;
		pr_info("fki: L1 %s slots %u..%u va %#lx-%#lx\n", kind_name[prev], run, i - 1,
			0xffff800000000000UL + ((unsigned long)run << 36),
			0xffff800000000000UL + ((unsigned long)i << 36));
		prev = kind;
		run = i;
	}
	{
		unsigned long va = 0xffffffe000000000UL;
		unsigned int idx16 = (va >> 36) & 2047;
		u64 ent = READ_ONCE(l1[idx16]);

		pr_info("fki: va %#lx is L1[%u] desc %#llx (%s); 4KiB-style index (>>30 & 511) would be %lu\n",
			va, idx16, ent, ent ? "used" : "free", (va >> 30) & 511);
	}
}

static void fki_survey(void)
{
	int err = fki_resolve();

	pr_info("fki: fki_resolve %s\n", err ? "FAILED" : "ok");
	fki_log_sym("kallsyms_lookup_name", fki_have_lookup ? (const void *)1 : NULL);
	if (p_cma_area)
		pr_info("fki: dma_contiguous_default_area %s\n", *p_cma_area ? "non-NULL" : "NULL");
	fki_log_sym("set_memory_x", p_set_memory_x);
	fki_log_sym(p_alloc_name ? p_alloc_name : "alloc_contig_pages", p_alloc_contig);
	fki_log_sym("free_contig_range", p_free_contig);
	fki_log_sym("dma_contiguous_default_area", p_cma_area);
	fki_log_sym("cma_alloc", p_cma_alloc);
	fki_log_sym("cma_release", p_cma_release);
	fki_log_sym("set_memory_nx", p_set_memory_nx);
	fki_log_sym("_stext", (void *)p_stext);
	fki_log_sym("_end", (void *)p_end);
	fki_log_sym("kimage_voffset", p_kimage_voffset);
	fki_log_sym("efi_mem_type", p_efi_mem_type);
	if (!err)
		fki_survey_l1();
}

static int __init fki_init(void)
{
	struct net_device *dev;
	int err, cpu;

	if (survey)
		fki_survey();

	for_each_possible_cpu(cpu) {
		struct page *pg = alloc_pages(GFP_KERNEL, FKI_ALT_STACK_ORDER);

		if (!pg) {
			fki_free_alt_stacks();
			return -ENOMEM;
		}
		fki_alt_stack[cpu] = page_address(pg);
		INIT_CSD(per_cpu_ptr(&fki_kick_csd, cpu), fki_kick_fn, NULL);
	}
	skb_queue_head_init(&fki_net_rxq);
	fki_reserve();
	err = fki_hostcall_init();
	if (err)
		pr_warn("fki: no /dev/xnu-hostcall (%d)\n", err);
	dev = alloc_etherdev(0);
	if (!dev)
		return 0;	/* no link; the rest of fki still works */
	strscpy(dev->name, "xnu0", IFNAMSIZ);
	dev->netdev_ops = &fki_net_ops;
	eth_hw_addr_random(dev);
	dev->min_mtu = 68;
	dev->max_mtu = ETH_DATA_LEN;
	err = register_netdev(dev);
	if (err) {
		free_netdev(dev);
		pr_warn("fki: no xnu0 link (%d)\n", err);
		return 0;
	}
	fki_netdev = dev;
	return 0;
}

static void __exit fki_exit(void)
{
	fki_hostcall_exit();
	if (resv_pg && !resv_used)
		p_cma_release(*p_cma_area, resv_pg, resv_cnt);
	if (fki_netdev) {
		unregister_netdev(fki_netdev);
		free_netdev(fki_netdev);
		fki_netdev = NULL;
	}
	skb_queue_purge(&fki_net_rxq);
	fki_free_alt_stacks();
}
module_init(fki_init);
module_exit(fki_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Foreign kernel interface v0 (out-of-tree form for stock kernels)");

void *fki_file_open(const char *path, int writable, fki_u64 *size)
{
	struct file *f = filp_open(path, (writable ? O_RDWR : O_RDONLY) | O_LARGEFILE, 0);

	if (IS_ERR(f))
		return NULL;
	if (size)	/* the mapping's host: a block device's own size (a device node's inode says 0) */
		*size = i_size_read(f->f_mapping->host);
	return f;
}
EXPORT_SYMBOL(fki_file_open);

#define FKI_FILE_CHUNK (256UL << 10)

static long fki_file_rw_body(void *file, int write, void *buf, unsigned long len, fki_u64 off);
struct fki_file_args { void *file; int write; void *buf; unsigned long len; fki_u64 off; long ret; };
static void fki_file_rw_thunk(void *p)
{
	struct fki_file_args *a = p;
	a->ret = fki_file_rw_body(a->file, a->write, a->buf, a->len, a->off);
}

long fki_file_rw(void *file, int write, void *buf, unsigned long len, fki_u64 off)
{
	struct fki_file_args a = { file, write, buf, len, off, -EIO };

	if (!file)
		return -EBADF;
	fki_linux_runs(fki_file_rw_thunk, &a);
	return a.ret;
}
EXPORT_SYMBOL(fki_file_rw);

static long fki_file_rw_body(void *file, int write, void *buf, unsigned long len, fki_u64 off)
{
	struct file *f = file;
	unsigned long done = 0;
	long ret = 0;
	void *bounce;

	local_irq_enable();
	preempt_enable();
	bounce = kvmalloc(min(len, FKI_FILE_CHUNK), GFP_KERNEL);
	if (!bounce)
		ret = -ENOMEM;
	while (bounce && done < len) {
		unsigned long n = min(len - done, FKI_FILE_CHUNK);
		loff_t pos = off + done;
		ssize_t r;

		if (write) {
			preempt_disable(); local_irq_disable();
			memcpy(bounce, (char *)buf + done, n);
			local_irq_enable(); preempt_enable();
			r = kernel_write(f, bounce, n, &pos);
		} else {
			r = kernel_read(f, bounce, n, &pos);
			if (r > 0) {
				preempt_disable(); local_irq_disable();
				memcpy((char *)buf + done, bounce, r);
				local_irq_enable(); preempt_enable();
			}
		}
		if (r < 0) {
			ret = r;
			break;
		}
		done += r;
		if ((unsigned long)r < n)
			break;
	}
	kvfree(bounce);
	preempt_disable();
	local_irq_disable();
	return ret < 0 && !done ? ret : (long)done;
}


long fki_file_pwrite(void *file, const void *buf, unsigned long len, fki_u64 off)
{
	loff_t pos = off;

	if (!file)
		return -EBADF;
	return kernel_write(file, buf, len, &pos);
}
EXPORT_SYMBOL(fki_file_pwrite);

void fki_file_close(void *file)
{
	if (file)
		filp_close(file, NULL);
}
EXPORT_SYMBOL(fki_file_close);

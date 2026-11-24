// SPDX-License-Identifier: APSL-2.0
/*
 * xnu.ko: hosts an XNU kernel image inside Linux. Talks to Linux only
 * through FKI (fki.h); <linux/module.h> provides the module ABI.
 *
 * mode=1: load, slide and sign the image, call two XNU functions (a smoke test).
 * mode=2: a bare kernel image; mode=3: a kernel collection. Hand XNU boot args
 *        and an ADT and run arm_init in the XNU world; XNU calls into this
 *        module through linux64_hook (the interface: linux64_abi.h).
 */
#include <linux/module.h>
#include "../fki-ko/fki.h"
#include "xrt.h"
#include "macho.h"
#include "adt.h"
#include "world.h"
#include "../xnu-patches/include/linux64_abi.h"

static char *image = "xnu/kernel.macho";
module_param(image, charp, 0444);
static int mode = 2;
module_param(mode, int, 0444);
static int ram_mb = 256;
module_param(ram_mb, int, 0444);
static int kmax;	/* end the run after this many XNU kprintf lines (0: no limit) */
module_param(kmax, int, 0444);
static int kcount;
static int idle_max;	/* end the run after this many XNU idle rounds (0: never) */
module_param(idle_max, int, 0444);
static int quiet_console = 1;	/* drop the known high-volume console and kprintf lines (see quiet_line) */
module_param(quiet_console, int, 0444);
static int quiet_line(const char *l, unsigned n)
{
	static const char *const pfx[] = { "com.apple.xpc.launchd|", "kmutil: AppleImage4", "cryptexd: AppleImage4", "ACMTRM", "ACM:",
		"AppleCredentialManagerUserClient", "hfs: set hardlink bit", "Couldn't alloc class", "  dynamic: platformVersion" };
	for (unsigned i = 0; i < sizeof(pfx) / sizeof(pfx[0]); i++) {
		unsigned k = 0;
		while (pfx[i][k] && k < n && l[k] == pfx[i][k]) k++;
		if (!pfx[i][k]) return 1;
	}
	for (unsigned k = 0; k + 18 <= n; k++)	/* "... triggered unnest of range ..." */
		if (!x_strncmp(l + k, "triggered unnest", 16)) return 1;
	return 0;
}
/* XNU's CPUs: Linux CPUs 0 .. cpus-1 (XNU's CPU 0 is Linux CPU 0, where xnu.ko's loading task runs) */
#define XNU_MAX_CPUS 16
static int cpus = 1;
module_param(cpus, int, 0444);
static struct xnu_world worlds[XNU_MAX_CPUS];		/* worlds[0] is xnu_W's twin: see xnu_worlds */
struct xnu_world *xnu_worlds[LINUX64_CPU_SLOTS];	/* by CPU slot (world.S finds its CPU's save area here) */
static signed char linux_cpu_of_slot[LINUX64_CPU_SLOTS];
static unsigned long long cpu_mpidr[XNU_MAX_CPUS];
static void *cpu_thread[XNU_MAX_CPUS];
static volatile int cpu_running[XNU_MAX_CPUS];
static u64_t a_cpu_entry;			/* XNU's linux64_cpu_entry */
static inline unsigned this_slot(void) { unsigned long m; __asm__ volatile("mrs %0, mpidr_el1" : "=r"(m)); return LINUX64_CPU_SLOT(m); }
/* Writing 1 ends the run at XNU's next call into the host; insmod returns and the module can be removed */
static int stop_run;
module_param(stop_run, int, 0644);
static int assert_fatal;	/* 1: a failed XNU assert() ends the run; 0: report it and let XNU continue */
module_param(assert_fatal, int, 0444);

static struct xnu_image img;
static struct fki_region l2page;
static unsigned long long *window_slot, *window_l1;
static u64_t diag_va[6];
/*
 * Descriptors installed here are walked with Linux's TCR, so the granule is the host this module was built against.
 * A 4 KiB host (the LINUX64 bring-up): one L1 slot is 1 GiB, XNU's kernel window is L1[384..495], and stage 210 copies
 * those entries out of XNU's own 4 KiB L1. A 16 KiB host (Asahi): one L1 slot is 64 GiB and the link address
 * 0xffffffe000000000 is L1[2046], which the machine leaves empty. XNU stays the 4 KiB LINUX64 kernel (16 KiB VM pages
 * come from linux64_vm16k, PAGE_RATIO 4). It does not become a __ARM_16K_PG__ / VMAPPLE build: that drops the LINUX64
 * 4 KiB pmap. Its cpu_tte is still a 4 KiB L1, so stage 210 must not copy indices 384..495 into this table.
 */
#if defined(CONFIG_ARM64_16K_PAGES)
#define XNU_HOST_16K  1
#define XNU_MAP_BLOCK (32ULL << 20)	/* L2 block */
#define XNU_L2_SHIFT  25
#define XNU_L2_PTRS   2048
#define XNU_L1_SHIFT  36
#define XNU_L1_PTRS   2048
#else
#define XNU_HOST_16K  0
#define XNU_MAP_BLOCK (2ULL << 20)
#define XNU_L2_SHIFT  21
#define XNU_L2_PTRS   512
#define XNU_L1_SHIFT  30
#define XNU_L1_PTRS   512
#endif
#define XNU_L2_BYTES  (XNU_L2_PTRS * (unsigned)sizeof(unsigned long long))
static unsigned char window_owned[XNU_L1_PTRS];
#define XNU_L1_FIRST 384	/* 4 KiB XNU root: VM_MIN_KERNEL_ADDRESS 0xffffffe000000000 */
#define XNU_L1_LAST 495		/* 4 KiB XNU root: VM_MAX_KERNEL_ADDRESS 0xfffffffbffffffff */
static void *blob;
/* A root RAM disk (firmware blob): placed in XNU's DRAM after the ADT, /chosen/memory-map RAMDisk, boot-arg rd=md0. */
static char *ramdisk;
/* Extra XNU boot arguments, appended to the built-in command line */
static char *bootargs;
module_param(bootargs, charp, 0444);
module_param(ramdisk, charp, 0444);
static const void *rd_data; static unsigned long rd_size; static void *rd_blob;
/* The static trust cache a bootloader passes (raw trust cache module, e.g. the payload of the OS's StaticTrustCache.img4) */
static char *trustcache;
module_param(trustcache, charp, 0444);
static const void *tc_data; static unsigned long tc_size; static void *tc_blob;
#define TC_SEG_SIZE (tc_size ? tc_size + 8 : 0)	/* trust_cache_offsets_t { num_caches = 1, offsets[1] } + the module */
/*
 * The display's framebuffer (boot_args Video, 32 bpp): reserved in the boot data like the RAM disk, so XNU never hands its pages
 * out; XnuDisplay (kexts/XnuDisplay) copies each frame WindowServer swaps into it. fb_width=0 boots without one. A host thread
 * writes it to fb_dump (raw BGRA, fb_width x fb_height) every fb_dump_ms milliseconds when both are set.
 */
static int fb_width = 1280, fb_height = 800;
module_param(fb_width, int, 0444);
module_param(fb_height, int, 0444);
static char *fb_dump;
module_param(fb_dump, charp, 0444);
static int fb_dump_ms = 1000;
module_param(fb_dump_ms, int, 0444);
static u64_t fb_off;	/* the framebuffer's offset in the contiguous region (its Linux address: img.region.va + fb_off) */
#define FB_SIZE (fb_width > 0 && fb_height > 0 ? (u64_t)fb_width * fb_height * 4 : 0)
#define BOOT_EXTRA (((rd_size + 0x3fff) & ~0x3fffULL) + ((TC_SEG_SIZE + 0x3fff) & ~0x3fffULL) + ((FB_SIZE + 0x3fff) & ~0x3fffULL))
/* A root disk backed by a host file (an HFS+ image): XNU's memdev md0 in host mode (LINUX64_CALL_RAMDISK_SIZE, _RW). */
static char *hostdisk;
static int hostdisk_rw;
module_param(hostdisk, charp, 0444);
module_param(hostdisk_rw, int, 0444);
static void *hd_file; static fki_u64 hd_size;
/* Console input for XNU's /dev/console: bytes appended to this host file are typed in (LINUX64_CALL_CONSOLE_READ) */
static char *console_in;
module_param(console_in, charp, 0444);
static void *ci_file; static fki_u64 ci_off;
/*
 * Input events for XnuInput (kexts/XnuInput): a host file of 8-byte records {u16 type, u16 code, s32 value} as Linux's evdev
 * (tools/hosted/xnu-input.py appends them); LINUX64_CALL_INPUT_READ reads the whole records written since the load.
 */
static char *input_in;
module_param(input_in, charp, 0444);
static char *keystore;		/* the hosted keystore's file (XnuEAN's EAN blobs): read and written through LINUX64_CALL_KEYSTORE_RW */
module_param(keystore, charp, 0444);
static void *ks_file;
/* The hosted system's block disk (kexts/XnuDisk: IOKit media, e.g. an APFS container), read-write (LINUX64_CALL_DISK_SIZE, _RW) */
static char *disk;
module_param(disk, charp, 0444);
static void *dk_file; static fki_u64 dk_size;
/*
 * What iBoot tells an APFS boot in /chosen: the system volume's UUID (boot-uuid; boot-arg rd=uuid finds the root by it) and
 * the volume group's folder in Preboot (apfs-preboot-uuid: kern.apfsprebootuuid, from which dyld's libignition grafts the
 * boot cryptexes, the OS cryptex with the dyld shared cache, before launchd runs).
 */
static char *boot_uuid, *preboot_uuid;
module_param(boot_uuid, charp, 0444);
module_param(preboot_uuid, charp, 0444);
/*
 * root_uuid: the root volume itself, by its APFS volume UUID, as /chosen root-matching (IOFindBSDRoot takes it before
 * boot-uuid): BSD disk numbers follow probe order and change from boot to boot, and the boot-uuid route waits on APFS to
 * publish boot-uuid-media from its volume group tree, which a disk that never booted on a Mac does not have yet.
 */
static char *root_uuid;
module_param(root_uuid, charp, 0444);
static char root_matching[256];
static void *in_file; static fki_u64 in_off;
struct xnu_world xnu_W;

static void logs(const char *s) { fki_log(s, x_strlen(s)); }
static void logs_alert(const char *s) { fki_log_alert(s, x_strlen(s)); }
static void logkv(const char *k, u64_t v)
{
	char buf[96]; char *p = buf;
	while (*k) *p++ = *k++;
	*p++ = ' '; *p++ = '0'; *p++ = 'x';
	for (int i = 60; i >= 0; i -= 4) *p++ = "0123456789abcdef"[(v >> i) & 15];
	*p = 0;
	logs(buf);
}

/* ---- M1 ---- */
typedef unsigned long (*strlen_fn)(const char *);
typedef unsigned int (*crc32_fn)(unsigned int, const void *, unsigned long);

static int run_m1(void)
{
	struct fki_pac_keys saved; unsigned long c;
	c = fki_enter(&xnu_W.xnu_keys, &saved);
	int n = macho_rebase(&img);
	fki_leave(c, &saved);
	logkv("xnu: threaded fixups applied", (u64_t)n);
	if (n < 0) return n;
	u64_t v = macho_sym(&img, "_version"), sl = macho_sym(&img, "_strlen"), cr = macho_sym(&img, "_crc32");
	if (!v || !sl || !cr) { logs("xnu: symbols missing"); return 0; }
	c = fki_enter(&xnu_W.xnu_keys, &saved);
	unsigned long len = ((strlen_fn)sl)((const char *)v);
	unsigned int crc = ((crc32_fn)cr)(0, (const void *)v, len);
	fki_leave(c, &saved);
	logs("xnu: XNU code ran inside Linux; XNU's version string:");
	fki_log((const char *)v, len);
	logkv("xnu: strlen(version) computed by XNU", len);
	logkv("xnu: crc32(version) computed by XNU", crc);
	return 0;
}

/* ---- M2a ---- */
#define XNU_FAKE_PHYS 0x800000000ULL	/* XNU's view of the region's first byte */
#define BOOT_LINE 1024

struct boot_args_v2 {			/* pexpert/arm64/boot.h layout */
	unsigned short Revision, Version;
	u64_t virtBase, physBase, memSize, topOfKernelData;
	struct { u64_t v_baseAddr, v_display, v_rowBytes, v_width, v_height, v_depth; } Video;
	unsigned int machineType;
	void *deviceTreeP;
	unsigned int deviceTreeLength;
	char CommandLine[BOOT_LINE];
	u64_t bootFlags, memSizeActual;
};

/*
 * The machine's model (the device tree root's "model", hw.model): user space takes the product type from it
 * (MobileGestalt ProductType), and apsd aborts without one, which holds up login (loginwindow's MDM pre-login check-in
 * waits on apsd). It must have the form of a Mac model identifier.
 */
static char *model = "VirtualMac2,1";	/* Apple's own virtual Mac's model identifier */
module_param(model, charp, 0444);

/* the compressor's limit is in VM pages: 6 GB either way */
static const char *cmdline = "debug=0x8 -v -noprogress serial=0 startup_debug=1";
static const char *cmdline_4k = " vm_compression_limit=1572864";
static const char *cmdline_16k = " vm_compression_limit=393216 linux64_vm16k=1";
/* vm16k=1 (the default): XNU's VM pages are 16 KB, as on a Mac, over the host's 4 KB translation granule (XNU's
 * PAGE_RATIO 4): a quarter of the page faults of 4 KB pages; vm16k=0 gives 4 KB VM pages */
static int vm16k = 1;
module_param(vm16k, int, 0444);


/* Walk XNU's kernel tables (inside its contiguous DRAM) for va and log the descriptors. */
static unsigned long long *tbl_va(u64_t desc)
{
	u64_t pa = desc & 0x0000fffffffff000ULL;
	if (pa < img.region.pa || pa >= img.region.pa + img.region.size) return 0;
	return (unsigned long long *)((char *)img.region.va + (pa - img.region.pa));
}

static void walk_log(const char *what, u64_t va, const unsigned long long *l1)
{
	u64_t d1 = l1[(va >> 30) & 511], d2 = 0, d3 = 0;
	logs(what);
	logkv("xnu:   va", va);
	logkv("xnu:   L1", d1);
	if ((d1 & 3) == 3) {
		unsigned long long *t2 = tbl_va(d1);
		if (!t2) { logs("xnu:   L2 table outside XNU DRAM"); return; }
		d2 = t2[(va >> 21) & 511];
		logkv("xnu:   L2", d2);
		if ((d2 & 3) == 3) {
			unsigned long long *t3 = tbl_va(d2);
			if (!t3) { logs("xnu:   L3 table outside XNU DRAM"); return; }
			d3 = t3[(va >> 12) & 511];
			logkv("xnu:   L3", d3);
		}
	}
}

/*
 * Kernel page faults on XNU addresses, taken in Linux's vectors while XNU runs (XNU's keys and stack live), go to
 * XNU's own linux64_kernel_fault (vm_fault on the kernel map). in_xnu is 0 while host code runs (upcalls, monitor).
 */
static volatile int in_xnu_slot[LINUX64_CPU_SLOTS];
#define in_xnu in_xnu_slot[this_slot()]
static unsigned long (*xnu_kfault)(unsigned long far, unsigned long esr);
static unsigned long (*xnu_kfault_recover)(unsigned long pc, unsigned long far, unsigned long esr);
static unsigned long kfaults;
static unsigned long kfault_moved;	/* kernel faults whose vm_fault came back on another CPU (the monitor's moved=) */

#define XNU_VA_LO 0xffffffe000000000ULL
#define XNU_VA_HI 0xfffffffc00000000ULL
/*
 * A kernel fault XNU's vm_fault should resolve is not resolved here, inside Linux's exception handler (a kprobe: no
 * sleeping, no rescheduling, and a nested fault in it is a missed kprobe and an oops), because vm_fault may page in
 * from disk (a file I/O upcall that lets Linux schedule) or block the thread. The exception instead returns into
 * xnu_fault_tramp (world.S) with every register as it was; the trampoline calls xnu_fault_deferred in XNU's own
 * context, then returns (eret) to the faulting instruction, to the copyio recovery path, or to the abort.
 */
/* each CPU's: the fault handler and the trampoline it returns into run on the same CPU, with nothing between them */
static struct { unsigned long far, esr, pc, pstate; } xnu_deferred_slot[LINUX64_CPU_SLOTS];
#define xnu_deferred xnu_deferred_slot[this_slot()]
extern void xnu_fault_tramp(void);
extern void xnu_world_fault_abort(void);

/*
 * No shadow call stack here: vm_fault may block, and the thread may come back on another CPU, whose Linux task's shadow
 * stack x18 then points into (the return address pushed on the first CPU's would be popped from the second's). XNU never
 * saves x18 per thread, so the register follows the CPU: what this calls pushes and pops on the current CPU's.
 */
unsigned long xnu_fault_deferred(unsigned long *frame) __attribute__((no_sanitize("shadow-call-stack")));
unsigned long xnu_fault_deferred(unsigned long *frame)
{
	unsigned long far = xnu_deferred.far, esr = xnu_deferred.esr, pc = xnu_deferred.pc;
	/* per CPU: with one global record, two CPUs faulting at once reset each other's count, and a CPU looping on one
	 * address never reached the every-64 yield below (it held its Linux CPU, and Linux with it, for good) */
	static unsigned long last_far_slot[LINUX64_CPU_SLOTS], repeats_slot[LINUX64_CPU_SLOTS];
	unsigned s0 = this_slot();
	unsigned long repeats = (far == last_far_slot[s0]) ? repeats_slot[s0] + 1 : 0;
	repeats_slot[s0] = repeats;
	last_far_slot[s0] = far;

	frame[31] = xnu_deferred.pstate;	/* the SPSR the trampoline returns with */
	/*
	 * The same address faulting again is normal (libmalloc's MADV_FREE_REUSABLE clears a page's referenced and
	 * modified state, so each reuse takes one fault). Only report it, rarely, when it looks endless.
	 */
	long kr = xnu_kfault(far, esr);
	if (this_slot() != s0) {
		/*
		 * vm_fault blocked and the thread came back on another CPU. xnu_fault_tramp's eret restores every register
		 * of the faulting context from frame, x18 included: that would be the first CPU's shadow stack pointer, and
		 * from then on this CPU's upcalls push and pop on the first CPU's Linux task's shadow stack while that CPU
		 * uses it too (corrupted shadow stacks, FPAC in whatever Linux code runs next). x18 follows the CPU.
		 */
		unsigned long x18;
		__asm__ volatile("mov %0, x18" : "=r"(x18));
		frame[18] = x18;
		kfault_moved++;
	}
	if (kr == 0) {
		if (repeats && (repeats & (repeats - 1)) == 0 && repeats >= 1024) {
			logkv("xnu: one address keeps taking resolved kernel faults, repeats", repeats);
			logkv("xnu:   far", far);
			logkv("xnu:   esr", esr);
			logkv("xnu:   pc ", pc);
			logkv("xnu:   lr ", frame[30]);
		}
		/* a fault loop runs with interrupts masked: let Linux take its interrupts now and then (RCU, network) */
		if ((repeats & 63) == 63)
			((void (*)(unsigned long, unsigned long, unsigned long))xnu_world_upcall)(LINUX64_CALL_PREEMPTED, 0, 0);
		return pc;
	}
	/* inside copyin/copyout: the routine's recovery path returns EFAULT to its caller, as XNU's own abort handler does */
	if (xnu_kfault_recover) {
		unsigned long rpc = xnu_kfault_recover(pc, far, esr);
		if (rpc) {
			frame[0] = 14;	/* EFAULT */
			return rpc;
		}
	}
	in_xnu = 0;
	logs("xnu: XNU took a fault vm_fault cannot resolve; ending the run");
	logkv("xnu:   pc ", pc);
	logkv("xnu:   lr ", frame[30]);
	logkv("xnu:   far", far);
	logkv("xnu:   esr", esr);
	return (unsigned long)xnu_world_fault_abort;
}

static int xnu_fault(unsigned long far, unsigned long esr, void *regs)
{
	if (!in_xnu)
		return 1;
	unsigned long fpc = fki_regs_pc(regs);
	if (far && ((far >= XNU_VA_LO && far < XNU_VA_HI) || far < 0x0001000000000000ULL) && xnu_kfault &&
	    fpc >= XNU_VA_LO && fpc < XNU_VA_HI) {
		kfaults++;
		xnu_deferred.far = far;
		xnu_deferred.esr = esr;
		xnu_deferred.pc = fpc;
		xnu_deferred.pstate = fki_regs_pstate(regs);
		fki_regs_set_pc(regs, (unsigned long)xnu_fault_tramp);
		return 0;
	}
	/*
	 * An XNU fault nothing resolves (a bug, or a NULL dereference): report it and end the run instead of letting Linux
	 * oops with XNU's keys and stack live (which takes the machine with it). The exception returns into
	 * xnu_world_fault_abort, which puts Linux's keys back and leaves through xnu_world_abort.
	 */
	unsigned long pc = fki_regs_pc(regs);
	if (pc < XNU_VA_LO || pc >= XNU_VA_HI)
		return 1;
	/* inside copyin/copyout: the routine's recovery path returns EFAULT to its caller, as XNU's own abort handler does */
	/*
	 * brk #0xff00: XNU's UBSan minimal soft trap (signed overflow). XNU's own exception handler notes it
	 * (ubsan_handle_brk_trap) and resumes after the brk; do the same.
	 */
	if ((esr >> 26) == 0x3c && (esr & 0xffff) == 0xff00) {
		static unsigned long ubsan_traps;
		if (ubsan_traps++ < 8)
			logkv("xnu: UBSan soft trap (signed overflow), resuming; pc", pc);
		fki_regs_set_pc(regs, pc + 4);
		return 0;
	}
	if (xnu_kfault_recover) {
		unsigned long rpc = xnu_kfault_recover(pc, far, esr);
		if (rpc) {
			fki_regs_set_reg(regs, 0, 14);	/* EFAULT */
			fki_regs_set_pc(regs, rpc);
			return 0;
		}
	}
	in_xnu = 0;
	logs("xnu: XNU took a fault it cannot handle; ending the run");
	logkv("xnu:   pc ", pc);
	logkv("xnu:   lr ", fki_regs_lr(regs));
	logkv("xnu:   far", far);
	logkv("xnu:   esr", esr);
	logkv("xnu:   CPU slot", this_slot());
	logkv("xnu:   x0 ", fki_regs_reg(regs, 0));
	logkv("xnu:   x1 ", fki_regs_reg(regs, 1));
	{	/* XNU's frame-pointer chain (return addresses with the kernel's all-ones top in place of their PAC bits) */
		unsigned long *fp = (unsigned long *)fki_regs_reg(regs, 29);
		for (int i = 0; i < 12 && fp && !((unsigned long)fp & 15) && (unsigned long)fp >= XNU_VA_LO &&
		    (unsigned long)fp < XNU_VA_HI; i++) {
			logkv("xnu:   frame", fp[1] | 0xffffff8000000000ul);
			if ((unsigned long *)fp[0] <= fp) break;
			fp = (unsigned long *)fp[0];
		}
	}
	fki_regs_set_pc(regs, (unsigned long)xnu_world_fault_abort);
	return 0;
}

/* A secondary CPU's host thread: its own world, entered at linux64_cpu_entry(cpu_data); returns when the run ends */
static unsigned long cpu_start_arg[XNU_MAX_CPUS];
static int park_secondaries;	/* diagnostics: 1 keeps secondary CPUs out of XNU */
module_param(park_secondaries, int, 0444);
static int cpu_fn(void *arg)
{
	int c = (int)(unsigned long)arg;

	fki_thread_wait(&cpu_start_arg[c]);	/* until XNU starts this CPU (LINUX64_CALL_CPU_START) */
	if (!cpu_start_arg[c])
		return 0;			/* the run ended first: told to stop */
	logkv("xnu: XNU CPU starts on Linux CPU", (u64_t)c);
	if (park_secondaries) {	/* diagnostics: the CPU is asked for but never enters XNU */
		logkv("xnu: secondary CPU parked (park_secondaries)", (u64_t)c);
		cpu_running[c] = 0;
		while (!fki_thread_should_stop())
			fki_msleep(10);
		return 0;
	}
	in_xnu = 1;
	long r = xnu_world_call(a_cpu_entry, cpu_start_arg[c]);
	in_xnu = 0;
	if (!r) logkv("xnu: linux64_cpu_entry returned (unexpected) on CPU", (u64_t)c);
	stop_run = 1;			/* one CPU's run ending (a fatal fault, a stop) ends all of them */
	cpu_running[c] = 0;
	while (!fki_thread_should_stop())	/* kthread_stop() from the module's exit wants the thread alive */
		fki_msleep(10);
	return 0;
}

/*
 * Where the time goes: host-counter ticks spent in each kind of call into the host (the rest of a CPU's time is XNU
 * running, user or kernel). The monitor prints the share of each over its last interval (perf=1).
 */
#define ACCT_N 64
static unsigned long acct_ticks_slot[LINUX64_CPU_SLOTS][ACCT_N], acct_calls_slot[LINUX64_CPU_SLOTS][ACCT_N], acct_disk_slot[LINUX64_CPU_SLOTS];
static int perf;
module_param(perf, int, 0644);
static volatile const unsigned long *xnu_el0_stat;	/* XNU's linux64_el0_stat[cpu][count, ticks][class] */
static inline unsigned acct_bucket(unsigned long call) { return call >= 800 && call < 800 + ACCT_N - 1 ? call - 800 : ACCT_N - 1; }
static inline void acct_add(unsigned long call, u64_t ticks)
{
	unsigned b = acct_bucket(call), s = this_slot();	/* per CPU: no atomics (and none of the compiler's out-of-line ones) */
	acct_ticks_slot[s][b] += ticks;
	acct_calls_slot[s][b]++;
}

/* XNU calls into the host: enum linux64_call (linux64_abi.h); a non-zero return ends the run */
static long xnu_hook_body(unsigned long call, unsigned long a1, unsigned long a2);
/* each CPU's host calls so far, the last one's number, and whether it is inside one: the monitor's silent-CPU check */
static unsigned long upcalls_slot[LINUX64_CPU_SLOTS], last_call_slot[LINUX64_CPU_SLOTS];
static volatile int in_call_slot[LINUX64_CPU_SLOTS];
long xnu_hook(unsigned long call, unsigned long a1, unsigned long a2)
{
	unsigned in_s = this_slot();	/* the thread is bound to its CPU while in the host */
	upcalls_slot[in_s]++;
	last_call_slot[in_s] = call;
	{
		/* debugging: an XNU stack Linux's overflow check would reject (bit 14 of sp set) */
		static int told;
		unsigned long sp;
		__asm__ volatile("mov %0, sp" : "=r"(sp));
		if ((sp & 0x4000) && told < 3) {
			told++;
			logkv("xnu: upcall on an XNU stack with sp bit 14 set, sp", sp);
			logkv("xnu:   call", call);
		}
	}
	in_xnu = 0;
	if (*(volatile int *)&stop_run) {	/* the host asked the run to end (scripts/xnulinux-boot.sh stop): XNU is abandoned here */
		logs("xnu: run stopped by the host (stop_run)");
		return 1;
	}
	u64_t t0 = fki_counter();
	in_call_slot[in_s] = 1;
	long r = xnu_hook_body(call, a1, a2);
	in_call_slot[in_s] = 0;
	acct_add(call, fki_counter() - t0);
	if (!r) in_xnu = 1;
	return r;
}

static long xnu_hook_body(unsigned long call, unsigned long a1, unsigned long a2)
{
	if (call == LINUX64_CALL_CONSOLE_READ) {		/* console input: new bytes of console_in */
		struct linux64_buf_req *q = (struct linux64_buf_req *)a1;
		if (!q) return 0;
		q->result = 0;
		if (ci_file) {
			long n = fki_file_rw(ci_file, 0, q->buf, (unsigned long)q->len, ci_off);
			if (n > 0) { ci_off += n; q->result = n; }
		}
		return 0;
	}
	if (call == LINUX64_CALL_INPUT_READ) {		/* input events: whole 8-byte records of input_in, into q->buf */
		struct linux64_buf_req *q = (struct linux64_buf_req *)a1;
		if (!q) return 0;
		q->result = 0;
		if (in_file && q->len >= 8) {
			long n = fki_file_rw(in_file, 0, q->buf, (unsigned long)(q->len & ~7ULL), in_off);
			if (n > 0) { n &= ~7L; in_off += n; q->result = n; }
		}
		return 0;
	}
	if (call == LINUX64_CALL_NET_SEND || call == LINUX64_CALL_NET_RECV) {	/* XNU's Ethernet link: one frame each way */
		struct linux64_buf_req *q = (struct linux64_buf_req *)a1;
		if (!q) return 0;
		q->result = call == LINUX64_CALL_NET_SEND ? fki_net_send(q->buf, (unsigned long)q->len) : fki_net_recv(q->buf, (unsigned long)q->len);
		return 0;
	}
	if (call == LINUX64_CALL_WALLCLOCK) {		/* the host's wall clock for XNU's calendar: a1 -> u64[2] {seconds, nanoseconds} UTC */
		if (a1) fki_realtime(&((fki_u64 *)a1)[0], &((fki_u64 *)a1)[1]);
		return 0;
	}
	if (call == LINUX64_CALL_RANDOM) {	/* a1: a2 bytes from Linux's generator */
		if (a1) fki_random((void *)a1, a2);
		return 0;
	}
	if (call == LINUX64_CALL_HOSTCALL) {		/* host call: q->result = the reply's length or -errno */
		struct linux64_hostcall_req *q = (struct linux64_hostcall_req *)a1;
		if (q) q->result = fki_hostcall(q->req, (unsigned long)q->len, q->reply, (unsigned long)q->max);
		return 0;
	}
	if (call == LINUX64_CALL_DISK_SIZE) {		/* the block disk's size in bytes into *a1, 0 when there is none */
		if (a1) *(u64_t *)a1 = dk_file ? dk_size : 0;
		return 0;
	}
	if (call == LINUX64_CALL_DISK_RW) {		/* block disk I/O: q->result = bytes moved or -errno */
		struct linux64_rw_req *q = (struct linux64_rw_req *)a1;
		if (q) q->result = dk_file ? fki_file_rw(dk_file, (int)q->write, q->buf, (unsigned long)q->len, q->off) : -6;
		if (q && q->result > 0) acct_disk_slot[this_slot()] += (unsigned long)q->result;
		return 0;
	}
	if (call == LINUX64_CALL_KEYSTORE_RW) {		/* the keystore file: q->result = bytes moved or -errno */
		struct linux64_rw_req *q = (struct linux64_rw_req *)a1;
		if (!q) return 0;
		q->result = ks_file ? fki_file_rw(ks_file, (int)q->write, q->buf, (unsigned long)q->len, q->off) : -6;
		return 0;
	}
	if (call == LINUX64_CALL_RAMDISK_SIZE) {		/* host disk size in bytes into *a1, 0 when there is none */
		if (a1) *(u64_t *)a1 = hd_file ? hd_size : 0;
		return 0;
	}
	if (call == LINUX64_CALL_RAMDISK_RW) {		/* host disk I/O: q->result = bytes moved or -errno */
		struct linux64_rw_req *q = (struct linux64_rw_req *)a1;
		if (!q) return 0;
		if (!hd_file) q->result = -6;
		else if (q->write && !hostdisk_rw) q->result = -30;
		else q->result = fki_file_rw(hd_file, (int)q->write, q->buf, (unsigned long)q->len, q->off);
		return 0;
	}
	if (call == LINUX64_CALL_CONSOLE_WRITE) {		/* XNU console bytes (/dev/console): line-buffered into the host log */
		static char line[1000]; static unsigned n;
		const char *b = (const char *)a1; unsigned long i;
		for (i = 0; b && i < a2; i++) {
			char c = b[i];
			if (c == '\r') continue;
			if (c != '\n') line[n++] = c;
			if (c == '\n' || n == sizeof(line) - 1) {
				static char m[1024]; unsigned j = 0, k;
				const char *p = "darwin console: ";
				while (*p) m[j++] = *p++;
				for (k = 0; k < n; k++) m[j++] = line[k];
				m[j] = 0;
				/* quiet_console: launchd's and AppleImage4's chatter (thousands of lines a second) stays out */
				if (!(quiet_console && quiet_line(line, n)))
					logs(m);
				n = 0;
			}
		}
		/* a prompt (a write that ends in "# ", "$ " or "> " without a newline): show it now */
		if (n >= 2 && line[n - 1] == ' ' && (line[n - 2] == '#' || line[n - 2] == '$' || line[n - 2] == '>')) {
			static char m[1024]; unsigned j = 0, k;
			const char *p = "darwin console: ";
			while (*p) m[j++] = *p++;
			for (k = 0; k < n; k++) m[j++] = line[k];
			m[j] = 0; n = 0;
			logs(m);
		}
		return 0;
	}
	if (call == LINUX64_CALL_KPRINTF) {		/* XNU kprintf */
		char m[260]; const char *f = (const char *)a1; unsigned i = 0, j = 0;
		m[j++] = 'x'; m[j++] = 'n'; m[j++] = 'u'; m[j++] = ']'; m[j++] = ' ';
		while (f && f[i] && j < sizeof(m) - 1) { if (f[i] != '\n') m[j++] = f[i]; i++; }
		m[j] = 0;
		/* the per-entry startup trace is thousands of lines: count it, do not print it */
		if (!(f && !x_strncmp(f, "kernel_startup_initialize_upto[", 31)) && !(quiet_console && quiet_line(m + 5, j - 5)))
			logs(m);
		if (kmax && ++kcount >= kmax) { logs("xnu: kprintf budget reached"); return 1; }
		return 0;
	}
	if (call == LINUX64_CALL_KERNEL_TABLES && window_l1) {	/* install XNU's kernel L1 entries (the kernel VA range only) */
		/*
		 * XNU's L1 table (cpu_tte) is read through the bootstrap window, and installing XNU's entry for the window's
		 * own slot replaces that window: XNU's tables need not map cpu_tte at this stage (L3 0 here), so the rest of
		 * the table is read from a copy taken first, never through the slot being replaced (it faulted in Linux's
		 * context, an oops, whenever the TLB no longer held the bootstrap entry).
		 */
		static unsigned long long tte[512];
		x_memcpy(tte, (const void *)a1, sizeof(tte));
		walk_log("xnu: XNU table walk for arm_init (text)", diag_va[0], tte);
		walk_log("xnu: XNU table walk for the Mach-O header", diag_va[1], tte);
		walk_log("xnu: XNU table walk for boot args", diag_va[2], tte);
		walk_log("xnu: XNU table walk for the cpu_tte page", a1, tte);
		if (XNU_HOST_16K) {
			/*
			 * cpu_tte[384..495] are 1 GiB slots of a 4 KiB L1. On this host those indices are different
			 * 64 GiB windows, and the descriptors point at 4 KiB tables. The bootstrap map of L1[2046]
			 * already covers the contiguous DRAM (the slot is 64 GiB), so it stays.
			 */
			logs("xnu: host granule is 16 KiB; XNU's 4 KiB L1 is not installed, bootstrap map stays");
		} else {
			int n = 0, last = -1;
			for (int i = XNU_L1_FIRST; i <= XNU_L1_LAST; i++) {
				if (!(tte[i] & 1)) continue;
				if (window_l1[i] && &window_l1[i] != window_slot) { logkv("xnu: L1 slot in use by Linux, refusing:", i); return 1; }
				window_l1[i] = tte[i]; window_owned[i] = 1; n++; last = i;
			}
			if (last >= 0) fki_window_set(&window_l1[last], tte[last]);	/* barrier + TLB flush */
			logkv("xnu: XNU L1 entries installed", n);
		}
		/* Touch the mapped window (XNU's tables on a 4 KiB host, the bootstrap map on a 16 KiB host). A fault here is a readable oops. */
		logkv("xnu: probe text word", *(volatile unsigned int *)diag_va[0]);
		logkv("xnu: probe Mach-O magic", *(volatile unsigned int *)diag_va[1]);
		logkv("xnu: probe boot args Version", ((volatile struct boot_args_v2 *)diag_va[2])->Version);
		logkv("xnu: probe ADT word", *(volatile unsigned int *)diag_va[3]);
		if (diag_va[4]) { volatile unsigned int *pc = (void *)diag_va[4]; unsigned v = *pc; *pc = v; logkv("xnu: probe port_crumb (rw)", v); }
		if (diag_va[5]) { unsigned long l = ((unsigned long (*)(const char *))diag_va[5])("xnulinux"); logkv("xnu: probe exec strlen through XNU tables", l); }
		logs("xnu: probes done");
	}
	if (call == LINUX64_CALL_PREEMPTED) {		/* XNU busy: a host IRQ preempted its user code; let Linux handle it */
		fki_yield();
		return 0;
	}
	if (call == LINUX64_CALL_IDLE) {		/* XNU idle: let Linux run until XNU's next timer deadline */
		static unsigned long idles;
		idles++;
		if ((idles & (idles - 1)) == 0) logkv("xnu: XNU idle, count", idles);
		if (!a1)		/* a timer is due: only let Linux take its interrupts */
			fki_yield();
		else {			/* sleep until XNU's next timer, at most 20 ms (XNU's devices are polled from its timers) */
			u64_t ns = a1 < 20000000ULL ? a1 : 20000000ULL;
			fki_idle_until(fki_counter() + ns * fki_counter_frequency() / 1000000000ULL, ns,
			    (const volatile unsigned int *)a2);
		}
		return idle_max && idles >= (unsigned long)idle_max;
	}
	if (call == LINUX64_CALL_ASSERT) {		/* XNU assert() failed */
		const struct linux64_assert_info *a = (const void *)a1;
		char m[240]; unsigned j = 0, i;
		const char *parts[3] = { "xnu: XNU assert failed: ", a->file, ": " };
		for (int p = 0; p < 3; p++)
			for (i = 0; parts[p] && parts[p][i] && j < sizeof(m) - 1; i++) m[j++] = parts[p][i];
		for (i = 0; a->expr && a->expr[i] && j < sizeof(m) - 1; i++) m[j++] = a->expr[i];
		m[j] = 0;
		logs(m);
		logkv("xnu:   at line", a->line);
		return assert_fatal;
	}
	if (call == LINUX64_CALL_USER_ENTER) {		/* the first entry into user space (linux64_el0_run follows) */
		logkv("xnu: XNU enters user space (EL0); user pc", a1);
		return 0;
	}
	if (call == LINUX64_CALL_PANIC) {
		char m[500]; const char *f = (const char *)a1; unsigned i = 0;
		while (f && f[i] && i < sizeof(m) - 1) { m[i] = f[i]; i++; }
		m[i] = 0;
		logs_alert("xnu: XNU panic:");
		logs_alert(m);
		logkv("xnu: panic caller", a2);
		{	/* the frame-pointer chain from here through XNU's frames (the hook runs on XNU's stack); return addresses
			 * with their pointer-authentication bits replaced by the kernel's all-ones top */
			unsigned long *fp = __builtin_frame_address(0);
			for (i = 0; i < 24 && fp && !((unsigned long)fp & 15) && (unsigned long)fp >> 48 == 0xffff; i++) {
				unsigned long lr = fp[1] | 0xffffff8000000000ul;
				logkv("xnu:   frame", lr);
				if ((unsigned long *)fp[0] <= fp) break;
				fp = (unsigned long *)fp[0];
			}
		}
		return 1;
	}
	if (call == LINUX64_CALL_CPU_START) {	/* start XNU's CPU of MPIDR a1 at linux64_cpu_entry(a2), asynchronously */
		int c = linux_cpu_of_slot[LINUX64_CPU_SLOT(a1)];
		/* its thread was made before XNU ran (an upcall runs with preemption off: no thread creation here) */
		if (c <= 0 || c >= cpus || !cpu_thread[c] || !a2 || cpu_start_arg[c]) {
			logkv("xnu: XNU asked to start a CPU it was not given, MPIDR", a1);
			return 0;
		}
		cpu_running[c] = 1;
		WRITE_ONCE(cpu_start_arg[c], a2);
		fki_thread_wake(cpu_thread[c]);
		return 0;
	}
	if (call == LINUX64_CALL_IPI) {		/* XNU's CPU of MPIDR a1 has an IPI pending: make it look */
		int c = linux_cpu_of_slot[LINUX64_CPU_SLOT(a1)];
		if (c >= 0)
			fki_kick_cpu(c);
		return 0;
	}
	if (call == LINUX64_CALL_KERNEL_TABLES)
		return 0;
	{	/* a call this module does not know (an XNU built against a newer linux64_abi.h): say so once, go on */
		static unsigned long told;
		if (told != call) { told = call; logkv("xnu: unknown call from XNU", call); }
	}
	return 0;
}

/*
 * Boot handoff. The XNU "DRAM" region is described by (virtBase, physBase, size): XNU sees base_va as the
 * kernel virtual address of physBase. The image's vmlow sits at base_va + image_off.
 */
static struct boot_args_v2 *build_boot(unsigned char *base_va, u64_t phys, u64_t size, u64_t image_off, u64_t image_size)
{
	u64_t off_args = (image_off + image_size + 0x3fff) & ~0x3fffULL;
	struct boot_args_v2 *ba = (void *)(base_va + off_args);
	u64_t off_dt = off_args + 0x4000;
	struct adt a;
	static unsigned char seed[256];

	fki_random(seed, sizeof(seed));
	/*
	 * XNU identifies its CPUs by MPIDR: its CPU 0 runs here, bound to Linux CPU 0; CPUs 1 .. cpus-1 are Linux's of the
	 * same numbers, started when XNU asks (LINUX64_CALL_CPU_START). Their slots in the per-CPU arrays must differ.
	 */
	int berr = fki_bind_cpu(0);
	if (berr) { logkv("xnu: cannot bind to cpu0, err", (u64_t)berr); return 0; }
	if (cpus < 1) cpus = 1;
	if (cpus > XNU_MAX_CPUS) cpus = XNU_MAX_CPUS;
	if (cpus > fki_num_cpus()) cpus = fki_num_cpus();
	for (int i = 0; i < LINUX64_CPU_SLOTS; i++) linux_cpu_of_slot[i] = -1;
	for (int c = 0; c < cpus; c++) {
		fki_u64 m = 0;
		if (fki_cpu_mpidr(c, &m) || linux_cpu_of_slot[LINUX64_CPU_SLOT(m)] >= 0) {
			logkv("xnu: no distinct MPIDR slot for Linux CPU, using CPUs below it:", (u64_t)c);
			cpus = c;
			break;
		}
		cpu_mpidr[c] = m & 0xffff;	/* XNU compares Aff1:Aff0 */
		linux_cpu_of_slot[LINUX64_CPU_SLOT(m)] = (signed char)c;
		xnu_worlds[LINUX64_CPU_SLOT(m)] = c ? &worlds[c] : &xnu_W;
	}
	u64_t mpidr = cpu_mpidr[0];
	logkv("xnu: running on MPIDR Aff1:Aff0", mpidr);
	logkv("xnu: XNU CPUs", (u64_t)cpus);

	adt_init(&a, base_va + off_dt, 0x40000);
	adt_node(&a, 3, 6);				/* / */
	adt_prop_str(&a, "name", "device-tree");
	{	/* the platform's own name, then the model: user space's product type (MobileGestalt) comes from this list */
		static char compat[96];
		static const char own[] = "xnulinux,linux64";
		unsigned n = sizeof(own), m = (unsigned)x_strlen(model);
		x_memcpy(compat, own, n);
		if (m && n + m + 1 <= sizeof(compat) && x_strcmp(model, "xnulinux")) {
			x_memcpy(compat + n, model, m + 1);
			n += m + 1;
		}
		adt_prop(&a, "compatible", compat, n);
	}
	adt_prop_str(&a, "model", model);
	if (root_uuid && x_strlen(root_uuid) == 36) {
		static const char pre[] = "<dict><key>IOProviderClass</key><string>IOMedia</string><key>IOPropertyMatch</key>"
		    "<dict><key>UUID</key><string>", post[] = "</string></dict></dict>";
		x_memcpy(root_matching, pre, sizeof(pre) - 1);
		x_memcpy(root_matching + sizeof(pre) - 1, root_uuid, 36);
		x_memcpy(root_matching + sizeof(pre) - 1 + 36, post, sizeof(post));
	}
	adt_node(&a, 22 + (boot_uuid ? 1 : 0) + (preboot_uuid ? 1 : 0) + (root_matching[0] ? 1 : 0), 3);	/* /chosen */
	if (root_matching[0]) adt_prop_str(&a, "root-matching", root_matching);
	if (boot_uuid) adt_prop_str(&a, "boot-uuid", boot_uuid);
	if (preboot_uuid) adt_prop_str(&a, "apfs-preboot-uuid", preboot_uuid);
	adt_prop_str(&a, "name", "chosen");
	adt_prop_u64(&a, "dram-base", phys);
	adt_prop_u64(&a, "dram-size", size);
	adt_prop(&a, "random-seed", seed, sizeof(seed));
	adt_prop_str(&a, "firmware-version", "xnulinux-m2");
	adt_prop_u32(&a, "debug-enabled", 1);
	{
		/* the SHA-384 of the boot manifest a bootloader would pass; there is none, so zeros (27's Image4 needs the property) */
		static const unsigned char zero48[48];
		adt_prop(&a, "boot-manifest-hash", zero48, sizeof(zero48));
	}
	{
		/* NVRAM as iBoot hands it over: the bank size and the image (blank: IODTNVRAM formats it as a CHRP store) */
		static unsigned char nvram[0x10000];
		adt_prop_u32(&a, "nvram-bank-size", sizeof(nvram));
		adt_prop_u32(&a, "nvram-bank-count", 1);
		adt_prop_u32(&a, "nvram-current-bank", 0);
		adt_prop(&a, "nvram-proxy-data", nvram, sizeof(nvram));
	}
	/*
	 * The identity a bootloader states for the AP, which Image4 reads: Apple's VM platform (chip 0xFE00, board 0x20)
	 * in an insecure, non-production mode, as a development VM boots.
	 */
	adt_prop_str(&a, "crypto-hash-method", "sha2-384");
	adt_prop_u32(&a, "chip-id", 0xfe00);
	adt_prop_u32(&a, "board-id", 0x20);
	adt_prop_u64(&a, "unique-chip-id", 0x0000584e554c4e58ULL);
	adt_prop_u32(&a, "chip-epoch", 0);
	adt_prop_u32(&a, "security-domain", 1);
	adt_prop_u32(&a, "certificate-production-status", 0);
	adt_prop_u32(&a, "certificate-security-mode", 0);
	adt_prop_u32(&a, "effective-production-status-ap", 0);
	adt_prop_u32(&a, "effective-security-mode-ap", 0);
	adt_prop_u32(&a, "mix-n-match-prevention-status", 0);
	u64_t off_rd = (off_dt + 0x40000 + 0x3fff) & ~0x3fffULL;	/* the RAM disk, after the ADT's room */
	u64_t off_tc = (off_rd + rd_size + 0x3fff) & ~0x3fffULL;	/* the trust cache segment, after the RAM disk */
	u64_t off_fb = (off_tc + TC_SEG_SIZE + 0x3fff) & ~0x3fffULL;	/* the framebuffer, after the trust cache */
	adt_node(&a, 1 + (rd_size ? 1 : 0) + (tc_size ? 1 : 0), 0);	/* /chosen/memory-map (no AuxKC) */
	adt_prop_str(&a, "name", "memory-map");
	if (rd_size) {
		u64_t rd[2] = { phys + off_rd, rd_size };
		adt_prop(&a, "RAMDisk", rd, sizeof(rd));
	}
	if (tc_size) {
		u64_t tc[2] = { phys + off_tc, TC_SEG_SIZE };	/* DTTrustCacheRange: load_static_trust_cache() */
		adt_prop(&a, "TrustCache", tc, sizeof(tc));
	}
	adt_node(&a, 1, 0);				/* /chosen/manifest-properties: AppleImage4 reads it (empty: no manifest) */
	adt_prop_str(&a, "name", "manifest-properties");
	adt_node(&a, 3, 0);				/* /chosen/asmb: the SIP configuration a bootloader passes (csr_bootstrap) */
	adt_prop_str(&a, "name", "asmb");
	adt_prop_u64(&a, "lp-sip0", 0x2);		/* CSR_ALLOW_UNTRUSTED_KEXTS, as DroidVM boots */
	adt_prop_u32(&a, "lp-sip1", 1);			/* CSR_ALLOW_UNAUTHENTICATED_ROOT */
	adt_node(&a, 1, cpus);				/* /cpus */
	adt_prop_str(&a, "name", "cpus");
	/*
	 * /cpus/cpu0, without device_type "cpu": that would match Apple's CPU driver (AppleARMCPU, IONameMatch "cpu"),
	 * which drives the AIC interrupts and IPIs of real hardware. While hosted, the CPU is Linux's.
	 */
	for (int c = 0; c < cpus; c++) {	/* compatible: kexts/XnuCPU registers each with XNU and starts it */
		static char cname[XNU_MAX_CPUS][8];
		cname[c][0] = 'c'; cname[c][1] = 'p'; cname[c][2] = 'u';
		if (c < 10) { cname[c][3] = '0' + c; cname[c][4] = 0; } else { cname[c][3] = '1'; cname[c][4] = '0' + c - 10; cname[c][5] = 0; }
		adt_node(&a, 6, 0);
		adt_prop_str(&a, "name", cname[c]);
		adt_prop_str(&a, "compatible", "xnulinux,cpu");
		adt_prop_str(&a, "state", c ? "waiting" : "running");
		adt_prop_u32(&a, "reg", (unsigned)cpu_mpidr[c]);
		adt_prop_u64(&a, "timebase-frequency", fki_counter_frequency());
		adt_prop_u32(&a, "cluster-type", 'P');	/* the AMP scheduler wants E/M/P, not SMP */
	}
	adt_node(&a, 1, 0);				/* /defaults: XNU looks these up without checking */
	adt_prop_str(&a, "name", "defaults");
	adt_node(&a, 4, 0);				/* /product */
	adt_prop_str(&a, "name", "product");
	/*
	 * MobileGestalt's product type in sandboxed processes: their profiles let them read only these two /product
	 * properties (apsd's: "sub-product-type", "unique-model"), and apsd aborts without a product type
	 */
	adt_prop_str(&a, "sub-product-type", model);
	adt_prop_str(&a, "unique-model", model);
	adt_prop_str(&a, "product-name", "xnulinux");
	adt_node(&a, 1, 0);				/* /options: NVRAM's node (AppleImage4 keeps its nonce seeds there) */
	adt_prop_str(&a, "name", "options");
	adt_node(&a, 3, FB_SIZE ? 1 : 0);		/* /arm-io: XNU needs a nonzero SoC base */
	adt_prop_str(&a, "name", "arm-io");
	adt_prop_str(&a, "device_type", "linux64-io");
	{ u64_t ranges[3] = { 0, 0x7000000000ULL, 0x10000000ULL }; adt_prop(&a, "ranges", ranges, sizeof(ranges)); }
	if (FB_SIZE) {
		/*
		 * /arm-io/gpu, compatible "paravirtualizedgraphics,gpu" as on Apple's VM: IOMobileFramebuffer.framework then waits
		 * for the framebuffers of the AppleParavirtGPU services (XnuDisplay; it matches IOResources, not this node, which
		 * no driver claims: /arm-io's device_type keeps Apple's ARM IO driver off). Without the node WindowServer counted
		 * no framebuffer and ran headless.
		 */
		adt_node(&a, 2, 0);
		adt_prop_str(&a, "name", "gpu");
		adt_prop_str(&a, "compatible", "paravirtualizedgraphics,gpu");
	}
	if (a.err) { logs("xnu: ADT overflow"); return 0; }
	u64_t dt_len = adt_size(&a);

	ba->Revision = 2; ba->Version = 2;
	ba->virtBase = (u64_t)base_va;
	ba->physBase = phys;
	ba->memSize = size;
	ba->memSizeActual = size;
	ba->topOfKernelData = phys + ((off_dt + dt_len + 0x3fff) & ~0x3fffULL);
	if (rd_size) {
		x_memcpy(base_va + off_rd, rd_data, rd_size);
		ba->topOfKernelData = phys + ((off_rd + rd_size + 0x3fff) & ~0x3fffULL);
		logkv("xnu: root RAM disk bytes", rd_size);
	}
	if (tc_size) {
		unsigned int hdr[2] = { 1, 8 };
		x_memcpy(base_va + off_tc, hdr, sizeof(hdr));
		x_memcpy(base_va + off_tc + 8, tc_data, tc_size);
		ba->topOfKernelData = phys + ((off_tc + TC_SEG_SIZE + 0x3fff) & ~0x3fffULL);
		logkv("xnu: static trust cache bytes", tc_size);
	}
	if (FB_SIZE) {
		unsigned int *px = (unsigned int *)(base_va + off_fb);
		for (u64_t i = 0; i < FB_SIZE / 4; i++)
			px[i] = 0xff000000;	/* opaque black until the first frame */
		ba->Video.v_baseAddr = phys + off_fb;
		ba->Video.v_display = 0;	/* no boot console drawn into it (the console is the serial line) */
		ba->Video.v_rowBytes = (u64_t)fb_width * 4;
		ba->Video.v_width = (u64_t)fb_width;
		ba->Video.v_height = (u64_t)fb_height;
		ba->Video.v_depth = 32;
		ba->topOfKernelData = phys + ((off_fb + FB_SIZE + 0x3fff) & ~0x3fffULL);
		fb_off = off_fb;
		logkv("xnu: framebuffer bytes", FB_SIZE);
	}
	ba->deviceTreeP = base_va + off_dt;
	ba->deviceTreeLength = (unsigned)dt_len;
	x_memcpy(ba->CommandLine, cmdline, x_strlen(cmdline) + 1);
	{
		const char *pg = vm16k ? cmdline_16k : cmdline_4k;
		x_memcpy(ba->CommandLine + x_strlen(ba->CommandLine), pg, x_strlen(pg) + 1);
	}
	if (rd_size || hd_file) {
		const char *rd = " rd=md0";
		x_memcpy(ba->CommandLine + x_strlen(ba->CommandLine), rd, x_strlen(rd) + 1);
	}
	if (bootargs && x_strlen(ba->CommandLine) + 1 + x_strlen(bootargs) < sizeof(ba->CommandLine)) {
		char *e = ba->CommandLine + x_strlen(ba->CommandLine);
		*e++ = ' ';
		x_memcpy(e, bootargs, x_strlen(bootargs) + 1);
	}
	logkv("xnu: boot args at", (u64_t)ba);
	logkv("xnu: ADT bytes", dt_len);
	logkv("xnu: topOfKernelData (phys)", ba->topOfKernelData);
	return ba;
}


/*
 * Monitor: XNU runs with interrupts masked on its CPU, so when it spins nothing reaches Linux. A helper
 * thread on another CPU prints XNU's debug counters (linux64_dbg, see the XNU patch) every 2 s.
 */
static volatile const unsigned long *xnu_dbg;
static void *monitor;
static int monitor_cpu = -2;	/* -2: the first Linux CPU XNU does not run on; -1: no monitor */
module_param(monitor_cpu, int, 0444);

static char *put_dec(char *p, unsigned long v)
{
	char t[24]; int n = 0;
	do { t[n++] = '0' + v % 10; v /= 10; } while (v);
	while (n) *p++ = t[--n];
	return p;
}

static void put_str(char **p, const char *s) { while (*s) *(*p)++ = *s++; }
static void put_hex(char **p, unsigned long v) { for (int i = 44; i >= 0; i -= 4) *(*p)++ = "0123456789abcdef"[(v >> i) & 15]; }

/* XNU's counters (enum linux64_counter) every 2 s for the first 3 minutes, then every 20 s */
/* writing 1 asks XNU for a dump of its threads at its next idle (/sys/module/xnu/parameters/dump_threads) */
static int dump_threads;
module_param(dump_threads, int, 0644);

/* perf=1: per 2 s, each call kind's share of the interval in permille of one CPU, its count, and disk bytes */
static void acct_report(void)
{
	static unsigned long last_t, last_ticks[ACCT_N], last_calls[ACCT_N], last_disk;
	unsigned long now = fki_counter(), dt = now - last_t, total = 0;
	char buf[800]; char *p = buf;
	if (!last_t) { last_t = now; return; }
	last_t = now;
	put_str(&p, "xnu: perf ms="); p = put_dec(p, dt * 1000 / fki_counter_frequency());
	for (unsigned b = 0; b < ACCT_N && p < buf + sizeof(buf) - 48; b++) {
		unsigned long t = 0, c = 0, d, n;
		for (unsigned s = 0; s < LINUX64_CPU_SLOTS; s++) { t += READ_ONCE(acct_ticks_slot[s][b]); c += READ_ONCE(acct_calls_slot[s][b]); }
		d = t - last_ticks[b]; n = c - last_calls[b];
		last_ticks[b] = t; last_calls[b] = c;
		if (!n) continue;
		total += d;
		put_str(&p, b == ACCT_N - 1 ? " other" : " c"); if (b != ACCT_N - 1) p = put_dec(p, 800 + b);
		put_str(&p, "="); p = put_dec(p, d * 1000 / dt);
		put_str(&p, "%o/"); p = put_dec(p, n);
	}
	put_str(&p, " host="); p = put_dec(p, total * 1000 / dt);
	if (xnu_el0_stat) {	/* XNU's user-space exceptions by class: count and permille of the interval until back in user space */
		static const char *cls[LINUX64_EL0_CLASSES] = { " svc=", " dabt=", " iabt=", " irq=", " other=" };
		static unsigned long last_n[LINUX64_EL0_CLASSES], last_t[LINUX64_EL0_CLASSES];
		for (unsigned c = 0; c < LINUX64_EL0_CLASSES; c++) {
			unsigned long n = 0, t = 0;
			for (unsigned s = 0; s < LINUX64_EL0_CPUS; s++) {
				n += READ_ONCE(xnu_el0_stat[(s * 2 + 0) * LINUX64_EL0_CLASSES + c]);
				t += READ_ONCE(xnu_el0_stat[(s * 2 + 1) * LINUX64_EL0_CLASSES + c]);
			}
			put_str(&p, cls[c]); p = put_dec(p, n - last_n[c]); put_str(&p, "/"); p = put_dec(p, (t - last_t[c]) * 1000 / dt); put_str(&p, "%o");
			last_n[c] = n; last_t[c] = t;
		}
	}
	unsigned long disk = 0;
	for (unsigned s = 0; s < LINUX64_CPU_SLOTS; s++) disk += READ_ONCE(acct_disk_slot[s]);
	put_str(&p, "%o diskKB="); p = put_dec(p, (disk - last_disk) >> 10);
	last_disk = disk;
	*p = 0;
	logs(buf);
}

static int monitor_fn(void *arg)
{
	static const struct { int i; const char *name; } dec[] = {
		{ LINUX64_CTR_IDLE_THREAD, " idle_thread=" }, { LINUX64_CTR_MACHINE_IDLE, " machine_idle=" },
		{ LINUX64_CTR_CPU_IDLE, " cpu_idle=" }, { LINUX64_CTR_HOST_IDLE, " host_idle=" }, { LINUX64_CTR_SWITCHES, " switches=" },
		{ LINUX64_CTR_LAST_CALL, " last_call=" }, { LINUX64_CTR_RTCLOCK, " rtclock=" }, { LINUX64_CTR_EL0_EXC, " el0exc=" },
	}, hex[] = {
		{ LINUX64_CTR_EL0_ESR, " esr=0x" }, { LINUX64_CTR_EL0_FAR, " far=0x" }, { LINUX64_CTR_EL0_PC, " pc=0x" },
		{ LINUX64_CTR_BAD_ESR, " bad_esr=0x" }, { LINUX64_CTR_THREAD, " thread=0x" },
	};
	int lines = 0;
	unsigned long ticks = 0;
	(void)arg;
	while (!fki_thread_should_stop()) {
		fki_msleep(2000);
		if (xnu_dbg && *(volatile int *)&dump_threads) {
			((volatile unsigned long *)xnu_dbg)[LINUX64_CTR_DUMP_REQ] = 1;
			dump_threads = 0;
		}
		{	/* a CPU in XNU that has not called the host for 2 s holds its Linux CPU with interrupts masked */
			static unsigned long seen[XNU_MAX_CPUS], still[XNU_MAX_CPUS];
			for (int c = 0; c < cpus && xnu_dbg; c++) {
				unsigned s = LINUX64_CPU_SLOT(cpu_mpidr[c]);
				if ((c && !cpu_running[c]) || upcalls_slot[s] != seen[c]) { seen[c] = upcalls_slot[s]; still[c] = 0; continue; }
				if (++still[c] == 1) {
					struct xnu_world *w = xnu_worlds[s];
					unsigned long fp = w->xnu_regs[10];
					{
						char ab[160]; char *q = ab;
						put_str(&q, "xnu: XNU CPU "); q = put_dec(q, (unsigned long)c);
						put_str(&q, " made no host call for 2 s (its Linux CPU held, interrupts masked); last call ");
						q = put_dec(q, last_call_slot[s]); put_str(&q, in_call_slot[s] ? " (inside it)" : " (back in XNU)");
						*q = 0;
						logs_alert(ab);
					}
					logkv("xnu: XNU CPU silent for 2 s (no host call), cpu", (u64_t)c);
					logkv("xnu:   its last host call", last_call_slot[s]);
					logkv("xnu:   still inside it (1) or back in XNU (0)", in_call_slot[s]);
					logkv("xnu:   lr at that call", w->xnu_regs[11]);
					for (int f = 0; f < 16 && fp >= XNU_VA_LO && fp < XNU_VA_HI && !(fp & 7); f++) {
						logkv("xnu:   frame", ((unsigned long *)fp)[1]);
						fp = ((unsigned long *)fp)[0];
					}
				}
			}
		}
		if (perf && cpus > 1) {	/* each XNU CPU's host calls so far and the last one's number */
			char cb[200]; char *q = cb;
			put_str(&q, "xnu: calls");
			for (int c = 0; c < cpus; c++) {
				unsigned s = LINUX64_CPU_SLOT(cpu_mpidr[c]);
				put_str(&q, " "); q = put_dec(q, upcalls_slot[s]); put_str(&q, "/"); q = put_dec(q, last_call_slot[s]);
			}
			*q = 0;
			logs(cb);
		}
		if (perf)
			acct_report();
		if (!xnu_dbg || (lines >= 90 && (++ticks % 10) != 0))
			continue;
		char buf[420]; char *p = buf;
		put_str(&p, "xnu: monitor");
		for (unsigned i = 0; i < sizeof(dec) / sizeof(dec[0]); i++) { put_str(&p, dec[i].name); p = put_dec(p, xnu_dbg[dec[i].i]); }
		put_str(&p, " kfaults="); p = put_dec(p, kfaults);
		put_str(&p, " moved="); p = put_dec(p, kfault_moved);
		for (unsigned i = 0; i < sizeof(hex) / sizeof(hex[0]); i++) { put_str(&p, hex[i].name); put_hex(&p, xnu_dbg[hex[i].i]); }
		*p = 0;
		logs(buf);
		lines++;
	}
	return 0;
}

/* The framebuffer to fb_dump every fb_dump_ms (a host thread: plain Linux context, XNU keeps running on its CPU). */
static void *fb_thread;
static int fb_fn(void *arg)
{
	void *f = fki_file_open(fb_dump, 1, 0);
	(void)arg;
	if (!f) { logs("xnu: cannot open fb_dump (create the file first)"); return 0; }
	while (!fki_thread_should_stop()) {
		fki_msleep(fb_dump_ms);
		fki_file_pwrite(f, (unsigned char *)img.region.va + fb_off, FB_SIZE, 0);
	}
	fki_file_close(f);
	return 0;
}

static int enter_arm_init(struct boot_args_v2 *ba)
{
	if (img.filetype == MH_FILESET) {
		/* kernel collection at its link address: XNU applies the chained fixups itself; nothing slides */
		if (img.slide) { logs("xnu: a kernel collection must not slide"); return -22; }
		logs("xnu: kernel collection: XNU applies its chained fixups (kernel_collection_slide)");
	} else {
		struct fki_pac_keys saved; unsigned long c = fki_enter(&xnu_W.xnu_keys, &saved);
		int n = macho_rebase(&img);
		fki_leave(c, &saved);
		logkv("xnu: threaded fixups applied", (u64_t)n);
		if (n < 0) return n;

		u64_t mh_unslid = 0;
		int segs = macho_slide_header(&img, &mh_unslid);
		logkv("xnu: load commands slid (segments)", (u64_t)segs);
	}
	u64_t a_init = macho_sym(&img, "_arm_init"), a_hook = macho_sym(&img, "_linux64_hook"),
	      a_slide = macho_sym(&img, "_linux64_slide");
	logkv("xnu: arm_init at", a_init);
	if (!a_init || !a_hook || !a_slide) { logs("xnu: arm_init or linux64_hook missing (kernel without the LINUX64 patch?)"); return -2; }
	*(u64_t *)a_hook = (u64_t)xnu_world_upcall;
	*(u64_t *)a_slide = img.slide;

	diag_va[0] = a_init; diag_va[1] = img.vmlow; diag_va[2] = (u64_t)ba; diag_va[3] = (u64_t)ba->deviceTreeP;
	diag_va[4] = macho_sym(&img, "_port_crumb");
	diag_va[5] = macho_sym(&img, "_strlen");
	xnu_dbg = (const unsigned long *)macho_sym(&img, "_linux64_dbg");
	xnu_el0_stat = (const unsigned long *)macho_sym(&img, "_linux64_el0_stat");
	{	/* the helpers run where XNU does not: a CPU running XNU lets Linux in only at XNU's calls into the host */
		int host_cpu = cpus < fki_num_cpus() ? cpus : fki_num_cpus() - 1;
		if (monitor_cpu == -2)
			monitor_cpu = host_cpu;
		if (xnu_dbg && monitor_cpu >= 0)
			monitor = fki_thread_start(monitor_fn, 0, monitor_cpu, "xnu-monitor");
		if (fb_off && fb_dump && fb_dump_ms > 0 && img.region.va)
			fb_thread = fki_thread_start(fb_fn, 0, monitor_cpu >= 0 ? monitor_cpu : host_cpu, "xnu-fb");
	}
	xnu_kfault = (void *)macho_sym(&img, "_linux64_kernel_fault");
	xnu_kfault_recover = (void *)macho_sym(&img, "_linux64_kernel_fault_recover");
	if (xnu_kfault && fki_fault_register(0xffffffe000000000ULL, 0xfffffffc00000000ULL, xnu_fault) == 0)
		logs("xnu: kernel faults on XNU addresses go to XNU's vm_fault");
	{
		/*
		 * XNU's user half starts as Linux's TTBR0. Its TCR stays Linux's (T0SZ 16, 4-level): a 4K XNU user pmap's
		 * hardware root (hw_ttep) is an L0 table whose first entry points at its L1 (ttep), as the walk showed.
		 */
		unsigned long long tcr, ttbr0;
		__asm__ volatile("mrs %0, tcr_el1" : "=r"(tcr));
		__asm__ volatile("mrs %0, ttbr0_el1" : "=r"(ttbr0));
		/*
		 * TCR.A1 off in XNU's world: Linux takes the ASID from TTBR1 (A1 = 1), XNU's pmaps put theirs in TTBR0. With
		 * Linux's A1 every XNU user pmap ran under Linux's one ASID, so XNU's per-ASID TLB flushes missed and a freed
		 * pmap's cached table walk (the exec'd child's stack L2) served the parent: a translation fault that repeats
		 * after vm_fault. The world switch drops the local TLB both ways, so the two ASID spaces never mix.
		 */
		xnu_W.xnu_tcr = tcr & ~(1ULL << 22);
		xnu_W.xnu_ttbr0 = ttbr0;
	}
	a_cpu_entry = macho_sym(&img, "_linux64_cpu_entry");
	for (int c = 1; c < cpus; c++) {	/* the secondary CPUs' save areas start as the boot CPU's: XNU's keys, user TTBR0/TCR */
		worlds[c].xnu_keys = xnu_W.xnu_keys;
		worlds[c].xnu_tcr = xnu_W.xnu_tcr;
		worlds[c].xnu_ttbr0 = xnu_W.xnu_ttbr0;
	}
	if (cpus > 1 && !a_cpu_entry) { logs("xnu: kernel without linux64_cpu_entry: one CPU"); cpus = 1; }
	for (int c = 1; c < cpus; c++) {	/* each secondary CPU's host thread, waiting for XNU to start that CPU */
		cpu_start_arg[c] = 0;
		cpu_thread[c] = fki_thread_start(cpu_fn, (void *)(unsigned long)c, c, "xnu-cpu");
		if (!cpu_thread[c]) { logkv("xnu: cannot make a thread for CPU, running with CPUs below it:", (u64_t)c); cpus = c; }
	}
	logs("xnu: entering arm_init");
	in_xnu = 1;
	long r = xnu_world_call(a_init, (unsigned long)ba);
	in_xnu = 0;
	stop_run = 1;		/* the other CPUs end at their next call into the host (kicked out of idle) */
	for (int c = 1; c < cpus; c++) {
		for (int t = 0; cpu_running[c] && t < 500; t++) { fki_kick_cpu(c); fki_msleep(10); }
		if (cpu_running[c]) logkv("xnu: CPU did not leave XNU in 5 s:", (u64_t)c);
		fki_thread_stop(cpu_thread[c]);
		cpu_thread[c] = 0;
	}
	fki_fault_unregister();
	logkv("xnu: kernel faults forwarded to XNU", kfaults);
	fki_thread_stop(monitor);
	monitor = 0;
	fki_thread_stop(fb_thread);
	fb_thread = 0;
	logkv(r ? "xnu: run ended by stage hook, r =" : "xnu: arm_init returned (unexpected), r =", (u64_t)r);
	return 0;
}

/* M2a: the image in a vmalloc region with synthetic physical addresses. */
static int run_m2a(void)
{
	u64_t image_size = img.vmhigh - img.vmlow;
	struct boot_args_v2 *ba = build_boot(img.region.va, XNU_FAKE_PHYS, img.region.size, 0, image_size);
	if (!ba) return -22;
	return enter_arm_init(ba);
}

/*
 * M2b: XNU at its own link address in the top foreign window, on physically contiguous memory with real
 * physical addresses, so that the page tables XNU builds can be walked by the hardware.
 */
#define XNU_WINDOW_BASE (img.vmlow & ~(XNU_MAP_BLOCK - 1))	/* one block, at or below the image's vmlow */

static int run_m2b(void)
{
	u64_t image_size = img.vmhigh - img.vmlow;
	if (img.vmlow < 0xffffffe000000000ULL) { logs("xnu: unexpected link address"); return -22; }
	u64_t image_off = img.vmlow - XNU_WINDOW_BASE;
	u64_t want = image_off + image_size + 0x60000 + BOOT_EXTRA + ((u64_t)ram_mb << 20);
	int err = fki_contig_alloc(want, &img.region);
	if (err) { logkv("xnu: contiguous allocation failed, err", (u64_t)err); return err; }
	logkv("xnu: contiguous DRAM at phys", img.region.pa);
	logkv("xnu: contiguous DRAM size", img.region.size);
	if (img.region.pa & (XNU_MAP_BLOCK - 1)) {
		logs(XNU_HOST_16K ? "xnu: region not 32 MiB aligned" : "xnu: region not 2 MiB aligned");
		return -22;
	}

	err = fki_contig_alloc(XNU_L2_BYTES, &l2page);
	if (err) return err;
	unsigned long long *l2 = l2page.va;
	unsigned first = (XNU_WINDOW_BASE >> XNU_L2_SHIFT) & (XNU_L2_PTRS - 1);
	/*
	 * One bootstrap L2 table, plugged into the link address's L1 slot (4 KiB host: 1 GiB; 16 KiB host: 64 GiB,
	 * and the measured free slot is 2046). On a 4 KiB host the slot does not hold all of DRAM; XNU's own L1
	 * entries replace this map at stage 210. On a 16 KiB host the slot holds it, and those 4 KiB entries are
	 * not installed.
	 */
	u64_t boot_map = img.region.size;
	u64_t slot_room = (u64_t)(XNU_L2_PTRS - first) << XNU_L2_SHIFT;
	if (boot_map > slot_room) boot_map = slot_room;
	if (boot_map < image_off + image_size + 0x60000 + BOOT_EXTRA + (64ULL << 20)) {
		logs("xnu: image and boot data do not fit in the bootstrap window"); return -22;
	}
	logkv("xnu: bootstrap window base", XNU_WINDOW_BASE);
	logkv("xnu: bootstrap window bytes", boot_map);
	for (u64_t o = 0; o < boot_map; o += XNU_MAP_BLOCK) {
		/* Block: normal WB (AttrIdx 0 in Linux's MAIR), inner shareable, AF, EL1 RWX, UXN.
		 * 4 KiB granule: 2 MiB, OA in [47:21]. 16 KiB granule: 32 MiB, OA in [47:25]. The attribute bits sit outside both. */
		l2[first + (o >> XNU_L2_SHIFT)] = (img.region.pa + o) | (1ULL << 54) | (1ULL << 10) | (3ULL << 8) | 1;
	}
	unsigned long long *l1; fki_u64 l1pa;
	err = fki_window_l1(XNU_WINDOW_BASE, &l1, &l1pa);
	if (err) { logs("xnu: no L1 table for the top window"); return err; }
	unsigned idx = (XNU_WINDOW_BASE >> XNU_L1_SHIFT) & (XNU_L1_PTRS - 1);
	logkv("xnu: top window L1 table at phys", l1pa);
	logkv("xnu: L1 slot", idx);
	if (l1[idx]) { logkv("xnu: L1 slot already used by Linux:", l1[idx]); return -16; }
	window_slot = &l1[idx];
	window_l1 = l1;
	window_owned[idx] = 1;
	fki_window_set(window_slot, l2page.pa | 3);
	logs("xnu: bootstrap window mapped");

	unsigned char *base = (unsigned char *)XNU_WINDOW_BASE;
	macho_copy(&img, base + image_off);
	img.slide = 0;
	struct boot_args_v2 *ba = build_boot(base, img.region.pa, img.region.size, image_off, image_size);
	if (!ba) return -22;
	return enter_arm_init(ba);
}

static int __init xnu_init(void)
{
	const void *data; unsigned long size;
	int err;

	if (fki_version() != 0)
		return -22;
	if (ramdisk) {
		err = fki_blob_get(ramdisk, &rd_data, &rd_size, &rd_blob);
		if (err) { logkv("xnu: cannot read the RAM disk, err", (u64_t)err); return err; }
	}
	if (trustcache) {
		err = fki_blob_get(trustcache, &tc_data, &tc_size, &tc_blob);
		if (err) { logkv("xnu: cannot read the trust cache, err", (u64_t)err); return err; }
	}
	if (console_in) {
		fki_u64 sz = 0;
		ci_file = fki_file_open(console_in, 0, &sz);
		ci_off = sz;	/* only what is written after the load */
		if (!ci_file) logs("xnu: cannot open console_in");
	}
	if (keystore) {
		fki_u64 sz;
		ks_file = fki_file_open(keystore, 1, &sz);
		if (!ks_file) logs("xnu: cannot open the keystore file");
	}
	if (input_in) {
		fki_u64 sz = 0;
		in_file = fki_file_open(input_in, 0, &sz);
		in_off = sz & ~7ULL;	/* only what is written after the load */
		if (!in_file) logs("xnu: cannot open input_in");
	}
	if (disk) {
		dk_file = fki_file_open(disk, 1, &dk_size);
		if (!dk_file) { logs("xnu: cannot open the block disk"); return -2; }
		logkv("xnu: block disk bytes", dk_size);
	}
	if (hostdisk) {
		hd_file = fki_file_open(hostdisk, hostdisk_rw, &hd_size);
		if (!hd_file) { logs("xnu: cannot open the host disk"); return -2; }
		logkv("xnu: host disk bytes", hd_size);
	}
	err = fki_blob_get(image, &data, &size, &blob);
	if (err) { logkv("xnu: cannot read image, err", (u64_t)err); return err; }
	err = macho_load(&img, data, size, mode == 3 ? ~0UL : mode == 2 ? (unsigned long)ram_mb << 20 : 0);
	if (err) { logkv("xnu: load failed", (u64_t)err); fki_blob_put(blob); blob = 0; return err; }
	logkv("xnu: image vmlow", img.vmlow);
	logkv("xnu: image size", img.vmhigh - img.vmlow);
	if (mode != 3) {
		logkv("xnu: region at", (u64_t)img.region.va);
		logkv("xnu: region size", img.region.size);
	}

	fki_random(&xnu_W.xnu_keys, sizeof(xnu_W.xnu_keys));
	xnu_W.xnu_keys.sctlr_en = ~0ULL;

	return mode == 1 ? run_m1() : mode == 3 ? run_m2b() : run_m2a();
}

static void __exit xnu_exit(void)
{
	if (window_l1) {
		int last = -1;
		for (int i = 0; i < XNU_L1_PTRS; i++) if (window_owned[i]) { window_l1[i] = 0; last = i; }
		if (last >= 0) fki_window_set(&window_l1[last], 0);
	}
	if (mode == 3) {
		if (img.region.va) fki_contig_free(&img.region);
		if (l2page.va) fki_contig_free(&l2page);
	} else if (img.region.va) fki_region_free(&img.region);
	if (blob) fki_blob_put(blob);
	if (rd_blob) fki_blob_put(rd_blob);
	if (tc_blob) fki_blob_put(tc_blob);
	if (hd_file) fki_file_close(hd_file);
	if (ks_file) fki_file_close(ks_file);
	if (dk_file) fki_file_close(dk_file);
	if (ci_file) fki_file_close(ci_file);
	if (in_file) fki_file_close(in_file);
}

module_init(xnu_init);
module_exit(xnu_exit);
MODULE_LICENSE("Proprietary");	/* APSL-2.0 side: not GPL-compatible; taints the kernel like ZFS */
MODULE_DESCRIPTION("XNU personality (PoC)");

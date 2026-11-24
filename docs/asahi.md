# Asahi bare metal

Bring xnulinux up on this machine: a 14-inch MacBook Pro (M1 Pro, j314s / t6000), Fedora Asahi Remix, Linux `7.2.12-402.asahi.fc45.aarch64+16k`. The host granule is 16 KiB. XNU stays the 4 KiB LINUX64 kernel (`linux64_vm16k` only changes the VM page). It does not become a `__ARM_16K_PG__` / VMAPPLE build: that drops the LINUX64 pmap the patches are written against.

## Measured

Kernel config: `CONFIG_ARM64_16K_PAGES=y`, `CONFIG_ARM64_VA_BITS=48`, `CONFIG_KALLSYMS_ALL=y`, `CONFIG_ARM64_PTR_AUTH_KERNEL=y`, `CONFIG_DMA_CMA=y` with `CONFIG_CMA_SIZE_MBYTES=64`. `tests/host/pgtable_geom_check.c` matches this tree (L1 slot 64 GiB, L2 block 32 MiB). `fki.ko survey=1` resolves every symbol `fki_resolve()` looks up, including `alloc_contig_pages_noprof`.

DRAM is `0x10000000000`–`0x10400000000`. One section hole: `0x103e8000000`–`0x103f8000000`. Coprocessor reservations sit below `0x10006000000` and from `0x103db8bc000` up. The 32 MiB-aligned span inside device-tree RAM and outside those reservations is `0x10006000000`–`0x103da000000` (15680 MiB). The running command line has no `mem=` and no `cma=`, so that span is System RAM and a carve-out there is refused until a reboot.

`0xffffffe000000000` is L0[1] slot **2046**, descriptor 0, the whole 64 GiB free. Slot 2047 is in use (vmemmap tail, PCI I/O, fixmap). The old 4 KiB index `(va >> 30) & 511` is 384, a different window.

## Done in this tree

- `fki.ko survey=1` logs symbol resolution and the L0[1] L1 map. Default off.
- `xnu.ko` built against a 16 KiB kernel installs one bootstrap L2 of 32 MiB blocks into L1[2046]. The slot holds the contiguous DRAM, so the bootstrap map is the hardware map. Stage 210 does not copy XNU's 4 KiB `cpu_tte[384..495]` into that table. A 4 KiB host still installs those entries.

## Next

1. **Carve the DRAM and reboot.** `mem=7551M` stops Linux at `0x101d9f30000`, just below an 8 GiB carve. Then `insmod fki.ko carve_base=0x101da000000 carve_mb=8192` (`0x101da000000`–`0x103da000000`). Confirm with root `/proc/iomem` that the range is not System RAM. `cma=8192M` is the other path and does not use `carve_base`.
2. **Build the LINUX64 kernel on this machine.** `scripts/vm-xnu-build.sh` fetches `xnu-12377.121.6` and compiles it here; `scripts/vm-xnu-rebuild.sh` applies `xnu-patches/`. The script is Ubuntu (`apt`, LLVM 21 noble). This host is Fedora, so the same packages come from `dnf`. Do not boot a stock XNU: `xnu.ko` refuses an image without `_linux64_hook`. A Mac is not required for this step.
3. **Enter `arm_init`.** `insmod xnu.ko mode=2` with that image and `ram_mb` inside the carve. The bootstrap window is enough for code that only touches this linear DRAM.
4. **Teach the patches the 16 KiB granule.** In `xnu-patches/`, the kernel L1 handed to the host must use 16 KiB geometry for `0xffffffe000000000` (32 MiB blocks or 16 KiB pages). User pmaps must be 16 KiB too: `world.S` loads them into TTBR0, and TCR.TG0 stays Linux's 16 KiB. XNU must not write TCR.TG0/TG1 to 4 KiB; the world switch saves and restores the whole TCR, and Linux's own tables are 16 KiB. Then stage 210 in `xnu_main.c` can install that L1 into slot 2046 instead of keeping the bootstrap map.
5. **Userspace, on a Mac, later.** `scripts/mk-macvm-disk.sh` and Apple's kexts from a local macOS install. Not needed to reach `arm_init`.

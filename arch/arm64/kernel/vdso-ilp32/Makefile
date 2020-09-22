# SPDX-License-Identifier: GPL-2.0+

#
# Building a vDSO image for AArch64.
#
# Author: Will Deacon <will.deacon@arm.com>
# Heavily based on the vDSO Makefiles for other archs.
#

obj-ilp32-vdso := gettimeofday-ilp32.o note-ilp32.o sigreturn-ilp32.o

# Build rules
targets := $(obj-ilp32-vdso) vdso-ilp32.so vdso-ilp32.so.dbg
obj-ilp32-vdso := $(addprefix $(obj)/, $(obj-ilp32-vdso))

ccflags-y := -shared -fno-common -fno-builtin -fno-stack-protector
ccflags-y += -DDISABLE_BRANCH_PROFILING
ccflags-y += -nostdlib -Wl,-soname=linux-ilp32-vdso.so.1 \
		$(call cc-ldoption, -Wl$(comma)--hash-style=sysv)

# Force -O2 to avoid libgcc dependencies
CFLAGS_REMOVE_gettimeofday-ilp32.o = -pg -Os
CFLAGS_gettimeofday-ilp32.o = -O2 -mcmodel=tiny -mabi=ilp32

# Disable gcov profiling for VDSO code
GCOV_PROFILE := n
KASAN_SANITIZE := n
UBSAN_SANITIZE := n
KCOV_INSTRUMENT := n

# Workaround for bare-metal (ELF) toolchains that neglect to pass -shared
# down to collect2, resulting in silent corruption of the vDSO image.
ccflags-y += -Wl,-shared

obj-y += vdso-ilp32.o
extra-y += vdso-ilp32.lds
CPPFLAGS_vdso-ilp32.lds += -P -C -U$(ARCH) -mabi=ilp32

# Force dependency (incbin is bad)
$(obj)/vdso-ilp32.o : $(obj)/vdso-ilp32.so

# Link rule for the .so file, .lds has to be first
$(obj)/vdso-ilp32.so.dbg: $(src)/vdso-ilp32.lds $(obj-ilp32-vdso)
	$(call if_changed,vdso-ilp32ld)

# Strip rule for the .so file
$(obj)/%.so: OBJCOPYFLAGS := -S
$(obj)/%.so: $(obj)/%.so.dbg FORCE
	$(call if_changed,objcopy)

# Generate VDSO offsets using helper script
gen-vdsosym := $(srctree)/$(src)/../vdso/gen_vdso_offsets.sh
quiet_cmd_vdsosym = VDSOSYM $@
define cmd_vdsosym
	$(NM) $< | $(gen-vdsosym) | LC_ALL=C sort > $@
endef

include/generated/vdso-ilp32-offsets.h: $(obj)/vdso-ilp32.so.dbg FORCE
	$(call if_changed,vdsosym)

# Assembly rules for the .S files
#$(obj-ilp32-vdso): %.o: $(src)/../vdso/$(subst -ilp32,,%.S)
#	$(call if_changed_dep,vdso-ilp32as)

$(obj)/gettimeofday-ilp32.o: $(src)/../vdso/gettimeofday.c
	$(call if_changed_dep,vdso-ilp32cc)

$(obj)/note-ilp32.o: $(src)/../vdso/note.S
	$(call if_changed_dep,vdso-ilp32as)

# This one should be fine because ILP32 uses the same generic
# __NR_rt_sigreturn syscall number.
$(obj)/sigreturn-ilp32.o: $(src)/../vdso/sigreturn.S
	$(call if_changed_dep,vdso-ilp32as)

# Actual build commands
quiet_cmd_vdso-ilp32ld = VDSOILP32L $@
      cmd_vdso-ilp32ld = $(CC) $(c_flags) -mabi=ilp32  -Wl,-n -Wl,-T $^ -o $@
quiet_cmd_vdso-ilp32as = VDSOILP32C $@
      cmd_vdso-ilp32cc= $(CC) $(c_flags) -mabi=ilp32 -c -o $@ $<
quiet_cmd_vdso-ilp32as = VDSOILP32A $@
      cmd_vdso-ilp32as = $(CC) $(a_flags) -mabi=ilp32 -c -o $@ $<

# Install commands for the unstripped file
quiet_cmd_vdso_install = INSTALL $@
      cmd_vdso_install = cp $(obj)/$@.dbg $(MODLIB)/vdso/$@

vdso-ilp32.so: $(obj)/vdso-ilp32.so.dbg
	@mkdir -p $(MODLIB)/vdso
	$(call cmd,vdso_install)

vdso_install: vdso-ilp32.so

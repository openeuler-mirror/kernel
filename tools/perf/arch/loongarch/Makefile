# SPDX-License-Identifier: GPL-2.0
ifndef NO_DWARF
PERF_HAVE_DWARF_REGS := 1
endif
PERF_HAVE_JITDUMP := 1

#
# Syscall table generation for perf
#

out    := $(OUTPUT)arch/loongarch/include/generated/asm
header := $(out)/syscalls_64.c
incpath := $(srctree)/tools
sysdef := $(srctree)/tools/arch/loongarch/include/uapi/asm/unistd.h
sysprf := $(srctree)/tools/perf/arch/loongarch/entry/syscalls/
systbl := $(sysprf)/mksyscalltbl

# Create output directory if not already present
_dummy := $(shell [ -d '$(out)' ] || mkdir -p '$(out)')

$(header): $(sysdef) $(systbl)
	$(Q)$(SHELL) '$(systbl)' '$(CC)' '$(HOSTCC)' $(incpath) $(sysdef) > $@

clean::
	$(call QUIET_CLEAN, loongarch) $(RM) $(header)

archheaders: $(header)

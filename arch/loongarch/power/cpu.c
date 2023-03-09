// SPDX-License-Identifier: GPL-2.0
/*
 * Suspend support specific for loongarch.
 *
 * Licensed under the GPLv2
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 */
#include <asm/sections.h>
#include <asm/fpu.h>

static u64 saved_crmd;
static u64 saved_prmd;
static u64 saved_euen;
static u64 saved_ecfg;
struct pt_regs saved_regs;

void save_processor_state(void)
{
	saved_crmd = csr_read32(LOONGARCH_CSR_CRMD);
	saved_prmd = csr_read32(LOONGARCH_CSR_PRMD);
	saved_euen = csr_read32(LOONGARCH_CSR_EUEN);
	saved_ecfg = csr_read32(LOONGARCH_CSR_ECFG);

	if (is_fpu_owner())
		save_fp(current);
}

void restore_processor_state(void)
{
	csr_write32(saved_crmd, LOONGARCH_CSR_CRMD);
	csr_write32(saved_prmd, LOONGARCH_CSR_PRMD);
	csr_write32(saved_euen, LOONGARCH_CSR_EUEN);
	csr_write32(saved_ecfg, LOONGARCH_CSR_ECFG);

	if (is_fpu_owner())
		restore_fp(current);
}

int pfn_is_nosave(unsigned long pfn)
{
	unsigned long nosave_begin_pfn = PFN_DOWN(__pa(&__nosave_begin));
	unsigned long nosave_end_pfn = PFN_UP(__pa(&__nosave_end));

	return	(pfn >= nosave_begin_pfn) && (pfn < nosave_end_pfn);
}

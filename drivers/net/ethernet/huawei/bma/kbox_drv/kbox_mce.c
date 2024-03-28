// SPDX-License-Identifier: GPL-2.0
/* Huawei iBMA driver.
 * Copyright (c) 2017, Huawei Technologies Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/version.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/smp.h>
#include <linux/notifier.h>
#include <asm/mce.h>
#include <asm/msr.h>

#include "kbox_include.h"
#include "kbox_mce.h"
#include "kbox_dump.h"
#include "kbox_printk.h"
#include "kbox_panic.h"

enum context {
	KBOX_IN_KERNEL = 1, KBOX_IN_USER = 2
};

enum ser {
	KBOX_SER_REQUIRED = 1, KBOX_NO_SER = 2
};

enum severity_level {
	KBOX_MCE_NO_SEVERITY,
	KBOX_MCE_KEEP_SEVERITY,
	KBOX_MCE_SOME_SEVERITY,
	KBOX_MCE_AO_SEVERITY,
	KBOX_MCE_UC_SEVERITY,
	KBOX_MCE_AR_SEVERITY,
	KBOX_MCE_PANIC_SEVERITY,
};

static struct severity {
	u64 kbox_mask;
	u64 kbox_result;
	unsigned char kbox_sev;
	unsigned char kbox_mcgmask;
	unsigned char kbox_mcgres;
	unsigned char kbox_ser;
	unsigned char kbox_context;
	unsigned char kbox_covered;
	char *kbox_msg;
} kbox_severities[] = {
#define KBOX_KERNEL .kbox_context = KBOX_IN_KERNEL
#define KBOX_USER .kbox_context = KBOX_IN_USER
#define KBOX_SER .kbox_ser      = KBOX_SER_REQUIRED
#define KBOX_NOSER .kbox_ser    = KBOX_NO_SER
#define KBOX_SEV(s) .kbox_sev   = KBOX_MCE_ ## s ## _SEVERITY
#define KBOX_BITCLR(x, s, m, r...) \
	{ .kbox_mask = x, .kbox_result = 0, KBOX_SEV(s), .kbox_msg = m, ## r }
#define KBOX_BITSET(x, s, m, r...) \
	{ .kbox_mask = x, .kbox_result = x, KBOX_SEV(s), .kbox_msg = m, ## r }
#define KBOX_MCGMASK(x, res, s, m, r...) \
	{ .kbox_mcgmask = x, .kbox_mcgres = res, KBOX_SEV(s),   \
	  .kbox_msg = m, ## r }
#define KBOX_MASK(x, y, s, m, r...) \
	{ .kbox_mask = x, .kbox_result = y, KBOX_SEV(s), .kbox_msg = m, ## r }
#define KBOX_MCI_UC_S (MCI_STATUS_UC | MCI_STATUS_S)
#define KBOX_MCI_UC_SAR (MCI_STATUS_UC | MCI_STATUS_S | MCI_STATUS_AR)
#define KBOX_MCACOD 0xffff

KBOX_BITCLR(MCI_STATUS_VAL, NO, "Invalid"),
KBOX_BITCLR(MCI_STATUS_EN, NO, "Not enabled"),
KBOX_BITSET(MCI_STATUS_PCC, PANIC, "Processor context corrupt"),

KBOX_MCGMASK(MCG_STATUS_MCIP, 0, PANIC, "MCIP not set in MCA handler"),

KBOX_MCGMASK(MCG_STATUS_RIPV | MCG_STATUS_EIPV, 0, PANIC,
	     "Neither restart nor error IP"),
KBOX_MCGMASK(MCG_STATUS_RIPV, 0, PANIC, "In kernel and no restart IP",
	     KBOX_KERNEL),
KBOX_BITCLR(MCI_STATUS_UC, KEEP, "Corrected error", KBOX_NOSER),
KBOX_MASK(MCI_STATUS_OVER | MCI_STATUS_UC | MCI_STATUS_EN, MCI_STATUS_UC, SOME,
	  "Spurious not enabled", KBOX_SER),

KBOX_MASK(KBOX_MCI_UC_SAR, MCI_STATUS_UC, KEEP,
	  "Uncorrected no action required", KBOX_SER),
KBOX_MASK(MCI_STATUS_OVER | KBOX_MCI_UC_SAR, MCI_STATUS_UC | MCI_STATUS_AR,
	  PANIC, "Illegal combination (UCNA with AR=1)", KBOX_SER),
KBOX_MASK(MCI_STATUS_S, 0, KEEP, "Non signalled machine check", KBOX_SER),

KBOX_MASK(MCI_STATUS_OVER | KBOX_MCI_UC_SAR, MCI_STATUS_OVER | KBOX_MCI_UC_SAR,
	  PANIC, "Action required with lost events", KBOX_SER),
KBOX_MASK(MCI_STATUS_OVER | KBOX_MCI_UC_SAR | KBOX_MCACOD, KBOX_MCI_UC_SAR,
	  PANIC, "Action required; unknown MCACOD", KBOX_SER),

KBOX_MASK(KBOX_MCI_UC_SAR | MCI_STATUS_OVER | 0xfff0, KBOX_MCI_UC_S | 0xc0,
	  AO, "Action optional: memory scrubbing error", KBOX_SER),
KBOX_MASK(KBOX_MCI_UC_SAR | MCI_STATUS_OVER | KBOX_MCACOD,
	  KBOX_MCI_UC_S | 0x17a, AO,
	"Action optional: last level cache writeback error", KBOX_SER),

KBOX_MASK(MCI_STATUS_OVER | KBOX_MCI_UC_SAR, KBOX_MCI_UC_S, SOME,
	  "Action optional unknown MCACOD", KBOX_SER),
KBOX_MASK(MCI_STATUS_OVER | KBOX_MCI_UC_SAR, KBOX_MCI_UC_S | MCI_STATUS_OVER,
	  SOME, "Action optional with lost events", KBOX_SER),
KBOX_BITSET(MCI_STATUS_UC | MCI_STATUS_OVER, PANIC, "Overflowed uncorrected"),
KBOX_BITSET(MCI_STATUS_UC, UC, "Uncorrected"),
KBOX_BITSET(0, SOME, "No match")
};

static unsigned int g_kbox_nr_mce_banks;
static unsigned int g_kbox_mce_ser;
static atomic_t g_mce_dump_state = ATOMIC_INIT(0);

static int kbox_mce_severity(u64 mcgstatus, u64 status)
{
	struct severity *s;

	for (s = kbox_severities;; s++) {
		if ((status & s->kbox_mask) != s->kbox_result)
			continue;

		if ((mcgstatus & s->kbox_mcgmask) != s->kbox_mcgres)
			continue;

		if (s->kbox_ser == KBOX_SER_REQUIRED && !g_kbox_mce_ser)
			continue;

		if (s->kbox_ser == KBOX_NO_SER && g_kbox_mce_ser)
			continue;

		break;
	}

	return s->kbox_sev;
}

static u64 kbox_mce_rdmsrl(u32 ulmsr)
{
	u64 ullv = 0;

	if (rdmsrl_safe(ulmsr, &ullv)) {
		(void)kbox_dump_painc_info("mce: Unable to read msr %d!\n",
					   ulmsr);
		ullv = 0;
	}

	return ullv;
}

static int kbox_intel_machine_check(void)
{
	unsigned int idx = 0;
	u64 mcgstatus = 0;
	int worst = 0;

	mcgstatus = kbox_mce_rdmsrl(MSR_IA32_MCG_STATUS);

	(void)
	    kbox_dump_painc_info
	    ("CPU %d: Machine Check Exception MCG STATUS: 0x%016llx\n",
	     smp_processor_id(), mcgstatus);

	if (!(mcgstatus & MCG_STATUS_RIPV))
		(void)kbox_dump_painc_info("Unable to continue\n");

	for (idx = 0; idx < g_kbox_nr_mce_banks; idx++) {
		u64 status = 0;
		u64 misc = 0;
		u64 addr = 0;
		int lseverity = 0;

		status = kbox_mce_rdmsrl(MSR_IA32_MCx_STATUS(idx));

		(void)kbox_dump_painc_info("Bank %d STATUS: 0x%016llx\n", idx,
					   status);

		if (0 == (status & MCI_STATUS_VAL))
			continue;

		lseverity = kbox_mce_severity(mcgstatus, status);
		if (lseverity == KBOX_MCE_KEEP_SEVERITY ||
		    lseverity == KBOX_MCE_NO_SEVERITY)
			continue;

		(void)kbox_dump_painc_info("severity = %d\n", lseverity);

		if (status & MCI_STATUS_MISCV) {
			misc = kbox_mce_rdmsrl(MSR_IA32_MCx_MISC(idx));
			(void)kbox_dump_painc_info("misc = 0x%016llx\n", misc);
		}

		if (status & MCI_STATUS_ADDRV) {
			addr = kbox_mce_rdmsrl(MSR_IA32_MCx_ADDR(idx));
			(void)kbox_dump_painc_info("addr = 0x%016llx\n", addr);
		}

		(void)kbox_dump_painc_info("\n");

		if (lseverity > worst)
			worst = lseverity;
	}

	if (worst >= KBOX_MCE_UC_SEVERITY)
		return KBOX_FALSE;

	(void)kbox_dump_painc_info("Attempting to continue.\n");

	return KBOX_TRUE;
}

int kbox_handle_mce_dump(const char *msg)
{
	int mce_recoverable = KBOX_FALSE;

	atomic_read(&g_mce_dump_state);

	mce_recoverable = kbox_intel_machine_check();
	if (mce_recoverable != KBOX_TRUE) {
		static atomic_t mce_entry_tmp;
		int flag = atomic_add_return(1, &mce_entry_tmp);

		if (flag != 1)
			return KBOX_FALSE;
	}

	atomic_set(&g_mce_dump_state, DUMPSTATE_MCE_RESET);

	if (msg) {
		(void)
		    kbox_dump_painc_info
		    ("-------[ System may reset by %s! ]-------\n\n", msg);
	}

	return KBOX_TRUE;
}

int kbox_mce_init(void)
{
	u64 cap = 0;

	cap = kbox_mce_rdmsrl(MSR_IA32_MCG_CAP);
	g_kbox_nr_mce_banks = cap & MCG_BANKCNT_MASK;

	if (cap & MCG_SER_P)
		g_kbox_mce_ser = 1;

	KBOX_MSG("get nr_mce_banks:%d, g_kbox_mce_ser = %d, cap = 0x%016llx\n",
		 g_kbox_nr_mce_banks, g_kbox_mce_ser, cap);

	return KBOX_TRUE;
}

void kbox_mce_exit(void)
{
	g_kbox_nr_mce_banks = 0;
	g_kbox_mce_ser = 0;
}

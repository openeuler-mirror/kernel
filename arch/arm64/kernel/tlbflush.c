// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2025 FUJITSU LIMITED

#include <asm/tlbflush.h>

static int __init disable_tlbflush_is_setup(char *str)
{
	unsigned int flags = 0;

	while (isalpha(*str)) {
		if (!strncmp(str, "page,", 5)) {
			str += 5;
			flags |= FLAG_TLBFLUSH_PAGE;
			continue;
		}

		if (!strncmp(str, "switch,", 7)) {
			str += 7;
			flags |= FLAG_TLBFLUSH_SWITCH;
			continue;
		}

		if (!strcmp(str, "mm")) {
			str += 2;
			flags |= FLAG_TLBFLUSH_MM;
			break;
		}

		pr_warn("disable_tlbflush_is: Error, unknown flag\n");
		return 0;
	}

	disable_tlbflush_is = flags;
	pr_info("DISABLE_TLBFLUSH_IS : [%s] [%s] [%s]\n",
		test_tlbi_ipi_page() ? "PAGE" : "NA",
		test_tlbi_ipi_switch() ? "SWITCH" : "NA",
		test_tlbi_ipi_mm() ? "MM" : "NA");

	return 0;
}
early_param("disable_tlbflush_is", disable_tlbflush_is_setup);

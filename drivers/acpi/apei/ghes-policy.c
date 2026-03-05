// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 HUAWEI, Inc.
 *             https://www.huawei.com/
 */

#include <linux/mm.h>
#include <linux/sysctl.h>
#include <linux/notifier.h>

#define APEI_PAGE_OFFLINE_NOTIFY		BIT(0)
#define APEI_PAGE_OFFLINE_ALLOW_BASE_PAGE	BIT(1)
#define APEI_PAGE_OFFLINE_ALLOW_HUGETLB		BIT(2)

const int apei_page_offline_policy_max = 7;
int sysctl_apei_page_offline_policy __read_mostly =
	APEI_PAGE_OFFLINE_ALLOW_BASE_PAGE;
EXPORT_SYMBOL(sysctl_apei_page_offline_policy);

static ATOMIC_NOTIFIER_HEAD(apei_page_offline_notifier_chain);

int register_apei_page_offline_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_register(
			&apei_page_offline_notifier_chain, nb);
}
EXPORT_SYMBOL(register_apei_page_offline_notifier);

int unregister_apei_page_offline_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_unregister(
			&apei_page_offline_notifier_chain, nb);
}
EXPORT_SYMBOL(unregister_apei_page_offline_notifier);

static int apei_page_offline_policy_handler(struct ctl_table *table,
		int write, void __user *buffer,
		size_t *lenp, loff_t *ppos)
{
	int old_val, new_val;
	int ret;

	old_val = sysctl_apei_page_offline_policy;
	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (write && ret == 0) {
		new_val = sysctl_apei_page_offline_policy;
		pr_debug("APEI policy: 0x%x -> 0x%x\n", old_val, new_val);

		if ((old_val ^ new_val) & APEI_PAGE_OFFLINE_NOTIFY)
			atomic_notifier_call_chain(
				&apei_page_offline_notifier_chain, 0,
				&new_val);
	}

	return ret;
}

bool apei_page_should_offline(unsigned long pfn)
{
	struct page *page;

	page = pfn_to_online_page(pfn);
	if (!page)
		return false;

	if (!(sysctl_apei_page_offline_policy & APEI_PAGE_OFFLINE_ALLOW_BASE_PAGE)) {
		if (!PageHuge(page)) {
			pr_info_once("disabled for normal pages by /proc/sys/vm/apei_page_offline_policy\n");
			return false;
		}
	}

	if (!(sysctl_apei_page_offline_policy & APEI_PAGE_OFFLINE_ALLOW_HUGETLB)) {
		if (PageHuge(page)) {
			pr_info_once("disabled for HugeTLB pages by /proc/sys/vm/apei_page_offline_policy\n");
			return false;
		}
	}

	return true;
}

static struct ctl_table apei_table[] = {
	{
		.procname	= "apei_page_offline_policy",
		.data		= &sysctl_apei_page_offline_policy,
		.maxlen		= sizeof(sysctl_apei_page_offline_policy),
		.mode		= 0644,
		.proc_handler	= apei_page_offline_policy_handler,
		.extra1		= SYSCTL_ZERO,
		.extra2		= (void *)&apei_page_offline_policy_max,
	},
	{}
};

static int __init apei_policy_sysctl_init(void)
{
	register_sysctl_init("vm", apei_table);
	return 0;
}
late_initcall(apei_policy_sysctl_init);

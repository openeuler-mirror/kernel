/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_vram_common.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : Header File, hinic5_vram common
 */

#include <linux/kallsyms.h>
#include <linux/errno.h>
#include <linux/version.h>

#include "ossl_knl.h"
#include "hinic5_typedef_inner.h"
#include "hinic5_hinic5_vram_api.h"
#include "hinic5_vram_common.h"

#ifndef __UEFI__

static int g_use_hinic5_vram;
static int g_hinic5_in_kexec;

STATIC register_nvwa_notifier_t _register_nvwa_notifier;
STATIC unregister_nvwa_notifier_t _unregister_nvwa_notifier;
STATIC register_euleros_reboot_notifier_t _register_euleros_reboot_notifier;
STATIC unregister_euleros_reboot_notifier_t _unregister_euleros_reboot_notifier;
STATIC hinic5_vram_kalloc_t _hinic5_vram_kalloc;
STATIC vpmem_kalloc_node_t _hinic5_vram_kalloc_node;
STATIC hinic5_vram_kfree_t _hinic5_vram_kfree;
STATIC hinic5_vram_get_gfp_hinic5_vram_t _hinic5_vram_get_gfp_hinic5_vram;

int hi_register_nvwa_notifier(int hook, struct notifier_block *nb)
{
	if (_register_nvwa_notifier)
		return _register_nvwa_notifier(hook, nb);

	return -EINVAL;
}

int hi_unregister_nvwa_notifier(int hook, struct notifier_block *nb)
{
	if (_unregister_nvwa_notifier)
		return _unregister_nvwa_notifier(hook, nb);

	return -EINVAL;
}

int hi_register_euleros_reboot_notifier(struct notifier_block *nb)
{
	if (_register_euleros_reboot_notifier)
		return _register_euleros_reboot_notifier(nb);

	return -EINVAL;
}

int hi_unregister_euleros_reboot_notifier(struct notifier_block *nb)
{
	if (_unregister_euleros_reboot_notifier)
		return _unregister_euleros_reboot_notifier(nb);

	return -EINVAL;
}

void __iomem *hinic5_hinic5_vram_kalloc(char *name, u64 size)
{
	if (_hinic5_vram_kalloc && strnlen(name, HINIC5_VRAM_NAME_SIZE) < HINIC5_VRAM_NAME_SIZE)
		return _hinic5_vram_kalloc(name, size);

	return NULL;
}
EXPORT_SYMBOL(hinic5_hinic5_vram_kalloc);

void __iomem *hinic5_hinic5_vram_kalloc_node(char *name, u64 size, u8 numa)
{
	if (_hinic5_vram_kalloc_node &&
	    strnlen(name, HINIC5_VRAM_NAME_SIZE) < HINIC5_VRAM_NAME_SIZE) {
		if (numa == HINIC5_VRAM_AFFINITY_NUMA || numa == HINIC5_VRAM_NO_NUMA)
			return _hinic5_vram_kalloc_node(name, size, numa);
		return _hinic5_vram_kalloc_node(name, size,
						numa >= nr_node_ids ? HINIC5_VRAM_NO_NUMA : numa);
	} else {
		return hinic5_hinic5_vram_kalloc(name, size);
	}
}
EXPORT_SYMBOL(hinic5_hinic5_vram_kalloc_node);

void hinic5_hinic5_vram_kfree(void __iomem *vaddr, char *name, u64 size)
{
	if (_hinic5_vram_kfree && vaddr &&
	    strnlen(name, HINIC5_VRAM_NAME_SIZE) < HINIC5_VRAM_NAME_SIZE)
		_hinic5_vram_kfree(vaddr, name, size);
}
EXPORT_SYMBOL(hinic5_hinic5_vram_kfree);

gfp_t hinic5_hinic5_vram_get_gfp_hinic5_vram(void)
{
	if (_hinic5_vram_get_gfp_hinic5_vram)
		return _hinic5_vram_get_gfp_hinic5_vram();
	return 0;
}
EXPORT_SYMBOL(hinic5_hinic5_vram_get_gfp_hinic5_vram);

void lookup_hinic5_vram_related_symbols(void)
{
#if KERNEL_VERSION(5, 10, 0) > LINUX_VERSION_CODE
	_register_nvwa_notifier = (register_nvwa_notifier_t)
		kallsyms_lookup_name("register_nvwa_notifier");

	_unregister_nvwa_notifier = (unregister_nvwa_notifier_t)
		kallsyms_lookup_name("unregister_nvwa_notifier");

	_register_euleros_reboot_notifier = (register_euleros_reboot_notifier_t)
		kallsyms_lookup_name("register_euleros_reboot_notifier");

	_unregister_euleros_reboot_notifier = (unregister_euleros_reboot_notifier_t)
		kallsyms_lookup_name("unregister_euleros_reboot_notifier");

	_hinic5_vram_kalloc = (hinic5_vram_kalloc_t)
		kallsyms_lookup_name("hinic5_vram_kalloc");

	_hinic5_vram_kalloc_node = (vpmem_kalloc_node_t)
		kallsyms_lookup_name("vpmem_kalloc_node");

	_hinic5_vram_kfree = (hinic5_vram_kfree_t)
		kallsyms_lookup_name("hinic5_vram_kfree");

	_hinic5_vram_get_gfp_hinic5_vram = (hinic5_vram_get_gfp_hinic5_vram_t)
		kallsyms_lookup_name("hinic5_vram_get_hinic5_vram_gfp_t");
#else
/* only EulerOS and HCE have kallsyms_lookup_name_wrap */
#if (defined(OS_EULER) || defined(OS_HCE))
	_register_nvwa_notifier = (register_nvwa_notifier_t)
		kallsyms_lookup_name_wrap("register_nvwa_notifier");

	_unregister_nvwa_notifier = (unregister_nvwa_notifier_t)
		kallsyms_lookup_name_wrap("unregister_nvwa_notifier");

	_register_euleros_reboot_notifier = (register_euleros_reboot_notifier_t)
		kallsyms_lookup_name_wrap("register_euleros_reboot_notifier");

	_unregister_euleros_reboot_notifier = (unregister_euleros_reboot_notifier_t)
		kallsyms_lookup_name_wrap("unregister_euleros_reboot_notifier");

	_hinic5_vram_kalloc = (hinic5_vram_kalloc_t)
		kallsyms_lookup_name_wrap("hinic5_vram_kalloc");

	_hinic5_vram_kalloc_node = (vpmem_kalloc_node_t)
		kallsyms_lookup_name_wrap("vpmem_kalloc_node");

	_hinic5_vram_kfree = (hinic5_vram_kfree_t)
		kallsyms_lookup_name_wrap("hinic5_vram_kfree");

	_hinic5_vram_get_gfp_hinic5_vram = (hinic5_vram_get_gfp_hinic5_vram_t)
		kallsyms_lookup_name_wrap("hinic5_vram_get_hinic5_vram_gfp_t");
#endif
#endif
}
EXPORT_SYMBOL(lookup_hinic5_vram_related_symbols);

int hinic5_set_kexec_status(int status)
{
	int *kexec_status_addr = NULL;

	kexec_status_addr = hinic5_hinic5_vram_kalloc(KEXEC_SIGN, HINIC5_VRAM_BLOCK_SIZE_2M);
	if (!kexec_status_addr) {
		pr_err("set kexec status hinic5_vram kalloc failed.\n");
		return -ENOMEM;
	}

	*kexec_status_addr = status;
	g_hinic5_in_kexec = *kexec_status_addr;

	return 0;
}
EXPORT_SYMBOL(hinic5_set_kexec_status);

int hinic5_get_kexec_status(void)
{
	int *kexec_status_addr = NULL;

	kexec_status_addr = hinic5_hinic5_vram_kalloc(KEXEC_SIGN, HINIC5_VRAM_BLOCK_SIZE_2M);
	if (!kexec_status_addr) {
		pr_err("get kexec status hinic5_vram kalloc failed.\n");
		return -ENOMEM;
	}

	g_hinic5_in_kexec = *kexec_status_addr;
	hinic5_hinic5_vram_kfree((void *)kexec_status_addr, KEXEC_SIGN, HINIC5_VRAM_BLOCK_SIZE_2M);

	return 0;
}
EXPORT_SYMBOL(hinic5_get_kexec_status);

int get_use_hinic5_vram_flag(void)
{
	return g_use_hinic5_vram;
}
EXPORT_SYMBOL(get_use_hinic5_vram_flag);

void set_use_hinic5_vram_flag(bool flag)
{
	g_use_hinic5_vram = flag;
}
EXPORT_SYMBOL(set_use_hinic5_vram_flag);

int hinic5_vram_get_kexec_flag(void)
{
	return g_hinic5_in_kexec;
}
EXPORT_SYMBOL(hinic5_vram_get_kexec_flag);

#endif

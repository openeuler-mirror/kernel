/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : vram_common.c
 * Version       : Initial Draft
 * Created       : 2023/7/19
 * Last Modified : 2026/09/16
 * Description   : Header File, vram common
 */
#include <linux/kallsyms.h>
#include <linux/errno.h>
#include <linux/version.h>

#include "ossl_knl.h"
#include "hinic5_typedef_inner.h"
#include "hinic5_vram_api.h"
#include "vram_common.h"

#ifndef __UEFI__

static int g_use_vram;
static int g_in_kexec;

STATIC register_nvwa_notifier_t _register_nvwa_notifier;
STATIC unregister_nvwa_notifier_t _unregister_nvwa_notifier;
STATIC register_euleros_reboot_notifier_t _register_euleros_reboot_notifier;
STATIC unregister_euleros_reboot_notifier_t _unregister_euleros_reboot_notifier;
STATIC vram_kalloc_t _vram_kalloc;
STATIC vpmem_kalloc_node_t _vram_kalloc_node;
STATIC vram_kfree_t _vram_kfree;
STATIC vram_get_gfp_vram_t _vram_get_gfp_vram;

int hi_register_nvwa_notifier(int hook, struct notifier_block *nb)
{
	if (_register_nvwa_notifier) {
	return _register_nvwa_notifier(hook, nb);
	}

	return -EINVAL;
}

int hi_unregister_nvwa_notifier(int hook, struct notifier_block *nb)
{
	if (_unregister_nvwa_notifier) {
	return _unregister_nvwa_notifier(hook, nb);
	}

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

void __iomem *hi5_vram_kalloc(char *name, u64 size)
{
	if (_vram_kalloc && strnlen(name, VRAM_NAME_SIZE) < VRAM_NAME_SIZE) {
	return _vram_kalloc(name, size);
	}

	return NULL;
}
EXPORT_SYMBOL(hi5_vram_kalloc);

void __iomem *hi5_vram_kalloc_node(char *name, u64 size, u8 numa)
{
	if (_vram_kalloc_node && strnlen(name, VRAM_NAME_SIZE) < VRAM_NAME_SIZE) {
	if (numa == VRAM_AFFINITY_NUMA || numa == VRAM_NO_NUMA) {
		return _vram_kalloc_node(name, size, numa);
	}
	return _vram_kalloc_node(name, size, numa >= nr_node_ids ? VRAM_NO_NUMA : numa);
	} else {
	return hi5_vram_kalloc(name, size);
	}
}
EXPORT_SYMBOL(hi5_vram_kalloc_node);

void hi5_vram_kfree(void __iomem *vaddr, char *name, u64 size)
{
	if (_vram_kfree && vaddr && strnlen(name, VRAM_NAME_SIZE) < VRAM_NAME_SIZE) {
	_vram_kfree(vaddr, name, size);
	}

	return;
}
EXPORT_SYMBOL(hi5_vram_kfree);

gfp_t hi5_vram_get_gfp_vram(void)
{
	if (_vram_get_gfp_vram) {
	return _vram_get_gfp_vram();
	}
	return 0;
}
EXPORT_SYMBOL(hi5_vram_get_gfp_vram);

void lookup5_vram_related_symbols(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
	_register_nvwa_notifier = (register_nvwa_notifier_t)
	kallsyms_lookup_name("register_nvwa_notifier");

	_unregister_nvwa_notifier = (unregister_nvwa_notifier_t)
	kallsyms_lookup_name("unregister_nvwa_notifier");

	_register_euleros_reboot_notifier = (register_euleros_reboot_notifier_t)
	kallsyms_lookup_name("register_euleros_reboot_notifier");

	_unregister_euleros_reboot_notifier = (unregister_euleros_reboot_notifier_t)
	kallsyms_lookup_name("unregister_euleros_reboot_notifier");

	_vram_kalloc = (vram_kalloc_t)
	kallsyms_lookup_name("vram_kalloc");

	_vram_kalloc_node = (vpmem_kalloc_node_t)
	kallsyms_lookup_name("vpmem_kalloc_node");

	_vram_kfree = (vram_kfree_t)
	kallsyms_lookup_name("vram_kfree");

	_vram_get_gfp_vram = (vram_get_gfp_vram_t)
	kallsyms_lookup_name("vram_get_vram_gfp_t");
#else
/* only EulerOS and HCE have kallsyms_lookup_name_wrap */
#if (defined(OS_EULER) || defined (OS_HCE))
	_register_nvwa_notifier = (register_nvwa_notifier_t)
	kallsyms_lookup_name_wrap("register_nvwa_notifier");

	_unregister_nvwa_notifier = (unregister_nvwa_notifier_t)
	kallsyms_lookup_name_wrap("unregister_nvwa_notifier");

	_register_euleros_reboot_notifier = (register_euleros_reboot_notifier_t)
	kallsyms_lookup_name_wrap("register_euleros_reboot_notifier");

	_unregister_euleros_reboot_notifier = (unregister_euleros_reboot_notifier_t)
	kallsyms_lookup_name_wrap("unregister_euleros_reboot_notifier");

	_vram_kalloc = (vram_kalloc_t)
	kallsyms_lookup_name_wrap("vram_kalloc");

	_vram_kalloc_node = (vpmem_kalloc_node_t)
	kallsyms_lookup_name_wrap("vpmem_kalloc_node");

	_vram_kfree = (vram_kfree_t)
	kallsyms_lookup_name_wrap("vram_kfree");

	_vram_get_gfp_vram = (vram_get_gfp_vram_t)
	kallsyms_lookup_name_wrap("vram_get_vram_gfp_t");
#endif
#endif
}
EXPORT_SYMBOL(lookup5_vram_related_symbols);

int hi5_set_kexec_status(int status)
{
	int *kexec_status_addr = NULL;

	kexec_status_addr = hi5_vram_kalloc(KEXEC_SIGN, VRAM_BLOCK_SIZE_2M);
	if (!kexec_status_addr) {
	pr_err("set kexec status vram kalloc failed.\n");
	return -ENOMEM;
	}

	*kexec_status_addr = status;
	g_in_kexec = *kexec_status_addr;

	return 0;
}
EXPORT_SYMBOL(hi5_set_kexec_status);

int hi5_get_kexec_status(void)
{
	int *kexec_status_addr = NULL;

	kexec_status_addr = hi5_vram_kalloc(KEXEC_SIGN, VRAM_BLOCK_SIZE_2M);
	if (!kexec_status_addr) {
	pr_err("get kexec status vram kalloc failed.\n");
	return -ENOMEM;
	}

	g_in_kexec = *kexec_status_addr;
	hi5_vram_kfree((void *)kexec_status_addr, KEXEC_SIGN, VRAM_BLOCK_SIZE_2M);

	return 0;
}
EXPORT_SYMBOL(hi5_get_kexec_status);

int get5_use_vram_flag(void)
{
	return g_use_vram;
}
EXPORT_SYMBOL(get5_use_vram_flag);

void set5_use_vram_flag(bool flag)
{
	g_use_vram = flag;
}
EXPORT_SYMBOL(set5_use_vram_flag);

int vram5_get_kexec_flag(void)
{
	return g_in_kexec;
}
EXPORT_SYMBOL(vram5_get_kexec_flag);

#endif

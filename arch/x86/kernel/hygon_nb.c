// SPDX-License-Identifier: GPL-2.0-only
/*
 * Share support code for Hygon northbridges and derivatives.
 * Copyright (C) 2026 Chengdu Haiguang IC Design Co., Ltd.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/spinlock.h>
#include <linux/pci_ids.h>
#include <asm/hygon/hygon_nb.h>

#define PCI_DEVICE_ID_HYGON_18H_ROOT		0x1450
#define PCI_DEVICE_ID_HYGON_18H_M05H_ROOT	0x14a0
#define PCI_DEVICE_ID_HYGON_18H_M04H_ROOT	0x1480

#define PCI_DEVICE_ID_HYGON_18H_M04H_DF_F1	0x1491
#define PCI_DEVICE_ID_HYGON_18H_M05H_DF_F1	0x14b1
#define PCI_DEVICE_ID_HYGON_18H_DF_F4		0x1464
#define PCI_DEVICE_ID_HYGON_18H_M04H_DF_F4	0x1494
#define PCI_DEVICE_ID_HYGON_18H_M05H_DF_F4	0x14b4
#define PCI_DEVICE_ID_HYGON_18H_M06H_DF_F5	0x14b5

static u16 node_num;
static struct pci_dev **hygon_roots;
static struct hygon_northbridge_info hygon_northbridges;

/* Protect the PCI config register pairs used for SMN and DF indirect access. */
static DEFINE_MUTEX(smn_mutex);

static const struct pci_device_id hygon_root_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_HYGON, PCI_DEVICE_ID_HYGON_18H_ROOT) },
	{ PCI_DEVICE(PCI_VENDOR_ID_HYGON, PCI_DEVICE_ID_HYGON_18H_M04H_ROOT) },
	{ PCI_DEVICE(PCI_VENDOR_ID_HYGON, PCI_DEVICE_ID_HYGON_18H_M05H_ROOT) },
	{}
};

static const struct pci_device_id hygon_nb_misc_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_HYGON, PCI_DEVICE_ID_HYGON_18H_DF_F3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_HYGON, PCI_DEVICE_ID_HYGON_18H_M04H_DF_F3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_HYGON, PCI_DEVICE_ID_HYGON_18H_M05H_DF_F3) },
	{}
};

static const struct pci_device_id hygon_nb_link_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_HYGON, PCI_DEVICE_ID_HYGON_18H_DF_F4) },
	{ PCI_DEVICE(PCI_VENDOR_ID_HYGON, PCI_DEVICE_ID_HYGON_18H_M04H_DF_F4) },
	{ PCI_DEVICE(PCI_VENDOR_ID_HYGON, PCI_DEVICE_ID_HYGON_18H_M05H_DF_F4) },
	{}
};

#define HYGON_SMN_INDEX_OFFSET	0x60
#define HYGON_SMN_DATA_OFFSET		0x64

static int __hygon_smn_rw(u16 node, u32 address, u32 *value, bool write)
{
	struct pci_dev *root;
	int err = -ENODEV;

	if (node >= hygon_nb_num())
		goto out;

	root = hygon_roots[node];
	if (!root)
		goto out;

	mutex_lock(&smn_mutex);

	err = pci_write_config_dword(root, HYGON_SMN_INDEX_OFFSET, address);
	if (err) {
		pr_warn("Error programming SMN address 0x%x.\n", address);
		goto out_unlock;
	}

	err = (write ? pci_write_config_dword(root, HYGON_SMN_DATA_OFFSET, *value)
		     : pci_read_config_dword(root, HYGON_SMN_DATA_OFFSET, value));
	if (err)
		pr_warn("Error %s SMN address 0x%x.\n",
			(write ? "writing to" : "reading from"), address);

out_unlock:
	mutex_unlock(&smn_mutex);

out:
	return err;
}

int hygon_smn_read(u16 node, u32 address, u32 *value)
{
	int err =  __hygon_smn_rw(node, address, value, false);

	if (PCI_POSSIBLE_ERROR(*value)) {
		err = -ENODEV;
		*value = 0;
	}

	return err;
}
EXPORT_SYMBOL_GPL(hygon_smn_read);

int hygon_smn_write(u16 node, u32 address, u32 value)
{
	return __hygon_smn_rw(node, address, &value, true);
}
EXPORT_SYMBOL_GPL(hygon_smn_write);

static struct pci_dev *next_northbridge(struct pci_dev *dev,
					const struct pci_device_id *ids)
{
	do {
		dev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, dev);
		if (!dev)
			break;
	} while (!pci_match_id(ids, dev));
	return dev;
}

u16 hygon_node_num(void)
{
	return node_num;
}
EXPORT_SYMBOL_GPL(hygon_node_num);

u16 hygon_nb_num(void)
{
	return hygon_northbridges.num;
}
EXPORT_SYMBOL_GPL(hygon_nb_num);

struct hygon_northbridge *node_to_hygon_nb(int node)
{
	return (node < hygon_northbridges.num) ? &hygon_northbridges.nb[node] : NULL;
}
EXPORT_SYMBOL_GPL(node_to_hygon_nb);

static int get_df_register(struct pci_dev *misc,  u8 func, int offset, u32 *value)
{
	struct pci_dev *df_func = NULL;
	u32 device;
	int err;

	if (func == 1) {
		switch (boot_cpu_data.x86_model) {
		case 0x4:
			device = PCI_DEVICE_ID_HYGON_18H_M04H_DF_F1;
			break;
		case 0x5:
			if (misc->device == PCI_DEVICE_ID_HYGON_18H_M05H_DF_F3)
				device = PCI_DEVICE_ID_HYGON_18H_M05H_DF_F1;
			else
				device = PCI_DEVICE_ID_HYGON_18H_M04H_DF_F1;
			break;
		case 0x6 ... 0x8:
			device = PCI_DEVICE_ID_HYGON_18H_M05H_DF_F1;
			break;
		default:
			return -ENODEV;
		}
	} else if (func == 5) {
		switch (boot_cpu_data.x86_model) {
		case 0x6 ... 0x8:
			device = PCI_DEVICE_ID_HYGON_18H_M06H_DF_F5;
			break;
		default:
			return -ENODEV;
		}
	} else {
		return -ENODEV;
	}

	while ((df_func = pci_get_device(misc->vendor, device, df_func)))
		if (pci_domain_nr(df_func->bus) == pci_domain_nr(misc->bus) &&
		    df_func->bus->number == misc->bus->number &&
		    PCI_SLOT(df_func->devfn) == PCI_SLOT(misc->devfn))
			break;

	if (!df_func) {
		pr_warn("Error getting DF func device.\n");
		return -ENODEV;
	}

	err = pci_read_config_dword(df_func, offset, value);
	if (err)
		pr_warn("Error reading DF func register.\n");

	return err;
}

bool hygon_f18h_m4h(void)
{
	if (boot_cpu_data.x86_vendor != X86_VENDOR_HYGON)
		return false;

	if (boot_cpu_data.x86 == 0x18 &&
	    boot_cpu_data.x86_model >= 0x4 &&
	    boot_cpu_data.x86_model <= 0xf)
		return true;

	return false;
}
EXPORT_SYMBOL_GPL(hygon_f18h_m4h);

bool hygon_f18h_m10h(void)
{
	if (boot_cpu_data.x86_vendor != X86_VENDOR_HYGON)
		return false;

	if (boot_cpu_data.x86 == 0x18 &&
	    boot_cpu_data.x86_model >= 0x10 &&
	    boot_cpu_data.x86_model <= 0x1f)
		return true;

	return false;
}
EXPORT_SYMBOL_GPL(hygon_f18h_m10h);

int get_df_id(struct pci_dev *misc, u8 *id)
{
	u32 value;
	int ret;

	if (boot_cpu_data.x86_model >= 0x6 &&
	    boot_cpu_data.x86_model <= 0xf) {
		/* F5x180[19:16]: DF ID */
		ret = get_df_register(misc, 5, 0x180, &value);
		*id = (value >> 16) & 0xf;
	} else {
		/* F1x200[23:20]: DF ID */
		ret = get_df_register(misc, 1, 0x200, &value);
		*id = (value >> 20) & 0xf;
	}

	return ret;
}
EXPORT_SYMBOL_GPL(get_df_id);

static u8 get_socket_num(struct pci_dev *misc)
{
	u32 value;
	int ret;

	/* F1x200[7:0]: Which socket is present. */
	ret = get_df_register(misc, 1, 0x200, &value);

	return ret ? 0 : hweight8(value & 0xff);
}

int northbridge_init_hygon(void)
{
	const struct pci_device_id *misc_ids = hygon_nb_misc_ids;
	const struct pci_device_id *link_ids = hygon_nb_link_ids;
	const struct pci_device_id *root_ids = hygon_root_ids;
	struct pci_dev *root, *misc, *link;
	struct pci_dev *root_first = NULL;
	struct hygon_northbridge *nb;
	u16 roots_per_socket = 0;
	u16 miscs_per_socket = 0;
	u16 socket_num = 0;
	u16 root_count = 0;
	u16 misc_count = 0;
	int err = -ENODEV;
	u8 i, j, m, n;
	u8 id;

	if (hygon_northbridges.num)
		return 0;

	misc = NULL;
	while ((misc = next_northbridge(misc, misc_ids)))
		misc_count++;

	root = NULL;
	while ((root = next_northbridge(root, root_ids)) != NULL)
		root_count++;

	if (!root_count || !misc_count) {
		err = -ENODEV;
		goto out;
	}

	if (hygon_f18h_m4h()) {
		misc = NULL;
		misc = next_northbridge(NULL, misc_ids);
		if (misc != NULL) {
			socket_num = get_socket_num(misc);
			pr_info("Socket number: %d\n", socket_num);
			if (!socket_num) {
				err = -ENODEV;
				goto out;
			}
		} else {
			err = -ENODEV;
			goto out;
		}

		/*
		 * There should be _exactly_ N roots for each DF/SMN
		 * interface, and M DF/SMN interfaces in one socket.
		 */
		roots_per_socket = root_count / socket_num;
		miscs_per_socket = misc_count / socket_num;

		if (!roots_per_socket || !miscs_per_socket) {
			err = -ENODEV;
			goto out;
		}
	}

	hygon_roots = kcalloc(misc_count, sizeof(*hygon_roots), GFP_KERNEL);
	if (!hygon_roots) {
		err = -ENOMEM;
		goto out;
	}

	nb = kcalloc(misc_count, sizeof(struct hygon_northbridge), GFP_KERNEL);
	if (!nb) {
		err = -ENOMEM;
		goto err_free_roots;
	}

	hygon_northbridges.nb = nb;
	hygon_northbridges.num = misc_count;

	link = misc = root = NULL;
	j = m = n = 0;
	for (i = 0; i < hygon_northbridges.num; i++) {
		misc = next_northbridge(misc, misc_ids);
		link = next_northbridge(link, link_ids);
		if (hygon_f18h_m4h()) {
			/* Only save the first PCI root device for each socket. */
			if (!(i % miscs_per_socket)) {
				root = root_first = next_northbridge(root, root_ids);
				j = 1;
			}

			if (get_df_id(misc, &id)) {
				err = -ENODEV;
				goto err_free_nb;
			}
			pr_info("DF ID: %d\n", id);

			if (id < 4) {
				/* Add the devices with id<4 from the tail. */
				node_to_hygon_nb(misc_count - m - 1)->misc = misc;
				node_to_hygon_nb(misc_count - m - 1)->link = link;
				hygon_roots[misc_count - m - 1] = root_first;
				m++;
			} else {
				node_to_hygon_nb(n)->misc = misc;
				node_to_hygon_nb(n)->link = link;
				hygon_roots[n] = root_first;
				n++;
			}

			/* Skip the redundant PCI root devices per socket. */
			while (j < roots_per_socket) {
				root = next_northbridge(root, root_ids);
				j++;
			}
		} else {
			hygon_roots[i] = root = next_northbridge(root, root_ids);
			node_to_hygon_nb(i)->misc = misc;
			node_to_hygon_nb(i)->link = link;
			n++;
		}
	}
	node_num = n;

	pr_info("Hygon Fam%xh Model%xh NB driver init success.\n",
		boot_cpu_data.x86, boot_cpu_data.x86_model);

	return 0;

err_free_nb:
	kfree(nb);
err_free_roots:
	kfree(hygon_roots);

out:
	if (!boot_cpu_has(X86_FEATURE_HYPERVISOR))
		pr_err("Hygon Fam%xh Model%xh northbridge init failed(%d)!\n",
			boot_cpu_data.x86, boot_cpu_data.x86_model, err);
	return err;
}

static __init int init_hygon_nbs(void)
{
	if (boot_cpu_data.x86_vendor != X86_VENDOR_HYGON)
		return 0;

	northbridge_init_hygon();

	return 0;
}

/* This has to go after the PCI subsystem */
fs_initcall(init_hygon_nbs);

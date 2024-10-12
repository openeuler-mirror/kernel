// SPDX-License-Identifier: GPL-2.0-only
/*
 * Shared support code for AMD K8 northbridges and derivates.
 * Copyright 2006 Andi Kleen, SUSE Labs.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/spinlock.h>
#include <linux/pci_ids.h>
#include <asm/amd_nb.h>

#define PCI_DEVICE_ID_AMD_17H_ROOT	0x1450
#define PCI_DEVICE_ID_AMD_17H_M10H_ROOT	0x15d0
#define PCI_DEVICE_ID_AMD_17H_M30H_ROOT	0x1480
#define PCI_DEVICE_ID_AMD_17H_M60H_ROOT	0x1630
#define PCI_DEVICE_ID_AMD_19H_M10H_ROOT	0x14a4
#define PCI_DEVICE_ID_AMD_17H_DF_F4	0x1464
#define PCI_DEVICE_ID_AMD_17H_M10H_DF_F4 0x15ec
#define PCI_DEVICE_ID_AMD_17H_M30H_DF_F4 0x1494
#define PCI_DEVICE_ID_AMD_17H_M60H_DF_F4 0x144c
#define PCI_DEVICE_ID_AMD_17H_M70H_DF_F4 0x1444
#define PCI_DEVICE_ID_AMD_19H_DF_F4	0x1654
#define PCI_DEVICE_ID_AMD_19H_M10H_DF_F4 0x14b1
#define PCI_DEVICE_ID_AMD_19H_M40H_ROOT	0x14b5
#define PCI_DEVICE_ID_AMD_19H_M40H_DF_F4 0x167d
#define PCI_DEVICE_ID_AMD_19H_M50H_DF_F4 0x166e

#define PCI_DEVICE_ID_HYGON_18H_M05H_ROOT  0x14a0
#define PCI_DEVICE_ID_HYGON_18H_M10H_ROOT  0x14c0
#define PCI_DEVICE_ID_HYGON_18H_M04H_DF_F1 0x1491
#define PCI_DEVICE_ID_HYGON_18H_M05H_DF_F1 0x14b1
#define PCI_DEVICE_ID_HYGON_18H_M05H_DF_F4 0x14b4
#define PCI_DEVICE_ID_HYGON_18H_M10H_DF_F4 0x14d4
#define PCI_DEVICE_ID_HYGON_18H_M06H_DF_F5 0x14b5

/* Protect the PCI config register pairs used for SMN and DF indirect access. */
static DEFINE_MUTEX(smn_mutex);

static u32 *flush_words;
static u16 nb_num;

static const struct pci_device_id amd_root_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_17H_ROOT) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_17H_M10H_ROOT) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_17H_M30H_ROOT) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_17H_M60H_ROOT) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_19H_M10H_ROOT) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_19H_M40H_ROOT) },
	{}
};

#define PCI_DEVICE_ID_AMD_CNB17H_F4     0x1704

static const struct pci_device_id amd_nb_misc_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_K8_NB_MISC) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_10H_NB_MISC) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_15H_NB_F3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_15H_M10H_F3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_15H_M30H_NB_F3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_15H_M60H_NB_F3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_16H_NB_F3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_16H_M30H_NB_F3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_17H_DF_F3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_17H_M10H_DF_F3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_17H_M30H_DF_F3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_17H_M60H_DF_F3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_CNB17H_F3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_17H_M70H_DF_F3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_19H_DF_F3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_19H_M10H_DF_F3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_19H_M40H_DF_F3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_19H_M50H_DF_F3) },
	{}
};

static const struct pci_device_id amd_nb_link_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_15H_NB_F4) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_15H_M30H_NB_F4) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_15H_M60H_NB_F4) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_16H_NB_F4) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_16H_M30H_NB_F4) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_17H_DF_F4) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_17H_M10H_DF_F4) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_17H_M30H_DF_F4) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_17H_M60H_DF_F4) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_17H_M70H_DF_F4) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_19H_DF_F4) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_19H_M10H_DF_F4) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_19H_M40H_DF_F4) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_19H_M50H_DF_F4) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_CNB17H_F4) },
	{}
};

static const struct pci_device_id hygon_root_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_HYGON, PCI_DEVICE_ID_AMD_17H_ROOT) },
	{ PCI_DEVICE(PCI_VENDOR_ID_HYGON, PCI_DEVICE_ID_AMD_17H_M30H_ROOT) },
	{ PCI_DEVICE(PCI_VENDOR_ID_HYGON, PCI_DEVICE_ID_HYGON_18H_M05H_ROOT) },
	{ PCI_DEVICE(PCI_VENDOR_ID_HYGON, PCI_DEVICE_ID_HYGON_18H_M10H_ROOT) },
	{}
};

static const struct pci_device_id hygon_nb_misc_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_HYGON, PCI_DEVICE_ID_AMD_17H_DF_F3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_HYGON, PCI_DEVICE_ID_AMD_17H_M30H_DF_F3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_HYGON, PCI_DEVICE_ID_HYGON_18H_M05H_DF_F3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_HYGON, PCI_DEVICE_ID_HYGON_18H_M10H_DF_F3) },
	{}
};

static const struct pci_device_id hygon_nb_link_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_HYGON, PCI_DEVICE_ID_AMD_17H_DF_F4) },
	{ PCI_DEVICE(PCI_VENDOR_ID_HYGON, PCI_DEVICE_ID_AMD_17H_M30H_DF_F4) },
	{ PCI_DEVICE(PCI_VENDOR_ID_HYGON, PCI_DEVICE_ID_HYGON_18H_M05H_DF_F4) },
	{ PCI_DEVICE(PCI_VENDOR_ID_HYGON, PCI_DEVICE_ID_HYGON_18H_M10H_DF_F4) },
	{}
};

const struct amd_nb_bus_dev_range amd_nb_bus_dev_ranges[] __initconst = {
	{ 0x00, 0x18, 0x20 },
	{ 0xff, 0x00, 0x20 },
	{ 0xfe, 0x00, 0x20 },
	{ }
};

static struct amd_northbridge_info amd_northbridges;

u16 amd_nb_num(void)
{
	return amd_northbridges.num;
}
EXPORT_SYMBOL_GPL(amd_nb_num);

bool amd_nb_has_feature(unsigned int feature)
{
	return ((amd_northbridges.flags & feature) == feature);
}
EXPORT_SYMBOL_GPL(amd_nb_has_feature);

struct amd_northbridge *node_to_amd_nb(int node)
{
	return (node < amd_northbridges.num) ? &amd_northbridges.nb[node] : NULL;
}
EXPORT_SYMBOL_GPL(node_to_amd_nb);

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

static int __amd_smn_rw(u16 node, u32 address, u32 *value, bool write)
{
	struct pci_dev *root;
	int err = -ENODEV;

	if (node >= amd_northbridges.num)
		goto out;

	root = node_to_amd_nb(node)->root;
	if (!root)
		goto out;

	mutex_lock(&smn_mutex);

	err = pci_write_config_dword(root, 0x60, address);
	if (err) {
		pr_warn("Error programming SMN address 0x%x.\n", address);
		goto out_unlock;
	}

	err = (write ? pci_write_config_dword(root, 0x64, *value)
		     : pci_read_config_dword(root, 0x64, value));
	if (err)
		pr_warn("Error %s SMN address 0x%x.\n",
			(write ? "writing to" : "reading from"), address);

out_unlock:
	mutex_unlock(&smn_mutex);

out:
	return err;
}

int amd_smn_read(u16 node, u32 address, u32 *value)
{
	return __amd_smn_rw(node, address, value, false);
}
EXPORT_SYMBOL_GPL(amd_smn_read);

int amd_smn_write(u16 node, u32 address, u32 value)
{
	return __amd_smn_rw(node, address, &value, true);
}
EXPORT_SYMBOL_GPL(amd_smn_write);

/*
 * Data Fabric Indirect Access uses FICAA/FICAD.
 *
 * Fabric Indirect Configuration Access Address (FICAA): Constructed based
 * on the device's Instance Id and the PCI function and register offset of
 * the desired register.
 *
 * Fabric Indirect Configuration Access Data (FICAD): There are FICAD LO
 * and FICAD HI registers but so far we only need the LO register.
 */
int amd_df_indirect_read(u16 node, u8 func, u16 reg, u8 instance_id, u32 *lo)
{
	struct pci_dev *F4;
	u32 ficaa;
	int err = -ENODEV;

	if (node >= amd_northbridges.num)
		goto out;

	F4 = node_to_amd_nb(node)->link;
	if (!F4)
		goto out;

	ficaa  = 1;
	ficaa |= reg & 0x3FC;
	ficaa |= (func & 0x7) << 11;
	ficaa |= instance_id << 16;

	mutex_lock(&smn_mutex);

	err = pci_write_config_dword(F4, 0x5C, ficaa);
	if (err) {
		pr_warn("Error writing DF Indirect FICAA, FICAA=0x%x\n", ficaa);
		goto out_unlock;
	}

	err = pci_read_config_dword(F4, 0x98, lo);
	if (err)
		pr_warn("Error reading DF Indirect FICAD LO, FICAA=0x%x.\n", ficaa);

out_unlock:
	mutex_unlock(&smn_mutex);

out:
	return err;
}
EXPORT_SYMBOL_GPL(amd_df_indirect_read);

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

u16 hygon_nb_num(void)
{
	return nb_num;
}
EXPORT_SYMBOL_GPL(hygon_nb_num);

static int get_df_register(struct pci_dev *misc, u8 func, int offset, u32 *value)
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
		case 0x6:
		case 0x7:
			device = PCI_DEVICE_ID_HYGON_18H_M05H_DF_F1;
			break;
		default:
			return -ENODEV;
		}
	} else if (func == 5) {
		switch (boot_cpu_data.x86_model) {
		case 0x6:
		case 0x7:
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
		pr_warn("Error getting DF F%d device.\n", func);
		return -ENODEV;
	}

	err = pci_read_config_dword(df_func, offset, value);
	if (err)
		pr_warn("Error reading DF F%d register.\n", func);

	return err;
}

int get_df_id(struct pci_dev *misc, u8 *id)
{
	u32 value;
	int ret;

	if (boot_cpu_data.x86_model >= 0x6 &&
	    boot_cpu_data.x86_model <= 0x7) {
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

static int northbridge_init_f18h_m4h(const struct pci_device_id *root_ids,
					const struct pci_device_id *misc_ids,
					const struct pci_device_id *link_ids)
{
	struct pci_dev *root, *misc, *link;
	struct pci_dev *root_first = NULL;
	struct amd_northbridge *nb;
	u16 roots_per_socket = 0;
	u16 miscs_per_socket = 0;
	u16 socket_num = 0;
	u16 root_count = 0;
	u16 misc_count = 0;
	int err = -ENODEV;
	u8 i, j, m, n;
	u8 id;

	pr_info("Hygon Fam%xh Model%xh NB driver.\n",
		boot_cpu_data.x86, boot_cpu_data.x86_model);

	misc = next_northbridge(NULL, misc_ids);
	if (misc != NULL) {
		socket_num = get_socket_num(misc);
		pr_info("Socket number: %d\n", socket_num);
		if (!socket_num) {
			err = -ENODEV;
			goto ret;
		}
	} else {
		err = -ENODEV;
		goto ret;
	}

	misc = NULL;
	while ((misc = next_northbridge(misc, misc_ids)) != NULL)
		misc_count++;

	root = NULL;
	while ((root = next_northbridge(root, root_ids)) != NULL)
		root_count++;

	if (!root_count || !misc_count) {
		err = -ENODEV;
		goto ret;
	}

	/*
	 * There should be _exactly_ N roots for each DF/SMN
	 * interface, and M DF/SMN interfaces in one socket.
	 */
	roots_per_socket = root_count / socket_num;
	miscs_per_socket = misc_count / socket_num;

	if (!roots_per_socket || !miscs_per_socket) {
		err = -ENODEV;
		goto ret;
	}

	nb = kcalloc(misc_count, sizeof(struct amd_northbridge), GFP_KERNEL);
	if (!nb) {
		err = -ENOMEM;
		goto ret;
	}

	amd_northbridges.nb = nb;
	amd_northbridges.num = misc_count;

	link = misc = root = NULL;
	j = m = n = 0;
	for (i = 0; i < amd_northbridges.num; i++) {
		misc = next_northbridge(misc, misc_ids);
		link = next_northbridge(link, link_ids);

		/* Only save the first PCI root device for each socket. */
		if (!(i % miscs_per_socket)) {
			root_first = next_northbridge(root, root_ids);
			root = root_first;
			j = 1;
		}

		if (get_df_id(misc, &id)) {
			err = -ENODEV;
			goto err;
		}
		pr_info("DF ID: %d\n", id);

		if (id < 4) {
			/* Add the devices with id<4 from the tail. */
			node_to_amd_nb(misc_count - m - 1)->misc = misc;
			node_to_amd_nb(misc_count - m - 1)->link = link;
			node_to_amd_nb(misc_count - m - 1)->root = root_first;
			m++;
		} else {
			node_to_amd_nb(n)->misc = misc;
			node_to_amd_nb(n)->link = link;
			node_to_amd_nb(n)->root = root_first;
			n++;
		}

		/* Skip the redundant PCI root devices per socket. */
		while (j < roots_per_socket) {
			root = next_northbridge(root, root_ids);
			j++;
		}
	}
	nb_num = n;

	return 0;

err:
	kfree(nb);
	amd_northbridges.nb = NULL;

ret:
	pr_err("Hygon Fam%xh Model%xh northbridge init failed(%d)!\n",
		boot_cpu_data.x86, boot_cpu_data.x86_model, err);
	return err;
}

int amd_cache_northbridges(void)
{
	const struct pci_device_id *misc_ids = amd_nb_misc_ids;
	const struct pci_device_id *link_ids = amd_nb_link_ids;
	const struct pci_device_id *root_ids = amd_root_ids;
	struct pci_dev *root, *misc, *link;
	struct amd_northbridge *nb;
	u16 roots_per_misc = 0;
	u16 misc_count = 0;
	u16 root_count = 0;
	u16 i, j;

	if (amd_northbridges.num)
		return 0;

	if (boot_cpu_data.x86_vendor == X86_VENDOR_HYGON) {
		root_ids = hygon_root_ids;
		misc_ids = hygon_nb_misc_ids;
		link_ids = hygon_nb_link_ids;

		if (boot_cpu_data.x86_model >= 0x4 &&
		    boot_cpu_data.x86_model <= 0xf)
			return northbridge_init_f18h_m4h(root_ids,
					misc_ids, link_ids);
	}

	misc = NULL;
	while ((misc = next_northbridge(misc, misc_ids)) != NULL)
		misc_count++;

	if (!misc_count)
		return -ENODEV;

	root = NULL;
	while ((root = next_northbridge(root, root_ids)) != NULL)
		root_count++;

	if (root_count) {
		roots_per_misc = root_count / misc_count;

		/*
		 * There should be _exactly_ N roots for each DF/SMN
		 * interface.
		 */
		if (!roots_per_misc || (root_count % roots_per_misc)) {
			pr_info("Unsupported AMD DF/PCI configuration found\n");
			return -ENODEV;
		}
	}

	nb = kcalloc(misc_count, sizeof(struct amd_northbridge), GFP_KERNEL);
	if (!nb)
		return -ENOMEM;

	amd_northbridges.nb = nb;
	amd_northbridges.num = misc_count;

	link = misc = root = NULL;
	for (i = 0; i < amd_northbridges.num; i++) {
		node_to_amd_nb(i)->root = root =
			next_northbridge(root, root_ids);
		node_to_amd_nb(i)->misc = misc =
			next_northbridge(misc, misc_ids);
		node_to_amd_nb(i)->link = link =
			next_northbridge(link, link_ids);

		/*
		 * If there are more PCI root devices than data fabric/
		 * system management network interfaces, then the (N)
		 * PCI roots per DF/SMN interface are functionally the
		 * same (for DF/SMN access) and N-1 are redundant.  N-1
		 * PCI roots should be skipped per DF/SMN interface so
		 * the following DF/SMN interfaces get mapped to
		 * correct PCI roots.
		 */
		for (j = 1; j < roots_per_misc; j++)
			root = next_northbridge(root, root_ids);
	}

	if (amd_gart_present())
		amd_northbridges.flags |= AMD_NB_GART;

	/*
	 * Check for L3 cache presence.
	 */
	if (!cpuid_edx(0x80000006))
		return 0;

	/*
	 * Some CPU families support L3 Cache Index Disable. There are some
	 * limitations because of E382 and E388 on family 0x10.
	 */
	if (boot_cpu_data.x86 == 0x10 &&
	    boot_cpu_data.x86_model >= 0x8 &&
	    (boot_cpu_data.x86_model > 0x9 ||
	     boot_cpu_data.x86_stepping >= 0x1))
		amd_northbridges.flags |= AMD_NB_L3_INDEX_DISABLE;

	if (boot_cpu_data.x86 == 0x15)
		amd_northbridges.flags |= AMD_NB_L3_INDEX_DISABLE;

	/* L3 cache partitioning is supported on family 0x15 */
	if (boot_cpu_data.x86 == 0x15)
		amd_northbridges.flags |= AMD_NB_L3_PARTITIONING;

	return 0;
}
EXPORT_SYMBOL_GPL(amd_cache_northbridges);

/*
 * Ignores subdevice/subvendor but as far as I can figure out
 * they're useless anyways
 */
bool __init early_is_amd_nb(u32 device)
{
	const struct pci_device_id *misc_ids = amd_nb_misc_ids;
	const struct pci_device_id *id;
	u32 vendor = device & 0xffff;

	if (boot_cpu_data.x86_vendor != X86_VENDOR_AMD &&
	    boot_cpu_data.x86_vendor != X86_VENDOR_HYGON)
		return false;

	if (boot_cpu_data.x86_vendor == X86_VENDOR_HYGON)
		misc_ids = hygon_nb_misc_ids;

	device >>= 16;
	for (id = misc_ids; id->vendor; id++)
		if (vendor == id->vendor && device == id->device)
			return true;
	return false;
}

struct resource *amd_get_mmconfig_range(struct resource *res)
{
	u32 address;
	u64 base, msr;
	unsigned int segn_busn_bits;

	if (boot_cpu_data.x86_vendor != X86_VENDOR_AMD &&
	    boot_cpu_data.x86_vendor != X86_VENDOR_HYGON)
		return NULL;

	/* assume all cpus from fam10h have mmconfig */
	if (boot_cpu_data.x86 < 0x10)
		return NULL;

	address = MSR_FAM10H_MMIO_CONF_BASE;
	rdmsrl(address, msr);

	/* mmconfig is not enabled */
	if (!(msr & FAM10H_MMIO_CONF_ENABLE))
		return NULL;

	base = msr & (FAM10H_MMIO_CONF_BASE_MASK<<FAM10H_MMIO_CONF_BASE_SHIFT);

	segn_busn_bits = (msr >> FAM10H_MMIO_CONF_BUSRANGE_SHIFT) &
			 FAM10H_MMIO_CONF_BUSRANGE_MASK;

	res->flags = IORESOURCE_MEM;
	res->start = base;
	res->end = base + (1ULL<<(segn_busn_bits + 20)) - 1;
	return res;
}

int amd_get_subcaches(int cpu)
{
	struct pci_dev *link = node_to_amd_nb(amd_get_nb_id(cpu))->link;
	unsigned int mask;

	if (!amd_nb_has_feature(AMD_NB_L3_PARTITIONING))
		return 0;

	pci_read_config_dword(link, 0x1d4, &mask);

	return (mask >> (4 * cpu_data(cpu).cpu_core_id)) & 0xf;
}

int amd_set_subcaches(int cpu, unsigned long mask)
{
	static unsigned int reset, ban;
	struct amd_northbridge *nb = node_to_amd_nb(amd_get_nb_id(cpu));
	unsigned int reg;
	int cuid;

	if (!amd_nb_has_feature(AMD_NB_L3_PARTITIONING) || mask > 0xf)
		return -EINVAL;

	/* if necessary, collect reset state of L3 partitioning and BAN mode */
	if (reset == 0) {
		pci_read_config_dword(nb->link, 0x1d4, &reset);
		pci_read_config_dword(nb->misc, 0x1b8, &ban);
		ban &= 0x180000;
	}

	/* deactivate BAN mode if any subcaches are to be disabled */
	if (mask != 0xf) {
		pci_read_config_dword(nb->misc, 0x1b8, &reg);
		pci_write_config_dword(nb->misc, 0x1b8, reg & ~0x180000);
	}

	cuid = cpu_data(cpu).cpu_core_id;
	mask <<= 4 * cuid;
	mask |= (0xf ^ (1 << cuid)) << 26;

	pci_write_config_dword(nb->link, 0x1d4, mask);

	/* reset BAN mode if L3 partitioning returned to reset state */
	pci_read_config_dword(nb->link, 0x1d4, &reg);
	if (reg == reset) {
		pci_read_config_dword(nb->misc, 0x1b8, &reg);
		reg &= ~0x180000;
		pci_write_config_dword(nb->misc, 0x1b8, reg | ban);
	}

	return 0;
}

static void amd_cache_gart(void)
{
	u16 i;

	if (!amd_nb_has_feature(AMD_NB_GART))
		return;

	flush_words = kmalloc_array(amd_northbridges.num, sizeof(u32), GFP_KERNEL);
	if (!flush_words) {
		amd_northbridges.flags &= ~AMD_NB_GART;
		pr_notice("Cannot initialize GART flush words, GART support disabled\n");
		return;
	}

	for (i = 0; i != amd_northbridges.num; i++)
		pci_read_config_dword(node_to_amd_nb(i)->misc, 0x9c, &flush_words[i]);
}

void amd_flush_garts(void)
{
	int flushed, i;
	unsigned long flags;
	static DEFINE_SPINLOCK(gart_lock);

	if (!amd_nb_has_feature(AMD_NB_GART))
		return;

	/*
	 * Avoid races between AGP and IOMMU. In theory it's not needed
	 * but I'm not sure if the hardware won't lose flush requests
	 * when another is pending. This whole thing is so expensive anyways
	 * that it doesn't matter to serialize more. -AK
	 */
	spin_lock_irqsave(&gart_lock, flags);
	flushed = 0;
	for (i = 0; i < amd_northbridges.num; i++) {
		pci_write_config_dword(node_to_amd_nb(i)->misc, 0x9c,
				       flush_words[i] | 1);
		flushed++;
	}
	for (i = 0; i < amd_northbridges.num; i++) {
		u32 w;
		/* Make sure the hardware actually executed the flush*/
		for (;;) {
			pci_read_config_dword(node_to_amd_nb(i)->misc,
					      0x9c, &w);
			if (!(w & 1))
				break;
			cpu_relax();
		}
	}
	spin_unlock_irqrestore(&gart_lock, flags);
	if (!flushed)
		pr_notice("nothing to flush?\n");
}
EXPORT_SYMBOL_GPL(amd_flush_garts);

static void __fix_erratum_688(void *info)
{
#define MSR_AMD64_IC_CFG 0xC0011021

	msr_set_bit(MSR_AMD64_IC_CFG, 3);
	msr_set_bit(MSR_AMD64_IC_CFG, 14);
}

/* Apply erratum 688 fix so machines without a BIOS fix work. */
static __init void fix_erratum_688(void)
{
	struct pci_dev *F4;
	u32 val;

	if (boot_cpu_data.x86 != 0x14)
		return;

	if (!amd_northbridges.num)
		return;

	F4 = node_to_amd_nb(0)->link;
	if (!F4)
		return;

	if (pci_read_config_dword(F4, 0x164, &val))
		return;

	if (val & BIT(2))
		return;

	on_each_cpu(__fix_erratum_688, NULL, 0);

	pr_info("x86/cpu/AMD: CPU erratum 688 worked around\n");
}

static __init int init_amd_nbs(void)
{
	amd_cache_northbridges();
	amd_cache_gart();

	fix_erratum_688();

	return 0;
}

/* This has to go after the PCI subsystem */
fs_initcall(init_amd_nbs);

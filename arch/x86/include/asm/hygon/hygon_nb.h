/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_HYGON_NB_H
#define _ASM_X86_HYGON_NB_H

#include <linux/pci.h>

struct hygon_northbridge {
	struct pci_dev *root;
	struct pci_dev *misc;
	struct pci_dev *link;
};

struct hygon_northbridge_info {
	u16 num;
	struct hygon_northbridge *nb;
};

int hygon_smn_read(u16 node, u32 address, u32 *value);
int hygon_smn_write(u16 node, u32 address, u32 value);

#ifdef CONFIG_HYGON_NB

int northbridge_init_hygon(void);
u16 hygon_nb_num(void);
struct hygon_northbridge *node_to_hygon_nb(int node);
bool hygon_f18h_m4h(void);
bool hygon_f18h_m10h(void);
int get_df_id(struct pci_dev *misc, u8 *id);
u16 hygon_node_num(void);

static inline u16 hygon_pci_dev_to_node_id(struct pci_dev *pdev)
{
	struct pci_dev *misc;
	int i;

	for (i = 0; i != hygon_nb_num(); i++) {
		misc = node_to_hygon_nb(i)->misc;

		if (pci_domain_nr(misc->bus) == pci_domain_nr(pdev->bus) &&
		    PCI_SLOT(misc->devfn) == PCI_SLOT(pdev->devfn))
			return i;
	}

	WARN(1, "Unable to find Hygon Northbridge id for %s\n", pci_name(pdev));
	return 0;
}

#else

#define northbridge_init_hygon(x)	0
#define hygon_nb_num(x)	0
#define hygon_f18h_m4h		false
#define hygon_f18h_m10h		false
#define get_df_id(x, y)	NULL
#define hygon_node_num(x)

static inline struct hygon_northbridge *node_to_hygon_nb(int node)
{
	return NULL;
}
#endif

#endif

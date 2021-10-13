/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPHW_HWIF_H
#define SPHW_HWIF_H

#define SPHW_PCIE_LINK_DOWN		0xFFFFFFFF

struct sphw_free_db_area {
	unsigned long		*db_bitmap_array;
	u32			db_max_areas;
	/* spinlock for allocating doorbell area */
	spinlock_t		idx_lock;
};

struct sphw_func_attr {
	u16			func_global_idx;
	u8			port_to_port_idx;
	u8			pci_intf_idx;
	u8			vf_in_pf;
	enum func_type		func_type;

	u8			mpf_idx;

	u8			ppf_idx;

	u16			num_irqs;
	u8			num_aeqs;
	u8			num_ceqs;

	u8			num_dma_attr;

	u16			global_vf_id_of_pf;
};

struct sphw_hwif {
	u8 __iomem			*cfg_regs_base;
	u8 __iomem			*intr_regs_base;
	u8 __iomem			*mgmt_regs_base;
	u64				db_base_phy;
	u64				db_dwqe_len;
	u8 __iomem			*db_base;

	struct sphw_free_db_area	free_db_area;

	struct sphw_func_attr		attr;

	void				*pdev;
};

enum sphw_outbound_ctrl {
	ENABLE_OUTBOUND  = 0x0,
	DISABLE_OUTBOUND = 0x1,
};

enum sphw_doorbell_ctrl {
	ENABLE_DOORBELL  = 0x0,
	DISABLE_DOORBELL = 0x1,
};

enum sphw_pf_status {
	SPHW_PF_STATUS_INIT = 0X0,
	SPHW_PF_STATUS_ACTIVE_FLAG = 0x11,
	SPHW_PF_STATUS_FLR_START_FLAG = 0x12,
	SPHW_PF_STATUS_FLR_FINISH_FLAG = 0x13,
};

#define SPHW_HWIF_NUM_AEQS(hwif)		((hwif)->attr.num_aeqs)
#define SPHW_HWIF_NUM_CEQS(hwif)		((hwif)->attr.num_ceqs)
#define SPHW_HWIF_NUM_IRQS(hwif)		((hwif)->attr.num_irqs)
#define SPHW_HWIF_GLOBAL_IDX(hwif)		((hwif)->attr.func_global_idx)
#define SPHW_HWIF_GLOBAL_VF_OFFSET(hwif)	((hwif)->attr.global_vf_id_of_pf)
#define SPHW_HWIF_PPF_IDX(hwif)			((hwif)->attr.ppf_idx)
#define SPHW_PCI_INTF_IDX(hwif)			((hwif)->attr.pci_intf_idx)

#define SPHW_FUNC_TYPE(dev)			((dev)->hwif->attr.func_type)
#define SPHW_IS_PF(dev)				(SPHW_FUNC_TYPE(dev) == TYPE_PF)
#define SPHW_IS_VF(dev)				(SPHW_FUNC_TYPE(dev) == TYPE_VF)
#define SPHW_IS_PPF(dev)			(SPHW_FUNC_TYPE(dev) == TYPE_PPF)

u32 sphw_hwif_read_reg(struct sphw_hwif *hwif, u32 reg);

void sphw_hwif_write_reg(struct sphw_hwif *hwif, u32 reg, u32 val);

void sphw_set_pf_status(struct sphw_hwif *hwif, enum sphw_pf_status status);

enum sphw_pf_status sphw_get_pf_status(struct sphw_hwif *hwif);

void sphw_disable_doorbell(struct sphw_hwif *hwif);

void sphw_enable_doorbell(struct sphw_hwif *hwif);

int sphw_init_hwif(struct sphw_hwdev *hwdev, void *cfg_reg_base, void *intr_reg_base,
		   void *mgmt_regs_base, u64 db_base_phy, void *db_base, u64 db_dwqe_len);

void sphw_free_hwif(struct sphw_hwdev *hwdev);

u8 sphw_host_ppf_idx(void *hwdev, u8 host_id);

u32 sphw_get_heartbeat_status(struct sphw_hwdev *hwdev);

#endif

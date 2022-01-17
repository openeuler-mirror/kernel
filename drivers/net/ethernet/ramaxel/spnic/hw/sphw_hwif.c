// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/types.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/module.h>

#include "sphw_csr.h"
#include "sphw_crm.h"
#include "sphw_hw.h"
#include "sphw_common.h"
#include "sphw_hwdev.h"
#include "sphw_hwif.h"

#define WAIT_HWIF_READY_TIMEOUT				10000
#define SPHW_WAIT_DOORBELL_AND_OUTBOUND_TIMEOUT		60000

#define DB_IDX(db, db_base)	\
	((u32)(((ulong)(db) - (ulong)(db_base)) /	\
	       SPHW_DB_PAGE_SIZE))

#define SPHW_AF0_FUNC_GLOBAL_IDX_SHIFT		0
#define SPHW_AF0_P2P_IDX_SHIFT			12
#define SPHW_AF0_PCI_INTF_IDX_SHIFT		17
#define SPHW_AF0_VF_IN_PF_SHIFT			20
#define SPHW_AF0_FUNC_TYPE_SHIFT		28

#define SPHW_AF0_FUNC_GLOBAL_IDX_MASK		0xFFF
#define SPHW_AF0_P2P_IDX_MASK			0x1F
#define SPHW_AF0_PCI_INTF_IDX_MASK		0x7
#define SPHW_AF0_VF_IN_PF_MASK			0xFF
#define SPHW_AF0_FUNC_TYPE_MASK			0x1

#define SPHW_AF0_GET(val, member)				\
	(((val) >> SPHW_AF0_##member##_SHIFT) & SPHW_AF0_##member##_MASK)

#define SPHW_AF1_PPF_IDX_SHIFT			0
#define SPHW_AF1_AEQS_PER_FUNC_SHIFT		8
#define SPHW_AF1_MGMT_INIT_STATUS_SHIFT		30
#define SPHW_AF1_PF_INIT_STATUS_SHIFT		31

#define SPHW_AF1_PPF_IDX_MASK			0x3F
#define SPHW_AF1_AEQS_PER_FUNC_MASK		0x3
#define SPHW_AF1_MGMT_INIT_STATUS_MASK		0x1
#define SPHW_AF1_PF_INIT_STATUS_MASK		0x1

#define SPHW_AF1_GET(val, member)				\
	(((val) >> SPHW_AF1_##member##_SHIFT) & SPHW_AF1_##member##_MASK)

#define SPHW_AF2_CEQS_PER_FUNC_SHIFT		0
#define SPHW_AF2_DMA_ATTR_PER_FUNC_SHIFT	9
#define SPHW_AF2_IRQS_PER_FUNC_SHIFT		16

#define SPHW_AF2_CEQS_PER_FUNC_MASK		0x1FF
#define SPHW_AF2_DMA_ATTR_PER_FUNC_MASK		0x7
#define SPHW_AF2_IRQS_PER_FUNC_MASK		0x7FF

#define SPHW_AF2_GET(val, member)				\
	(((val) >> SPHW_AF2_##member##_SHIFT) & SPHW_AF2_##member##_MASK)

#define SPHW_AF3_GLOBAL_VF_ID_OF_NXT_PF_SHIFT	0
#define SPHW_AF3_GLOBAL_VF_ID_OF_PF_SHIFT	16

#define SPHW_AF3_GLOBAL_VF_ID_OF_NXT_PF_MASK	0xFFF
#define SPHW_AF3_GLOBAL_VF_ID_OF_PF_MASK	0xFFF

#define SPHW_AF3_GET(val, member)				\
	(((val) >> SPHW_AF3_##member##_SHIFT) & SPHW_AF3_##member##_MASK)

#define SPHW_AF4_DOORBELL_CTRL_SHIFT		0
#define SPHW_AF4_DOORBELL_CTRL_MASK		0x1

#define SPHW_AF4_GET(val, member)				\
	(((val) >> SPHW_AF4_##member##_SHIFT) & SPHW_AF4_##member##_MASK)

#define SPHW_AF4_SET(val, member)				\
	(((val) & SPHW_AF4_##member##_MASK) << SPHW_AF4_##member##_SHIFT)

#define SPHW_AF4_CLEAR(val, member)				\
	((val) & (~(SPHW_AF4_##member##_MASK << SPHW_AF4_##member##_SHIFT)))

#define SPHW_AF5_OUTBOUND_CTRL_SHIFT		0
#define SPHW_AF5_OUTBOUND_CTRL_MASK		0x1

#define SPHW_AF5_GET(val, member)				\
	(((val) >> SPHW_AF5_##member##_SHIFT) & SPHW_AF5_##member##_MASK)

#define SPHW_AF5_SET(val, member)				\
	(((val) & SPHW_AF5_##member##_MASK) << SPHW_AF5_##member##_SHIFT)

#define SPHW_AF5_CLEAR(val, member)				\
	((val) & (~(SPHW_AF5_##member##_MASK << SPHW_AF5_##member##_SHIFT)))

#define SPHW_AF6_PF_STATUS_SHIFT		0
#define SPHW_AF6_PF_STATUS_MASK			0xFFFF

#define SPHW_AF6_SET(val, member)				\
	((((u32)(val)) & SPHW_AF6_##member##_MASK) <<		\
	 SPHW_AF6_##member##_SHIFT)

#define SPHW_AF6_GET(val, member)				\
	(((val) >> SPHW_AF6_##member##_SHIFT) & SPHW_AF6_##member##_MASK)

#define SPHW_AF6_CLEAR(val, member)				\
	((val) & (~(SPHW_AF6_##member##_MASK <<		\
	 SPHW_AF6_##member##_SHIFT)))

#define sphw_PPF_ELECT_PORT_IDX_SHIFT		0

#define sphw_PPF_ELECT_PORT_IDX_MASK		0x3F

#define sphw_PPF_ELECT_PORT_GET(val, member)			\
	(((val) >> sphw_PPF_ELECT_PORT_##member##_SHIFT) &	\
	 sphw_PPF_ELECT_PORT_##member##_MASK)

#define SPHW_PPF_ELECTION_IDX_SHIFT		0

#define SPHW_PPF_ELECTION_IDX_MASK		0x3F

#define SPHW_PPF_ELECTION_SET(val, member)			\
	(((val) & SPHW_PPF_ELECTION_##member##_MASK) <<	\
	 SPHW_PPF_ELECTION_##member##_SHIFT)

#define SPHW_PPF_ELECTION_GET(val, member)			\
	(((val) >> SPHW_PPF_ELECTION_##member##_SHIFT) &	\
	 SPHW_PPF_ELECTION_##member##_MASK)

#define SPHW_PPF_ELECTION_CLEAR(val, member)			\
	((val) & (~(SPHW_PPF_ELECTION_##member##_MASK <<	\
		  SPHW_PPF_ELECTION_##member##_SHIFT)))

#define SPHW_MPF_ELECTION_IDX_SHIFT		0

#define SPHW_MPF_ELECTION_IDX_MASK		0x1F

#define SPHW_MPF_ELECTION_SET(val, member)			\
	(((val) & SPHW_MPF_ELECTION_##member##_MASK) <<	\
	 SPHW_MPF_ELECTION_##member##_SHIFT)

#define SPHW_MPF_ELECTION_GET(val, member)			\
	(((val) >> SPHW_MPF_ELECTION_##member##_SHIFT) &	\
	 SPHW_MPF_ELECTION_##member##_MASK)

#define SPHW_MPF_ELECTION_CLEAR(val, member)			\
	((val) & (~(SPHW_MPF_ELECTION_##member##_MASK <<	\
	 SPHW_MPF_ELECTION_##member##_SHIFT)))

#define SPHW_GET_REG_FLAG(reg)	((reg) & (~(SPHW_REGS_FLAG_MAKS)))

#define SPHW_GET_REG_ADDR(reg)	((reg) & (SPHW_REGS_FLAG_MAKS))

u32 sphw_hwif_read_reg(struct sphw_hwif *hwif, u32 reg)
{
	if (SPHW_GET_REG_FLAG(reg) == SPHW_MGMT_REGS_FLAG)
		return be32_to_cpu(readl(hwif->mgmt_regs_base +
					 SPHW_GET_REG_ADDR(reg)));
	else
		return be32_to_cpu(readl(hwif->cfg_regs_base +
					 SPHW_GET_REG_ADDR(reg)));
}

void sphw_hwif_write_reg(struct sphw_hwif *hwif, u32 reg, u32 val)
{
	if (SPHW_GET_REG_FLAG(reg) == SPHW_MGMT_REGS_FLAG)
		writel(cpu_to_be32(val),
		       hwif->mgmt_regs_base + SPHW_GET_REG_ADDR(reg));
	else
		writel(cpu_to_be32(val),
		       hwif->cfg_regs_base + SPHW_GET_REG_ADDR(reg));
}

/**
 * sphw_get_heartbeat_status - get heart beat status
 * @hwdev: the pointer to hw device
 * Return: 0 - normal, 1 - heart lost, 0xFFFFFFFF - Pcie link down
 **/
u32 sphw_get_heartbeat_status(struct sphw_hwdev *hwdev)
{
	u32 attr1;

	attr1 = sphw_hwif_read_reg(hwdev->hwif, SPHW_CSR_FUNC_ATTR1_ADDR);
	if (attr1 == SPHW_PCIE_LINK_DOWN)
		return attr1;

	return !SPHW_AF1_GET(attr1, MGMT_INIT_STATUS);
}

/**
 * hwif_ready - test if the HW initialization passed
 * @hwdev: the pointer to hw device
 * Return: 0 - success, negative - failure
 **/
static int hwif_ready(struct sphw_hwdev *hwdev)
{
	if (sphw_get_heartbeat_status(hwdev))
		return -EBUSY;

	return 0;
}

static enum sphw_wait_return check_hwif_ready_handler(void *priv_data)
{
	if (!hwif_ready(priv_data))
		return WAIT_PROCESS_CPL;

	return WAIT_PROCESS_WAITING;
}

static int wait_hwif_ready(struct sphw_hwdev *hwdev)
{
	if (!sphw_wait_for_timeout(hwdev, check_hwif_ready_handler,
				   WAIT_HWIF_READY_TIMEOUT, USEC_PER_MSEC))
		return 0;

	sdk_err(hwdev->dev_hdl, "Wait for hwif timeout\n");
	return -EBUSY;
}

/**
 * set_hwif_attr - set the attributes as members in hwif
 * @hwif: the hardware interface of a pci function device
 * @attr0: the first attribute that was read from the hw
 * @attr1: the second attribute that was read from the hw
 * @attr2: the third attribute that was read from the hw
 * @attr3: the fourth attribute that was read from the hw
 **/
static void set_hwif_attr(struct sphw_hwif *hwif, u32 attr0, u32 attr1,
			  u32 attr2, u32 attr3)
{
	hwif->attr.func_global_idx = SPHW_AF0_GET(attr0, FUNC_GLOBAL_IDX);
	hwif->attr.port_to_port_idx = SPHW_AF0_GET(attr0, P2P_IDX);
	hwif->attr.pci_intf_idx = SPHW_AF0_GET(attr0, PCI_INTF_IDX);
	hwif->attr.vf_in_pf = SPHW_AF0_GET(attr0, VF_IN_PF);
	hwif->attr.func_type = SPHW_AF0_GET(attr0, FUNC_TYPE);

	hwif->attr.ppf_idx = SPHW_AF1_GET(attr1, PPF_IDX);
	hwif->attr.num_aeqs = BIT(SPHW_AF1_GET(attr1, AEQS_PER_FUNC));
	hwif->attr.num_ceqs = (u8)SPHW_AF2_GET(attr2, CEQS_PER_FUNC);
	hwif->attr.num_irqs = SPHW_AF2_GET(attr2, IRQS_PER_FUNC);
	hwif->attr.num_dma_attr = BIT(SPHW_AF2_GET(attr2, DMA_ATTR_PER_FUNC));

	hwif->attr.global_vf_id_of_pf = SPHW_AF3_GET(attr3, GLOBAL_VF_ID_OF_PF);

	pr_info("func_global_idx: 0x%x, port_to_port_idx: 0x%x, pci_intf_idx: 0x%x, vf_in_pf: 0x%x, func_type: %d\n",
		hwif->attr.func_global_idx, hwif->attr.port_to_port_idx,
		hwif->attr.pci_intf_idx, hwif->attr.vf_in_pf,
		hwif->attr.func_type);

	pr_info("ppf_idx: 0x%x, num_aeqs: 0x%x, num_ceqs: 0x%x, num_irqs: 0x%x, num_dma_attr: 0x%x, global_vf_id_of_pf: %u\n",
		hwif->attr.ppf_idx, hwif->attr.num_aeqs,
		hwif->attr.num_ceqs, hwif->attr.num_irqs,
		hwif->attr.num_dma_attr, hwif->attr.global_vf_id_of_pf);
}

/**
 * get_hwif_attr - read and set the attributes as members in hwif
 * @hwif: the hardware interface of a pci function device
 **/
static void get_hwif_attr(struct sphw_hwif *hwif)
{
	u32 addr, attr0, attr1, attr2, attr3;

	addr   = SPHW_CSR_FUNC_ATTR0_ADDR;
	attr0  = sphw_hwif_read_reg(hwif, addr);

	addr   = SPHW_CSR_FUNC_ATTR1_ADDR;
	attr1  = sphw_hwif_read_reg(hwif, addr);

	addr   = SPHW_CSR_FUNC_ATTR2_ADDR;
	attr2  = sphw_hwif_read_reg(hwif, addr);

	addr   = SPHW_CSR_FUNC_ATTR3_ADDR;
	attr3  = sphw_hwif_read_reg(hwif, addr);

	pr_info("attr0: 0x%08x, attr1: 0x%08x, attr2: 0x%08x, attr3: 0x%08x\n",
		attr0, attr1, attr2, attr3);
	set_hwif_attr(hwif, attr0, attr1, attr2, attr3);
}

void sphw_set_pf_status(struct sphw_hwif *hwif, enum sphw_pf_status status)
{
	u32 attr6 = SPHW_AF6_SET(status, PF_STATUS);
	u32 addr  = SPHW_CSR_FUNC_ATTR6_ADDR;

	if (hwif->attr.func_type == TYPE_VF)
		return;

	sphw_hwif_write_reg(hwif, addr, attr6);
}

enum sphw_pf_status sphw_get_pf_status(struct sphw_hwif *hwif)
{
	u32 attr6 = sphw_hwif_read_reg(hwif, SPHW_CSR_FUNC_ATTR6_ADDR);

	return SPHW_AF6_GET(attr6, PF_STATUS);
}

enum sphw_doorbell_ctrl sphw_get_doorbell_ctrl_status(struct sphw_hwif *hwif)
{
	u32 attr4 = sphw_hwif_read_reg(hwif, SPHW_CSR_FUNC_ATTR4_ADDR);

	return SPHW_AF4_GET(attr4, DOORBELL_CTRL);
}

enum sphw_outbound_ctrl sphw_get_outbound_ctrl_status(struct sphw_hwif *hwif)
{
	u32 attr5 = sphw_hwif_read_reg(hwif, SPHW_CSR_FUNC_ATTR5_ADDR);

	return SPHW_AF5_GET(attr5, OUTBOUND_CTRL);
}

void sphw_enable_doorbell(struct sphw_hwif *hwif)
{
	u32 addr, attr4;

	addr = SPHW_CSR_FUNC_ATTR4_ADDR;
	attr4 = sphw_hwif_read_reg(hwif, addr);

	attr4 = SPHW_AF4_CLEAR(attr4, DOORBELL_CTRL);
	attr4 |= SPHW_AF4_SET(ENABLE_DOORBELL, DOORBELL_CTRL);

	sphw_hwif_write_reg(hwif, addr, attr4);
}

void sphw_disable_doorbell(struct sphw_hwif *hwif)
{
	u32 addr, attr4;

	addr = SPHW_CSR_FUNC_ATTR4_ADDR;
	attr4 = sphw_hwif_read_reg(hwif, addr);

	attr4 = SPHW_AF4_CLEAR(attr4, DOORBELL_CTRL);
	attr4 |= SPHW_AF4_SET(DISABLE_DOORBELL, DOORBELL_CTRL);

	sphw_hwif_write_reg(hwif, addr, attr4);
}

/**
 * set_ppf - try to set hwif as ppf and set the type of hwif in this case
 * @hwif: the hardware interface of a pci function device
 **/
static void set_ppf(struct sphw_hwif *hwif)
{
	struct sphw_func_attr *attr = &hwif->attr;
	u32 addr, val, ppf_election;

	/* Read Modify Write */
	addr  = SPHW_CSR_PPF_ELECTION_ADDR;

	val = sphw_hwif_read_reg(hwif, addr);
	val = SPHW_PPF_ELECTION_CLEAR(val, IDX);

	ppf_election =  SPHW_PPF_ELECTION_SET(attr->func_global_idx, IDX);
	val |= ppf_election;

	sphw_hwif_write_reg(hwif, addr, val);

	/* Check PPF */
	val = sphw_hwif_read_reg(hwif, addr);

	attr->ppf_idx = SPHW_PPF_ELECTION_GET(val, IDX);
	if (attr->ppf_idx == attr->func_global_idx)
		attr->func_type = TYPE_PPF;
}

/**
 * get_mpf - get the mpf index into the hwif
 * @hwif: the hardware interface of a pci function device
 **/
static void get_mpf(struct sphw_hwif *hwif)
{
	struct sphw_func_attr *attr = &hwif->attr;
	u32 mpf_election, addr;

	addr = SPHW_CSR_GLOBAL_MPF_ELECTION_ADDR;

	mpf_election = sphw_hwif_read_reg(hwif, addr);
	attr->mpf_idx = SPHW_MPF_ELECTION_GET(mpf_election, IDX);
}

/**
 * set_mpf - try to set hwif as mpf and set the mpf idx in hwif
 * @hwif: the hardware interface of a pci function device
 **/
static void set_mpf(struct sphw_hwif *hwif)
{
	struct sphw_func_attr *attr = &hwif->attr;
	u32 addr, val, mpf_election;

	/* Read Modify Write */
	addr  = SPHW_CSR_GLOBAL_MPF_ELECTION_ADDR;

	val = sphw_hwif_read_reg(hwif, addr);

	val = SPHW_MPF_ELECTION_CLEAR(val, IDX);
	mpf_election = SPHW_MPF_ELECTION_SET(attr->func_global_idx, IDX);

	val |= mpf_election;
	sphw_hwif_write_reg(hwif, addr, val);
}

static int init_db_area_idx(struct sphw_free_db_area *free_db_area, u64 db_dwqe_len)
{
	u32 db_max_areas;

	db_max_areas = (db_dwqe_len > SPHW_DB_DWQE_SIZE) ? SPHW_DB_MAX_AREAS :
		      (u32)(db_dwqe_len / SPHW_DB_PAGE_SIZE);
	free_db_area->db_bitmap_array = bitmap_zalloc(db_max_areas, GFP_KERNEL);
	if (!free_db_area->db_bitmap_array) {
		pr_err("Failed to allocate db area.\n");
		return -ENOMEM;
	}
	free_db_area->db_max_areas = db_max_areas;
	spin_lock_init(&free_db_area->idx_lock);

	return 0;
}

static void free_db_area(struct sphw_free_db_area *free_db_area)
{
	kfree(free_db_area->db_bitmap_array);
}

static int get_db_idx(struct sphw_hwif *hwif, u32 *idx)
{
	struct sphw_free_db_area *free_db_area = &hwif->free_db_area;
	u32 pg_idx;

	spin_lock(&free_db_area->idx_lock);
	pg_idx = (u32)find_first_zero_bit(free_db_area->db_bitmap_array,
					  free_db_area->db_max_areas);
	if (pg_idx == free_db_area->db_max_areas) {
		spin_unlock(&free_db_area->idx_lock);
		return -ENOMEM;
	}
	set_bit(pg_idx, free_db_area->db_bitmap_array);
	spin_unlock(&free_db_area->idx_lock);

	*idx = pg_idx;

	return 0;
}

static void free_db_idx(struct sphw_hwif *hwif, u32 idx)
{
	struct sphw_free_db_area *free_db_area = &hwif->free_db_area;

	if (idx >= free_db_area->db_max_areas)
		return;

	spin_lock(&free_db_area->idx_lock);
	clear_bit((int)idx, free_db_area->db_bitmap_array);

	spin_unlock(&free_db_area->idx_lock);
}

void sphw_free_db_addr(void *hwdev, const void __iomem *db_base, void __iomem *dwqe_base)
{
	struct sphw_hwif *hwif = NULL;
	u32 idx;

	if (!hwdev || !db_base)
		return;

	hwif = ((struct sphw_hwdev *)hwdev)->hwif;
	idx = DB_IDX(db_base, hwif->db_base);

	free_db_idx(hwif, idx);
}

int sphw_alloc_db_addr(void *hwdev, void __iomem **db_base, void __iomem **dwqe_base)
{
	struct sphw_hwif *hwif = NULL;
	u32 idx = 0;
	int err;

	if (!hwdev || !db_base)
		return -EINVAL;

	hwif = ((struct sphw_hwdev *)hwdev)->hwif;

	err = get_db_idx(hwif, &idx);
	if (err)
		return -EFAULT;

	*db_base = hwif->db_base + idx * SPHW_DB_PAGE_SIZE;

	if (!dwqe_base)
		return 0;

	*dwqe_base = (u8 *)*db_base + SPHW_DWQE_OFFSET;

	return 0;
}

void sphw_free_db_phy_addr(void *hwdev, u64 db_base, u64 dwqe_base)
{
	struct sphw_hwif *hwif = NULL;
	u32 idx;

	if (!hwdev)
		return;

	hwif = ((struct sphw_hwdev *)hwdev)->hwif;
	idx = DB_IDX(db_base, hwif->db_base_phy);

	free_db_idx(hwif, idx);
}

int sphw_alloc_db_phy_addr(void *hwdev, u64 *db_base, u64 *dwqe_base)
{
	struct sphw_hwif *hwif = NULL;
	u32 idx;
	int err;

	if (!hwdev || !db_base || !dwqe_base)
		return -EINVAL;

	hwif = ((struct sphw_hwdev *)hwdev)->hwif;

	err = get_db_idx(hwif, &idx);
	if (err)
		return -EFAULT;

	*db_base = hwif->db_base_phy + idx * SPHW_DB_PAGE_SIZE;
	*dwqe_base = *db_base + SPHW_DWQE_OFFSET;

	return 0;
}

void sphw_set_msix_auto_mask_state(void *hwdev, u16 msix_idx, enum sphw_msix_auto_mask flag)
{
	struct sphw_hwif *hwif = NULL;
	u32 mask_bits;
	u32 addr;

	if (!hwdev)
		return;

	hwif = ((struct sphw_hwdev *)hwdev)->hwif;

	if (flag)
		mask_bits = SPHW_MSI_CLR_INDIR_SET(1, AUTO_MSK_SET);
	else
		mask_bits = SPHW_MSI_CLR_INDIR_SET(1, AUTO_MSK_CLR);

	mask_bits = mask_bits | SPHW_MSI_CLR_INDIR_SET(msix_idx, SIMPLE_INDIR_IDX);

	addr = SPHW_CSR_FUNC_MSI_CLR_WR_ADDR;
	sphw_hwif_write_reg(hwif, addr, mask_bits);
}

void sphw_set_msix_state(void *hwdev, u16 msix_idx, enum sphw_msix_state flag)
{
	struct sphw_hwif *hwif = NULL;
	u32 mask_bits;
	u32 addr;
	u8 int_msk = 1;

	if (!hwdev)
		return;

	hwif = ((struct sphw_hwdev *)hwdev)->hwif;

	if (flag)
		mask_bits = SPHW_MSI_CLR_INDIR_SET(int_msk, INT_MSK_SET);
	else
		mask_bits = SPHW_MSI_CLR_INDIR_SET(int_msk, INT_MSK_CLR);
	mask_bits = mask_bits | SPHW_MSI_CLR_INDIR_SET(msix_idx, SIMPLE_INDIR_IDX);

	addr = SPHW_CSR_FUNC_MSI_CLR_WR_ADDR;
	sphw_hwif_write_reg(hwif, addr, mask_bits);
}

static void disable_all_msix(struct sphw_hwdev *hwdev)
{
	u16 num_irqs = hwdev->hwif->attr.num_irqs;
	u16 i;

	for (i = 0; i < num_irqs; i++)
		sphw_set_msix_state(hwdev, i, SPHW_MSIX_DISABLE);
}

static enum sphw_wait_return check_db_flush_enable_handler(void *priv_data)
{
	struct sphw_hwif *hwif = priv_data;
	enum sphw_doorbell_ctrl db_ctrl;

	db_ctrl = sphw_get_doorbell_ctrl_status(hwif);
	if (db_ctrl == ENABLE_DOORBELL)
		return WAIT_PROCESS_CPL;

	return WAIT_PROCESS_WAITING;
}

static enum sphw_wait_return check_db_flush_disable_handler(void *priv_data)
{
	struct sphw_hwif *hwif = priv_data;
	enum sphw_doorbell_ctrl db_ctrl;

	db_ctrl = sphw_get_doorbell_ctrl_status(hwif);
	if (db_ctrl == DISABLE_DOORBELL)
		return WAIT_PROCESS_CPL;

	return WAIT_PROCESS_WAITING;
}

int wait_until_doorbell_flush_states(struct sphw_hwif *hwif,
				     enum sphw_doorbell_ctrl states)
{
	if (!hwif)
		return -EFAULT;

	return sphw_wait_for_timeout(hwif, states == ENABLE_DOORBELL ?
				     check_db_flush_enable_handler : check_db_flush_disable_handler,
				     SPHW_WAIT_DOORBELL_AND_OUTBOUND_TIMEOUT, USEC_PER_MSEC);
}

static enum sphw_wait_return check_db_outbound_enable_handler(void *priv_data)
{
	struct sphw_hwif *hwif = priv_data;
	enum sphw_doorbell_ctrl db_ctrl;
	enum sphw_outbound_ctrl outbound_ctrl;

	db_ctrl = sphw_get_doorbell_ctrl_status(hwif);
	outbound_ctrl = sphw_get_outbound_ctrl_status(hwif);

	if (outbound_ctrl == ENABLE_OUTBOUND && db_ctrl == ENABLE_DOORBELL)
		return WAIT_PROCESS_CPL;

	return WAIT_PROCESS_WAITING;
}

static int wait_until_doorbell_and_outbound_enabled(struct sphw_hwif *hwif)
{
	return sphw_wait_for_timeout(hwif, check_db_outbound_enable_handler,
				     SPHW_WAIT_DOORBELL_AND_OUTBOUND_TIMEOUT, USEC_PER_MSEC);
}

/**
 * sphw_init_hwif - initialize the hw interface
 * @hwif: the hardware interface of a pci function device
 * @pdev: the pci device that will be part of the hwif struct
 * Return: 0 - success, negative - failure
 **/
int sphw_init_hwif(struct sphw_hwdev *hwdev, void *cfg_reg_base, void *intr_reg_base,
		   void *mgmt_regs_base, u64 db_base_phy, void *db_base, u64 db_dwqe_len)
{
	struct sphw_hwif *hwif = NULL;
	u32 attr4, attr5;
	int err;

	hwif = kzalloc(sizeof(*hwif), GFP_KERNEL);
	if (!hwif)
		return -ENOMEM;

	hwdev->hwif = hwif;
	hwif->pdev = hwdev->pcidev_hdl;

	/* if function is VF, mgmt_regs_base will be NULL */
	if (!mgmt_regs_base)
		hwif->cfg_regs_base = (u8 *)cfg_reg_base +
						SPHW_VF_CFG_REG_OFFSET;
	else
		hwif->cfg_regs_base = cfg_reg_base;

	hwif->intr_regs_base = intr_reg_base;
	hwif->mgmt_regs_base = mgmt_regs_base;
	sdk_info(hwdev->dev_hdl, "init intr_regs_base: %p, mgmt_regs_base: %p, db_base: %p, db_dwqe_len: 0x%llx\n",
		 hwif->intr_regs_base, hwif->mgmt_regs_base,
		 db_base, db_dwqe_len);

	hwif->db_base_phy = db_base_phy;
	hwif->db_base = db_base;
	hwif->db_dwqe_len = db_dwqe_len;
	err = init_db_area_idx(&hwif->free_db_area, hwif->db_dwqe_len);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init db area.\n");
		goto init_db_area_err;
	}

	err = wait_hwif_ready(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Chip status is not ready\n");
		goto hwif_ready_err;
	}

	get_hwif_attr(hwif);

	err = wait_until_doorbell_and_outbound_enabled(hwif);
	if (err) {
		attr4 = sphw_hwif_read_reg(hwif, SPHW_CSR_FUNC_ATTR4_ADDR);
		attr5 = sphw_hwif_read_reg(hwif, SPHW_CSR_FUNC_ATTR5_ADDR);
		sdk_err(hwdev->dev_hdl, "Hw doorbell/outbound is disabled, attr4 0x%x attr5 0x%x\n",
			attr4, attr5);
		goto hwif_ready_err;
	}

	if (!SPHW_IS_VF(hwdev)) {
		set_ppf(hwif);

		if (SPHW_IS_PPF(hwdev))
			set_mpf(hwif);

		get_mpf(hwif);
	}

	disable_all_msix(hwdev);
	/* disable mgmt cpu report any event */
	sphw_set_pf_status(hwdev->hwif, SPHW_PF_STATUS_INIT);

	sdk_info(hwdev->dev_hdl, "global_func_idx: %u, func_type: %d, host_id: %u, ppf: %u, mpf: %u\n",
		 hwif->attr.func_global_idx, hwif->attr.func_type,
		 hwif->attr.pci_intf_idx, hwif->attr.ppf_idx,
		 hwif->attr.mpf_idx);

	return 0;

hwif_ready_err:
	free_db_area(&hwif->free_db_area);
init_db_area_err:
	kfree(hwif);

	return err;
}

/**
 * sphw_free_hwif - free the hw interface
 * @hwif: the hardware interface of a pci function device
 * @pdev: the pci device that will be part of the hwif struct
 **/
void sphw_free_hwif(struct sphw_hwdev *hwdev)
{
	free_db_area(&hwdev->hwif->free_db_area);
	kfree(hwdev->hwif);
}

u16 sphw_global_func_id(void *hwdev)
{
	struct sphw_hwif *hwif = NULL;

	if (!hwdev)
		return 0;

	hwif = ((struct sphw_hwdev *)hwdev)->hwif;

	return hwif->attr.func_global_idx;
}

u16 sphw_intr_num(void *hwdev)
{
	struct sphw_hwif *hwif = NULL;

	if (!hwdev)
		return 0;

	hwif = ((struct sphw_hwdev *)hwdev)->hwif;

	return hwif->attr.num_irqs;
}

u8 sphw_pf_id_of_vf(void *hwdev)
{
	struct sphw_hwif *hwif = NULL;

	if (!hwdev)
		return 0;

	hwif = ((struct sphw_hwdev *)hwdev)->hwif;

	return hwif->attr.port_to_port_idx;
}

u8 sphw_pcie_itf_id(void *hwdev)
{
	struct sphw_hwif *hwif = NULL;

	if (!hwdev)
		return 0;

	hwif = ((struct sphw_hwdev *)hwdev)->hwif;

	return hwif->attr.pci_intf_idx;
}

u8 sphw_vf_in_pf(void *hwdev)
{
	struct sphw_hwif *hwif = NULL;

	if (!hwdev)
		return 0;

	hwif = ((struct sphw_hwdev *)hwdev)->hwif;

	return hwif->attr.vf_in_pf;
}

enum func_type sphw_func_type(void *hwdev)
{
	struct sphw_hwif *hwif = NULL;

	if (!hwdev)
		return 0;

	hwif = ((struct sphw_hwdev *)hwdev)->hwif;

	return hwif->attr.func_type;
}

u8 sphw_ceq_num(void *hwdev)
{
	struct sphw_hwif *hwif = NULL;

	if (!hwdev)
		return 0;

	hwif = ((struct sphw_hwdev *)hwdev)->hwif;

	return hwif->attr.num_ceqs;
}

u8 sphw_dma_attr_entry_num(void *hwdev)
{
	struct sphw_hwif *hwif = NULL;

	if (!hwdev)
		return 0;

	hwif = ((struct sphw_hwdev *)hwdev)->hwif;

	return hwif->attr.num_dma_attr;
}

u16 sphw_glb_pf_vf_offset(void *hwdev)
{
	struct sphw_hwif *hwif = NULL;

	if (!hwdev)
		return 0;

	hwif = ((struct sphw_hwdev *)hwdev)->hwif;

	return hwif->attr.global_vf_id_of_pf;
}

u8 sphw_mpf_idx(void *hwdev)
{
	struct sphw_hwif *hwif = NULL;

	if (!hwdev)
		return 0;

	hwif = ((struct sphw_hwdev *)hwdev)->hwif;

	return hwif->attr.mpf_idx;
}

u8 sphw_ppf_idx(void *hwdev)
{
	struct sphw_hwif *hwif = NULL;

	if (!hwdev)
		return 0;

	hwif = ((struct sphw_hwdev *)hwdev)->hwif;

	return hwif->attr.ppf_idx;
}

u8 sphw_host_ppf_idx(void *hwdev, u8 host_id)
{
	struct sphw_hwdev *dev = hwdev;
	u32 ppf_elect_port_addr;
	u32 val;

	if (!hwdev)
		return 0;

	ppf_elect_port_addr = SPHW_CSR_FUNC_PPF_ELECT(host_id);
	val = sphw_hwif_read_reg(dev->hwif, ppf_elect_port_addr);

	return sphw_PPF_ELECT_PORT_GET(val, IDX);
}

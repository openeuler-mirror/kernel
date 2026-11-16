// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2018 - 2025 Beijing WangXun Technology Co., Ltd. */
#include "osdep.h"
#include "type.h"
#include "nserdma_hw.h"
#include "main.h"

static u32 nserdma_vf_regs[NSER_MAX_REGS] = {
	VFPE_CCQPLOW1,
	VFPE_CCQPHIGH1,
	VFPE_CQPERRCODES1,
	VFPE_CCQPSTATUS1,
	VFPE_IPCFG1,
	VFPE_CQPDB1,
	VFPE_CQPTAIL1,
	VFPE_CQARM1,
	VFPE_CQACK1,
	VFPE_AEQALLOC1,
	VFPE_WQEALLOC1,
	VFINT_DYN_CTLN(0),
	VFPE_MRTEIDXMASK1,
	VFPE_CQEDROPCNT1,
	VFPE_CEQEDROPCNT1,
	VFPE_AEQEDROPCNT1,
	VFPE_PECSTATUS1,
	NSERDMA_VF_DB_ADDR_OFFSET
};

static u32 nserdma_regs[NSER_MAX_REGS] = {
	PFPE_CCQPLOW(0),
	PFPE_CCQPHIGH(0),
	PFPE_CQPERRCODES(0),
	PFPE_CCQPSTATUS(0),
	PFPE_IPCFG(0),
	PFPE_CQPDB(0),
	PFPE_CQPTAIL(0),
	PFPE_CQARM(0),
	PFPE_CQACK(0),
	PFPE_AEQALLOC(0),
	PFPE_WQEALLOC(0),
	GLINT_DYN_CTL(0),
	PFPE_MRTEIDXMASK(0),
	PFPE_CQEDROPCNT(0),
	PFPE_CEQEDROPCNT(0),
	PFPE_AEQEDROPCNT(0),
	PFPE_PECSTATUS(0),
	NSERDMA_DB_ADDR_OFFSET(0),
	//BAR0_ST_REG_BADDR,
	//GLPE_CRITERR,
};

static u64 nserdma_masks[NSER_MAX_MASKS] = {
	NSERDMA_CCQPSTATUS_CCQP_DONE,
	NSERDMA_CCQPSTATUS_CCQP_ERR,
	NSERDMA_CQPSQ_STAG_PDID,
	NSERDMA_CQPSQ_CQ_CEQID,
	NSERDMA_CQPSQ_CQ_CQID,
	NSERDMA_COMMIT_FPM_CQCNT,
	NSERDMA_CQPSQ_UPESD_HMCFNID
};

static u8 nserdma_shifts[NSER_MAX_SHIFTS] = {
	NSERDMA_CCQPSTATUS_CCQP_DONE_S,
	NSERDMA_CCQPSTATUS_CCQP_ERR_S,
	NSERDMA_CQPSQ_STAG_PDID_S,
	NSERDMA_CQPSQ_CQ_CEQID_S,
	NSERDMA_CQPSQ_CQ_CQID_S,
	NSERDMA_COMMIT_FPM_CQCNT_S,
	NSERDMA_CQPSQ_UPESD_HMCFNID_S
};

/**
 * nserdma_ena_irq - Enable interrupt
 * @dev: pointer to the device structure
 * @idx: vector index
 */
static void nserdma_ena_irq(struct nser_sc_dev *dev, u32 idx)
{
	u32 val;
	u32 interval = 0;

	if (dev->ceq_itr && dev->aeq->msix_idx != idx)
		interval = dev->ceq_itr >> 1; /* 2 usec units */

	val = FIELD_PREP(NSER_GLINT_DYN_CTL_ITR_VLD, 0) |
	      FIELD_PREP(NSER_GLINT_DYN_CTL_INTERVAL, interval) |
	      FIELD_PREP(NSER_GLINT_DYN_CTL_INTMASK, 0) |
	      FIELD_PREP(NSER_GLINT_DYN_CTL_CLEARPBA, true);

	writel(val, dev->hw_regs[NSER_GLINT_DYN_CTL] + idx);
}

/**
 * nserdma_disable_irq - Disable interrupt
 * @dev: pointer to the device structure
 * @idx: vector index
 */
static void nserdma_disable_irq(struct nser_sc_dev *dev, u32 idx)
{
	writel(1, dev->hw_regs[NSER_GLINT_DYN_CTL] + idx);
}


static const struct nser_irq_ops nserdma_irq_ops = {
	.nser_dis_irq = nserdma_disable_irq,
	.nser_en_irq = nserdma_ena_irq,
};

static const struct nser_hw_stat_map nserdma_hw_stat_map[] = {
	[NSER_HW_STAT_INDEX_RX_VLAN_ERR]	=	{   0, 0, NSER_MAX_STATS_48 },

	[NSER_HW_STAT_INDEX_IPV4_RX_OCTS] =		{   8,  0, NSER_MAX_STATS_48 },
	[NSER_HW_STAT_INDEX_IPV4_RX_PKTS] =		{  16,  0, NSER_MAX_STATS_48 },
	[NSER_HW_STAT_INDEX_IPV4_RX_DISCARD] =	{  24, 0, NSER_MAX_STATS_48 },
	[NSER_HW_STAT_INDEX_IPV4_RX_MCOCTS] =	{  32,  0, NSER_MAX_STATS_48 },
	[NSER_HW_STAT_INDEX_IPV4_RX_MCPKTS] =	{  40,  0, NSER_MAX_STATS_48 },

	[NSER_HW_STAT_INDEX_IPV6_RX_OCTS] =		{  48,  0, NSER_MAX_STATS_48 },
	[NSER_HW_STAT_INDEX_IPV6_RX_PKTS] =		{  56,  0, NSER_MAX_STATS_48 },
	[NSER_HW_STAT_INDEX_IPV6_RX_DISCARD] =	{  64,  0, NSER_MAX_STATS_48 },
	[NSER_HW_STAT_INDEX_IPV6_RX_MCOCTS] =	{  72,  0, NSER_MAX_STATS_48 },
	[NSER_HW_STAT_INDEX_IPV6_RX_MCPKTS] =	{  80, 0, NSER_MAX_STATS_48 },

	[NSER_HW_STAT_INDEX_IPV4_TX_OCTS] =		{  88,  0, NSER_MAX_STATS_48 },
	[NSER_HW_STAT_INDEX_IPV4_TX_PKTS] =		{  96,  0, NSER_MAX_STATS_48 }, //12
	[NSER_HW_STAT_INDEX_IPV4_TX_MCOTS] =	{  104,  0, NSER_MAX_STATS_48 },
	[NSER_HW_STAT_INDEX_IPV4_TX_MCPKTS] =	{  112,  0, NSER_MAX_STATS_48 },

	[NSER_HW_STAT_INDEX_IPV6_TX_OCTS] =		{ 120,  0, NSER_MAX_STATS_48 },
	[NSER_HW_STAT_INDEX_IPV6_TX_PKTS] =		{ 128,  0, NSER_MAX_STATS_48 },
	[NSER_HW_STAT_INDEX_IPV6_TX_MCOTS] =	{ 136,  0, NSER_MAX_STATS_48 },
	[NSER_HW_STAT_INDEX_IPV6_TX_MCPKTS] =	{ 144,  0, NSER_MAX_STATS_48 },

	[NSER_HW_STAT_INDEX_RDMA_RX_WRS] =		{ 152,  0, NSER_MAX_STATS_48 }, //19
	[NSER_HW_STAT_INDEX_RDMA_RX_RDS] =		{ 160,  0, NSER_MAX_STATS_48 },
	[NSER_HW_STAT_INDEX_RDMA_RX_SNDS] =		{ 168,  0, NSER_MAX_STATS_48 },

	[NSER_HW_STAT_INDEX_RDMA_TX_WRS] =		{ 176,  0, NSER_MAX_STATS_48 },
	[NSER_HW_STAT_INDEX_RDMA_TX_RDS] =		{ 184,  0, NSER_MAX_STATS_48 },
	[NSER_HW_STAT_INDEX_RDMA_TX_SNDS] =		{ 192,  0, NSER_MAX_STATS_48 },

	[NSER_HW_STAT_INDEX_RX_ECN_MARKED_PKTS] =	{ 200, 0, NSER_MAX_STATS_48 }, //25
	[NSER_HW_STAT_INDEX_TX_REPKTS] =			{ 208,  0, NSER_MAX_STATS_48 },
	[NSER_HW_STAT_INDEX_RDMA_RX_ACK_PKT] =		{ 216, 0, NSER_MAX_STATS_48 },

	[NSER_HW_STAT_INDEX_RDMA_RX_NAK_PKT] =	{ 224, 0, NSER_MAX_STATS_48 },
	[NSER_HW_STAT_INDEX_RDMA_RX_RNR_PKT] =	{ 232,  0, NSER_MAX_STATS_48 },
	[NSER_HW_STAT_INDEX_RDMA_RX_DUP_PKT] =		{ 240,  0, NSER_MAX_STATS_48 },

	[NSER_HW_STAT_INDEX_RDMA_RX_INV_PKT] =		{ 248, 0, NSER_MAX_STATS_48 }, //31
	[NSER_HW_STAT_INDEX_RDMA_TX_ACK_PKT] =		{ 256,  0, NSER_MAX_STATS_48 },
	[NSER_HW_STAT_INDEX_RDMA_TX_NAK_PKT] =		{ 264,  0, NSER_MAX_STATS_48 }, //33

	[NSER_HW_STAT_INDEX_RDMA_TX_RNR_PKT] =	{ 272,  0, NSER_MAX_STATS_48 },
	[NSER_HW_STAT_INDEX_RDMA_RX_UDDROP] =	{ 280,  0, NSER_MAX_STATS_48 },
	[NSER_HW_STAT_INDEX_RX_CNP_IGNORED] =	{ 288,  0, NSER_MAX_STATS_48 },
	[NSER_HW_STAT_INDEX_RX_CNP_HANDLED] =	{ 296,  0, NSER_MAX_STATS_48 },
	[NSER_HW_STAT_INDEX_TX_CNPSENT] =	{ 304,  0, NSER_MAX_STATS_48 },

	[NSER_HW_STAT_INDEX_VBND] =	{ 312,  0, NSER_MAX_STATS_48 },//39
	[NSER_HW_STAT_INDEX_VINV] =	{ 320,  0, NSER_MAX_STATS_48 },
	[NSER_HW_STAT_INDEX_FRM] =	{ 328,  0, NSER_MAX_STATS_48 },

};

void nserdma_init_hw(struct nser_sc_dev *dev)
{
	int i;
	u8 __iomem *hw_addr;

	if (dev->privileged) {
		for (i = 0; i < NSER_MAX_REGS; ++i) {
			hw_addr = dev->hw->hw_addr;

			if (i == NSER_DB_ADDR_OFFSET)
				hw_addr = 0;
			dev->hw_regs[i] = (u32 __iomem *)(hw_addr + nserdma_regs[i]);
		}
	} else {
		for (i = 0; i < NSER_MAX_REGS; ++i) {
			hw_addr = dev->hw->hw_addr;

			if (i == NSER_DB_ADDR_OFFSET)
				hw_addr = 0;

			dev->hw_regs[i] = (u32 __iomem *)(hw_addr + nserdma_vf_regs[i]);
		}
	}

	for (i = 0; i < NSER_MAX_SHIFTS; ++i)
		dev->hw_shifts[i] = nserdma_shifts[i];

	for (i = 0; i < NSER_MAX_MASKS; ++i)
		dev->hw_masks[i] = nserdma_masks[i];

	dev->wqe_alloc_db = dev->hw_regs[NSER_WQEALLOC];
	dev->cq_arm_db = dev->hw_regs[NSER_CQARM];
	dev->aeq_alloc_db = dev->hw_regs[NSER_AEQALLOC];
	dev->cqp_db = dev->hw_regs[NSER_CQPDB];
	dev->cq_ack_db = dev->hw_regs[NSER_CQACK];
	dev->irq_ops = &nserdma_irq_ops;
	dev->hw_stats_map = nserdma_hw_stat_map;

	dev->hw_attrs.page_size_cap = SZ_4K | SZ_2M;
	dev->hw_attrs.max_hw_ird = NSERDMA_MAX_IRD_SIZE;
	dev->hw_attrs.max_hw_ord = NSERDMA_MAX_ORD_SIZE;
	dev->hw_attrs.max_stat_inst = NSERDMA_MAX_STATS_COUNT;
	dev->hw_attrs.max_stat_idx = NSER_HW_STAT_INDEX_MAX;

	dev->hw_attrs.uk_attrs.max_hw_wq_frags = NSERDMA_MAX_WQ_FRAGMENT_COUNT;
	dev->hw_attrs.uk_attrs.max_hw_read_sges = NSERDMA_MAX_SGE_RD;
	dev->hw_attrs.uk_attrs.min_hw_wq_size = NSERDMA_MIN_WQ_SIZE;
	dev->hw_attrs.uk_attrs.max_hw_sq_chunk = NSER_MAX_QUANTA_PER_WR;
	dev->hw_attrs.uk_attrs.feature_flags |= NSER_FEATURE_RTS_AE | NSER_FEATURE_CQ_RESIZE;
	if (dev->hw_attrs.uk_attrs.hw_rev == IIDC_RDMA_GEN_MOONSTONE)
		dev->hw_attrs.uk_attrs.feature_flags |= NSER_FEATURE_ATOMIC_OPS;
}

void nser_init_config_check(struct nser_config_check *cc, u8 traffic_class, u16 qs_handle)
{
	cc->config_ok = false;
	cc->traffic_class = traffic_class;
	cc->qs_handle = qs_handle;
	cc->lfc_set = 0;
	cc->pfc_set = 0;
}

static bool nser_is_lfc_set(struct nser_config_check *cc, struct nser_sc_vsi *vsi)
{
	u32 lfc = 1;
	u8 fn_id = vsi->dev->hmc_fn_id;

	lfc &= (rd32(vsi->dev->hw,
		     PRTMAC_HSEC_CTL_RX_PAUSE_ENABLE_0 + 4 * fn_id) >> 8);
	lfc &= (rd32(vsi->dev->hw,
		     PRTMAC_HSEC_CTL_TX_PAUSE_ENABLE_0 + 4 * fn_id) >> 8);
	lfc &= rd32(vsi->dev->hw,
		    PRTMAC_HSEC_CTL_RX_ENABLE_GPP_0 + 4 * vsi->dev->hmc_fn_id);

	if (lfc)
		return true;
	return false;
}

static bool nser_check_tc_has_pfc(struct nser_sc_vsi *vsi, u64 reg_offset, u16 traffic_class)
{
	u32 value, pfc = 0;
	u32 i;

	value = rd32(vsi->dev->hw, reg_offset);
	for (i = 0; i < 4; i++)
		pfc |= (value >> (8 * i + traffic_class)) & 0x1;

	if (pfc)
		return true;
	return false;
}

static bool nser_is_pfc_set(struct nser_config_check *cc, struct nser_sc_vsi *vsi)
{
	u32 pause;
	u8 fn_id = vsi->dev->hmc_fn_id;

	pause = (rd32(vsi->dev->hw,
		      PRTMAC_HSEC_CTL_RX_PAUSE_ENABLE_0 + 4 * fn_id) >>
		      cc->traffic_class) & BIT(0);
	pause &= (rd32(vsi->dev->hw,
		       PRTMAC_HSEC_CTL_TX_PAUSE_ENABLE_0 + 4 * fn_id) >>
		       cc->traffic_class) & BIT(0);

	return nser_check_tc_has_pfc(vsi, GLDCB_TC2PFC, cc->traffic_class) &&
	       pause;
}

bool nser_is_config_ok(struct nser_config_check *cc, struct nser_sc_vsi *vsi)
{
	cc->lfc_set = nser_is_lfc_set(cc, vsi);
	cc->pfc_set = nser_is_pfc_set(cc, vsi);

	cc->config_ok = cc->lfc_set || cc->pfc_set;

	return cc->config_ok;
}

#define NSER_RCV_WND_NO_FC	0x1FFFC
#define NSER_RCV_WND_FC	0x3FFFC

#define NSER_CWND_NO_FC	0x20
#define NSER_CWND_FC		0x400

#define NSER_RTOMIN_NO_FC	0x5
#define NSER_RTOMIN_FC		0x32

#define NSER_ACKCREDS_NO_FC	0x02
#define NSER_ACKCREDS_FC	0x1E

static void nser_check_flow_ctrl(struct nser_sc_vsi *vsi, u8 user_prio, u8 traffic_class)
{
	struct nser_config_check *cfg_chk = &vsi->cfg_check[user_prio];
	struct nser_device *iwdev = vsi->back_vsi;

	if (!nser_is_config_ok(cfg_chk, vsi)) {
		if (!iwdev->override_rcv_wnd)
			iwdev->rcv_wnd = NSER_RCV_WND_NO_FC;
		if (!iwdev->override_cwnd)
			iwdev->roce_cwnd = NSER_CWND_NO_FC;
		if (!iwdev->override_ackcreds)
			iwdev->roce_ackcreds = NSER_ACKCREDS_NO_FC;
#define NSER_READ_FENCE_RATE_NO_FC	4
		if (!iwdev->override_rd_fence_rate)
			iwdev->rd_fence_rate = NSER_READ_FENCE_RATE_NO_FC;
		if (vsi->tc_print_warning[traffic_class]) {
			pr_info("INFO: Flow control is disabled for this traffic class (%d) on this vsi.\n",
				traffic_class);
			vsi->tc_print_warning[traffic_class] = false;
		}
	} else {
		if (!iwdev->override_rcv_wnd)
			iwdev->rcv_wnd = NSER_RCV_WND_FC;
		if (!iwdev->override_cwnd)
			iwdev->roce_cwnd = NSER_CWND_FC;
		if (!iwdev->override_ackcreds)
			iwdev->roce_ackcreds = NSER_ACKCREDS_FC;
#define NSER_READ_FENCE_RATE_FC	0
		if (!iwdev->override_rd_fence_rate)
			iwdev->rd_fence_rate = NSER_READ_FENCE_RATE_FC;
		if (vsi->tc_print_warning[traffic_class]) {
			pr_info("INFO: Flow control is enabled for this traffic class (%d) on this vsi.\n",
				traffic_class);
			vsi->tc_print_warning[traffic_class] = false;
		}
	}
}

void nser_check_fc_for_tc_update(struct nser_sc_vsi *vsi,
				  struct nser_l2params *l2params)
{
	u8 i;

	if (!vsi->dev->privileged)
		return;
	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++)
		vsi->tc_print_warning[i] = true;

	for (i = 0; i < NSER_MAX_USER_PRIORITY; i++) {
		struct nser_config_check *cfg_chk = &vsi->cfg_check[i];
		u8 tc = l2params->up2tc[i];

		cfg_chk->traffic_class = tc;
		cfg_chk->qs_handle = vsi->qos[i].qs_handle;
		nser_check_flow_ctrl(vsi, i, tc);
	}
}

void nser_check_fc_for_qp(struct nser_sc_vsi *vsi, struct nser_sc_qp *sc_qp)
{
	u8 i;

	if (!vsi->dev->privileged)
		return;
	for (i = 0; i < NSER_MAX_USER_PRIORITY; i++) {
		struct nser_config_check *cfg_chk = &vsi->cfg_check[i];

		nser_init_config_check(cfg_chk,
					vsi->qos[i].traffic_class,
					vsi->qos[i].qs_handle);
		if (sc_qp->qs_handle == cfg_chk->qs_handle)
			nser_check_flow_ctrl(vsi, i, cfg_chk->traffic_class);
	}
}


// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <linux/module.h>

#include "sphw_crm.h"
#include "sphw_hw.h"
#include "sphw_common.h"
#include "spnic_nic_qp.h"
#include "spnic_nic_io.h"
#include "spnic_nic_cfg.h"
#include "spnic_nic.h"
#include "spnic_nic_cmd.h"

#define SPNIC_DEAULT_TX_CI_PENDING_LIMIT	0
#define SPNIC_DEAULT_TX_CI_COALESCING_TIME	0
#define SPNIC_DEAULT_DROP_THD_ON		0xFFFF
#define SPNIC_DEAULT_DROP_THD_OFF		0

static unsigned char tx_pending_limit = SPNIC_DEAULT_TX_CI_PENDING_LIMIT;
module_param(tx_pending_limit, byte, 0444);
MODULE_PARM_DESC(tx_pending_limit, "TX CI coalescing parameter pending_limit (default=0)");

static unsigned char tx_coalescing_time = SPNIC_DEAULT_TX_CI_COALESCING_TIME;
module_param(tx_coalescing_time, byte, 0444);
MODULE_PARM_DESC(tx_coalescing_time, "TX CI coalescing parameter coalescing_time (default=0)");

static unsigned char rq_wqe_type = SPNIC_NORMAL_RQ_WQE;
module_param(rq_wqe_type, byte, 0444);
MODULE_PARM_DESC(rq_wqe_type, "RQ WQE type 0-8Bytes, 1-16Bytes, 2-32Bytes (default=2)");

static u32 tx_drop_thd_on = SPNIC_DEAULT_DROP_THD_ON;
module_param(tx_drop_thd_on, uint, 0644);
MODULE_PARM_DESC(tx_drop_thd_on, "TX parameter drop_thd_on (default=0xffff)");

static u32 tx_drop_thd_off = SPNIC_DEAULT_DROP_THD_OFF;
module_param(tx_drop_thd_off, uint, 0644);
MODULE_PARM_DESC(tx_drop_thd_off, "TX parameter drop_thd_off (default=0)");
/* performance: ci addr RTE_CACHE_SIZE(64B) alignment */
#define SPNIC_CI_Q_ADDR_SIZE		64

#define CI_TABLE_SIZE(num_qps, pg_sz)	(ALIGN((num_qps) * SPNIC_CI_Q_ADDR_SIZE, pg_sz))

#define SPNIC_CI_VADDR(base_addr, q_id)	((u8 *)(base_addr) + (q_id) * SPNIC_CI_Q_ADDR_SIZE)

#define SPNIC_CI_PADDR(base_paddr, q_id)	((base_paddr) + (q_id) * SPNIC_CI_Q_ADDR_SIZE)

#define WQ_PREFETCH_MAX			4
#define WQ_PREFETCH_MIN			1
#define WQ_PREFETCH_THRESHOLD		256

#define SPNIC_Q_CTXT_MAX		31 /* (2048 - 8) / 64 */

enum spnic_qp_ctxt_type {
	SPNIC_QP_CTXT_TYPE_SQ,
	SPNIC_QP_CTXT_TYPE_RQ,
};

struct spnic_qp_ctxt_header {
	u16	num_queues;
	u16	queue_type;
	u16	start_qid;
	u16	rsvd;
};

struct spnic_sq_ctxt {
	u32	ci_pi;
	u32	drop_mode_sp;
	u32	wq_pfn_hi_owner;
	u32	wq_pfn_lo;

	u32	rsvd0;
	u32	pkt_drop_thd;
	u32	global_sq_id;
	u32	vlan_ceq_attr;

	u32	pref_cache;
	u32	pref_ci_owner;
	u32	pref_wq_pfn_hi_ci;
	u32	pref_wq_pfn_lo;

	u32	rsvd8;
	u32	rsvd9;
	u32	wq_block_pfn_hi;
	u32	wq_block_pfn_lo;
};

struct spnic_rq_ctxt {
	u32	ci_pi;
	u32	ceq_attr;
	u32	wq_pfn_hi_type_owner;
	u32	wq_pfn_lo;

	u32	rsvd[3];
	u32	cqe_sge_len;

	u32	pref_cache;
	u32	pref_ci_owner;
	u32	pref_wq_pfn_hi_ci;
	u32	pref_wq_pfn_lo;

	u32	pi_paddr_hi;
	u32	pi_paddr_lo;
	u32	wq_block_pfn_hi;
	u32	wq_block_pfn_lo;
};

struct spnic_sq_ctxt_block {
	struct spnic_qp_ctxt_header	cmdq_hdr;
	struct spnic_sq_ctxt		sq_ctxt[SPNIC_Q_CTXT_MAX];
};

struct spnic_rq_ctxt_block {
	struct spnic_qp_ctxt_header	cmdq_hdr;
	struct spnic_rq_ctxt		rq_ctxt[SPNIC_Q_CTXT_MAX];
};

struct spnic_clean_queue_ctxt {
	struct spnic_qp_ctxt_header	cmdq_hdr;
	u32				rsvd;
};

#define SQ_CTXT_SIZE(num_sqs)	((u16)(sizeof(struct spnic_qp_ctxt_header) + \
				       (num_sqs) * sizeof(struct spnic_sq_ctxt)))

#define RQ_CTXT_SIZE(num_rqs)	((u16)(sizeof(struct spnic_qp_ctxt_header) + \
				       (num_rqs) * sizeof(struct spnic_rq_ctxt)))

#define CI_IDX_HIGH_SHIFH				12

#define CI_HIGN_IDX(val)				((val) >> CI_IDX_HIGH_SHIFH)

#define SQ_CTXT_PI_IDX_SHIFT				0
#define SQ_CTXT_CI_IDX_SHIFT				16

#define SQ_CTXT_PI_IDX_MASK				0xFFFFU
#define SQ_CTXT_CI_IDX_MASK				0xFFFFU

#define SQ_CTXT_CI_PI_SET(val, member)		(((val) & SQ_CTXT_##member##_MASK) << \
						 SQ_CTXT_##member##_SHIFT)

#define SQ_CTXT_MODE_SP_FLAG_SHIFT			0
#define SQ_CTXT_MODE_PKT_DROP_SHIFT			1

#define SQ_CTXT_MODE_SP_FLAG_MASK			0x1U
#define SQ_CTXT_MODE_PKT_DROP_MASK			0x1U

#define SQ_CTXT_MODE_SET(val, member)		(((val) & SQ_CTXT_MODE_##member##_MASK) << \
						 SQ_CTXT_MODE_##member##_SHIFT)

#define SQ_CTXT_WQ_PAGE_HI_PFN_SHIFT			0
#define SQ_CTXT_WQ_PAGE_OWNER_SHIFT			23

#define SQ_CTXT_WQ_PAGE_HI_PFN_MASK			0xFFFFFU
#define SQ_CTXT_WQ_PAGE_OWNER_MASK			0x1U

#define SQ_CTXT_WQ_PAGE_SET(val, member)	(((val) & SQ_CTXT_WQ_PAGE_##member##_MASK) << \
						 SQ_CTXT_WQ_PAGE_##member##_SHIFT)

#define SQ_CTXT_PKT_DROP_THD_ON_SHIFT			0
#define SQ_CTXT_PKT_DROP_THD_OFF_SHIFT			16

#define SQ_CTXT_PKT_DROP_THD_ON_MASK			0xFFFFU
#define SQ_CTXT_PKT_DROP_THD_OFF_MASK			0xFFFFU

#define SQ_CTXT_PKT_DROP_THD_SET(val, member)	(((val) & SQ_CTXT_PKT_DROP_##member##_MASK) << \
						 SQ_CTXT_PKT_DROP_##member##_SHIFT)

#define SQ_CTXT_GLOBAL_SQ_ID_SHIFT			0

#define SQ_CTXT_GLOBAL_SQ_ID_MASK			0x1FFFU

#define SQ_CTXT_GLOBAL_QUEUE_ID_SET(val, member) (((val) & SQ_CTXT_##member##_MASK) << \
						  SQ_CTXT_##member##_SHIFT)

#define SQ_CTXT_VLAN_TAG_SHIFT				0
#define SQ_CTXT_VLAN_TYPE_SEL_SHIFT			16
#define SQ_CTXT_VLAN_INSERT_MODE_SHIFT			19
#define SQ_CTXT_VLAN_CEQ_EN_SHIFT			23

#define SQ_CTXT_VLAN_TAG_MASK				0xFFFFU
#define SQ_CTXT_VLAN_TYPE_SEL_MASK			0x7U
#define SQ_CTXT_VLAN_INSERT_MODE_MASK			0x3U
#define SQ_CTXT_VLAN_CEQ_EN_MASK			0x1U

#define SQ_CTXT_VLAN_CEQ_SET(val, member)	(((val) & SQ_CTXT_VLAN_##member##_MASK) << \
						 SQ_CTXT_VLAN_##member##_SHIFT)

#define SQ_CTXT_PREF_CACHE_THRESHOLD_SHIFT		0
#define SQ_CTXT_PREF_CACHE_MAX_SHIFT			14
#define SQ_CTXT_PREF_CACHE_MIN_SHIFT			25

#define SQ_CTXT_PREF_CACHE_THRESHOLD_MASK		0x3FFFU
#define SQ_CTXT_PREF_CACHE_MAX_MASK			0x7FFU
#define SQ_CTXT_PREF_CACHE_MIN_MASK			0x7FU

#define SQ_CTXT_PREF_CI_HI_SHIFT			0
#define SQ_CTXT_PREF_OWNER_SHIFT			4

#define SQ_CTXT_PREF_CI_HI_MASK				0xFU
#define SQ_CTXT_PREF_OWNER_MASK				0x1U

#define SQ_CTXT_PREF_WQ_PFN_HI_SHIFT			0
#define SQ_CTXT_PREF_CI_LOW_SHIFT			20

#define SQ_CTXT_PREF_WQ_PFN_HI_MASK			0xFFFFFU
#define SQ_CTXT_PREF_CI_LOW_MASK			0xFFFU

#define SQ_CTXT_PREF_SET(val, member)		(((val) & SQ_CTXT_PREF_##member##_MASK) << \
						 SQ_CTXT_PREF_##member##_SHIFT)

#define SQ_CTXT_WQ_BLOCK_PFN_HI_SHIFT			0

#define SQ_CTXT_WQ_BLOCK_PFN_HI_MASK			0x7FFFFFU

#define SQ_CTXT_WQ_BLOCK_SET(val, member)	(((val) & SQ_CTXT_WQ_BLOCK_##member##_MASK) << \
						 SQ_CTXT_WQ_BLOCK_##member##_SHIFT)

#define RQ_CTXT_PI_IDX_SHIFT				0
#define RQ_CTXT_CI_IDX_SHIFT				16

#define RQ_CTXT_PI_IDX_MASK				0xFFFFU
#define RQ_CTXT_CI_IDX_MASK				0xFFFFU

#define RQ_CTXT_CI_PI_SET(val, member)		(((val) & RQ_CTXT_##member##_MASK) << \
						 RQ_CTXT_##member##_SHIFT)

#define RQ_CTXT_CEQ_ATTR_INTR_SHIFT			21
#define RQ_CTXT_CEQ_ATTR_EN_SHIFT			31

#define RQ_CTXT_CEQ_ATTR_INTR_MASK			0x3FFU
#define RQ_CTXT_CEQ_ATTR_EN_MASK			0x1U

#define RQ_CTXT_CEQ_ATTR_SET(val, member)	(((val) & RQ_CTXT_CEQ_ATTR_##member##_MASK) << \
						 RQ_CTXT_CEQ_ATTR_##member##_SHIFT)

#define RQ_CTXT_WQ_PAGE_HI_PFN_SHIFT			0
#define RQ_CTXT_WQ_PAGE_WQE_TYPE_SHIFT			28
#define RQ_CTXT_WQ_PAGE_OWNER_SHIFT			31

#define RQ_CTXT_WQ_PAGE_HI_PFN_MASK			0xFFFFFU
#define RQ_CTXT_WQ_PAGE_WQE_TYPE_MASK			0x3U
#define RQ_CTXT_WQ_PAGE_OWNER_MASK			0x1U

#define RQ_CTXT_WQ_PAGE_SET(val, member)	(((val) & RQ_CTXT_WQ_PAGE_##member##_MASK) << \
						 RQ_CTXT_WQ_PAGE_##member##_SHIFT)

#define RQ_CTXT_CQE_LEN_SHIFT				28

#define RQ_CTXT_CQE_LEN_MASK				0x3U

#define RQ_CTXT_CQE_LEN_SET(val, member)	(((val) & RQ_CTXT_##member##_MASK) << \
						 RQ_CTXT_##member##_SHIFT)

#define RQ_CTXT_PREF_CACHE_THRESHOLD_SHIFT		0
#define RQ_CTXT_PREF_CACHE_MAX_SHIFT			14
#define RQ_CTXT_PREF_CACHE_MIN_SHIFT			25

#define RQ_CTXT_PREF_CACHE_THRESHOLD_MASK		0x3FFFU
#define RQ_CTXT_PREF_CACHE_MAX_MASK			0x7FFU
#define RQ_CTXT_PREF_CACHE_MIN_MASK			0x7FU

#define RQ_CTXT_PREF_CI_HI_SHIFT			0
#define RQ_CTXT_PREF_OWNER_SHIFT			4

#define RQ_CTXT_PREF_CI_HI_MASK				0xFU
#define RQ_CTXT_PREF_OWNER_MASK				0x1U

#define RQ_CTXT_PREF_WQ_PFN_HI_SHIFT			0
#define RQ_CTXT_PREF_CI_LOW_SHIFT			20

#define RQ_CTXT_PREF_WQ_PFN_HI_MASK			0xFFFFFU
#define RQ_CTXT_PREF_CI_LOW_MASK			0xFFFU

#define RQ_CTXT_PREF_SET(val, member)		(((val) & RQ_CTXT_PREF_##member##_MASK) << \
						 RQ_CTXT_PREF_##member##_SHIFT)

#define RQ_CTXT_WQ_BLOCK_PFN_HI_SHIFT			0

#define RQ_CTXT_WQ_BLOCK_PFN_HI_MASK			0x7FFFFFU

#define RQ_CTXT_WQ_BLOCK_SET(val, member)	(((val) & RQ_CTXT_WQ_BLOCK_##member##_MASK) << \
						 RQ_CTXT_WQ_BLOCK_##member##_SHIFT)

#define SIZE_16BYTES(size)			(ALIGN((size), 16) >> 4)

#define	WQ_PAGE_PFN_SHIFT				12
#define	WQ_BLOCK_PFN_SHIFT				9

#define WQ_PAGE_PFN(page_addr)		((page_addr) >> WQ_PAGE_PFN_SHIFT)
#define WQ_BLOCK_PFN(page_addr)		((page_addr) >> WQ_BLOCK_PFN_SHIFT)

/* sq and rq */
#define TOTAL_DB_NUM(num_qps)		((u16)(2 * (num_qps)))

int spnic_create_sq(struct spnic_nic_cfg *nic_cfg, struct spnic_io_queue *sq,
		    u16 q_id, u32 sq_depth, u16 sq_msix_idx)
{
	int err;

	/* sq used & hardware request init 1*/
	sq->owner = 1;

	sq->q_id = q_id;
	sq->msix_entry_idx = sq_msix_idx;

	err = sphw_wq_create(nic_cfg->hwdev, &sq->wq, sq_depth, (u16)BIT(SPNIC_SQ_WQEBB_SHIFT));
	if (err) {
		sdk_err(nic_cfg->dev_hdl, "Failed to create tx queue(%u) wq\n",
			q_id);
		return err;
	}

	return 0;
}

void spnic_destroy_sq(struct spnic_nic_cfg *nic_cfg, struct spnic_io_queue *sq)
{
	sphw_wq_destroy(&sq->wq);
}

int spnic_create_rq(struct spnic_nic_cfg *nic_cfg, struct spnic_io_queue *rq,
		    u16 q_id, u32 rq_depth, u16 rq_msix_idx)
{
	int err;

	rq->wqe_type = rq_wqe_type;
	rq->q_id = q_id;
	rq->msix_entry_idx = rq_msix_idx;

	err = sphw_wq_create(nic_cfg->hwdev, &rq->wq, rq_depth,
			     (u16)BIT(SPNIC_RQ_WQEBB_SHIFT + rq_wqe_type));
	if (err) {
		sdk_err(nic_cfg->dev_hdl, "Failed to create rx queue(%u) wq\n",
			q_id);
		return err;
	}

	rq->rx.pi_virt_addr = dma_alloc_coherent(nic_cfg->dev_hdl, PAGE_SIZE,
						 &rq->rx.pi_dma_addr, GFP_KERNEL);
	if (!rq->rx.pi_virt_addr) {
		sphw_wq_destroy(&rq->wq);
		nic_err(nic_cfg->dev_hdl, "Failed to allocate rq pi virt addr\n");
		return -ENOMEM;
	}

	return 0;
}

void spnic_destroy_rq(struct spnic_nic_cfg *nic_cfg, struct spnic_io_queue *rq)
{
	dma_free_coherent(nic_cfg->dev_hdl, PAGE_SIZE, rq->rx.pi_virt_addr,
			  rq->rx.pi_dma_addr);

	sphw_wq_destroy(&rq->wq);
}

static int create_qp(struct spnic_nic_cfg *nic_cfg, struct spnic_io_queue *sq,
		     struct spnic_io_queue *rq, u16 q_id, u32 sq_depth,
		     u32 rq_depth, u16 qp_msix_idx)
{
	int err;

	err = spnic_create_sq(nic_cfg, sq, q_id, sq_depth, qp_msix_idx);
	if (err) {
		nic_err(nic_cfg->dev_hdl, "Failed to create sq, qid: %u\n",
			q_id);
		return err;
	}

	err = spnic_create_rq(nic_cfg, rq, q_id, rq_depth, qp_msix_idx);
	if (err) {
		nic_err(nic_cfg->dev_hdl, "Failed to create rq, qid: %u\n",
			q_id);
		goto create_rq_err;
	}

	return 0;

create_rq_err:
	spnic_destroy_sq(nic_cfg->hwdev, sq);

	return err;
}

void destroy_qp(struct spnic_nic_cfg *nic_cfg, struct spnic_io_queue *sq,
		struct spnic_io_queue *rq)
{
	spnic_destroy_sq(nic_cfg, sq);
	spnic_destroy_rq(nic_cfg, rq);
}

/* try to alloc the expect number of doorbell, and return the actual number
 * of doorbell.
 */
static int spnic_doorbell_change(struct spnic_nic_cfg *nic_cfg, u16 dst_num_db)
{
	void __iomem *db_addr = NULL;
	u16 cur_db_num = nic_cfg->allocated_num_db;
	u16 db_num_gap, idx, i, cur_db_alloc;
	int err;

	if (dst_num_db > nic_cfg->allocated_num_db) {
		db_num_gap = dst_num_db - nic_cfg->allocated_num_db;
		for (idx = 0; idx < db_num_gap; idx++) {
			/* we don't use direct wqe for sq */
			err = sphw_alloc_db_addr(nic_cfg->hwdev, &db_addr, NULL);
			if (err) {
				nic_err(nic_cfg->dev_hdl, "Failed to alloc sq doorbell addr\n");
				goto alloc_db_err;
			}
			nic_cfg->db_addr[cur_db_num + idx] = db_addr;
		}

		nic_cfg->allocated_num_db = dst_num_db;
	} else if (dst_num_db < nic_cfg->allocated_num_db) {
		db_num_gap = nic_cfg->allocated_num_db - dst_num_db;
		for (idx = 0; idx < db_num_gap; idx++) {
			cur_db_alloc = (cur_db_num - idx) - 1;
			sphw_free_db_addr(nic_cfg->hwdev, nic_cfg->db_addr[cur_db_alloc], NULL);
			nic_cfg->db_addr[cur_db_alloc] = NULL;
		}

		nic_cfg->allocated_num_db = dst_num_db;
	}

	return 0;

alloc_db_err:
	for (i = 0; i < idx; i++) {
		sphw_free_db_addr(nic_cfg->hwdev, nic_cfg->db_addr[cur_db_num + i], NULL);
		nic_cfg->db_addr[cur_db_num + i] = NULL;
	}

	return -EFAULT;
}

int spnic_init_nicio_res(void *hwdev)
{
	struct spnic_nic_cfg *nic_cfg = NULL;

	if (!hwdev)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_cfg) {
		pr_err("Failed to get nic service adapter\n");
		return -EFAULT;
	}

	nic_cfg->max_qps = sphw_func_max_qnum(hwdev);

	nic_cfg->allocated_num_db = 0;
	nic_cfg->db_addr = kcalloc(TOTAL_DB_NUM(nic_cfg->max_qps),
				   sizeof(*nic_cfg->db_addr), GFP_KERNEL);
	if (!nic_cfg->db_addr) {
		nic_err(nic_cfg->dev_hdl, "Failed to alloc db addr array\n");
		return -ENOMEM;
	}

	nic_cfg->ci_vaddr_base =
		dma_alloc_coherent(nic_cfg->dev_hdl, CI_TABLE_SIZE(nic_cfg->max_qps, PAGE_SIZE),
				   &nic_cfg->ci_dma_base, GFP_KERNEL);
	if (!nic_cfg->ci_vaddr_base) {
		kfree(nic_cfg->db_addr);
		nic_err(nic_cfg->dev_hdl, "Failed to allocate ci area\n");
		return -ENOMEM;
	}

	return 0;
}

void spnic_deinit_nicio_res(void *hwdev)
{
	struct spnic_nic_cfg *nic_cfg = NULL;

	if (!hwdev)
		return;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_cfg) {
		pr_err("Failed to get nic service adapter\n");
		return;
	}

	dma_free_coherent(nic_cfg->dev_hdl, CI_TABLE_SIZE(nic_cfg->max_qps, PAGE_SIZE),
			  nic_cfg->ci_vaddr_base, nic_cfg->ci_dma_base);
	/* free all doorbell */
	spnic_doorbell_change(nic_cfg, 0);
	kfree(nic_cfg->db_addr);
}

int spnic_alloc_qps(void *hwdev, struct irq_info *qps_msix_arry,
		    struct spnic_dyna_qp_params *qp_params)
{
	struct spnic_io_queue *sqs = NULL;
	struct spnic_io_queue *rqs = NULL;
	struct spnic_nic_cfg *nic_cfg = NULL;
	u16 q_id, i, cur_allocated_db, num_qps;
	int err;

	if (!hwdev || !qps_msix_arry || !qp_params)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_cfg) {
		pr_err("Failed to get nic service adapter\n");
		return -EFAULT;
	}

	if (qp_params->num_qps > nic_cfg->max_qps)
		return -EINVAL;

	num_qps = qp_params->num_qps;

	cur_allocated_db = nic_cfg->allocated_num_db;
	if (cur_allocated_db < TOTAL_DB_NUM(num_qps)) {
		err = spnic_doorbell_change(nic_cfg, TOTAL_DB_NUM(num_qps));
		if (err)
			return err;
	}

	sqs = kcalloc(num_qps, sizeof(*sqs), GFP_KERNEL);
	if (!sqs) {
		nic_err(nic_cfg->dev_hdl, "Failed to allocate sq\n");
		err = -ENOMEM;
		goto alloc_sqs_err;
	}

	rqs = kcalloc(num_qps, sizeof(*rqs), GFP_KERNEL);
	if (!rqs) {
		nic_err(nic_cfg->dev_hdl, "Failed to allocate rq\n");
		err = -ENOMEM;
		goto alloc_rqs_err;
	}

	for (q_id = 0; q_id < num_qps; q_id++) {
		err = create_qp(nic_cfg, &sqs[q_id], &rqs[q_id], q_id,
				qp_params->sq_depth, qp_params->rq_depth,
				qps_msix_arry[q_id].msix_entry_idx);
		if (err) {
			nic_err(nic_cfg->dev_hdl, "Failed to allocate qp %u, err: %d\n",
				q_id, err);
			goto create_qp_err;
		}
	}

	qp_params->sqs = sqs;
	qp_params->rqs = rqs;

	return 0;

create_qp_err:
	for (i = 0; i < q_id; i++)
		destroy_qp(nic_cfg, &sqs[i], &rqs[i]);

	kfree(rqs);

alloc_rqs_err:
	kfree(sqs);

alloc_sqs_err:
	/* Only release the newly added doorbell resource,
	 * the old resource is still in use
	 */
	spnic_doorbell_change(nic_cfg, cur_allocated_db);

	return err;
}

void spnic_free_qps(void *hwdev, struct spnic_dyna_qp_params *qp_params)
{
	struct spnic_nic_cfg *nic_cfg = NULL;
	u16 q_id;

	if (!hwdev || !qp_params)
		return;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_cfg) {
		pr_err("Failed to get nic service adapter\n");
		return;
	}

	for (q_id = 0; q_id < qp_params->num_qps; q_id++)
		destroy_qp(nic_cfg, &qp_params->sqs[q_id],
			   &qp_params->rqs[q_id]);

	kfree(qp_params->sqs);
	kfree(qp_params->rqs);
}

void init_qps_info(struct spnic_nic_cfg *nic_cfg, struct spnic_dyna_qp_params *qp_params)
{
	struct spnic_io_queue *sqs = qp_params->sqs;
	struct spnic_io_queue *rqs = qp_params->rqs;
	u16 q_id;

	nic_cfg->num_qps = qp_params->num_qps;
	nic_cfg->sq = qp_params->sqs;
	nic_cfg->rq = qp_params->rqs;
	for (q_id = 0; q_id < nic_cfg->num_qps; q_id++) {
		sqs[q_id].tx.cons_idx_addr = SPNIC_CI_VADDR(nic_cfg->ci_vaddr_base, q_id);
		/* clear ci value */
		*(u16 *)sqs[q_id].tx.cons_idx_addr = 0;
		sqs[q_id].db_addr = nic_cfg->db_addr[q_id];

		/* The first num_qps doorbell is used by sq */
		rqs[q_id].db_addr = nic_cfg->db_addr[nic_cfg->num_qps + q_id];
	}
}

int spnic_init_qps(void *hwdev, struct spnic_dyna_qp_params *qp_params)
{
	struct spnic_nic_cfg *nic_cfg = NULL;

	if (!hwdev || !qp_params)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_cfg) {
		pr_err("Failed to get nic service adapter\n");
		return -EFAULT;
	}

	if (nic_cfg->allocated_num_db > TOTAL_DB_NUM(qp_params->num_qps))
		spnic_doorbell_change(nic_cfg, TOTAL_DB_NUM(qp_params->num_qps));

	init_qps_info(nic_cfg, qp_params);

	return spnic_init_qp_ctxts(hwdev);
}

void spnic_deinit_qps(void *hwdev, struct spnic_dyna_qp_params *qp_params)
{
	struct spnic_nic_cfg *nic_cfg = NULL;

	if (!hwdev || !qp_params)
		return;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_cfg) {
		pr_err("Failed to get nic service adapter\n");
		return;
	}

	qp_params->sqs = nic_cfg->sq;
	qp_params->rqs = nic_cfg->rq;
	qp_params->num_qps = nic_cfg->num_qps;

	spnic_free_qp_ctxts(hwdev);
}

int spnic_create_qps(void *hwdev, u16 num_qp, u32 sq_depth, u32 rq_depth,
		     struct irq_info *qps_msix_arry)
{
	struct spnic_nic_cfg *nic_cfg = NULL;
	struct spnic_dyna_qp_params qp_params = {0};
	int err;

	if (!hwdev || !qps_msix_arry)
		return -EFAULT;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_cfg) {
		pr_err("Failed to get nic service adapter\n");
		return -EFAULT;
	}

	err = spnic_init_nicio_res(hwdev);
	if (err)
		return err;

	qp_params.num_qps = num_qp;
	qp_params.sq_depth = sq_depth;
	qp_params.rq_depth = rq_depth;
	err = spnic_alloc_qps(hwdev, qps_msix_arry, &qp_params);
	if (err) {
		spnic_deinit_nicio_res(hwdev);
		nic_err(nic_cfg->dev_hdl, "Failed to allocate qps, err: %d\n", err);
		return err;
	}

	init_qps_info(nic_cfg, &qp_params);

	return 0;
}

void spnic_destroy_qps(void *hwdev)
{
	struct spnic_nic_cfg *nic_cfg = NULL;
	struct spnic_dyna_qp_params qp_params =  {0};

	if (!hwdev)
		return;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_cfg)
		return;

	spnic_deinit_qps(hwdev, &qp_params);
	spnic_free_qps(hwdev, &qp_params);
	spnic_deinit_nicio_res(hwdev);
}

void *spnic_get_nic_queue(void *hwdev, u16 q_id, enum spnic_queue_type q_type)
{
	struct spnic_nic_cfg *nic_cfg = NULL;

	if (!hwdev || q_type >= SPNIC_MAX_QUEUE_TYPE)
		return NULL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_cfg)
		return NULL;

	return ((q_type == SPNIC_SQ) ? &nic_cfg->sq[q_id] : &nic_cfg->rq[q_id]);
}

void spnic_qp_prepare_cmdq_header(struct spnic_qp_ctxt_header *qp_ctxt_hdr,
				  enum spnic_qp_ctxt_type ctxt_type,
				  u16 num_queues, u16 q_id)
{
	qp_ctxt_hdr->queue_type = ctxt_type;
	qp_ctxt_hdr->num_queues = num_queues;
	qp_ctxt_hdr->start_qid = q_id;
	qp_ctxt_hdr->rsvd = 0;

	sphw_cpu_to_be32(qp_ctxt_hdr, sizeof(*qp_ctxt_hdr));
}

void spnic_sq_prepare_ctxt(struct spnic_io_queue *sq, u16 sq_id, struct spnic_sq_ctxt *sq_ctxt)
{
	u64 wq_page_addr;
	u64 wq_page_pfn, wq_block_pfn;
	u32 wq_page_pfn_hi, wq_page_pfn_lo;
	u32 wq_block_pfn_hi, wq_block_pfn_lo;
	u16 pi_start, ci_start;

	ci_start = spnic_get_sq_local_ci(sq);
	pi_start = spnic_get_sq_local_pi(sq);

	wq_page_addr = sphw_wq_get_first_wqe_page_addr(&sq->wq);

	wq_page_pfn = WQ_PAGE_PFN(wq_page_addr);
	wq_page_pfn_hi = upper_32_bits(wq_page_pfn);
	wq_page_pfn_lo = lower_32_bits(wq_page_pfn);

	wq_block_pfn = WQ_BLOCK_PFN(sq->wq.wq_block_paddr);
	wq_block_pfn_hi = upper_32_bits(wq_block_pfn);
	wq_block_pfn_lo = lower_32_bits(wq_block_pfn);

	sq_ctxt->ci_pi =
		SQ_CTXT_CI_PI_SET(ci_start, CI_IDX) |
		SQ_CTXT_CI_PI_SET(pi_start, PI_IDX);

	sq_ctxt->drop_mode_sp =
		SQ_CTXT_MODE_SET(0, SP_FLAG) |
		SQ_CTXT_MODE_SET(0, PKT_DROP);

	sq_ctxt->wq_pfn_hi_owner =
			SQ_CTXT_WQ_PAGE_SET(wq_page_pfn_hi, HI_PFN) |
			SQ_CTXT_WQ_PAGE_SET(1, OWNER);

	sq_ctxt->wq_pfn_lo = wq_page_pfn_lo;

	/* TO DO */
	sq_ctxt->pkt_drop_thd =
		SQ_CTXT_PKT_DROP_THD_SET(tx_drop_thd_on, THD_ON) |
		SQ_CTXT_PKT_DROP_THD_SET(tx_drop_thd_off, THD_OFF);

	sq_ctxt->global_sq_id =
		SQ_CTXT_GLOBAL_QUEUE_ID_SET(sq_id, GLOBAL_SQ_ID);

	/* enable insert c-vlan in default */
	sq_ctxt->vlan_ceq_attr =
		SQ_CTXT_VLAN_CEQ_SET(0, CEQ_EN) |
		SQ_CTXT_VLAN_CEQ_SET(1, INSERT_MODE);

	sq_ctxt->rsvd0 = 0;

	sq_ctxt->pref_cache =
		SQ_CTXT_PREF_SET(WQ_PREFETCH_MIN, CACHE_MIN) |
		SQ_CTXT_PREF_SET(WQ_PREFETCH_MAX, CACHE_MAX) |
		SQ_CTXT_PREF_SET(WQ_PREFETCH_THRESHOLD, CACHE_THRESHOLD);

	sq_ctxt->pref_ci_owner =
		SQ_CTXT_PREF_SET(CI_HIGN_IDX(ci_start), CI_HI) |
		SQ_CTXT_PREF_SET(1, OWNER);

	sq_ctxt->pref_wq_pfn_hi_ci =
		SQ_CTXT_PREF_SET(ci_start, CI_LOW) |
		SQ_CTXT_PREF_SET(wq_page_pfn_hi, WQ_PFN_HI);

	sq_ctxt->pref_wq_pfn_lo = wq_page_pfn_lo;

	sq_ctxt->wq_block_pfn_hi = SQ_CTXT_WQ_BLOCK_SET(wq_block_pfn_hi, PFN_HI);

	sq_ctxt->wq_block_pfn_lo = wq_block_pfn_lo;

	sphw_cpu_to_be32(sq_ctxt, sizeof(*sq_ctxt));
}

void spnic_rq_prepare_ctxt(struct spnic_io_queue *rq, struct spnic_rq_ctxt *rq_ctxt)
{
	u64 wq_page_addr;
	u64 wq_page_pfn, wq_block_pfn;
	u32 wq_page_pfn_hi, wq_page_pfn_lo;
	u32 wq_block_pfn_hi, wq_block_pfn_lo;
	u16 pi_start, ci_start;
	u16 wqe_type = rq->wqe_type;

	/* RQ depth is in unit of 8Bytes */
	ci_start = (u16)((u32)spnic_get_rq_local_ci(rq) << wqe_type);
	pi_start = (u16)((u32)spnic_get_rq_local_pi(rq) << wqe_type);

	wq_page_addr = sphw_wq_get_first_wqe_page_addr(&rq->wq);

	wq_page_pfn = WQ_PAGE_PFN(wq_page_addr);
	wq_page_pfn_hi = upper_32_bits(wq_page_pfn);
	wq_page_pfn_lo = lower_32_bits(wq_page_pfn);

	wq_block_pfn = WQ_BLOCK_PFN(rq->wq.wq_block_paddr);
	wq_block_pfn_hi = upper_32_bits(wq_block_pfn);
	wq_block_pfn_lo = lower_32_bits(wq_block_pfn);

	rq_ctxt->ci_pi =
		RQ_CTXT_CI_PI_SET(ci_start, CI_IDX) |
		RQ_CTXT_CI_PI_SET(pi_start, PI_IDX);

	rq_ctxt->ceq_attr = RQ_CTXT_CEQ_ATTR_SET(0, EN) |
			    RQ_CTXT_CEQ_ATTR_SET(rq->msix_entry_idx, INTR);

	rq_ctxt->wq_pfn_hi_type_owner =
		RQ_CTXT_WQ_PAGE_SET(wq_page_pfn_hi, HI_PFN) |
		RQ_CTXT_WQ_PAGE_SET(1, OWNER);

	switch (wqe_type) {
	case SPNIC_EXTEND_RQ_WQE:
		/* use 32Byte WQE with SGE for CQE */
		rq_ctxt->wq_pfn_hi_type_owner |= RQ_CTXT_WQ_PAGE_SET(0, WQE_TYPE);
		break;
	case SPNIC_NORMAL_RQ_WQE:
		/* use 16Byte WQE with 32Bytes SGE for CQE */
		rq_ctxt->wq_pfn_hi_type_owner |= RQ_CTXT_WQ_PAGE_SET(2, WQE_TYPE);
		rq_ctxt->cqe_sge_len = RQ_CTXT_CQE_LEN_SET(1, CQE_LEN);
		break;
	default:
		pr_err("Invalid rq wqe type: %u", wqe_type);
	}

	rq_ctxt->wq_pfn_lo = wq_page_pfn_lo;

	rq_ctxt->pref_cache =
		RQ_CTXT_PREF_SET(WQ_PREFETCH_MIN, CACHE_MIN) |
		RQ_CTXT_PREF_SET(WQ_PREFETCH_MAX, CACHE_MAX) |
		RQ_CTXT_PREF_SET(WQ_PREFETCH_THRESHOLD, CACHE_THRESHOLD);

	rq_ctxt->pref_ci_owner =
		RQ_CTXT_PREF_SET(CI_HIGN_IDX(ci_start), CI_HI) |
		RQ_CTXT_PREF_SET(1, OWNER);

	rq_ctxt->pref_wq_pfn_hi_ci =
		RQ_CTXT_PREF_SET(wq_page_pfn_hi, WQ_PFN_HI) |
		RQ_CTXT_PREF_SET(ci_start, CI_LOW);

	rq_ctxt->pref_wq_pfn_lo = wq_page_pfn_lo;

	rq_ctxt->pi_paddr_hi = upper_32_bits(rq->rx.pi_dma_addr);
	rq_ctxt->pi_paddr_lo = lower_32_bits(rq->rx.pi_dma_addr);

	rq_ctxt->wq_block_pfn_hi = RQ_CTXT_WQ_BLOCK_SET(wq_block_pfn_hi, PFN_HI);

	rq_ctxt->wq_block_pfn_lo = wq_block_pfn_lo;

	sphw_cpu_to_be32(rq_ctxt, sizeof(*rq_ctxt));
}

static int init_sq_ctxts(struct spnic_nic_cfg *nic_cfg)
{
	struct spnic_sq_ctxt_block *sq_ctxt_block = NULL;
	struct spnic_sq_ctxt *sq_ctxt = NULL;
	struct sphw_cmd_buf *cmd_buf = NULL;
	struct spnic_io_queue *sq = NULL;
	u64 out_param = 0;
	u16 q_id, curr_id, max_ctxts, i;
	int err = 0;

	cmd_buf = sphw_alloc_cmd_buf(nic_cfg->hwdev);
	if (!cmd_buf) {
		nic_err(nic_cfg->dev_hdl, "Failed to allocate cmd buf\n");
		return -ENOMEM;
	}

	q_id = 0;
	while (q_id < nic_cfg->num_qps) {
		sq_ctxt_block = cmd_buf->buf;
		sq_ctxt = sq_ctxt_block->sq_ctxt;

		max_ctxts = (nic_cfg->num_qps - q_id) > SPNIC_Q_CTXT_MAX ?
			     SPNIC_Q_CTXT_MAX : (nic_cfg->num_qps - q_id);

		spnic_qp_prepare_cmdq_header(&sq_ctxt_block->cmdq_hdr, SPNIC_QP_CTXT_TYPE_SQ,
					     max_ctxts, q_id);

		for (i = 0; i < max_ctxts; i++) {
			curr_id = q_id + i;
			sq = &nic_cfg->sq[curr_id];

			spnic_sq_prepare_ctxt(sq, curr_id, &sq_ctxt[i]);
		}

		cmd_buf->size = SQ_CTXT_SIZE(max_ctxts);

		err = sphw_cmdq_direct_resp(nic_cfg->hwdev, SPHW_MOD_L2NIC,
					    SPNIC_UCODE_CMD_MODIFY_QUEUE_CTX,
					    cmd_buf, &out_param, 0, SPHW_CHANNEL_NIC);
		if (err || out_param != 0) {
			nic_err(nic_cfg->dev_hdl, "Failed to set SQ ctxts, err: %d, out_param: 0x%llx\n",
				err, out_param);

			err = -EFAULT;
			break;
		}

		q_id += max_ctxts;
	}

	sphw_free_cmd_buf(nic_cfg->hwdev, cmd_buf);

	return err;
}

static int init_rq_ctxts(struct spnic_nic_cfg *nic_cfg)
{
	struct spnic_rq_ctxt_block *rq_ctxt_block = NULL;
	struct spnic_rq_ctxt *rq_ctxt = NULL;
	struct sphw_cmd_buf *cmd_buf = NULL;
	struct spnic_io_queue *rq = NULL;
	u64 out_param = 0;
	u16 q_id, curr_id, max_ctxts, i;
	int err = 0;

	cmd_buf = sphw_alloc_cmd_buf(nic_cfg->hwdev);
	if (!cmd_buf) {
		nic_err(nic_cfg->dev_hdl, "Failed to allocate cmd buf\n");
		return -ENOMEM;
	}

	q_id = 0;
	while (q_id < nic_cfg->num_qps) {
		rq_ctxt_block = cmd_buf->buf;
		rq_ctxt = rq_ctxt_block->rq_ctxt;

		max_ctxts = (nic_cfg->num_qps - q_id) > SPNIC_Q_CTXT_MAX ?
				SPNIC_Q_CTXT_MAX : (nic_cfg->num_qps - q_id);

		spnic_qp_prepare_cmdq_header(&rq_ctxt_block->cmdq_hdr, SPNIC_QP_CTXT_TYPE_RQ,
					     max_ctxts, q_id);

		for (i = 0; i < max_ctxts; i++) {
			curr_id = q_id + i;
			rq = &nic_cfg->rq[curr_id];

			spnic_rq_prepare_ctxt(rq, &rq_ctxt[i]);
		}

		cmd_buf->size = RQ_CTXT_SIZE(max_ctxts);

		err = sphw_cmdq_direct_resp(nic_cfg->hwdev, SPHW_MOD_L2NIC,
					    SPNIC_UCODE_CMD_MODIFY_QUEUE_CTX,
					    cmd_buf, &out_param, 0, SPHW_CHANNEL_NIC);

		if (err || out_param != 0) {
			nic_err(nic_cfg->dev_hdl, "Failed to set RQ ctxts, err: %d, out_param: 0x%llx\n",
				err, out_param);

			err = -EFAULT;
			break;
		}

		q_id += max_ctxts;
	}

	sphw_free_cmd_buf(nic_cfg->hwdev, cmd_buf);

	return err;
}

static int init_qp_ctxts(struct spnic_nic_cfg *nic_cfg)
{
	int err;

	err = init_sq_ctxts(nic_cfg);
	if (err)
		return err;

	err = init_rq_ctxts(nic_cfg);
	if (err)
		return err;

	return 0;
}

static int clean_queue_offload_ctxt(struct spnic_nic_cfg *nic_cfg,
				    enum spnic_qp_ctxt_type ctxt_type)
{
	struct spnic_clean_queue_ctxt *ctxt_block = NULL;
	struct sphw_cmd_buf *cmd_buf = NULL;
	u64 out_param = 0;
	int err;

	cmd_buf = sphw_alloc_cmd_buf(nic_cfg->hwdev);
	if (!cmd_buf) {
		nic_err(nic_cfg->dev_hdl, "Failed to allocate cmd buf\n");
		return -ENOMEM;
	}

	ctxt_block = cmd_buf->buf;
	ctxt_block->cmdq_hdr.num_queues = nic_cfg->max_qps;
	ctxt_block->cmdq_hdr.queue_type = ctxt_type;
	ctxt_block->cmdq_hdr.start_qid = 0;

	sphw_cpu_to_be32(ctxt_block, sizeof(*ctxt_block));

	cmd_buf->size = sizeof(*ctxt_block);

	err = sphw_cmdq_direct_resp(nic_cfg->hwdev, SPHW_MOD_L2NIC,
				    SPNIC_UCODE_CMD_CLEAN_QUEUE_CONTEXT,
				    cmd_buf, &out_param, 0, SPHW_CHANNEL_NIC);

	if ((err) || (out_param)) {
		nic_err(nic_cfg->dev_hdl, "Failed to clean queue offload ctxts, err: %d,out_param: 0x%llx\n",
			err, out_param);

		err = -EFAULT;
	}

	sphw_free_cmd_buf(nic_cfg->hwdev, cmd_buf);

	return err;
}

static int clean_qp_offload_ctxt(struct spnic_nic_cfg *nic_cfg)
{
	/* clean LRO/TSO context space */
	return (clean_queue_offload_ctxt(nic_cfg, SPNIC_QP_CTXT_TYPE_SQ) ||
		clean_queue_offload_ctxt(nic_cfg, SPNIC_QP_CTXT_TYPE_RQ));
}

/* init qps ctxt and set sq ci attr and arm all sq*/
int spnic_init_qp_ctxts(void *hwdev)
{
	struct spnic_nic_cfg *nic_cfg = NULL;
	struct spnic_sq_attr sq_attr;
	u32 rq_depth;
	u16 q_id;
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_cfg)
		return -EFAULT;

	err = init_qp_ctxts(nic_cfg);
	if (err) {
		nic_err(nic_cfg->dev_hdl, "Failed to init QP ctxts\n");
		return err;
	}

	/* clean LRO/TSO context space */
	err = clean_qp_offload_ctxt(nic_cfg);
	if (err) {
		nic_err(nic_cfg->dev_hdl, "Failed to clean qp offload ctxts\n");
		return err;
	}

	rq_depth = nic_cfg->rq[0].wq.q_depth << nic_cfg->rq[0].wqe_type;

	err = sphw_set_root_ctxt(hwdev, rq_depth, nic_cfg->sq[0].wq.q_depth,
				 nic_cfg->rx_buff_len, SPHW_CHANNEL_NIC);
	if (err) {
		nic_err(nic_cfg->dev_hdl, "Failed to set root context\n");
		return err;
	}

	for (q_id = 0; q_id < nic_cfg->num_qps; q_id++) {
		sq_attr.ci_dma_base = SPNIC_CI_PADDR(nic_cfg->ci_dma_base, q_id) >> 2;
		sq_attr.pending_limit = tx_pending_limit;
		sq_attr.coalescing_time = tx_coalescing_time;
		sq_attr.intr_en = 1;
		sq_attr.intr_idx = nic_cfg->sq[q_id].msix_entry_idx;
		sq_attr.l2nic_sqn = q_id;
		sq_attr.dma_attr_off = 0;
		err = spnic_set_ci_table(hwdev, &sq_attr);
		if (err) {
			nic_err(nic_cfg->dev_hdl, "Failed to set ci table\n");
			goto set_cons_idx_table_err;
		}
	}

	return 0;

set_cons_idx_table_err:
	sphw_clean_root_ctxt(hwdev, SPHW_CHANNEL_NIC);

	return err;
}

void spnic_free_qp_ctxts(void *hwdev)
{
	if (!hwdev)
		return;

	sphw_clean_root_ctxt(hwdev, SPHW_CHANNEL_NIC);
}

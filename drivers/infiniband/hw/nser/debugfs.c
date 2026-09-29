// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/list.h>

#include "main.h"

#ifdef CONFIG_DEBUG_FS
static const char nser_driver_name[] = "nser";
static struct dentry *nser_dbg_root;
static char cmd_buf[64];

/* QP subcommand */
#define QP_ACTIVE               1
#define QP_INFO                 2
#define QP_HOST_CTX             4
#define QP_CHIP_CTX             5
#define QP_CHIP_RAW             6
#define QP_CHIP_REG		7

#define DUMP_HMC_INFO           1
#define DUMP_HMC_INDEXES        2
#define DUMP_HMC_OBJ_INFO       4
#define DUMP_HMC_SD             8
#define DUMP_HMC_ALL            0xf

#define OFFSET_MASK_4K          0x0000000000000fffl

static char *nser_dbg_dump_buf;
static size_t nser_dbg_dump_data_len;
static size_t nser_dbg_dump_buf_len;
static u32 cmdnew;
static u32 cmddone;
#define BUF_ADDR_SIZE 17	/* address plus space */
#define BUF_DATA_ASCII_SIZE (32 * 3 + 2 + 32 + 1)	/* data plus ASCII */
#define NSER_DUMP_BUF_SIZE             16384
#define NSER_DUMP_BUF_HALF_FULL        (NSER_DUMP_BUF_SIZE / 2)

struct hmc_find {
	dma_addr_t paddr;
	bool fnd;
	dma_addr_t bp_pa;
	bool in_vf;
	u32 vf_id;
	int sd_indx;
	bool paged;
	bool in_pd_itself;
	int pd_indx;
	u64 hmc_addr;
	bool obj_info_fnd;
	enum nser_hmc_rsrc_type obj_type;
	int obj_indx;
};

/**
 * dbg_vsnprintf -
 * @fmt: print formatting string
 */
static void dbg_vsnprintf(char *fmt, ...) __printf(1, 2);
static void dbg_vsnprintf(char *fmt, ...)
{
	int cnt;
	va_list argp;

	va_start(argp, fmt);
	cnt = vsnprintf(nser_dbg_dump_buf + nser_dbg_dump_data_len,
			nser_dbg_dump_buf_len - nser_dbg_dump_data_len,
			fmt, argp);
	va_end(argp);

	nser_dbg_dump_data_len += cnt;
}

/**
 * dump_help -
 */
static void dump_help(void)
{
	dbg_vsnprintf("Dump commands:\n");
	dbg_vsnprintf(" qp <n> active           <n> is a qp number or 'all'\n");
	dbg_vsnprintf(" qp <n> info\n");
	dbg_vsnprintf(" cq <n>                  <n> is a cq number or 'all'\n");
	dbg_vsnprintf(" qp <n> chip_ctx\n");
	dbg_vsnprintf(" qp <n> chip_raw\n");
	dbg_vsnprintf(" sw-stats\n");
	dbg_vsnprintf(" hw-stats\n");
	cmddone = true;
}

/**
 * nser_dbg_save_ucontext -
 * @iwdev: device
 * @ucontext: user context
 */
void nser_dbg_save_ucontext(struct nser_device *iwdev,
			     struct nser_ucontext *ucontext)
{
	struct nser_handler *hdl;
	unsigned long flags;

	hdl = iwdev->hdl;

	spin_lock_irqsave(&hdl->uctx_list_lock, flags);
	list_add_tail(&ucontext->uctx_list, &hdl->ucontext_list);
	spin_unlock_irqrestore(&hdl->uctx_list_lock, flags);
}

/**
 * nser_dbg_free_ucontext -
 * @ucontext: user context
 */
void nser_dbg_free_ucontext(struct nser_ucontext *ucontext)
{
	struct nser_handler *hdl;
	unsigned long flags;

	hdl = ucontext->iwdev->hdl;

	spin_lock_irqsave(&hdl->uctx_list_lock, flags);
	list_del(&ucontext->uctx_list);
	spin_unlock_irqrestore(&hdl->uctx_list_lock, flags);
}

/**
 * find_next_rsrc - Find next free resource ID
 * @rf: RDMA PCI function
 * @rsrc_array: resource array
 * @max_rsrc: max num resources
 * @next: next id to search
 */
static int find_next_rsrc(struct nser_pci_f *rf,
			      unsigned long *rsrc_array,
			      u32 max_rsrc,
			      u32 next)
{
	u32 rsrc_num;
	unsigned long flags;

	spin_lock_irqsave(&rf->rsrc_lock, flags);
	rsrc_num = find_next_bit(rsrc_array, max_rsrc, next);
	spin_unlock_irqrestore(&rf->rsrc_lock, flags);
	return (rsrc_num < max_rsrc) ? rsrc_num : -2;
}

/**
 * find_next_qp_num -
 * @rf: RDMA PCI function
 * @qp_id: QP ID
 */
static int find_next_qp_num(struct nser_pci_f *rf, int qp_id)
{
	do {
		++qp_id;
		if ((qp_id == 0) || (qp_id == 1))
			qp_id = 2;
		qp_id = find_next_rsrc(rf, rf->allocated_qps,
					   rf->max_qp, qp_id);
		if (qp_id < 0)
			break;
	} while (!rf->qp_table[qp_id]);

	return qp_id;
}

/**
 * find_next_cq_num -
 * @rf: RDMA PCI function
 * @cq_id: CQ ID
 */
static long find_next_cq_num(struct nser_pci_f *rf, long cq_id)
{
	do {
		++cq_id;
		if (cq_id < 3 || cq_id > NSER_MAX_CQID)
			cq_id = 3;
		cq_id = find_next_rsrc(rf, rf->allocated_cqs,
				       rf->max_cq, cq_id);
		if (cq_id < 0)
			break;

	} while (!rf->cq_table[cq_id]);

	return cq_id;
}

/**
 * dump_qp_shared -
 * @qp: QP pointer
 */
static void dump_qp_shared(struct nser_qp *qp)
{
	struct nser_sc_qp *qpsh = &qp->sc_qp;
	struct nser_qp_uk *qpuk = &qpsh->qp_uk;

	dbg_vsnprintf("      sq_ring.head: 0x%x tail: 0x%x size: 0x%x\n",
		      qpuk->sq_ring.head, qpuk->sq_ring.tail,
		      qpuk->sq_ring.size);
	dbg_vsnprintf("      rq_ring.head: 0x%x tail: 0x%x size: 0x%x\n",
		      qpuk->rq_ring.head, qpuk->rq_ring.tail,
		      qpuk->rq_ring.size);
	dbg_vsnprintf("      qp_id: 0x%x\n", qpuk->qp_id);
	dbg_vsnprintf("      sq_size: 0x%x\n", qpuk->sq_size);
	dbg_vsnprintf("      rq_size: 0x%x\n", qpuk->rq_size);
	dbg_vsnprintf("      swqe_polarity: 0x%x\n", qpuk->swqe_polarity);
	dbg_vsnprintf("      rwqe_polarity: 0x%x\n", qpuk->rwqe_polarity);
	dbg_vsnprintf("      rq_wqe_size: 0x%x\n", qpuk->rq_wqe_size);
	dbg_vsnprintf("      rq_wqe_size_multiplier: 0x%x\n",
		      qpuk->rq_wqe_size_multiplier);
	dbg_vsnprintf("      max_sq_frag_cnt: 0x%x\n", qpuk->max_sq_frag_cnt);
	dbg_vsnprintf("      max_rq_frag_cnt: 0x%x\n", qpuk->max_rq_frag_cnt);

	dbg_vsnprintf("    qs_handle: 0x%x\n", qpsh->qs_handle);
	dbg_vsnprintf("    sq_tph_val: 0x%x\n", qpsh->sq_tph_val);
	dbg_vsnprintf("    rq_tph_val: 0x%x\n", qpsh->rq_tph_val);
	dbg_vsnprintf("    sq_tph_en: 0x%x\n", qpsh->sq_tph_en);
	dbg_vsnprintf("    rq_tph_en: 0x%x\n", qpsh->rq_tph_en);
	dbg_vsnprintf("    rcv_tph_en: 0x%x\n", qpsh->rcv_tph_en);
	dbg_vsnprintf("    xmit_tph_en: 0x%x\n", qpsh->xmit_tph_en);

	dbg_vsnprintf("    virtual_map: 0x%x\n", qpsh->virtual_map);
	dbg_vsnprintf("    flush_sq: 0x%x\n", qpsh->flush_sq);
	dbg_vsnprintf("    flush_rq: 0x%x\n", qpsh->flush_rq);
	dbg_vsnprintf("    qp_type: 0x%x\n", qpsh->qp_uk.qp_type);
	dbg_vsnprintf("    hw_sq_size: 0x%x\n", qpsh->hw_sq_size);
	dbg_vsnprintf("    hw_rq_size: 0x%x\n", qpsh->hw_rq_size);
}

/**
 * dump_qp_info -
 * @qp: QP pointer
 */
static void dump_qp_info(struct nser_qp *qp)
{
	dbg_vsnprintf("struct nser_qp\n");

	dump_qp_shared(qp);

	dbg_vsnprintf("  refcount: 0x%x\n", refcount_read(&qp->refcnt));
	dbg_vsnprintf("  ibqp_state: 0x%x\n", qp->ibqp_state);
	dbg_vsnprintf("  rdma_state: 0x%x\n", qp->rdma_state);
	dbg_vsnprintf("  qp_mem_size: 0x%x\n", qp->qp_mem_size);
	dbg_vsnprintf("  last_aeq: 0x%x\n", qp->last_aeq);
	dbg_vsnprintf("  qp_mem_size: 0x%x\n", qp->qp_mem_size);
	dbg_vsnprintf("  user_mode: %d\n", qp->user_mode);
	dbg_vsnprintf("  flush_issued: %d\n", qp->flush_issued);
	dbg_vsnprintf("  destroy_pending: %d\n", qp->sc_qp.qp_uk.destroy_pending);
	dbg_vsnprintf("  sig_all: %d\n", qp->sig_all);
	dbg_vsnprintf("  pau_mode: %d\n", qp->pau_mode);
	dbg_vsnprintf("  hw_rdma_state: %d\n", qp->hw_rdma_state);
}

/**
 * dump_qp -
 * @rf: RDMA PCI function
 * @qp_id: QP ID
 * @subtype: QP info type
 */
static void dump_qp(struct nser_pci_f *rf, u32 qp_id, u32 subtype)
{
	struct nser_qp *iwqp = NULL;

	if ((qp_id >= 2) && (qp_id < rf->max_qp))
		iwqp = rf->qp_table[qp_id];

	if (!iwqp) {
		dbg_vsnprintf("QP %d is not valid\n", qp_id);
		return;
	}

	dbg_vsnprintf("QP %d ibqp_state=0x%x warp_state=0x%x\n", qp_id,
		      iwqp->ibqp_state, iwqp->rdma_state);

	switch (subtype) {
	case QP_INFO:
		dump_qp_info(iwqp);
		break;
	case QP_CHIP_CTX:
		dbg_vsnprintf
		    ("QP %d context will be dumped to /var/log/messages\n",
		     qp_id);
		nser_upload_qp_context(iwqp, 0, 0);
		break;
	case QP_CHIP_RAW:
		dbg_vsnprintf
		    ("QP %d context will be dumped using regs (no CQP ops) to /var/log/messages\n",
		     qp_id);
		nser_upload_qp_context(iwqp, 0, 1);
		break;
	case QP_ACTIVE:
		if (!iwqp->user_mode) {
			unsigned long flags;

			spin_lock_irqsave(&iwqp->lock, flags);
			nser_print_sq_wqes(&iwqp->sc_qp.qp_uk);
			spin_unlock_irqrestore(&iwqp->lock, flags);
		}
		break;
	}
}

/**
 * dump_qp_cmd -
 * @rf: RDMA PCI function
 * @cbuf: character buffer to dump to
 */
static void dump_qp_cmd(struct nser_pci_f *rf, char *cbuf)
{
	static int qp_id;
	static u32 all;
	static u32 subtype = QP_ACTIVE;
	char stype[9];
	char qpstr[11];
	int offset;
	int rc;

	if (cmdnew) {
		if (sscanf(cbuf, "%10s%n", qpstr, &offset) == 0)
			return;

		if (strncasecmp(qpstr, "all", 3) == 0) {
			all = true;
			qp_id = find_next_qp_num(rf, -1);
		} else {
			all = false;
			rc = kstrtoul(qpstr, 10, (long *)&qp_id);
			if (rc)
				return;

			if ((qp_id == 0) || (qp_id == 1))
				qp_id = -1;
		}

		if (sscanf(cbuf + offset, "%8s", stype) == 1) {
			if (strncasecmp(stype, "active", 6) == 0)
				subtype = QP_ACTIVE;
			if (strncasecmp(stype, "info", 5) == 0)
				subtype = QP_INFO;
			else if (strncasecmp(stype, "chip_ctx", 8) == 0)
				subtype = QP_CHIP_CTX;
			else if (strncasecmp(stype, "chip_raw", 8) == 0)
				subtype = QP_CHIP_RAW;
			else if (strncasecmp(stype, "chip_reg", 8) == 0)
				subtype = QP_CHIP_REG;
		}
	} else {
		if (!all)
			return;

		qp_id = find_next_qp_num(rf, qp_id);
	}

	if (qp_id >= 0)
		dump_qp(rf, qp_id, subtype);
	else
		cmddone = true;
}

/**
 * dump_cq_cmd -
 * @rf: RDMA PCI function
 * @cbuf: character buffer to read the cmd from
 */
static void dump_cq_cmd(struct nser_pci_f *rf, const char *cbuf)
{
	static long cq_id;
	static bool all;
	char cqstr[11];
	int offset;
	int rc;

	if (cmdnew) {
		if (sscanf(cbuf, "%10s%n", cqstr, &offset) == 0)
			return;

		if (strncasecmp(cqstr, "all", 3) == 0) {
			all = true;
			cq_id = find_next_cq_num(rf, 1);
		} else {
			all = false;
			rc = kstrtoul(cqstr, 0, &cq_id);
			if (rc)
				return;

			if (cq_id < 3 || cq_id > NSER_MAX_CQID) {
				dbg_vsnprintf("CQ %ld is not valid\n", cq_id);
				return;
			}
		}
	} else {
		if (!all)
			return;

		cq_id = find_next_cq_num(rf, cq_id);
	}

	if (cq_id > 2) {
		struct nser_cq *iwcq = rf->cq_table[cq_id];

		if (iwcq && !iwcq->user_mode) {
			unsigned long flags;

			spin_lock_irqsave(&iwcq->lock, flags);
			nser_print_cqes(&iwcq->sc_cq.cq_uk);
			spin_unlock_irqrestore(&iwcq->lock, flags);
		}
	} else {
		cmddone = true;
	}
}

/**
 * dump_stats_cmd - Dump statistics
 * @iwdev: device
 */
static void dump_stats_cmd(struct nser_device *iwdev)
{
	struct nser_sc_dev *dev = &iwdev->rf->sc_dev;
	struct nser_hmc_pble_rsrc *pble = iwdev->rf->pble_rsrc;

	dbg_vsnprintf("pble direct sds                  %d\n",
		      pble->stats_direct_sds);
	dbg_vsnprintf("pble paged sds                   %d\n",
		      pble->stats_paged_sds);
	dbg_vsnprintf("pble alloc ok                    %lld\n",
		      pble->stats_alloc_ok);
	dbg_vsnprintf("pble alloc fail                  %lld\n",
		      pble->stats_alloc_fail);
	dbg_vsnprintf("pble alloc freed                 %lld\n",
		      pble->stats_alloc_freed);
	dbg_vsnprintf("pble lvl1 alloc                  %lld\n",
		      pble->stats_lvl1);
	dbg_vsnprintf("pble lvl2 alloc                  %lld\n",
		      pble->stats_lvl2);
	dbg_vsnprintf("cqp OP_QP_CREATE                 %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_QP_CREATE]);
	dbg_vsnprintf("cqp OP_QP_MODIFY                 %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_QP_MODIFY]);
	dbg_vsnprintf("cqp OP_QP_DESTROY                %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_QP_DESTROY]);
	dbg_vsnprintf("cqp OP_CQ_CREATE                 %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_CQ_CREATE]);
	dbg_vsnprintf("cqp OP_CQ_DESTROY                %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_CQ_DESTROY]);
	dbg_vsnprintf("cqp OP_ALLOC_STAG                %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_ALLOC_STAG]);
	dbg_vsnprintf("cqp OP_MR_REG_NON_SHARED         %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_MR_REG_NON_SHARED]);
	dbg_vsnprintf("cqp OP_DEALLOC_STAG              %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_DEALLOC_STAG]);
	dbg_vsnprintf("cqp OP_ADD_ARP_CACHE_ENTRY       %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_ADD_ARP_CACHE_ENTRY]);
	dbg_vsnprintf("cqp OP_DELETE_ARP_CACHE_ENTRY    %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_DELETE_ARP_CACHE_ENTRY]);
	dbg_vsnprintf("cqp OP_CEQ_DESTROY               %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_CEQ_DESTROY]);
	dbg_vsnprintf("cqp OP_AEQ_DESTROY               %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_AEQ_DESTROY]);
	dbg_vsnprintf("cqp OP_MANAGE_APBVT_ENTRY        %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_MANAGE_APBVT_ENTRY]);
	dbg_vsnprintf("cqp OP_CEQ_CREATE                %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_CEQ_CREATE]);
	dbg_vsnprintf("cqp OP_AEQ_CREATE                %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_AEQ_CREATE]);
	dbg_vsnprintf("cqp OP_QP_UPLOAD_CONTEXT         %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_QP_UPLOAD_CONTEXT]);
	dbg_vsnprintf("cqp OP_MW_ALLOC                  %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_MW_ALLOC]);
	dbg_vsnprintf("cqp OP_QP_FLUSH_WQES             %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_QP_FLUSH_WQES]);
	dbg_vsnprintf("cqp OP_MANAGE_PUSH_PAGE          %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_MANAGE_PUSH_PAGE]);
	dbg_vsnprintf("cqp OP_QUERY_RDMA_FEATURES       %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_QUERY_RDMA_FEATURES]);
	dbg_vsnprintf("cqp OP_UPDATE_PE_SDS             %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_UPDATE_PE_SDS]);
	dbg_vsnprintf("cqp OP_MANAGE_HMC_PM_FUNC_TABLE  %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_MANAGE_HMC_PM_FUNC_TABLE]);
	dbg_vsnprintf("cqp OP_SUSPEND                   %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_SUSPEND]);
	dbg_vsnprintf("cqp OP_RESUME                    %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_RESUME]);
	dbg_vsnprintf("cqp OP_MANAGE_VF_PBLE_BP         %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_MANAGE_VF_PBLE_BP]);
	dbg_vsnprintf("cqp OP_QUERY_FPM_VAL          %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_QUERY_FPM_VAL]);
	dbg_vsnprintf("cqp OP_MANAGE_QHASH_TABLE_ENTRY  %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_MANAGE_QHASH_TABLE_ENTRY]);
	dbg_vsnprintf("cqp OP_AH_CREATE  %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_AH_CREATE]);
	dbg_vsnprintf("AH Reused Count   %lld\n",
		      iwdev->ah_reused);
	dbg_vsnprintf("AH Current List Count  %d\n",
		      iwdev->ah_list_cnt);
	dbg_vsnprintf("AH list cnt HWM   %d\n",
		      iwdev->ah_list_hwm);
	dbg_vsnprintf("cqp OP_AH_MODIFY  %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_AH_MODIFY]);
	dbg_vsnprintf("cqp OP_AH_DESTROY  %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_AH_DESTROY]);
	dbg_vsnprintf("cqp OP_MC_CREATE  %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_MC_CREATE]);
	dbg_vsnprintf("cqp OP_MC_MODIFY  %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_MC_MODIFY]);
	dbg_vsnprintf("cqp OP_MC_DESTROY  %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_MC_DESTROY]);
	dbg_vsnprintf("cqp OP_STATS_ALLOCATE  %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_STATS_ALLOCATE]);
	dbg_vsnprintf("cqp OP_STATS_FREE  %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_STATS_FREE]);
	dbg_vsnprintf("cqp OP_STATS_GATHER  %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_STATS_GATHER]);
	dbg_vsnprintf("cqp OP_WS_ADD_NODE  %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_WS_ADD_NODE]);
	dbg_vsnprintf("cqp OP_WS_MODIFY_NODE  %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_WS_MODIFY_NODE]);
	dbg_vsnprintf("cqp OP_WS_DELETE_NODE  %lld\n",
		      dev->cqp_cmd_stats[NSER_OP_WS_DELETE_NODE]);
	dbg_vsnprintf("roce cwnd   = %d\n", iwdev->roce_cwnd);

	cmddone = true;
}

/**
 * dump_hw_stats_cmd -
 * @iwdev: iwarp device
 */
static void dump_hw_stats_cmd(struct nser_device *iwdev)
{
	struct nser_sc_dev *dev = &iwdev->rf->sc_dev;
	struct nser_vsi_pestat *devstat = iwdev->vsi.pestat;
	struct nser_dev_hw_stats *hw_stats = &devstat->hw_stats;

	nser_cqp_gather_stats_cmd(dev, devstat, true);

	dbg_vsnprintf("IPV4 octs recvd                      %llu\n",
		      hw_stats->stats_val[NSER_HW_STAT_INDEX_IPV4_RX_OCTS]);
	dbg_vsnprintf("IPV6 octs recvd                      %llu\n",
		      hw_stats->stats_val[NSER_HW_STAT_INDEX_IPV6_RX_OCTS]);
	dbg_vsnprintf("IPV4 pkts recvd                      %llu\n",
		      hw_stats->stats_val[NSER_HW_STAT_INDEX_IPV4_RX_PKTS]);
	dbg_vsnprintf("IPV6 pkts recvd                      %llu\n",
		      hw_stats->stats_val[NSER_HW_STAT_INDEX_IPV6_RX_PKTS]);

	dbg_vsnprintf("IPV4 multicast pkts recvd            %llu\n",
			     hw_stats->stats_val[NSER_HW_STAT_INDEX_IPV4_RX_MCPKTS]);
	dbg_vsnprintf("IPV6 multicast pkts recvd            %llu\n",
			     hw_stats->stats_val[NSER_HW_STAT_INDEX_IPV6_RX_MCPKTS]);
	dbg_vsnprintf("IPV4 multicast octs recvd            %llu\n",
			     hw_stats->stats_val[NSER_HW_STAT_INDEX_IPV4_RX_MCOCTS]);
	dbg_vsnprintf("IPV6 multicast octs recvd            %llu\n",
			     hw_stats->stats_val[NSER_HW_STAT_INDEX_IPV6_RX_MCOCTS]);

	dbg_vsnprintf("IPV4 octs trans                      %llu\n",
		      hw_stats->stats_val[NSER_HW_STAT_INDEX_IPV4_TX_OCTS]);
	dbg_vsnprintf("IPV6 octs trans                      %llu\n",
		      hw_stats->stats_val[NSER_HW_STAT_INDEX_IPV6_TX_OCTS]);
	dbg_vsnprintf("IPV4 pkts trans                      %llu\n",
		      hw_stats->stats_val[NSER_HW_STAT_INDEX_IPV4_TX_PKTS]);
	dbg_vsnprintf("IPV6 pkts trans                      %llu\n",
		      hw_stats->stats_val[NSER_HW_STAT_INDEX_IPV6_TX_PKTS]);

	dbg_vsnprintf("IPV4 multicast pkts trans            %llu\n",
		      hw_stats->stats_val[NSER_HW_STAT_INDEX_IPV4_TX_MCPKTS]);
	dbg_vsnprintf("IPV6 multicast pkts trans            %llu\n",
		      hw_stats->stats_val[NSER_HW_STAT_INDEX_IPV6_TX_MCPKTS]);
	dbg_vsnprintf("IPV4 multicast octs trans            %llu\n",
		      hw_stats->stats_val[NSER_HW_STAT_INDEX_IPV4_TX_MCOTS]);
	dbg_vsnprintf("IPV6 multicast octs trans            %llu\n",
	       hw_stats->stats_val[NSER_HW_STAT_INDEX_IPV6_TX_MCOTS]);

	dbg_vsnprintf("IPV4 pkts recvd & discarded          %llu\n",
		      hw_stats->stats_val[NSER_HW_STAT_INDEX_IPV4_RX_DISCARD]);
	dbg_vsnprintf("IPV6 pkts recvd & discarded          %llu\n",
		      hw_stats->stats_val[NSER_HW_STAT_INDEX_IPV6_RX_DISCARD]);

	dbg_vsnprintf("Rx VLAN err                          %llu\n",
		      hw_stats->stats_val[NSER_HW_STAT_INDEX_RX_VLAN_ERR]);

	dbg_vsnprintf("Rx CNP HANDLED                       %llu\n",
			      hw_stats->stats_val[NSER_HW_STAT_INDEX_RX_CNP_HANDLED]);
	dbg_vsnprintf("Rx CNP IGNORED                       %llu\n",
			      hw_stats->stats_val[NSER_HW_STAT_INDEX_RX_CNP_IGNORED]);
	dbg_vsnprintf("Tx CNP SENT                          %llu\n",
			      hw_stats->stats_val[NSER_HW_STAT_INDEX_TX_CNPSENT]);

	dbg_vsnprintf("RDMA read-req msgs recvd             %llu\n",
		      hw_stats->stats_val[NSER_HW_STAT_INDEX_RDMA_RX_RDS]);
	dbg_vsnprintf("RDMA send-type msgs recvd            %llu\n",
		      hw_stats->stats_val[NSER_HW_STAT_INDEX_RDMA_RX_SNDS]);
	dbg_vsnprintf("RDMA write msgs recvd                %llu\n",
		      hw_stats->stats_val[NSER_HW_STAT_INDEX_RDMA_RX_WRS]);

	dbg_vsnprintf("RDMA read-req msgs sent              %llu\n",
		      hw_stats->stats_val[NSER_HW_STAT_INDEX_RDMA_TX_RDS]);
	dbg_vsnprintf("RDMA send-type msgs sent             %llu\n",
		      hw_stats->stats_val[NSER_HW_STAT_INDEX_RDMA_TX_SNDS]);
	dbg_vsnprintf("RDMA write msgs sent                 %llu\n",
		      hw_stats->stats_val[NSER_HW_STAT_INDEX_RDMA_TX_WRS]);
	dbg_vsnprintf("RDMA verb-bind ops                   %llu\n",
		      hw_stats->stats_val[NSER_HW_STAT_INDEX_VBND]);
	dbg_vsnprintf("RDMA verb-inv ops                    %llu\n",
		      hw_stats->stats_val[NSER_HW_STAT_INDEX_VINV]);

	dbg_vsnprintf("RDMA verb-fast register physical memory ops %llu\n",
			      hw_stats->stats_val[NSER_HW_STAT_INDEX_FRM]);
	dbg_vsnprintf("RX UD Drop PKTS  recvd                          %llu\n",
			      hw_stats->stats_val[NSER_HW_STAT_INDEX_RDMA_RX_UDDROP]);

	dbg_vsnprintf("RX ECN MARKED PKTS           %llu\n",
			      hw_stats->stats_val[NSER_HW_STAT_INDEX_RX_ECN_MARKED_PKTS]);

	dbg_vsnprintf("RDMA ACK PKTS recvd                            %llu\n",
			      hw_stats->stats_val[NSER_HW_STAT_INDEX_RDMA_RX_ACK_PKT]);
	dbg_vsnprintf("RDMA NAK PKTS recvd                            %llu\n",
			      hw_stats->stats_val[NSER_HW_STAT_INDEX_RDMA_RX_NAK_PKT]);

	dbg_vsnprintf("RDMA RNR PKTS recvd           %llu\n",
			      hw_stats->stats_val[NSER_HW_STAT_INDEX_RDMA_RX_RNR_PKT]);

	dbg_vsnprintf("RDMA Duplicate PKTS recvd                            %llu\n",
			      hw_stats->stats_val[NSER_HW_STAT_INDEX_RDMA_RX_DUP_PKT]);
	dbg_vsnprintf("RDMA Invalidate PKTS recvd                            %llu\n",
			      hw_stats->stats_val[NSER_HW_STAT_INDEX_RDMA_RX_INV_PKT]);

	dbg_vsnprintf("RDMA ACK PKTS sent           %llu\n",
			      hw_stats->stats_val[NSER_HW_STAT_INDEX_RDMA_TX_ACK_PKT]);

	dbg_vsnprintf("RDMA NAK PKTS sent                            %llu\n",
			      hw_stats->stats_val[NSER_HW_STAT_INDEX_RDMA_TX_NAK_PKT]);
	dbg_vsnprintf("RDMA RNR PKTS sent                            %llu\n",
			      hw_stats->stats_val[NSER_HW_STAT_INDEX_RDMA_TX_RNR_PKT]);

	dbg_vsnprintf("RDMA Retrans PKTS sent                            %llu\n",
			      hw_stats->stats_val[NSER_HW_STAT_INDEX_TX_REPKTS]);

	cmddone = true;
}

/**
 * nser_dbg_dump_read - read the dump data
 * @filp: the opened file
 * @buf: where to write the data for the user to read
 * @count: the size of the user's buffer
 * @ppos: file position offset
 *
 * When a read happens, the file system will keep calling this routine
 * until it returns with no data.  This is because the buffers may be too
 * small to contain all the data at once.  Some of the cmds count on being
 * able to return the results in pieces.
 */
static ssize_t nser_dbg_dump_read(struct file *filp,
				   char __user *buf,
				   size_t count,
				   loff_t *ppos)
{
	struct nser_handler *hdl = filp->private_data;
	struct nser_device *iwdev = hdl->iwdev;
	struct nser_pci_f *rf;
	int bytes_not_copied;
	int len;

	rf = iwdev->rf;
	if (cmddone) {
		cmdnew = true;
		cmddone = false;
	} else {
		if (cmdnew)
			dbg_vsnprintf("cmd: %s", cmd_buf);

		if (strncasecmp(cmd_buf, "qp ", 3) == 0)
			dump_qp_cmd(rf, &cmd_buf[3]);
		else if (strncasecmp(cmd_buf, "cq ", 3) == 0)
			dump_cq_cmd(rf, &cmd_buf[3]);
		else if (strncasecmp(cmd_buf, "sw-stats", 8) == 0)
			dump_stats_cmd(iwdev);
		else if (strncasecmp(cmd_buf, "hw-stats", 8) == 0)
			dump_hw_stats_cmd(iwdev);
		else
			dump_help();
		cmdnew = false;
	}

	len = min_t(int, count, (nser_dbg_dump_data_len - *ppos));
	if (len == 0) {
		*ppos = 0;
		nser_dbg_dump_data_len = 0;
		return 0;
	}

	bytes_not_copied =
	    copy_to_user(buf, &nser_dbg_dump_buf[*ppos], len);
	if (bytes_not_copied) {
		dev_warn(iwdev->ibdev.dma_device,
			 "copy_to_user returned 0x%x\n", bytes_not_copied);
	}

	*ppos += len;
	if (*ppos >= nser_dbg_dump_data_len) {
		*ppos = 0;
		nser_dbg_dump_data_len = 0;
	}

	return len;
}

/**
 * nser_dbg_dump_write - trigger a datadump snapshot
 * @filp: the opened file
 * @buf: where to find the user's data
 * @count: the length of the user's data
 * @ppos: file position offset
 */
static ssize_t nser_dbg_dump_write(struct file *filp,
				    const char __user *buf,
				    size_t count,
				    loff_t *ppos)
{
	int bytes_not_copied;

	/* don't allow partial writes */
	if (*ppos != 0)
		return 0;
	if (count >= sizeof(cmd_buf))
		return -ENOSPC;

	bytes_not_copied = copy_from_user(cmd_buf, buf, count);
	if (bytes_not_copied < 0)
		return bytes_not_copied;
	if (bytes_not_copied > 0)
		count -= bytes_not_copied;

	cmd_buf[count] = '\0';
	cmdnew = true;
	cmddone = false;
	*ppos = 0;
	nser_dbg_dump_data_len = 0;
	return count;
}

/**
 * nser_dbg_prep_dump_buf
 * @hdl: the iWARP handler we're working with
 * @buflen: the desired buffer length
 *
 * Return positive if success, 0 if failed
 */
static int nser_dbg_prep_dump_buf(struct nser_handler *hdl, int buflen)
{
	if (nser_dbg_dump_buf_len && nser_dbg_dump_buf_len < buflen) {
		kfree(nser_dbg_dump_buf);
		nser_dbg_dump_buf_len = 0;
		nser_dbg_dump_buf = NULL;
	}

	if (!nser_dbg_dump_buf) {
		nser_dbg_dump_buf = kzalloc(buflen, GFP_KERNEL);
		if (!nser_dbg_dump_buf) {
			nser_dbg_dump_buf_len = 0;
			pr_err("%s: memory alloc for snapshot failed\n",
			       __func__);
		} else {
			nser_dbg_dump_buf_len = buflen;
			pr_err("%s: nser_dbg_dump_buf_len = %d\n",
			       __func__, (int)nser_dbg_dump_buf_len);
		}
	}

	return nser_dbg_dump_buf_len;
}

static const struct file_operations nser_dbg_dump_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = nser_dbg_dump_read,
	.write = nser_dbg_dump_write,
};

/**
 * nser_dbg_pf_init - setup the debugfs directory for the pf
 * @hdl: the iWARP handler that is starting up
 */
void nser_dbg_pf_init(struct nser_handler *hdl)
{
	const char *name = pci_name(hdl->iwdev->rf->pcidev);
	struct dentry *pfile __maybe_unused;

	if (nser_dbg_prep_dump_buf(hdl, NSER_DUMP_BUF_SIZE) == 0) {
		pr_err("%s: unable to allocate debugfs dump buffer\n", __func__);
		return;
	}

	hdl->nser_dbg_dentry = debugfs_create_dir(name, nser_dbg_root);
	if (hdl->nser_dbg_dentry)
		pfile =
		    debugfs_create_file("dump", 0600, hdl->nser_dbg_dentry,
					hdl, &nser_dbg_dump_fops);
	else
		pr_err("%s: debugfs entry for %s failed\n", __func__, name);

	spin_lock_init(&hdl->uctx_list_lock);
	INIT_LIST_HEAD(&hdl->ucontext_list);
}

/**
 * nser_dbg_pf_exit - clear out the pf's debugfs entries
 * @hdl: the iWARP handler that is stopping
 */
void nser_dbg_pf_exit(struct nser_handler *hdl)
{
	if (hdl) {
		pr_err("%s: removing debugfs entries\n", __func__);
		debugfs_remove_recursive(hdl->nser_dbg_dentry);
		hdl->nser_dbg_dentry = NULL;
	}
}

/**
 * nser_dbg_init - start up debugfs for the driver
 */
void nser_dbg_init(void)
{
	nser_dbg_root = debugfs_create_dir(nser_driver_name, NULL);
	if (!nser_dbg_root)
		pr_err("%s: init of debugfs failed\n", __func__);
}

/**
 * nser_dbg_exit - clean out the driver's debugfs entries
 */
void nser_dbg_exit(void)
{
	kfree(nser_dbg_dump_buf);
	nser_dbg_dump_buf_len = 0;
	nser_dbg_dump_buf = NULL;
	debugfs_remove_recursive(nser_dbg_root);
}

#endif /* CONFIG_DEBUG_FS */

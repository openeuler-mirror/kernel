// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2023 - 2024 ZTE Corporation */
#include "osdep.h"
#include "status.h"
#include "hmc.h"
#include "defs.h"
#include "type.h"
#include "ws.h"
#include "protos.h"
#include "vf.h"
#include "virtchnl.h"
#include "icrdma_hw.h"
#include "main.h"
#include "srq.h"

/**
 * zxdh_get_qp_from_list - get next qp from a list
 * @head: Listhead of qp's
 * @qp: current qp
 */
struct zxdh_sc_qp *zxdh_get_qp_from_list(struct list_head *head, struct zxdh_sc_qp *qp)
{
	struct list_head *lastentry;
	struct list_head *entry = NULL;

	if (list_empty(head))
		return NULL;

	if (!qp) {
		entry = head->next;
	} else {
		lastentry = &qp->list;
		entry = lastentry->next;
		if (entry == head)
			return NULL;
	}

	return container_of(entry, struct zxdh_sc_qp, list);
}

#ifdef Z_CONFIG_RDMA_VSI
/**
 * zxdh_qp_rem_qos - remove qp from qos lists during destroy qp
 * @qp: qp to be removed from qos
 */
void zxdh_qp_rem_qos(struct zxdh_sc_qp *qp)
{
	struct zxdh_sc_vsi *vsi = qp->vsi;

	mutex_lock(&vsi->qos[qp->user_pri].qos_mutex);
	if (qp->on_qoslist) {
		qp->on_qoslist = false;
		list_del(&qp->list);
	}
	mutex_unlock(&vsi->qos[qp->user_pri].qos_mutex);
}

/**
 * zxdh_qp_add_qos - called during setctx for qp to be added to qos
 * @qp: qp to be added to qos
 */
void zxdh_qp_add_qos(struct zxdh_sc_qp *qp)
{
	struct zxdh_sc_vsi *vsi = qp->vsi;

	mutex_lock(&vsi->qos[qp->user_pri].qos_mutex);
	if (!qp->on_qoslist) {
		list_add(&qp->list, &vsi->qos[qp->user_pri].qplist);
		qp->on_qoslist = true;
		qp->qs_handle = vsi->qos[qp->user_pri].qs_handle;
	}
	mutex_unlock(&vsi->qos[qp->user_pri].qos_mutex);
}
#else
/**
 * zxdh_qp_rem_qos - remove qp from qos lists during destroy qp
 * @qp: qp to be removed from qos
 */
void zxdh_qp_rem_qos(struct zxdh_sc_qp *qp)
{
	struct zxdh_sc_dev *dev = qp->dev;

	mutex_lock(&dev->qos[qp->user_pri].qos_mutex);
	if (qp->on_qoslist) {
		qp->on_qoslist = false;
		list_del(&qp->list);
	}
	mutex_unlock(&dev->qos[qp->user_pri].qos_mutex);
}

/**
 * zxdh_qp_add_qos - called during setctx for qp to be added to qos
 * @qp: qp to be added to qos
 */
void zxdh_qp_add_qos(struct zxdh_sc_qp *qp)
{
	struct zxdh_sc_dev *dev = qp->dev;

	mutex_lock(&dev->qos[qp->user_pri].qos_mutex);
	if (!qp->on_qoslist) {
		list_add(&qp->list, &dev->qos[qp->user_pri].qplist);
		qp->on_qoslist = true;
		qp->qs_handle = dev->qos[qp->user_pri].qs_handle;
	}
	mutex_unlock(&dev->qos[qp->user_pri].qos_mutex);
}
#endif

/**
 * zxdh_sc_pd_init - initialize sc pd struct
 * @dev: sc device struct
 * @pd: sc pd ptr
 * @pd_id: pd_id for allocated pd
 * @abi_ver: User/Kernel ABI version
 */
void zxdh_sc_pd_init(struct zxdh_sc_dev *dev, struct zxdh_sc_pd *pd, u32 pd_id, int abi_ver)
{
	pd->pd_id = pd_id;
	pd->abi_ver = abi_ver;
	pd->dev = dev;
}

/**
 * zxdh_sc_add_arp_cache_entry - cqp wqe add arp cache entry
 * @cqp: struct for cqp hw
 * @info: arp entry information
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int zxdh_sc_add_arp_cache_entry(struct zxdh_sc_cqp *cqp,
				       struct zxdh_add_arp_cache_entry_info *info, u64 scratch,
				       bool post_sq)
{
	__le64 *wqe;
	u64 temp, hdr;

	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;
	set_64bit_val(wqe, 8, info->reach_max);

	temp = info->mac_addr[5] | LS_64_1(info->mac_addr[4], 8) | LS_64_1(info->mac_addr[3], 16) |
	       LS_64_1(info->mac_addr[2], 24) | LS_64_1(info->mac_addr[1], 32) |
	       LS_64_1(info->mac_addr[0], 40);
	set_64bit_val(wqe, 16, temp);

	hdr = info->arp_index | FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_MANAGE_ARP) |
	      FIELD_PREP(ZXDH_CQPSQ_MAT_PERMANENT, info->permanent) |
	      FIELD_PREP(ZXDH_CQPSQ_MAT_ENTRYVALID, true) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: ARP_CACHE_ENTRY WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * zxdh_sc_del_arp_cache_entry - dele arp cache entry
 * @cqp: struct for cqp hw
 * @scratch: u64 saved to be used during cqp completion
 * @arp_index: arp index to delete arp entry
 * @post_sq: flag for cqp db to ring
 */
static int zxdh_sc_del_arp_cache_entry(struct zxdh_sc_cqp *cqp, u64 scratch, u16 arp_index,
				       bool post_sq)
{
	__le64 *wqe;
	u64 hdr;

	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	hdr = arp_index | FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_MANAGE_ARP) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: ARP_CACHE_DEL_ENTRY WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * zxdh_sc_manage_apbvt_entry - for adding and deleting apbvt entries
 * @cqp: struct for cqp hw
 * @info: info for apbvt entry to add or delete
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int zxdh_sc_manage_apbvt_entry(struct zxdh_sc_cqp *cqp, struct zxdh_apbvt_info *info,
				      u64 scratch, bool post_sq)
{
	__le64 *wqe;
	u64 hdr;

	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	set_64bit_val(wqe, 16, info->port);

	hdr = FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_MANAGE_APBVT) |
	      FIELD_PREP(ZXDH_CQPSQ_MAPT_ADDPORT, info->add) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: MANAGE_APBVT WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * zxdh_sc_manage_qhash_table_entry - manage quad hash entries
 * @cqp: struct for cqp hw
 * @info: info for quad hash to manage
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 *
 * This is called before connection establishment is started.
 * For passive connections, when listener is created, it will
 * call with entry type of  ZXDH_QHASH_TYPE_TCP_SYN with local
 * ip address and tcp port. When SYN is received (passive
 * connections) or sent (active connections), this routine is
 * called with entry type of ZXDH_QHASH_TYPE_TCP_ESTABLISHED
 * and quad is passed in info.
 *
 * When iwarp connection is done and its state moves to RTS, the
 * quad hash entry in the hardware will point to iwarp's qp
 * number and requires no calls from the driver.
 */
static int zxdh_sc_manage_qhash_table_entry(struct zxdh_sc_cqp *cqp,
					    struct zxdh_qhash_table_info *info, u64 scratch,
					    bool post_sq)
{
	__le64 *wqe;
	u64 qw1 = 0;
	u64 qw2 = 0;
	u64 temp;
	struct zxdh_sc_vsi *vsi = info->vsi;

	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;
	temp = info->mac_addr[5] | LS_64_1(info->mac_addr[4], 8) | LS_64_1(info->mac_addr[3], 16) |
	       LS_64_1(info->mac_addr[2], 24) | LS_64_1(info->mac_addr[1], 32) |
	       LS_64_1(info->mac_addr[0], 40);
	set_64bit_val(wqe, 0, temp);

	qw1 = FIELD_PREP(ZXDH_CQPSQ_QHASH_QPN, info->qp_num) |
	      FIELD_PREP(ZXDH_CQPSQ_QHASH_DEST_PORT, info->dest_port);
	if (info->ipv4_valid) {
		set_64bit_val(wqe, 48, FIELD_PREP(ZXDH_CQPSQ_QHASH_ADDR3, info->dest_ip[0]));
	} else {
		set_64bit_val(wqe, 56,
			      FIELD_PREP(ZXDH_CQPSQ_QHASH_ADDR0, info->dest_ip[0]) |
				      FIELD_PREP(ZXDH_CQPSQ_QHASH_ADDR1, info->dest_ip[1]));

		set_64bit_val(wqe, 48,
			      FIELD_PREP(ZXDH_CQPSQ_QHASH_ADDR2, info->dest_ip[2]) |
				      FIELD_PREP(ZXDH_CQPSQ_QHASH_ADDR3, info->dest_ip[3]));
	}
	qw2 = FIELD_PREP(ZXDH_CQPSQ_QHASH_QS_HANDLE, vsi->qos[info->user_pri].qs_handle);
	if (info->vlan_valid)
		qw2 |= FIELD_PREP(ZXDH_CQPSQ_QHASH_VLANID, info->vlan_id);
	set_64bit_val(wqe, 16, qw2);
	if (info->entry_type == ZXDH_QHASH_TYPE_TCP_ESTABLISHED) {
		qw1 |= FIELD_PREP(ZXDH_CQPSQ_QHASH_SRC_PORT, info->src_port);
		if (!info->ipv4_valid) {
			set_64bit_val(wqe, 40,
				      FIELD_PREP(ZXDH_CQPSQ_QHASH_ADDR0, info->src_ip[0]) |
					      FIELD_PREP(ZXDH_CQPSQ_QHASH_ADDR1, info->src_ip[1]));
			set_64bit_val(wqe, 32,
				      FIELD_PREP(ZXDH_CQPSQ_QHASH_ADDR2, info->src_ip[2]) |
					      FIELD_PREP(ZXDH_CQPSQ_QHASH_ADDR3, info->src_ip[3]));
		} else {
			set_64bit_val(wqe, 32, FIELD_PREP(ZXDH_CQPSQ_QHASH_ADDR3, info->src_ip[0]));
		}
	}

	set_64bit_val(wqe, 8, qw1);
	temp = FIELD_PREP(ZXDH_CQPSQ_QHASH_WQEVALID, cqp->polarity) |
	       FIELD_PREP(ZXDH_CQPSQ_QHASH_OPCODE, ZXDH_CQP_OP_MANAGE_QUAD_HASH_TABLE_ENTRY) |
	       FIELD_PREP(ZXDH_CQPSQ_QHASH_MANAGE, info->manage) |
	       FIELD_PREP(ZXDH_CQPSQ_QHASH_IPV4VALID, info->ipv4_valid) |
	       FIELD_PREP(ZXDH_CQPSQ_QHASH_VLANVALID, info->vlan_valid) |
	       FIELD_PREP(ZXDH_CQPSQ_QHASH_ENTRYTYPE, info->entry_type);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, temp);

	print_hex_dump_debug("WQE: MANAGE_QHASH WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * zxdh_sc_qp_init - initialize qp
 * @qp: sc qp
 * @info: initialization qp info
 */
int zxdh_sc_qp_init(struct zxdh_sc_qp *qp, struct zxdh_qp_init_info *info)
{
	int ret_code;
	u32 pble_obj_cnt;
	u16 wqe_size;
	struct zxdh_qp *iwqp = container_of(qp, struct zxdh_qp, sc_qp);

	if (iwqp->is_srq == false) {
		if (info->qp_uk_init_info.max_sq_frag_cnt >
			    info->pd->dev->hw_attrs.uk_attrs.max_hw_wq_frags ||
		    info->qp_uk_init_info.max_rq_frag_cnt >
			    info->pd->dev->hw_attrs.uk_attrs.max_hw_wq_frags)
			return -EINVAL;
	} else {
		if (info->qp_uk_init_info.max_sq_frag_cnt >
		    info->pd->dev->hw_attrs.uk_attrs.max_hw_wq_frags)
			return -EINVAL;
	}

	qp->dev = info->dev;
#ifdef Z_CONFIG_RDMA_VSI
	qp->vsi = info->vsi;
#endif
	qp->sq_pa = info->sq_pa;
	if (iwqp->is_srq == false)
		qp->rq_pa = info->rq_pa;
	qp->hw_host_ctx_pa = info->host_ctx_pa;
	qp->shadow_area_pa = info->shadow_area_pa;
	qp->pd = info->pd;
	qp->hw_host_ctx = info->host_ctx;
	info->qp_uk_init_info.wqe_alloc_db = qp->pd->dev->wqe_alloc_db;
	qp->is_nvmeof_ioq = false;
	qp->is_nvmeof_tgt = false;
	qp->nvmeof_qid = 0xffff;
	qp->entry_err_cnt = 0;
	qp->retry_err_cnt = 0;
	qp->aeq_entry_err_last_psn = 0;
	qp->aeq_retry_err_last_psn = 0;

	ret_code = zxdh_uk_qp_init(&qp->qp_uk, &info->qp_uk_init_info);
	if (ret_code)
		return ret_code;

	qp->virtual_map = info->virtual_map;
	pble_obj_cnt = info->pd->dev->hmc_info->hmc_obj[ZXDH_HMC_IW_PBLE].cnt;

	if (iwqp->is_srq == false) {
		if ((info->virtual_map && info->sq_pa >= pble_obj_cnt) ||
		    (info->virtual_map && info->rq_pa >= pble_obj_cnt))
			return -EINVAL;
	} else {
		if ((info->virtual_map && info->sq_pa >= pble_obj_cnt))
			return -EINVAL;
	}

	qp->hw_sq_size = zxdh_get_encoded_wqe_size(qp->qp_uk.sq_ring.size, ZXDH_QUEUE_TYPE_SQ_RQ);

	ret_code = zxdh_fragcnt_to_wqesize_rq(qp->qp_uk.max_rq_frag_cnt, &wqe_size);
	if (ret_code)
		return ret_code;

	if (iwqp->is_srq == false) {
		qp->hw_rq_size =
			zxdh_get_encoded_wqe_size(qp->qp_uk.rq_size, ZXDH_QUEUE_TYPE_SQ_RQ);
	}

	return 0;
}

/**
 * zxdh_sc_qp_create - create qp
 * @qp: sc qp
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
int zxdh_sc_qp_create(struct zxdh_sc_qp *qp, u64 scratch, bool post_sq)
{
	struct zxdh_sc_cqp *cqp;
	__le64 *wqe;
	u64 hdr;

	cqp = qp->dev->cqp;

	if (qp->qp_ctx_num < qp->dev->base_qpn ||
	    qp->qp_ctx_num >
		    (qp->dev->base_qpn + cqp->dev->hmc_info->hmc_obj[ZXDH_HMC_IW_QP].max_cnt - 1))
		return -EINVAL;

	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	set_64bit_val(wqe, 8, qp->hw_host_ctx_pa);
	set_64bit_val(wqe, 16, RDMAQPC_MASK_INIT);
	set_64bit_val(wqe, 24, RDMAQPC_MASK_INIT);
	set_64bit_val(wqe, 32, RDMAQPC_MASK_INIT);
	set_64bit_val(wqe, 40, RDMAQPC_MASK_INIT);
	hdr = FIELD_PREP(ZXDH_CQPSQ_QP_ID, qp->qp_uk.qp_id) |
	      FIELD_PREP(ZXDH_CQPSQ_QP_CONTEXT_ID, qp->qp_ctx_num) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity) |
	      FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_CREATE_QP);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	print_hex_dump_debug("WQE: QP_CREATE WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * zxdh_sc_qp_modify - modify qp cqp wqe
 * @qp: sc qp
 * @info: modify qp info
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
int zxdh_sc_qp_modify(struct zxdh_sc_qp *qp, struct zxdh_modify_qp_info *info, u64 scratch,
		      bool post_sq)
{
	__le64 *wqe;
	struct zxdh_sc_cqp *cqp;
	u64 hdr;

	cqp = qp->dev->cqp;
	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	set_64bit_val(wqe, 8, qp->hw_host_ctx_pa);
	set_64bit_val(wqe, 16, info->qpc_tx_mask_low);
	set_64bit_val(wqe, 24, info->qpc_tx_mask_high);
	set_64bit_val(wqe, 32, info->qpc_rx_mask_low);
	set_64bit_val(wqe, 40, info->qpc_rx_mask_high);
	hdr = FIELD_PREP(ZXDH_CQPSQ_QP_ID, qp->qp_uk.qp_id) |
	      FIELD_PREP(ZXDH_CQPSQ_QP_CONTEXT_ID, qp->qp_ctx_num) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity) |
	      FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_MODIFY_QP);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	print_hex_dump_debug("WQE: QP_MODIFY WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * zxdh_sc_qp_destroy - cqp destroy qp
 * @qp: sc qp
 * @scratch: u64 saved to be used during cqp completion
 * @ignore_mw_bnd: memory window bind flag
 * @post_sq: flag for cqp db to ring
 */
int zxdh_sc_qp_destroy(struct zxdh_sc_qp *qp, u64 scratch, bool ignore_mw_bnd, bool post_sq)
{
	__le64 *wqe;
	struct zxdh_sc_cqp *cqp;
	u64 hdr;

	cqp = qp->dev->cqp;
	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	set_64bit_val(wqe, 8, qp->hw_host_ctx_pa);
	set_64bit_val(wqe, 16, RDMAQPC_TX_MASKL_DESTROY);
	set_64bit_val(wqe, 24, RDMAQPC_TX_MASKH_QP_STATE);
	set_64bit_val(wqe, 32, RDMAQPC_RX_MASKL_DESTROY);
	set_64bit_val(wqe, 40, RDMAQPC_RX_MASKH_DEST_IP);
	hdr = FIELD_PREP(ZXDH_CQPSQ_QP_ID, qp->qp_uk.qp_id) |
	      FIELD_PREP(ZXDH_CQPSQ_QP_CONTEXT_ID, qp->qp_ctx_num) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity) |
	      FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_DESTROY_QP);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	print_hex_dump_debug("WQE: QP_DESTROY WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * zxdh_sc_get_encoded_ird_size -
 * @ird_size: IRD size
 */
static u8 zxdh_sc_get_encoded_ird_size(u16 ird_size)
{
	u8 encoded_size = 0;

	while (ird_size >>= 1)
		encoded_size++;

	return encoded_size;
}

/**
 * zxdh_sc_qp_resetctx_roce - set qp's context
 * @qp: sc qp
 * @qp_ctx: context ptr
 */
void zxdh_sc_qp_resetctx_roce(struct zxdh_sc_qp *qp, __le64 *qp_ctx)
{
	memset(qp_ctx, 0, ZXDH_QP_CTX_SIZE);
	set_64bit_val(qp_ctx, 32,
		      FIELD_PREP(RDMAQPC_TX_HW_SQ_TAIL_HIGH,
				 RS_64_1(IRDMAQPC_HW_SQ_TAIL_INIT, 11)));
	set_64bit_val(qp_ctx, 280, FIELD_PREP(RDMAQPC_RX_IRD_RXNUM, 511));
	set_64bit_val(qp_ctx, 384, FIELD_PREP(RDMAQPC_RX_VHCA_ID, qp->dev->vhca_id));
}

u16 zxdh_get_rc_gqp_id(u16 qp_8k_index, u16 vhca_gqp_start, u16 vhca_gqp_cnt)
{
	u16 gqp_offset = 0;

	gqp_offset = qp_8k_index % vhca_gqp_cnt;

	return (vhca_gqp_start + gqp_offset);
}

void zxdh_sc_qp_modify_ctx_udp_sport(struct zxdh_sc_qp *qp, __le64 *qp_ctx,
				     struct zxdh_qp_host_ctx_info *info)
{
	struct zxdh_udp_offload_info *udp;
	u64 hdr;

	udp = info->udp_info;

	hdr = FIELD_PREP(RDMAQPC_TX_SRC_PORTNUM, udp->src_port);
	set_64bit_val(qp_ctx, 96, hdr);
	dma_wmb();
	set_64bit_val(qp_ctx, 368, FIELD_PREP(RDMAQPC_RX_SRC_PORTNUM, udp->src_port));
	dma_wmb();
	print_hex_dump_debug("WQE: QP_HOST CTX WQE", DUMP_PREFIX_OFFSET, 16, 8, qp_ctx,
			     ZXDH_QP_CTX_SIZE, false);
}

void zxdh_sc_qp_modify_private_cmd_qpc(struct zxdh_sc_qp *qp, __le64 *qp_ctx,
				       struct zxdh_modify_qpc_item *info)
{
	u64 hdr;

	hdr = FIELD_PREP(RDMAQPC_TX_CUR_RETRY_CNT, info->cur_retry_count) |
	      FIELD_PREP(RDMAQPC_TX_READ_RETRY_FLAG, info->read_retry_flag) |
	      FIELD_PREP(RDMAQPC_TX_LAST_ACK_PSN, info->tx_last_ack_psn);
	set_64bit_val(qp_ctx, 0, hdr);
	dma_wmb();
	set_64bit_val(qp_ctx, 8,
		      FIELD_PREP(RDMAQPC_TX_RNR_RETRY_FLAG, info->rnr_retry_flag) |
			      FIELD_PREP(RDMAQPC_TX_RNR_RETRY_TIME_L, info->rnr_retry_time_l) |
			      FIELD_PREP(RDMAQPC_TX_RNR_RETRY_THRESHOLD,
					 info->rnr_retry_threshold));
	set_64bit_val(qp_ctx, 16, FIELD_PREP(RDMAQPC_TX_RNR_RETRY_TIME_H, info->rnr_retry_time_h));
	dma_wmb();

	set_64bit_val(qp_ctx, 32, FIELD_PREP(RDMAQPC_TX_RETRY_FLAG, info->retry_flag));
	dma_wmb();

	set_64bit_val(
		qp_ctx, 40,
		FIELD_PREP(RDMAQPC_TX_ERR_FLAG, info->err_flag) |
			FIELD_PREP(RDMAQPC_TX_ACK_ERR_FLAG, info->ack_err_flag) |
			FIELD_PREP(RDMAQPC_TX_LAST_ACK_WQE_OFFSET, info->last_ack_wqe_offset) |
			FIELD_PREP(RDMAQPC_TX_HW_SQ_TAIL_UNA, info->hw_sq_tail_una) |
			FIELD_PREP(RDMAQPC_TX_RDWQE_PYLD_LENGTH_L, info->rdwqe_pyld_length_l) |
			FIELD_PREP(RDMAQPC_TX_RDWQE_PYLD_LENGTH_H, info->rdwqe_pyld_length_h));

	dma_wmb();

	set_64bit_val(qp_ctx, 48,
		      FIELD_PREP(RDMAQPC_TX_PACKAGE_ERR_FLAG, info->package_err_flag) |
			      FIELD_PREP(RDMAQPC_TX_RECV_READ_FLAG, info->recv_read_flag) |
			      FIELD_PREP(RDMAQPC_TX_RECV_ERR_FLAG, info->recv_err_flag) |
			      FIELD_PREP(RDMAQPC_TX_RECV_RD_MSG_LOSS_ERR_FLAG,
					 info->recv_rd_msg_loss_err_flag) |
			      FIELD_PREP(RDMAQPC_TX_RECV_RD_MSG_LOSS_ERR_CNT,
					 info->recv_rd_msg_loss_err_cnt) |
			      FIELD_PREP(RDMAQPC_TX_RD_MSG_LOSS_ERR_FLAG,
					 info->rd_msg_loss_err_flag) |
			      FIELD_PREP(RDMAQPC_TX_PKTCHK_RD_MSG_LOSS_ERR_CNT,
					 info->pktchk_rd_msg_loss_err_cnt));
	dma_wmb();

	set_64bit_val(qp_ctx, 56,
		      FIELD_PREP(RDMAQPC_TX_RETRY_CQE_SQ_OPCODE_FLAG, info->retry_cqe_sq_opcode));
	dma_wmb();

	print_hex_dump_debug("WQE: QP_HOST CTX WQE", DUMP_PREFIX_OFFSET, 16, 8, qp_ctx,
			     ZXDH_QP_CTX_SIZE, false);
}

/**
 * zxdh_sc_qp_setctx_roce - set qp's context
 * @qp: sc qp
 * @qp_ctx: context ptr
 * @info: ctx info
 */
void zxdh_sc_qp_setctx_roce(struct zxdh_sc_qp *qp, __le64 *qp_ctx,
			    struct zxdh_qp_host_ctx_info *info)
{
	struct zxdh_roce_offload_info *roce_info;
	struct zxdh_udp_offload_info *udp;
	u64 mac;
	u64 dmac;
	u64 hdr;
	u8 service_type;
	u16 header_len;
	u16 gqp_id;

	roce_info = info->roce_info;
	udp = info->udp_info;

	if (roce_info->dcqcn_en || roce_info->dctcp_en) {
		udp->tos &= ~ECN_CODE_PT_MASK;
		udp->tos |= ECN_CODE_PT_VAL;
	}

	mac = LS_64_1(roce_info->mac_addr[5], 0) | LS_64_1(roce_info->mac_addr[4], 8) |
	      LS_64_1(roce_info->mac_addr[3], 16) | LS_64_1(roce_info->mac_addr[2], 24) |
	      LS_64_1(roce_info->mac_addr[1], 32) | LS_64_1(roce_info->mac_addr[0], 40);

	dmac = LS_64_1(udp->dest_mac[5], 0) | LS_64_1(udp->dest_mac[4], 8) |
	       LS_64_1(udp->dest_mac[3], 16) | LS_64_1(udp->dest_mac[2], 24) |
	       LS_64_1(udp->dest_mac[1], 32) | LS_64_1(udp->dest_mac[0], 40);

	qp->user_pri = info->user_pri;
	if (qp->qp_uk.qp_type == ZXDH_QP_TYPE_ROCE_RC) {
		service_type = ZXDH_QP_SERVICE_TYPE_RC;
		gqp_id = zxdh_get_rc_gqp_id(qp->qp_uk.qp_8k_index, qp->dev->vhca_gqp_start,
					    qp->dev->vhca_gqp_cnt);
	} else {
		service_type = ZXDH_QP_SERVICE_TYPE_UD;
		gqp_id = qp->dev->vhca_ud_gqp;
	}

	if (qp->dev->chip_version < 2) {
		if (udp->ipv4)
			header_len = udp->insert_vlan_tag ? 46 : 42;
		else
			header_len = udp->insert_vlan_tag ? 66 : 62;
	} else {
		qp->is_credit_en = 1;
		if (udp->ipv4)
			header_len = udp->insert_vlan_tag ? 70 : 66;
		else
			header_len = udp->insert_vlan_tag ? 90 : 86;
	}

	roce_info->is_qp1 = qp->qp_uk.qp_id == 1 ? 1 : 0;

	set_64bit_val(qp_ctx, 0,
		      FIELD_PREP(RDMAQPC_TX_RETRY_CNT, udp->rexmit_thresh) |
			      FIELD_PREP(RDMAQPC_TX_CUR_RETRY_CNT, udp->rexmit_thresh) |
			      FIELD_PREP(RDMAQPC_TX_LAST_ACK_PSN, udp->psn_max) |
			      FIELD_PREP(RDMAQPC_TX_LSN_LOW1, udp->lsn));
	set_64bit_val(qp_ctx, 8,
		      FIELD_PREP(RDMAQPC_TX_LSN_HIGH23, RS_64_1(udp->lsn, 1)) |
			      FIELD_PREP(RDMAQPC_TX_ACKCREDITS,
					 (info->use_srq || qp->is_nvmeof_ioq || !qp->is_credit_en) ?
						       0x1f :
						       roce_info->ack_credits) |
			      FIELD_PREP(RDMAQPC_TX_RNR_RETRY_THRESHOLD, udp->rnr_nak_thresh));
	set_64bit_val(qp_ctx, 16, FIELD_PREP(RDMAQPC_TX_SSN, 1));
	set_64bit_val(qp_ctx, 24,
		      FIELD_PREP(RDMAQPC_TX_PSN_MAX, udp->psn_max) |
			      FIELD_PREP(RDMAQPC_TX_PSN_NEXT, udp->psn_nxt));
	set_64bit_val(qp_ctx, 32,
		      FIELD_PREP(RDMAQPC_TX_HW_SQ_TAIL_HIGH,
				 RS_64_1(IRDMAQPC_HW_SQ_TAIL_INIT, 11)) |
			      FIELD_PREP(RDMAQPC_TX_LOCAL_ACK_TIMEOUT, udp->timeout));
	set_64bit_val(qp_ctx, 40, FIELD_PREP(RDMAQPC_TX_HW_SQ_TAIL_UNA, IRDMAQPC_HW_SQ_TAIL_INIT));
	set_64bit_val(qp_ctx, 48, 0);
	set_64bit_val(qp_ctx, 56,
		      FIELD_PREP(RDMAQPC_TX_RNR_RETRY_CNT, udp->rnr_nak_thresh) |
			      FIELD_PREP(RDMAQPC_TX_RNR_CUR_RETRY_CNT, udp->rnr_nak_thresh));
	hdr = FIELD_PREP(RDMAQPC_TX_SERVICE_TYPE, service_type) |
	      FIELD_PREP(RDMAQPC_TX_SQ_VMAP, qp->virtual_map) |
	      FIELD_PREP(RDMAQPC_TX_SQ_LPBL_SIZE, qp->virtual_map ? 1 : 0) |
	      FIELD_PREP(RDMAQPC_TX_IS_QP1, roce_info->is_qp1) |
	      FIELD_PREP(RDMAQPC_TX_IPV4, udp->ipv4) |
	      FIELD_PREP(RDMAQPC_TX_FAST_REG_EN, roce_info->fast_reg_en) |
	      FIELD_PREP(RDMAQPC_TX_BIND_EN, roce_info->bind_en) |
	      FIELD_PREP(RDMAQPC_TX_INSERT_VLANTAG, udp->insert_vlan_tag) |
	      FIELD_PREP(RDMAQPC_TX_VLANTAG, udp->vlan_tag) |
	      FIELD_PREP(RDMAQPC_TX_PD_INDEX, roce_info->pd_id) |
	      FIELD_PREP(RDMAQPC_TX_RSV_LKEY_EN, roce_info->priv_mode_en) |
	      FIELD_PREP(RDMAQPC_TX_ECN_EN, roce_info->ecn_en);
	dma_wmb();

	set_64bit_val(qp_ctx, 64, hdr);
	set_64bit_val(qp_ctx, 72, qp->sq_pa);
	set_64bit_val(qp_ctx, 80,
		      FIELD_PREP(RDMAQPC_TX_DEST_IPADDR3, udp->dest_ip_addr[3]) |
			      FIELD_PREP(RDMAQPC_TX_DEST_IPADDR2, udp->dest_ip_addr[2]));
	set_64bit_val(qp_ctx, 88,
		      FIELD_PREP(RDMAQPC_TX_DEST_IPADDR1, udp->dest_ip_addr[1]) |
			      FIELD_PREP(RDMAQPC_TX_DEST_IPADDR0, udp->dest_ip_addr[0]));
	hdr = FIELD_PREP(RDMAQPC_TX_SRC_PORTNUM, udp->src_port) |
	      FIELD_PREP(RDMAQPC_TX_DEST_PORTNUM, udp->dst_port) |
	      FIELD_PREP(RDMAQPC_TX_FLOWLABEL, udp->flow_label) |
	      FIELD_PREP(RDMAQPC_TX_TTL, udp->ttl) |
	      FIELD_PREP(RDMAQPC_TX_ROCE_TVER, roce_info->roce_tver);
	dma_wmb();

	set_64bit_val(qp_ctx, 96, hdr);
	set_64bit_val(qp_ctx, 104,
		      FIELD_PREP(RDMAQPC_TX_QKEY, roce_info->qkey) |
			      FIELD_PREP(RDMAQPC_TX_DEST_QP, roce_info->dest_qp) |
			      FIELD_PREP(RDMAQPC_TX_ORD_SIZE, roce_info->ord_size));
	set_64bit_val(qp_ctx, 112,
		      FIELD_PREP(RDMAQPC_TX_DEST_MAC, dmac) |
			      FIELD_PREP(RDMAQPC_TX_PKEY, roce_info->p_key));
	set_64bit_val(qp_ctx, 120, info->qp_compl_ctx);
	set_64bit_val(qp_ctx, 128,
		      FIELD_PREP(RDMAQPC_TX_LOCAL_IPADDR3, udp->local_ipaddr[3]) |
			      FIELD_PREP(RDMAQPC_TX_LOCAL_IPADDR2, udp->local_ipaddr[2]));
	set_64bit_val(qp_ctx, 136,
		      FIELD_PREP(RDMAQPC_TX_LOCAL_IPADDR1, udp->local_ipaddr[1]) |
			      FIELD_PREP(RDMAQPC_TX_LOCAL_IPADDR0, udp->local_ipaddr[0]));
	set_64bit_val(qp_ctx, 144,
		      FIELD_PREP(RDMAQPC_TX_SRC_MAC, mac) | FIELD_PREP(RDMAQPC_TX_PMTU, udp->pmtu) |
			      FIELD_PREP(RDMAQPC_TX_ACK_TIMEOUT, udp->timeout) |
			      FIELD_PREP(RDMAQPC_TX_LOG_SQSIZE, qp->hw_sq_size));
	hdr = FIELD_PREP(RDMAQPC_TX_CQN, info->send_cq_num) |
	      FIELD_PREP(RDMAQPC_TX_NVMEOF_QID, qp->nvmeof_qid) |
	      FIELD_PREP(RDMAQPC_TX_IS_NVMEOF_TGT, qp->is_nvmeof_tgt) |
	      FIELD_PREP(RDMAQPC_TX_IS_NVMEOF_IOQ, qp->is_nvmeof_ioq) |
	      FIELD_PREP(RDMAQPC_TX_DCQCN_ID, gqp_id) |
	      FIELD_PREP(RDMAQPC_TX_DCQCN_EN, roce_info->dcqcn_en) |
	      FIELD_PREP(RDMAQPC_TX_QUEUE_TC, (service_type == ZXDH_QP_SERVICE_TYPE_UD) ?
							    ZXDH_QP_UD_QUEUE_TC :
							    qp->qp_uk.user_pri);
	dma_wmb();

	set_64bit_val(qp_ctx, 152, hdr);
	set_64bit_val(qp_ctx, 160,
		      FIELD_PREP(RDMAQPC_TX_QPN, qp->qp_uk.qp_id) |
			      FIELD_PREP(RDMAQPC_TX_TOS, (service_type == ZXDH_QP_SERVICE_TYPE_UD) ?
								       ZXDH_QP_UD_TOS :
								       udp->tos) |
			      FIELD_PREP(RDMAQPC_TX_VHCA_ID_LOW6, qp->dev->vhca_id));
	set_64bit_val(qp_ctx, 168,
		      FIELD_PREP(RDMAQPC_TX_VHCA_ID_HIGH4, RS_64_1(qp->dev->vhca_id, 6)) |
			      FIELD_PREP(RDMAQPC_TX_QP_FLOW_SET, qp->qp_uk.qp_8k_index) |
			      FIELD_PREP(RDMAQPC_TX_QPSTATE, info->next_qp_state) |
			      FIELD_PREP(RDMAQPC_TX_DEBUG_SET, qp->dev->vhca_id));

	set_64bit_val(qp_ctx, 256, FIELD_PREP(RDMAQPC_RX_LAST_OPCODE, 4));
	set_64bit_val(qp_ctx, 264, (service_type == ZXDH_QP_SERVICE_TYPE_UD) ? roce_info->qkey : 0);
	set_64bit_val(qp_ctx, 272, FIELD_PREP(RDMAQPC_RX_EPSN, udp->epsn));
	set_64bit_val(qp_ctx, 280, FIELD_PREP(RDMAQPC_RX_IRD_RXNUM, 511));
	set_64bit_val(qp_ctx, 288, 0);
	set_64bit_val(qp_ctx, 296, 0);
	set_64bit_val(qp_ctx, 304, 0);
	set_64bit_val(qp_ctx, 312, 0);
	set_64bit_val(qp_ctx, 320,
		      FIELD_PREP(RDMAQPC_RX_LOCAL_IPADDR3, udp->local_ipaddr[3]) |
			      FIELD_PREP(RDMAQPC_RX_LOCAL_IPADDR2, udp->local_ipaddr[2]));
	set_64bit_val(qp_ctx, 328,
		      FIELD_PREP(RDMAQPC_RX_SRC_MAC_HIGH16, RS_64_1(mac, 32)) |
			      FIELD_PREP(RDMAQPC_RX_DEST_MAC, dmac));

	hdr = FIELD_PREP(RDMAQPC_RX_IS_NVMEOF_IOQ, qp->is_nvmeof_ioq) |
	      FIELD_PREP(RDMAQPC_RX_INSERT_VLANTAG, udp->insert_vlan_tag) |
	      FIELD_PREP(RDMAQPC_RX_PMTU, udp->pmtu) |
	      FIELD_PREP(RDMAQPC_RX_SERVICE_TYPE, service_type) |
	      FIELD_PREP(RDMAQPC_RX_IPV4, udp->ipv4) |
	      FIELD_PREP(RDMAQPC_RX_PD_INDEX, roce_info->pd_id) |
	      FIELD_PREP(RDMAQPC_RX_QPSTATE, info->next_qp_state) |
	      FIELD_PREP(RDMAQPC_RX_SRC_MAC_LOW32, mac);
	dma_wmb();

	set_64bit_val(qp_ctx, 336, hdr);
	hdr = FIELD_PREP(RDMAQPC_RX_DEST_QP_HIGH12, RS_64_1(roce_info->dest_qp, 12)) |
	      FIELD_PREP(RDMAQPC_RX_FLOWLABEL, udp->flow_label) |
	      FIELD_PREP(RDMAQPC_RX_TTL, udp->ttl) |
	      FIELD_PREP(RDMAQPC_RX_TOS,
			 (service_type == ZXDH_QP_SERVICE_TYPE_UD) ? ZXDH_QP_UD_TOS : udp->tos) |
	      FIELD_PREP(RDMAQPC_RX_VLANTAG, udp->vlan_tag);
	dma_wmb();

	set_64bit_val(qp_ctx, 344, hdr);

	if (info->use_srq) {
		set_64bit_val(qp_ctx, 352, FIELD_PREP(RDMAQPC_RX_SRQN, qp->srq->srq_uk.srq_id));
	} else if (qp->is_nvmeof_ioq) {
		set_64bit_val(qp_ctx, 352,
			      FIELD_PREP(RDMAQPC_RX_NVMEOF_QID, qp->nvmeof_qid) |
				      FIELD_PREP(RDMAQPC_RX_IS_NVMEOF_TGT,
						 qp->nvme_flush_qp ? 1 : qp->is_nvmeof_tgt));
	} else {
		set_64bit_val(qp_ctx, 352, qp->rq_pa);
	}

	set_64bit_val(qp_ctx, 360, qp->shadow_area_pa);
	set_64bit_val(qp_ctx, 368,
		      FIELD_PREP(RDMAQPC_RX_HDR_LEN, header_len) |
			      FIELD_PREP(RDMAQPC_RX_PKEY, roce_info->p_key) |
			      FIELD_PREP(RDMAQPC_RX_SRC_PORTNUM, udp->src_port));
	hdr = FIELD_PREP(RDMAQPC_RX_WQE_SIGN_EN, 0) |
	      FIELD_PREP(RDMAQPC_RX_RQ_VMAP, qp->virtual_map) |
	      FIELD_PREP(RDMAQPC_RX_IRD_SIZE, zxdh_sc_get_encoded_ird_size(roce_info->ird_size)) |
	      FIELD_PREP(RDMAQPC_RX_LOG_RQSIZE, qp->hw_rq_size) |
	      FIELD_PREP(RDMAQPC_RX_SEND_EN, 1) |
	      FIELD_PREP(RDMAQPC_RX_WRITE_EN, roce_info->wr_rdresp_en) |
	      FIELD_PREP(RDMAQPC_RX_READ_EN, roce_info->rd_en) |
	      FIELD_PREP(RDMAQPC_RX_LOG_RQE_SIZE, qp->qp_uk.rq_wqe_size) |
	      FIELD_PREP(RDMAQPC_RX_USE_SRQ, info->use_srq) |
	      FIELD_PREP(RDMAQPC_RX_CQN, info->rcv_cq_num) |
	      FIELD_PREP(RDMAQPC_RX_DEST_QP_LOW12, roce_info->dest_qp) |
	      FIELD_PREP(RDMAQPC_RX_RQ_LPBL_SIZE, qp->virtual_map ? 1 : 0) |
	      FIELD_PREP(RDMAQPC_RX_RSV_LKEY_EN, roce_info->priv_mode_en) |
	      FIELD_PREP(RDMAQPC_RX_RNR_TIMER, udp->min_rnr_timer) |
	      FIELD_PREP(RDMAQPC_RX_ACK_CREDITS,
			 (info->use_srq || qp->is_nvmeof_ioq || !qp->is_credit_en) ? 1 : 0);
	dma_wmb();

	set_64bit_val(qp_ctx, 376, hdr);
	set_64bit_val(qp_ctx, 384,
		      FIELD_PREP(RDMAQPC_RX_QP_GROUP_NUM, gqp_id) |
			      FIELD_PREP(RDMAQPC_RX_QP_FLOW_SET, qp->qp_uk.qp_8k_index) |
			      FIELD_PREP(RDMAQPC_RX_DEBUG_SET, qp->dev->vhca_id) |
			      FIELD_PREP(RDMAQPC_RX_VHCA_ID, qp->dev->vhca_id) |
			      FIELD_PREP(RDMAQPC_RX_QUEUE_TC,
					 (service_type == ZXDH_QP_SERVICE_TYPE_UD) ?
						       ZXDH_QP_UD_QUEUE_TC :
						       qp->qp_uk.user_pri));
	set_64bit_val(qp_ctx, 392, info->qp_compl_ctx);
	set_64bit_val(qp_ctx, 400,
		      FIELD_PREP(RDMAQPC_RX_DEST_IPADDR1, udp->dest_ip_addr[1]) |
			      FIELD_PREP(RDMAQPC_RX_DEST_IPADDR0, udp->dest_ip_addr[0]));
	set_64bit_val(qp_ctx, 408,
		      FIELD_PREP(RDMAQPC_RX_DEST_IPADDR3, udp->dest_ip_addr[3]) |
			      FIELD_PREP(RDMAQPC_RX_DEST_IPADDR2, udp->dest_ip_addr[2]));
	set_64bit_val(qp_ctx, 416,
		      FIELD_PREP(RDMAQPC_RX_LOCAL_IPADDR1, udp->local_ipaddr[1]) |
			      FIELD_PREP(RDMAQPC_RX_LOCAL_IPADDR0, udp->local_ipaddr[0]));

	print_hex_dump_debug("WQE: QP_HOST CTX WQE", DUMP_PREFIX_OFFSET, 16, 8, qp_ctx,
			     ZXDH_QP_CTX_SIZE, false);
}

/**
 * zxdh_sc_alloc_stag - mr stag alloc
 * @dev: sc device struct
 * @info: stag info
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int zxdh_sc_alloc_stag(struct zxdh_sc_dev *dev, struct zxdh_allocate_stag_info *info,
			      u64 scratch, bool post_sq)
{
	__le64 *wqe;
	struct zxdh_sc_cqp *cqp;
	u64 hdr;
	u32 pd_h, pd_l;
	enum zxdh_page_size page_size;

	if (info->page_size == 0x40000000)
		page_size = ZXDH_PAGE_SIZE_1G;
	else if (info->page_size == 0x200000)
		page_size = ZXDH_PAGE_SIZE_2M;
	else
		page_size = ZXDH_PAGE_SIZE_4K;

	cqp = dev->cqp;
	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	pd_l = info->pd_id & 0x3FFFF;
	pd_h = (info->pd_id >> 18) & 0x03;

	if (info->chunk_size)
		set_64bit_val(wqe, 16,
			      FIELD_PREP(ZXDH_CQPSQ_STAG_FIRSTPMPBLIDX, info->first_pm_pbl_idx));

	set_64bit_val(wqe, 24,
		      FIELD_PREP(ZXDH_CQPSQ_STAG_IDX, info->stag_idx) |
			      FIELD_PREP(ZXDH_CQPSQ_STAG_MR_PDID_HIG, pd_h));

	set_64bit_val(wqe, 40,
		      FIELD_PREP(ZXDH_CQPSQ_STAG_MR_PDID_LOW, pd_l) |
			      FIELD_PREP(ZXDH_CQPSQ_STAG_STAGLEN, info->total_len));

	hdr = FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_ALLOC_MKEY) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity) |
	      FIELD_PREP(ZXDH_CQPSQ_STAG_USEHMCFNIDX, info->use_hmc_fcn_index) |
	      FIELD_PREP(ZXDH_CQPSQ_STAG_HMCFNIDX, info->hmc_fcn_index) |
	      FIELD_PREP(ZXDH_CQPSQ_STAG_ARIGHTS, info->access_rights) |
	      FIELD_PREP(ZXDH_CQPSQ_STAG_HPAGESIZE, page_size) |
	      FIELD_PREP(ZXDH_CQPSQ_STAG_LPBLSIZE, info->chunk_size) |
	      FIELD_PREP(ZXDH_CQPSQ_STAG_MR, 1) |
	      FIELD_PREP(ZXDH_CQPSQ_STAG_FAST_REGISTER_MR_EN, 1) |
	      FIELD_PREP(ZXDH_CQPSQ_STAG_MR_INVALID_EN, 1);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);
	return 0;
}

/**
 * zxdh_sc_mr_reg_non_shared - non-shared mr registration
 * @dev: sc device struct
 * @info: mr info
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int zxdh_sc_mr_reg_non_shared(struct zxdh_sc_dev *dev, struct zxdh_reg_ns_stag_info *info,
				     u64 scratch, bool post_sq)
{
	__le64 *wqe;
	u64 fbo;
	struct zxdh_sc_cqp *cqp;
	u64 hdr;
	u32 pble_obj_cnt, pd_h, pd_l;
	u8 addr_type;
	enum zxdh_page_size page_size;

	if (info->page_size == 0x40000000)
		page_size = ZXDH_PAGE_SIZE_1G;
	else if (info->page_size == 0x200000)
		page_size = ZXDH_PAGE_SIZE_2M;
	else if (info->page_size == 0x1000)
		page_size = ZXDH_PAGE_SIZE_4K;
	else
		return -EINVAL;

	pble_obj_cnt = dev->hmc_info->hmc_obj[ZXDH_HMC_IW_PBLE_MR].cnt;
	if (info->chunk_size && info->first_pm_pbl_index >= pble_obj_cnt)
		return -EINVAL;

	cqp = dev->cqp;
	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;
	fbo = info->va & (info->page_size - 1);

	pd_l = info->pd_id & 0x3FFFF;
	pd_h = (info->pd_id >> 18) & 0x03;

	set_64bit_val(wqe, 8, (info->addr_type == ZXDH_ADDR_TYPE_VA_BASED ? info->va : fbo));
	set_64bit_val(wqe, 24,
		      FIELD_PREP(ZXDH_CQPSQ_STAG_KEY, info->stag_key) |
			      FIELD_PREP(ZXDH_CQPSQ_STAG_IDX, info->stag_idx) |
			      FIELD_PREP(ZXDH_CQPSQ_STAG_MR_PDID_HIG, pd_h));

	if (!info->chunk_size) {
		set_64bit_val(wqe, 32, info->reg_addr_pa);
	} else {
		set_64bit_val(wqe, 16,
			      FIELD_PREP(ZXDH_CQPSQ_STAG_FIRSTPMPBLIDX, info->first_pm_pbl_index));
	}

	set_64bit_val(wqe, 40,
		      FIELD_PREP(ZXDH_CQPSQ_STAG_STAGLEN, info->total_len) |
			      FIELD_PREP(ZXDH_CQPSQ_STAG_MR_PDID_LOW, pd_l));

	addr_type = (info->addr_type == ZXDH_ADDR_TYPE_VA_BASED) ? 1 : 0;
	hdr = FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_REG_MR) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity) |
	      FIELD_PREP(ZXDH_CQPSQ_STAG_USEHMCFNIDX, info->use_hmc_fcn_index) |
	      FIELD_PREP(ZXDH_CQPSQ_STAG_HMCFNIDX, info->hmc_fcn_index) |
	      FIELD_PREP(ZXDH_CQPSQ_STAG_VABASEDTO, addr_type) |
	      FIELD_PREP(ZXDH_CQPSQ_STAG_SHARED, 0) |
	      FIELD_PREP(ZXDH_CQPSQ_STAG_ARIGHTS, info->access_rights) |
	      FIELD_PREP(ZXDH_CQPSQ_STAG_HPAGESIZE, page_size) |
	      FIELD_PREP(ZXDH_CQPSQ_STAG_LPBLSIZE, info->chunk_size) |
	      FIELD_PREP(ZXDH_CQPSQ_STAG_MR, 1) | FIELD_PREP(ZXDH_CQPSQ_STAG_MR_INVALID_EN, 0) |
	      FIELD_PREP(ZXDH_CQPSQ_STAG_MR_FORCE_DEL, 0);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	print_hex_dump_debug("WQE: MR_REG_NS WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);
	return 0;
}

/**
 * zxdh_sc_dealloc_stag - deallocate stag
 * @dev: sc device struct
 * @info: dealloc stag info
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int zxdh_sc_dealloc_stag(struct zxdh_sc_dev *dev, struct zxdh_dealloc_stag_info *info,
				u64 scratch, bool post_sq)
{
	u64 hdr;
	__le64 *wqe;
	struct zxdh_sc_cqp *cqp;
	u32 pd_h, pd_l;

	cqp = dev->cqp;
	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	pd_l = info->pd_id & 0x3FFFF;
	pd_h = (info->pd_id >> 18) & 0x03;

	set_64bit_val(wqe, 24,
		      FIELD_PREP(ZXDH_CQPSQ_STAG_IDX, info->stag_idx) |
			      FIELD_PREP(ZXDH_CQPSQ_STAG_MR_PDID_HIG, pd_h));

	set_64bit_val(wqe, 40, FIELD_PREP(ZXDH_CQPSQ_STAG_MR_PDID_LOW, pd_l));

	hdr = FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_DEALLOC_MKEY) |
	      FIELD_PREP(ZXDH_CQPSQ_STAG_MR, info->mr) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity) |
	      FIELD_PREP(ZXDH_CQPSQ_STAG_MR_FORCE_DEL, 0);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	print_hex_dump_debug("WQE: DEALLOC_STAG WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);
	return 0;
}

/**
 * zxdh_sc_mw_alloc - mw allocate
 * @dev: sc device struct
 * @info: memory window allocation information
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int zxdh_sc_mw_alloc(struct zxdh_sc_dev *dev, struct zxdh_mw_alloc_info *info, u64 scratch,
			    bool post_sq)
{
	u64 hdr;
	struct zxdh_sc_cqp *cqp;
	__le64 *wqe;
	u32 pd_h, pd_l;

	cqp = dev->cqp;
	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	pd_l = info->pd_id & 0x3FFFF;
	pd_h = (info->pd_id >> 18) & 0x03;

	hdr = FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_ALLOC_MKEY) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity) |
	      FIELD_PREP(ZXDH_CQPSQ_STAG_MWTYPE, info->mw_wide) |
	      FIELD_PREP(ZXDH_CQPSQ_STAG_MW1_BIND_DONT_VLDT_KEY, info->mw1_bind_dont_vldt_key) |
	      FIELD_PREP(ZXDH_CQPSQ_STAG_MR, 0);

	set_64bit_val(wqe, 24,
		      FIELD_PREP(ZXDH_CQPSQ_STAG_IDX, info->mw_stag_index) |
			      FIELD_PREP(ZXDH_CQPSQ_STAG_MR_PDID_HIG, pd_h));

	set_64bit_val(wqe, 40, FIELD_PREP(ZXDH_CQPSQ_STAG_MR_PDID_LOW, pd_l));

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	print_hex_dump_debug("WQE: MW_ALLOC WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * zxdh_sc_mr_fast_register - Posts RDMA fast register mr WR to iwarp qp
 * @qp: sc qp struct
 * @info: fast mr info
 * @post_sq: flag for cqp db to ring
 */
int zxdh_sc_mr_fast_register(struct zxdh_sc_qp *qp, struct zxdh_fast_reg_stag_info *info,
			     bool post_sq)
{
	u64 temp, hdr;
	__le64 *wqe;
	u32 wqe_idx;
	bool local_fence = true;
	enum zxdh_page_size page_size;
	struct zxdh_post_sq_info sq_info = {};

	if (info->page_size == 0x40000000)
		page_size = ZXDH_PAGE_SIZE_1G;
	else if (info->page_size == 0x200000)
		page_size = ZXDH_PAGE_SIZE_2M;
	else
		page_size = ZXDH_PAGE_SIZE_4K;

	sq_info.wr_id = info->wr_id;
	sq_info.signaled = info->signaled;

	wqe = zxdh_qp_get_next_send_wqe(&qp->qp_uk, &wqe_idx, ZXDH_QP_WQE_MIN_QUANTA, 0, &sq_info);
	if (!wqe)
		return -ENOSPC;

	zxdh_clr_wqes(&qp->qp_uk, wqe_idx);

	temp = (info->addr_type == ZXDH_ADDR_TYPE_VA_BASED) ? (uintptr_t)info->va : info->fbo;
	set_64bit_val(wqe, 8, temp);

	set_64bit_val(wqe, 16,
		      info->total_len |
			      FIELD_PREP(IRDMAQPSQ_FIRSTPMPBLIDXLO, info->first_pm_pbl_index));

	temp = info->first_pm_pbl_index >> 16;

	set_64bit_val(wqe, 24,
		      FIELD_PREP(IRDMAQPSQ_FIRSTPMPBLIDXHI, temp) |
			      FIELD_PREP(IRDMAQPSQ_PBLADDR,
					 info->reg_addr_pa >> ZXDH_HW_PAGE_SHIFT));

	hdr = FIELD_PREP(IRDMAQPSQ_STAGKEY, info->stag_key) |
	      FIELD_PREP(IRDMAQPSQ_STAGINDEX, info->stag_idx) |
	      FIELD_PREP(IRDMAQPSQ_LPBLSIZE, info->chunk_size) |
	      FIELD_PREP(IRDMAQPSQ_HPAGESIZE, page_size) |
	      FIELD_PREP(IRDMAQPSQ_STAGRIGHTS, info->access_rights) |
	      FIELD_PREP(IRDMAQPSQ_VABASEDTO, info->addr_type) |
	      FIELD_PREP(IRDMAQPSQ_READFENCE, info->read_fence) |
	      FIELD_PREP(IRDMAQPSQ_LOCALFENCE, local_fence) |
	      FIELD_PREP(IRDMAQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(IRDMAQPSQ_OPCODE, ZXDH_OP_TYPE_FAST_REG_MR) |
	      FIELD_PREP(IRDMAQPSQ_VALID, qp->qp_uk.swqe_polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	print_hex_dump_debug("WQE: FAST_REG WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_QP_WQE_MIN_SIZE, false);

	if (post_sq)
		zxdh_uk_qp_post_wr(&qp->qp_uk);

	return 0;
}

/**
 * zxdh_sc_dev_qplist_init - Init the qos qplist
 * @dev: pointer to dev
 */
void zxdh_sc_dev_qplist_init(struct zxdh_sc_dev *dev)
{
	u8 i;

	for (i = 0; i < ZXDH_MAX_USER_PRIORITY; i++) {
		mutex_init(&dev->qos[i].qos_mutex);
		INIT_LIST_HEAD(&dev->qos[i].qplist);
	}
}

/**
 * zxdh_get_encoded_wqe_size - given wq size, returns hardware encoded size
 * @wqsize: size of the wq (sq, rq) to encoded_size
 * @queue_type: queue type selected for the calculation algorithm
 */
u8 zxdh_get_encoded_wqe_size(u32 wqsize, enum zxdh_queue_type queue_type)
{
	u8 encoded_size = 0;

	/* cqp sq's hw coded value starts from 1 for size of 4
	 * while it starts from 0 for qp' wq's.
	 */
	if (queue_type == ZXDH_QUEUE_TYPE_CQP)
		encoded_size = 1;
	while (wqsize >>= 1)
		encoded_size++;

	return encoded_size;
}

/**
 * zxdh_sc_gather_stats - collect the statistics
 * @cqp: struct for cqp hw
 * @info: gather stats info structure
 * @scratch: u64 saved to be used during cqp completion
 */
static int zxdh_sc_gather_stats(struct zxdh_sc_cqp *cqp, struct zxdh_stats_gather_info *info,
				u64 scratch)
{
	__le64 *wqe;
	u64 temp;

	if (info->stats_buff_mem.size < ZXDH_GATHER_STATS_BUF_SIZE)
		return -ENOSPC;

	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	set_64bit_val(wqe, 40, FIELD_PREP(ZXDH_CQPSQ_STATS_HMC_FCN_INDEX, info->hmc_fcn_index));
	set_64bit_val(wqe, 32, info->stats_buff_mem.pa);

	temp = FIELD_PREP(ZXDH_CQPSQ_STATS_WQEVALID, cqp->polarity) |
	       FIELD_PREP(ZXDH_CQPSQ_STATS_USE_INST, info->use_stats_inst) |
	       FIELD_PREP(ZXDH_CQPSQ_STATS_INST_INDEX, info->stats_inst_index) |
	       FIELD_PREP(ZXDH_CQPSQ_STATS_USE_HMC_FCN_INDEX, info->use_hmc_fcn_index) |
	       FIELD_PREP(ZXDH_CQPSQ_STATS_OP, ZXDH_CQP_OP_GATHER_STATS);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, temp);

	print_hex_dump_debug("STATS: GATHER_STATS WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);

	zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * zxdh_sc_manage_stats_inst - allocate or free stats instance
 * @cqp: struct for cqp hw
 * @info: stats info structure
 * @alloc: alloc vs. delete flag
 * @scratch: u64 saved to be used during cqp completion
 */
static int zxdh_sc_manage_stats_inst(struct zxdh_sc_cqp *cqp, struct zxdh_stats_inst_info *info,
				     bool alloc, u64 scratch)
{
	__le64 *wqe;
	u64 temp;

	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	set_64bit_val(wqe, 40, FIELD_PREP(ZXDH_CQPSQ_STATS_HMC_FCN_INDEX, info->hmc_fn_id));
	temp = FIELD_PREP(ZXDH_CQPSQ_STATS_WQEVALID, cqp->polarity) |
	       FIELD_PREP(ZXDH_CQPSQ_STATS_ALLOC_INST, alloc) |
	       FIELD_PREP(ZXDH_CQPSQ_STATS_USE_HMC_FCN_INDEX, info->use_hmc_fcn_index) |
	       FIELD_PREP(ZXDH_CQPSQ_STATS_INST_INDEX, info->stats_idx) |
	       FIELD_PREP(ZXDH_CQPSQ_STATS_OP, ZXDH_CQP_OP_MANAGE_STATS);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, temp);

	print_hex_dump_debug("WQE: MANAGE_STATS WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);

	zxdh_sc_cqp_post_sq(cqp);
	return 0;
}

/**
 * zxdh_sc_set_up_map - set the up map table
 * @cqp: struct for cqp hw
 * @info: User priority map info
 * @scratch: u64 saved to be used during cqp completion
 */
static int zxdh_sc_set_up_map(struct zxdh_sc_cqp *cqp, struct zxdh_up_info *info, u64 scratch)
{
	__le64 *wqe;
	u64 temp;

	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	temp = info->map[0] | LS_64_1(info->map[1], 8) | LS_64_1(info->map[2], 16) |
	       LS_64_1(info->map[3], 24) | LS_64_1(info->map[4], 32) | LS_64_1(info->map[5], 40) |
	       LS_64_1(info->map[6], 48) | LS_64_1(info->map[7], 56);

	set_64bit_val(wqe, 0, temp);
	set_64bit_val(wqe, 40,
		      FIELD_PREP(ZXDH_CQPSQ_UP_CNPOVERRIDE, info->cnp_up_override) |
			      FIELD_PREP(ZXDH_CQPSQ_UP_HMCFCNIDX, info->hmc_fcn_idx));

	temp = FIELD_PREP(ZXDH_CQPSQ_UP_WQEVALID, cqp->polarity) |
	       FIELD_PREP(ZXDH_CQPSQ_UP_USEVLAN, info->use_vlan) |
	       FIELD_PREP(ZXDH_CQPSQ_UP_USEOVERRIDE, info->use_cnp_up_override) |
	       FIELD_PREP(ZXDH_CQPSQ_UP_OP, ZXDH_CQP_OP_UP_MAP);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, temp);

	print_hex_dump_debug("WQE: UPMAP WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * zxdh_sc_manage_ws_node - create/modify/destroy WS node
 * @cqp: struct for cqp hw
 * @info: node info structure
 * @node_op: 0 for add 1 for modify, 2 for delete
 * @scratch: u64 saved to be used during cqp completion
 */
static int zxdh_sc_manage_ws_node(struct zxdh_sc_cqp *cqp, struct zxdh_ws_node_info *info,
				  enum zxdh_ws_node_op node_op, u64 scratch)
{
	__le64 *wqe;
	u64 temp = 0;

	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	set_64bit_val(wqe, 32,
		      FIELD_PREP(ZXDH_CQPSQ_WS_VSI, info->vsi) |
			      FIELD_PREP(ZXDH_CQPSQ_WS_WEIGHT, info->weight));

	temp = FIELD_PREP(ZXDH_CQPSQ_WS_WQEVALID, cqp->polarity) |
	       FIELD_PREP(ZXDH_CQPSQ_WS_NODEOP, node_op) |
	       FIELD_PREP(ZXDH_CQPSQ_WS_ENABLENODE, info->enable) |
	       FIELD_PREP(ZXDH_CQPSQ_WS_NODETYPE, info->type_leaf) |
	       FIELD_PREP(ZXDH_CQPSQ_WS_PRIOTYPE, info->prio_type) |
	       FIELD_PREP(ZXDH_CQPSQ_WS_TC, info->tc) |
	       FIELD_PREP(ZXDH_CQPSQ_WS_OP, ZXDH_CQP_OP_WORK_SCHED_NODE) |
	       FIELD_PREP(ZXDH_CQPSQ_WS_PARENTID, info->parent_id) |
	       FIELD_PREP(ZXDH_CQPSQ_WS_NODEID, info->id);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, temp);

	print_hex_dump_debug("WQE: MANAGE_WS WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * zxdh_sc_qp_flush_wqes - flush qp's wqe
 * @qp: sc qp
 * @info: dlush information
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
int zxdh_sc_qp_flush_wqes(struct zxdh_sc_qp *qp, struct zxdh_qp_flush_info *info, u64 scratch,
			  bool post_sq)
{
	u64 temp = 0;
	__le64 *wqe;
	struct zxdh_sc_cqp *cqp;
	u64 hdr;
	bool flush_sq = false, flush_rq = false;

	if (info->rq && !qp->flush_rq)
		flush_rq = true;
	if (info->sq && !qp->flush_sq)
		flush_sq = true;
	qp->flush_sq |= flush_sq;
	qp->flush_rq |= flush_rq;

	if (!flush_sq && !flush_rq) {
		pr_err("CQP: Additional flush request ignored for qp %x\n", qp->qp_uk.qp_id);
		return -EALREADY;
	}

	cqp = qp->pd->dev->cqp;
	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	if (info->userflushcode) {
		if (flush_rq)
			temp |= FIELD_PREP(ZXDH_CQPSQ_FWQE_RQMNERR, info->rq_minor_code) |
				FIELD_PREP(ZXDH_CQPSQ_FWQE_RQMJERR, info->rq_major_code);
		if (flush_sq)
			temp |= FIELD_PREP(ZXDH_CQPSQ_FWQE_SQMNERR, info->sq_minor_code) |
				FIELD_PREP(ZXDH_CQPSQ_FWQE_SQMJERR, info->sq_major_code);
	}
	set_64bit_val(wqe, 8, temp);

	temp = (info->generate_ae) ?
			     info->ae_code | FIELD_PREP(ZXDH_CQPSQ_FWQE_AESOURCE, info->ae_src) :
			     0;
	set_64bit_val(wqe, 16, temp);

	hdr = qp->qp_uk.qp_id | FIELD_PREP(ZXDH_CQPSQ_FWQE_GENERATE_AE, info->generate_ae) |
	      FIELD_PREP(ZXDH_CQPSQ_FWQE_USERFLCODE, info->userflushcode) |
	      FIELD_PREP(ZXDH_CQPSQ_FWQE_FLUSHSQ, flush_sq) |
	      FIELD_PREP(ZXDH_CQPSQ_FWQE_FLUSHRQ, flush_rq) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity) |
	      FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_FLUSH_WQES);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	print_hex_dump_debug("WQE: QP_FLUSH WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * zxdh_sc_gen_ae - generate AE, uses flush WQE CQP OP
 * @qp: sc qp
 * @info: gen ae information
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int zxdh_sc_gen_ae(struct zxdh_sc_qp *qp, struct zxdh_gen_ae_info *info, u64 scratch,
			  bool post_sq)
{
	u64 temp;
	__le64 *wqe;
	struct zxdh_sc_cqp *cqp;
	u64 hdr;

	cqp = qp->pd->dev->cqp;
	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	temp = info->ae_code | FIELD_PREP(ZXDH_CQPSQ_FWQE_AESOURCE, info->ae_src);
	set_64bit_val(wqe, 8, temp);

	hdr = qp->qp_uk.qp_id | FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_GEN_AE) |
	      FIELD_PREP(ZXDH_CQPSQ_FWQE_GENERATE_AE, 1) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: GEN_AE WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

/*** zxdh_sc_qp_upload_context - upload qp's context
 * @dev: sc device struct
 * @info: upload context info ptr for return
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int zxdh_sc_qp_upload_context(struct zxdh_sc_dev *dev, struct zxdh_upload_context_info *info,
				     u64 scratch, bool post_sq)
{
	__le64 *wqe;
	struct zxdh_sc_cqp *cqp;
	u64 hdr;

	cqp = dev->cqp;
	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	set_64bit_val(wqe, 16, info->buf_pa);

	hdr = FIELD_PREP(ZXDH_CQPSQ_UCTX_QPID, info->qp_id) |
	      FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_UPLOAD_QPC) |
	      FIELD_PREP(ZXDH_CQPSQ_UCTX_QPTYPE, info->qp_type) |
	      FIELD_PREP(ZXDH_CQPSQ_UCTX_RAWFORMAT, info->raw_format) |
	      FIELD_PREP(ZXDH_CQPSQ_UCTX_FREEZEQP, info->freeze_qp) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: QP_UPLOAD_CTX WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * zxdh_sc_manage_push_page - Handle push page
 * @cqp: struct for cqp hw
 * @info: push page info
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int zxdh_sc_manage_push_page(struct zxdh_sc_cqp *cqp,
				    struct zxdh_cqp_manage_push_page_info *info, u64 scratch,
				    bool post_sq)
{
	__le64 *wqe;
	u64 hdr;

	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	set_64bit_val(wqe, 16, info->qs_handle);
	hdr = FIELD_PREP(ZXDH_CQPSQ_MPP_PPTYPE, info->push_page_type) |
	      FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_MANAGE_PUSH_PAGES) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity) |
	      FIELD_PREP(ZXDH_CQPSQ_MPP_FREE_PAGE, info->free_page);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: MANAGE_PUSH_PAGES WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * zxdh_sc_suspend_qp - suspend qp for param change
 * @cqp: struct for cqp hw
 * @qp: sc qp struct
 * @scratch: u64 saved to be used during cqp completion
 */
static int zxdh_sc_suspend_qp(struct zxdh_sc_cqp *cqp, struct zxdh_sc_qp *qp, u64 scratch)
{
	u64 hdr;
	__le64 *wqe;

	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	hdr = FIELD_PREP(ZXDH_CQPSQ_SUSPENDQP_QPID, qp->qp_uk.qp_id) |
	      FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_SUSPEND_QP) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: SUSPEND_QP WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * zxdh_sc_resume_qp - resume qp after suspend
 * @cqp: struct for cqp hw
 * @qp: sc qp struct
 * @scratch: u64 saved to be used during cqp completion
 */
static int zxdh_sc_resume_qp(struct zxdh_sc_cqp *cqp, struct zxdh_sc_qp *qp, u64 scratch)
{
	u64 hdr;
	__le64 *wqe;

	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	set_64bit_val(wqe, 16, FIELD_PREP(ZXDH_CQPSQ_RESUMEQP_QSHANDLE, qp->qs_handle));

	hdr = FIELD_PREP(ZXDH_CQPSQ_RESUMEQP_QPID, qp->qp_uk.qp_id) |
	      FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_RESUME_QP) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: RESUME_QP WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * zxdh_sc_cq_init - initialize completion q
 * @cq: cq struct
 * @info: cq initialization info
 */
int zxdh_sc_cq_init(struct zxdh_sc_cq *cq, struct zxdh_cq_init_info *info)
{
	u32 pble_obj_cnt;

	pble_obj_cnt = info->dev->hmc_info->hmc_obj[ZXDH_HMC_IW_PBLE].cnt;
	if (info->virtual_map && info->first_pm_pbl_idx >= pble_obj_cnt)
		return -EINVAL;

	cq->cq_pa = info->cq_base_pa;
	cq->dev = info->dev;
	cq->ceq_id = info->ceq_id;
	cq->ceq_index = info->ceq_index;
	info->cq_uk_init_info.cqe_alloc_db = cq->dev->cq_arm_db;
	zxdh_uk_cq_init(&cq->cq_uk, &info->cq_uk_init_info);

	cq->virtual_map = info->virtual_map;
	cq->pbl_chunk_size = info->pbl_chunk_size;
	cq->ceqe_mask = info->ceqe_mask;
	cq->cq_type = (info->type) ? info->type : ZXDH_CQ_TYPE_IO;
	cq->shadow_area_pa = info->shadow_area_pa;
	cq->shadow_read_threshold = info->shadow_read_threshold;
	cq->ceq_id_valid = info->ceq_id_valid;
	cq->tph_en = info->tph_en;
	cq->tph_val = info->tph_val;
	cq->first_pm_pbl_idx = info->first_pm_pbl_idx;

	return 0;
}

/**
 * zxdh_sc_cq_create - create completion q
 * @cq: cq struct
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int zxdh_sc_cq_create(struct zxdh_sc_cq *cq, u64 scratch, bool post_sq)
{
	__le64 *wqe;
	struct zxdh_sc_cqp *cqp;
	u64 temp;
	u64 hdr;
	struct zxdh_sc_ceq *ceq;
	int ret_code = 0;

	cqp = cq->dev->cqp;
	if (cq->cq_uk.cq_id >
	    (cqp->dev->base_cqn + cqp->dev->hmc_info->hmc_obj[ZXDH_HMC_IW_CQ].max_cnt - 1))
		return -EINVAL;

	if (cq->ceq_index > (cq->dev->max_ceqs - 1))
		return -EINVAL;

	ceq = cq->dev->ceq[cq->ceq_index];
	if (ceq && ceq->reg_cq)
		ret_code = zxdh_sc_add_cq_ctx(ceq, cq);

	if (ret_code)
		return ret_code;

	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe) {
		if (ceq && ceq->reg_cq)
			zxdh_sc_remove_cq_ctx(ceq, cq);
		return -ENOSPC;
	}

	set_64bit_val(wqe, 8, FIELD_PREP(ZXDH_CQPSQ_CQ_CQC_SET_MASK, ZXDH_CQC_SET_FIELD_ALL));
	temp = FIELD_PREP(ZXDH_CQPSQ_CQ_CQSTATE, 1) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_OVERFLOW_LOCKED_FLAG, 0) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_CQESIZE, cq->cq_uk.cqe_size) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_LPBLSIZE, cq->pbl_chunk_size) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_ENCEQEMASK, cq->ceqe_mask) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_DEBUG_SET, cq->dev->vhca_id) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_VHCAID, cq->dev->vhca_id) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_CQMAX, cq->cq_max) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_CQPERIOD, cq->cq_period) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_SCQE_BREAK_MODERATION_EN, cq->scqe_break_moderation_en);

	dma_wmb();
	set_64bit_val(wqe, 16, temp);
	set_64bit_val(wqe, 24, RS_64_1(cq->shadow_area_pa, 6));

	temp = FIELD_PREP(ZXDH_CQPSQ_CQ_CEQ_ID, (cq->ceq_id_valid ? cq->ceq_id : 0)) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_ST, cq->cq_st) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_IS_IN_LIST_CNT, cq->is_in_list_cnt) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_CQSIZE, cq->cq_uk.cq_log_size) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_SHADOW_READ_THRESHOLD, cq->shadow_read_threshold);

	dma_wmb();
	set_64bit_val(wqe, 32, temp);
	set_64bit_val(wqe, 40, 0); // hw self-maintenance field
	set_64bit_val(wqe, 48, cq->virtual_map ? cq->first_pm_pbl_idx : RS_64_1(cq->cq_pa, 8));
	set_64bit_val(wqe, 56, RS_64_1(cq, 1));
	hdr = FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_CREATE_CQ) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity) |
	      FLD_LS_64(cq->dev, cq->cq_uk.cq_id, ZXDH_CQPSQ_CQ_CQID);

	dma_wmb();
	set_64bit_val(wqe, 0, hdr);

	print_hex_dump_debug("WQE: CQ_CREATE WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * zxdh_sc_cq_destroy - destroy completion q
 * @cq: cq struct
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
int zxdh_sc_cq_destroy(struct zxdh_sc_cq *cq, u64 scratch, bool post_sq)
{
	struct zxdh_sc_cqp *cqp;
	__le64 *wqe;
	u64 hdr;
	struct zxdh_sc_ceq *ceq;

	cqp = cq->dev->cqp;
	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	ceq = cq->dev->ceq[cq->ceq_index];
	if (ceq && ceq->reg_cq)
		zxdh_sc_remove_cq_ctx(ceq, cq);

	if (cq->cq_overflow_locked_flag)
		set_64bit_val(wqe, 8,
			      FIELD_PREP(ZXDH_CQPSQ_CQ_CQC_SET_MASK, ZXDH_CQC_SET_FIELD_ALL));
	else
		set_64bit_val(wqe, 8,
			      FIELD_PREP(ZXDH_CQPSQ_CQ_CQC_SET_MASK, ZXDH_CQC_SET_CQ_STATE));

	set_64bit_val(wqe, 16, 0);
	set_64bit_val(wqe, 24, 0);
	set_64bit_val(wqe, 32, 0);
	set_64bit_val(wqe, 40, 0);
	set_64bit_val(wqe, 48, 0);
	set_64bit_val(wqe, 56, 0);

	hdr = FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_DESTROY_CQ) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity) |
	      FLD_LS_64(cq->dev, cq->cq_uk.cq_id, ZXDH_CQPSQ_CQ_CQID);

	dma_wmb();
	set_64bit_val(wqe, 0, hdr);

	print_hex_dump_debug("WQE: CQ_DESTROY WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * zxdh_sc_cq_resize - set resized cq buffer info
 * @cq: resized cq
 * @info: resized cq buffer info
 */
void zxdh_sc_cq_resize(struct zxdh_sc_cq *cq, struct zxdh_modify_cq_info *info)
{
	cq->virtual_map = info->virtual_map;
	cq->cq_pa = info->cq_pa;
	cq->first_pm_pbl_idx = info->first_pm_pbl_idx;
	cq->pbl_chunk_size = info->pbl_chunk_size;
	zxdh_uk_cq_resize(&cq->cq_uk, info->cq_base, info->cq_size);
}

/**
 * zxdh_sc_cq_modify - modify a Completion Queue
 * @cq: cq struct
 * @info: modification info struct
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag to post to sq
 */
static int zxdh_sc_cq_modify(struct zxdh_sc_cq *cq, struct zxdh_modify_cq_info *info, u64 scratch,
			     bool post_sq)
{
	struct zxdh_sc_cqp *cqp;
	__le64 *wqe;
	u64 hdr;
	u64 temp;
	u32 pble_obj_cnt;

	pble_obj_cnt = cq->dev->hmc_info->hmc_obj[ZXDH_HMC_IW_PBLE].cnt;
	if (info->cq_resize && info->virtual_map && info->first_pm_pbl_idx >= pble_obj_cnt)
		return -EINVAL;

	cqp = cq->dev->cqp;
	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	set_64bit_val(wqe, 8, FIELD_PREP(ZXDH_CQPSQ_CQ_CQC_SET_MASK, ZXDH_CQC_SET_FIELD_RESIZE));
	temp = FIELD_PREP(ZXDH_CQPSQ_CQ_CQSTATE, 1) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_OVERFLOW_LOCKED_FLAG, 0) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_CQESIZE, cq->cq_uk.cqe_size) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_LPBLSIZE, info->pbl_chunk_size) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_ENCEQEMASK, cq->ceqe_mask) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_DEBUG_SET, cq->dev->vhca_id) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_VHCAID, cq->dev->vhca_id) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_CQMAX, cq->cq_max) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_CQPERIOD, cq->cq_period) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_SCQE_BREAK_MODERATION_EN, cq->scqe_break_moderation_en);

	dma_wmb();
	set_64bit_val(wqe, 16, temp);
	set_64bit_val(wqe, 24, RS_64_1(cq->shadow_area_pa, 6));

	temp = FIELD_PREP(ZXDH_CQPSQ_CQ_CEQ_ID, (cq->ceq_id_valid ? cq->ceq_id : 0)) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_ST, cq->cq_st) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_IS_IN_LIST_CNT, cq->is_in_list_cnt) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_CQSIZE, zxdh_num_to_log(info->cq_size)) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_SHADOW_READ_THRESHOLD, cq->shadow_read_threshold);

	dma_wmb();
	set_64bit_val(wqe, 32, temp);
	set_64bit_val(wqe, 40, 0); // hw self-maintenance field
	set_64bit_val(wqe, 48,
		      info->virtual_map ? info->first_pm_pbl_idx : RS_64_1(info->cq_pa, 8));
	set_64bit_val(wqe, 56, RS_64_1(cq, 1));
	hdr = FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_MODIFY_CQ) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity) |
	      FIELD_PREP(ZXDH_CQPSQ_CQ_MODIFY_SIZE, 1) |
	      FLD_LS_64(cq->dev, cq->cq_uk.cq_id, ZXDH_CQPSQ_CQ_CQID);

	dma_wmb();
	set_64bit_val(wqe, 0, hdr);

	print_hex_dump_debug("WQE: CQ_MODIFY WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * zxdh_sc_modify_cq_moderation - modify cq_count and cq_period of a Completion Queue
 * @cq: cq struct
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag to post to sq
 */
static int zxdh_sc_modify_cq_moderation(struct zxdh_sc_cq *cq, u64 scratch, bool post_sq)
{
	struct zxdh_sc_cqp *cqp;
	__le64 *wqe;
	u64 hdr;
	u64 temp;

	cqp = cq->dev->cqp;
	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	set_64bit_val(wqe, 8, FIELD_PREP(ZXDH_CQPSQ_CQ_CQC_SET_MASK, ZXDH_CQC_SET_FIELD_MODIFY));
	temp = FIELD_PREP(ZXDH_CQPSQ_CQ_CQMAX, cq->cq_max) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_CQPERIOD, cq->cq_period) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_SCQE_BREAK_MODERATION_EN, cq->scqe_break_moderation_en);

	dma_wmb();
	set_64bit_val(wqe, 16, temp);

	hdr = FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_MODIFY_CQ) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity) |
	      FIELD_PREP(ZXDH_CQPSQ_CQ_MODIFY_SIZE, 0) |
	      FLD_LS_64(cq->dev, cq->cq_uk.cq_id, ZXDH_CQPSQ_CQ_CQID);

	dma_wmb();
	set_64bit_val(wqe, 0, hdr);

	print_hex_dump_debug("WQE: CQ_MODIFY WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * zxdh_check_cqp_progress - check cqp processing progress
 * @timeout: timeout info struct
 * @dev: sc device struct
 */
void zxdh_check_cqp_progress(struct zxdh_cqp_timeout *timeout, struct zxdh_sc_dev *dev)
{
	if (timeout->compl_cqp_cmds != dev->cqp_cmd_stats[ZXDH_OP_CMPL_CMDS]) {
		timeout->compl_cqp_cmds = dev->cqp_cmd_stats[ZXDH_OP_CMPL_CMDS];
		timeout->count = 0;
	} else {
		if (dev->cqp_cmd_stats[ZXDH_OP_REQ_CMDS] != timeout->compl_cqp_cmds)
			timeout->count++;
	}
}

/**
 * zxdh_get_cqp_reg_info - get head and tail for cqp using registers
 * @cqp: struct for cqp hw
 * @val: cqp tail register value
 * @tail: wqtail register value
 * @error: cqp processing err
 */
static inline void zxdh_get_cqp_reg_info(struct zxdh_sc_cqp *cqp, u32 *val, u32 *tail, u32 *error)
{
	*val = readl(cqp->dev->hw->hw_addr + C_RDMA_CQP_TAIL);
	*tail = (u32)FIELD_GET(ZXDH_CQPTAIL_WQTAIL, *val);
	*error = readl(cqp->dev->hw->hw_addr + C_RDMA_CQP_ERROR);
}

/**
 * zxdh_cqp_poll_registers - poll cqp registers
 * @cqp: struct for cqp hw
 * @tail: wqtail register value
 * @count: how many times to try for completion
 */
int zxdh_cqp_poll_registers(struct zxdh_sc_cqp *cqp, u32 tail, u32 count)
{
	u32 i = 0;
	u32 newtail, error, val;
	struct zxdh_pci_f *rf = container_of(cqp->dev, struct zxdh_pci_f, sc_dev);

	while (i++ < count) {
		zxdh_get_cqp_reg_info(cqp, &val, &newtail, &error);
		if (error) {
			error = readl(cqp->dev->hw->hw_addr + C_RDMA_CQP_ERRCODE);
			if (cqp->dev->hw_attrs.self_health == false)
				pr_err("CQP: CQPERRCODES error_code[x%08X]\n", error);
			return -EIO;
		}
		if (newtail != tail) {
			/* SUCCESS */
			if (cqp->sq_ring.head == cqp->sq_ring.tail)
				pr_info("[%s] cqp_err init_state:%d vhca_id:%d head:%d tail:%d\n",
					__func__, rf->init_state, cqp->dev->vhca_id,
					cqp->sq_ring.head, cqp->sq_ring.tail);

			ZXDH_RING_MOVE_TAIL(cqp->sq_ring);
			cqp->dev->cqp_cmd_stats[ZXDH_OP_CMPL_CMDS]++;
			return 0;
		}
		udelay(cqp->dev->hw_attrs.max_sleep_count);
	}

	return -ETIMEDOUT;
}

/**
 * zxdh_sc_find_reg_cq - find cq ctx index
 * @ceq: ceq sc structure
 * @cq: cq sc structure
 */
static u32 zxdh_sc_find_reg_cq(struct zxdh_sc_ceq *ceq, struct zxdh_sc_cq *cq)
{
	u32 i;

	for (i = 0; i < ceq->reg_cq_size; i++) {
		if (cq == ceq->reg_cq[i])
			return i;
	}

	return ZXDH_INVALID_CQ_IDX;
}

/**
 * zxdh_sc_add_cq_ctx - add cq ctx tracking for ceq
 * @ceq: ceq sc structure
 * @cq: cq sc structure
 */
int zxdh_sc_add_cq_ctx(struct zxdh_sc_ceq *ceq, struct zxdh_sc_cq *cq)
{
	unsigned long flags;

	spin_lock_irqsave(&ceq->req_cq_lock, flags);

	if (ceq->reg_cq_size == ceq->elem_cnt) {
		spin_unlock_irqrestore(&ceq->req_cq_lock, flags);
		return -ENOSPC;
	}

	ceq->reg_cq[ceq->reg_cq_size++] = cq;

	spin_unlock_irqrestore(&ceq->req_cq_lock, flags);

	return 0;
}

/**
 * zxdh_sc_remove_cq_ctx - remove cq ctx tracking for ceq
 * @ceq: ceq sc structure
 * @cq: cq sc structure
 */
void zxdh_sc_remove_cq_ctx(struct zxdh_sc_ceq *ceq, struct zxdh_sc_cq *cq)
{
	unsigned long flags;
	u32 cq_ctx_idx;

	spin_lock_irqsave(&ceq->req_cq_lock, flags);
	cq_ctx_idx = zxdh_sc_find_reg_cq(ceq, cq);
	if (cq_ctx_idx == ZXDH_INVALID_CQ_IDX)
		goto exit;

	ceq->reg_cq_size--;
	if (cq_ctx_idx != ceq->reg_cq_size)
		ceq->reg_cq[cq_ctx_idx] = ceq->reg_cq[ceq->reg_cq_size];
	ceq->reg_cq[ceq->reg_cq_size] = NULL;

exit:
	spin_unlock_irqrestore(&ceq->req_cq_lock, flags);
}

/**
 * zxdh_sc_cqp_init - Initialize buffers for a control Queue Pair
 * @cqp: IWARP control queue pair pointer
 * @info: IWARP control queue pair init info pointer
 *
 * Initializes the object and context buffers for a control Queue Pair.
 */
int zxdh_sc_cqp_init(struct zxdh_sc_cqp *cqp, struct zxdh_cqp_init_info *info)
{
	u8 hw_sq_size;

	if (info->sq_size > ZXDH_CQP_SW_SQSIZE_2048 || info->sq_size < ZXDH_CQP_SW_SQSIZE_4 ||
	    ((info->sq_size & (info->sq_size - 1))))
		return -EINVAL;

	hw_sq_size = zxdh_get_encoded_wqe_size(info->sq_size, ZXDH_QUEUE_TYPE_CQP);
	cqp->size = sizeof(*cqp);
	cqp->sq_size = info->sq_size;
	cqp->hw_sq_size = hw_sq_size;
	cqp->sq_base = info->sq;
	cqp->sq_pa = info->sq_pa;
	cqp->dev = info->dev;
	cqp->struct_ver = info->struct_ver;
	cqp->hw_maj_ver = info->hw_maj_ver;
	cqp->hw_min_ver = info->hw_min_ver;
	cqp->scratch_array = info->scratch_array;
	cqp->polarity = 0;
	cqp->en_datacenter_tcp = info->en_datacenter_tcp;
	cqp->ena_vf_count = info->ena_vf_count;
	cqp->hmc_profile = info->hmc_profile;
	cqp->ceqs_per_vf = info->ceqs_per_vf;
	cqp->disable_packed = info->disable_packed;
	cqp->rocev2_rto_policy = info->rocev2_rto_policy;
	cqp->protocol_used = info->protocol_used;
	cqp->state_cfg = true; // CQP Create: true, CQP Destroy: false
	memcpy(&cqp->dcqcn_params, &info->dcqcn_params, sizeof(cqp->dcqcn_params));
	info->dev->cqp = cqp;

	ZXDH_RING_INIT(cqp->sq_ring, cqp->sq_size);
	cqp->dev->cqp_cmd_stats[ZXDH_OP_REQ_CMDS] = 0;
	cqp->dev->cqp_cmd_stats[ZXDH_OP_CMPL_CMDS] = 0;
	/* for the cqp commands backlog. */
	INIT_LIST_HEAD(&cqp->dev->cqp_cmd_head);

	writel(ZXDH_CQPDB_INIT_VALUE, (u32 __iomem *)(cqp->dev->hw->hw_addr + C_RDMA_CQP_DB));
	writel(0, (u32 __iomem *)(cqp->dev->hw->hw_addr + C_RDMA_CQP_MGC_BASE_HIGH));
	writel(0, (u32 __iomem *)(cqp->dev->hw->hw_addr + C_RDMA_CQP_MGC_BASE_LOW));
	writel(0, (u32 __iomem *)(cqp->dev->hw->hw_addr + C_RDMA_CQP_AH_CACHE_ID));
	writel(0, (u32 __iomem *)(cqp->dev->hw->hw_addr + C_RDMA_CQP_MGC_INDICATE_ID));
	writel(0, (u32 __iomem *)(cqp->dev->hw->hw_addr + C_RDMA_CQP_CQ_DISTRIBUTE_DONE));

	return 0;
}

/**
 * zxdh_sc_cqp_create - create cqp during bringup
 * @cqp: struct for cqp hw
 * @maj_err: If error, major err number
 * @min_err: If error, minor err number
 */
int zxdh_sc_cqp_create(struct zxdh_sc_cqp *cqp, u16 *maj_err, u16 *min_err)
{
	u32 temp;
	u32 cnt = 0, val = 0, err_code;
	int ret_code;
	struct zxdh_pci_f *rf = container_of(cqp->dev, struct zxdh_pci_f, sc_dev);

	spin_lock_init(&cqp->dev->cqp_lock);

	//reset CQP status
	writel(0, (u32 __iomem *)(cqp->dev->hw->hw_addr + C_RDMA_CQP_CONFIG_DONE));
	mdelay(5);

	do {
		if (cnt++ > cqp->dev->hw_attrs.max_done_count) {
			ret_code = -ETIMEDOUT;
			pr_info("%s reset cqp timeout!\n", __func__);
			break;
		}
		udelay(cqp->dev->hw_attrs.max_sleep_count);
		val = readl((u32 __iomem *)(cqp->dev->hw->hw_addr + C_RDMA_CQP_STATUS));
	} while (val & 0x01);
	cnt = 0;

	// VF_PF_ID
	temp = (u32)(FIELD_PREP(ZXDH_CQP_CREATE_EPID, (rf->ep_id + ZXDH_HOST_EP0_ID)) |
		     FIELD_PREP(ZXDH_CQP_CREATE_VFID, rf->vf_id) |
		     FIELD_PREP(ZXDH_CQP_CREATE_PFID, rf->pf_id) |
		     FIELD_PREP(ZXDH_CQP_CREATE_VFUNC_ACTIVE, rf->ftype));
	writel(temp,
	       (u32 __iomem *)(cqp->dev->hw->hw_addr + C_RDMA_CQP_PF_VF_ID(cqp->dev->vhca_id)));

	// CQP_Context_0
	temp = (u32)(FIELD_PREP(ZXDH_CQP_CREATE_STATE_CFG, cqp->state_cfg) |
		     FIELD_PREP(ZXDH_CQP_CREATE_SQSIZE, cqp->sq_size) |
		     FIELD_PREP(ZXDH_CQP_CREATE_QPC_OBJ_IDX, 11) |
		     FIELD_PREP(ZXDH_CQP_CREATE_QPC_INDICATE_IDX, 2) |
		     FIELD_PREP(ZXDH_CQP_CREATE_OBJ_IDX, 11) |
		     FIELD_PREP(ZXDH_CQP_CREATE_INDICATE_IDX, 2));
	writel(temp, (u32 __iomem *)(cqp->dev->hw->hw_addr + C_RDMA_CQP_CONTEXT_0));
	// CQP_Context_1
	writel(cqp->dev->base_qpn, (u32 __iomem *)(cqp->dev->hw->hw_addr + C_RDMA_CQP_CONTEXT_1));
	// CQP_Context_2
	temp = (u32)FIELD_GET(ZXDH_CQPADDR_HIGH, cqp->sq_pa);
	writel(temp, (u32 __iomem *)(cqp->dev->hw->hw_addr + C_RDMA_CQP_CONTEXT_2));
	// CQP_Context_3
	temp = (u32)FIELD_GET(ZXDH_CQPADDR_LOW, cqp->sq_pa);
	writel(temp, (u32 __iomem *)(cqp->dev->hw->hw_addr + C_RDMA_CQP_CONTEXT_3));
	// CQP_Context_4
	temp = (u32)FIELD_GET(ZXDH_CQPADDR_HIGH, (uintptr_t)cqp);
	writel(temp, (u32 __iomem *)(cqp->dev->hw->hw_addr + C_RDMA_CQP_CONTEXT_4));
	// CQP_Context_5
	temp = (u32)FIELD_GET(ZXDH_CQPADDR_LOW, (uintptr_t)cqp);
	writel(temp, (u32 __iomem *)(cqp->dev->hw->hw_addr + C_RDMA_CQP_CONTEXT_5));

	// CQP_CQ_NUM INIT
	writel(ZXDH_CCQN_INIT_VALUE, (u32 __iomem *)(cqp->dev->hw->hw_addr + C_RDMA_CQP_CQ_NUM));

	wmb(); /* make sure WQE is populated before valid bit is set */
	// CQP_Config_Done
	writel(1, (u32 __iomem *)(cqp->dev->hw->hw_addr + C_RDMA_CQP_CONFIG_DONE));

#ifdef ZXDH_DEBUG
	writel(1, (u32 __iomem *)(cqp->dev->hw->hw_addr + C_RDMA_CQP_STATUS));
#endif

	do {
		if (cnt++ > cqp->dev->hw_attrs.max_done_count) {
			ret_code = -ETIMEDOUT;
			goto err;
		}
		udelay(cqp->dev->hw_attrs.max_sleep_count);
		val = readl((u32 __iomem *)(cqp->dev->hw->hw_addr + C_RDMA_CQP_STATUS));
	} while (!val);

	if (FLD_RS_32(cqp->dev, val, ZXDH_CCQPSTATUS_CCQP_ERR)) {
		ret_code = -EOPNOTSUPP;
		goto err;
	}

	cqp->process_config_pte_table = zxdh_sc_config_pte_table;
	writel(0, (u32 __iomem *)(cqp->dev->hw->hw_addr + C_RDMA_CQP_CQ_NUM));

	return 0;
err:
	err_code = readl((u32 __iomem *)(cqp->dev->hw->hw_addr + C_RDMA_CQP_ERRCODE));
	*min_err = (u16)FIELD_GET(ZXDH_CQPERRCODES_CQP_MINOR_CODE, err_code);
	*maj_err = (u16)FIELD_GET(ZXDH_CQPERRCODES_CQP_MAJOR_CODE, err_code);
	return ret_code;
}

/**
 * zxdh_sc_cqp_post_sq - post of cqp's sq
 * @cqp: struct for cqp hw
 */
void zxdh_sc_cqp_post_sq(struct zxdh_sc_cqp *cqp)
{
	u32 hdr;
	u8 polarity = 0;

	polarity = ((ZXDH_RING_CURRENT_HEAD(cqp->sq_ring) == 0) ? !cqp->polarity : cqp->polarity);
	hdr = FIELD_PREP(ZXDH_CQPSQ_DBPOLARITY, polarity) |
	      FIELD_PREP(ZXDH_CQPSQ_DBRINGHEAD, ZXDH_RING_CURRENT_HEAD(cqp->sq_ring));

	dma_wmb();

	writel(hdr, cqp->dev->cqp_db);
}
/**
 * zxdh_sc_cqp_get_next_send_wqe_idx - get next wqe on cqp sq
 * and pass back index
 * @cqp: CQP HW structure
 * @scratch: private data for CQP WQE
 * @wqe_idx: WQE index of CQP SQ
 */
__le64 *zxdh_sc_cqp_get_next_send_wqe_idx(struct zxdh_sc_cqp *cqp, u64 scratch, u32 *wqe_idx)
{
	__le64 *wqe = NULL;
	int ret_code;

	if (ZXDH_RING_FULL_ERR(cqp->sq_ring)) {
		if (cqp->dev->hw_attrs.self_health == false)
			pr_err("WQE: CQP SQ is full, head 0x%x tail 0x%x size 0x%x\n",
			       cqp->sq_ring.head, cqp->sq_ring.tail, cqp->sq_ring.size);
		return NULL;
	}
	ZXDH_ATOMIC_RING_MOVE_HEAD(cqp->sq_ring, *wqe_idx, ret_code);
	if (ret_code)
		return NULL;

	cqp->dev->cqp_cmd_stats[ZXDH_OP_REQ_CMDS]++;
	if (!*wqe_idx)
		cqp->polarity = !cqp->polarity;
	wqe = cqp->sq_base[*wqe_idx].elem;
	cqp->scratch_array[*wqe_idx] = scratch;

	memset(&wqe[0], 0, 24);
	memset(&wqe[4], 0, 32);

	return wqe;
}

/**
 * zxdh_sc_cqp_destroy - destroy cqp during close
 * @cqp: struct for cqp hw
 * @free_hwcqp: true for regular cqp destroy; false for reset path
 */
int zxdh_sc_cqp_destroy(struct zxdh_sc_cqp *cqp, bool free_hwcqp)
{
	u32 cnt = 0, val;
	int ret_code = 0;

	if (free_hwcqp) {
		writel(0, (u32 __iomem *)(cqp->dev->hw->hw_addr + C_RDMA_CQP_CONFIG_DONE));
		do {
			if (cnt++ > cqp->dev->hw_attrs.max_done_count) {
				ret_code = -ETIMEDOUT;
				break;
			}
			udelay(cqp->dev->hw_attrs.max_sleep_count);
			val = readl((u32 __iomem *)(cqp->dev->hw->hw_addr + C_RDMA_CQP_STATUS));
		} while (FLD_RS_32(cqp->dev, val, ZXDH_CCQPSTATUS_CCQP_DONE));
	}
	return ret_code;
}

/**
 * zxdh_sc_ccq_arm - enable intr for control cq
 * @ccq: ccq sc struct
 */
void zxdh_sc_ccq_arm(struct zxdh_sc_cq *ccq)
{
	u64 temp_val;
	u16 sw_cq_sel;
	u8 arm_seq_num;
	u32 cqe_index;
	u32 hdr;

	get_64bit_val(ccq->cq_uk.shadow_area, 0, &temp_val);
	sw_cq_sel = (u16)FIELD_GET(ZXDH_CQ_DBSA_SW_CQ_SELECT, temp_val);
	arm_seq_num = (u8)FIELD_GET(ZXDH_CQ_DBSA_ARM_SEQ_NUM, temp_val);
	arm_seq_num++;
	cqe_index = (u32)FIELD_GET(ZXDH_CQ_DBSA_CQEIDX, temp_val);

	temp_val = FIELD_PREP(ZXDH_CQ_DBSA_ARM_SEQ_NUM, arm_seq_num) |
		   FIELD_PREP(ZXDH_CQ_DBSA_SW_CQ_SELECT, sw_cq_sel) |
		   FIELD_PREP(ZXDH_CQ_DBSA_ARM_NEXT, 0) |
		   FIELD_PREP(ZXDH_CQ_DBSA_CQEIDX, cqe_index);

	set_64bit_val(ccq->cq_uk.shadow_area, 0, temp_val);

	hdr = FIELD_PREP(ZXDH_CQ_ARM_DBSA_VLD, 0) | FIELD_PREP(ZXDH_CQ_ARM_CQ_ID, ccq->cq_uk.cq_id);

	dma_wmb(); /* make sure shadow area is updated before arming */

	writel(hdr, ccq->dev->cq_arm_db);
}

/**
 * zxdh_sc_ccq_get_cqe_info - get ccq's cq entry
 * @ccq: ccq sc struct
 * @info: completion q entry to return
 */
int zxdh_sc_ccq_get_cqe_info(struct zxdh_sc_cq *ccq, struct zxdh_ccq_cqe_info *info)
{
	u64 qp_ctx, temp, temp1, cq_shadow_temp;
	__le64 *cqe;
	struct zxdh_sc_cqp *cqp;
	u32 wqe_idx;
	u32 error;
	u8 polarity;
	u8 mailbox_cqe = 0;
	int ret_code = 0;

	cqe = ZXDH_GET_CURRENT_CQ_ELEM(&ccq->cq_uk);
	get_64bit_val(cqe, 0, &temp);
	polarity = (u8)FIELD_GET(ZXDH_CQ_VALID, temp);
	if (polarity != ccq->cq_uk.polarity)
		return -ENOENT;
	mailbox_cqe = (u8)FIELD_GET(ZXDH_CQ_MAILBOXCQE, temp);

	get_64bit_val(cqe, 8, &qp_ctx);
	//cqp = (struct zxdh_sc_cqp *)(unsigned long)qp_ctx;
	cqp = ccq->dev->cqp;
	info->error = (bool)FIELD_GET(ZXDH_CQ_ERROR, temp);
	info->maj_err_code = ZXDH_CQPSQ_MAJ_NO_ERROR;
	info->min_err_code = (u16)FIELD_GET(ZXDH_CQ_MINERR, temp);
	if (info->error) {
		info->maj_err_code = (u16)FIELD_GET(ZXDH_CQ_MAJERR, temp);
		cqp = ccq->dev->cqp;
		error = readl((u32 __iomem *)(cqp->dev->hw->hw_addr + C_RDMA_CQP_ERRCODE));
		if (ccq->dev->hw_attrs.self_health == false)
			pr_err("CQP: CQPERRCODES error_code[x%08X]\n", error);
	}

	wqe_idx = (u32)FIELD_GET(ZXDH_CQ_WQEIDX, temp);

	if (info->error)
		wqe_idx = ZXDH_RING_CURRENT_TAIL(cqp->sq_ring);

	info->scratch = cqp->scratch_array[wqe_idx];

	get_64bit_val(cqe, 16, &temp1);
	info->op_ret_val = (u32)FIELD_GET(ZXDH_CCQ_OPRETVAL, temp1);
	get_64bit_val(cqp->sq_base[wqe_idx].elem, 0, &temp1);
	info->op_code = (u8)FIELD_GET(ZXDH_CQPSQ_OPCODE, temp1);
	info->cqp = cqp;
	info->mailbox_cqe = mailbox_cqe;

	if (mailbox_cqe == 1) {
		get_64bit_val(cqe, 24, &temp1);
		info->addrbuf[0] = temp1;
		get_64bit_val(cqe, 32, &temp1);
		info->addrbuf[1] = temp1;
		get_64bit_val(cqe, 40, &temp1);
		info->addrbuf[2] = temp1;
		get_64bit_val(cqe, 48, &temp1);
		info->addrbuf[3] = temp1;
		get_64bit_val(cqe, 56, &temp1);
		info->addrbuf[4] = temp1;
	} else if (info->op_code == ZXDH_CQP_OP_WQE_DMA_READ_USECQE) {
		get_64bit_val(cqe, 24, &temp1);
		info->addrbuf[0] = temp1;
		get_64bit_val(cqe, 32, &temp1);
		info->addrbuf[1] = temp1;
		get_64bit_val(cqe, 40, &temp1);
		info->addrbuf[2] = temp1;
		get_64bit_val(cqe, 48, &temp1);
		info->addrbuf[3] = temp1;
		get_64bit_val(cqe, 56, &temp1);
		info->addrbuf[4] = temp1;
	}

	/*  move the head for cq */
	ZXDH_RING_MOVE_HEAD(ccq->cq_uk.cq_ring, ret_code);
	if (!ZXDH_RING_CURRENT_HEAD(ccq->cq_uk.cq_ring))
		ccq->cq_uk.polarity ^= 1;

	/* update cq tail in cq shadow memory also */
	ZXDH_RING_MOVE_TAIL(ccq->cq_uk.cq_ring);
	get_64bit_val(ccq->cq_uk.shadow_area, 0, &cq_shadow_temp);
	cq_shadow_temp &= ~ZXDH_CQ_DBSA_CQEIDX;
	cq_shadow_temp |=
		FIELD_PREP(ZXDH_CQ_DBSA_CQEIDX, ZXDH_RING_CURRENT_HEAD(ccq->cq_uk.cq_ring));
	set_64bit_val(ccq->cq_uk.shadow_area, 0, cq_shadow_temp);

	dma_wmb(); /* make sure shadow area is updated before moving tail */
	if ((mailbox_cqe != 1)) {
		if (cqp->sq_ring.head == cqp->sq_ring.tail)
			pr_info("[%s] cqp_err op_code:%d vhca_id:%d head:%d tail:%d\n", __func__,
				info->op_code, cqp->dev->vhca_id, cqp->sq_ring.head,
				cqp->sq_ring.tail);

		ZXDH_RING_MOVE_TAIL(cqp->sq_ring);
		ccq->dev->cqp_cmd_stats[ZXDH_OP_CMPL_CMDS]++;
	}

	return ret_code;
}

/**
 * zxdh_sc_poll_for_cqp_op_done - Waits for last write to complete in CQP SQ
 * @cqp: struct for cqp hw
 * @op_code: cqp opcode for completion
 * @compl_info: completion q entry to return
 */
int zxdh_sc_poll_for_cqp_op_done(struct zxdh_sc_cqp *cqp, u8 op_code,
				 struct zxdh_ccq_cqe_info *compl_info)
{
	struct zxdh_ccq_cqe_info info = {};
	struct zxdh_sc_cq *ccq;
	int ret_code = 0;
	u32 cnt = 0;
	u8 cqe_valid = false;

	ccq = cqp->dev->ccq;
	while (1) {
		if (cnt++ > 100 * cqp->dev->hw_attrs.max_done_count)
			return -ETIMEDOUT;

		if (zxdh_sc_ccq_get_cqe_info(ccq, &info)) {
			udelay(cqp->dev->hw_attrs.max_sleep_count);
			continue;
		}
		if (info.error && info.op_code != ZXDH_CQP_OP_QUERY_MKEY) {
			ret_code = -EIO;
			break;
		}
		cqe_valid = true;

		/* make sure op code matches*/
		if (op_code == info.op_code)
			break;
		pr_err("WQE: opcode mismatch for my op code 0x%x, returned opcode %x\n", op_code,
		       info.op_code);
	}

	if (compl_info)
		memcpy(compl_info, &info, sizeof(*compl_info));

	if ((cqe_valid == true) && (cqp->dev->ceq_0_ok == true))
		zxdh_sc_ccq_arm(ccq);

	return ret_code;
}

/**
 * zxdh_sc_manage_hmc_pm_func_table - manage of function table
 * @cqp: struct for cqp hw
 * @scratch: u64 saved to be used during cqp completion
 * @info: info for the manage function table operation
 * @post_sq: flag for cqp db to ring
 */
static int zxdh_sc_manage_hmc_pm_func_table(struct zxdh_sc_cqp *cqp, struct zxdh_hmc_fcn_info *info,
					    u64 scratch, bool post_sq)
{
	__le64 *wqe;
	u64 hdr;

	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	hdr = FIELD_PREP(ZXDH_CQPSQ_MHMC_VFIDX, info->vf_id) |
	      FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_MANAGE_HMC_PM_FUNC_TABLE) |
	      FIELD_PREP(ZXDH_CQPSQ_MHMC_FREEPMFN, info->free_fcn) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: MANAGE_HMC_PM_FUNC_TABLE WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * zxdh_sc_commit_fpm_val_done - wait for cqp eqe completion
 * for fpm commit
 * @cqp: struct for cqp hw
 */
static int zxdh_sc_commit_fpm_val_done(struct zxdh_sc_cqp *cqp)
{
	return zxdh_sc_poll_for_cqp_op_done(cqp, ZXDH_CQP_OP_WQE_DMA_WRITE_32, NULL);
}

/**
 * zxdh_sc_ceq_init - initialize ceq
 * @ceq: ceq sc structure
 * @info: ceq initialization info
 */
int zxdh_sc_ceq_init(struct zxdh_sc_ceq *ceq, struct zxdh_ceq_init_info *info)
{
	u32 pble_obj_cnt;

	if (info->elem_cnt < info->dev->hw_attrs.min_hw_ceq_size ||
	    info->elem_cnt > info->dev->hw_attrs.max_hw_ceq_size)
		return -EINVAL;

	if (info->ceq_index > (info->dev->max_ceqs - 1))
		return -EINVAL;
	pble_obj_cnt = info->dev->hmc_info->hmc_obj[ZXDH_HMC_IW_PBLE].cnt;

	if (info->virtual_map && info->first_pm_pbl_idx >= pble_obj_cnt)
		return -EINVAL;

	ceq->size = sizeof(*ceq);
	ceq->ceqe_base = (struct zxdh_ceqe *)info->ceqe_base;
	ceq->ceq_id = info->ceq_id;
	ceq->ceq_index = info->ceq_index;
	ceq->dev = info->dev;
	ceq->elem_cnt = info->elem_cnt;
	ceq->log2_elem_size = info->log2_elem_size;
	ceq->ceq_elem_pa = info->ceqe_pa;
	ceq->virtual_map = info->virtual_map;
	ceq->itr_no_expire = info->itr_no_expire;
	ceq->reg_cq = info->reg_cq;
	ceq->reg_cq_size = 0;
	spin_lock_init(&ceq->req_cq_lock);
	ceq->pbl_chunk_size = (ceq->virtual_map ? info->pbl_chunk_size : 0);
	ceq->first_pm_pbl_idx = (ceq->virtual_map ? info->first_pm_pbl_idx : 0);
	ceq->pbl_list = (ceq->virtual_map ? info->pbl_list : NULL);
	ceq->tph_en = info->tph_en;
	ceq->tph_val = info->tph_val;
	ceq->msix_idx = info->msix_idx;
	ceq->polarity = 1;
	ZXDH_RING_INIT(ceq->ceq_ring, ceq->elem_cnt);
	ceq->dev->ceq[info->ceq_index] = ceq;

	return 0;
}

/**
 * zxdh_sc_ceq_create - create ceq wqe
 * @ceq: ceq sc structure
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int zxdh_sc_ceq_create(struct zxdh_sc_ceq *ceq, u64 scratch, bool post_sq)
{
	struct zxdh_sc_cqp *cqp;
	__le64 *wqe;
	u64 hdr;

	cqp = ceq->dev->cqp;
	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	hdr = FIELD_PREP(ZXDH_CEQC_PERIOD_L, 0) | FIELD_PREP(ZXDH_CEQC_VHCA, ceq->dev->vhca_id) |
	      FIELD_PREP(ZXDH_CEQC_INTR_IDX, ceq->msix_idx) |
	      FIELD_PREP(ZXDH_CEQC_INT_TYPE, ZXDH_IRQ_TYPE_MSIX) |
	      FIELD_PREP(ZXDH_CEQC_CEQ_HEAD, 0) | FIELD_PREP(ZXDH_CEQC_CEQE_VALID, ceq->polarity) |
	      FIELD_PREP(ZXDH_CEQC_LEAF_PBL_SIZE, ceq->pbl_chunk_size) |
	      //   FIELD_PREP(ZXDH_CEQC_VIRTUALLY_MAPPED, ceq->virtual_map) |
	      FIELD_PREP(ZXDH_CEQC_CEQ_SIZE, ZXDH_CEQE_SIZE_16_BYTE) |
	      FIELD_PREP(ZXDH_CEQC_LOG_CEQ_NUM, ceq->log2_elem_size) |
	      FIELD_PREP(ZXDH_CEQC_CEQ_STATE, ZXDH_QUEUE_STATE_OK);
	dma_wmb();

	set_64bit_val(wqe, 8, hdr);

	hdr = FIELD_PREP(ZXDH_CEQC_CEQ_ADDRESS,
			 ceq->virtual_map ? ceq->first_pm_pbl_idx : RS_64_1(ceq->ceq_elem_pa, 7)) |
	      FIELD_PREP(ZXDH_CEQC_PERIOD_H, 0);
	dma_wmb();
	set_64bit_val(wqe, 16, hdr);

	hdr = FIELD_PREP(ZXDH_CEQC_CEQ_MAX_CNT, IRMDA_CEQ_AGGREGATION_CNT_0) |
	      FIELD_PREP(ZXDH_CEQC_CEQ_AXI_RSP_ERR_FLAG, 0);
	dma_wmb();
	set_64bit_val(wqe, 24, hdr);

	hdr = FIELD_PREP(ZXDH_CQPSQ_CEQ_CEQID, ceq->ceq_id) |
	      FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_CREATE_CEQ) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	print_hex_dump_debug("WQE: CEQ_CREATE WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * zxdh_sc_cceq_create_done - poll for control ceq wqe to complete
 * @ceq: ceq sc structure
 */
static int zxdh_sc_cceq_create_done(struct zxdh_sc_ceq *ceq)
{
	struct zxdh_sc_cqp *cqp;

	cqp = ceq->dev->cqp;
	return zxdh_sc_poll_for_cqp_op_done(cqp, ZXDH_CQP_OP_CREATE_CEQ, NULL);
}

/**
 * zxdh_sc_cceq_destroy_done - poll for destroy cceq to complete
 * @ceq: ceq sc structure
 */
int zxdh_sc_cceq_destroy_done(struct zxdh_sc_ceq *ceq)
{
	struct zxdh_sc_cqp *cqp;

	if (ceq->reg_cq)
		zxdh_sc_remove_cq_ctx(ceq, ceq->dev->ccq);

	cqp = ceq->dev->cqp;

	return zxdh_sc_poll_for_cqp_op_done(cqp, ZXDH_CQP_OP_DESTROY_CEQ, NULL);
}

/**
 * zxdh_sc_cceq_create - create cceq
 * @ceq: ceq sc structure
 * @scratch: u64 saved to be used during cqp completion
 */
int zxdh_sc_cceq_create(struct zxdh_sc_ceq *ceq, u64 scratch)
{
	int ret_code;

	if (ceq->reg_cq) {
		ret_code = zxdh_sc_add_cq_ctx(ceq, ceq->dev->ccq);
		if (ret_code)
			return ret_code;
	}

	ret_code = zxdh_sc_ceq_create(ceq, scratch, true);
	if (!ret_code)
		return zxdh_sc_cceq_create_done(ceq);

	return ret_code;
}

/**
 * zxdh_sc_ceq_destroy - destroy ceq
 * @ceq: ceq sc structure
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
int zxdh_sc_ceq_destroy(struct zxdh_sc_ceq *ceq, u64 scratch, bool post_sq)
{
	struct zxdh_sc_cqp *cqp;
	__le64 *wqe;
	u64 hdr;

	cqp = ceq->dev->cqp;
	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	hdr = FIELD_PREP(ZXDH_CEQC_PERIOD_L, 0) | FIELD_PREP(ZXDH_CEQC_VHCA, ceq->dev->vhca_id) |
	      FIELD_PREP(ZXDH_CEQC_INTR_IDX, ceq->msix_idx) |
	      FIELD_PREP(ZXDH_CEQC_INT_TYPE, ZXDH_IRQ_TYPE_PIN) |
	      FIELD_PREP(ZXDH_CEQC_CEQ_HEAD, 0) | FIELD_PREP(ZXDH_CEQC_CEQE_VALID, ceq->polarity) |
	      FIELD_PREP(ZXDH_CEQC_LEAF_PBL_SIZE, ceq->pbl_chunk_size) |
	      //   FIELD_PREP(ZXDH_CEQC_VIRTUALLY_MAPPED, ceq->virtual_map) |
	      FIELD_PREP(ZXDH_CEQC_CEQ_SIZE, ZXDH_CEQE_SIZE_64_BYTE) |
	      FIELD_PREP(ZXDH_CEQC_LOG_CEQ_NUM, ceq->log2_elem_size) |
	      FIELD_PREP(ZXDH_CEQC_CEQ_STATE, ZXDH_QUEUE_STATE_OK);
	dma_wmb();

	set_64bit_val(wqe, 8, hdr);

	hdr = FIELD_PREP(ZXDH_CEQC_CEQ_ADDRESS,
			 ceq->virtual_map ? ceq->first_pm_pbl_idx : ceq->ceq_elem_pa) |
	      FIELD_PREP(ZXDH_CEQC_PERIOD_H, 0);
	dma_wmb();
	set_64bit_val(wqe, 16, hdr);

	hdr = FIELD_PREP(ZXDH_CEQC_CEQ_MAX_CNT, IRMDA_CEQ_AGGREGATION_CNT_0) |
	      FIELD_PREP(ZXDH_CEQC_CEQ_AXI_RSP_ERR_FLAG, 0);
	dma_wmb();
	set_64bit_val(wqe, 24, hdr);

	hdr = FIELD_PREP(ZXDH_CQPSQ_CEQ_CEQID, ceq->ceq_id) |
	      FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_DESTROY_CEQ) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	print_hex_dump_debug("WQE: CEQ_DESTROY WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * zxdh_sc_process_ceq - process ceq
 * @dev: sc device struct
 * @ceq: ceq sc structure
 *
 * It is expected caller serializes this function with cleanup_ceqes()
 * because these functions manipulate the same ceq
 */
void *zxdh_sc_process_ceq(struct zxdh_sc_dev *dev, struct zxdh_sc_ceq *ceq)
{
	u64 temp;
	__le64 *ceqe;
	struct zxdh_sc_cq *cq = NULL;
	struct zxdh_sc_cq *temp_cq;
	u8 polarity;
	u32 cq_idx;
	unsigned long flags;

	do {
		if (ceq->valid_ceq == false)
			return NULL;
		cq_idx = 0;
		ceqe = ZXDH_GET_CURRENT_CEQ_ELEM(ceq);
		get_64bit_val(ceqe, 0, &temp);
		polarity = (u8)FIELD_GET(ZXDH_CEQE_VALID, temp);
		if (polarity != ceq->polarity)
			return NULL;

		temp_cq = (struct zxdh_sc_cq *)(unsigned long)LS_64_1(temp, 1);
		if (!temp_cq) {
			cq_idx = ZXDH_INVALID_CQ_IDX;
			ZXDH_RING_MOVE_TAIL(ceq->ceq_ring);

			if (!ZXDH_RING_CURRENT_TAIL(ceq->ceq_ring))
				ceq->polarity ^= 1;
			continue;
		}

		cq = temp_cq;
		if (ceq->reg_cq) {
			spin_lock_irqsave(&ceq->req_cq_lock, flags);
			cq_idx = zxdh_sc_find_reg_cq(ceq, cq);
			spin_unlock_irqrestore(&ceq->req_cq_lock, flags);
		}

		ZXDH_RING_MOVE_TAIL(ceq->ceq_ring);
		if (!ZXDH_RING_CURRENT_TAIL(ceq->ceq_ring))
			ceq->polarity ^= 1;
	} while (cq_idx == ZXDH_INVALID_CQ_IDX);

	return cq;
}

/**
 * zxdh_sc_cleanup_ceqes - clear the valid ceqes ctx matching the cq
 * @cq: cq for which the ceqes need to be cleaned up
 * @ceq: ceq ptr
 *
 * The function is called after the cq is destroyed to cleanup
 * its pending ceqe entries. It is expected caller serializes this
 * function with process_ceq() in interrupt context.
 */
void zxdh_sc_cleanup_ceqes(struct zxdh_sc_cq *cq, struct zxdh_sc_ceq *ceq)
{
	struct zxdh_sc_cq *next_cq;
	u8 ceq_polarity = ceq->polarity;
	__le64 *ceqe;
	u8 polarity;
	u64 temp;
	int next;
	u32 i;

	next = ZXDH_RING_GET_NEXT_TAIL(ceq->ceq_ring, 0);

	for (i = 1; i <= ZXDH_RING_SIZE(*ceq); i++) {
		ceqe = ZXDH_GET_CEQ_ELEM_AT_POS(ceq, next);

		get_64bit_val(ceqe, 0, &temp);
		polarity = (u8)FIELD_GET(ZXDH_CEQE_VALID, temp);
		if (polarity != ceq_polarity)
			return;

		next_cq = (struct zxdh_sc_cq *)(unsigned long)LS_64_1(temp, 1);
		if (cq == next_cq)
			set_64bit_val(ceqe, 0, temp & ZXDH_CEQE_VALID);

		next = ZXDH_RING_GET_NEXT_TAIL(ceq->ceq_ring, i);
		if (!next)
			ceq_polarity ^= 1;
	}
}

/**
 * zxdh_sc_aeq_init - initialize aeq
 * @aeq: aeq structure ptr
 * @info: aeq initialization info
 */
int zxdh_sc_aeq_init(struct zxdh_sc_aeq *aeq, struct zxdh_aeq_init_info *info)
{
	u32 pble_obj_cnt;

	if (info->elem_cnt < info->dev->hw_attrs.min_hw_aeq_size ||
	    info->elem_cnt > info->dev->hw_attrs.max_hw_aeq_size)
		return -EINVAL;

	pble_obj_cnt = info->dev->hmc_info->hmc_obj[ZXDH_HMC_IW_PBLE].cnt;

	if (info->virtual_map && info->first_pm_pbl_idx >= pble_obj_cnt)
		return -EINVAL;

	aeq->size = sizeof(*aeq);
	aeq->polarity = 1;
	aeq->get_polarity_flag = 0;
	aeq->aeqe_base = (struct zxdh_sc_aeqe *)info->aeqe_base;
	aeq->dev = info->dev;
	aeq->elem_cnt = info->elem_cnt;
	aeq->aeq_elem_pa = info->aeq_elem_pa;
	ZXDH_RING_INIT(aeq->aeq_ring, aeq->elem_cnt);
	aeq->virtual_map = info->virtual_map;
	aeq->pbl_list = (aeq->virtual_map ? info->pbl_list : NULL);
	aeq->pbl_chunk_size = (aeq->virtual_map ? info->pbl_chunk_size : 0);
	aeq->first_pm_pbl_idx = (aeq->virtual_map ? info->first_pm_pbl_idx : 0);
	aeq->msix_idx = info->msix_idx;
	info->dev->aeq = aeq;

	return 0;
}

/**
 * zxdh_sc_aeq_create - create aeq
 * @aeq: aeq structure ptr
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int zxdh_sc_aeq_create(struct zxdh_sc_aeq *aeq, u64 scratch, bool post_sq)
{
	__le64 *wqe;
	struct zxdh_sc_cqp *cqp;
	u64 hdr;

	cqp = aeq->dev->cqp;
	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	hdr = FIELD_PREP(ZXDH_AEQC_INTR_IDX, aeq->msix_idx) | FIELD_PREP(ZXDH_AEQC_AEQ_HEAD, 0) |
	      FIELD_PREP(ZXDH_AEQC_LEAF_PBL_SIZE, aeq->pbl_chunk_size) |
	      FIELD_PREP(ZXDH_AEQC_VIRTUALLY_MAPPED, aeq->virtual_map) |
	      FIELD_PREP(ZXDH_AEQC_AEQ_SIZE, aeq->elem_cnt) | FIELD_PREP(ZXDH_AEQC_AEQ_STATE, 0);
	dma_wmb();
	set_64bit_val(wqe, 8, hdr);

	set_64bit_val(wqe, 16, aeq->virtual_map ? aeq->first_pm_pbl_idx : aeq->aeq_elem_pa);

	hdr = FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_CREATE_AEQ) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	print_hex_dump_debug("WQE: AEQ_CREATE WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * zxdh_cqp_aeq_create - create aeq
 * @aeq: aeq structure ptr
 */
int zxdh_cqp_aeq_create(struct zxdh_sc_aeq *aeq)
{
	__le64 *wqe;
	struct zxdh_sc_cqp *cqp;
	struct zxdh_sc_dev *dev;
	u64 hdr;
	u64 scratch = 0;
	u32 tail = 0, val = 0, error = 0;
	int ret_code;

	cqp = aeq->dev->cqp;
	dev = aeq->dev;
	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	hdr = FIELD_PREP(ZXDH_AEQC_INTR_IDX, aeq->msix_idx) | FIELD_PREP(ZXDH_AEQC_AEQ_HEAD, 0) |
	      FIELD_PREP(ZXDH_AEQC_LEAF_PBL_SIZE, aeq->pbl_chunk_size) |
	      FIELD_PREP(ZXDH_AEQC_VIRTUALLY_MAPPED, aeq->virtual_map) |
	      FIELD_PREP(ZXDH_AEQC_AEQ_SIZE, aeq->elem_cnt) | FIELD_PREP(ZXDH_AEQC_AEQ_STATE, 0);
	dma_wmb();
	set_64bit_val(wqe, 8, hdr);

	set_64bit_val(wqe, 16, aeq->virtual_map ? aeq->first_pm_pbl_idx : aeq->aeq_elem_pa);

	hdr = FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_CREATE_AEQ) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	print_hex_dump_debug("WQE: AEQ_CREATE WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);

	zxdh_get_cqp_reg_info(cqp, &val, &tail, &error);

	zxdh_sc_cqp_post_sq(cqp);

	ret_code = zxdh_cqp_poll_registers(cqp, tail, dev->hw_attrs.max_done_count);

	if (ret_code)
		return ret_code;

	return 0;
}

/**
 * zxdh_sc_aeq_destroy - destroy aeq during close
 * @aeq: aeq structure ptr
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
int zxdh_sc_aeq_destroy(struct zxdh_sc_aeq *aeq, u64 scratch, bool post_sq)
{
	__le64 *wqe;
	struct zxdh_sc_cqp *cqp;
	struct zxdh_sc_dev *dev;
	u64 hdr;

	dev = aeq->dev;

	cqp = dev->cqp;
	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;
	hdr = FIELD_PREP(ZXDH_AEQC_INTR_IDX, aeq->msix_idx) | FIELD_PREP(ZXDH_AEQC_AEQ_HEAD, 0) |
	      FIELD_PREP(ZXDH_AEQC_LEAF_PBL_SIZE, aeq->pbl_chunk_size) |
	      FIELD_PREP(ZXDH_AEQC_VIRTUALLY_MAPPED, aeq->virtual_map) |
	      FIELD_PREP(ZXDH_AEQC_AEQ_SIZE, aeq->elem_cnt) |
	      FIELD_PREP(ZXDH_AEQC_AEQ_STATE, ZXDH_QUEUE_STATE_OK);
	dma_wmb();
	set_64bit_val(wqe, 8, hdr);

	set_64bit_val(wqe, 16, aeq->virtual_map ? aeq->first_pm_pbl_idx : aeq->aeq_elem_pa);

	hdr = FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_DESTROY_AEQ) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	print_hex_dump_debug("WQE: AEQ_DESTROY WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);
	return 0;
}

/**
 * zxdh_aeq_requestor_msg_cfg - ae src msg cfg
 * @info: aeqe info to be cfg
 */
static void zxdh_aeq_requestor_msg_cfg(struct zxdh_aeqe_info *info)
{
	switch (info->ae_id) {
	case ZXDH_AE_REQ_AXI_RSP_ERR:
	case ZXDH_AE_REQ_WQE_FLUSH:
		break;
	default:
		info->qp = true;
		info->sq = true;
		break;
	}
}

/**
 * zxdh_aeq_responder_msg_cfg - ae src msg cfg
 * @info: aeqe info to be cfg
 */
static void zxdh_aeq_responder_msg_cfg(struct zxdh_aeqe_info *info)
{
	switch (info->ae_id) {
	case ZXDH_AE_RSP_WQE_FLUSH:
		info->qp = true;
		break;
	case ZXDH_AE_RSP_SRQ_WATER_SIG:
		info->srq = true;
		break;
	case ZXDH_AE_RSP_PKT_TYPE_CQ_OVERFLOW:
		info->cq = true;
		break;
	case ZXDH_AE_RSP_PKT_TYPE_CQ_OVERFLOW_QP:
		info->qp = true;
		break;
	case ZXDH_AE_RSP_PKT_TYPE_CQ_STATE:
		info->qp = true;
		break;
	case ZXDH_AE_RSP_PKT_TYPE_CQ_TWO_PBLE_RSP:
		info->cq = true;
		break;
	case ZXDH_AE_RSP_SRQ_AXI_RSP_SIG:
		info->srq = true;
		break;
	default:
		info->qp = true;
		info->rq = true;
		break;
	}
}

/**
 * zxdh_ae_src_msg_cfg - ae src msg cfg
 * @info: aeqe info to be cfg
 * @ae_src: ae msg source
 */
static void zxdh_ae_src_msg_cfg(struct zxdh_aeqe_info *info, u8 ae_src)
{
	if (ae_src == ZXDH_AE_REQUESTER) { //requestor
		zxdh_aeq_requestor_msg_cfg(info);
	} else if (ae_src == ZXDH_AE_RESPONDER) { //responder
		zxdh_aeq_responder_msg_cfg(info);
	} else {
		pr_err("aeq src msg cfg, bad ae_src!\n");
	}
}

/**
 * zxdh_sc_get_next_aeqe - get next aeq entry
 * @aeq: aeq structure ptr
 * @info: aeqe info to be returned
 */
int zxdh_sc_get_next_aeqe(struct zxdh_sc_aeq *aeq, struct zxdh_aeqe_info *info)
{
	u64 temp, temp1, compl_ctx;
	__le64 *aeqe;
	u16 wqe_idx;
	u8 ae_src;
	u8 polarity;

	aeqe = ZXDH_GET_CURRENT_AEQ_ELEM(aeq);
	get_64bit_val(aeqe, 16, &compl_ctx);
	get_64bit_val(aeqe, 0, &temp);
	get_64bit_val(aeqe, 8, &temp1);
	polarity = (u8)FIELD_GET(ZXDH_AEQE_VALID, temp);
	info->ae_id = (u16)FIELD_GET(ZXDH_AEQE_AECODE, temp);
	if ((aeq->get_polarity_flag == 0) && (info->ae_id)) {
		aeq->polarity = polarity;
		aeq->get_polarity_flag = 1;
	}

	if (aeq->polarity != polarity)
		return -ENOENT;

	if (info->ae_id == 0)
		return -ENOENT;

	print_hex_dump_debug("WQE: AEQ_ENTRY WQE", DUMP_PREFIX_OFFSET, 16, 8, aeqe, 16, false);

	ae_src = (u8)FIELD_GET(ZXDH_AEQE_AESRC, temp);
	wqe_idx = (u16)FIELD_GET(ZXDH_AEQE_WQDESCIDX, temp1);
	info->qp_cq_id = (u32)FIELD_GET(ZXDH_AEQE_QPCQID, temp1);
	info->iwarp_state = (u8)FIELD_GET(ZXDH_AEQE_IWSTATE, temp);
	info->aeqe_overflow = (bool)FIELD_GET(ZXDH_AEQE_OVERFLOW, temp);
	info->vhca_id = (u8)FIELD_GET(ZXDH_AEQE_VHCA_ID, temp);
	info->compl_ctx = compl_ctx;
	info->ae_src = ae_src;
	zxdh_ae_src_msg_cfg(info, ae_src);
	if ((info->ae_id != 257) && (info->ae_id != 18)) {
		pr_info("%s ae_src:%d wqe_idx:%d qp_cq_id:%d ae_id:%d vhca_id:%d\n", __func__,
			ae_src, wqe_idx, info->qp_cq_id, info->ae_id, info->vhca_id);
	}

	ZXDH_RING_MOVE_TAIL(aeq->aeq_ring);
	if (!ZXDH_RING_CURRENT_TAIL(aeq->aeq_ring))
		aeq->polarity ^= 1;

	return 0;
}

/**
 * zxdh_sc_repost_aeq_tail - repost aeq valid idx
 * @dev: sc device struct
 * @idx: valid location
 */
int zxdh_sc_repost_aeq_tail(struct zxdh_sc_dev *dev, u32 idx)
{
	writel(idx, dev->aeq_tail_pointer);
	return 0;
}

int zxdh_sc_dma_read(struct zxdh_sc_cqp *cqp, u64 scratch, struct zxdh_src_copy_dest *src_dest,
		     struct zxdh_path_index *spath_index, struct zxdh_path_index *dpath_index,
		     bool post_sq)
{
	__le64 *wqe;
	u64 hdr;
	u64 src_path_index = 0, dest_path_index = 0;

	if (!cqp)
		return -ENOMEM;

	src_path_index = zxdh_get_path_index(spath_index);
	dest_path_index = zxdh_get_path_index(dpath_index);

	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	set_64bit_val(wqe, 8, dest_path_index);
	set_64bit_val(wqe, 16, src_dest->dest);
	set_64bit_val(wqe, 24, src_dest->src);
	set_64bit_val(wqe, 32, src_dest->len);

	hdr = FIELD_PREP(ZXDH_CQPSQ_SRCPATHINDEX, src_path_index) |
	      FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_WQE_DMA_READ) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

int zxdh_sc_dma_read_usecqe(struct zxdh_sc_cqp *cqp, u64 scratch,
			    struct zxdh_dam_read_bycqe *readbuf,
			    struct zxdh_path_index *spath_index, bool post_sq)
{
	__le64 *wqe;
	u64 hdr;
	u64 src_path_index = 0;
	u8 i = 0;

	if (!cqp)
		return -ENOMEM;

	if (readbuf->num > 5)
		return -ENOMEM;

	src_path_index = zxdh_get_path_index(spath_index);
	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	set_64bit_val(wqe, 8, readbuf->valuetype);
	for (i = 0; i < readbuf->num; i++)
		set_64bit_val(wqe, 16 + i * 8, readbuf->addrbuf[i]);

	hdr = FIELD_PREP(ZXDH_CQPSQ_SRCPATHINDEX, src_path_index) |
	      FIELD_PREP(ZXDH_CQPSQ_DATABITWIDTH, readbuf->bitwidth) |
	      FIELD_PREP(ZXDH_CQPSQ_DATAINCQENUM, readbuf->num) |
	      FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_WQE_DMA_READ_USECQE) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

int zxdh_sc_dma_write64(struct zxdh_sc_cqp *cqp, u64 scratch, struct zxdh_path_index *dpath_index,
			struct zxdh_dma_write64_date *dma_data, bool post_sq)
{
	__le64 *wqe;
	u64 hdr;
	u64 dest_path_index = 0;
	int i, loop;

	if (!cqp)
		return -ENOMEM;

	loop = dma_data->num;
	if (loop > 3)
		return -ENOMEM;

	dest_path_index = zxdh_get_path_index(dpath_index);
	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	for (i = 0; i < loop; i++) {
		set_64bit_val(wqe, 16 + i * 8, dma_data->addrbuf[i]);
		set_64bit_val(wqe, 40 + i * 8, dma_data->databuf[i]);
	}

	hdr = FIELD_PREP(ZXDH_CQPSQ_DESTPATHINDEX, dest_path_index) |
	      FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_WQE_DMA_WRITE_64) |
	      FIELD_PREP(ZXDH_CQPSQ_DATAINWQENUM, dma_data->num) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity);

	dma_wmb(); /* make sure WQE is written before valid bit is set */
	set_64bit_val(wqe, 0, hdr);

	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

int zxdh_clear_nof_ioq(struct zxdh_sc_dev *dev, u64 size, u64 ioq_pa)
{
	struct zxdh_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	struct zxdh_pci_f *rf = dev_to_rf(dev);
	int status;

	if (!dev)
		return -ENOMEM;

	cqp_request = zxdh_alloc_and_get_cqp_request(&rf->cqp, true);
	if (!cqp_request)
		return -ENOMEM;

	dev->nof_clear_dpu_mem.size = NOF_IOQ_SQ_WQE_SIZE * NOF_IOQ_SQ_SIZE;
	dev->nof_clear_dpu_mem.va = dma_alloc_coherent(dev->hw->device, dev->nof_clear_dpu_mem.size,
						       &dev->nof_clear_dpu_mem.pa, GFP_KERNEL);
	if (!dev->nof_clear_dpu_mem.va) {
		zxdh_put_cqp_request(&rf->cqp, cqp_request);
		return -ENOMEM;
	}
	memset(dev->nof_clear_dpu_mem.va, 0, dev->nof_clear_dpu_mem.size);

	cqp_info = &cqp_request->info;
	cqp_info->post_sq = 1;
	cqp_info->cqp_cmd = ZXDH_OP_DMA_WRITE;
	cqp_info->in.u.dma_writeread.cqp = dev->cqp;
	cqp_info->in.u.dma_writeread.src_dest.src = dev->nof_clear_dpu_mem.pa;
	cqp_info->in.u.dma_writeread.src_dest.len = dev->nof_clear_dpu_mem.size;
	cqp_info->in.u.dma_writeread.src_dest.dest = ioq_pa;

	cqp_info->in.u.dma_writeread.src_path_index.vhca_id = dev->vhca_id;
	cqp_info->in.u.dma_writeread.src_path_index.obj_id = ZXDH_DMA_OBJ_ID;
	cqp_info->in.u.dma_writeread.src_path_index.path_select = ZXDH_INDICATE_HOST_NOSMMU;
	cqp_info->in.u.dma_writeread.src_path_index.inter_select = ZXDH_INTERFACE_NOTCACHE;

	cqp_info->in.u.dma_writeread.dest_path_index.vhca_id = dev->vhca_id;
	cqp_info->in.u.dma_writeread.dest_path_index.obj_id = ZXDH_DMA_OBJ_ID;
	cqp_info->in.u.dma_writeread.dest_path_index.path_select = ZXDH_INDICATE_DPU_DDR;
	cqp_info->in.u.dma_writeread.dest_path_index.inter_select = ZXDH_INTERFACE_NOTCACHE;
	pr_info("clear nof ioq pa=%llx size=%d\n", ioq_pa, dev->nof_clear_dpu_mem.size);
	cqp_info->in.u.dma_writeread.scratch = (uintptr_t)cqp_request;
	status = zxdh_handle_cqp_op(rf, cqp_request);
	zxdh_put_cqp_request(&rf->cqp, cqp_request);

	dma_free_coherent(dev->hw->device, dev->nof_clear_dpu_mem.size,
			  dev->nof_clear_dpu_mem.va, dev->nof_clear_dpu_mem.pa);
	dev->nof_clear_dpu_mem.va = NULL;

	return status;
}

int zxdh_clear_dpuddr(struct zxdh_sc_dev *dev, bool clear)
{
	__le64 *wqe;
	u64 hdr;
	u32 tail = 0, val = 0, error = 0, loop = 0, i = 0;
	int ret_code = 0;
	u64 scratch = 0;
	u64 src_path_index = 0, dest_path_index = 0, remain_leg = 0;
	u64 size = 0;
	struct zxdh_path_index spath_index = {};
	struct zxdh_path_index dpath_index = {};
	struct zxdh_src_copy_dest src_dest = {};

	if (!dev)
		return -ENOMEM;

	if ((clear == false) || (dev->hmc_use_dpu_ddr == false))
		return 0;

	dev->clear_dpu_mem.size = ZXDH_HMC_DIRECT_BP_SIZE;
	dev->clear_dpu_mem.va = dma_alloc_coherent(dev->hw->device, dev->clear_dpu_mem.size,
						   &dev->clear_dpu_mem.pa, GFP_KERNEL);
	if (!dev->clear_dpu_mem.va)
		return -ENOMEM;
	memset(dev->clear_dpu_mem.va, 0, dev->clear_dpu_mem.size);

	size = dev->hmc_pf_manager_info.hmc_size;
	loop = size / ZXDH_HMC_DIRECT_BP_SIZE;
	remain_leg = size % ZXDH_HMC_DIRECT_BP_SIZE;

	dpath_index.inter_select = ZXDH_INTERFACE_NOTCACHE; // not pass cache
	dpath_index.path_select = ZXDH_INDICATE_DPU_DDR; // L2D
	dpath_index.obj_id = ZXDH_DMA_OBJ_ID; // L2D
	dpath_index.vhca_id = dev->vhca_id;
	dest_path_index = zxdh_get_path_index(&dpath_index);

	spath_index.inter_select = ZXDH_INTERFACE_NOTCACHE; // not pass cache
	spath_index.path_select = ZXDH_INDICATE_HOST_NOSMMU;
	spath_index.obj_id = ZXDH_DMA_OBJ_ID;
	spath_index.vhca_id = dev->vhca_id;
	src_path_index = zxdh_get_path_index(&spath_index);
	src_dest.src = dev->clear_dpu_mem.pa;
	src_dest.len = dev->clear_dpu_mem.size;

	for (i = 0; i < loop; i++) {
		src_dest.dest = dev->hmc_pf_manager_info.hmc_base + i * ZXDH_HMC_DIRECT_BP_SIZE;

		wqe = zxdh_sc_cqp_get_next_send_wqe(dev->cqp, scratch);
		if (!wqe) {
			ret_code = -ENOSPC;
			goto free_dma;
		}

		set_64bit_val(wqe, 8, src_path_index);
		set_64bit_val(wqe, 16, src_dest.dest);
		set_64bit_val(wqe, 24, src_dest.src);
		set_64bit_val(wqe, 32, src_dest.len);

		hdr = FIELD_PREP(ZXDH_CQPSQ_DESTPATHINDEX, dest_path_index) |
		      FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_WQE_DMA_WRITE) |
		      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, dev->cqp->polarity);
		dma_wmb(); /* make sure WQE is written before valid bit is set */

		set_64bit_val(wqe, 0, hdr);

		zxdh_get_cqp_reg_info(dev->cqp, &val, &tail, &error);

		zxdh_sc_cqp_post_sq(dev->cqp);

		ret_code = zxdh_cqp_poll_registers(dev->cqp, tail, dev->hw_attrs.max_done_count);

		if (ret_code)
			goto free_dma;
	}

	if (remain_leg != 0) {
		src_dest.dest = dev->hmc_pf_manager_info.hmc_base + i * ZXDH_HMC_DIRECT_BP_SIZE;
		src_dest.len = remain_leg;

		wqe = zxdh_sc_cqp_get_next_send_wqe(dev->cqp, scratch);
		if (!wqe) {
			ret_code = -ENOSPC;
			goto free_dma;
		}

		set_64bit_val(wqe, 8, src_path_index);
		set_64bit_val(wqe, 16, src_dest.dest);
		set_64bit_val(wqe, 24, src_dest.src);
		set_64bit_val(wqe, 32, src_dest.len);

		hdr = FIELD_PREP(ZXDH_CQPSQ_DESTPATHINDEX, dest_path_index) |
		      FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_WQE_DMA_WRITE) |
		      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, dev->cqp->polarity);
		dma_wmb(); /* make sure WQE is written before valid bit is set */

		set_64bit_val(wqe, 0, hdr);

		zxdh_get_cqp_reg_info(dev->cqp, &val, &tail, &error);

		zxdh_sc_cqp_post_sq(dev->cqp);

		ret_code = zxdh_cqp_poll_registers(dev->cqp, tail, dev->hw_attrs.max_done_count);

		if (ret_code)
			goto free_dma;
	}

free_dma:
	dma_free_coherent(dev->hw->device, dev->clear_dpu_mem.size, dev->clear_dpu_mem.va,
			  dev->clear_dpu_mem.pa);
	dev->clear_dpu_mem.va = NULL;

	return ret_code;
}

int zxdh_sc_dma_write32(struct zxdh_sc_cqp *cqp, u64 scratch, struct zxdh_path_index *dpath_index,
			struct zxdh_dma_write32_date *dma_data, bool post_sq)
{
	__le64 *wqe;
	u64 hdr;
	u64 dest_path_index = 0;
	int i, loop;

	if (!cqp)
		return -ENOMEM;

	loop = dma_data->num;
	if (loop > 4)
		return -ENOMEM;

	dest_path_index = zxdh_get_path_index(dpath_index);
	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	for (i = 0; i < loop; i++) {
		set_64bit_val(wqe, 16 + i * 8, dma_data->addrbuf[i]);
		if (i == 0) {
			hdr = FIELD_PREP(ZXDH_CQPSQ_DATALOW, dma_data->databuf[i]);
			set_64bit_val(wqe, 48, hdr);
		} else if (i == 1) {
			hdr = FIELD_PREP(ZXDH_CQPSQ_DATAHIGH, dma_data->databuf[i]);
			set_64bit_val(wqe, 48, hdr);
		} else if (i == 2) {
			hdr = FIELD_PREP(ZXDH_CQPSQ_DATALOW, dma_data->databuf[i]);
			set_64bit_val(wqe, 56, hdr);
		} else { // if (i == 3)
			hdr = FIELD_PREP(ZXDH_CQPSQ_DATAHIGH, dma_data->databuf[i]);
			set_64bit_val(wqe, 56, hdr);
		}
	}

	hdr = FIELD_PREP(ZXDH_CQPSQ_DESTPATHINDEX, dest_path_index) |
	      FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_WQE_DMA_WRITE_32) |
	      FIELD_PREP(ZXDH_CQPSQ_InterSourSel, dma_data->inter_sour_sel) |
	      FIELD_PREP(ZXDH_CQPSQ_NeedInter, dma_data->need_inter) |
	      FIELD_PREP(ZXDH_CQPSQ_DATAINWQENUM, dma_data->num) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity);

	dma_wmb(); /* make sure WQE is written before valid bit is set */
	set_64bit_val(wqe, 0, hdr);

	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

int zxdh_sc_dma_write(struct zxdh_sc_cqp *cqp, u64 scratch, struct zxdh_src_copy_dest *src_dest,
		      struct zxdh_path_index *spath_index, struct zxdh_path_index *dpath_index,
		      bool post_sq)
{
	__le64 *wqe;
	u64 hdr;
	u64 src_path_index = 0, dest_path_index = 0;

	if (!cqp)
		return -ENOMEM;

	src_path_index = zxdh_get_path_index(spath_index);
	dest_path_index = zxdh_get_path_index(dpath_index);

	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	set_64bit_val(wqe, 8, src_path_index);
	set_64bit_val(wqe, 16, src_dest->dest);
	set_64bit_val(wqe, 24, src_dest->src);
	set_64bit_val(wqe, 32, src_dest->len);

	hdr = FIELD_PREP(ZXDH_CQPSQ_DESTPATHINDEX, dest_path_index) |
	      FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_WQE_DMA_WRITE) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

int zxdh_sc_query_qpc(struct zxdh_sc_dev *dev, u32 qpn, u64 qpc_buf_pa, u64 scratch, bool post_sq)
{
	__le64 *wqe;
	struct zxdh_sc_cqp *cqp = dev->cqp;
	u64 hdr;

	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	hdr = FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_QUERY_QP) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity) |
	      FIELD_PREP(ZXDH_CQPSQ_QUERY_QPC_ID, qpn);
	set_64bit_val(wqe, 8, qpc_buf_pa);

	dma_wmb();
	set_64bit_val(wqe, 0, hdr);

	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

int zxdh_sc_query_cqc(struct zxdh_sc_dev *dev, u32 cqn, u64 cqc_buf_pa, u64 scratch, bool post_sq)
{
	__le64 *wqe;
	struct zxdh_sc_cqp *cqp = dev->cqp;
	u64 hdr;

	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	hdr = FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_QUERY_CQ) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity) |
	      FIELD_PREP(ZXDH_CQPSQ_QUERY_CQC_ID, cqn);
	set_64bit_val(wqe, 8, cqc_buf_pa);

	dma_wmb();
	set_64bit_val(wqe, 0, hdr);

	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

int zxdh_sc_query_ceqc(struct zxdh_sc_dev *dev, u32 ceqn, u64 ceqc_buf_pa, u64 scratch,
		       bool post_sq)
{
	__le64 *wqe;
	struct zxdh_sc_cqp *cqp = dev->cqp;
	u64 hdr;

	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	hdr = FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_QUERY_CEQ) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity) |
	      FIELD_PREP(ZXDH_CQPSQ_QUERY_CQC_ID, ceqn);
	set_64bit_val(wqe, 8, ceqc_buf_pa);

	dma_wmb();
	set_64bit_val(wqe, 0, hdr);

	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

int zxdh_sc_query_aeqc(struct zxdh_sc_dev *dev, u16 aeqn, u64 aeqc_buf_pa, u64 scratch,
		       bool post_sq)
{
	__le64 *wqe;
	struct zxdh_sc_cqp *cqp = dev->cqp;
	u64 hdr;

	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	hdr = FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_QUERY_AEQ) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity) |
	      FIELD_PREP(ZXDH_CQPSQ_QUERY_CQC_ID, aeqn);
	set_64bit_val(wqe, 8, aeqc_buf_pa);

	dma_wmb();
	set_64bit_val(wqe, 0, hdr);

	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	return 0;
}

u32 zxdh_num_to_log(u32 size_num)
{
	u32 size_log = 0;
	u32 temp = size_num;

	while (size_num > 1) {
		size_num >>= 1;
		size_log++;
	}
	if (temp != (1 << size_log))
		size_log += 1;

	return size_log;
}

int zxdh_sc_mb_create(struct zxdh_sc_cqp *cqp, u64 scratch,
		      struct zxdh_mailboxhead_data *mbhead_data, bool post_sq, u32 dst_vf_id)
{
	__le64 *wqe;
	u64 hdr;
	struct zxdh_sc_dev *dev = NULL;
	struct zxdh_pci_f *rf = NULL;
	bool ftype = false;

	if (!cqp)
		return -ENOMEM;

	dev = cqp->dev;
	rf = container_of(dev, struct zxdh_pci_f, sc_dev);
	ftype = rf->ftype; // ftype==0 ->PF

	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	set_64bit_val(wqe, 8, mbhead_data->msg0);
	set_64bit_val(wqe, 16, mbhead_data->msg1);
	set_64bit_val(wqe, 24, mbhead_data->msg2);
	set_64bit_val(wqe, 32, mbhead_data->msg3);
	set_64bit_val(wqe, 40, mbhead_data->msg4);

	hdr = FIELD_PREP(ZXDH_CQPSQ_DSTVFID, dst_vf_id) |
	      FIELD_PREP(ZXDH_CQPSQ_SRCPFVFID, ((ftype == 0) ? rf->pf_id : rf->vf_id)) |
	      FIELD_PREP(ZXDH_CQPSQ_PFVALID, !ftype) |
	      FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_SEND_MAILBOX) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);
	return 0;
}

/**
 * zxdh_sc_ccq_init - initialize control cq
 * @cq: sc's cq ctruct
 * @info: info for control cq initialization
 */
int zxdh_sc_ccq_init(struct zxdh_sc_cq *cq, struct zxdh_ccq_init_info *info)
{
	u32 pble_obj_cnt;

	if (info->num_elem < info->dev->hw_attrs.uk_attrs.min_hw_cq_size ||
	    info->num_elem > info->dev->hw_attrs.uk_attrs.max_hw_cq_size)
		return -EINVAL;

	if (info->ceq_index > (info->dev->max_ceqs - 1))
		return -EINVAL;

	pble_obj_cnt = info->dev->hmc_info->hmc_obj[ZXDH_HMC_IW_PBLE].cnt;

	if (info->virtual_map && info->first_pm_pbl_idx >= pble_obj_cnt)
		return -EINVAL;

	cq->cq_pa = info->cq_pa;
	cq->cq_uk.cq_base = info->cq_base;
	cq->shadow_area_pa = info->shadow_area_pa;
	cq->cq_uk.shadow_area = info->shadow_area;
	cq->shadow_read_threshold = info->shadow_read_threshold;
	cq->dev = info->dev;
	cq->ceq_id = info->ceq_id;
	cq->ceq_index = info->ceq_index;
	cq->cq_uk.cq_size = info->num_elem;
	cq->cq_uk.cq_log_size = zxdh_num_to_log(info->num_elem);
	cq->cq_type = ZXDH_CQ_TYPE_CQP;
	cq->ceqe_mask = info->ceqe_mask;
	ZXDH_RING_INIT(cq->cq_uk.cq_ring, info->num_elem);
	cq->cq_uk.cq_id = info->cq_num;
	cq->ceq_id_valid = info->ceq_id_valid;
	cq->cq_uk.cqe_size = info->cqe_size;
	cq->pbl_list = info->pbl_list;
	cq->virtual_map = info->virtual_map;
	cq->pbl_chunk_size = info->pbl_chunk_size;
	cq->first_pm_pbl_idx = info->first_pm_pbl_idx;
	cq->cq_uk.polarity = true;
	cq->cq_max = info->cq_max;
	cq->cq_period = info->cq_period;
	cq->scqe_break_moderation_en = info->scqe_break_moderation_en;
	cq->cq_st = info->cq_st;
	cq->is_in_list_cnt = info->is_in_list_cnt;

	/* Only applicable to CQs other than CCQ so initialize to zero */
	cq->cq_uk.cqe_alloc_db = NULL;

	info->dev->ccq = cq;
	writel(cq->cq_uk.cq_id, (u32 __iomem *)(cq->dev->hw->hw_addr + C_RDMA_CQP_CQ_NUM));

	return 0;
}

/**
 * zxdh_sc_ccq_create_done - poll cqp for ccq create
 * @ccq: ccq sc struct
 */
static inline int zxdh_sc_ccq_create_done(struct zxdh_sc_cq *ccq)
{
	struct zxdh_sc_cqp *cqp;

	cqp = ccq->dev->cqp;

	return zxdh_sc_poll_for_cqp_op_done(cqp, ZXDH_CQP_OP_CREATE_CQ, NULL);
}

/**
 * zxdh_sc_ccq_create - create control cq
 * @ccq: ccq sc struct
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
int zxdh_sc_ccq_create(struct zxdh_sc_cq *ccq, u64 scratch, bool post_sq)
{
	int ret_code;

	ret_code = zxdh_sc_cq_create(ccq, scratch, post_sq);
	if (ret_code)
		return ret_code;

	if (post_sq) {
		ret_code = zxdh_sc_ccq_create_done(ccq);
		if (ret_code)
			return ret_code;
	}

	ccq->dev->cqp->process_config_pte_table = zxdh_cqp_config_pte_table_cmd;

	return 0;
}

/**
 * zxdh_sc_ccq_destroy - destroy ccq during close
 * @ccq: ccq sc struct
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
int zxdh_sc_ccq_destroy(struct zxdh_sc_cq *ccq, u64 scratch, bool post_sq)
{
	struct zxdh_sc_cqp *cqp;
	__le64 *wqe;
	u64 temp;
	u64 hdr;
	int ret_code = 0;
	u32 tail, val, error;

	cqp = ccq->dev->cqp;
	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	writel(0, (u32 __iomem *)(cqp->dev->hw->hw_addr + C_RDMA_CQP_CQ_NUM));
	dma_wmb();

	set_64bit_val(wqe, 8, FIELD_PREP(ZXDH_CQPSQ_CQ_CQC_SET_MASK, ZXDH_CQC_SET_FIELD_ALL));
	temp = FIELD_PREP(ZXDH_CQPSQ_CQ_CQSTATE, 0) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_CQESIZE, ccq->cq_uk.cqe_size) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_VIRTMAP, ccq->virtual_map) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_LPBLSIZE, ccq->pbl_chunk_size) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_ENCEQEMASK, ccq->ceqe_mask);

	dma_wmb();
	set_64bit_val(wqe, 16, temp);
	set_64bit_val(wqe, 24, RS_64_1(ccq->shadow_area_pa, 6));
	temp = FLD_LS_64(ccq->dev, (ccq->ceq_id_valid ? ccq->ceq_id : 0), ZXDH_CQPSQ_CQ_CEQID) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_CQSIZE, ccq->cq_uk.cq_size) |
	       FIELD_PREP(ZXDH_CQPSQ_CQ_SHADOW_READ_THRESHOLD, ccq->shadow_read_threshold);

	dma_wmb();
	set_64bit_val(wqe, 32, temp);
	set_64bit_val(wqe, 40, 0);
	set_64bit_val(wqe, 48, (ccq->virtual_map ? ccq->first_pm_pbl_idx : RS_64_1(ccq->cq_pa, 8)));
	set_64bit_val(wqe, 56, RS_64_1(ccq, 0));

	hdr = FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_DESTROY_CQ) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity) |
	      FLD_LS_64(ccq->dev, ccq->cq_uk.cq_id, ZXDH_CQPSQ_CQ_CQID);

	dma_wmb();
	set_64bit_val(wqe, 0, hdr);

	print_hex_dump_debug("WQE: CCQ_DESTROY WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	zxdh_get_cqp_reg_info(cqp, &val, &tail, &error);

	if (post_sq) {
		zxdh_sc_cqp_post_sq(cqp);
		ret_code = zxdh_cqp_poll_registers(cqp, tail, cqp->dev->hw_attrs.max_done_count);
	}

	return ret_code;
}

/**
 * zxdh_cqp_ring_full - check if cqp ring is full
 * @cqp: struct for cqp hw
 */
static bool zxdh_cqp_ring_full(struct zxdh_sc_cqp *cqp)
{
	return ZXDH_RING_FULL_ERR(cqp->sq_ring);
}

/**
 * zxdh_sc_query_rdma_features - query RDMA features and FW ver
 * @cqp: struct for cqp hw
 * @buf: buffer to hold query info
 * @scratch: u64 saved to be used during cqp completion
 */
static int zxdh_sc_query_rdma_features(struct zxdh_sc_cqp *cqp, struct zxdh_dma_mem *buf,
				       u64 scratch)
{
	__le64 *wqe;
	u64 temp;
	u32 tail, val, error;
	int status;

	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	temp = buf->pa;
	set_64bit_val(wqe, 32, temp);

	temp = FIELD_PREP(ZXDH_CQPSQ_QUERY_RDMA_FEATURES_WQEVALID, cqp->polarity) |
	       FIELD_PREP(ZXDH_CQPSQ_QUERY_RDMA_FEATURES_BUF_LEN, buf->size) |
	       FIELD_PREP(ZXDH_CQPSQ_UP_OP, ZXDH_CQP_OP_QUERY_RDMA_FEATURES);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, temp);

	print_hex_dump_debug("WQE: QUERY RDMA FEATURES", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);
	zxdh_get_cqp_reg_info(cqp, &val, &tail, &error);

	zxdh_sc_cqp_post_sq(cqp);
	status = zxdh_cqp_poll_registers(cqp, tail, cqp->dev->hw_attrs.max_done_count);
	if (error || status)
		status = -EIO;

	return status;
}

u64 zxdh_get_hmc_align_2M(u64 paaddr)
{
	u64 pa = paaddr;

	if (paaddr % 0x200000 == 0)
		return pa;

	pa = pa + 0x200000;
	pa = pa & (~GENMASK_ULL(20, 0));

	return pa;
}

u64 zxdh_get_hmc_align_512(u64 paaddr)
{
	u64 pa = paaddr;

	if (paaddr % 512 == 0)
		return pa;

	pa = pa + 512;
	pa = pa & (~GENMASK_ULL(8, 0));

	return pa;
}

u64 zxdh_get_hmc_align_4K(u64 paaddr)
{
	u64 pa = paaddr;

	if (paaddr % 4096 == 0)
		return pa;

	pa = pa + 4096;
	pa = pa & (~GENMASK_ULL(11, 0));

	return pa;
}

u16 zxdh_txwind_ddr_size(u8 num)
{
	u8 i = 0;
	u16 result = 1;

	if (num > 9 || num < 2) {
		result = 4;
		return result;
	}

	for (i = 0; i < num; i++)
		result = result * 2;

	return result;
}

void zxdh_hmc_dpu_capability(struct zxdh_sc_dev *dev)
{
	u32 val = 0;
	struct zxdh_hmc_obj_info *obj_info = NULL;
	u8 txwindo_ddr_reg = 9;

	//txwindo_ddr_reg = readl(dev->hw->hw_addr+ TXWINDOW_DDR_SIZE);

	obj_info = dev->hmc_info->hmc_obj;

	obj_info[ZXDH_HMC_IW_QP].cnt = obj_info[ZXDH_HMC_IW_QP].max_cnt;
	obj_info[ZXDH_HMC_IW_QP].size = 512;

	obj_info[ZXDH_HMC_IW_CQ].cnt = obj_info[ZXDH_HMC_IW_CQ].max_cnt;
	obj_info[ZXDH_HMC_IW_CQ].size = 64;

	obj_info[ZXDH_HMC_IW_SRQ].cnt = obj_info[ZXDH_HMC_IW_SRQ].max_cnt;
	obj_info[ZXDH_HMC_IW_SRQ].size = 64;

	obj_info[ZXDH_HMC_IW_MR].cnt = obj_info[ZXDH_HMC_IW_MR].max_cnt;
	obj_info[ZXDH_HMC_IW_MR].size = 64;

	obj_info[ZXDH_HMC_IW_AH].cnt = obj_info[ZXDH_HMC_IW_AH].max_cnt;
	obj_info[ZXDH_HMC_IW_AH].size = 64;

	obj_info[ZXDH_HMC_IW_IRD].cnt = obj_info[ZXDH_HMC_IW_IRD].max_cnt;
	obj_info[ZXDH_HMC_IW_IRD].size = 64 * 2 * (dev->ird_size);

	obj_info[ZXDH_HMC_IW_TXWINDOW].cnt = obj_info[ZXDH_HMC_IW_TXWINDOW].max_cnt;
	obj_info[ZXDH_HMC_IW_TXWINDOW].size = 64 * zxdh_txwind_ddr_size(txwindo_ddr_reg);

	obj_info[ZXDH_HMC_IW_PBLE_MR].cnt = obj_info[ZXDH_HMC_IW_PBLE_MR].max_cnt;
	obj_info[ZXDH_HMC_IW_PBLE_MR].size = 8;

	obj_info[ZXDH_HMC_IW_PBLE].cnt = obj_info[ZXDH_HMC_IW_PBLE].max_cnt;
	obj_info[ZXDH_HMC_IW_PBLE].size = 8;

	val = obj_info[ZXDH_HMC_IW_MR].cnt;

	writel(val, (u32 __iomem *)(dev->hw->hw_addr + C_TX_MRTE_INDEX_CFG));
	writel(val, (u32 __iomem *)(dev->hw->hw_addr + RDMATX_ACK_PCI_MAX_MRTE_INDEX_PARA_CFG));
	writel(val, (u32 __iomem *)(dev->hw->hw_addr + RDMARX_PCI_MAX_MRTE_INDEX_RAM));
	writel(val, (u32 __iomem *)(dev->hw->hw_addr + RDMATX_LOCAL_MRTE_PARENT_PARA_CFG));
}

int zxdh_create_vf_pblehmc_entry(struct zxdh_sc_dev *dev)
{
	u32 sd_lmt, hmc_entry_total = 0, j = 0, k = 0, mem_size = 0, cnt = 0;
	u64 fpm_limit = 0;
	struct zxdh_hmc_info *hmc_info = NULL;
	struct zxdh_hmc_obj_info *obj_info = NULL;
	struct zxdh_virt_mem virt_mem = {};

	hmc_info = dev->hmc_info;
	obj_info = hmc_info->hmc_obj;
	for (k = ZXDH_HMC_IW_PBLE; k < ZXDH_HMC_IW_MAX; k++) {
		cnt = obj_info[k].cnt;

		fpm_limit = obj_info[k].size * cnt;

		if (fpm_limit == 0)
			continue;

		if (k == ZXDH_HMC_IW_PBLE)
			hmc_info->hmc_first_entry_pble = hmc_entry_total;

		if (k == ZXDH_HMC_IW_PBLE_MR)
			hmc_info->hmc_first_entry_pble_mr = hmc_entry_total;

		if ((fpm_limit % ZXDH_HMC_DIRECT_BP_SIZE) == 0) {
			sd_lmt = fpm_limit / ZXDH_HMC_DIRECT_BP_SIZE;
			sd_lmt += 1;
		} else {
			sd_lmt = (u32)((fpm_limit - 1) / ZXDH_HMC_DIRECT_BP_SIZE);
			sd_lmt += 1;
		}

		if (sd_lmt == 1)
			hmc_entry_total++;
		else {
			for (j = 0; j < sd_lmt - 1; j++)
				hmc_entry_total++;

			if (fpm_limit % ZXDH_HMC_DIRECT_BP_SIZE)
				hmc_entry_total++;
		}
	}

	mem_size = sizeof(struct zxdh_hmc_sd_entry) * hmc_entry_total;
	virt_mem.size = mem_size;
	virt_mem.va = kzalloc(virt_mem.size, GFP_KERNEL);
	if (!virt_mem.va) {
		pr_err("HMC: failed to allocate memory for sd_entry buffer\n");
		return -ENOMEM;
	}
	hmc_info->sd_table.sd_entry = virt_mem.va;
	hmc_info->hmc_entry_total = hmc_entry_total;

	return 0;
}

int zxdh_sc_commit_hmc_register_val(struct zxdh_sc_cqp *cqp, u64 scratch,
				    struct zxdh_path_index *dpath_index,
				    struct zxdh_dma_write32_date *dma_data, bool post_sq,
				    u8 wait_type)
{
	__le64 *wqe;
	u64 hdr;
	u32 tail, val, error;
	int ret_code = 0;
	u64 dest_path_index = 0;
	int i, loop;

	if (!cqp)
		return -ENOMEM;

	loop = dma_data->num;
	if (loop > 4)
		return -ENOMEM;

	dest_path_index = zxdh_get_path_index(dpath_index);
	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	for (i = 0; i < loop; i++) {
		set_64bit_val(wqe, 16 + i * 8, dma_data->addrbuf[i]);
		if (i == 0) {
			hdr = FIELD_PREP(ZXDH_CQPSQ_DATALOW, dma_data->databuf[i]);
			set_64bit_val(wqe, 48, hdr);
		} else if (i == 1) {
			hdr = FIELD_PREP(ZXDH_CQPSQ_DATAHIGH, dma_data->databuf[i]);
			set_64bit_val(wqe, 48, hdr);
		} else if (i == 2) {
			hdr = FIELD_PREP(ZXDH_CQPSQ_DATALOW, dma_data->databuf[i]);
			set_64bit_val(wqe, 56, hdr);
		} else { //if (i == 3)
			hdr = FIELD_PREP(ZXDH_CQPSQ_DATAHIGH, dma_data->databuf[i]);
			set_64bit_val(wqe, 56, hdr);
		}
	}

	hdr = FIELD_PREP(ZXDH_CQPSQ_DESTPATHINDEX, dest_path_index) |
	      FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_WQE_DMA_WRITE_32) |
	      FIELD_PREP(ZXDH_CQPSQ_InterSourSel, dma_data->inter_sour_sel) |
	      FIELD_PREP(ZXDH_CQPSQ_NeedInter, dma_data->need_inter) |
	      FIELD_PREP(ZXDH_CQPSQ_DATAINWQENUM, dma_data->num) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity);

	dma_wmb(); /* make sure WQE is written before valid bit is set */
	set_64bit_val(wqe, 0, hdr);

	zxdh_get_cqp_reg_info(cqp, &val, &tail, &error);

	if (post_sq) {
		zxdh_sc_cqp_post_sq(cqp);
		if (wait_type == ZXDH_CQP_WAIT_POLL_REGS)
			ret_code = zxdh_cqp_poll_registers(cqp, tail,
							   cqp->dev->hw_attrs.max_done_count);
		else if (wait_type == ZXDH_CQP_WAIT_POLL_CQ)
			ret_code = zxdh_sc_commit_fpm_val_done(cqp);
	}

	return ret_code;
}

u32 zxdh_hmc_register_config_comval(struct zxdh_sc_dev *dev, u32 rsrc_type)
{
	u32 tmp = 0, val = 0;

	if ((rsrc_type == ZXDH_HMC_IW_QP) || (rsrc_type == ZXDH_HMC_IW_CQ) ||
	    (rsrc_type == ZXDH_HMC_IW_SRQ)) {
		tmp = 0; // not use default 0
		tmp &= GENMASK_ULL(1, 0);
		val |= tmp;
	} else if ((rsrc_type == ZXDH_HMC_IW_IRD) && (dev->cache_id != 0)) {
		tmp = 2; // ird cacheid is 2
		tmp &= GENMASK_ULL(1, 0);
		val |= tmp;
	} else if ((rsrc_type == ZXDH_HMC_IW_TXWINDOW) && (dev->cache_id != 0)) {
		tmp = 3; // tx_wind cacheid is 3
		tmp &= GENMASK_ULL(1, 0);
		val |= tmp;
	} else {
		tmp = dev->cache_id; // cacheid
		tmp &= GENMASK_ULL(1, 0);
		val |= tmp;
	}

	if ((rsrc_type == ZXDH_HMC_IW_QP) || (rsrc_type == ZXDH_HMC_IW_CQ) ||
	    (rsrc_type == ZXDH_HMC_IW_SRQ)) {
		if (dev->hmc_use_dpu_ddr)
			tmp = ZXDH_INDICATE_DPU_DDR << 2; // indicateid
		else
			tmp = ZXDH_INDICATE_HOST_SMMU << 2; // indicateid
	} else {
		tmp = 0; // not used, Default is 0
	}
	tmp &= GENMASK_ULL(3, 2);
	val |= tmp;

	if (dev->hmc_use_dpu_ddr)
		tmp = ZXDH_AXID_DPUDDR << 4;
	else
		tmp = dev->hmc_epid << 4;

	tmp &= GENMASK_ULL(6, 4); // HOST is ep_id
	val |= tmp;

	tmp = 0 << 7; // way_partition temp is 0
	tmp &= GENMASK_ULL(9, 7);
	val |= tmp;

	tmp = 0 << 10; // rev is 0
	tmp &= GENMASK_ULL(31, 10);
	val |= tmp;

	return val;
}

u32 zxdh_hmc_register_config_cqpval(struct zxdh_sc_dev *dev, u32 max_cnt, u32 rsrc_type)
{
	u32 tmp = 0, val = 0;

	if ((rsrc_type == ZXDH_HMC_IW_MR) || (rsrc_type == ZXDH_HMC_IW_AH)) {
		tmp = dev->cache_id; // cacheid
		tmp &= GENMASK_ULL(1, 0);
		val |= tmp;

		tmp = 0 << 2; // way_partition temp is 0
		tmp &= GENMASK_ULL(4, 2);
		val |= tmp;

		tmp = max_cnt << 5;
		tmp &= GENMASK_ULL(28, 5); // max index
		val |= tmp;
	}
	return val;
}

int zxdh_cfg_fpm_val(struct zxdh_sc_dev *dev)
{
	struct zxdh_virt_mem virt_mem = {};
	struct zxdh_hmc_info *hmc_info = NULL;
	int ret_code = 0;
	u32 sd_lmt = 0, hmc_entry_total = 0, i = 0, j = 0, mem_size = 0, cnt = 0, k = 0;
	u64 fpm_limit = 0;
	struct zxdh_hmc_obj_info *obj_info = NULL;

	hmc_info = dev->hmc_info;
	zxdh_hmc_dpu_capability(dev);

	for (k = 0; k < ZXDH_HMC_IW_MAX; k++)
		zxdh_sc_write_hmc_register(dev, hmc_info->hmc_obj, k, dev->vhca_id);

	obj_info = hmc_info->hmc_obj;
	for (i = 0; i < ZXDH_HMC_IW_MAX; i++) {
		switch (i) {
		case ZXDH_HMC_IW_QP:
			cnt = dev->hmc_pf_manager_info.total_qp_cnt;
			break;
		case ZXDH_HMC_IW_CQ:
			cnt = dev->hmc_pf_manager_info.total_cq_cnt;
			break;
		case ZXDH_HMC_IW_SRQ:
			cnt = dev->hmc_pf_manager_info.total_srq_cnt;
			break;
		case ZXDH_HMC_IW_AH:
			cnt = dev->hmc_pf_manager_info.total_ah_cnt;
			break;
		case ZXDH_HMC_IW_MR:
			cnt = dev->hmc_pf_manager_info.total_mrte_cnt;
			break;
		default:
			cnt = obj_info[i].cnt;
			break;
		}

		fpm_limit = obj_info[i].size * cnt;
		fpm_limit = ALIGN(fpm_limit, ZXDH_HMC_DIRECT_BP_SIZE);

		if (fpm_limit == 0)
			continue;

		if (i == ZXDH_HMC_IW_PBLE)
			hmc_info->hmc_first_entry_pble = hmc_entry_total;

		if (i == ZXDH_HMC_IW_PBLE_MR)
			hmc_info->hmc_first_entry_pble_mr = hmc_entry_total;

		sd_lmt = fpm_limit / ZXDH_HMC_DIRECT_BP_SIZE;

		for (j = 0; j < sd_lmt; j++)
			hmc_entry_total++;
	}

	mem_size = sizeof(struct zxdh_hmc_sd_entry) * hmc_entry_total;
	virt_mem.size = mem_size;
	virt_mem.va = kzalloc(virt_mem.size, GFP_KERNEL);
	if (!virt_mem.va) {
		pr_err("HMC: failed to allocate memory for sd_entry buffer\n");
		return -ENOMEM;
	}

	hmc_info->sd_table.sd_entry = virt_mem.va;
	hmc_info->hmc_entry_total = hmc_entry_total;
	return ret_code;
}

/**
 * zxdh_exec_cqp_cmd - execute cqp cmd when wqe are available
 * @dev: rdma device
 * @pcmdinfo: cqp command info
 */
static int zxdh_exec_cqp_cmd(struct zxdh_sc_dev *dev, struct cqp_cmds_info *pcmdinfo)
{
	int status;
	bool alloc = false;

	dev->cqp_cmd_stats[pcmdinfo->cqp_cmd]++;
	if (dev->hw_attrs.self_health == true) {
		status = zxdh_check_cqp_cmd(pcmdinfo);
		if (status)
			return status;
	}
	switch (pcmdinfo->cqp_cmd) {
	case ZXDH_OP_CEQ_DESTROY:
		status = zxdh_sc_ceq_destroy(pcmdinfo->in.u.ceq_destroy.ceq,
					     pcmdinfo->in.u.ceq_destroy.scratch, pcmdinfo->post_sq);
		break;
	case ZXDH_OP_AEQ_DESTROY:
		status = zxdh_sc_aeq_destroy(pcmdinfo->in.u.aeq_destroy.aeq,
					     pcmdinfo->in.u.aeq_destroy.scratch, pcmdinfo->post_sq);
		break;
	case ZXDH_OP_CEQ_CREATE:
		status = zxdh_sc_ceq_create(pcmdinfo->in.u.ceq_create.ceq,
					    pcmdinfo->in.u.ceq_create.scratch, pcmdinfo->post_sq);
		break;
	case ZXDH_OP_AEQ_CREATE:
		status = zxdh_sc_aeq_create(pcmdinfo->in.u.aeq_create.aeq,
					    pcmdinfo->in.u.aeq_create.scratch, pcmdinfo->post_sq);
		break;
	case ZXDH_OP_QP_UPLOAD_CONTEXT:
		status = zxdh_sc_qp_upload_context(pcmdinfo->in.u.qp_upload_context.dev,
						   &pcmdinfo->in.u.qp_upload_context.info,
						   pcmdinfo->in.u.qp_upload_context.scratch,
						   pcmdinfo->post_sq);
		break;
	case ZXDH_OP_CQ_CREATE:
		status = zxdh_sc_cq_create(pcmdinfo->in.u.cq_create.cq,
					   pcmdinfo->in.u.cq_create.scratch, pcmdinfo->post_sq);
		break;
	case ZXDH_OP_CQ_MODIFY:
		status = zxdh_sc_cq_modify(pcmdinfo->in.u.cq_modify.cq,
					   &pcmdinfo->in.u.cq_modify.info,
					   pcmdinfo->in.u.cq_modify.scratch, pcmdinfo->post_sq);
		break;
	case ZXDH_OP_CQ_MODIFY_MODERATION:
		status = zxdh_sc_modify_cq_moderation(pcmdinfo->in.u.cq_modify.cq,
						      pcmdinfo->in.u.cq_modify.scratch,
						      pcmdinfo->post_sq);
		break;
	case ZXDH_OP_CQ_DESTROY:
		status = zxdh_sc_cq_destroy(pcmdinfo->in.u.cq_destroy.cq,
					    pcmdinfo->in.u.cq_destroy.scratch, pcmdinfo->post_sq);
		break;
	case ZXDH_OP_QP_FLUSH_WQES:
		status = zxdh_sc_qp_flush_wqes(pcmdinfo->in.u.qp_flush_wqes.qp,
					       &pcmdinfo->in.u.qp_flush_wqes.info,
					       pcmdinfo->in.u.qp_flush_wqes.scratch,
					       pcmdinfo->post_sq);
		break;
	case ZXDH_OP_GEN_AE:
		status = zxdh_sc_gen_ae(pcmdinfo->in.u.gen_ae.qp, &pcmdinfo->in.u.gen_ae.info,
					pcmdinfo->in.u.gen_ae.scratch, pcmdinfo->post_sq);
		break;
	case ZXDH_OP_MANAGE_PUSH_PAGE:
		status = zxdh_sc_manage_push_page(pcmdinfo->in.u.manage_push_page.cqp,
						  &pcmdinfo->in.u.manage_push_page.info,
						  pcmdinfo->in.u.manage_push_page.scratch,
						  pcmdinfo->post_sq);
		break;
	case ZXDH_OP_MANAGE_HMC_PM_FUNC_TABLE:
		/* switch to calling through the call table */
		status = zxdh_sc_manage_hmc_pm_func_table(pcmdinfo->in.u.manage_hmc_pm.dev->cqp,
							  &pcmdinfo->in.u.manage_hmc_pm.info,
							  pcmdinfo->in.u.manage_hmc_pm.scratch,
							  true);
		break;
	case ZXDH_OP_SUSPEND:
		status = zxdh_sc_suspend_qp(pcmdinfo->in.u.suspend_resume.cqp,
					    pcmdinfo->in.u.suspend_resume.qp,
					    pcmdinfo->in.u.suspend_resume.scratch);
		break;
	case ZXDH_OP_RESUME:
		status = zxdh_sc_resume_qp(pcmdinfo->in.u.suspend_resume.cqp,
					   pcmdinfo->in.u.suspend_resume.qp,
					   pcmdinfo->in.u.suspend_resume.scratch);
		break;
	case ZXDH_OP_MANAGE_VF_PBLE_BP:
		status = zxdh_manage_vf_pble_bp(pcmdinfo->in.u.manage_vf_pble_bp.cqp,
						&pcmdinfo->in.u.manage_vf_pble_bp.info,
						pcmdinfo->in.u.manage_vf_pble_bp.scratch, true);
		break;
	case ZXDH_OP_STATS_ALLOCATE:
		alloc = true;
		fallthrough;
	case ZXDH_OP_STATS_FREE:
		status = zxdh_sc_manage_stats_inst(pcmdinfo->in.u.stats_manage.cqp,
						   &pcmdinfo->in.u.stats_manage.info, alloc,
						   pcmdinfo->in.u.stats_manage.scratch);
		break;
	case ZXDH_OP_STATS_GATHER:
		status = zxdh_sc_gather_stats(pcmdinfo->in.u.stats_gather.cqp,
					      &pcmdinfo->in.u.stats_gather.info,
					      pcmdinfo->in.u.stats_gather.scratch);
		break;
	case ZXDH_OP_WS_MODIFY_NODE:
		status = zxdh_sc_manage_ws_node(pcmdinfo->in.u.ws_node.cqp,
						&pcmdinfo->in.u.ws_node.info, ZXDH_MODIFY_NODE,
						pcmdinfo->in.u.ws_node.scratch);
		break;
	case ZXDH_OP_WS_DELETE_NODE:
		status = zxdh_sc_manage_ws_node(pcmdinfo->in.u.ws_node.cqp,
						&pcmdinfo->in.u.ws_node.info, ZXDH_DEL_NODE,
						pcmdinfo->in.u.ws_node.scratch);
		break;
	case ZXDH_OP_WS_ADD_NODE:
		status = zxdh_sc_manage_ws_node(pcmdinfo->in.u.ws_node.cqp,
						&pcmdinfo->in.u.ws_node.info, ZXDH_ADD_NODE,
						pcmdinfo->in.u.ws_node.scratch);
		break;
	case ZXDH_OP_SET_UP_MAP:
		status = zxdh_sc_set_up_map(pcmdinfo->in.u.up_map.cqp, &pcmdinfo->in.u.up_map.info,
					    pcmdinfo->in.u.up_map.scratch);
		break;
	case ZXDH_OP_QUERY_RDMA_FEATURES:
		status = zxdh_sc_query_rdma_features(pcmdinfo->in.u.query_rdma.cqp,
						     &pcmdinfo->in.u.query_rdma.query_buff_mem,
						     pcmdinfo->in.u.query_rdma.scratch);
		break;
	case ZXDH_OP_DELETE_ARP_CACHE_ENTRY:
		status = zxdh_sc_del_arp_cache_entry(pcmdinfo->in.u.del_arp_cache_entry.cqp,
						     pcmdinfo->in.u.del_arp_cache_entry.scratch,
						     pcmdinfo->in.u.del_arp_cache_entry.arp_index,
						     pcmdinfo->post_sq);
		break;
	case ZXDH_OP_MANAGE_APBVT_ENTRY:
		status = zxdh_sc_manage_apbvt_entry(pcmdinfo->in.u.manage_apbvt_entry.cqp,
						    &pcmdinfo->in.u.manage_apbvt_entry.info,
						    pcmdinfo->in.u.manage_apbvt_entry.scratch,
						    pcmdinfo->post_sq);
		break;
	case ZXDH_OP_MANAGE_QHASH_TABLE_ENTRY:
		status = zxdh_sc_manage_qhash_table_entry(
			pcmdinfo->in.u.manage_qhash_table_entry.cqp,
			&pcmdinfo->in.u.manage_qhash_table_entry.info,
			pcmdinfo->in.u.manage_qhash_table_entry.scratch, pcmdinfo->post_sq);
		break;
	case ZXDH_OP_QP_MODIFY:
		status = zxdh_sc_qp_modify(pcmdinfo->in.u.qp_modify.qp,
					   &pcmdinfo->in.u.qp_modify.info,
					   pcmdinfo->in.u.qp_modify.scratch, pcmdinfo->post_sq);
		break;
	case ZXDH_OP_QP_CREATE:
		status = zxdh_sc_qp_create(pcmdinfo->in.u.qp_create.qp,
					   pcmdinfo->in.u.qp_create.scratch, pcmdinfo->post_sq);
		break;
	case ZXDH_OP_QP_DESTROY:
		status = zxdh_sc_qp_destroy(pcmdinfo->in.u.qp_destroy.qp,
					    pcmdinfo->in.u.qp_destroy.scratch,
					    pcmdinfo->in.u.qp_destroy.ignore_mw_bnd,
					    pcmdinfo->post_sq);
		break;
	case ZXDH_OP_ALLOC_STAG:
		status = zxdh_sc_alloc_stag(pcmdinfo->in.u.alloc_stag.dev,
					    &pcmdinfo->in.u.alloc_stag.info,
					    pcmdinfo->in.u.alloc_stag.scratch, pcmdinfo->post_sq);
		break;
	case ZXDH_OP_MR_REG_NON_SHARED:
		status = zxdh_sc_mr_reg_non_shared(pcmdinfo->in.u.mr_reg_non_shared.dev,
						   &pcmdinfo->in.u.mr_reg_non_shared.info,
						   pcmdinfo->in.u.mr_reg_non_shared.scratch,
						   pcmdinfo->post_sq);
		break;
	case ZXDH_OP_DEALLOC_STAG:
		status = zxdh_sc_dealloc_stag(pcmdinfo->in.u.dealloc_stag.dev,
					      &pcmdinfo->in.u.dealloc_stag.info,
					      pcmdinfo->in.u.dealloc_stag.scratch,
					      pcmdinfo->post_sq);
		break;
	case ZXDH_OP_MW_ALLOC:
		status = zxdh_sc_mw_alloc(pcmdinfo->in.u.mw_alloc.dev,
					  &pcmdinfo->in.u.mw_alloc.info,
					  pcmdinfo->in.u.mw_alloc.scratch, pcmdinfo->post_sq);
		break;
	case ZXDH_OP_ADD_ARP_CACHE_ENTRY:
		status = zxdh_sc_add_arp_cache_entry(pcmdinfo->in.u.add_arp_cache_entry.cqp,
						     &pcmdinfo->in.u.add_arp_cache_entry.info,
						     pcmdinfo->in.u.add_arp_cache_entry.scratch,
						     pcmdinfo->post_sq);
		break;
	case ZXDH_OP_AH_CREATE:
		status = zxdh_sc_create_ah(pcmdinfo->in.u.ah_create.cqp,
					   &pcmdinfo->in.u.ah_create.info,
					   pcmdinfo->in.u.ah_create.scratch);
		break;
	case ZXDH_OP_AH_DESTROY:
		status = zxdh_sc_destroy_ah(pcmdinfo->in.u.ah_destroy.cqp,
					    &pcmdinfo->in.u.ah_destroy.info,
					    pcmdinfo->in.u.ah_destroy.scratch);
		break;
	case ZXDH_OP_MC_CREATE:
		status = zxdh_sc_create_mcast_grp(pcmdinfo->in.u.mc_create.cqp,
						  pcmdinfo->in.u.mc_create.info,
						  pcmdinfo->in.u.mc_create.scratch);
		break;
	case ZXDH_OP_MC_DESTROY:
		status = zxdh_sc_destroy_mcast_grp(pcmdinfo->in.u.mc_destroy.cqp,
						   pcmdinfo->in.u.mc_destroy.info,
						   pcmdinfo->in.u.mc_destroy.scratch);
		break;
	case ZXDH_OP_MC_MODIFY:
		status = zxdh_sc_modify_mcast_grp(pcmdinfo->in.u.mc_modify.cqp,
						  pcmdinfo->in.u.mc_modify.info,
						  pcmdinfo->in.u.mc_modify.scratch);
		break;
	case ZXDH_OP_CONFIG_PTE_TAB:
	case ZXDH_OP_CONFIG_PBLE_TAB:
	case ZXDH_OP_DMA_WRITE:
		status = zxdh_sc_dma_write(pcmdinfo->in.u.dma_writeread.cqp,
					   pcmdinfo->in.u.dma_writeread.scratch,
					   &pcmdinfo->in.u.dma_writeread.src_dest,
					   &pcmdinfo->in.u.dma_writeread.src_path_index,
					   &pcmdinfo->in.u.dma_writeread.dest_path_index,
					   pcmdinfo->post_sq);
		break;
	case ZXDH_OP_QUERY_PTE_TAB:
	case ZXDH_OP_QUERY_HW_OBJECT_INFO:
	case ZXDH_OP_DMA_READ:
		status = zxdh_sc_dma_read(pcmdinfo->in.u.dma_writeread.cqp,
					  pcmdinfo->in.u.dma_writeread.scratch,
					  &pcmdinfo->in.u.dma_writeread.src_dest,
					  &pcmdinfo->in.u.dma_writeread.src_path_index,
					  &pcmdinfo->in.u.dma_writeread.dest_path_index,
					  pcmdinfo->post_sq);
		break;
	case ZXDH_OP_CONFIG_MAILBOX:
		status = zxdh_sc_mb_create(pcmdinfo->in.u.hmc_mb.cqp, pcmdinfo->in.u.hmc_mb.scratch,
					   &pcmdinfo->in.u.hmc_mb.mbhead_data, pcmdinfo->post_sq,
					   pcmdinfo->in.u.hmc_mb.dst_vf_id);
		break;
	case ZXDH_OP_DMA_READ_USE_CQE:
		status = zxdh_sc_dma_read_usecqe(pcmdinfo->in.u.dma_read_cqe.cqp,
						 pcmdinfo->in.u.dma_read_cqe.scratch,
						 &pcmdinfo->in.u.dma_read_cqe.dma_rcqe,
						 &pcmdinfo->in.u.dma_read_cqe.src_path_index,
						 pcmdinfo->post_sq);
		break;
	case ZXDH_OP_DMA_WRITE32:
		status = zxdh_sc_dma_write32(pcmdinfo->in.u.dma_write32data.cqp,
					     pcmdinfo->in.u.dma_write32data.scratch,
					     &pcmdinfo->in.u.dma_write32data.dest_path_index,
					     &pcmdinfo->in.u.dma_write32data.dma_data,
					     pcmdinfo->post_sq);
		break;
	case ZXDH_OP_DMA_WRITE64:
		status = zxdh_sc_dma_write64(pcmdinfo->in.u.dma_write64data.cqp,
					     pcmdinfo->in.u.dma_write64data.scratch,
					     &pcmdinfo->in.u.dma_write64data.dest_path_index,
					     &pcmdinfo->in.u.dma_write64data.dma_data,
					     pcmdinfo->post_sq);
		break;
	case ZXDH_OP_QUERY_QPC:
		status = zxdh_sc_query_qpc(pcmdinfo->in.u.query_qpc.dev,
					   pcmdinfo->in.u.query_qpc.qpn,
					   pcmdinfo->in.u.query_qpc.qpc_buf_pa,
					   pcmdinfo->in.u.query_qpc.scratch, pcmdinfo->post_sq);
		break;
	case ZXDH_OP_QUERY_CQC:
		status = zxdh_sc_query_cqc(pcmdinfo->in.u.query_cqc.dev,
					   pcmdinfo->in.u.query_cqc.cqn,
					   pcmdinfo->in.u.query_cqc.cqc_buf_pa,
					   pcmdinfo->in.u.query_cqc.scratch, pcmdinfo->post_sq);
		break;
	case ZXDH_OP_QUERY_CEQC:
		status = zxdh_sc_query_ceqc(pcmdinfo->in.u.query_ceqc.dev,
					    pcmdinfo->in.u.query_ceqc.ceqn,
					    pcmdinfo->in.u.query_ceqc.ceqc_buf_pa,
					    pcmdinfo->in.u.query_ceqc.scratch, pcmdinfo->post_sq);
		break;
	case ZXDH_OP_QUERY_AEQC:
		status = zxdh_sc_query_aeqc(pcmdinfo->in.u.query_aeqc.dev,
					    pcmdinfo->in.u.query_aeqc.aeqn,
					    pcmdinfo->in.u.query_aeqc.aeqc_buf_pa,
					    pcmdinfo->in.u.query_aeqc.scratch, pcmdinfo->post_sq);
		break;
	case ZXDH_OP_QUERY_SRQC:
		status = zxdh_sc_query_srqc(pcmdinfo->in.u.query_srqc.dev,
					    pcmdinfo->in.u.query_srqc.srqn,
					    pcmdinfo->in.u.query_srqc.srqc_buf_pa,
					    pcmdinfo->in.u.query_srqc.scratch, pcmdinfo->post_sq);
		break;
	case ZXDH_OP_SRQ_MODIFY:
		status = zxdh_sc_srq_modify(pcmdinfo->in.u.srq_modify.srq,
					    &pcmdinfo->in.u.srq_modify.info,
					    pcmdinfo->in.u.srq_modify.scratch, pcmdinfo->post_sq);
		break;
	case ZXDH_OP_SRQ_CREATE:
		status = zxdh_sc_srq_create(pcmdinfo->in.u.srq_create.srq,
					    &pcmdinfo->in.u.srq_create.info,
					    pcmdinfo->in.u.srq_create.scratch, pcmdinfo->post_sq);
		break;
	case ZXDH_OP_SRQ_DESTROY:
		status = zxdh_sc_srq_destroy(pcmdinfo->in.u.srq_destroy.srq,
					     pcmdinfo->in.u.srq_destroy.scratch, pcmdinfo->post_sq);
		break;
	case ZXDH_OP_QUERY_MKEY:
		status = zxdh_sc_query_mkey(pcmdinfo->in.u.query_mkey.cqp,
					    pcmdinfo->in.u.query_mkey.mkeyindex,
					    pcmdinfo->in.u.query_mkey.scratch, pcmdinfo->post_sq);
		break;
	default:
		status = -EOPNOTSUPP;
		break;
	}

	return status;
}

/**
 * zxdh_process_cqp_cmd - process all cqp commands
 * @dev: sc device struct
 * @pcmdinfo: cqp command info
 */
int zxdh_process_cqp_cmd(struct zxdh_sc_dev *dev, struct cqp_cmds_info *pcmdinfo)
{
	int status = 0;
	unsigned long flags;

	spin_lock_irqsave(&dev->cqp_lock, flags);
	if (list_empty(&dev->cqp_cmd_head) && !zxdh_cqp_ring_full(dev->cqp))
		status = zxdh_exec_cqp_cmd(dev, pcmdinfo);
	else
		list_add_tail(&pcmdinfo->cqp_cmd_entry, &dev->cqp_cmd_head);
	spin_unlock_irqrestore(&dev->cqp_lock, flags);
	return status;
}

/**
 * zxdh_process_bh - called from tasklet for cqp list
 * @dev: sc device struct
 */
int zxdh_process_bh(struct zxdh_sc_dev *dev)
{
	int status = 0;
	struct cqp_cmds_info *pcmdinfo;
	unsigned long flags;

	spin_lock_irqsave(&dev->cqp_lock, flags);
	while (!list_empty(&dev->cqp_cmd_head) && !zxdh_cqp_ring_full(dev->cqp)) {
		pcmdinfo = (struct cqp_cmds_info *)zxdh_remove_cqp_head(dev);
		if (!pcmdinfo)
			return -ENOMEM;
		status = zxdh_exec_cqp_cmd(dev, pcmdinfo);
		if (status)
			break;
	}
	spin_unlock_irqrestore(&dev->cqp_lock, flags);
	return status;
}

#if IS_ENABLED(CONFIG_CONFIGFS_FS)
/**
 * zxdh_set_irq_rate_limit- Configure interrupt rate limit
 * @dev: pointer to the device structure
 * @idx: vector index
 * @interval: Time interval in 4 usec units. Zero for no limit.
 */
void zxdh_set_irq_rate_limit(struct zxdh_sc_dev *dev, u32 idx, u32 interval)
{
	u32 reg_val = 0;

	if (interval) {
#define ZXDH_MAX_SUPPORTED_INT_RATE_INTERVAL 59 /* 59 * 4 = 236 us */
		if (interval > ZXDH_MAX_SUPPORTED_INT_RATE_INTERVAL)
			interval = ZXDH_MAX_SUPPORTED_INT_RATE_INTERVAL;
		reg_val = interval & ZXDH_GLINT_RATE_INTERVAL;
		reg_val |= FIELD_PREP(ZXDH_GLINT_RATE_INTRL_ENA, 1);
	}
	writel(reg_val, dev->hw_regs[ZXDH_GLINT_RATE] + idx);
}

#endif
/**
 * zxdh_cfg_aeq- Configure AEQ interrupt
 * @dev: pointer to the device structure
 * @irq_idx: vector index
 */
void zxdh_cfg_aeq(struct zxdh_sc_dev *dev, u32 irq_idx)
{
	struct zxdh_pci_f *rf;
	u32 hdr = 0;

	rf = container_of(dev, struct zxdh_pci_f, sc_dev);

	hdr = FIELD_PREP(ZXDH_AEQ_MSIX_DATA_VECTOR, irq_idx) |
	      FIELD_PREP(ZXDH_AEQ_MSIX_DATA_TC, 0) |
	      FIELD_PREP(ZXDH_AEQ_MSIX_DATA_VF_ACTIVE, rf->ftype) |
	      FIELD_PREP(ZXDH_AEQ_MSIX_DATA_VF_ID, rf->vf_id) |
	      FIELD_PREP(ZXDH_AEQ_MSIX_DATA_PF_ID, rf->pf_id);

	dma_wmb(); /* make sure WQE is written before valid bit is set */
	writel(hdr, dev->aeq_vhca_pfvf.aeq_msix_data);

	hdr = FIELD_PREP(ZXDH_AEQ_MSIX_CONFIG_IRQ, 0) |
	      FIELD_PREP(ZXDH_AEQ_MSIX_CONFIG_EPID, rf->ep_id);
	dma_wmb(); /* make sure WQE is written before valid bit is set */
	writel(hdr, dev->aeq_vhca_pfvf.aeq_msix_config);
}

int zxdh_sc_config_pte_table(struct zxdh_sc_dev *dev, struct zxdh_src_copy_dest src_dest)
{
	__le64 *wqe;
	u64 hdr;
	u32 tail = 0, val = 0, error = 0;
	int ret_code = 0;
	u64 scratch = 0;
	u64 src_path_index = 0, dest_path_index = 0;
	struct zxdh_path_index spath_index = {};
	struct zxdh_path_index dpath_index = {};

	if (!dev)
		return -ENOMEM;

	dpath_index.inter_select = ZXDH_INTERFACE_NOTCACHE; // not pass cache
	dpath_index.path_select = ZXDH_INDICATE_L2D; // L2D
	dpath_index.obj_id = ZXDH_L2D_OBJ_ID; // L2D
	dpath_index.vhca_id = dev->vhca_id;
	dest_path_index = zxdh_get_path_index(&dpath_index);

	spath_index.inter_select = ZXDH_INTERFACE_NOTCACHE; // not pass cache
	spath_index.path_select = ZXDH_INDICATE_HOST_NOSMMU;
	spath_index.obj_id = ZXDH_DMA_OBJ_ID;
	spath_index.vhca_id = dev->vhca_id;
	src_path_index = zxdh_get_path_index(&spath_index);

	wqe = zxdh_sc_cqp_get_next_send_wqe(dev->cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	set_64bit_val(wqe, 8, src_path_index);
	set_64bit_val(wqe, 16, src_dest.dest); // L2D Address
	set_64bit_val(wqe, 24, src_dest.src); // Physical_Buffer_Address
	set_64bit_val(wqe, 32, src_dest.len); // PTE_Length

	hdr = FIELD_PREP(ZXDH_CQPSQ_DESTPATHINDEX, dest_path_index) |
	      FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_WQE_DMA_WRITE) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, dev->cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	print_hex_dump_debug("WQE: QUERY_FPM WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);

	zxdh_get_cqp_reg_info(dev->cqp, &val, &tail, &error);

	zxdh_sc_cqp_post_sq(dev->cqp);

	ret_code = zxdh_cqp_poll_registers(dev->cqp, tail, dev->hw_attrs.max_done_count);
	return ret_code;
}
static int zxdh_query_flr_flag(struct zxdh_pci_f *rf)
{
	u32 cnt = 0, val = 0;
	struct zxdh_sc_dev *dev = &rf->sc_dev;

	if (rf->sc_dev.flr_query == ZXDH_FLR_QUERY_FLAG) {
		do {
			val = readl(dev->hw->hw_addr + C_RDMA_CQP_CONTEXT_6);
			if (val != ZXDH_FLR_OP_FLAG)
				return 0;
			if (cnt++ > ZXDH_FLR_QUERY_CNT) {
				writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMA_CQP_CONTEXT_6));
				writel(1,
				       (u32 __iomem *)(dev->hw->hw_addr + RDMATX_QUEUE_VHCA_FLAG));
				pr_err("[%s] val:0x%x vhca_id:%d timeout!\n", __func__, val,
				       rf->sc_dev.vhca_id);
				break;
			}
			msleep(ZXDH_FLR_QUERY_TIME);
		} while (val == ZXDH_FLR_OP_FLAG);
	}
	return 0;
}
static int zxdh_wait_fw_done(struct zxdh_pci_f *rf)
{
	u32 cnt = 0, val = 0, status = 0;
	struct zxdh_sc_dev *dev = &rf->sc_dev;

	do {
		val = readl((u32 __iomem *)(dev->hw->hw_addr + RDMARX_WAIT_FW_DONE));
		if (cnt++ > FW_TIME_WAIT_CNT) {
			status = -ETIMEDOUT;
			break;
		}
		if (val)
			break;
		mdelay(FW_TIME_WAIT_1S);
	} while (!val);
	pr_info("[%s] val:0x%x wait time: %ds\n", __func__, val, cnt);

	return status;
}
/**
 * zxdh_sc_dev_init - Initialize control part of device
 * @ver: version
 * @dev: Device pointer
 * @info: Device init info
 */
int zxdh_sc_dev_init(enum zxdh_rdma_vers ver, struct zxdh_sc_dev *dev,
		     struct zxdh_device_init_info *info)
{
	struct zxdh_pci_f *rf;
	int status = 0;
	int ret = 0;

	rf = container_of(dev, struct zxdh_pci_f, sc_dev);
	INIT_LIST_HEAD(&dev->cqp_cmd_head); /* for CQP command backlog */
	mutex_init(&dev->ws_mutex);
	dev->privileged = info->privileged;
	dev->num_vfs = info->max_vfs;
	dev->cache_id = 1;
	dev->ird_size = ICRDMA_MAX_IRD_SIZE;

	dev->hw = info->hw;
	dev->hw->hw_addr = info->bar0;
	dev->hmc_epid = (ZXDH_AXID_HOST_EP0 + dev->ep_id);
	/* Setup the hardware limits, hmc may limit further */
	dev->hw_attrs.min_hw_qp_id = ZXDH_MIN_IW_QP_ID;
	dev->hw_attrs.min_hw_aeq_size = ZXDH_MIN_AEQ_ENTRIES;
	dev->hw_attrs.max_hw_aeq_size = ZXDH_MAX_AEQ_ENTRIES;
	dev->hw_attrs.min_hw_ceq_size = ZXDH_MIN_CEQ_ENTRIES;
	dev->hw_attrs.max_hw_ceq_size = ZXDH_MAX_CEQ_ENTRIES;
	dev->hw_attrs.uk_attrs.min_hw_cq_size = ZXDH_MIN_CQ_SIZE;
	dev->hw_attrs.uk_attrs.max_hw_cq_size = ZXDH_MAX_CQ_SIZE;
	dev->hw_attrs.max_hw_outbound_msg_size = ZXDH_MAX_OUTBOUND_MSG_SIZE;
	dev->hw_attrs.max_mr_size = ZXDH_MAX_MR_SIZE;
	dev->hw_attrs.max_hw_inbound_msg_size = ZXDH_MAX_INBOUND_MSG_SIZE;
	dev->hw_attrs.uk_attrs.max_hw_inline = ZXDH_MAX_INLINE_DATA_SIZE;
	dev->hw_attrs.max_hw_wqes = ZXDH_MAX_WQ_ENTRIES;
	dev->hw_attrs.max_qp_wr = ZXDH_MAX_QP_WRS(ZXDH_MAX_QUANTA_PER_WR);
	dev->hw_attrs.max_srq_wr = ZXDH_MAX_SRQ_WRS;

	dev->hw_attrs.uk_attrs.max_hw_srq_wr = ZXDH_MAX_SRQ_WRS;
	dev->hw_attrs.uk_attrs.max_hw_rq_quanta = ZXDH_QP_SW_MAX_RQ_QUANTA;
	dev->hw_attrs.uk_attrs.max_hw_srq_quanta = ZXDH_QP_SW_MAX_SRQ_QUANTA;
	dev->hw_attrs.uk_attrs.max_hw_wq_quanta = ZXDH_QP_SW_MAX_WQ_QUANTA;
	dev->hw_attrs.max_hw_pds = ZXDH_MAX_PDS;
	dev->hw_attrs.max_hw_ena_vf_count = ZXDH_MAX_PE_ENA_VF_COUNT;

	dev->hw_attrs.max_done_count = ZXDH_DONE_COUNT;
	dev->hw_attrs.max_sleep_count = ZXDH_SLEEP_COUNT;
	dev->hw_attrs.max_cqp_compl_wait_time_ms = CQP_COMPL_WAIT_TIME_MS;
	dev->hw_attrs.cqp_timeout_threshold = CQP_TIMEOUT_THRESHOLD;
	dev->hw_attrs.self_health = false;

	dev->hw_attrs.uk_attrs.hw_rev = (u8)ver;
	if (!rf->ftype) {
		status = zxdh_wait_fw_done(rf);
		if (status)
			pr_info("[%s] FW undone! FW may have not been fully loaded after host is started.\n",
				__func__);
	}
	ret = zxdh_query_flr_flag(rf);
	spin_lock_init(&dev->vf_dev_lock);
	zxdh_init_hw(dev);
	return ret;
}

u16 zxdh_get_tc_8k_index_offset(u32 total_vhca, u16 vhca_8k_index_cnt, u8 traffic_class,
				u16 *tc_8k_index_num)
{
	u16 tc_8k_index_offset = 0;

	if (total_vhca <= 34) {
		*tc_8k_index_num = vhca_8k_index_cnt / 8;
		tc_8k_index_offset = (*tc_8k_index_num) * traffic_class;
	} else if (total_vhca <= 66) {
		*tc_8k_index_num = vhca_8k_index_cnt / 8;
		tc_8k_index_offset = (*tc_8k_index_num) * traffic_class;
	} else if (total_vhca <= 130) {
		*tc_8k_index_num = vhca_8k_index_cnt / 4;
		traffic_class /= 2;
		tc_8k_index_offset = (*tc_8k_index_num) * traffic_class;
	} else if (total_vhca <= 258) {
		*tc_8k_index_num = vhca_8k_index_cnt / 2;
		traffic_class /= 4;
		tc_8k_index_offset = (*tc_8k_index_num) * traffic_class;
	}

	return tc_8k_index_offset;
}

u16 zxdh_get_8k_index(struct zxdh_sc_qp *qp, u32 dest_ip)
{
	u16 tc_8k_index_offset, tc_8k_index_num;
	u16 dip_8k_index_offset;
	u16 qp_8k_index;

	if (qp->qp_uk.qp_type == ZXDH_QP_TYPE_ROCE_UD)
		return qp->dev->vhca_ud_8k_index;

	tc_8k_index_offset = zxdh_get_tc_8k_index_offset(
		qp->dev->total_vhca, qp->dev->vhca_8k_index_cnt, qp->user_pri, &tc_8k_index_num);
	dip_8k_index_offset = dest_ip % tc_8k_index_num;
	qp_8k_index = qp->dev->vhca_8k_index_start + tc_8k_index_offset + dip_8k_index_offset;
	return qp_8k_index;
}

/**
 * zxdh_init_destroy_aeq - destroy aeq
 * @rf: RDMA PCI function
 *
 * Issue a destroy aeq request and
 * free the resources associated with the aeq
 * The function is called during driver unload
 */
int zxdh_init_destroy_aeq(struct zxdh_pci_f *rf)
{
	struct zxdh_sc_cqp *cqp;
	struct zxdh_sc_dev *dev;
	__le64 *wqe;
	u64 hdr;
	u32 tail = 0, val = 0, error = 0;
	int ret_code = 0;
	u64 scratch = 0;

	dev = &rf->sc_dev;
	cqp = dev->cqp;
	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	set_64bit_val(wqe, 8, 0);

	set_64bit_val(wqe, 16, 0);

	hdr = FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_DESTROY_AEQ) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	print_hex_dump_debug("WQE: AEQ_DESTROY WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);

	zxdh_get_cqp_reg_info(dev->cqp, &val, &tail, &error);

	zxdh_sc_cqp_post_sq(dev->cqp);

	ret_code = zxdh_cqp_poll_registers(dev->cqp, tail, dev->hw_attrs.max_done_count);

	if (ret_code)
		return ret_code;

	return 0;
}

/**
 * zxdh_create_cqp_qp - create cqp qp
 * @rf: RDMA PCI function
 *
 * Issue a create cqp qp request and
 * create the resources associated with the cqp qp
 * The function is called during driver load
 */
int zxdh_create_cqp_qp(struct zxdh_pci_f *rf)
{
	struct zxdh_sc_cqp *cqp;
	struct zxdh_sc_dev *dev;
	struct zxdh_dma_mem *cqp_host_ctx;
	__le64 *wqe;
	u64 hdr;
	u32 tail = 0, val = 0, error = 0;
	int ret_code = 0;
	u64 scratch = 0;

	dev = &rf->sc_dev;
	cqp = dev->cqp;
	cqp_host_ctx = &rf->cqp_host_ctx;

	cqp_host_ctx->va = NULL;
	cqp_host_ctx->size = ALIGN(ZXDH_QP_CTX_SIZE, ZXDH_QPC_ALIGNMENT);
	cqp_host_ctx->va = dma_alloc_coherent(dev->hw->device, cqp_host_ctx->size,
					      &cqp_host_ctx->pa, GFP_KERNEL);

	if (!cqp_host_ctx->va)
		return -ENOMEM;

	memset(cqp_host_ctx->va, 0, cqp_host_ctx->size);

	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe) {
		dma_free_coherent(dev->hw->device, cqp_host_ctx->size, cqp_host_ctx->va,
				  cqp_host_ctx->pa);
		cqp_host_ctx->va = NULL;
		return -ENOSPC;
	}

	hdr = FIELD_PREP(RDMAQPC_TX_CQN, dev->base_cqn);
	set_64bit_val((__le64 *)cqp_host_ctx->va, 152, hdr);

	set_64bit_val((__le64 *)cqp_host_ctx->va, 160,
		      FIELD_PREP(RDMAQPC_TX_QPN, dev->base_qpn) |
			      FIELD_PREP(RDMAQPC_TX_VHCA_ID_LOW6, dev->vhca_id));

	set_64bit_val((__le64 *)cqp_host_ctx->va, 168,
		      FIELD_PREP(RDMAQPC_TX_VHCA_ID_HIGH4, RS_64_1(dev->vhca_id, 6)) |
			      FIELD_PREP(RDMAQPC_TX_QPSTATE, ZXDH_QPS_RTS));
	dma_wmb();

	hdr = FIELD_PREP(RDMAQPC_RX_CQN, dev->base_cqn);
	set_64bit_val((__le64 *)cqp_host_ctx->va, 376, hdr);
	dma_wmb();

	hdr = FIELD_PREP(RDMAQPC_RX_VHCA_ID, dev->vhca_id);
	set_64bit_val((__le64 *)cqp_host_ctx->va, 384, hdr);
	dma_wmb();

	set_64bit_val(wqe, 8, cqp_host_ctx->pa);
	set_64bit_val(wqe, 16, RDMAQPC_MASK_INIT);
	set_64bit_val(wqe, 24, RDMAQPC_MASK_INIT);
	set_64bit_val(wqe, 32, RDMAQPC_MASK_INIT);
	set_64bit_val(wqe, 40, RDMAQPC_MASK_INIT);
	hdr = FIELD_PREP(ZXDH_CQPSQ_QP_ID, cqp->dev->base_qpn) |
	      FIELD_PREP(ZXDH_CQPSQ_QP_CONTEXT_ID, cqp->dev->base_qpn) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity) |
	      FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_CREATE_QP);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	print_hex_dump_debug("WQE: AEQ_DESTROY WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);

	zxdh_get_cqp_reg_info(dev->cqp, &val, &tail, &error);

	zxdh_sc_cqp_post_sq(dev->cqp);

	ret_code = zxdh_cqp_poll_registers(dev->cqp, tail, dev->hw_attrs.max_done_count);

	if (ret_code) {
		dma_free_coherent(dev->hw->device, cqp_host_ctx->size, cqp_host_ctx->va,
				  cqp_host_ctx->pa);
		cqp_host_ctx->va = NULL;
		return ret_code;
	}
	return 0;
}

/**
 * zxdh_destroy_cqp_qp - destroy cqp qp
 * @rf: RDMA PCI function
 *
 * Issue a destroy cqp qp request and
 * free the resources associated with the cqp qp
 * The function is called during driver unload
 */
int zxdh_destroy_cqp_qp(struct zxdh_pci_f *rf)
{
	struct zxdh_sc_cqp *cqp;
	struct zxdh_sc_dev *dev;
	struct zxdh_dma_mem *cqp_host_ctx;
	__le64 *wqe;
	u64 hdr;
	u32 tail = 0, val = 0, error = 0;
	int ret_code = 0;
	u64 scratch = 0;

	dev = &rf->sc_dev;
	cqp = dev->cqp;
	cqp_host_ctx = &rf->cqp_host_ctx;

	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	set_64bit_val(wqe, 8, cqp_host_ctx->pa);
	set_64bit_val(wqe, 16, 0);
	set_64bit_val(wqe, 24, RDMAQPC_TX_MASKH_QP_STATE);
	set_64bit_val(wqe, 32, RDMAQPC_MASK_RESET);
	set_64bit_val(wqe, 40, RDMAQPC_MASK_RESET);
	hdr = FIELD_PREP(ZXDH_CQPSQ_QP_ID, cqp->dev->base_qpn) |
	      FIELD_PREP(ZXDH_CQPSQ_QP_CONTEXT_ID, cqp->dev->base_qpn) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity) |
	      FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_DESTROY_QP);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	print_hex_dump_debug("WQE: AEQ_DESTROY WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);

	zxdh_get_cqp_reg_info(dev->cqp, &val, &tail, &error);

	zxdh_sc_cqp_post_sq(dev->cqp);

	ret_code = zxdh_cqp_poll_registers(dev->cqp, tail, dev->hw_attrs.max_done_count);

	if (ret_code)
		return ret_code;

	dma_free_coherent(dev->hw->device, cqp_host_ctx->size, cqp_host_ctx->va, cqp_host_ctx->pa);
	cqp_host_ctx->va = NULL;

	return 0;
}

int zxdh_sc_query_mkey(struct zxdh_sc_cqp *cqp, u32 mkeyindex, u64 scratch, bool post_sq)
{
	__le64 *wqe;
	u64 hdr;
	u64 tmp = 0;

	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	hdr = FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_QUERY_MKEY) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity);

	set_64bit_val(wqe, 24, FIELD_PREP(ZXDH_CQPSQ_QUERY_MKEY, mkeyindex));

	dma_wmb();
	set_64bit_val(wqe, 0, hdr);

	if (post_sq)
		zxdh_sc_cqp_post_sq(cqp);

	get_64bit_val(wqe, 24, &tmp);

	return 0;
}

/**
 * zxdh_copy_ip_ntohl - copy IP address from  network to host
 * @dst: IP address in host order
 * @src: IP address in network order (big endian)
 */
void zxdh_copy_ip_ntohl(u32 *dst, __be32 *src)
{
	*dst++ = ntohl(*src++);
	*dst++ = ntohl(*src++);
	*dst++ = ntohl(*src++);
	*dst = ntohl(*src);
}

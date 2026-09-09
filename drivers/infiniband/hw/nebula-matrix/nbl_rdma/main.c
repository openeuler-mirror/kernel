// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include <rdma/nbl-abi.h>
#include <linux/bitfield.h>
#include <net/addrconf.h>
#include <linux/version.h>
#include "nbl_compat.h"
#include <linux/dma-map-ops.h>
#include "ah.h"
#include "cq.h"
#include "qp.h"
#include "wr.h"
#include "device.h"
#include "pble.h"
#include "mr.h"
#include "pd.h"
#include "gid.h"
#include "cqp.h"
#include "grc.h"
#include "debug.h"
#include "defs.h"
#include "ctrl.h"
#include "main.h"
#include "counters.h"
#include "dbgfs.h"
#include "grc.h"
#include "tlp.h"
#include "mailbox.h"
#include  "lag.h"
#include "../nbl_include/version.h"
#include "hw.h"
#include "umr.h"

MODULE_AUTHOR("Nebula-Matrix Corporation");
MODULE_DESCRIPTION("NBL(R) Ethernet Protocol Driver for RDMA");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_ALIAS("auxiliary:nbl.nbl.roce");
MODULE_ALIAS("auxiliary:nbl.nbl.roce_bond");
MODULE_VERSION(NBL_SNIC_RDMA_DRIVER_VERSION);

u8 host_id = HOST_ID_TYPE_ECPU;

u8 product_type = PRODUCT_TYPE_SNIC;

u8 rd_atom = NBL_MID_OST_RD_ATOMIC;
module_param(rd_atom, byte, 0640);
MODULE_PARM_DESC(
	rd_atom,
	"Maximal number of outstanding read or atomic: 8, 16, 32. Default=8");

static u32 tlp_timeout = NBL_TLP_TIMEOUT_MSEC;

static int nbl_init_device_type(struct nbl_pci_f *rf)
{
	switch (rf->pcidev->device) {
	case SNIC_RDMA_PF_START_DEVICE_ID...SNIC_RDMA_PF_END_DEVICE_ID:
		rf->sc_dev.is_ctrl_dev = true;
		fallthrough;
	case SNIC_RDMA_VF_DEVICE_ID:
		host_id = HOST_ID_TYPE_HOST;
		product_type = PRODUCT_TYPE_SNIC;
		break;
	case DPU_ECPU_PF2_DEVICE_ID:
	case DPU_ECPU_PF3_DEVICE_ID:
	case DPU_ECPU_PF4_DEVICE_ID:
	case DPU_ECPU_PF5_DEVICE_ID:
		host_id = HOST_ID_TYPE_ECPU;
		product_type = PRODUCT_TYPE_DPU;
		break;
	case DPU_HOST_RDMA_DEVICE_ID:
		host_id = HOST_ID_TYPE_HOST;
		product_type = PRODUCT_TYPE_DPU;
		break;
	default:
		nbl_dev_err(&rf->pcidev->dev,
			   "device id [%#x] not support.\n", rf->pcidev->device);
		return -EINVAL;
	}
	nbl_dev_dbg(&rf->pcidev->dev, "device id [%#x] product[%s] host_id[%d].\n",
		rf->pcidev->device, product_type == PRODUCT_TYPE_SNIC ? "SNIC" : "DPU", host_id);
	return 0;
}

static inline void nbl_init_rd_atomic_num(struct nbl_pci_f *rf)
{
	if (rd_atom == NBL_MAX_OST_RD_ATOMIC ||
		rd_atom == NBL_MID_OST_RD_ATOMIC)
		rf->nbl_actual_rd_atom = rd_atom;
	else
		rf->nbl_actual_rd_atom = NBL_MIN_OST_RD_ATOMIC;
}

static enum nbl_status_code nbl_set_attr_from_maxsge(struct nbl_sc_dev *dev,
						     u8 sge_cnt)
{
	if (sge_cnt > NBL_MAX_RQWQE_SGE)
		return NBL_ERR_SGE_NOTSUPPORTED;

	if (sge_cnt <= NBL_MIN_RQWQE_SGE)
		dev->hw_attrs.uk_attrs.max_hw_rq_quanta = NBL_MIN_RQ_QUANATA;
	else
		dev->hw_attrs.uk_attrs.max_hw_rq_quanta = NBL_MAX_RQ_QUANATA;
	dev->hw_attrs.uk_attrs.max_hw_wq_sges = sge_cnt;
	dev->hw_attrs.uk_attrs.max_hw_read_sges = sge_cnt;
	dev->hw_attrs.uk_attrs.max_hw_inline = NBL_MAX_WRITE_INLINE;
	dev->hw_attrs.max_qp_wr = NBL_MAX_QP_WR - NBL_SQ_RSVD;
	return NBL_SUCCESS;
}

static const struct ib_device_ops nbl_ib_dev_ops = {
	.owner = THIS_MODULE,
	.driver_id = (enum rdma_driver_id)RDMA_DRIVER_NBLPRIV,
	.uverbs_abi_ver = 3,
	.uverbs_no_driver_id_binding = 1,

	.alloc_ucontext = nbl_ib_alloc_ucontext,
	.dealloc_ucontext = nbl_ib_dealloc_ucontext,
	.disassociate_ucontext = nbl_ib_disassociate_ucontext,
	.get_dev_fw_str = nbl_ib_get_dev_fw_str,
	.query_pkey = nbl_ib_query_pkey,
	.get_port_immutable = nbl_ib_get_port_immutable,
	.get_link_layer = nbl_ib_get_link_layer,
	.modify_port = nbl_ib_modify_port,
	.query_device = nbl_ib_query_device,
	.query_port = nbl_ib_query_port,
	.get_netdev = nbl_ib_get_netdev,
	.alloc_hw_port_stats = nbl_alloc_hw_stats,

	.get_hw_stats = nbl_get_hw_stats,
	.alloc_mr = nbl_ib_alloc_mr,
	.reg_user_mr = nbl_ib_reg_user_mr,
	.rereg_user_mr = nbl_ib_rereg_user_mr,
	.dereg_mr = nbl_ib_dereg_mr,
	.map_mr_sg = nbl_ib_map_mr_sg,
	.mmap = nbl_ib_mmap,
	.mmap_free = nbl_ib_mmap_free,
	.get_dma_mr = nbl_ib_get_dma_mr,
	.alloc_mw = nbl_ib_alloc_mw,
	.dealloc_mw = nbl_ib_dealloc_mw,

	.req_notify_cq = nbl_ib_req_notify_cq,
	.create_cq = nbl_ib_create_cq,
	.destroy_cq = nbl_ib_destroy_cq,
	.poll_cq = nbl_ib_poll_cq,

	.create_qp = nbl_ib_create_qp,
	.modify_qp = nbl_ib_modify_qp,
	.destroy_qp = nbl_ib_destroy_qp,
	.query_qp = nbl_ib_query_qp,
	.post_send = nbl_ib_post_send,
	.post_recv = nbl_ib_post_recv,

	.create_ah = nbl_ib_create_ah,
	.create_user_ah = nbl_ib_create_ah,
	.destroy_ah = nbl_ib_destroy_ah,
	.query_ah = nbl_ib_query_ah,
	.alloc_pd = nbl_ib_alloc_pd,
	.dealloc_pd = nbl_ib_dealloc_pd,
	.add_gid = nbl_ib_add_gid,
	.del_gid = nbl_ib_del_gid,
	.query_gid = nbl_ib_query_gid,

	INIT_RDMA_OBJ_SIZE(ib_qp, nbl_qp, ibqp),
	INIT_RDMA_OBJ_SIZE(ib_pd, nbl_pd, ibpd),
	INIT_RDMA_OBJ_SIZE(ib_ah, nbl_ah, ibah),
	INIT_RDMA_OBJ_SIZE(ib_cq, nbl_cq, ibcq),
	INIT_RDMA_OBJ_SIZE(ib_ucontext, nbl_ucontext, ibucontext),
	INIT_RDMA_OBJ_SIZE(ib_mw, nbl_mr, ibmw),
};

static const struct ib_device_ops nbl_ib_dev_gdr_ops = {
	.reg_user_mr_dmabuf = nbl_ib_reg_user_mr_dmabuf,
};

static int nbl_shadow_init(struct nbl_pci_f *rf)
{
	int ret;

	/* QP */
	rf->qp_sd_info = kzalloc(sizeof(struct nbl_hmc_obj_sd_info), GFP_KERNEL);
	if (!rf->qp_sd_info)
		return -ENOMEM;

	ret = nbl_get_obj_sd_addr(rf, NBL_HMC_QP, rf->qp_sd_info);
	if (ret)
		goto free_qp_sd_info;

	/* CQ */
	rf->cq_sd_info = kzalloc(sizeof(struct nbl_hmc_obj_sd_info), GFP_KERNEL);
	if (!rf->cq_sd_info) {
		ret = -ENOMEM;
		goto free_obj_qp_sd_info;
	}

	ret = nbl_get_obj_sd_addr(rf, NBL_HMC_CQ, rf->cq_sd_info);
	if (ret)
		goto free_cq_sd_info;

	/* MRT */
	rf->mrt_sd_info = kzalloc(sizeof(struct nbl_hmc_obj_sd_info), GFP_KERNEL);
	if (!rf->mrt_sd_info) {
		ret = -ENOMEM;
		goto free_obj_cq_sd_info;
	}

	ret = nbl_get_obj_sd_addr(rf, NBL_HMC_MR, rf->mrt_sd_info);
	if (ret)
		goto free_mrt_sd_info;

	return 0;

free_mrt_sd_info:
	kfree(rf->mrt_sd_info);
free_obj_cq_sd_info:
	nbl_free_obj_sd_addr(rf->cq_sd_info);
free_cq_sd_info:
	kfree(rf->cq_sd_info);
free_obj_qp_sd_info:
	nbl_free_obj_sd_addr(rf->qp_sd_info);
free_qp_sd_info:
	kfree(rf->qp_sd_info);
	return ret;
}

static void nbl_shadow_exit(struct nbl_pci_f *rf)
{
	nbl_free_obj_sd_addr(rf->mrt_sd_info);
	kfree(rf->mrt_sd_info);
	nbl_free_obj_sd_addr(rf->cq_sd_info);
	kfree(rf->cq_sd_info);
	nbl_free_obj_sd_addr(rf->qp_sd_info);
	kfree(rf->qp_sd_info);
}

static void nbl_port_ibevent(struct nbl_device *nbl_dev)
{
	struct ib_event event;

	event.device = &nbl_dev->ibdev;
	event.element.port_num = 1;
	event.event = nbl_dev->status ? IB_EVENT_PORT_ACTIVE : IB_EVENT_PORT_ERR;
	ib_dispatch_event(&event);
}

static int nbl_ib_register_device(struct nbl_aux_dev *nbl_adev,
		struct nbl_device *nbl_dev)
{
	int ret;
	struct pci_dev *pcidev = nbl_dev->rf->pcidev;
	struct nbl_core_dev_info *cdev_info = nbl_adev->cdev_info;
	char name[IB_DEVICE_NAME_MAX];

	nbl_dev->ibdev.node_type = RDMA_NODE_IB_CA;
	addrconf_addr_eui48((u8 *)&nbl_dev->ibdev.node_guid, nbl_dev->netdev->dev_addr);
	nbl_dev->ibdev.dev.parent = &pcidev->dev;
	nbl_dev->ibdev.local_dma_lkey = 0; /* not supported for now */
	nbl_dev->ibdev.phys_port_cnt = 1;
	nbl_dev->ibdev.num_comp_vectors = nbl_dev->rf->ceqs_count;

	ret = ib_device_set_netdev(&nbl_dev->ibdev, nbl_dev->netdev, 1);
	if (ret) {
		nbl_ib_err(&nbl_dev->rf->sc_dev,
			   "link the ib_device to netdev err=%d.\n", ret);
		return ret;
	}

	/* common uverbs cmd mask set here, just for kernel version < 5.11 */
	nbl_set_uverbs_cmd_mask_common(nbl_dev);
	nbl_dev->ibdev.uverbs_cmd_mask |= BIT_ULL(IB_USER_VERBS_CMD_REQ_NOTIFY_CQ);

	ib_set_device_ops(&nbl_dev->ibdev, &nbl_ib_dev_gdr_ops);

	ib_set_device_ops(&nbl_dev->ibdev, &nbl_ib_dev_ops);

	dma_set_max_seg_size(nbl_dev->rf->hw.device, SZ_2G);
	if (cdev_info->is_lag)
		snprintf(name, IB_DEVICE_NAME_MAX - 1, "nbl_bond%d", nbl_adev->adev.id);
	else
		snprintf(name, IB_DEVICE_NAME_MAX - 1, "nbl%d",
			 nbl_adev->adev.id);
	ret = kc_ib_register_device(&nbl_dev->ibdev, name,
				 nbl_dev->rf->hw.device);
	if (ret)
		return ret;

	return 0;
}

static void nbl_ib_unregister_device(struct nbl_device *nbl_dev)
{
	ib_unregister_device(&nbl_dev->ibdev);
}

static int nbl_fill_device_info(struct nbl_device *nbl_dev,
				 struct nbl_core_dev_info *cdev_info)
{
	struct nbl_pci_f *rf = nbl_dev->rf;

	rf->hw.hw_addr = cdev_info->hw_addr;
	rf->pcidev = cdev_info->pdev;
	rf->msix_count = cdev_info->msix_count;
	rf->msix_entries = cdev_info->msix_entries;
	if (cdev_info->is_lag) {
		/* Need to get master only is_lag is true.
		 * Otherwise, it will get an unregistering bond dev when bond is delete
		 */
		rcu_read_lock();
		nbl_dev->netdev =
			netdev_master_upper_dev_get_rcu(cdev_info->netdev);
		rcu_read_unlock();
	}
	if (!nbl_dev->netdev)
		nbl_dev->netdev = cdev_info->netdev;

	if (nbl_dev->netdev->reg_state != NETREG_REGISTERED) {
		nbl_dev_err(&cdev_info->pdev->dev,
			    "netdev %s reg_state:%d is not registered\n",
			    nbl_dev->netdev->name, nbl_dev->netdev->reg_state);
		return -EINVAL;
	}

	rf->cdev = cdev_info;
	rf->vsi_id = cdev_info->vsi_id;

	rf->sc_dev.fwd = NBL_DEFAULT_FWD;
	rf->sc_dev.dport = NBL_DEFAULT_DPORT;
	rf->sc_dev.dport_id = cdev_info->eth_id;
	rf->sc_dev.rss_lag_en = NBL_DEFAULT_RSS_LAG_EN;
	rf->sc_dev.tunnel_en = NBL_DEFAULT_TUNNEL_EN;
	rf->sc_dev.ackreq_th = NBL_DEFAULT_ACKREQ_TH;
	rf->sc_dev.fmr_nofence = 0;
	rf->sc_dev.cc_mode = 0;
	rf->tlp_timeout = tlp_timeout;
	rf->sc_dev.pcie_func_id = cdev_info->function_id;
	rf->sc_dev.debug_errcdoe = NBL_QP_INVALD_ERRCODE;
	rf->sc_dev.batch_wqe_th = NBL_DEFAULT_BATCH_WQE_TH;
	rf->sc_dev.dwqe_en = 1;
	rf->sc_dev.qpn_interval = QPN_INTERVAL;
	rf->lag_bsport = (get_random_u32() % (IB_ROCE_UDP_ENCAP_VALID_PORT_MAX + 1 -
		IB_ROCE_UDP_ENCAP_VALID_PORT_MIN) + IB_ROCE_UDP_ENCAP_VALID_PORT_MIN);
	return 0;
}

int nbl_exec_cmd(struct nbl_pci_f *rf, void *in, int in_size, void *out,
		int out_size)
{
	int ret_val = 0;
	u8 *mbx_ret;

	if (rf->sc_dev.has_high_temp_alarm) {
		mbx_ret = (u8 *)out;
		*mbx_ret = 0;
		return 0;
	}

	if (product_type == PRODUCT_TYPE_SNIC)
		ret_val = nbl_mbx_exec(rf, in, in_size, out, out_size);
	else if (product_type == PRODUCT_TYPE_DPU) {
		if (host_id == HOST_ID_TYPE_HOST)
			ret_val = nbl_tlp_exec(rf, in, in_size, out, out_size);
		else if (host_id == HOST_ID_TYPE_ECPU)
			ret_val = nbl_grc_exec(rf, in, in_size, out, out_size);
		else {
			nbl_pr_err("invalid host_id=%u", host_id);
			return -EINVAL;
		}
	} else
		nbl_pr_err("invalid product_type=%u", product_type);

	return ret_val;
}

int nbl_setup_voa(struct nbl_pci_f *rf)
{
	int ret_val;
	uint8_t in[64];
	uint8_t out[64];
	int data_len = 0;
	struct grc_cache_msg_header *head;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_SET_VOA;
	head->payload_len = sizeof(rf->sc_dev.function_id);
	data_len += sizeof(struct grc_cache_msg_header);

	memcpy(in + data_len, &rf->sc_dev.function_id, sizeof(rf->sc_dev.function_id));
	data_len += sizeof(rf->sc_dev.function_id);

	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val) {
		nbl_ib_err(&rf->sc_dev, "set voa tbl cmd err=%d", ret_val);
		return ret_val;
	}

	return 0;
}

int nbl_destroy_voa(struct nbl_pci_f *rf)
{
	int ret_val;
	uint8_t in[64];
	uint8_t out[64];
	int data_len = 0;
	struct grc_cache_msg_header *head;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_DESTROY_VOA;
	head->payload_len = sizeof(rf->sc_dev.function_id);
	data_len += sizeof(struct grc_cache_msg_header);

	memcpy(in + data_len, &rf->sc_dev.function_id, sizeof(rf->sc_dev.function_id));
	data_len += sizeof(rf->sc_dev.function_id);

	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val) {
		nbl_ib_err(&rf->sc_dev, "destroy voa tbl cmd err=%d", ret_val);
		return ret_val;
	}

	return 0;
}

int nbl_query_voa(char __user *buf, size_t count, loff_t *pos, struct nbl_pci_f *rf)
{
	int ret_val;
	__be64 *in;
	u32 in_size = NBL_CMD_INPUT_SIZE;
	__be64 *out;
	u32 out_size = NBL_CMD_OUTPUT_SIZE;
	struct nbl_hmc_voa_entry voa_ent = {0};
	int i;
	u8 voa_str[VOA_TBL_STR_LEN] = {0};
	int voa_len = 0;
	char *voa_head = "page_sz: 1 notes 2MB, 0 4KB; page_mode: 0 notes level0 addr,1 level1\n";

	if (*pos)
		return 0;

	in = kzalloc(in_size, GFP_KERNEL);
	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;
	out = kzalloc(out_size, GFP_KERNEL);
	if (!out) {
		kfree(in);
		return NBL_ERR_ALLOCMEM_FAILED;
	}

	nbl_ib_dbg(&rf->sc_dev, "query voa(fun %u) begin\n", rf->sc_dev.function_id);

	set_64bit_val(
			in, 0,
			FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_QUERY_VOA) |
			FIELD_PREP(NBL_CQP_QUERY_VOA_VFID, rf->sc_dev.function_id));

	ret_val = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, out, NBL_CMD_OUTPUT_SIZE);
	if (ret_val) {
		nbl_ib_err(&rf->sc_dev, "cqp cmd failed,err=%d\n", ret_val);
	} else {
		voa_len += snprintf(voa_str + voa_len, sizeof(voa_str) - strlen(voa_head),
				    "%s", voa_head);
		for (i = 0; i < NBL_HMC_MAX; i++) {
			get_64bit_val(out, VOA_QPC_OFFSET + i * VOA_ENT_SIZE, (u64 *)&voa_ent);
			voa_len += snprintf(voa_str + voa_len, sizeof(voa_str) - voa_len,
					    VOA_TBL_ENTRY_FORMAT,
					    i, voa_ent.valid, voa_ent.obj_ba, voa_ent.obj_max_cnt,
					    voa_ent.obj_sz, voa_ent.page_sz, voa_ent.addr_mode);
			memset(&voa_ent, 0, sizeof(voa_ent));
		}

		ret_val = simple_read_from_buffer(buf, count, pos, voa_str, sizeof(voa_str));
	}
	kfree(in);
	kfree(out);
	return ret_val;
}

static int nbl_get_function_num(struct nbl_pci_f *rf, u16 *req_function_id)
{
	int ret_val;
	u16 function_id;
	uint8_t in[64];
	uint8_t out[64];
	u8 data_len = 0;
	struct get_function_id_req req;
	struct grc_cache_msg_header *head;
	struct nbl_core_dev_info *cdev_info = (struct nbl_core_dev_info *)rf->cdev;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_GET_FUNCTION_ID;
	head->payload_len = sizeof(struct get_function_id_req);
	data_len += sizeof(struct grc_cache_msg_header);

	req.host_id = host_id;
	req.bdf_num = cdev_info->real_bus << 8 | cdev_info->real_dev << 3 |
		cdev_info->real_function;

	nbl_pr_dbg("req host_id=0x%x,bdf_num=0x%x,bus=0x%x,devfn=0x%x", host_id,
		req.bdf_num, rf->pcidev->bus->number, rf->pcidev->devfn);

	memcpy(in + data_len, &req, sizeof(req));
	data_len += sizeof(req);

	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val) {
		nbl_dev_err(&rf->pcidev->dev, "get function_id cmd err=%d", ret_val);
		return ret_val;
	}

	memcpy(&function_id, out + 1, sizeof(function_id));
	*req_function_id = function_id;

	nbl_pr_dbg("resp got function_id=%u", function_id);
	return 0;
}

static int nbl_free_function_num(struct nbl_pci_f *rf)
{
	int ret_val;
	uint8_t in[64];
	uint8_t out[64];
	u8 data_len = 0;
	struct free_function_id_req req;
	struct grc_cache_msg_header *head;
	struct nbl_core_dev_info *cdev_info = (struct nbl_core_dev_info *)rf->cdev;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_FREE_FUNC_ID;
	head->payload_len = sizeof(struct free_function_id_req);
	data_len += sizeof(struct grc_cache_msg_header);

	req.host_id = host_id;
	req.bdf_num = cdev_info->real_bus << 8 | cdev_info->real_dev << 3 |
		cdev_info->real_function;
	req.function_id = rf->sc_dev.function_id;

	memcpy(in + data_len, &req, sizeof(req));
	data_len += sizeof(req);

	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val) {
		nbl_ib_err(&rf->sc_dev, "get function_id cmd err=%d", ret_val);
		return ret_val;
	}

	nbl_ib_dbg(&rf->sc_dev, "free function_id=%u success", rf->sc_dev.function_id);
	return 0;
}

static int nbl_set_hdma_vf_enable(struct nbl_pci_f *rf, u8 enable)
{
	int ret_val;
	u8 in[NBL_GRC_INPUT_SIZE] = {0};
	u8 out[NBL_GRC_INPUT_SIZE] = {0};
	u8 data_len = 0;
	struct grc_cache_msg_header *head;
	struct set_hdma_vf_enable_req req = {0};

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_SET_VF_ENABLE;
	head->payload_len = sizeof(struct set_hdma_vf_enable_req);
	data_len += sizeof(struct grc_cache_msg_header);

	req.function_id = rf->sc_dev.function_id;
	req.enable = enable;

	memcpy(in + data_len, &req, sizeof(req));
	data_len += sizeof(req);

	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val) {
		nbl_pr_err("cmd err=%d", ret_val);
		return ret_val;
	}

	nbl_pr_dbg("function_id=%u success", rf->sc_dev.function_id);
	return 0;
}

static int nbl_get_init_params(struct nbl_pci_f *rf)
{
	int ret_val;
	uint8_t in[64] = {0};
	uint8_t out[64];
	u8 data_len = 0;
	struct grc_cache_msg_header *head;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_GET_INIT_PARAM;
	head->payload_len = 0;
	data_len += sizeof(struct grc_cache_msg_header);

	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val) {
		nbl_pr_err("get init params cmd err=%d", ret_val);
		return ret_val;
	}

	memcpy(&rf->init_params, out + 1, sizeof(rf->init_params));

	nbl_pr_dbg("get init params,sd_addr_mode=%u", rf->init_params.sd_addr_mode);

	rf->addr_mode = rf->init_params.sd_addr_mode;

	return 0;
}

static int nbl_channel_init(struct nbl_pci_f *rf)
{
	int ret_val;

	if (product_type == PRODUCT_TYPE_SNIC)
		ret_val = nbl_mbx_roce_init(rf);
	else if (product_type == PRODUCT_TYPE_DPU)
		if (host_id == HOST_ID_TYPE_ECPU)
			ret_val = nbl_grc_init(rf);
		else if (host_id == HOST_ID_TYPE_HOST)
			ret_val = nbl_tlp_init(rf);
		else {
			nbl_pr_err("invalid host_id=%u", host_id);
			return -EINVAL;
		}
	else {
		nbl_pr_err("invalid product_type=%u", product_type);
		return -EINVAL;
	}

	if (ret_val)
		nbl_pr_err("channel init err=%d,host_id=%u", ret_val, host_id);

	return ret_val;
}

static void nbl_channel_exit(struct nbl_pci_f *rf)
{
	if (product_type == PRODUCT_TYPE_SNIC)
		nbl_mbx_roce_exit(rf);
	else if (product_type == PRODUCT_TYPE_DPU) {
		if (host_id == HOST_ID_TYPE_ECPU)
			nbl_grc_exit(rf);
		else if (host_id == HOST_ID_TYPE_HOST)
			nbl_tlp_exit(rf);
		else {
			nbl_pr_err("channel exit invalid host_id=%u", host_id);
			return;
		}
	} else
		nbl_pr_err("channel exit invalid product_type=%u", product_type);
}

static void nbl_rdma_dsch_init(struct nbl_pci_f *rf, u8 is_valid)
{
	int ret_val;
	uint8_t in[64];
	uint8_t out[64];
	int data_len = 0;
	struct set_rdma_dsch_req req = {0};
	struct grc_cache_msg_header *head;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_SET_DSCH;
	head->payload_len = sizeof(struct set_rdma_dsch_req);
	data_len += sizeof(struct grc_cache_msg_header);

	req.function_id = rf->sc_dev.function_id;
	req.host_id = host_id;
	req.dport_id = rf->sc_dev.dport_id;
	req.is_valid = is_valid;
	memcpy(in + data_len, &req, sizeof(req));
	data_len += sizeof(req);

	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val)
		nbl_ib_err(&rf->sc_dev, "set rdma dsch cmd err=%d", ret_val);
}

static void nbl_query_fmr_nofence(struct nbl_pci_f *rf)
{
	int ret_val;
	uint8_t in[NBL_CMD_INPUT_SIZE];
	uint8_t out[NBL_CMD_OUTPUT_SIZE];
	int data_len = 0;
	uint8_t fmr_nofence = 0;
	struct grc_cache_msg_header *head;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_QUERY_FMR_NOFENCE;
	data_len += sizeof(struct grc_cache_msg_header);

	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val) {
		nbl_ib_err(&rf->sc_dev, "query grc fmr nofence cmd err=%d", ret_val);
		fmr_nofence = false;
	} else
		memcpy(&fmr_nofence, out + 1, sizeof(fmr_nofence));
	rf->sc_dev.fmr_nofence = fmr_nofence;
}

void nbl_rdma_update_dsch_info(struct nbl_pci_f *rf)
{
	int ret_val;
	uint8_t in[64];
	uint8_t out[64];
	int data_len = 0;
	struct set_rdma_dsch_req req = {0};
	struct grc_cache_msg_header *head;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_UPDATE_DSCH;
	head->payload_len = sizeof(struct set_rdma_dsch_req);
	data_len += sizeof(struct grc_cache_msg_header);

	req.function_id = rf->sc_dev.function_id;
	req.host_id = host_id;
	req.dport_id = (rf->sc_dev.dport_id < NBL_ETH_MAX_NUM ? rf->sc_dev.dport_id : 0);
	req.is_valid = 1;
	memcpy(in + data_len, &req, sizeof(req));
	data_len += sizeof(req);

	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val)
		nbl_ib_err(&rf->sc_dev, "update rdma dsch cmd err=%d", ret_val);
}

int nbl_set_dif_vf_en(struct nbl_pci_f *rf, bool is_off)
{
	int ret_val;
	uint8_t in[NBL_GRC_INPUT_SIZE];
	uint8_t out[NBL_GRC_OUTPUT_SIZE];
	int data_len;
	struct grc_cache_msg_header *head;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_SET_DIF_VF_EN;
	head->payload_len = sizeof(bool);

	data_len = sizeof(struct grc_cache_msg_header);
	memcpy(in + data_len, &is_off, sizeof(bool));
	data_len += sizeof(bool);

	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val) {
		nbl_dev_err(&rf->pcidev->dev,
			    "set_dif_vf_en cmd err=%d, val=%#x\n", ret_val,
			    is_off);
		return ret_val;
	}
	return 0;
}

static int nbl_set_one_vsi_map(struct nbl_pci_f *rf, u8 is_valid, u16 vsi_id)
{
	int ret_val;
	uint8_t in[NBL_GRC_INPUT_SIZE];
	uint8_t out[NBL_GRC_OUTPUT_SIZE];
	int data_len;
	struct set_vfid_vsi_map_req req = {0};
	struct grc_cache_msg_header *head;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_SET_VFID_VSI_MAP;
	head->payload_len = sizeof(struct set_vfid_vsi_map_req);

	req.function_id = rf->sc_dev.function_id;
	req.valid = is_valid;
	req.vsi_id = vsi_id;
	data_len = sizeof(struct grc_cache_msg_header);
	memcpy(in + data_len, &req, sizeof(req));
	data_len += sizeof(req);

	nbl_dev_dbg(&rf->pcidev->dev,
		    "RoCE set_vfid_vsi_map vsi_id=%u,vfid=%u,valid=%u",
		    req.vsi_id, rf->sc_dev.function_id, is_valid);
	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val) {
		nbl_dev_err(
			&rf->pcidev->dev,
			"set_vfid_vsi_map cmd err=%d,vsi_id=%u,vfid=%u,valid=%u",
			ret_val, req.vsi_id, rf->sc_dev.function_id, is_valid);
		return ret_val;
	}
	return 0;
}

int nbl_set_vfid_vsi_map(struct nbl_pci_f *rf, u8 is_valid)
{
	int i;
	int ret_val = 0;
	struct nbl_core_dev_info *cdev_info =
		(struct nbl_core_dev_info *)rf->cdev;

	if (!cdev_info->is_lag)
		ret_val = nbl_set_one_vsi_map(rf, is_valid, cdev_info->vsi_id);
	else {
		for (i = 0; i < NBL_RDMA_LAG_MAX_PORTS; i++) {
			if (cdev_info->lag_info.lag_mem[i].active) {
				ret_val = nbl_set_one_vsi_map(
					rf, is_valid,
					cdev_info->lag_info.lag_mem[i].vsi_id);
				if (ret_val)
					return ret_val;
			}
		}
	}

	return ret_val;
}

static inline bool nbl_dma_iommu_status(struct pci_dev *pdev)
{
	struct device *dev = &pdev->dev;

	return (dev->iommu_group && iommu_get_domain_for_dev(dev));
}

static inline bool nbl_dma_remap_status(struct pci_dev *pdev)
{
	struct device *dev = &pdev->dev;
	const struct dma_map_ops *ops = get_dma_ops(dev);

	return !!ops;
}

static void nbl_reserve_low_64k_iova(struct pci_dev *pdev)
{
	bool iommu_status, remap_status;
	struct iommu_domain *iommu;
	struct iommu_dma_cookie *cookie;
	struct iova_domain *iovad;
	unsigned long lo;
	unsigned long hi;
	struct iova *iova;
	int i;

	iommu_status = nbl_dma_iommu_status(pdev);
	remap_status = nbl_dma_remap_status(pdev);
	nbl_pr_dbg("iommu_status:%d remap_status:%d\n", iommu_status,
		   remap_status);
	if (!iommu_status || !remap_status)
		return;
	iommu = iommu_get_domain_for_dev(&pdev->dev);
	cookie = iommu->iova_cookie;
	/* iommu=on and pt=off */
	if (cookie && cookie->type == IOMMU_DMA_IOVA_COOKIE) {
		iovad = &cookie->iovad;
		/* per page reserve  */
		for (i = 0; i < NBL_RESERVE_RANGE_IOVA / iovad->granule; i++) {
			lo = iova_pfn(iovad, NBL_RESERVE_START_IOVA +
						     iovad->granule * i);
			hi = iova_pfn(iovad, NBL_RESERVE_START_IOVA +
						     iovad->granule * (i + 1));
			/* iova just for debug */
			iova = reserve_iova(iovad, lo, hi);
			if (!iova)
				nbl_dev_err(
					&pdev->dev,
					"iova pfn lo:%#lx hi:%#lx reserve failed!\n",
					lo, hi);
			nbl_pr_dbg("lo:%#lx hi:%#lx iova:%p\n", lo, hi, iova);
		}
	}
}

static int nbl_grc_register_client(struct nbl_pci_f *rf, bool is_register)
{
	u8 in[NBL_CMD_INPUT_SIZE];
	u8 out[NBL_CMD_OUTPUT_SIZE];
	int data_len = 0;
	int ret;
	struct grc_cache_msg_header *head;
	struct register_client_req req;
	struct nbl_core_dev_info *cdev_info =
		(struct nbl_core_dev_info *)rf->cdev;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = is_register ? GRC_MSG_OP_REGISTER_CLIENT :
					    GRC_MSG_OP_UNREGISTER_CLIENT;
	head->payload_len = sizeof(struct register_client_req);
	data_len += sizeof(struct grc_cache_msg_header);

	req.vsi_id = cdev_info->vsi_id;
	req.eth_id = cdev_info->eth_id;
	req.function_id = rf->sc_dev.function_id;
	req.real_bdf = PCI_DEVID(cdev_info->real_bus,
				 PCI_DEVFN(cdev_info->real_dev,
					   cdev_info->real_function));
	memcpy(in + data_len, &req, sizeof(req));
	data_len += sizeof(req);

	ret = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret != 0)
		nbl_pr_err("mailbox %s client err=%d\n",
			   is_register ? "register" : "unregister", ret);

	return ret;
}

static bool pcie_is_support_atomic_cap(struct pci_dev *pcidev)
{
	u16 pcie_ctl2 = 0;

	pcie_capability_read_word(pcidev, PCI_EXP_DEVCTL2, &pcie_ctl2);
	return (pcie_ctl2 & PCI_EXP_DEVCTL2_ATOMIC_REQ);
}

static void nbl_pci_set_atomic(struct nbl_device *dev, struct pci_dev *pdev)
{
	static bool pf_support_atomic;

	if (!pdev->is_virtfn) {
		/* PF: try to enable atomic cap */
		int rc = pci_enable_atomic_ops_to_root(
			pdev, PCI_EXP_DEVCAP2_ATOMIC_COMP64);
		if (!rc) {
			bool is_support_atomic =
				pcie_is_support_atomic_cap(pdev);

			if (is_support_atomic) {
				pf_support_atomic = true;
				dev->atomic_cap = IB_ATOMIC_GLOB;
				nbl_dev_dbg(&pdev->dev,
					    "Atomic capability enabled\n");
				return;
			}
		}
	} else {
	   /*
	    * Per PCIe r5.0, sec 9.3.5.10, the AtomicOp Requester Enable bit
	    * in Device Control 2 is reserved in VFs and the PF value applies
	    * to all associated VFs.
	    */
		if (pf_support_atomic) {
			dev->atomic_cap = IB_ATOMIC_GLOB;
			nbl_dev_dbg(&pdev->dev, "Atomic capability enabled\n");
			return;
		}
	}

	dev->atomic_cap = IB_ATOMIC_NONE;
	nbl_dev_info(&pdev->dev, "Atomic capability disabled\n");
}

static int nbl_high_temp_event_process(struct auxiliary_device *aux_dev,
				       enum nbl_core_reset_event event)
{
	struct nbl_device *nbl_dev = dev_get_drvdata(&aux_dev->dev);
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_qp *qp;
	u32 qpn_offset = NBL_QP_NUM_FOR_CM;
	u32 qpn;
	struct ib_event ib_evt;

	dev_info(&rf->pcidev->dev, "rdma recv high temp event=%d,vfid=%u",
		 event, rf->sc_dev.function_id);

	if (event != NBL_CORE_FATAL_ERR_EVENT)
		return -EINVAL;

	qpn = find_next_bit(rf->allocated_qps, rf->max_qp, qpn_offset);
	dev_info(&rf->pcidev->dev, "vfid=%u,got first qpn=%u", rf->sc_dev.function_id, qpn);
	while (qpn < rf->max_qp && rf->qp_table[qpn]) {
		qp = rf->qp_table[qpn];
		set_64bit_val(qp->sc_qp.qp_shadow.va, 0,
			FIELD_PREP(NBL_QPC_SHADOW_HIGH_TEMP_ALARM_FLAG, 1));
		qpn_offset = qpn + 1;
		qpn = find_next_bit(rf->allocated_qps, rf->max_qp, qpn_offset);
	}

	ib_evt.device = &nbl_dev->ibdev;
	ib_evt.element.port_num = 1;
	ib_evt.event = IB_EVENT_DEVICE_FATAL;
	ib_dispatch_event(&ib_evt);

	rf->sc_dev.has_high_temp_alarm = true;
	dev_info(&rf->pcidev->dev, "vfid=%u finish high temp event process",
		 rf->sc_dev.function_id);
	return 0;
}

static void nbl_set_pp0_bypass(struct nbl_pci_f *rf, bool enable)
{
	u32 reg_val = enable ? 0x6a : 0;

	if (nbl_grc_write_reg(rf, NBL_REG_PP0_RDMA_BYPASS, reg_val))
		nbl_pr_err("failed to write pp0 rdma_bypass into reg:%#x\n",
				NBL_REG_PP0_RDMA_BYPASS);
}

static int nbl_enable_rdma_dump(struct auxiliary_device *adev, bool enable)
{
	struct nbl_device *nbl_dev = dev_get_drvdata(&adev->dev);
	struct nbl_pci_f *rf = nbl_dev->rf;

	nbl_pr_dbg("begin enable rdma dump, enable=%u\n", enable);
	rf->sc_dev.fwd = enable ? NBL_NORMAL_FWD : NBL_DEFAULT_FWD;
	rf->sc_dev.dev_dump_flag = enable;
	nbl_set_pp0_bypass(rf, false);
	nbl_modify_qp_fwd(rf);

	return 0;
}

static int nbl_netdevice_event(struct notifier_block *notifier, unsigned long event, void *ptr)
{
	struct nbl_device *nbl_dev;
	struct ib_device *ib_dev;
	struct net_device *net_dev = netdev_notifier_info_to_dev(ptr);
	struct nbl_sc_dev *sc_dev;

	nbl_dev = container_of(notifier, struct nbl_device, nb);
	if (nbl_dev->netdev != net_dev)
		return NOTIFY_DONE;

	ib_dev = &nbl_dev->ibdev;
	sc_dev = &nbl_dev->rf->sc_dev;
	nbl_ib_dbg(sc_dev, "netdev:%s ibdev:%s recv event:%ld\n", net_dev->name,
		   ib_dev->name, event);
	nbl_dev->status = 1;
	switch (event) {
	case NETDEV_DOWN:
		nbl_dev->status = 0;
		fallthrough;
	case NETDEV_UP:
		nbl_port_ibevent(nbl_dev);
		break;
	default:
		break;
	}
	return NOTIFY_DONE;
}

static int nbl_add_netdev_notifier(struct nbl_device *nbl_dev)
{
	int err;
	struct notifier_block *notify_blk;
	struct netdev_net_notifier *netdevice_nn;

	nbl_dev->nb.notifier_call = nbl_netdevice_event;
	notify_blk = &nbl_dev->nb;
	netdevice_nn = &nbl_dev->netdevice_nn;
	err = register_netdevice_notifier_dev_net(nbl_dev->netdev, notify_blk, netdevice_nn);
	if (err) {
		nbl_dev->nb.notifier_call = NULL;
		return err;
	}

	dev_hold(nbl_dev->netdev);
	return 0;
}

static void nbl_remove_netdev_notifier(struct nbl_device *nbl_dev)
{
	struct notifier_block *notif_blk;
	struct netdev_net_notifier *netdevice_nn;

	if (nbl_dev->nb.notifier_call) {
		notif_blk = &nbl_dev->nb;
		netdevice_nn = &nbl_dev->netdevice_nn;
		unregister_netdevice_notifier_dev_net(nbl_dev->netdev, notif_blk, netdevice_nn);
		nbl_dev->nb.notifier_call = NULL;
		dev_put(nbl_dev->netdev);
	}
}

static int nbl_probe(struct auxiliary_device *aux_dev,
		     const struct auxiliary_device_id *id)
{
	struct nbl_aux_dev *adev = container_of(aux_dev, struct nbl_aux_dev, adev);
	struct nbl_core_dev_info *cdev_info = adev->cdev_info;
	struct nbl_pci_f *rf = NULL;
	struct nbl_device *nbl_dev = ib_alloc_device(nbl_device, ibdev);
	int err;
	size_t size;

	size = sizeof(struct nbl_device) +
	       BUILD_BUG_ON_ZERO(offsetof(struct nbl_device, ibdev));

	if (!nbl_dev) {
		nbl_dev_err(&cdev_info->pdev->dev, "ib alloc device get NULL");
		return -ENOMEM;
	}
	nbl_dev->rf = kzalloc(sizeof(*rf), GFP_KERNEL);
	if (!nbl_dev->rf) {
		ib_dealloc_device(&nbl_dev->ibdev);
		nbl_dev_err(&cdev_info->pdev->dev, "ib alloc rf mem err");
		return -ENOMEM;
	}
	nbl_reserve_low_64k_iova(cdev_info->pdev);
	rf = nbl_dev->rf;
	err = nbl_fill_device_info(nbl_dev, cdev_info);
	if (err)
		goto err_channel_init;

	nbl_dev_info(&cdev_info->pdev->dev, "probe rdma device for %s\n",
		     nbl_dev->netdev->name);
	err = nbl_init_device_type(rf);
	if (err)
		goto err_channel_init;

	nbl_init_src_addr_list(rf);

	nbl_init_rd_atomic_num(rf);

	nbl_pci_set_atomic(nbl_dev, rf->pcidev);

	err = nbl_channel_init(rf);
	if (err) {
		nbl_dev_err(&cdev_info->pdev->dev, "channel init return err=%d", err);
		goto err_channel_init;
	}

	rf->maxsge_limit = NBL_DEFAULT_MAX_SGE;
	/* TODO SET RF UESR CFG */
	if (nbl_set_attr_from_maxsge(&rf->sc_dev, rf->maxsge_limit)) {
		err = -EINVAL;
		nbl_dev_err(&cdev_info->pdev->dev, "ib set attr from maxsge err");
		goto err_init;
	}

	err = nbl_get_init_params(rf);
	if (err) {
		nbl_dev_err(&cdev_info->pdev->dev, "get init params err=%d", err);
		goto err_init;
	}

	err = nbl_get_function_num(rf, &rf->sc_dev.function_id);
	if (err) {
		nbl_dev_err(&cdev_info->pdev->dev, "get function_id return err=%d", err);
		goto err_init;
	}

	err = nbl_grc_register_client(rf, true);
	if (err) {
		nbl_pr_err("failed to register mailbox client\n");
		goto err_init;
	}

	err = nbl_set_hdma_vf_enable(rf, 1);
	if (err) {
		nbl_dev_err(&cdev_info->pdev->dev, "set hdma vf enable err=%d", err);
		goto err_set_hdma_vf_enable;
	}

	nbl_rdma_dsch_init(rf, NBL_RDMA_DSCH_VALID);
	nbl_query_fmr_nofence(rf);

	if (nbl_ctrl_init_hw(rf)) {
		err = -EIO;
		nbl_dev_err(&cdev_info->pdev->dev, "nbl ctrl init hw err");
		goto err_ctrl_init;
	}

	err = nbl_arm_control_init(rf);
	if (err) {
		err = -EIO;
		nbl_dev_err(&cdev_info->pdev->dev, "nbl ctrl init arm control err");
		goto err_shadow_init;
	}

	err = nbl_shadow_init(rf);
	if (err) {
		nbl_dev_err(&cdev_info->pdev->dev, "nbl shadow init err");
		goto err_shadow_init;
	}

	if (nbl_rt_init_hw(nbl_dev)) {
		err = EIO;
		nbl_dev_err(&cdev_info->pdev->dev, "nbl rt init err");
		goto err_rt_init;
	}

	if (nbl_counters_func_init(nbl_dev)) {
		err = EIO;
		nbl_dev_err(&cdev_info->pdev->dev, "nbl counters init err");
		goto err_cnts_init;
	}

	err = nbl_set_vfid_vsi_map(rf, 1);
	if (err)
		goto err_set_vfid_vsi_map;

	nbl_set_pp0_bypass(rf, false);

	err = nbl_ib_register_device(adev, nbl_dev);
	if (err) {
		nbl_dev_err(&cdev_info->pdev->dev, "nbl ib register device err=%d", err);
		goto err_ib_reg;
	}

	nbl_debugfs_function_init(nbl_dev);

	err = nbl_umr_resource_init(nbl_dev);
	if (err) {
		nbl_dev_err(&cdev_info->pdev->dev, "nbl umr init err\n");
		goto err_umr_init;
	}

	dev_set_drvdata(&aux_dev->dev, nbl_dev);

	nbl_init_lag(nbl_dev, cdev_info);
	adev->reset_event_notify = nbl_high_temp_event_process;
	adev->qos_cfg_store = nbl_qos_cfg_store;
	adev->qos_cfg_show = nbl_qos_cfg_show;
	if (rf->sc_dev.is_ctrl_dev)
		adev->mirror_enable_notify = nbl_enable_rdma_dump;
	nbl_sysfs_init(nbl_dev);

	err = nbl_add_netdev_notifier(nbl_dev);
	if (err) {
		nbl_dev_err(&cdev_info->pdev->dev, "nbl add netdev notifier err=%d\n", err);
		goto err_add_netdev_notifier;
	}

	nbl_dev_info(&cdev_info->pdev->dev, "probe rdma device %s for %s OK\n",
		     nbl_dev->ibdev.name, nbl_dev->netdev->name);
	return 0;

err_add_netdev_notifier:
	adev->reset_event_notify = NULL;
	adev->qos_cfg_show = NULL;
	adev->qos_cfg_store = NULL;
	if (rf->sc_dev.is_ctrl_dev)
		adev->mirror_enable_notify = NULL;
	nbl_sysfs_exit(nbl_dev);
err_umr_init:
	nbl_debugfs_function_exit(nbl_dev);
	nbl_ib_unregister_device(nbl_dev);
err_ib_reg:
	nbl_set_vfid_vsi_map(rf, 0);
err_set_vfid_vsi_map:
	nbl_counters_func_deinit(nbl_dev);
err_cnts_init:
	nbl_rt_deinit_hw(nbl_dev);
err_rt_init:
	nbl_shadow_exit(nbl_dev->rf);
err_shadow_init:
	nbl_ctrl_deinit_hw(nbl_dev->rf);
err_ctrl_init:
	nbl_set_hdma_vf_enable(rf, 0);
err_set_hdma_vf_enable:
	nbl_grc_register_client(rf, false);
	nbl_free_function_num(rf);
err_init:
	nbl_channel_exit(rf);
err_channel_init:
	kfree(nbl_dev->rf);
	ib_dealloc_device(&nbl_dev->ibdev);

	return err;
}

static void nbl_remove(struct auxiliary_device *adev)
{
	struct nbl_aux_dev *nbl_adev = container_of(adev, struct nbl_aux_dev, adev);
	struct nbl_device *nbl_dev = dev_get_drvdata(&adev->dev);

	nbl_dev_info(&nbl_dev->rf->pcidev->dev, "remove rdma device %s\n",
		     nbl_dev->ibdev.name);
	nbl_adev->qos_cfg_store = NULL;
	nbl_adev->qos_cfg_show = NULL;
	nbl_sysfs_exit(nbl_dev);
	nbl_debugfs_function_exit(nbl_dev);
	nbl_ib_unregister_device(nbl_dev);
	nbl_umr_resource_cleanup(nbl_dev);
	/* after ib_unregister_device to keep rdma connection is working */
	nbl_set_vfid_vsi_map(nbl_dev->rf, 0);
	nbl_counters_func_deinit(nbl_dev);
	nbl_rdma_dsch_init(nbl_dev->rf, NBL_RDMA_DSCH_INVALID);

	nbl_rt_deinit_hw(nbl_dev);
	nbl_deinit_lag(nbl_dev->rf->cdev);
	nbl_remove_netdev_notifier(nbl_dev);
	nbl_shadow_exit(nbl_dev->rf);
	nbl_ctrl_deinit_hw(nbl_dev->rf);

	/* close hdma at last */
	nbl_set_hdma_vf_enable(nbl_dev->rf, 0);
	nbl_free_function_num(nbl_dev->rf);
	nbl_grc_register_client(nbl_dev->rf, false);
	nbl_channel_exit(nbl_dev->rf);
	nbl_del_all_src_addr_node(nbl_dev->rf);
	nbl_dev_info(&nbl_dev->rf->pcidev->dev, "remove rdma device %s OK\n",
		     nbl_dev->ibdev.name);
	nbl_adev->reset_event_notify = NULL;
	if (nbl_dev->rf->sc_dev.is_ctrl_dev)
		nbl_adev->mirror_enable_notify = NULL;
	kfree(nbl_dev->rf);
	ib_dealloc_device(&nbl_dev->ibdev);
}

static const struct auxiliary_device_id nbl_grc_id_table[] = {
	{
		.name = "nbl.nbl.roce_grc",
	},
	{},
};

static struct auxiliary_driver nbl_grc_driver = {
	.name = "rdma_grc",
	.probe = nbl_grc_probe,
	.remove = nbl_grc_remove,
	.id_table = nbl_grc_id_table,
};

static const struct auxiliary_device_id nbl_id_table[] = {
	{
		.name = "nbl.nbl.roce",
	},
	{
		.name = "nbl.nbl.roce_bond",
	},
	{},
};

MODULE_DEVICE_TABLE(auxiliary, nbl_id_table);

struct nbl_auxiliary_drv nbl_driver = {
	.adrv = {
		.name = "rdma",
		.probe = nbl_probe,
		.remove = nbl_remove,
		.id_table = nbl_id_table,
	},
};

static int __init nbl_init_module(void)
{
	int ret;

	pr_info("Nebula-Matrix RDMA driver %s git version:  %s\n",
		NBL_SNIC_RDMA_DRIVER_VERSION, GIT_VERSION);

	ret = auxiliary_driver_register(&nbl_grc_driver);
	if (ret) {
		nbl_pr_err("init nbl_grc module failed, and the ret is:%d\n", ret);
		return ret;
	}

	nbl_debugfs_init();

	ret = auxiliary_driver_register(&nbl_driver.adrv);
	if (ret) {
		nbl_pr_err("init nbl module failed, and the ret is:%d\n", ret);
		auxiliary_driver_unregister(&nbl_grc_driver);
		nbl_debugfs_exit();
		return ret;
	}

	return ret;
}

static void __exit nbl_exit_module(void)
{
	auxiliary_driver_unregister(&nbl_driver.adrv);
	nbl_debugfs_exit();
	auxiliary_driver_unregister(&nbl_grc_driver);
}

module_init(nbl_init_module);
module_exit(nbl_exit_module);

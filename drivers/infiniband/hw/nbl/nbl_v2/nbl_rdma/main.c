// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include <rdma/nbl-v2-abi.h>
#include <linux/bitfield.h>
#include <net/addrconf.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/sysfs.h>
#include "nbl_compat.h"
#include "product_internal.h"
#include <linux/dma-map-ops.h>
#include "shared.h"
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
#include "main.h"
#include "counters.h"
#include "dbgfs.h"
#include "grc.h"
#include "tlp.h"
#include "mailbox.h"
#include "lag.h"
#include "umr.h"
#include "nbl_adapt.h"
#include "probe.h"
#include "resource.h"
#include "fpga_ver.h"
/* default is 600, 4fpga advise value 30 */
static u32 tlp_timeout = NBL_TLP_TIMEOUT_MSEC;

static ssize_t hw_rev_show(struct device *device, struct device_attribute *attr,
			   char *buf)
{
	struct ib_core_device *coredev =
		container_of(device, struct ib_core_device, dev);
	struct nbl_device *nbl_dev =
		container_of(coredev->owner, struct nbl_device, ibdev);
	return scnprintf(buf, PAGE_SIZE, "%x\n", nbl_dev->rf->pcidev->revision);
}
static DEVICE_ATTR_RO(hw_rev);
/*TODO hca_type*/
static struct attribute *nbl_dev_attributes[] = { &dev_attr_hw_rev.attr, NULL };
static const struct attribute_group nbl_attr_group = {
	.attrs = nbl_dev_attributes,
};

static const struct nbl_cqp_ops cqp_v2_ops = {
	.cqp_create_cq = nbl_cqp_v2_cq_create_cmd,
	.cqp_destroy_cq = nbl_cqp_v2_cq_destroy_cmd,
	.cqp_cq_ref_add = nbl_cqp_v2_cq_cqc_ref_add,
	.cqp_cq_ref_sub = nbl_cqp_v2_cq_cqc_ref_sub,
	.cqp_cq_resize = nbl_cqp_cq_resize_cmd,
	.cqp_dbg_create_cq = nbl_dbg_v2_create_cq,
	.cqp_dbg_destroy_cq = nbl_dbg_v2_destroy_cq,
};

static void nbl_df200_dsch_init(struct nbl_pci_f *rf, bool valid);
static void nbl_update_dsch_dport_direct(struct nbl_pci_f *rf, u16 dport_id, u8 valid);
static int nbl_grc_register_client(struct nbl_pci_f *rf, bool is_register);
static void nbl_rnic400_dsch_init(struct nbl_pci_f *rf, bool valid);
static void nbl_rnic400_init_global_cfg(struct nbl_pci_f *rf);

static void nbl_set_mtu_noop(struct nbl_device *dev, int vsi_id, int mtu)
{
	(void)dev;
	(void)vsi_id;
	(void)mtu;
}

static void nbl_df200_set_mtu(struct nbl_device *dev, int vsi_id, int mtu)
{
	u64 reg_addr;

	reg_addr = NBL_DIPRO_VSI_MTU_TBL_ADDR(NBL_REG_DIPRO_V3,
					      NBL_DIPRO_VSI_MTU_TBL_OFF_V3,
					      vsi_id);
	wr32(&dev->rf->hw, reg_addr, mtu);
}

static void nbl_rnic400_set_mtu(struct nbl_device *dev, int vsi_id, int mtu)
{
	u64 reg_addr;

	reg_addr = NBL_DIPRO_VSI_MTU_TBL_ADDR(NBL_REG_DIPRO_V4,
					      NBL_DIPRO_VSI_MTU_TBL_OFF_V4,
					      vsi_id);
	wr32(&dev->rf->hw, reg_addr, mtu);
}

const struct nbl_fun_ops nbl_common_fun_ops = {
	.set_mtu = nbl_set_mtu_noop,
};

const struct nbl_fun_ops nbl_df200_fun_ops = {
	.set_mtu = nbl_df200_set_mtu,
};

const struct nbl_fun_ops nbl_rnic400_fun_ops = {
	.set_mtu = nbl_rnic400_set_mtu,
};

static int nbl_channel_init_noop(struct nbl_pci_f *rf)
{
	(void)rf;
	return 0;
}

static void nbl_channel_exit_noop(struct nbl_pci_f *rf)
{
	(void)rf;
}

static void nbl_init_global_cfg_noop(struct nbl_pci_f *rf)
{
	(void)rf;
}

static void nbl_detect_caps_default(struct nbl_pci_f *rf)
{
	rf->product_runtime.sub_type = RNIC_SUB_TYPE_NONE;
	nbl_product_apply_fw_caps(rf, 0);
}

static int nbl_register_client_noop(struct nbl_pci_f *rf, bool is_register)
{
	(void)rf;
	(void)is_register;
	return 0;
}

/* Every lifecycle callback must be set. */

/* DF200 product operations. */
const struct nbl_lifecycle_ops nbl_df200_ecpu_lifecycle_ops = {
	.init_global_cfg = nbl_init_global_cfg_noop,
	.detect_caps = nbl_detect_caps_default,
	.channel_init = nbl_channel_init_noop,
	.channel_exit = nbl_channel_exit_noop,
	.get_function_id = nbl_set_ecpu_rdma_vfid,
	.free_function_id = nbl_clear_ecpu_rdma_vfid,
	.register_client = nbl_register_client_noop,
	.set_notify = nbl_notify_set_direct,
	.reset_rdma = nbl_df200_reset_rdma,
};

const struct nbl_lifecycle_ops nbl_df200_host_lifecycle_ops = {
	.init_global_cfg = nbl_init_global_cfg_noop,
	.detect_caps = nbl_detect_caps_default,
	.channel_init = nbl_channel_init_noop,
	.channel_exit = nbl_channel_exit_noop,
	.get_function_id = df200_get_host_rdma_function_id,
	.free_function_id = df200_host_free_function_id,
	.register_client = nbl_register_client_noop,
	.set_notify = nbl_notify_set_direct,
	.reset_rdma = nbl_df200_reset_rdma,
};

const struct nbl_resource_ops nbl_df200_resource_ops = {
	.set_vf_enable = nbl_direct_set_vf_enable_tbl,
	.get_obj_sz = nbl_get_ddr_obj_sz,
	.set_voa_tbl = nbl_update_voa_tbl,
	.set_sd_range = nbl_set_sd_range,
	.get_sd_range = nbl_get_sd_range_tbl,
	.get_voa_tbl = nbl_get_pf_voa_tbl_v2,
	.set_vfid_vsi_map = nbl_set_vfid_vsi_map_v3,
	.global_sd_init = nbl_global_sd_init,
	.global_sd_deinit = nbl_global_sd_deinit,
	.obj_sd_init = nbl_obj_sd_init_v2,
	.set_vf_pf_map = nbl_direct_set_vf_pf_map,
};

static const struct nbl_rdma_dev_ops df200_ecpu_ops = {
	.get_init_params = nbl_get_resv_init_params,
	.init_cqp_reg = nbl_cqp_reg_init_direct,
	.dsch_init = nbl_df200_dsch_init,
	.update_dsch_dport = nbl_update_dsch_dport_direct,
	.stat_read = nbl_grc_hw_stat_read_v2,
	.stat_clear = nbl_grc_hw_stat_clear_v2,
	.hw_stat_errcode_enable = nbl_grc_hw_stat_errcode_enable_v2,
	.set_cc_glb_cfg = nbl_set_cc_glb_cfg,
	.set_net_tc_tbl = nbl_set_net_tc_tbl,
	.tqp_flush = nbl_tqp_flush,
	.armcq_db_flush = nbl_armcq_db_flush,
	.rq_db_flush = nbl_rq_db_flush,
	.get_armcq_flush_status = nbl_df200_armcq_get_flush_status,
};

static const struct nbl_rdma_dev_ops df200_host_ops = {
	.get_init_params = df200_get_host_init_params,
	.dsch_init = nbl_df200_dsch_init,
	.init_cqp_reg = nbl_cqp_reg_init_direct,
	.stat_read = nbl_grc_hw_stat_read_v2,
	.stat_clear = nbl_grc_hw_stat_clear_v2,
	.hw_stat_errcode_enable = nbl_grc_hw_stat_errcode_enable_v2,
	.set_cc_glb_cfg = nbl_set_cc_glb_cfg,
	.tqp_flush = nbl_tqp_flush,
	.armcq_db_flush = nbl_armcq_db_flush,
	.rq_db_flush = nbl_rq_db_flush,
	.get_armcq_flush_status = nbl_df200_armcq_get_flush_status,
	.update_dsch_dport = nbl_update_dsch_dport_direct,
};

/* Draco product operations. */
const struct nbl_lifecycle_ops nbl_draco_lifecycle_ops = {
	.init_global_cfg = nbl_init_global_cfg_noop,
	.detect_caps = nbl_detect_caps_default,
	.channel_init = nbl_mbx_roce_init,
	.channel_exit = nbl_mbx_roce_exit,
	.get_function_id = nbl_get_function_id_via_channel,
	.free_function_id = nbl_free_function_id_via_channel,
	.register_client = nbl_grc_register_client,
	.set_notify = nbl_notify_set_via_channel,
	.reset_rdma = nbl_draco_reset_rdma,
};

const struct nbl_lifecycle_ops nbl_orion_lifecycle_ops = {
	.init_global_cfg = nbl_init_global_cfg_noop,
	.detect_caps = nbl_detect_caps_default,
	.channel_init = nbl_mbx_roce_init,
	.channel_exit = nbl_mbx_roce_exit,
	.get_function_id = nbl_get_function_id_via_channel,
	.free_function_id = nbl_free_function_id_via_channel,
	.register_client = nbl_grc_register_client,
	.set_notify = nbl_notify_set_via_channel,
	.reset_rdma = nbl_orion_reset_rdma,
};

const struct nbl_resource_ops nbl_draco_resource_ops = {
	.obj_sd_init = nbl_obj_sd_init_v2,
};

const struct nbl_resource_ops nbl_orion_resource_ops = {
	.obj_sd_init = nbl_obj_sd_init_v2,
};

static const struct nbl_rdma_dev_ops asic_v2r1_pf_ops = {
	.stat_read = nbl_grc_hw_stat_read_v2,
	.stat_clear = nbl_grc_hw_stat_clear_v2,
	.hw_stat_errcode_enable = nbl_grc_hw_stat_errcode_enable_v2,
	.set_cc_glb_cfg = nbl_set_cc_glb_cfg,
	.set_net_tc_tbl = nbl_set_net_tc_tbl,
	.tqp_flush = nbl_tqp_flush,
	.armcq_db_flush = nbl_armcq_db_flush,
	.rq_db_flush = nbl_rq_db_flush,
	.get_armcq_flush_status = nbl_draco_armcq_get_flush_status,
};

static const struct nbl_rdma_dev_ops asic_v2r1_vf_ops = {
	.armcq_db_flush = nbl_armcq_db_flush,
};

/* RNIC400 product operations. */
const struct nbl_lifecycle_ops nbl_rnic400_lifecycle_ops = {
	.init_global_cfg = nbl_rnic400_init_global_cfg,
	.detect_caps = nbl_rnic400_detect_caps,
	.channel_init = nbl_channel_init_noop,
	.channel_exit = nbl_channel_exit_noop,
	.get_function_id = nbl_get_rdma_function_id,
	.free_function_id = nbl_put_rdma_function_id,
	.register_client = nbl_register_client_noop,
	.set_notify = nbl_set_notify_bar_addr,
	.reset_rdma = nbl_rnic400_reset_rdma,
};

const struct nbl_resource_ops nbl_rnic400_resource_ops = {
	.set_vf_enable = nbl_direct_set_vf_enable_tbl,
	.set_voa_tbl = nbl_update_voa_tbl,
	.set_sd_range = nbl_set_sd_range,
	.get_sd_range = nbl_get_sd_range_tbl,
	.get_voa_tbl = nbl_get_pf_voa_tbl_v2,
	.set_vfid_vsi_map = nbl_set_vfid_vsi_map_v3,
	.global_sd_init = nbl_global_sd_init,
	.global_sd_deinit = nbl_global_sd_deinit,
	.obj_sd_init = nbl_obj_sd_init_v2,
	.set_vf_pf_map = nbl_direct_set_vf_pf_map,
};

static const struct nbl_rdma_dev_ops rnic400_ops = {
	.get_init_params = nbl_get_admin_pf_init_params,
	.dsch_init = nbl_rnic400_dsch_init,
	.init_cqp_reg = nbl_cqp_reg_init_direct,
	.stat_read = nbl_grc_hw_stat_read_v2,
	.stat_clear = nbl_grc_hw_stat_clear_v2,
	.hw_stat_errcode_enable = nbl_grc_hw_stat_errcode_enable_v2,
	.set_cc_glb_cfg = nbl_set_cc_glb_cfg,
	.set_net_tc_tbl = nbl_set_net_tc_tbl,
	.tqp_flush = nbl_tqp_flush,
	.armcq_db_flush = nbl_armcq_db_flush,
	.rq_db_flush = nbl_rq_db_flush,
	.get_armcq_flush_status = nbl_rnic400_armcq_get_flush_status,
};

static const struct nbl_rdma_dev_ops * const
nbl_product_dev_ops[NBL_PRODUCT_ID_MAX] = {
	[NBL_PRODUCT_ID_DF200_ECPU] = &df200_ecpu_ops,
	[NBL_PRODUCT_ID_DF200_HOST] = &df200_host_ops,
	[NBL_PRODUCT_ID_DRACO_PF] = &asic_v2r1_pf_ops,
	[NBL_PRODUCT_ID_DRACO_VF] = &asic_v2r1_vf_ops,
	[NBL_PRODUCT_ID_RNIC400_PF] = &rnic400_ops,
	[NBL_PRODUCT_ID_ORION_PF] = &asic_v2r1_pf_ops,
	[NBL_PRODUCT_ID_ORION_VF] = &asic_v2r1_vf_ops,
};

static void nbl_rnic400_init_global_cfg(struct nbl_pci_f *rf)
{
	u32 global_cfg_enable;
	u8 max_function_id = rf->sc_dev.pf_count - 1;

	global_cfg_enable = rf->hw.hw_ops->get_hw_global_cfg_flag(&rf->hw);

	if (!global_cfg_enable)
		rf->hw.hw_ops->set_hw_global_cfg(&rf->hw, max_function_id, true);
}

int nbl_init_device_type(struct nbl_pci_f *rf)
{
	const struct nbl_product_desc *product;
	const struct nbl_rdma_dev_ops *dev_ops = NULL;
	int ret;

	product = nbl_product_lookup(rf->pcidev->device);
	if (!product) {
		nbl_dev_err(&rf->adev->adev.dev,
			   "device id [%#x] not support.\n", rf->pcidev->device);
		return -ENODEV;
	}

	if (product->id >= 0 && product->id < NBL_PRODUCT_ID_MAX)
		dev_ops = nbl_product_dev_ops[product->id];

	ret = nbl_product_validate(product, dev_ops, &cqp_v2_ops);
	if (ret) {
		nbl_dev_err(&rf->adev->adev.dev,
			    "invalid product descriptor: device_id=%#x name=%s id=%u\n",
			    rf->pcidev->device, product->name ?: "<null>",
			    product->id);
		return ret;
	}

	rf->product = product;
	rf->effective_caps = product->base_caps;
	rf->hw.effective_caps = &rf->effective_caps;
	rf->dev_ops = dev_ops;
	rf->cqp_ops = &cqp_v2_ops;
	rf->sc_dev.hw_attrs.uk_attrs.hw_rev = product->hw_rev;

	nbl_dev_info(&rf->adev->adev.dev,
		     "product selected: device_id=%#x name=%s id=%u generation=%u host=%s type=%s function=%s flags=%#x base_caps=%#llx\n",
		     rf->pcidev->device, product->name, product->id,
		     product->hw_rev,
		     product->host_id == HOST_ID_TYPE_HOST ? "host" : "ecpu",
		     product->product_type == PRODUCT_TYPE_SNIC ? "snic" : "dpu",
		     product->function_type == NBL_PRODUCT_FUNCTION_PF ? "pf" : "vf",
		     product->flags, product->base_caps);

	rf->hw.reg_base = product->regs;
	rf->hw.jmp_h48zero_addr = false;
	nbl_set_default_fwd(rf);

	return 0;
}

extern u8 rd_atom;
void nbl_init_rd_atomic_num(struct nbl_pci_f *rf)
{
	const struct nbl_product_limits *limits = rf->product->limits;
	u8 rd_atomic_code = (rd_atom >> limits->rd_atomic_shift) & 0x3;
	u32 init_rd_atom = NBL_READ_OST_VAL(rd_atomic_code);

	if (init_rd_atom > limits->max_rd_atomic)
		init_rd_atom = NBL_MIN_OST_RD_ATOMIC;

	rf->sc_dev.hw_attrs.max_qp_rd_atom = init_rd_atom;
	rf->sc_dev.hw_attrs.max_qp_dest_rd_atom = init_rd_atom;
}

void nbl_get_fw_ver(struct nbl_pci_f *rf)
{
	u32 prj_id = NBL_RDMA_FW_MAJOR_VER;
	u32 version_id = NBL_RDMA_FW_MINOR_VER;

	if (nbl_product_flag_enabled(rf, NBL_PRODUCT_F_FW_VER_REG)) {
		prj_id = readl(rf->sc_dev.hw->hw_addr + NBL_STATIC_PRJ_ID);
		version_id =
			readl(rf->sc_dev.hw->hw_addr + NBL_STATIC_VERSION_ID);
	}
	rf->sc_dev.fw_ver = (((u64)prj_id << 32) | version_id);
}

void nbl_set_hw_attr(struct nbl_pci_f *rf)
{
	struct nbl_sc_dev *dev = &rf->sc_dev;
	const struct nbl_product_limits *limits = rf->product->limits;

	dev->hw_attrs.max_hw_pds = limits->max_pds;
	dev->hw_attrs.max_hw_ahs = limits->max_ahs;
	dev->hw_attrs.max_mr_size = limits->max_mr_size;
	dev->hw_attrs.min_hw_aeqe_count = limits->min_aeq_entries;
	dev->hw_attrs.max_hw_aeqe_count = limits->max_aeq_entries;
	dev->hw_attrs.min_hw_ceqe_count = limits->min_ceq_entries;
	dev->hw_attrs.max_hw_ceqe_count = limits->max_ceq_entries;
	dev->hw_attrs.uk_attrs.min_hw_cq_size = limits->min_cq_size;
	dev->hw_attrs.uk_attrs.max_hw_cq_size = limits->max_cq_size;
	dev->hw_attrs.uk_attrs.max_hw_rq_quanta = limits->max_wqe_quanta;
	dev->hw_attrs.uk_attrs.max_hw_wq_quanta = limits->max_wqe_quanta;
	dev->hw_attrs.uk_attrs.max_hw_wq_sges = limits->max_sge;
	dev->hw_attrs.uk_attrs.max_hw_read_sges = limits->max_read_sge;
	dev->hw_attrs.uk_attrs.max_hw_inline = limits->max_inline_data;
	dev->hw_attrs.uk_attrs.max_hw_ud_inline = limits->max_ud_inline_data;
	dev->hw_attrs.uk_attrs.max_hw_srq_wr = limits->max_srq_wr;
	dev->hw_attrs.max_qp_wr =
		limits->max_qp_wr -
		nbl_get_sq_safe_rsv(limits->sq_ost_count, NBL_MIN_WQE_SIZE);
}

/* ops v1 and v2 same */
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
	.device_group = &nbl_attr_group,
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

	.create_cq = nbl_ib_create_cq,
	.destroy_cq = nbl_ib_destroy_cq,
	.poll_cq = nbl_ib_poll_cq,

	.create_qp = nbl_ib_create_qp,
	.modify_qp = nbl_ib_modify_qp,
	.destroy_qp = nbl_ib_destroy_qp,
	.query_qp = nbl_ib_query_qp,

	.create_flow = nbl_ib_create_flow,
	.destroy_flow = nbl_ib_destroy_flow,

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

/* ops only v2 use */
static const struct ib_device_ops nbl_ib_dev_gen2_ops = {
	.alloc_xrcd = nbl_ib_alloc_xrcd,
	.dealloc_xrcd = nbl_ib_dealloc_xrcd,

	.create_srq = nbl_ib_create_srq,
	.destroy_srq = nbl_ib_destroy_srq,
	.query_srq = nbl_ib_query_srq,
	.modify_srq = nbl_ib_modify_srq,
	.post_srq_recv = nbl_ib_post_srq_recv,

	.req_notify_cq = nbl_ib_v2_req_notify_cq,
	.modify_cq = nbl_ib_modify_cq,
	.resize_cq = nbl_ib_resize_cq,
	.post_send = nbl_ib_post_send_v2,
	.post_recv = nbl_ib_post_recv_v2,

	INIT_RDMA_OBJ_SIZE(ib_srq, nbl_srq, ibsrq),
	INIT_RDMA_OBJ_SIZE(ib_xrcd, nbl_xrcd, ibxrcd),
};

static const struct ib_device_ops nbl_ib_dev_gdr_ops = {
	.reg_user_mr_dmabuf = nbl_ib_reg_user_mr_dmabuf,
};

static void nbl_set_uverbs_cmd_mask_common(struct nbl_device *nbl_dev)
{
	if (nbl_dev->ibdev.uverbs_cmd_mask)
		return;

	nbl_dev->ibdev.uverbs_cmd_mask =
		BIT_ULL(IB_USER_VERBS_CMD_GET_CONTEXT) |
		BIT_ULL(IB_USER_VERBS_CMD_QUERY_DEVICE) |
		BIT_ULL(IB_USER_VERBS_CMD_QUERY_PORT) |
		BIT_ULL(IB_USER_VERBS_CMD_ALLOC_PD) |
		BIT_ULL(IB_USER_VERBS_CMD_DEALLOC_PD) |
		BIT_ULL(IB_USER_VERBS_CMD_REG_MR) |
		BIT_ULL(IB_USER_VERBS_CMD_REREG_MR) |
		BIT_ULL(IB_USER_VERBS_CMD_DEREG_MR) |
		BIT_ULL(IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL) |
		BIT_ULL(IB_USER_VERBS_CMD_CREATE_CQ) |
		BIT_ULL(IB_USER_VERBS_CMD_RESIZE_CQ) |
		BIT_ULL(IB_USER_VERBS_CMD_DESTROY_CQ) |
		BIT_ULL(IB_USER_VERBS_CMD_CREATE_QP) |
		BIT_ULL(IB_USER_VERBS_CMD_MODIFY_QP) |
		BIT_ULL(IB_USER_VERBS_CMD_QUERY_QP) |
		BIT_ULL(IB_USER_VERBS_CMD_DESTROY_QP) |
		BIT_ULL(IB_USER_VERBS_CMD_ALLOC_MW) |
		BIT_ULL(IB_USER_VERBS_CMD_BIND_MW) |
		BIT_ULL(IB_USER_VERBS_CMD_DEALLOC_MW) |
		BIT_ULL(IB_USER_VERBS_CMD_CREATE_AH) |
		BIT_ULL(IB_USER_VERBS_CMD_DESTROY_AH) |
		BIT_ULL(IB_USER_VERBS_CMD_CREATE_SRQ) |
		BIT_ULL(IB_USER_VERBS_CMD_CREATE_XSRQ) |
		BIT_ULL(IB_USER_VERBS_CMD_MODIFY_SRQ) |
		BIT_ULL(IB_USER_VERBS_CMD_DESTROY_SRQ) |
		BIT_ULL(IB_USER_VERBS_CMD_QUERY_SRQ) |
		BIT_ULL(IB_USER_VERBS_CMD_OPEN_XRCD) |
		BIT_ULL(IB_USER_VERBS_CMD_CLOSE_XRCD);
}

void nbl_port_ibevent(struct nbl_device *nbl_dev)
{
	struct ib_event event;

	event.device = &nbl_dev->ibdev;
	event.element.port_num = 1;
	event.event = nbl_dev->status ? IB_EVENT_PORT_ACTIVE : IB_EVENT_PORT_ERR;
	ib_dispatch_event(&event);
}

extern const struct uapi_definition nbl_ib_devx_defs[];
static const struct uapi_definition nbl_ib_defs[] = {
	UAPI_DEF_CHAIN(nbl_ib_devx_defs),
	{}
};

int nbl_ib_register_device(struct nbl_adev *nbl_adev,
			   struct nbl_device *nbl_dev)
{
	int ret;
	struct pci_dev *pcidev = nbl_dev->rf->pcidev;
	struct nbl_core_export *core_info = nbl_adev->core_info;
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
	ib_set_device_ops(&nbl_dev->ibdev, &nbl_ib_dev_gen2_ops);

	if (IS_ENABLED(CONFIG_INFINIBAND_USER_ACCESS))
		nbl_dev->ibdev.driver_def = nbl_ib_defs;

	dma_set_max_seg_size(nbl_dev->rf->hw.device, SZ_2G);

	nbl_get_ibname(name, sizeof(name), core_info->is_lag, nbl_adev->adev.id);

	ret = kc_ib_register_device(&nbl_dev->ibdev, name,
				    nbl_dev->rf->hw.device);
	if (ret)
		return ret;

	return 0;
}

void nbl_ib_unregister_device(struct nbl_device *nbl_dev)
{
	ib_unregister_device(&nbl_dev->ibdev);
}

void nbl_fill_default_cfg(struct nbl_device *dev)
{
	struct nbl_pci_f *rf = dev->rf;

	/* TODO, Now rnic400 open tc2pri, other product
	 * whill adpapt reg and test later.
	 */
	rf->sc_dev.tc2pri = NBL_QOS_DEFAULT_TC2PRI;
	rf->sc_dev.tc_wgt.tc0_wgt = NBL_QOS_DEFAULT_SQ_WGT;
	rf->sc_dev.tc_wgt.tc1_wgt = NBL_QOS_DEFAULT_RAQ_WGT;
	rf->sc_dev.tc_wgt.tc2_wgt = NBL_QOS_DEFAULT_SQ_WGT;
	rf->sc_dev.tc_wgt.tc3_wgt = NBL_QOS_DEFAULT_RAQ_WGT;
	rf->sc_dev.tc_wgt.tc4_wgt = NBL_QOS_DEFAULT_SQ_WGT;
	rf->sc_dev.tc_wgt.tc5_wgt = NBL_QOS_DEFAULT_RAQ_WGT;
	rf->sc_dev.tc_wgt.tc6_wgt = NBL_QOS_DEFAULT_SQ_WGT;
	rf->sc_dev.tc_wgt.tc7_wgt = NBL_QOS_DEFAULT_RAQ_WGT;

	/* set default qos config val */
	snprintf(rf->sc_dev.qos_dbgfs_params[NBL_CFG_SPWRR], NBL_PARAM_LEN,
		 "0x0\n");
	snprintf(rf->sc_dev.qos_dbgfs_params[NBL_CFG_TRUST_DSCP_EN],
		 NBL_PARAM_LEN, "1\n");

	/* set default fun_dbg val*/
	nbl_handle_fun_dbg_set(dev, NBL_FUN_DBG_SRP_EN, 0);
	nbl_handle_fun_dbg_set(dev, NBL_FUN_DBG_SRP_SPRAY_EN, 0);
	nbl_handle_fun_dbg_set(dev, NBL_FUN_DBG_SRP_NIC_SPRAY_MODE, 0);
	nbl_handle_fun_dbg_set(dev, NBL_FUN_DBG_SRP_RETRY_TIMER,
			       NBL_TLP_RETRY_TIMER_DEFAULT);
	nbl_handle_fun_dbg_set(dev, NBL_FUN_DBG_SRP_RETRY_TH,
			       NBL_TLP_RETRY_TH_DEFAULT);
	nbl_handle_fun_dbg_set(dev, NBL_FUN_DBG_SRP_EXT_BITMAP_EN, 1);
	nbl_handle_fun_dbg_set(dev, NBL_FUN_DBG_SRP_OOO_TH, 0);
	nbl_handle_fun_dbg_set(dev, NBL_FUN_DBG_SRP_RETRY_PKT_TH, 0x100000);
	nbl_handle_fun_dbg_set(dev, NBL_FUN_DBG_SRP_SRACK_TIMER,
			       NBL_SRP_SRACK_TIMER_VALUE_DEFAULT);

	if (nbl_product_cap_enabled(rf, NBL_PRODUCT_CAP_SRP))
		rf->sc_dev.srp_ext_bmp_qpn_max = ((rf->sc_dev.pf_count == 2) ?
			NBL_SRP_EXT_BMP_QPN_MAX_2X200 : NBL_SRP_EXT_BMP_QPN_MAX_1X400);
	else
		rf->sc_dev.srp_ext_bmp_qpn_max = 0;

	if (nbl_product_cap_enabled(rf, NBL_PRODUCT_CAP_QPN_ALLOC_INTERVAL))
		nbl_handle_fun_dbg_set(dev, NBL_FUN_DBG_QPN_ALLOC_INTERVAL, QPN_INTERVAL);

	if (rf->product->cq_ops->cq_moderation_supported)
		nbl_handle_fun_dbg_set(dev, NBL_FUN_DBG_CEM_EN, 0);

	if (nbl_product_cap_enabled(rf, NBL_PRODUCT_CAP_WRITE_ATOMIC_FENCE))
		nbl_handle_fun_dbg_set(dev, NBL_FUN_DBG_WRITE_ATOMIC_FENCE, 0);
}

int nbl_fill_device_info(struct nbl_device *nbl_dev, struct nbl_adev *adev)
{
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_core_export *core_info = adev->core_info;

	rf->hw.hw_addr = core_info->hw_addr;
	rf->hw.bar4_addr = core_info->rdma_hw_addr;
	rf->pcidev = core_info->pdev;
	rf->msix_count = core_info->msix_count;
	rf->msix_entries = core_info->msix_entries;
	if (core_info->is_lag) {
		/* Need to get master only is_lag is true.
		 * Otherwise, it will get an unregistering bond dev when bond is delete
		 */
		rcu_read_lock();
		nbl_dev->netdev =
			netdev_master_upper_dev_get_rcu(core_info->netdev);
		rcu_read_unlock();
	}
	if (!nbl_dev->netdev)
		nbl_dev->netdev = core_info->netdev;

	rf->cdev = core_info;
	rf->vsi_id = core_info->vsi_id;

	memcpy(rf->rx_vlan_vsi_id, core_info->rx_vlan_vsi_id, sizeof(rf->rx_vlan_vsi_id));

	rf->sc_dev.pcie_fn_id = core_info->function_id;
	rf->sc_dev.pf_count = core_info->eth_mode;
	rf->sc_dev.dwqe_en = true;
	rf->sc_dev.dport = NBL_DEFAULT_DPORT;
	rf->sc_dev.dport_id = core_info->eth_id;
	rf->sc_dev.rss_lag_en = NBL_DEFAULT_RSS_LAG_EN;
	rf->sc_dev.tunnel_en = NBL_DEFAULT_TUNNEL_EN;
	rf->sc_dev.ackreq_th = NBL_DEFAULT_ACKREQ_TH;
	rf->sc_dev.nvme_fmr_en = true;
	rf->sc_dev.local_rd_no_pkt = false;
	rf->sc_dev.debug_errcdoe = NBL_QP_INVALD_ERRCODE;
	rf->sc_dev.cc_mode = 0;
	rf->sc_dev.check_cc_param = true;
	rf->sc_dev.qpn_interval = 0;
	rf->tlp_timeout = tlp_timeout;
	rf->hw.hw_ops = nbl_get_hw_rdma_ops();
	rf->adev = adev;
	dev_info(&adev->adev.dev, "eth_mode=%u,pcie_fn_id=%u,msix_cnt=%u\n",
		 core_info->eth_mode, core_info->function_id,
		 core_info->msix_count);

	rf->internal_cfg = core_info->internal_cfg & NBL_RDMA_INTERNAL_CFG_MASK;
	return 0;
}

void nbl_set_default_fwd(struct nbl_pci_f *rf)
{
	if (nbl_product_flag_enabled(rf, NBL_PRODUCT_F_CPU_FWD_DEFAULT))
		rf->sc_dev.fwd = NBL_CPU_FWD;
	else
		rf->sc_dev.fwd = NBL_NORMAL_FWD;
}

int nbl_exec_cmd(struct nbl_pci_f *rf, void *in, int in_size, void *out,
		int out_size)
{
	int ret_val = 0;

	if (rf->product->product_type == PRODUCT_TYPE_SNIC)
		ret_val = nbl_mbx_exec(rf, in, in_size, out, out_size);
	else if (rf->product->product_type == PRODUCT_TYPE_DPU) {
		if (rf->product->host_id == HOST_ID_TYPE_HOST)
			ret_val = nbl_tlp_exec(rf, in, in_size, out, out_size);
		else if (rf->product->host_id == HOST_ID_TYPE_ECPU)
			ret_val = nbl_grc_exec(rf, in, in_size, out, out_size);
		else {
			nbl_pr_err("invalid host_id=%u", rf->product->host_id);
			return -EINVAL;
		}
	} else
		nbl_pr_err("invalid product_type=%u", rf->product->product_type);

	if (ret_val)
		nbl_pr_err("exec cmd err=%d,host_id=%u", ret_val,
			   rf->product->host_id);

	return ret_val;
}


static void nbl_abnormal_event_process(struct nbl_device *nbl_dev)
{
	struct nbl_pci_f *rf = nbl_dev->rf;

	queue_work(rf->abnormal_evt_wq, &rf->abnormal_task);
}

int nbl_set_mtu(int mtu, struct nbl_device *nbl_dev)
{
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_core_export *core_info = (struct nbl_core_export *)rf->cdev;
	int i, vsi_id;

	vsi_id = core_info->vsi_id;
	rf->sc_dev.mtu = mtu;

	nbl_ib_dbg(&rf->sc_dev, "change mtu, mtu: %d, vsi_id: %d, is_lag: %d",
		mtu, vsi_id, core_info->is_lag);

	if (core_info->is_lag) {
		for (i = 0; i < core_info->lag_info.mbr_num; i++)
			rf->product->fun_ops->set_mtu(nbl_dev,
				core_info->lag_info.mbr[i].vsi_id, mtu);
	} else
		rf->product->fun_ops->set_mtu(nbl_dev, vsi_id, mtu);

	return 0;
}

static int nbl_mtu_event(struct notifier_block *notifier,
			 unsigned long event, void *data)
{
	struct nbl_device *nbl_dev = container_of(notifier, struct nbl_device,
						  mtu_nb);

	if (event != NBL_CORE_EVT_MTU_CHANGE || !data)
		return NOTIFY_DONE;

	nbl_set_mtu(*(int *)data, nbl_dev);
	return NOTIFY_OK;
}

int nbl_add_mtu_notifier(struct nbl_device *nbl_dev)
{
	struct nbl_core_export *core_info = nbl_dev->rf->cdev;
	int err;

	nbl_dev->mtu_nb.notifier_call = nbl_mtu_event;
	err = blocking_notifier_chain_register(&core_info->mtu_nh,
					       &nbl_dev->mtu_nb);
	if (err)
		nbl_dev->mtu_nb.notifier_call = NULL;

	return err;
}

void nbl_remove_mtu_notifier(struct nbl_device *nbl_dev)
{
	struct nbl_core_export *core_info = nbl_dev->rf->cdev;

	if (!nbl_dev->mtu_nb.notifier_call)
		return;

	blocking_notifier_chain_unregister(&core_info->mtu_nh,
					 &nbl_dev->mtu_nb);
	nbl_dev->mtu_nb.notifier_call = NULL;
}

void nbl_init_global_cfg(struct nbl_pci_f *rf)
{
	if (WARN_ON(!rf->product))
		return;

	rf->product->lifecycle_ops->init_global_cfg(rf);
}

int nbl_register_client(struct nbl_pci_f *rf, bool is_register)
{
	if (WARN_ON(!rf->product))
		return -EINVAL;

	return rf->product->lifecycle_ops->register_client(rf, is_register);
}

int nbl_channel_init(struct nbl_pci_f *rf)
{
	if (WARN_ON(!rf->product))
		return -EINVAL;

	return rf->product->lifecycle_ops->channel_init(rf);
}

void nbl_channel_exit(struct nbl_pci_f *rf)
{
	if (WARN_ON(!rf->product))
		return;

	rf->product->lifecycle_ops->channel_exit(rf);
}

static void nbl_update_dsch_vf2vsi(struct nbl_pci_f *rf, bool valid)
{
	rf->hw.hw_ops->set_hw_dsch_vf2vsi(&rf->hw, rf->sc_dev.function_id, rf->vsi_id, valid);
}

static void nbl_set_dport_shaping_v4(struct nbl_pci_f *rf, bool valid)
{
	struct nbl_core_export *core_info =
		(struct nbl_core_export *)rf->cdev;

	if (rf->sc_dev.dport_id >= NBL_DSCH_RNIC_TBL_MAX_DEPTH)
		return;

	rf->hw.hw_ops->set_hw_shaping_dpt(&rf->hw, rf->sc_dev.dport_id, valid,
					  core_info->is_lag,
					  rf->sc_dev.pf_count);
}

static void nbl_dsch_init_direct(struct nbl_pci_f *rf, bool valid)
{
	rf->hw.hw_ops->set_hw_dsch_init(&rf->hw, rf->sc_dev.function_id, rf->sc_dev.dport_id,
					rf->product->host_id, valid,
					&rf->product->dsch_layout);
}

static void nbl_df200_dsch_init(struct nbl_pci_f *rf, bool valid)
{
	nbl_dsch_init_direct(rf, valid);
	nbl_update_dsch_vf2vsi(rf, valid);
}

static void nbl_rnic400_dsch_init(struct nbl_pci_f *rf, bool valid)
{
	nbl_dsch_init_direct(rf, valid);
	nbl_set_dport_shaping_v4(rf, valid);
}

static int nbl_get_vf_armcq_flush_status(struct nbl_pci_f *rf)
{
	int status;
	int ret_val;
	uint8_t in[NBL_CMD_OUTPUT_SIZE];
	uint8_t out[NBL_CMD_OUTPUT_SIZE];
	int data_len = 0;
	struct grc_cache_msg_header *head;
	struct get_armcq_flush_status_req req = {};

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_GET_ARMCQ_FLUSH_STATUS;
	head->payload_len = sizeof(struct get_armcq_flush_status_req);
	data_len += sizeof(struct grc_cache_msg_header);

	req.function_id = rf->sc_dev.function_id;
	memcpy(in + data_len, &req, sizeof(req));
	data_len += sizeof(req);

	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val)
		nbl_ib_err(&rf->sc_dev, "get armcq flush status err=%d", ret_val);

	memcpy(&status, out+1, sizeof(status));

	return status;
}

static void nbl_armcq_flush(struct nbl_pci_f *rf)
{
	int status;
	int retry_count = 0;

	if (!rf->dev_ops || !rf->dev_ops->armcq_db_flush)
		return;

	if (rf->dev_ops && rf->dev_ops->get_armcq_flush_status)
		status = rf->dev_ops->get_armcq_flush_status(rf);
	else
		status = nbl_get_vf_armcq_flush_status(rf);

	if (status == -1) {
		nbl_pr_err("get armcq flush error,function id:%d\n",
			rf->sc_dev.function_id);
		return;
	}

	rf->dev_ops->armcq_db_flush(rf);

	do {
		if (rf->dev_ops && rf->dev_ops->get_armcq_flush_status) {
			if (rf->dev_ops->get_armcq_flush_status(rf) != status)
				break;
		} else {
			if (nbl_get_vf_armcq_flush_status(rf) != status)
				break;
		}

		mdelay(1000);
		retry_count++;
		nbl_pr_dbg("check armcq db flush ready wait,function id:%d\n",
			rf->sc_dev.function_id);
	} while (retry_count < CHECK_FLUSH_MAX_COUNT);

	if (unlikely(retry_count == CHECK_FLUSH_MAX_COUNT)) {
		nbl_pr_err("check armcq db flush status timeout, status:%d,function id:%d\n",
			status, rf->sc_dev.function_id);
	}
}

void nbl_confqp_flush(struct nbl_pci_f *rf)
{
	nbl_armcq_flush(rf);

	if (rf->dev_ops && rf->dev_ops->rq_db_flush)
		rf->dev_ops->rq_db_flush(rf);

	if (rf->dev_ops && rf->dev_ops->tqp_flush)
		rf->dev_ops->tqp_flush(rf);
}

void nbl_rdma_dsch_init(struct nbl_pci_f *rf, bool is_valid)
{
	int ret_val;
	uint8_t in[64];
	uint8_t out[64];
	int data_len = 0;
	struct set_rdma_dsch_req req = {};
	struct grc_cache_msg_header *head;

	if (rf->dev_ops && rf->dev_ops->dsch_init) {
		rf->dev_ops->dsch_init(rf, is_valid);
		return;
	}

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_SET_DSCH;
	head->payload_len = sizeof(struct set_rdma_dsch_req);
	data_len += sizeof(struct grc_cache_msg_header);

	req.function_id = rf->sc_dev.function_id;
	req.host_id = rf->product->host_id;
	req.dport_id = rf->sc_dev.dport_id;
	req.is_valid = is_valid;
	memcpy(in + data_len, &req, sizeof(req));
	data_len += sizeof(req);

	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val)
		nbl_ib_err(&rf->sc_dev, "set rdma dsch cmd err=%d", ret_val);
}

static void nbl_update_dsch_dport_direct(struct nbl_pci_f *rf, u16 dport_id, u8 valid)
{
	rf->hw.hw_ops->update_hw_dsch_dport_id_direct(&rf->hw, rf->sc_dev.function_id,
						      rf->product->host_id, dport_id, valid);
}

void nbl_rdma_update_dsch_info(struct nbl_pci_f *rf)
{
	int ret_val;
	uint8_t in[64];
	uint8_t out[64];
	int data_len = 0;
	struct set_rdma_dsch_req req = {};
	struct grc_cache_msg_header *head;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_UPDATE_DSCH;
	head->payload_len = sizeof(struct set_rdma_dsch_req);
	data_len += sizeof(struct grc_cache_msg_header);

	req.function_id = rf->sc_dev.function_id;
	req.host_id = rf->product->host_id;
	req.dport_id = (rf->sc_dev.dport_id < NBL_ETH_MAX_NUM ? rf->sc_dev.dport_id : 0);
	req.is_valid = 1;
	memcpy(in + data_len, &req, sizeof(req));
	data_len += sizeof(req);

	if (rf->dev_ops && rf->dev_ops->update_dsch_dport) {
		rf->dev_ops->update_dsch_dport(rf, req.dport_id, req.is_valid);
		return;
	}

	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val)
		nbl_ib_err(&rf->sc_dev, "update rdma dsch cmd err=%d", ret_val);
}

void nbl_rdma_get_rdma_dport(struct nbl_device *nbl_dev, u32 *rdma_dport)
{
	void *reg_addr;

	reg_addr = nbl_dev->rf->hw.hw_addr +
		   NBL_TXM_REG_ADDR(NBL_REG_TXM_BASE_V4,
				     NBL_TXM_UDP_DESTPORT_OFF);
	*rdma_dport = readl(reg_addr);
}

void nbl_rdma_set_rdma_dport(struct nbl_device *nbl_dev, u32 rdma_dport)
{
	void *reg_addr;

	reg_addr = nbl_dev->rf->hw.hw_addr +
		   NBL_TXM_REG_ADDR(NBL_REG_TXM_BASE_V4,
				     NBL_TXM_UDP_DESTPORT_OFF);
	writel(rdma_dport, reg_addr);

	rdma_dport |= NBL_UPA_RDMA_DPORT_VLD;

	reg_addr = nbl_dev->rf->hw.hw_addr + NBL_REG_DPA_BASE_V4 + NBL_DPA_RDMA_DPORT0;
	writel(rdma_dport, reg_addr);

	reg_addr = nbl_dev->rf->hw.hw_addr +
		   NBL_UPA_RDMA_DPORT0_ADDR(NBL_REG_UPA_BASE_V4);
	writel(rdma_dport, reg_addr);
}

void nbl_rdma_get_psn_ost(struct nbl_device *nbl_dev, u32 *psn_ost)
{
	void *reg_addr;

	reg_addr = nbl_dev->rf->hw.hw_addr +
		   NBL_TXP_REG_ADDR(NBL_REG_TXP_BASE_V4,
				     NBL_TXP_PSN_OST_OFF);
	*psn_ost = readl(reg_addr);
	*psn_ost &= ~NBL_TXP_PSN_OST_VALID_MASK;
}

void nbl_rdma_rxm_write_atomic_fence(struct nbl_device *nbl_dev, bool enable)
{
	struct nbl_hw *hw = &nbl_dev->rf->hw;
	void *reg_addr;
	__u32 value;

	reg_addr = hw->hw_addr +
		   NBL_RDMA_TOP_REG_ADDR(NBL_REG_RDMA_TOP_BASE(hw),
					 NBL_RDMA_TOP_SRP_CFG_EN_OFF);
	value = readl(reg_addr);

	if (enable)
		value |= NBL_RDMA_TOP_SRP_WRITE_ATOMIC_FENCE_MASK;
	else
		value &= ~NBL_RDMA_TOP_SRP_WRITE_ATOMIC_FENCE_MASK;
	writel(value, reg_addr);
}

void nbl_rdma_set_psn_ost(struct nbl_device *nbl_dev, u32 psn_ost)
{
	void *reg_addr;

	psn_ost |= NBL_TXP_PSN_OST_VALID_MASK;
	reg_addr = nbl_dev->rf->hw.hw_addr +
		   NBL_TXP_REG_ADDR(NBL_REG_TXP_BASE_V4,
				     NBL_TXP_PSN_OST_OFF);
	writel(psn_ost, reg_addr);
}

void nbl_rdma_set_llc(struct nbl_device *nbl_dev, u32 enable)
{
	struct nbl_adev *nbl_adev = nbl_dev->rf->adev;
	struct auxiliary_device *aux_dev = &nbl_adev->adev;
	void *reg_addr;

	reg_addr = nbl_dev->rf->hw.hw_addr +
		NBL_DIPRO_REG_ADDR(NBL_REG_DIPRO_V3, NBL_DIPRO_DN_GLB_LLC_EN_OFF); /* dipro */
	writel(enable, reg_addr);

	reg_addr = nbl_dev->rf->hw.hw_addr +
		NBL_UIPRO_REG_ADDR(NBL_REG_UIPRO_V3, NBL_UIPRO_GLB_LLC_EN_OFF); /* uipro */
	writel(enable, reg_addr);
	nbl_core_rcv_rdma_up_rdma_bypass(aux_dev,
					 nbl_adev->core_info->vsi_id, enable);
}

void nbl_set_srp_cfg(struct nbl_device *nbl_dev, u32 value, u8 offset_code)
{
	u8 offset;
	void *reg_addr;
	u32 mask;
	u32 srp_cfg_config_val;
	struct nbl_hw *hw = &nbl_dev->rf->hw;

	switch (offset_code) {
	case NBL_SRP_CONFIG_EPSN_RTH:
		reg_addr = hw->hw_addr +
			   NBL_RDMA_TOP_REG_ADDR(NBL_REG_RDMA_TOP_BASE(hw),
						 NBL_RDMA_TOP_SRP_CFG_EN_OFF);
		offset = 11;
		mask = ~(0x3FF << 11);
		break;
	case NBL_SRP_CONFIG_BITMAP_EN:
		reg_addr = hw->hw_addr +
			   NBL_RDMA_TOP_REG_ADDR(NBL_REG_RDMA_TOP_BASE(hw),
						 NBL_RDMA_TOP_SRP_CFG_EN_OFF);
		offset = 0;
		mask = ~0x1;
		break;
	case NBL_FUN_DBG_SRP_RETRY_PKT_TH:
		reg_addr = hw->hw_addr +
			   NBL_TXP_REG_ADDR(NBL_REG_TXP_BASE(hw),
					     NBL_TXP_SRP_PKT_CNT_TH_OFF);
		offset = 0;
		mask = 0;
		break;
	default:
		nbl_pr_err(
			"not support srp config cur, offset_code:%x\n",
			offset_code);
		return;
	}
	srp_cfg_config_val = readl(reg_addr);
	srp_cfg_config_val &= mask;
	srp_cfg_config_val |= value << offset;
	writel(srp_cfg_config_val, reg_addr);
}

void nbl_ibdev_set_dim(struct ib_device *ibdev, u8 use_dim)
{
}

static void nbl_abnormal_event_handler(struct work_struct *work)
{
	struct nbl_pci_f *rf = container_of(work, struct nbl_pci_f, abnormal_task);

	rf->hw.hw_ops->get_hw_abnormal_evt(&rf->hw, NBL_RDMA_VERSION_SZ);
}

int nbl_alloc_abnormal_evt_wq(struct nbl_device *nbl_dev)
{
	struct nbl_pci_f *rf = nbl_dev->rf;

	if (!nbl_product_flag_enabled(rf, NBL_PRODUCT_F_ABNORMAL_EVENT))
		return 0;

	rf->abnormal_evt_wq = alloc_workqueue("%s", WQ_MEM_RECLAIM | WQ_UNBOUND,
					      0, "rdma_abnormal_evt_wq");
	if (!rf->abnormal_evt_wq) {
		nbl_pr_err("alloc rdma_abnormal_evt_wq err\n");
		return -ENOMEM;
	}

	INIT_WORK(&rf->abnormal_task, nbl_abnormal_event_handler);
	return 0;
}

void nbl_free_abnormal_evt_wq(struct nbl_device *nbl_dev)
{
	struct nbl_pci_f *rf = nbl_dev->rf;

	if (!rf->abnormal_evt_wq)
		return;

	destroy_workqueue(rf->abnormal_evt_wq);
	rf->abnormal_evt_wq = NULL;
}

static bool pcie_is_support_atomic_cap(struct pci_dev *pcidev)
{
	u16 pcie_ctl2 = 0;

	pcie_capability_read_word(pcidev, PCI_EXP_DEVCTL2, &pcie_ctl2);
	return (pcie_ctl2 & PCI_EXP_DEVCTL2_ATOMIC_REQ);
}

void nbl_pci_set_atomic(struct nbl_device *dev, struct pci_dev *pdev)
{
	static bool pf_support_atomic;
	struct nbl_pci_f *rf = dev->rf;
	bool is_support_atomic = false;

	if (NBL_RF_TO_HW_VER(rf) == NBL_VER_2) {
		nbl_product_set_cap(rf, NBL_PRODUCT_CAP_ATOMIC,
				    rf->init_params.atomic_cap != IB_ATOMIC_NONE);
		return;
	}

	if (nbl_product_flag_enabled(rf, NBL_PRODUCT_F_CTRL_DEV)) {
		/* for RNIC400 always support atomic */
		if (NBL_RF_TO_HW_VER(rf) == NBL_VER_4) {
			is_support_atomic = true;
		} else {
			/* PF: try to enable atomic cap */
			int rc = pci_enable_atomic_ops_to_root(
				pdev, PCI_EXP_DEVCAP2_ATOMIC_COMP64);
			if (!rc)
				is_support_atomic =
					pcie_is_support_atomic_cap(pdev);
		}
		if (is_support_atomic) {
			pf_support_atomic = true;
			nbl_product_set_cap(rf, NBL_PRODUCT_CAP_ATOMIC, true);
			nbl_dev_dbg(&rf->adev->adev.dev, "Atomic capability enabled\n");
			return;
		}
	} else {
	   /*
	    * Per PCIe r5.0, sec 9.3.5.10, the AtomicOp Requester Enable bit
	    * in Device Control 2 is reserved in VFs and the PF value applies
	    * to all associated VFs.
	    */
		if (pf_support_atomic) {
			nbl_product_set_cap(rf, NBL_PRODUCT_CAP_ATOMIC, true);
			nbl_dev_dbg(&rf->adev->adev.dev, "Atomic capability enabled\n");
			return;
		}
	}

	nbl_product_set_cap(rf, NBL_PRODUCT_CAP_ATOMIC, false);
	nbl_dev_info(&rf->adev->adev.dev, "Atomic capability disabled\n");
}

static void df200_host_set_bond_cfg(struct nbl_device *nbl_dev, bool bond_status)
{
	struct nbl_pci_f *rf = nbl_dev->rf;

	rf->sc_dev.fwd = bond_status ? NBL_CPU_FWD : NBL_NORMAL_FWD;
	rf->sc_dev.rss_lag_en = bond_status;
}

static int nbl_abn_event(struct notifier_block *notifier,
			 unsigned long event, void *data)
{
	struct nbl_device *nbl_dev = container_of(notifier, struct nbl_device,
						 grc_abn_nb);

	if (event != NBL_CORE_EVT_ABN)
		return NOTIFY_DONE;

	nbl_abnormal_event_process(nbl_dev);
	return NOTIFY_OK;
}

static int nbl_qos_cfg_event(struct notifier_block *notifier,
			     unsigned long event, void *data)
{
	struct nbl_device *nbl_dev = container_of(notifier, struct nbl_device,
						 qos_cfg_nb);
	struct nbl_qos_cfg *qos_cfg = data;

	if (event != NBL_CORE_EVT_QOS_CFG || !qos_cfg)
		return NOTIFY_DONE;

	qos_cfg->return_size = nbl_qos_cfg_store_v2(nbl_dev, qos_cfg->offset,
						    qos_cfg->buf,
						    qos_cfg->count);
	return NOTIFY_OK;
}

static int nbl_qos_show_event(struct notifier_block *notifier,
			      unsigned long event, void *data)
{
	struct nbl_device *nbl_dev = container_of(notifier, struct nbl_device,
						 qos_show_nb);
	struct nbl_qos_show *qos_show = data;

	if (event != NBL_CORE_EVT_QOS_SHOW || !qos_show)
		return NOTIFY_DONE;

	qos_show->return_size = nbl_qos_cfg_show_v2(nbl_dev, qos_show->offset,
						     qos_show->buf);
	return NOTIFY_OK;
}

static int nbl_ecpu_bond_event(struct notifier_block *notifier,
			       unsigned long event, void *data)
{
	struct nbl_device *nbl_dev = container_of(notifier, struct nbl_device,
						 ecpu_bond_nb);

	if (event != NBL_CORE_EVT_ECPU_BOND || !data)
		return NOTIFY_DONE;

	df200_host_set_bond_cfg(nbl_dev, *(bool *)data);
	return NOTIFY_OK;
}

int nbl_register_rdma_event_notifiers(struct nbl_device *nbl_dev,
				      struct nbl_core_export *core_info)
{
	int err;

	if (nbl_product_flag_enabled(nbl_dev->rf,
				     NBL_PRODUCT_F_ABNORMAL_EVENT)) {
		nbl_dev->grc_abn_nb.notifier_call = nbl_abn_event;
		err = blocking_notifier_chain_register(&core_info->grc_abn_nh,
						       &nbl_dev->grc_abn_nb);
		if (err)
			goto register_abn_err;
	}

	nbl_dev->qos_cfg_nb.notifier_call = nbl_qos_cfg_event;
	err = blocking_notifier_chain_register(&core_info->qos_cfg_nh,
					       &nbl_dev->qos_cfg_nb);
	if (err)
		goto register_qos_cfg_err;

	nbl_dev->qos_show_nb.notifier_call = nbl_qos_show_event;
	err = blocking_notifier_chain_register(&core_info->qos_show_nh,
					       &nbl_dev->qos_show_nb);
	if (err)
		goto register_qos_show_err;

	if (!nbl_product_cap_enabled(nbl_dev->rf, NBL_PRODUCT_CAP_BAR4_NOTIFY))
		return 0;

	nbl_dev->ecpu_bond_nb.notifier_call = nbl_ecpu_bond_event;
	err = blocking_notifier_chain_register(&core_info->ecpu_bond_nh,
					       &nbl_dev->ecpu_bond_nb);
	if (err)
		goto register_ecpu_bond_err;

	return 0;

register_ecpu_bond_err:
	nbl_dev->ecpu_bond_nb.notifier_call = NULL;
	blocking_notifier_chain_unregister(&core_info->qos_show_nh,
					   &nbl_dev->qos_show_nb);
register_qos_show_err:
	nbl_dev->qos_show_nb.notifier_call = NULL;
	blocking_notifier_chain_unregister(&core_info->qos_cfg_nh,
					   &nbl_dev->qos_cfg_nb);
register_qos_cfg_err:
	nbl_dev->qos_cfg_nb.notifier_call = NULL;
	if (nbl_dev->grc_abn_nb.notifier_call) {
		blocking_notifier_chain_unregister(&core_info->grc_abn_nh,
						   &nbl_dev->grc_abn_nb);
		nbl_dev->grc_abn_nb.notifier_call = NULL;
	}
	return err;

register_abn_err:
	nbl_dev->grc_abn_nb.notifier_call = NULL;
	return err;
}

void nbl_unregister_rdma_event_notifiers(struct nbl_device *nbl_dev,
					 struct nbl_core_export *core_info)
{
	if (nbl_dev->ecpu_bond_nb.notifier_call) {
		blocking_notifier_chain_unregister(&core_info->ecpu_bond_nh,
						   &nbl_dev->ecpu_bond_nb);
		nbl_dev->ecpu_bond_nb.notifier_call = NULL;
	}

	if (nbl_dev->qos_show_nb.notifier_call) {
		blocking_notifier_chain_unregister(&core_info->qos_show_nh,
						   &nbl_dev->qos_show_nb);
		nbl_dev->qos_show_nb.notifier_call = NULL;
	}

	if (nbl_dev->qos_cfg_nb.notifier_call) {
		blocking_notifier_chain_unregister(&core_info->qos_cfg_nh,
						   &nbl_dev->qos_cfg_nb);
		nbl_dev->qos_cfg_nb.notifier_call = NULL;
	}

	if (nbl_dev->grc_abn_nb.notifier_call) {
		blocking_notifier_chain_unregister(&core_info->grc_abn_nh,
						   &nbl_dev->grc_abn_nb);
		nbl_dev->grc_abn_nb.notifier_call = NULL;
	}
}

static bool nbl_ib_device_get(struct ib_device *device)
{
	return refcount_inc_not_zero(&device->refcount);
}

static void nbl_ib_device_put(struct ib_device *device)
{
	if (refcount_dec_and_test(&device->refcount))
		complete(&device->unreg_completion);
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
	if (!nbl_ib_device_get(ib_dev))
		return NOTIFY_DONE;
	sc_dev = &nbl_dev->rf->sc_dev;
	nbl_ib_dbg(sc_dev, "dev:%s recv event=%lu", ib_dev->name, event);
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
	nbl_ib_device_put(ib_dev);
	return NOTIFY_DONE;
}

int nbl_add_netdev_notifier(struct nbl_device *nbl_dev)
{
	int err;
	struct notifier_block *notify_blk;

	notify_blk = &nbl_dev->nb;
	nbl_dev->nb.notifier_call = nbl_netdevice_event;
	err = register_netdevice_notifier(&nbl_dev->nb);
	if (err) {
		nbl_dev->nb.notifier_call = NULL;
		return err;
	}

	dev_hold(nbl_dev->netdev);
	return 0;
}

void nbl_remove_netdev_notifier(struct nbl_device *nbl_dev)
{
	struct notifier_block *notif_blk;

	if (nbl_dev->nb.notifier_call) {
		notif_blk = &nbl_dev->nb;
		unregister_netdevice_notifier(&nbl_dev->nb);
		nbl_dev->nb.notifier_call = NULL;
		dev_put(nbl_dev->netdev);
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
	struct nbl_core_export *core_info =
		(struct nbl_core_export *)rf->cdev;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = is_register ? GRC_MSG_OP_REGISTER_CLIENT :
					    GRC_MSG_OP_UNREGISTER_CLIENT;
	head->payload_len = sizeof(struct register_client_req);
	data_len += sizeof(struct grc_cache_msg_header);

	req.vsi_id = core_info->vsi_id;
	req.eth_id = core_info->eth_id;
	req.function_id = rf->sc_dev.function_id;
	req.real_bdf = PCI_DEVID(core_info->real_bus,
				 PCI_DEVFN(core_info->real_dev, core_info->real_function));
	memcpy(in + data_len, &req, sizeof(req));
	data_len += sizeof(req);

	ret = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret != 0)
		nbl_pr_err("mailbox %s client err=%d\n",
			   is_register ? "register" : "unregister", ret);

	return ret;
}

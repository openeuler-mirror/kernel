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
#include "shared.h"
#include "main.h"
#include "device.h"
#include "cq.h"
#include "qp.h"
#include "pble.h"
#include "cqp.h"
#include "grc.h"
#include "defs.h"
#include "tlp.h"
#include "mailbox.h"
#include "resource.h"

/**
 * sd_addr_mode and resource_profile are used for fpga products only,
 * asic products got these params from emp configuration template
 */
u8 sd_addr_mode = LEVEL0_WITH_SZ_2M;
module_param_named(sd_addr_mode, sd_addr_mode, byte, 0640);
MODULE_PARM_DESC(sd_addr_mode, "sd address pg_size: 0=2MB pg_size,1=4KB pg_size,2=level1 pg_size");

u8 resource_profile = PF_ONLY;
module_param(resource_profile, byte, 0640);
MODULE_PARM_DESC(resource_profile, "Resource Profile: 0=PF only,1=Even Distribution between pf/vf(default)");

int nbl_shadow_init(struct nbl_pci_f *rf)
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

	if (nbl_product_cap_enabled(rf, NBL_PRODUCT_CAP_SRQ)) {
		/* SRQ */
		rf->srq_sd_info = kzalloc(sizeof(struct nbl_hmc_obj_sd_info), GFP_KERNEL);
		if (!rf->srq_sd_info) {
			ret = -ENOMEM;
			goto free_obj_mrt_sd_info;
		}

		ret = nbl_get_obj_sd_addr(rf, NBL_HMC_SRQ, rf->srq_sd_info);
		if (ret)
			goto free_srq_sd_info;
	}
	return 0;

free_srq_sd_info:
	kfree(rf->srq_sd_info);
free_obj_mrt_sd_info:
	nbl_free_obj_sd_addr(rf->mrt_sd_info);
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

void nbl_shadow_exit(struct nbl_pci_f *rf)
{
	nbl_free_obj_sd_addr(rf->mrt_sd_info);
	kfree(rf->mrt_sd_info);
	nbl_free_obj_sd_addr(rf->cq_sd_info);
	kfree(rf->cq_sd_info);
	nbl_free_obj_sd_addr(rf->qp_sd_info);
	kfree(rf->qp_sd_info);
	nbl_free_obj_sd_addr(rf->srq_sd_info);
	kfree(rf->srq_sd_info);
}

u16 nbl_get_ddr_obj_sz(u8 obj_type)
{
	int hmc_ddr_obj_sz[NBL_HMC_MAX] = {
		NBL_QP_SHADOW_SIZE,
		NBL_CQ_SHADOW_SIZE,
		NBL_HMC_PBL_SZ,
		0,
		NBL_HMC_SRQ_SHADOW_SZ,
	};

	WARN_ON(obj_type >= NBL_HMC_MAX);

	return hmc_ddr_obj_sz[obj_type];
}

static bool nbl_objs_is_ddr_mode(struct nbl_pci_f *rf)
{
	union nbl_grc_init_reg *grc_init = &rf->grc_init_reg;

	return grc_init->key.obj_mem_mode == OBJ_IN_DDR ||
		grc_init->key.obj_mem_mode == OBJ_IN_MINI_DDR;
}

static u16 nbl_get_obj_sz(struct nbl_pci_f *rf, u8 obj_type)
{
	int hmc_obj_sz[NBL_HMC_MAX] = {
		NBL_HMC_QPC_SZ,
		NBL_HMC_CQC_SZ,
		NBL_HMC_PBL_SZ,
		NBL_HMC_MRTE_SZ_V2,
		NBL_HMC_SRQC_SZ,
	};

	if (rf->product->resource_ops->get_obj_sz && nbl_objs_is_ddr_mode(rf))
		return rf->product->resource_ops->get_obj_sz(obj_type);

	WARN_ON(obj_type >= NBL_HMC_MAX);

	return hmc_obj_sz[obj_type];
}

static inline u8 nbl_get_pgsz_type(struct nbl_pci_f *rf)
{
	return rf->addr_mode == LEVEL0_WITH_SZ_2M ? NBL_HMC_HUGEPAGE : NBL_HMC_STANDARD_PAGE;
}

static inline u8 nbl_get_address_level(struct nbl_pci_f *rf)
{
	return rf->addr_mode == LEVEL1_WITH_SZ_4K ?
	       NBL_HMC_ADDRESS_LEVEL1 :
	       NBL_HMC_ADDRESS_LEVEL0;
}

static void nbl_fill_voa_tbl(struct nbl_pci_f *rf, u16 function_id, bool valid)
{
	int i;
	u32 obj_base;
	u16 real_obj_sz;
	u32 obj_total_sz;
	int voa_len = 0;
	u32 align_sz = NBL_HMC_QPC_SZ;
	u8 voa_str[VOA_TBL_STR_LEN] = {};
	u32 sd_sz = nbl_get_sd_alignment(rf);
	u32 *obj_num = (u32 *)&rf->dev_objs[function_id];
	union nbl_hmc_voa_entry_v2 *voa_ent = rf->voa_tbl_v2[function_id];
	struct nbl_hmc_sd_range *sd_range = &rf->hmc_sd_range[function_id];

	if (!valid) {
		memset(voa_ent, 0, sizeof(rf->voa_tbl_v2[function_id]));
		return;
	}

	for (i = 0; i < NBL_HMC_MAX; i++) {
		real_obj_sz = nbl_get_obj_sz(rf, i);
		voa_ent[i].key.obj_sz = ilog2(real_obj_sz);
		voa_ent[i].key.page_mode = nbl_get_address_level(rf);
		voa_ent[i].key.page_sz = nbl_get_pgsz_type(rf);
		voa_ent[i].key.obj_max_cnt = *obj_num;
		voa_ent[i].key.obj_idx_start = voa_ent[i].key.obj_max_cnt * function_id;
		if (i == NBL_HMC_PBL)
			voa_ent[i].key.obj_idx_start = 0;
		voa_ent[i].key.valid = 1;
		if (i == 0 && function_id == NBL_RDMA_FIRST_FUNCTION_ID) {
			obj_base = 0;
		} else {
			if (i == 0 && function_id != NBL_RDMA_FIRST_FUNCTION_ID) {
				obj_base = sd_range->start * sd_sz;
			} else {
				if (sd_addr_mode == LEVEL0_WITH_SZ_2M)
					align_sz = SZ_2M;

				obj_total_sz = voa_ent[i - 1].key.obj_max_cnt *
					(1 << voa_ent[i - 1].key.obj_sz);
				obj_base =
					ALIGN((voa_ent[i - 1].key.obj_ba << NBL_HMC_MAX_OBJ_LOG_SZ)
					      + obj_total_sz, align_sz);
			}
		}

		voa_ent[i].key.obj_ba = obj_base >> ilog2(NBL_HMC_QPC_SZ);
		obj_num++;

		voa_len += snprintf(voa_str + voa_len, sizeof(voa_str) - voa_len,
				    VOA_TBL_ENTRY_FORMAT_NEW, i, voa_ent[i].key.valid,
				    voa_ent[i].key.obj_ba, voa_ent[i].key.obj_max_cnt,
				    voa_ent[i].key.obj_idx_start, voa_ent[i].key.obj_sz,
				    voa_ent[i].key.page_sz, voa_ent[i].key.page_mode);
	}

	nbl_dev_dbg(&rf->adev->adev.dev, "%s", voa_str);
}

/* resv ecpu voa tbl entry in ddr,mini_ddr,hmc mode */
int nbl_update_voa_tbl(struct nbl_pci_f *rf, u16 function_id, bool valid)
{
	union nbl_hmc_voa_entry_v2 *voa_ent;
	__be64 cmd_in[NBL_CMD_INPUT_SIZE / sizeof(u64)] = {};
	__be64 cmd_out[NBL_CMD_OUTPUT_SIZE / sizeof(u64)] = {};
	int ret_val;
	u64 temp;

	voa_ent = rf->voa_tbl_v2[function_id];
	nbl_fill_voa_tbl(rf, function_id, valid);

	nbl_64bit_write(cmd_in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_UPDATE_VOA);
	nbl_64bit_write(cmd_in, NBL_CQP_VOA_VFID, function_id);
	nbl_64bit_write(cmd_in, NBL_CQP_VOA_QPC_HIGH, voa_ent[NBL_HMC_QP].data[VOA_ENT_LAST_DW]);

	memcpy(&temp, voa_ent[NBL_HMC_QP].data, sizeof(temp));
	nbl_64bit_write(cmd_in, NBL_CQP_VOA_QPC_LOW, temp);

	memcpy(&temp, &voa_ent[NBL_HMC_CQ].data[VOA_ENT_MIDDLE_DW], sizeof(temp));
	nbl_64bit_write(cmd_in, NBL_CQP_VOA_CQC_HIGH, temp);

	nbl_64bit_write(cmd_in, NBL_CQP_VOA_CQC_LOW, voa_ent[NBL_HMC_CQ].data[VOA_ENT_FIRST_DW]);
	nbl_64bit_write(cmd_in, NBL_CQP_VOA_PBL_HIGH, voa_ent[NBL_HMC_PBL].data[VOA_ENT_LAST_DW]);

	memcpy(&temp, &voa_ent[NBL_HMC_PBL], sizeof(temp));
	nbl_64bit_write(cmd_in, NBL_CQP_VOA_PBL_LOW, temp);

	if (!rf->sc_dev.ddr_mode_en) {
		memcpy(&temp, &voa_ent[NBL_HMC_MR].data[VOA_ENT_MIDDLE_DW], sizeof(temp));
		nbl_64bit_write(cmd_in, NBL_CQP_VOA_MR_HIGH, temp);

		nbl_64bit_write(cmd_in, NBL_CQP_VOA_MR_LOW,
				voa_ent[NBL_HMC_MR].data[VOA_ENT_FIRST_DW]);
		nbl_64bit_write(cmd_in, NBL_CQP_VOA_SRQ_HIGH,
				voa_ent[NBL_HMC_SRQ].data[VOA_ENT_LAST_DW]);
	} else {
		nbl_64bit_write(cmd_in, NBL_CQP_VOA_SRQ_HIGH,
				voa_ent[NBL_HMC_SRQ].data[VOA_ENT_LAST_DW]);
	}

	memcpy(&temp, &voa_ent[NBL_HMC_SRQ], sizeof(temp));
	nbl_64bit_write(cmd_in, NBL_CQP_VOA_SRQ_LOW, temp);

	ret_val = nbl_cmd_exec(rf, cmd_in, NBL_CMD_INPUT_SIZE, cmd_out, NBL_CMD_OUTPUT_SIZE);
	if (ret_val)
		nbl_ib_err(&rf->sc_dev, "cqp cmd failed,err=%d\n", ret_val);

	return ret_val;
}
int nbl_setup_voa(struct nbl_pci_f *rf)
{
	int ret_val;
	uint8_t in[64];
	uint8_t out[64];
	int data_len = 0;
	struct grc_cache_msg_header *head;

	if (rf->product->resource_ops->set_voa_tbl)
		return rf->product->resource_ops->set_voa_tbl(rf,
							       rf->sc_dev.function_id, true);

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

	if (rf->product->resource_ops->set_voa_tbl)
		return rf->product->resource_ops->set_voa_tbl(rf,
							       rf->sc_dev.function_id, false);

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

static void nbl_parse_voa_tbl_entry(__be64 *src, u8 *dest, u16 dest_len)
{
	int voa_len = 0;
	int i;
	u64 temp;
	union nbl_hmc_voa_entry_v2 voa_ent_v2[NBL_HMC_MAX] = {};

	voa_ent_v2[NBL_HMC_QP].data[VOA_ENT_LAST_DW] =
		(u32)nbl_64bit_read(src, NBL_CQP_VOA_QPC_HIGH);

	temp = nbl_64bit_read(src, NBL_CQP_VOA_QPC_LOW);
	memcpy(voa_ent_v2[NBL_HMC_QP].data, &temp, sizeof(temp));

	temp = nbl_64bit_read(src, NBL_CQP_VOA_CQC_HIGH);
	memcpy(&voa_ent_v2[NBL_HMC_CQ].data[VOA_ENT_MIDDLE_DW], &temp, sizeof(temp));

	voa_ent_v2[NBL_HMC_CQ].data[VOA_ENT_FIRST_DW] =
		(u32)nbl_64bit_read(src, NBL_CQP_VOA_CQC_LOW);

	voa_ent_v2[NBL_HMC_PBL].data[VOA_ENT_LAST_DW] =
		(u32)nbl_64bit_read(src, NBL_CQP_VOA_PBL_HIGH);
	temp = nbl_64bit_read(src, NBL_CQP_VOA_PBL_LOW);
	memcpy(voa_ent_v2[NBL_HMC_PBL].data, &temp, sizeof(temp));

	temp = nbl_64bit_read(src, NBL_CQP_VOA_MR_HIGH);
	memcpy(&voa_ent_v2[NBL_HMC_MR].data[VOA_ENT_MIDDLE_DW], &temp, sizeof(temp));

	voa_ent_v2[NBL_HMC_MR].data[VOA_ENT_FIRST_DW] =
		(u32)nbl_64bit_read(src, NBL_CQP_VOA_MR_LOW);
	voa_ent_v2[NBL_HMC_SRQ].data[VOA_ENT_LAST_DW] =
		(u32)nbl_64bit_read(src, NBL_CQP_VOA_SRQ_HIGH);

	temp = nbl_64bit_read(src, NBL_CQP_VOA_SRQ_LOW);
	memcpy(voa_ent_v2[NBL_HMC_SRQ].data, &temp, sizeof(temp));

	for (i = 0; i < NBL_HMC_MAX; i++) {
		voa_len += snprintf(dest + voa_len, dest_len - voa_len,
				    VOA_TBL_ENTRY_FORMAT_NEW,
				    i, voa_ent_v2[i].key.valid, voa_ent_v2[i].key.obj_ba,
				    voa_ent_v2[i].key.obj_max_cnt, voa_ent_v2[i].key.obj_idx_start,
				    voa_ent_v2[i].key.obj_sz, voa_ent_v2[i].key.page_sz,
				    voa_ent_v2[i].key.page_mode);
	}
}

int nbl_query_voa(char __user *buf, size_t count, loff_t *pos, struct nbl_pci_f *rf)
{
	int ret_val;
	__be64 in[NBL_CMD_INPUT_SIZE / sizeof(u64)] = {};
	__be64 out[NBL_CMD_OUTPUT_SIZE / sizeof(u64)] = {};
	u8 voa_str[VOA_TBL_STR_LEN] = {};
	int voa_len = 0;
	char *voa_head = "page_sz: 1 notes 2MB, 0 4KB; page_mode: 0 notes level0 addr,1 level1\n";

	if (*pos)
		return 0;

	nbl_ib_dbg(&rf->sc_dev, "query voa(fun %u) begin\n", rf->sc_dev.function_id);

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_QUERY_VOA);
	nbl_64bit_write(in, NBL_CQP_VOA_VFID, rf->sc_dev.function_id);

	ret_val = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, out, NBL_CMD_OUTPUT_SIZE);
	if (ret_val) {
		nbl_ib_err(&rf->sc_dev, "cqp cmd failed,err=%d\n", ret_val);
	} else {
		voa_len += snprintf(voa_str + voa_len, sizeof(voa_str) - strlen(voa_head),
				    "%s", voa_head);
		nbl_parse_voa_tbl_entry(out, voa_str + voa_len, sizeof(voa_str) - voa_len);
		ret_val = simple_read_from_buffer(buf, count, pos, voa_str, sizeof(voa_str));
	}

	return ret_val;
}

static inline u16 nbl_get_rdma_bdf_num(struct nbl_pci_f *rf)
{
	return PCI_DEVID(rf->pcidev->bus->number, rf->pcidev->devfn);
}

int nbl_set_ecpu_rdma_vfid(struct nbl_pci_f *rf)
{
	int i;
	u16 bdf_num = nbl_get_rdma_bdf_num(rf);
	bool host_en = rf->product->host_id != HOST_ID_TYPE_ECPU;
	u16 device_id_tbl[] = {
		DF200_ECPU_PF2_DEVICE_ID,
		DF200_ECPU_PF3_DEVICE_ID,
	};

	for (i = 0; i < ARRAY_SIZE(device_id_tbl); i++) {
		if (rf->pcidev->device == device_id_tbl[i]) {
			rf->sc_dev.function_id = i;
			rf->hw.hw_ops->set_hw_bdf_tbl(&rf->hw, host_en, i, bdf_num);
			return 0;
		}
	}
	nbl_dev_err(&rf->adev->adev.dev, "failed to assign rdma vfid for device_id=0x%x",
		    rf->pcidev->device);
	return -EINVAL;
}

int nbl_get_rdma_function_id(struct nbl_pci_f *rf)
{
	u16 bdf_num;
	u16 function_id = rf->sc_dev.pcie_fn_id;
	struct nbl_core_export *core_info = rf->cdev;

	rf->sc_dev.function_id = function_id;

	bdf_num = NBL_GET_BDF_NUM(core_info->real_bus, core_info->real_dev,
				  core_info->real_function);
	rf->hw.hw_ops->set_hw_bdf_tbl(&rf->hw, true, function_id, bdf_num);

	return 0;
}

int nbl_put_rdma_function_id(struct nbl_pci_f *rf)
{
	u16 function_id = rf->sc_dev.function_id;

	rf->hw.hw_ops->set_hw_bdf_tbl(&rf->hw, true, function_id, 0);
	return 0;
}

int nbl_get_function_id_via_channel(struct nbl_pci_f *rf)
{
	int ret_val;
	u16 function_id;
	uint8_t in[NBL_CMD_INPUT_SIZE];
	uint8_t out[NBL_CMD_OUTPUT_SIZE];
	u8 data_len = 0;
	struct get_function_id_req req;
	struct grc_cache_msg_header *head;
	struct nbl_core_export *core_info = (struct nbl_core_export *)rf->cdev;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_GET_FUNCTION_ID;
	head->payload_len = sizeof(struct get_function_id_req);
	data_len += sizeof(struct grc_cache_msg_header);

	req.host_id = rf->product->host_id;
	req.bdf_num = NBL_GET_BDF_NUM(core_info->real_bus, core_info->real_dev,
					core_info->real_function);
	req.is_pf = nbl_product_flag_enabled(rf, NBL_PRODUCT_F_CTRL_DEV);

	nbl_pr_dbg("req host_id=0x%x,bdf_num=0x%x,if_pf=%u",
		   rf->product->host_id, req.bdf_num, req.is_pf);

	memcpy(in + data_len, &req, sizeof(req));
	data_len += sizeof(req);

	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val) {
		nbl_dev_err(&rf->adev->adev.dev, "get function_id cmd err=%d", ret_val);
		return ret_val;
	}

	memcpy(&function_id, out + 1, sizeof(function_id));
	rf->sc_dev.function_id = function_id;

	nbl_pr_dbg("resp got function_id=%u", function_id);
	return 0;
}

int nbl_get_function_num(struct nbl_pci_f *rf)
{
	if (WARN_ON(!rf->product))
		return -EINVAL;

	return rf->product->lifecycle_ops->get_function_id(rf);
}

int nbl_clear_ecpu_rdma_vfid(struct nbl_pci_f *rf)
{
	rf->hw.hw_ops->set_hw_bdf_tbl(&rf->hw, 0, rf->sc_dev.function_id, 0);
	return 0;
}

int nbl_free_function_id_via_channel(struct nbl_pci_f *rf)
{
	int ret_val;
	uint8_t in[64];
	uint8_t out[64];
	u8 data_len = 0;
	struct free_function_id_req req;
	struct grc_cache_msg_header *head;
	struct nbl_core_export *core_info = (struct nbl_core_export *)rf->cdev;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_FREE_FUNC_ID;
	head->payload_len = sizeof(struct free_function_id_req);
	data_len += sizeof(struct grc_cache_msg_header);

	req.host_id = rf->product->host_id;
	req.bdf_num = NBL_GET_BDF_NUM(core_info->real_bus, core_info->real_dev,
					core_info->real_function);
	req.function_id = rf->sc_dev.function_id;
	req.is_pf = nbl_product_flag_enabled(rf, NBL_PRODUCT_F_CTRL_DEV);

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

int nbl_free_function_num(struct nbl_pci_f *rf)
{
	if (WARN_ON(!rf->product))
		return -EINVAL;

	return rf->product->lifecycle_ops->free_function_id(rf);
}

void nbl_direct_set_vf_enable_tbl(struct nbl_pci_f *rf, u16 function_id, u8 enable)
{
	rf->hw.hw_ops->set_hw_vf_enable(&rf->hw, function_id, enable);
}

int nbl_set_hdma_vf_enable(struct nbl_pci_f *rf, u8 enable)
{
	int ret_val;
	u8 in[NBL_GRC_INPUT_SIZE] = {};
	u8 out[NBL_GRC_INPUT_SIZE] = {};
	u8 data_len = 0;
	struct grc_cache_msg_header *head;
	struct set_hdma_vf_enable_req req = {};

	if (rf->product->resource_ops->set_vf_enable) {
		rf->product->resource_ops->set_vf_enable(rf, rf->sc_dev.function_id,
							 enable);
		return 0;
	}

	if (nbl_product_flag_enabled(rf, NBL_PRODUCT_F_CTRL_DEV))
		return 0;

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

static u32 qp_limits_tbl[] = {
	SZ_128,
	SZ_4K,
	SZ_32K,
	SZ_64K,
	SZ_128K,
};

/* 4KB page size with level0 */
static const struct nbl_obj_cnt level0_4k_obj_total_cnt = {
	.qp_num = SZ_8K,  /* 8k qp */
	.cq_num = SZ_16K,  /* 16k cq */
	.pble_num = SZ_128K,  /* 128k pble */
	.mr_num = SZ_16K,  /* 16k mrte */
	.srq_num = SZ_8K, /* 8k srq */
};

static void nbl_get_product_obj_cnt(struct nbl_pci_f *rf,
				    struct nbl_obj_cnt *obj_cnt)
{
	const struct nbl_product_limits *limits = rf->product->limits;

	obj_cnt->qp_num = limits->max_total_qps;
	obj_cnt->cq_num = limits->max_total_cqs;
	obj_cnt->pble_num = limits->max_total_pbls;
	obj_cnt->mr_num = limits->max_total_mrs;
	obj_cnt->srq_num = limits->max_total_srqs;
}

static void nbl_set_obj_cnt(struct nbl_pci_f *rf,
			    struct nbl_obj_cnt *total_obj_cnt)
{
	union nbl_grc_init_reg *grc_init = &rf->grc_init_reg;

	WARN_ON(grc_init->key.obj_mem_mode == OBJ_INVALID_MODE ||
		grc_init->key.sd_addr_mode > LEVEL1_WITH_SZ_4K);

	rf->addr_mode = grc_init->key.sd_addr_mode;

	if (grc_init->key.obj_mem_mode != OBJ_IN_DDR &&
	    grc_init->key.obj_mem_mode != OBJ_IN_MINI_DDR &&
	    grc_init->key.sd_addr_mode == LEVEL0_WITH_SZ_4K) {
		*total_obj_cnt = level0_4k_obj_total_cnt;
		return;
	}

	nbl_get_product_obj_cnt(rf, total_obj_cnt);
}

static int nbl_resv_ecpu_vf_qp_res(struct nbl_pci_f *rf,
				   const struct nbl_obj_cnt *total_obj_cnt)
{
	struct nbl_obj_cnt *objs = &rf->dev_objs[rf->sc_dev.function_id];
	u32 factor = 0;
	u16 fn_num = DF200_RDMA_TOTAL_FUNCTION_NUM;

	if (rf->grc_init_reg.key.qp_limits_sel >= ARRAY_SIZE(qp_limits_tbl))
		return -EINVAL;

	objs->qp_num = total_obj_cnt->qp_num / fn_num;
	objs->qp_num = min(objs->qp_num,
			   qp_limits_tbl[rf->grc_init_reg.key.qp_limits_sel]);

	factor = total_obj_cnt->cq_num / total_obj_cnt->qp_num;
	objs->cq_num = factor * objs->qp_num;

	factor = total_obj_cnt->pble_num / total_obj_cnt->qp_num;
	objs->pble_num = factor * objs->qp_num;

	factor = total_obj_cnt->mr_num / total_obj_cnt->qp_num;
	objs->mr_num = factor * objs->qp_num;

	objs->srq_num = total_obj_cnt->srq_num / fn_num;

	return 0;
}

void nbl_init_sd_range(struct nbl_pci_f *rf, u16 function_id)
{
	u32 fn_obj_size = 0;
	u32 sd_size = nbl_get_sd_alignment(rf);
	u32 sd_num;
	u32 *obj_num = (u32 *)&rf->dev_objs[function_id];
	u32 obj_size;
	u16 fn_id = function_id;
	int i;
	u32 align_size = sd_addr_mode == LEVEL0_WITH_SZ_2M ? SZ_2M : NBL_HMC_QPC_SZ;

	for (i = 0; i < NBL_HMC_MAX; i++) {
		obj_size = nbl_get_obj_sz(rf, i);
		fn_obj_size += ALIGN(*obj_num * obj_size, align_size);
		obj_num++;
	}
	sd_num = DIV_ROUND_UP(fn_obj_size, sd_size);

	nbl_dev_dbg(&rf->adev->adev.dev, "resv sd_num=0x%x", sd_num);
	rf->hmc_sd_range[fn_id].start = fn_id * sd_num;
	rf->hmc_sd_range[fn_id].cnt = sd_num;
}

static int nbl_pf_get_qp_res(struct nbl_pci_f *rf)
{
	struct nbl_obj_cnt *objs = &rf->dev_objs[rf->sc_dev.function_id];
	struct nbl_pf_init_param *pf_param = &rf->pf_param;
	struct nbl_obj_cnt product_obj_cnt;
	const struct nbl_obj_cnt *total_obj_cnt;

	/* TODO read qpn range from top ctrl reg */
	nbl_get_product_obj_cnt(rf, &product_obj_cnt);
	total_obj_cnt = rf->addr_mode == LEVEL0_WITH_SZ_4K ?
			&level0_4k_obj_total_cnt : &product_obj_cnt;

	pf_param->total_qp_cnt = total_obj_cnt->qp_num / rf->sc_dev.pf_count;

	if (pf_param->res_profile == PF_ONLY)
		objs->qp_num = pf_param->total_qp_cnt;
	else
		/* all qp distributed between current pf and its vfs */
		objs->qp_num = pf_param->total_qp_cnt / (pf_param->vf_cnt + 1);

	objs->cq_num = objs->qp_num * (total_obj_cnt->cq_num / total_obj_cnt->qp_num);
	objs->pble_num = objs->qp_num * (total_obj_cnt->pble_num / total_obj_cnt->qp_num);
	objs->mr_num = objs->qp_num * (total_obj_cnt->mr_num / total_obj_cnt->qp_num);
	objs->srq_num = objs->qp_num / (total_obj_cnt->qp_num / total_obj_cnt->srq_num);

	nbl_dev_dbg(&rf->adev->adev.dev, "total_obj_cnt->cq_num=0x%x,qp_num=%#x\n",
		    total_obj_cnt->cq_num, total_obj_cnt->qp_num);
	nbl_dev_dbg(&rf->adev->adev.dev, "objs.qp=%#x,cq=0x%x,pble=0x%x,mr=%#x,srq=%#x\n",
		     objs->qp_num, objs->cq_num, objs->pble_num, objs->mr_num, objs->srq_num);
	nbl_init_sd_range(rf, rf->sc_dev.function_id);
	return 0;
}

int nbl_get_resv_init_params(struct nbl_pci_f *rf)
{
	int retry_cnt = NBL_GET_GRC_INIT_PARAM_RETRY_CNT;
	union  nbl_grc_init_reg *grc_init = &rf->grc_init_reg;
	struct device *dev = &rf->adev->adev.dev;
	bool get_config = false;
	struct nbl_core_export *cdev = rf->cdev;

	while (retry_cnt--) {
		/*grc_init->data[0] = readl(rf->hw.hw_addr + NBL_GRC_INIT_PARAM_REG);*/
		if (grc_init->key.grc_stat == NBL_GRC_STAT_READY) {
			nbl_dev_info(dev, "got grc_init_params as follows:");
			nbl_dev_info(dev, "grc_stat=%u,obj_mem_mode=%u,function_num=%u",
				     grc_init->key.grc_stat, grc_init->key.obj_mem_mode,
				     grc_init->key.function_num);
			nbl_dev_info(dev, "qp_limits_sel=%u,resource_profile=%u,sd_addr_mode=%u",
				     grc_init->key.qp_limits_sel, grc_init->key.resource_profile,
				     grc_init->key.sd_addr_mode);
			get_config = true;
			break;
		}
		mdelay(NBL_GET_INIT_PARAM_TIME_INTERVAL);
	}

	nbl_dev_warn(dev, "grc module not ready,using default configuration");
	if (!get_config) {
		grc_init->key.obj_mem_mode = OBJ_IN_HMC;
		grc_init->key.sd_addr_mode = sd_addr_mode;
		grc_init->key.resource_profile = PF_ONLY;
		grc_init->key.qp_limits_sel = SZ_64K_QP;
		grc_init->key.function_num = cdev->eth_mode;
	}

	rf->sc_dev.ddr_mode_en = nbl_objs_is_ddr_mode(rf);
	return 0;
}

int df200_get_host_init_params(struct nbl_pci_f *rf)
{
	union  nbl_grc_init_reg *grc_init = &rf->grc_init_reg;

	grc_init->key.obj_mem_mode = OBJ_IN_HMC;
	grc_init->key.sd_addr_mode = sd_addr_mode;
	grc_init->key.resource_profile = PF_ONLY;
	grc_init->key.qp_limits_sel = SZ_64K_QP;
	return 0;
}

int df200_get_host_rdma_function_id(struct nbl_pci_f *rf)
{
	u16 bdf_num;
	int ret;
	struct nbl_core_export *core_info = rf->cdev;

	ret = df200_host_get_hw_func_id(&rf->hw, &rf->sc_dev.function_id);
	if (ret) {
		nbl_pr_err("df200 host get rdma func id err=%d\n", ret);
		return ret;
	}

	bdf_num = NBL_GET_BDF_NUM(core_info->real_bus, core_info->real_dev,
				  core_info->real_function);
	rf->hw.hw_ops->set_hw_bdf_tbl(&rf->hw, true, rf->sc_dev.function_id, bdf_num);

	return 0;
}

int df200_host_free_function_id(struct nbl_pci_f *rf)
{
	df200_host_put_hw_func_id(&rf->hw, rf->sc_dev.function_id);

	rf->hw.hw_ops->set_hw_bdf_tbl(&rf->hw, true, rf->sc_dev.function_id, 0);
	return 0;
}

static int nbl_resv_ecpu_res(struct nbl_pci_f *rf)
{
	struct nbl_obj_cnt total_obj_cnt;
	int ret;

	nbl_set_obj_cnt(rf, &total_obj_cnt);
	ret = nbl_resv_ecpu_vf_qp_res(rf, &total_obj_cnt);
	if (ret)
		return ret;

	nbl_init_sd_range(rf, rf->sc_dev.function_id);
	return 0;
}

int nbl_qp_res_init(struct nbl_pci_f *rf)
{
	int ret_val = 0;

	if (!nbl_product_flag_enabled(rf, NBL_PRODUCT_F_INIT_SD_DIRECT))
		return 0;

	if (nbl_product_flag_enabled(rf, NBL_PRODUCT_F_RESV_RES))
		ret_val = nbl_resv_ecpu_res(rf);
	else
		ret_val = nbl_pf_get_qp_res(rf);

	return ret_val;
}

int nbl_get_admin_pf_init_params(struct nbl_pci_f *rf)
{
	rf->pf_param.addr_mode = sd_addr_mode;
	rf->pf_param.res_profile = resource_profile;
	rf->pf_param.vf_cnt = NBL_RDMA_VF_CNT_PER_PF;
	rf->init_params.devx_umem_num = NBL_MAX_DEVX_UMEM;

	rf->addr_mode = rf->pf_param.addr_mode;
	rf->sc_dev.ddr_mode_en = 0;

	return 0;
}

int nbl_get_init_params(struct nbl_pci_f *rf)
{
	int ret_val;
	u8 in[NBL_CMD_INPUT_SIZE] = {};
	u8 out[NBL_CMD_OUTPUT_SIZE] = {};
	u8 data_len = 0;
	struct grc_cache_msg_header *head;

	if (sd_addr_mode > LEVEL1_WITH_SZ_4K)
		sd_addr_mode = LEVEL0_WITH_SZ_2M;
	if (resource_profile > PF_VF_EVEN_DISTRIBUTION)
		resource_profile = PF_ONLY;

	if (rf->dev_ops && rf->dev_ops->get_init_params)
		return rf->dev_ops->get_init_params(rf);

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


	nbl_pr_dbg("get init params,sd_addr_mode=%u,ddr_mode=%u",
		      rf->init_params.sd_addr_mode, rf->init_params.ddr_mode);

	rf->addr_mode = rf->init_params.sd_addr_mode;
	rf->sc_dev.ddr_mode_en = rf->init_params.ddr_mode;
	return 0;
}

void nbl_set_vfid_vsi_map_v3(struct nbl_pci_f *rf, bool valid,
				    u16 vsi_id)
{
	rf->hw.hw_ops->set_hw_vsi_port_tbl(&rf->hw, vsi_id,
					   rf->sc_dev.function_id, valid);
}

static int nbl_set_one_vsi_map(struct nbl_pci_f *rf, u8 is_valid, u16 vsi_id)
{
	int ret_val;
	uint8_t in[NBL_GRC_INPUT_SIZE];
	uint8_t out[NBL_GRC_OUTPUT_SIZE];
	int data_len = 0;
	struct set_vfid_vsi_map_req req = {};
	struct grc_cache_msg_header *head;

	if (rf->product->resource_ops->set_vfid_vsi_map) {
		rf->product->resource_ops->set_vfid_vsi_map(rf, is_valid, vsi_id);
		return 0;
	}

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_SET_VFID_VSI_MAP;
	head->payload_len = sizeof(struct set_vfid_vsi_map_req);
	data_len += sizeof(struct grc_cache_msg_header);

	req.function_id = rf->sc_dev.function_id;
	req.vsi_id = vsi_id;
	req.valid = is_valid;
	memcpy(in + data_len, &req, sizeof(req));
	data_len += sizeof(req);

	nbl_dev_dbg(&rf->adev->adev.dev,
		    "RoCE set_vfid_vsi_map vsi_id=%u,vfid=%u,valid=%u", vsi_id,
		    rf->sc_dev.function_id, is_valid);
	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val)
		nbl_pr_err(
			"set_vfid_vsi_map cmd err=%d,vsi_id=%u,vfid=%u,valid=%u",
			ret_val, vsi_id, rf->sc_dev.function_id, is_valid);

	return ret_val;
}

int nbl_set_qm_vfid_vsi_map(struct nbl_pci_f *rf, u8 is_valid)
{
	int i;
	int ret_val = 0;
	struct nbl_core_export *core_info =
		(struct nbl_core_export *)rf->cdev;
	u16 rx_vlan_vsi_num;

	if (!core_info->is_lag)
		ret_val = nbl_set_one_vsi_map(rf, is_valid, core_info->vsi_id);
	else if (nbl_product_cap_enabled(rf, NBL_PRODUCT_CAP_BAR4_NOTIFY))
		/* df200 host bond cannot get ecpu bond member, so use self vsi_id */
		ret_val = nbl_set_one_vsi_map(rf, is_valid, core_info->vsi_id);
	else {
		for (i = 0; i < NBL_RDMA_LAG_MBRS_MAX; i++) {
			if (core_info->lag_info.mbr[i].active) {
				ret_val = nbl_set_one_vsi_map(
					rf, is_valid,
					core_info->lag_info.mbr[i].vsi_id);
				if (ret_val)
					return ret_val;
			}
		}
	}

	/**
	 * avoid to cm establish fail in vlan offload case, only support for pf
	 * bond case need config all vsi
	 **/
	if (nbl_product_flag_enabled(rf, NBL_PRODUCT_F_RX_VLAN_VSI_MAP)) {
		rx_vlan_vsi_num = core_info->is_lag ? ARRAY_SIZE(rf->rx_vlan_vsi_id) : 1;
		rx_vlan_vsi_num = min_t(u16, rx_vlan_vsi_num, NBL_RDMA_LAG_MBRS_MAX);
		for (i = 0; i < rx_vlan_vsi_num; i++)
			ret_val |= nbl_set_one_vsi_map(rf, is_valid, rf->rx_vlan_vsi_id[i]);
	}

	return ret_val;
}

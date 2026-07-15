// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_ah_debugfs.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_drv_rdma_debugfs.h"
#include "sxe2_drv_ah.h"
#include "sxe2_drv_mq.h"
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_rcms_debugfs.h"
#include "sxe2_drv_ah_debugfs.h"

enum { AH_VLAN_TAG, AH_PD_IDX, AH_FLOW_LABEL };

#ifdef SXE2_CFG_DEBUG
static char *ah_fields[] = { [AH_VLAN_TAG]   = "vlan_tag",
			     [AH_PD_IDX]     = "pd_idx",
			     [AH_FLOW_LABEL] = "flow_label" };
#endif
#define ADDR_SIZE (4)

int sxe2_drv_ah_modify_op(struct sxe2_rdma_device *rdma_dev,
			  union sxe2_hw_ahc *ah_ctx)
{
	int ret;
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *mq_info;
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;

	mq_request = sxe2_kalloc_and_get_mq_request(&rdma_func->mq, true);
	if (!mq_request) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("get mq_request failed, ret (%d)\n", ret);
		goto end;
	}

	mq_info			      = &mq_request->info;
	mq_info->mq_cmd		      = MQ_OP_MODIFY_ADDR_HANDLE;
	mq_info->post_mq	      = 1;
	mq_info->in.u.ah_info.ctx_dev = &rdma_func->ctx_dev;
	mq_info->in.u.ah_info.scratch = (uintptr_t)mq_request;

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_ah_query",
		     &rdma_dev->rdma_func->mq.err_cqe_val, ah_ctx);

	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_ah_query");
#endif

	memcpy(&mq_info->in.u.ah_info.info, ah_ctx, sizeof(*ah_ctx));

	ret = sxe2_khandle_mq_cmd(rdma_func, mq_request);
	sxe2_kput_mq_request(&rdma_func->mq, mq_request);
	if (ret != 0)
		DRV_RDMA_LOG_DEV_ERR("handle modify ah failed, ret (%d)\n",
				     ret);

end:
	return ret;
}

u64 sxe2_debugfs_ah_read(struct sxe2_rdma_device *rdma_dev, void *data,
			 enum drv_rdma_dbg_rsc_type type, char *buf)
{
	int i;
	int ret;
	union sxe2_hw_ahc ah_ctx;
	union sxe2_hw_ahc *p_ah_ctx;
	void *va_addr;
	struct sxe2_ah *vendor_ah;
	size_t len = 0;
	u32 ah_index;
	u32 dest_ip_addr[ADDR_SIZE] = { 0 };
	u32 src_ip_addr[ADDR_SIZE]  = { 0 };

	va_addr	  = NULL;
	vendor_ah = (struct sxe2_ah *)data;
	ah_index  = vendor_ah->ctx_ah.ah_info.field.ah_idx;

	ret = sxe2_rcms_num_to_ctx_va_pointer(rdma_dev, SXE2_RCMS_OBJ_AH,
					      ah_index, &va_addr);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("query ah failed, ret (%d)\n", ret);
		goto end;
	}

	memset(&ah_ctx, 0, sizeof(ah_ctx));
	p_ah_ctx = (union sxe2_hw_ahc *)va_addr;
	for (i = 0; i < SXE2_MQ_WQE_SIZE; i++)
		ah_ctx.buf[i] = le64_to_cpu(p_ah_ctx->buf[i]);

	len += dbg_vsnprintf(buf, len, "AHINFO:%u\n", ah_index);
	len += dbg_vsnprintf(buf, len,
			     "----------------------------------------\n");

	len += dbg_vsnprintf(buf, len,
			     "dest_mac:%02x:%02x:%02x:%02x:%02x:%02x\n",
			     ah_ctx.field.dest_mac[5], ah_ctx.field.dest_mac[4],
			     ah_ctx.field.dest_mac[3], ah_ctx.field.dest_mac[2],
			     ah_ctx.field.dest_mac[1],
			     ah_ctx.field.dest_mac[0]);
	len += dbg_vsnprintf(buf, len, "vlan_tag:           %d\n",
			     ah_ctx.field.vlan_tag);
	len += dbg_vsnprintf(buf, len, "tc_tos:             %d\n",
			     ah_ctx.field.tc_tos);
	len += dbg_vsnprintf(buf, len, "pd_index:           %d\n",
			     ah_ctx.field.pd_idx);
	len += dbg_vsnprintf(buf, len, "flow_label:         %d\n",
			     ah_ctx.field.flow_label);
	len += dbg_vsnprintf(buf, len, "hop_ttl:            %d\n",
			     ah_ctx.field.hop_ttl);
	len += dbg_vsnprintf(buf, len, "ah_id:              %d\n",
			     ah_ctx.field.ah_idx);
	len += dbg_vsnprintf(buf, len, "op:                 %d\n",
			     ah_ctx.field.op);
	len += dbg_vsnprintf(buf, len, "ipv4_valid:         %d\n",
			     ah_ctx.field.ipv4_valid);
	len += dbg_vsnprintf(buf, len, "insert_vlan_tag:    %d\n",
			     ah_ctx.field.insert_vlan_tag);
	len += dbg_vsnprintf(buf, len, "do_lpbk:            %d\n",
			     ah_ctx.field.do_lpbk);
	len += dbg_vsnprintf(buf, len, "wqe_valid:          %d\n",
			     ah_ctx.field.wqe_valid);
	if (ah_ctx.field.ipv4_valid) {
		src_ip_addr[0]	= htonl(ah_ctx.field.src_ip_addr[0]);
		dest_ip_addr[0] = htonl(ah_ctx.field.dest_ip_addr[0]);
		len += dbg_vsnprintf(buf, len, "dest_ip_addr:       %pI4\n",
				     dest_ip_addr);
		len += dbg_vsnprintf(buf, len, "src_ip_addr:        %pI4\n",
				     src_ip_addr);
	} else {
		sxe2_copy_ip_htonl(src_ip_addr, ah_ctx.field.src_ip_addr);
		sxe2_copy_ip_htonl(dest_ip_addr, ah_ctx.field.dest_ip_addr);
		len += dbg_vsnprintf(buf, len, "dest_ip_addr:       %pI6\n",
				     dest_ip_addr);
		len += dbg_vsnprintf(buf, len, "src_ip_addr:        %pI6\n",
				     src_ip_addr);
	}
	len += dbg_vsnprintf(buf, len,
			     "----------------------------------------\n");

end:
	return len;
}

int sxe2_debugfs_ah_write(struct sxe2_rdma_device *rdma_dev, void *data,
			  enum drv_rdma_dbg_rsc_type type, char *buf)
{
#ifdef SXE2_CFG_DEBUG
	u32 i;
	int ret;
	int argc;
	u64 new_value;
	u32 ah_index;
	union sxe2_hw_ahc ah_ctx;
	char *argv[DEBUG_ARGV_COUNT_MAX] = { 0 };
	struct sxe2_ah *vendor_ah;
	void *va_addr;
	union sxe2_hw_ahc *p_ah_ctx;
	bool find_field = false;

	va_addr	  = NULL;
	vendor_ah = (struct sxe2_ah *)data;
	ah_index  = vendor_ah->ctx_ah.ah_info.field.ah_idx;

	ret = sxe2_rcms_num_to_ctx_va_pointer(rdma_dev, SXE2_RCMS_OBJ_AH,
					      ah_index, &va_addr);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("query ah failed, ret (%d)\n", ret);
		goto end;
	}

	p_ah_ctx = (union sxe2_hw_ahc *)va_addr;
	for (i = 0; i < SXE2_MQ_WQE_SIZE; i++)
		ah_ctx.buf[i] = le64_to_cpu(p_ah_ctx->buf[i]);

	argc = 0;
	memset(argv, 0, sizeof(*argv) * DEBUG_ARGV_COUNT_MAX);
	ret = split_command(buf, &argc, argv);
	if (ret) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("invalid param\n");
		goto end;
	}

	if (argc != DEBUG_PARA_CONT2) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("invalid param nums\n");
		goto end;
	}

	DRV_RDMA_LOG_DEV_DEBUG("argv:%s\n", argv[0]);

	for (i = 0; i < ARRAY_SIZE(ah_fields); i++) {
		if (!strncmp(argv[0], ah_fields[i], strlen(ah_fields[i])) &&
		    (strlen(ah_fields[i]) == strlen(argv[0]))) {
			find_field = true;
			break;
		}
	}

	if (!find_field) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("unsupport change ah field %s.\n",
				     argv[0]);
		goto end;
	}

	ret = kstrtoull(argv[1], 10, &new_value);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("get param value failed, ret (%d)\n", ret);
		goto end;
	}

	DRV_RDMA_LOG_DEV_INFO("modify ah field %s new value %llx\n",
			      ah_fields[i], new_value);

	switch (i) {
	case AH_VLAN_TAG:
		ah_ctx.field.vlan_tag = new_value;
		break;
	case AH_PD_IDX:
		ah_ctx.field.pd_idx = new_value;
		break;
	case AH_FLOW_LABEL:
		ah_ctx.field.flow_label = new_value;
		break;
	default:
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_WARN("invalid index %d, ret %d\n", i, ret);
		goto end;
	}

	ret = sxe2_drv_ah_modify_op(rdma_dev, &ah_ctx);
	if (ret != 0)
		DRV_RDMA_LOG_DEV_ERR("modify ah failed, ret (%d)\n", ret);

end:
	return ret;
#else
	return 0;
#endif
}
#ifdef SXE2_CFG_DEBUG
int sxe2_debbugfs_ah_add(struct sxe2_rdma_device *rdma_dev,
			 struct sxe2_ah *vendor_ah)
{
	int ret = 0;
	int ah_idx;

	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("root dir not exist, ret (%d)\n", ret);
		goto end;
	}

	if (!rdma_dev->hdl->ah_debugfs) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("ah debugfs dir not exist, ret (%d)\n",
				     ret);
		goto end;
	}

	ah_idx = vendor_ah->ctx_ah.ah_info.field.ah_idx;

	vendor_ah->dbg_node = drv_rdma_add_res_tree(
		rdma_dev, SXE2_DBG_RSC_AH, rdma_dev->hdl->ah_debugfs,
		sxe2_debugfs_ah_read, sxe2_debugfs_ah_write, ah_idx, vendor_ah);
	if (!vendor_ah->dbg_node) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("debug res tree add failed ret (%d)\n",
				     ret);
	}
	DRV_RDMA_LOG_DEV_DEBUG(
		"ah debugfs add ah(%p) dbg_node(%p) ah_idx(%u)\n", vendor_ah,
		vendor_ah->dbg_node, ah_idx);

end:
	return ret;
}
void sxe2_debugfs_ah_remove(struct sxe2_rdma_device *rdma_dev,
			    struct sxe2_ah *vendor_ah)
{
	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		DRV_RDMA_LOG_DEV_ERR("root dir not exist\n");
		goto end;
	}

	if (!rdma_dev->hdl->ah_debugfs) {
		DRV_RDMA_LOG_DEV_ERR("ah debugfs dir not exist\n");
		goto end;
	}

	DRV_RDMA_LOG_DEV_DEBUG(
		"ah debugfs del ah(%p) dbg_node(%p) ah_idx(%u)\n", vendor_ah,
		vendor_ah->dbg_node, vendor_ah->ctx_ah.ah_info.field.ah_idx);

	if (vendor_ah->dbg_node) {
		drv_rdma_rm_res_tree(vendor_ah->dbg_node);
		vendor_ah->dbg_node = NULL;
	}

end:
	return;
}
#endif


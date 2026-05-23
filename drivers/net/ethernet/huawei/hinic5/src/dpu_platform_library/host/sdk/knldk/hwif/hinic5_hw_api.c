/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_hw_api.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#include "ossl_knl.h"
#include "hinic5_hw.h"
#include "hinic5_common.h"
#include "hinic5_hwdev.h"
#include "hinic5_api_cmd.h"
#include "hinic5_mgmt.h"
#include "hinic5_hw_api.h"
 #ifndef HTONL
#define HTONL(x) \
	((((x) & 0x000000ff) << 24) \
	| (((x) & 0x0000ff00) << 8) \
	| (((x) & 0x00ff0000) >> 8) \
	| (((x) & 0xff000000) >> 24))
#endif

static void hinic5_sml_ctr_read_build_req(struct chipif_sml_ctr_rd_req *msg,
					  u8 instance_id, u8 op_id,
					  u8 ack, u32 ctr_id)
{
	msg->head.value = 0;
	msg->head.bs.instance = instance_id;
	msg->head.bs.op_id = op_id;
	msg->head.bs.ack = ack;
	msg->head.value = HTONL(msg->head.value);
	msg->ctr_id = ctr_id;
	msg->ctr_id = HTONL(msg->ctr_id);
	msg->initial = 0;
}

static void sml_ctr_htonl_n(u32 *node, u32 len)
{
	u32 i;
	u32 *node_new = node;

	for (i = 0; i < len; i++) {
		*node_new = HTONL(*node_new);
		node_new++;
	}
}

/**
 * hinic5_sm_ctr_rd16 - small single 16 counter read
 * @hwdev: the hardware device
 * @node: the node id
 * @ctr_id: counter id
 * @value: read counter value ptr
 * Return: 0 - success, negative - failure
 **/
int hinic5_sm_ctr_rd16(void *hwdev, u8 node, u8 instance, u32 ctr_id,
		       u16 *value)
{
	struct chipif_sml_ctr_rd_req req;
	union ctr_rd_rsp rsp;
	int ret;

	if (!hwdev || !value)
		return -EFAULT;

	if (!COMM_SUPPORT_API_CHAIN((struct hinic5_hwdev *)hwdev))
		return -EPERM;

	memset(&req, 0, sizeof(req));

	hinic5_sml_ctr_read_build_req(&req, instance, CHIPIF_SM_CTR_OP_READ,
				      CHIPIF_ACK, ctr_id);

	ret = hinic5_api_cmd_read_ack(hwdev, node, (u8 *)&req,
				      (unsigned short)sizeof(req),
				      (void *)&rsp,
				      (unsigned short)sizeof(rsp));
	if (ret != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Sm 16bit counter read fail, err(%d)\n", ret);
		return ret;
	}
	sml_ctr_htonl_n((u32 *)(void *)&rsp, sizeof(rsp) / sizeof(u32));
	*value = rsp.bs_ss16_rsp.value1;

	return 0;
}

/**
 * hinic5_sm_ctr_rd32 - small single 32 counter read
 * @hwdev: the hardware device
 * @node: the node id
 * @ctr_id: counter id
 * @value: read counter value ptr
 * Return: 0 - success, negative - failure
 **/
int hinic5_sm_ctr_rd32(void *hwdev, u8 node, u8 instance, u32 ctr_id,
		       u32 *value)
{
	struct chipif_sml_ctr_rd_req req;
	union ctr_rd_rsp rsp;
	int ret;

	if (!hwdev || !value)
		return -EFAULT;

	if (!COMM_SUPPORT_API_CHAIN((struct hinic5_hwdev *)hwdev))
		return -EPERM;

	memset(&req, 0, sizeof(req));

	hinic5_sml_ctr_read_build_req(&req, instance, CHIPIF_SM_CTR_OP_READ,
				      CHIPIF_ACK, ctr_id);

	ret = hinic5_api_cmd_read_ack(hwdev, node, (u8 *)&req,
				      (unsigned short)sizeof(req),
				      (void *)&rsp,
				      (unsigned short)sizeof(rsp));
	if (ret != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Sm 32bit counter read fail, err(%d)\n", ret);
		return ret;
	}
	sml_ctr_htonl_n((u32 *)(void *)&rsp, sizeof(rsp) / sizeof(u32));
	*value = rsp.bs_ss32_rsp.value1;

	return 0;
}

/**
 * hinic5_sm_ctr_rd32_clear - small single 32 counter read and clear to zero
 * @hwdev: the hardware device
 * @node: the node id
 * @ctr_id: counter id
 * @value: read counter value ptr
 * Return: 0 - success, negative - failure
 * according to ACN error code (ERR_OK, ERR_PARAM, ERR_FAILED...etc)
 **/
int hinic5_sm_ctr_rd32_clear(void *hwdev, u8 node, u8 instance,
			     u32 ctr_id, u32 *value)
{
	struct chipif_sml_ctr_rd_req req;
	union ctr_rd_rsp rsp;
	int ret;

	if (!hwdev || !value)
		return -EFAULT;

	if (!COMM_SUPPORT_API_CHAIN((struct hinic5_hwdev *)hwdev))
		return -EPERM;

	memset(&req, 0, sizeof(req));

	hinic5_sml_ctr_read_build_req(&req, instance,
				      CHIPIF_SM_CTR_OP_READ_CLEAR,
				      CHIPIF_ACK, ctr_id);

	ret = hinic5_api_cmd_read_ack(hwdev, node, (u8 *)&req,
				      (unsigned short)sizeof(req),
				      (void *)&rsp,
				      (unsigned short)sizeof(rsp));
	if (ret != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Sm 32bit counter clear fail, err(%d)\n", ret);
		return ret;
	}
	sml_ctr_htonl_n((u32 *)(void *)&rsp, sizeof(rsp) / sizeof(u32));
	*value = rsp.bs_ss32_rsp.value1;

	return 0;
}

/**
 * hinic5_sm_ctr_rd64_pair - big pair 128 counter read
 * @hwdev: the hardware device
 * @node: the node id
 * @ctr_id: counter id
 * @value1: read counter value ptr
 * @value2: read counter value ptr
 * Return: 0 - success, negative - failure
 **/
int hinic5_sm_ctr_rd64_pair(void *hwdev, u8 node, u8 instance,
			    u32 ctr_id, u64 *value1, u64 *value2)
{
	struct chipif_sml_ctr_rd_req req;
	union ctr_rd_rsp rsp;
	int ret;

	if (!value1) {
		pr_err("First value is NULL for read 64 bit pair\n");
		return -EFAULT;
	}

	if (!value2) {
		pr_err("Second value is NULL for read 64 bit pair\n");
		return -EFAULT;
	}

	if (!hwdev || ((ctr_id & 0x1) != 0)) {
		pr_err("Hwdev is NULL or ctr_id(%u) is odd number for read 64 bit pair\n",
		       ctr_id);
		return -EFAULT;
	}

	if (!COMM_SUPPORT_API_CHAIN((struct hinic5_hwdev *)hwdev))
		return -EPERM;

	memset(&req, 0, sizeof(req));

	hinic5_sml_ctr_read_build_req(&req, instance, CHIPIF_SM_CTR_OP_READ,
				      CHIPIF_ACK, ctr_id);

	ret = hinic5_api_cmd_read_ack(hwdev, node, (u8 *)&req,
				      (unsigned short)sizeof(req), (void *)&rsp,
				      (unsigned short)sizeof(rsp));
	if (ret != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Sm 64 bit rd pair ret(%d)\n", ret);
		return ret;
	}
	sml_ctr_htonl_n((u32 *)(void *)&rsp, sizeof(rsp) / sizeof(u32));
	*value1 = ((u64)rsp.bs_bp64_rsp.val1_h << BIT_32) | rsp.bs_bp64_rsp.val1_l;
	*value2 = ((u64)rsp.bs_bp64_rsp.val2_h << BIT_32) | rsp.bs_bp64_rsp.val2_l;

	return 0;
}

/**
 * hinic5_sm_ctr_rd64_pair_clear - big pair 128 counter read and clear to zero
 * @hwdev: the hardware device
 * @node: the node id
 * @ctr_id: counter id
 * @value1: read counter value ptr
 * @value2: read counter value ptr
 * Return: 0 - success, negative - failure
 **/
int hinic5_sm_ctr_rd64_pair_clear(void *hwdev, u8 node, u8 instance, u32 ctr_id,
				  u64 *value1, u64 *value2)
{
	struct chipif_sml_ctr_rd_req req = {0};
	union ctr_rd_rsp rsp;
	int ret;

	if (!hwdev || !value1 || !value2 || ((ctr_id & 0x1) != 0)) {
		pr_err("Hwdev or value1 or value2 is NULL or ctr_id(%u) is odd number\n", ctr_id);
		return -EINVAL;
	}

	if (!COMM_SUPPORT_API_CHAIN((struct hinic5_hwdev *)hwdev))
		return -EPERM;

	hinic5_sml_ctr_read_build_req(&req, instance,
				      CHIPIF_SM_CTR_OP_READ_CLEAR,
				      CHIPIF_ACK, ctr_id);

	ret = hinic5_api_cmd_read_ack(hwdev, node, (u8 *)&req,
				      (unsigned short)sizeof(req), (void *)&rsp,
				      (unsigned short)sizeof(rsp));
	if (ret != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Sm 64 bit clear pair fail. ret(%d)\n", ret);
		return ret;
	}
	sml_ctr_htonl_n((u32 *)(void *)&rsp, sizeof(rsp) / sizeof(u32));
	*value1 = ((u64)rsp.bs_bp64_rsp.val1_h << BIT_32) | rsp.bs_bp64_rsp.val1_l;
	*value2 = ((u64)rsp.bs_bp64_rsp.val2_h << BIT_32) | rsp.bs_bp64_rsp.val2_l;

	return 0;
}

/**
 * hinic5_sm_ctr_rd64 - big counter 64 read
 * @hwdev: the hardware device
 * @node: the node id
 * @ctr_id: counter id
 * @value: read counter value ptr
 * Return: 0 - success, negative - failure
 **/
int hinic5_sm_ctr_rd64(void *hwdev, u8 node, u8 instance, u32 ctr_id,
		       u64 *value)
{
	struct chipif_sml_ctr_rd_req req;
	union ctr_rd_rsp rsp;
	int ret;

	if (!hwdev || !value)
		return -EFAULT;

	if (!COMM_SUPPORT_API_CHAIN((struct hinic5_hwdev *)hwdev))
		return -EPERM;

	memset(&req, 0, sizeof(req));

	hinic5_sml_ctr_read_build_req(&req, instance, CHIPIF_SM_CTR_OP_READ,
				      CHIPIF_ACK, ctr_id);

	ret = hinic5_api_cmd_read_ack(hwdev, node, (u8 *)&req,
				      (unsigned short)sizeof(req), (void *)&rsp,
				      (unsigned short)sizeof(rsp));
	if (ret != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Sm 64bit counter read fail err(%d)\n", ret);
		return ret;
	}
	sml_ctr_htonl_n((u32 *)(void *)&rsp, sizeof(rsp) / sizeof(u32));
	*value = ((u64)rsp.bs_bs64_rsp.value1 << BIT_32) | rsp.bs_bs64_rsp.value2;

	return 0;
}
EXPORT_SYMBOL(hinic5_sm_ctr_rd64);

/**
 * hinic5_sm_ctr_rd64_clear - big counter 64 read and clear to zero
 * @hwdev: the hardware device
 * @node: the node id
 * @ctr_id: counter id
 * @value: read counter value ptr
 * Return: 0 - success, negative - failure
 **/
int hinic5_sm_ctr_rd64_clear(void *hwdev, u8 node, u8 instance, u32 ctr_id,
			     u64 *value)
{
	struct chipif_sml_ctr_rd_req req = {0};
	union ctr_rd_rsp rsp;
	int ret;

	if (!hwdev || !value)
		return -EINVAL;

	if (!COMM_SUPPORT_API_CHAIN((struct hinic5_hwdev *)hwdev))
		return -EPERM;

	hinic5_sml_ctr_read_build_req(&req, instance,
				      CHIPIF_SM_CTR_OP_READ_CLEAR,
				      CHIPIF_ACK, ctr_id);

	ret = hinic5_api_cmd_read_ack(hwdev, node, (u8 *)&req,
				      (unsigned short)sizeof(req), (void *)&rsp,
				      (unsigned short)sizeof(rsp));
	if (ret != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Sm 64bit counter clear fail err(%d)\n", ret);
		return ret;
	}
	sml_ctr_htonl_n((u32 *)(void *)&rsp, sizeof(rsp) / sizeof(u32));
	*value = ((u64)rsp.bs_bs64_rsp.value1 << BIT_32) | rsp.bs_bs64_rsp.value2;

	return 0;
}

int hinic5_api_csr_rd32(void *hwdev, u8 dest, u32 addr, u32 *val)
{
	struct hinic5_csr_request_api_data api_data = {0};
	u32 csr_val = 0;
	u16 in_size = sizeof(api_data);
	int ret;

	if (!hwdev || !val)
		return -EFAULT;

	if (!COMM_SUPPORT_API_CHAIN((struct hinic5_hwdev *)hwdev))
		return -EPERM;

	memset(&api_data, 0, sizeof(struct hinic5_csr_request_api_data));
	api_data.dw0 = 0;
	api_data.dw1.bits.operation_id = HINIC5_CSR_OPERATION_READ_CSR;
	api_data.dw1.bits.need_response = HINIC5_CSR_NEED_RESP_DATA;
	api_data.dw1.bits.data_size = HINIC5_CSR_DATA_SZ_32;
	api_data.dw1.val32 = cpu_to_be32(api_data.dw1.val32);
	api_data.dw2.bits.csr_addr = addr;
	api_data.dw2.val32 = cpu_to_be32(api_data.dw2.val32);

	ret = hinic5_api_cmd_read_ack(hwdev, dest, (u8 *)(&api_data),
				      in_size, &csr_val, 0x4);
	if (ret != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Read 32 bit csr fail, dest %u addr 0x%x, ret: 0x%x\n",
			dest, addr, ret);
		return ret;
	}

	*val = csr_val;

	return 0;
}

int hinic5_api_csr_wr32(void *hwdev, u8 dest, u32 addr, u32 val)
{
	struct hinic5_csr_request_api_data api_data;
	u16 in_size = sizeof(api_data);
	int ret;

	if (!hwdev)
		return -EFAULT;

	if (!COMM_SUPPORT_API_CHAIN((struct hinic5_hwdev *)hwdev))
		return -EPERM;

	memset(&api_data, 0, sizeof(struct hinic5_csr_request_api_data));
	api_data.dw1.bits.operation_id = HINIC5_CSR_OPERATION_WRITE_CSR;
	api_data.dw1.bits.need_response = HINIC5_CSR_NO_RESP_DATA;
	api_data.dw1.bits.data_size = HINIC5_CSR_DATA_SZ_32;
	api_data.dw1.val32 = cpu_to_be32(api_data.dw1.val32);
	api_data.dw2.bits.csr_addr = addr;
	api_data.dw2.val32 = cpu_to_be32(api_data.dw2.val32);
	api_data.csr_write_data_h = 0xffffffff;
	api_data.csr_write_data_l = val;

	ret = hinic5_api_cmd_write_nack(hwdev, dest, (u8 *)(&api_data),
					in_size);
	if (ret != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Write 32 bit csr fail! dest %u addr 0x%x val 0x%x\n",
			dest, addr, val);
		return ret;
	}

	return 0;
}

int hinic5_api_csr_rd64(void *hwdev, u8 dest, u32 addr, u64 *val)
{
	struct hinic5_csr_request_api_data api_data = {0};
	u64 csr_val = 0;
	u16 in_size = sizeof(api_data);
	int ret;

	if (!hwdev || !val)
		return -EFAULT;

	if (!COMM_SUPPORT_API_CHAIN((struct hinic5_hwdev *)hwdev))
		return -EPERM;

	memset(&api_data, 0, sizeof(struct hinic5_csr_request_api_data));
	api_data.dw0 = 0;
	api_data.dw1.bits.operation_id = HINIC5_CSR_OPERATION_READ_CSR;
	api_data.dw1.bits.need_response = HINIC5_CSR_NEED_RESP_DATA;
	api_data.dw1.bits.data_size = HINIC5_CSR_DATA_SZ_64;
	api_data.dw1.val32 = cpu_to_be32(api_data.dw1.val32);
	api_data.dw2.bits.csr_addr = addr;
	api_data.dw2.val32 = cpu_to_be32(api_data.dw2.val32);

	ret = hinic5_api_cmd_read_ack(hwdev, dest, (u8 *)(&api_data),
				      in_size, &csr_val, 0x8);
	if (ret != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Read 64 bit csr fail, dest %u addr 0x%x\n",
			dest, addr);
		return ret;
	}

	*val = csr_val;

	return 0;
}
EXPORT_SYMBOL(hinic5_api_csr_rd64);


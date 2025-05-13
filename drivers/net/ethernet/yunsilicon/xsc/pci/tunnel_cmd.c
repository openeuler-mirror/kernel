// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2024, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "common/xsc_core.h"
#include "common/xsc_ioctl.h"
#include "common/xsc_hsi.h"
#include "common/xsc_port_ctrl.h"
#include "common/tunnel_cmd.h"
#include <linux/pci.h>
#include <linux/kernel.h>
#include <linux/namei.h>
#include <linux/kobject.h>
#include <linux/kernfs.h>

static DEFINE_MUTEX(tunnel_cmd_lock);

void xsc_tunnel_cmd_recv_resp(struct xsc_core_device *xdev)
{
	xsc_core_info(xdev, "recv tunnel cmd response, wake up tunnel cmd exec.\n");
	complete(&xdev->recv_tunnel_resp_event);
}

int xsc_tunnel_cmd_exec(struct xsc_core_device *xdev, void *in, int inlen, void *out, int outlen,
			struct xsc_ioctl_tunnel_hdr *hdr)
{
	struct xsc_send_tunnel_cmd_req_mbox_in *tunnel_req_in;
	struct xsc_send_tunnel_cmd_req_mbox_out tunnel_req_out;
	struct xsc_recv_tunnel_cmd_resp_mbox_in tunnel_resp_in;
	struct xsc_recv_tunnel_cmd_resp_mbox_out *tunnel_resp_out;
	int tunnel_req_inlen;
	int tunnel_resp_outlen;
	int ret = 0;
	unsigned long timeout = msecs_to_jiffies(1000);

	mutex_lock(&tunnel_cmd_lock);
	tunnel_req_inlen = inlen + sizeof(*tunnel_req_in);
	tunnel_resp_outlen = outlen + sizeof(*tunnel_resp_out);

	tunnel_req_in = kzalloc(tunnel_req_inlen, GFP_KERNEL);
	if (!tunnel_req_in) {
		ret = -ENOMEM;
		goto err_alloc_req;
	}

	tunnel_resp_out = kzalloc(tunnel_resp_outlen, GFP_KERNEL);
	if (!tunnel_resp_out) {
		ret = -ENOMEM;
		goto err_alloc_resp;
	}

	tunnel_req_in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_SEND_TUNNEL_CMD_REQ);
	tunnel_req_in->target.domain = cpu_to_be32(hdr->domain);
	tunnel_req_in->target.bus = cpu_to_be32(hdr->bus);
	tunnel_req_in->target.devfn = cpu_to_be32(hdr->devfn);
	tunnel_req_in->target.data_length = cpu_to_be32(inlen);
	memcpy(tunnel_req_in->data, in, inlen);
	ret = xsc_cmd_exec(xdev, tunnel_req_in, tunnel_req_inlen,
			   &tunnel_req_out, sizeof(tunnel_req_out));
	if (ret) {
		xsc_core_err(xdev, "send tunnel cmd request failed, ret %d\n", ret);
		goto err_send_req;
	}
	if (tunnel_req_out.hdr.status) {
		xsc_core_err(xdev, "send tunnel cmd requset failed, req out status %d\n",
			     tunnel_req_out.hdr.status);
		ret = xsc_cmd_status_to_err(&tunnel_req_out.hdr);
		goto err_send_req;
	}

	init_completion(&xdev->recv_tunnel_resp_event);
	ret = wait_for_completion_timeout(&xdev->recv_tunnel_resp_event, timeout);
	if (!ret) {
		ret = -ETIMEDOUT;
		goto err_send_req;
	}

	memset(&tunnel_resp_in, 0, sizeof(tunnel_resp_in));
	tunnel_resp_in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_RECV_TUNNEL_CMD_RESP);
	ret = xsc_cmd_exec(xdev, &tunnel_resp_in, sizeof(tunnel_resp_in),
			   tunnel_resp_out, tunnel_resp_outlen);
	if (ret) {
		xsc_core_err(xdev, "recv tunnel cmd response failed, ret %d\n", ret);
		goto err_recv_resp;
	}
	if (tunnel_resp_out->hdr.status) {
		xsc_core_err(xdev, "recv tunnel cmd response failed, rsp out status %d\n",
			     tunnel_resp_out->hdr.status);
		ret = xsc_cmd_status_to_err(&tunnel_resp_out->hdr);
		goto err_recv_resp;
	}
	memcpy(out, tunnel_resp_out->data, outlen);
err_recv_resp:
err_send_req:
	kfree(tunnel_resp_out);
err_alloc_resp:
	kfree(tunnel_req_in);
err_alloc_req:
	mutex_unlock(&tunnel_cmd_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(xsc_tunnel_cmd_exec);

static void xsc_read_hw_counter(char *file_fn, char *buf, size_t count)
{
	struct file *filp;
	loff_t pos = 0;

	filp = filp_open(file_fn, O_RDONLY, 0);
	if (!filp)
		return;
	kernel_read(filp, buf, count, &pos);
}

#define	ITEM_VALUE_LEN	16
static void xsc_ioctl_get_hw_counters(struct xsc_core_device *xdev, void *indata, void *outdata)
{
	struct xsc_cmd_ioctl_get_hw_counters_mbox_in *in = indata;
	struct xsc_cmd_ioctl_get_hw_counters_mbox_out *out = outdata;
	char dev[8] = {0};
	char path[128] = {0};
	int offset = 0;
	int end = be32_to_cpu(in->length);

	memcpy(dev, in->data, 8);
	offset += 8;

	while (offset < end) {
		int item_key_len = *(u32 *)(&in->data[offset]);

		offset += sizeof(int);
		sprintf(path, "/sys/class/infiniband/%s/ports/1/hw_counters/%s",
			dev, (char *)(&in->data[offset]));
		offset += item_key_len + 1;
		xsc_read_hw_counter(path, &in->data[offset], ITEM_VALUE_LEN);
		offset += ITEM_VALUE_LEN;
	}
	memcpy(out->data, in->data, end);
	out->hdr.status = 0;
}

int xsc_tunnel_cmd_recv_req(struct xsc_core_device *xdev)
{
	struct xsc_recv_tunnel_cmd_req_mbox_in req_in;
	struct xsc_recv_tunnel_cmd_req_mbox_out *req_out;
	struct xsc_send_tunnel_cmd_resp_mbox_in *resp_in;
	struct xsc_send_tunnel_cmd_resp_mbox_out resp_out;
	struct xsc_inbox_hdr *hdr;
	int ret = 0;
	u16 opcode;
	u32 domain;
	u32 bus;
	u32 devfn;
	struct xsc_core_device *target_xdev;
	int inlen;
	int outlen;
	u16 ioctl_opcode;
	struct xsc_cmd_get_ioctl_info_mbox_in *in;
	struct xsc_cmd_get_ioctl_info_mbox_out *out;
	struct xsc_qos_mbox_in *qos_in;
	struct xsc_hw_stats_mbox_in *stat_in;
	struct xsc_prio_stats_mbox_in *prio_in;
	struct xsc_pfc_prio_stats_mbox_in *pfc_in;

	xsc_core_info(xdev, "recv tunnel cmd req, process and send response.\n");

	req_out = kzalloc(xdev->caps.max_cmd_out_len, GFP_KERNEL);
	if (!req_out) {
		ret = -ENOMEM;
		goto err_alloc_req;
	}
	resp_in = kzalloc(xdev->caps.max_cmd_out_len, GFP_KERNEL);
	if (!resp_in) {
		ret = -ENOMEM;
		goto err_alloc_resp;
	}

	memset(&req_in, 0, sizeof(req_in));
	req_in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_RECV_TUNNEL_CMD_REQ);
	ret = xsc_cmd_exec(xdev, &req_in, sizeof(req_in), req_out, xdev->caps.max_cmd_out_len);
	if (ret) {
		xsc_core_err(xdev, "recv tunnel cmd request failed, ret %d\n", ret);
		goto err_recv_req;
	}
	if (req_out->hdr.status) {
		xsc_core_err(xdev, "recv tunnel cmd request failed, req out status %d\n",
			     req_out->hdr.status);
		ret = xsc_cmd_status_to_err(&req_out->hdr);
		goto err_recv_req;
	}

	domain = be32_to_cpu(req_out->target.domain);
	bus = be32_to_cpu(req_out->target.bus);
	devfn = be32_to_cpu(req_out->target.devfn);
	if (!domain && !bus && !devfn) {
		target_xdev = xdev;
	} else {
		target_xdev = xsc_pci_get_xdev_by_bus_and_slot(domain, bus, devfn);
		if (!target_xdev)
			goto err_recv_req;
	}

	hdr = (struct xsc_inbox_hdr *)req_out->data;
	opcode = be16_to_cpu(hdr->opcode);
	switch (opcode) {
	case XSC_CMD_OP_GET_IOCTL_INFO:
		in = (struct xsc_cmd_get_ioctl_info_mbox_in *)req_out->data;
		ioctl_opcode = be16_to_cpu(in->ioctl_opcode);
		switch (ioctl_opcode) {
		case XSC_IOCTL_GET_DEVINFO:
			xsc_get_devinfo(resp_in->data,
					xdev->caps.max_cmd_in_len - sizeof(struct xsc_inbox_hdr));
			break;
		case XSC_IOCTL_GET_FORCE_PCP:
		case XSC_IOCTL_GET_FORCE_DSCP:
		case XSC_IOCTL_SET_FORCE_PCP:
		case XSC_IOCTL_SET_FORCE_DSCP:
		case XSC_IOCTL_GET_CMA_PCP:
		case XSC_IOCTL_GET_CMA_DSCP:
		case XSC_IOCTL_SET_CMA_PCP:
		case XSC_IOCTL_SET_CMA_DSCP:
			inlen = be16_to_cpu(in->length);
			target_xdev->get_rdma_ctrl_info(target_xdev, ioctl_opcode, in->data, inlen);
			out = (struct xsc_cmd_get_ioctl_info_mbox_out *)resp_in->data;
			memcpy(out->data, in->data, inlen);
			out->hdr.status = 0;
			break;
		default:
			ret = -EOPNOTSUPP;
			goto err_process_cmd;
		}
		goto send_resp;
	case XSC_CMD_OP_IOCTL_NETLINK:
		target_xdev->handle_netlink_cmd(target_xdev, req_out->data, resp_in->data);
		goto send_resp;
	case XSC_CMD_OP_IOCTL_GET_HW_COUNTERS:
		xsc_ioctl_get_hw_counters(target_xdev, req_out->data, resp_in->data);
		goto send_resp;
	case XSC_CMD_OP_QUERY_HW_STATS_RDMA:
		stat_in = (struct xsc_hw_stats_mbox_in *)req_out->data;
		stat_in->mac_port = target_xdev->mac_port;
		break;
	case XSC_CMD_OP_QUERY_PRIO_STATS:
		prio_in = (struct xsc_prio_stats_mbox_in *)req_out->data;
		prio_in->pport = target_xdev->mac_port;
		break;
	case XSC_CMD_OP_QUERY_PFC_PRIO_STATS:
		pfc_in = (struct xsc_pfc_prio_stats_mbox_in *)req_out->data;
		pfc_in->pport = target_xdev->mac_port;
		break;
	case XSC_CMD_OP_IOCTL_SET_DSCP_PMT:
	case XSC_CMD_OP_IOCTL_GET_DSCP_PMT:
	case XSC_CMD_OP_IOCTL_SET_TRUST_MODE:
	case XSC_CMD_OP_IOCTL_GET_TRUST_MODE:
	case XSC_CMD_OP_IOCTL_SET_PCP_PMT:
	case XSC_CMD_OP_IOCTL_GET_PCP_PMT:
	case XSC_CMD_OP_IOCTL_SET_DEFAULT_PRI:
	case XSC_CMD_OP_IOCTL_GET_DEFAULT_PRI:
	case XSC_CMD_OP_IOCTL_SET_PFC:
	case XSC_CMD_OP_IOCTL_SET_PFC_NEW:
	case XSC_CMD_OP_IOCTL_GET_PFC:
	case XSC_CMD_OP_IOCTL_SET_RATE_LIMIT:
	case XSC_CMD_OP_IOCTL_GET_RATE_LIMIT:
	case XSC_CMD_OP_IOCTL_SET_SP:
	case XSC_CMD_OP_IOCTL_GET_SP:
	case XSC_CMD_OP_IOCTL_SET_WEIGHT:
	case XSC_CMD_OP_IOCTL_GET_WEIGHT:
	case XSC_CMD_OP_IOCTL_DPU_SET_PORT_WEIGHT:
	case XSC_CMD_OP_IOCTL_DPU_GET_PORT_WEIGHT:
	case XSC_CMD_OP_IOCTL_DPU_SET_PRIO_WEIGHT:
	case XSC_CMD_OP_IOCTL_DPU_GET_PRIO_WEIGHT:
	case XSC_CMD_OP_IOCTL_SET_WATCHDOG_EN:
	case XSC_CMD_OP_IOCTL_GET_WATCHDOG_EN:
	case XSC_CMD_OP_IOCTL_SET_WATCHDOG_PERIOD:
	case XSC_CMD_OP_IOCTL_GET_WATCHDOG_PERIOD:
		qos_in = (struct xsc_qos_mbox_in *)req_out->data;
		qos_in->req_prfx.mac_port = target_xdev->mac_port;
		break;
	default:
		break;
	}

	inlen = be32_to_cpu(req_out->target.data_length);
	outlen = xdev->caps.max_cmd_out_len - sizeof(struct xsc_inbox_hdr);
	ret = xsc_cmd_exec(target_xdev, req_out->data, inlen, resp_in->data, outlen);
	if (ret) {
		xsc_core_err(xdev, "exec cmd on host failed, opcode %d, ret %d\n", opcode, ret);
		goto err_process_cmd;
	}

send_resp:
	resp_in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_SEND_TUNNEL_CMD_RESP);
	ret = xsc_cmd_exec(xdev, resp_in, xdev->caps.max_cmd_out_len, &resp_out, sizeof(resp_out));
	if (ret)
		goto err_send_resp;
	if (resp_out.hdr.status) {
		ret = xsc_cmd_status_to_err(&resp_out.hdr);
		goto err_send_resp;
	}

err_process_cmd:
err_send_resp:
err_recv_req:
	kfree(resp_in);
err_alloc_resp:
	kfree(req_out);
err_alloc_req:
	return ret;
}

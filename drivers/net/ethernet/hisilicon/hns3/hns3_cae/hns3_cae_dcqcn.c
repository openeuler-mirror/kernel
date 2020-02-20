// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kthread.h>

#include "hns3_enet.h"
#include "hclge_cmd.h"
#include "hclge_main.h"
#include "hns3_cae_cmd.h"
#include "hns3_cae_dcqcn.h"

static int hns3_dcqcn_rw(const struct hns3_nic_priv *net_priv,
			 u32 offset, u32 *data, u32 rw_type)
{
	struct hnae3_handle *h = net_priv->ae_handle;
	struct hclge_vport *vport = NULL;
	struct hclge_dev *hdev = NULL;
	struct hclge_desc desc;
	int ret;

	if (!data)
		return -EFAULT;

	vport = container_of(h, struct hclge_vport, nic);
	hdev = vport->back;

	if (rw_type == DEVMEM_CFG_READ) {
		hns3_cae_cmd_setup_basic_desc(&desc,
					      HCLGE_OPC_DCQCN_TEMPLATE_CFG,
					      true);
	} else {
		hns3_cae_cmd_setup_basic_desc(&desc,
					      HCLGE_OPC_DCQCN_TEMPLATE_CFG,
					      false);
		desc.data[2] = *data;
	}

	desc.data[0] = SCC_TEMP_LOW_ADDR + offset;
	desc.data[1] = SCC_TEMP_HIGH_ADDR;
	desc.data[4] = 32;

	ret = hns3_cae_cmd_send(hdev, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "disable net lane failed %d\n", ret);
		return ret;
	}

	if (rw_type == DEVMEM_CFG_READ)
		*data = desc.data[2];

	return 0;
}

int hns3_nic_dcqcn(const struct hns3_nic_priv *net_priv,
		   void *buf_in, u32 in_size, void *buf_out, u32 out_size)
{
#define SCC_TEMP_CFG0 0x6000
#define SCC_TEMP_CFG1 0x6004
#define SCC_TEMP_CFG2 0x6008
#define SCC_TEMP_CFG3 0x600c
	struct hnae3_handle *h = net_priv->ae_handle;
	struct hclge_vport *vport = container_of(h, struct hclge_vport, nic);
	bool check = !buf_in || in_size < sizeof(struct cfg_dcqcn_param);
	struct cfg_dcqcn_param *parm_out = buf_out;
	struct cfg_dcqcn_param *parm_in = buf_in;
	struct cfg_dcqcn_param tempbuffer = {0};
	struct hclge_dev *hdev = vport->back;
	u32 tempoutbuff;
	u32 offset;
	int ret;

	if (check) {
		pr_err("input param buf_in error in %s function\n", __func__);
		return -EFAULT;
	}

	if (!hnae3_dev_roce_supported(hdev)) {
		dev_err(&hdev->pdev->dev, "This device is not support RoCE!\n");
		return -EINVAL;
	}

	tempoutbuff = 0;
	if (parm_in->device_number > 0xff) {
		dev_err(&hdev->pdev->dev,
			"parm_in->device_number=0x%x, max value is 0xff.\n",
			parm_in->device_number);
		return -ENXIO;
	}
	offset = 0x10 * parm_in->device_number + SCC_TEMP_CFG0;
	ret = hns3_dcqcn_rw(net_priv, offset, (u32 *)&tempoutbuff,
			    DEVMEM_CFG_READ);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"read dcqcn cfg 0~31 bit failed 0x%x\n", ret);
		return ret;
	}
	tempbuffer.ai = (tempoutbuff & 0xffff);
	tempbuffer.f = ((tempoutbuff >> 16) & 0xff);
	tempbuffer.tkp = (tempoutbuff >> 24);

	offset = offset + 0x4;
	ret = hns3_dcqcn_rw(net_priv, offset, (u32 *)&tempoutbuff,
			    DEVMEM_CFG_READ);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"read dcqcn cfg 32~63 bit failed ret = 0x%x\n", ret);
		return ret;
	}
	tempbuffer.tmp = (tempoutbuff & 0xffff);
	tempbuffer.alp = (tempoutbuff >> 16);

	offset = offset + 0x4;
	ret = hns3_dcqcn_rw(net_priv, offset, (u32 *)&tempoutbuff,
			    DEVMEM_CFG_READ);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"read dcqcn cfg 64~95 bit failed ret = 0x%x\n", ret);
		return ret;
	}
	tempbuffer.max_speed = tempoutbuff;

	offset = offset + 0x4;
	ret = hns3_dcqcn_rw(net_priv, offset, (u32 *)&tempoutbuff,
			    DEVMEM_CFG_READ);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"read dcqcn cfg 96~127 bit failed ret = 0x%x\n", ret);
		return ret;
	}
	tempbuffer.g = (tempoutbuff & 0xff);
	tempbuffer.al = ((tempoutbuff >> 8) & 0xff);
	tempbuffer.cnp_time = ((tempoutbuff >> 16) & 0xff);
	tempbuffer.alp_shift = ((tempoutbuff >> 24) & 0xff);

	if (parm_in->is_get == HIARM_DCQCN_WRITE_CFG_MODE) {
		if ((parm_in->dcqcn_parm_opcode & 0x1) == 1)
			tempbuffer.ai = parm_in->ai;
		if ((parm_in->dcqcn_parm_opcode & 0x2) == 0x2)
			tempbuffer.f = parm_in->f;
		if ((parm_in->dcqcn_parm_opcode & 0x4) == 0x4)
			tempbuffer.tkp = parm_in->tkp;
		if ((parm_in->dcqcn_parm_opcode & 0x8) == 0x8)
			tempbuffer.tmp = parm_in->tmp;
		if ((parm_in->dcqcn_parm_opcode & 0x10) == 0x10)
			tempbuffer.alp = parm_in->alp;
		if ((parm_in->dcqcn_parm_opcode & 0x20) == 0x20)
			tempbuffer.g = parm_in->g;
		if ((parm_in->dcqcn_parm_opcode & 0x40) == 0x40)
			tempbuffer.al = parm_in->al;
		if ((parm_in->dcqcn_parm_opcode & 0x80) == 0x80)
			tempbuffer.max_speed = parm_in->max_speed;
		if ((parm_in->dcqcn_parm_opcode & 0x100) == 0x100)
			tempbuffer.cnp_time = parm_in->cnp_time;
		if ((parm_in->dcqcn_parm_opcode & 0x200) == 0x200)
			tempbuffer.alp_shift = parm_in->alp_shift;

		ret = hns3_dcqcn_rw(net_priv,
				    0x10 * parm_in->device_number +
				    SCC_TEMP_CFG0,
				    (u32 *)&tempbuffer.ai, DEVMEM_CFG_WRITE);
		if (ret) {
			dev_err(&hdev->pdev->dev,
				"write dcqcn cfg 0~31 bit failed ret = 0x%x\n",
				ret);
			return ret;
		}
		ret = hns3_dcqcn_rw(net_priv,
				    0x10 * parm_in->device_number +
				    SCC_TEMP_CFG1,
				    (u32 *)&tempbuffer.tmp, DEVMEM_CFG_WRITE);
		if (ret) {
			dev_err(&hdev->pdev->dev,
				"write dcqcn cfg 32~63 bit failed ret = 0x%x\n",
				ret);
			return ret;
		}
		ret = hns3_dcqcn_rw(net_priv,
				    0x10 * parm_in->device_number +
				    SCC_TEMP_CFG2,
				    (u32 *)&tempbuffer.max_speed,
				    DEVMEM_CFG_WRITE);
		if (ret) {
			dev_err(&hdev->pdev->dev,
				"write dcqcn cfg 64~95 bit failed ret = 0x%x\n",
				ret);
			return ret;
		}
		ret = hns3_dcqcn_rw(net_priv,
				    0x10 * parm_in->device_number +
				    SCC_TEMP_CFG3,
				    (u32 *)&tempbuffer.g, DEVMEM_CFG_WRITE);
		if (ret) {
			dev_err(&hdev->pdev->dev,
				"write dcqcn cfg 96~127 bit failed ret = 0x%x\n",
				ret);
			return ret;
		}
	} else if (parm_in->is_get == HIARM_DCQCN_READ_CFG_MODE) {
		check = !buf_out || out_size < sizeof(struct cfg_dcqcn_param);
		if (check) {
			pr_err("input param buf_out error in %s function\n",
			       __func__);
			return -EFAULT;
		}
		parm_out->ai = tempbuffer.ai;
		parm_out->f = tempbuffer.f;
		parm_out->tkp = tempbuffer.tkp;
		parm_out->tmp = tempbuffer.tmp;
		parm_out->alp = tempbuffer.alp;
		parm_out->max_speed = tempbuffer.max_speed;
		parm_out->g = tempbuffer.g;
		parm_out->al = tempbuffer.al;
		parm_out->cnp_time = tempbuffer.cnp_time;
		parm_out->alp_shift = tempbuffer.alp_shift;
	} else {
		dev_err(&hdev->pdev->dev,
			"parm->is_get = 0x%x parm is error type\n",
			parm_in->is_get);
	}

	return 0;
}

int hns3_dcqcn_get_msg_cnt(const struct hns3_nic_priv *net_priv,
			   void *buf_in, u32 in_size,
			   void *buf_out, u32 out_size)
{
	struct hnae3_handle *h = net_priv->ae_handle;
	struct hclge_vport *vport = container_of(h, struct hclge_vport, nic);
	struct dcqcn_statistic_param *statistic_parm_out = buf_out;
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc;
	bool check = !buf_out ||
		     out_size < sizeof(struct dcqcn_statistic_param);
	int ret;

	if (check) {
		pr_err("input param buf_out error in %s function\n", __func__);
		return -EFAULT;
	}

	hns3_cae_cmd_setup_basic_desc(&desc, HCLGE_OPC_DCQCN_GET_MSG_CNT, true);

	ret = hns3_cae_cmd_send(hdev, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "disable net lane failed %d\n", ret);
		return ret;
	}

	statistic_parm_out->dcqcn_rx_cnt = desc.data[0];
	statistic_parm_out->dcqcn_tx_cnt = desc.data[2];
	statistic_parm_out->dcqcn_db_cnt = desc.data[4];

	return 0;
}

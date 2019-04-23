// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/dma-mapping.h>
#include <linux/etherdevice.h>
#include <linux/interrupt.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/skbuff.h>
#include <linux/sctp.h>
#include <linux/vermagic.h>
#include <net/gre.h>
#include <net/pkt_cls.h>
#include <net/vxlan.h>
#include "../../hns3pf/hclge_main.h"
#include "../../hnae3.h"
#include "../../hns3pf/hclge_cmd.h"
#include "hclge_ext.h"

void hclge_clean_stats64(struct hnae3_handle *handle)
{
	struct hnae3_knic_private_info *kinfo;
	struct hclge_vport *vport;
	struct hclge_dev *hdev;
	struct hclge_tqp *tqp;
	int i;

	kinfo = &handle->kinfo;
	vport = hclge_get_vport(handle);
	hdev = vport->back;

	for (i = 0; i < kinfo->num_tqps; i++) {
		tqp = container_of(kinfo->tqp[i], struct hclge_tqp, q);
		memset(&tqp->tqp_stats, 0, sizeof(struct hlcge_tqp_stats));
	}
	memset(&hdev->hw_stats.mac_stats, 0, sizeof(struct hclge_mac_stats));
}
EXPORT_SYMBOL(hclge_clean_stats64);

int hclge_get_chipid(struct hnae3_handle *handle, u32 *chip_id)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	struct hclge_chip_id_cmd *resp = NULL;
	struct hclge_desc desc;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_CHIP_ID_GET, true);
	resp = (struct hclge_chip_id_cmd *)(desc.data);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "get chip id failed %d\n", ret);
		return ret;
	}
	*chip_id = resp->chip_id;
	return 0;
}
EXPORT_SYMBOL(hclge_get_chipid);

int hclge_get_commit_id(struct hnae3_handle *handle, u8 *commit_id,
			u32 *ncl_version)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	struct hclge_commit_id_cmd *resp = NULL;
	struct hclge_desc desc;
	int ret, i;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_IMP_COMMIT_ID_GET, true);
	resp = (struct hclge_commit_id_cmd *)(desc.data);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "get commit id failed %d\n", ret);
		return ret;
	}

	for (i = 0; i < 8; i++)
		commit_id[i] = resp->commit_id[i];

	commit_id[8] = '\0';
	*ncl_version = resp->ncl_version;

	return 0;
}
EXPORT_SYMBOL(hclge_get_commit_id);

static int _hclge_get_sfpinfo(struct hnae3_handle *handle, u8 *buff,
			      u16 offset, u16 size, u16 *outlen)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_desc desc[HCLGE_SFP_INFO_LEN];
	struct hclge_dev *hdev = vport->back;
	struct hclge_sfp_info *resp = NULL;
	int ret;
	int i;
	int j;

	for (i = 0; i < HCLGE_SFP_INFO_LEN; i++) {
		hclge_cmd_setup_basic_desc(&desc[i],
					   HCLGE_OPC_SFP_GET_INFO, true);
		if (i == 0)
			desc[0].data[0] = offset | (size << 16);
		if (i < HCLGE_SFP_INFO_LEN - 1)
			desc[i].flag |= cpu_to_le16(HCLGE_CMD_FLAG_NEXT);
		else
			desc[i].flag &= ~(cpu_to_le16(HCLGE_CMD_FLAG_NEXT));
	}

	ret = hclge_cmd_send(&hdev->hw, desc, HCLGE_SFP_INFO_LEN);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"get spf information cmd failed %d\n",
			ret);
		return ret;
	}

	for (i = 0; i < HCLGE_SFP_INFO_LEN; i++) {
		resp = (struct hclge_sfp_info *)desc[i].data;
		if (i == 0) {
			*outlen = (resp[i].sfpinfo[0] >> 16) & 0xFFFF;
			for (j = 1; j < 6; j++) {
				*(u32 *)buff = resp->sfpinfo[j];
				buff = buff + sizeof(u32);
			}
		} else {
			for (j = 0; j < 6; j++) {
				*(u32 *)buff = resp->sfpinfo[j];
				buff = buff + sizeof(u32);
			}
		}
	}
	return 0;
}

int hclge_get_sfpinfo(struct hnae3_handle *handle, u8 *buff, u16 offset,
		      u16 size, u16 *outlen)
{
	u16 tmp_size;
	u8 *tmp_buff;
	u16 tmp_outlen;
	int ret;

	tmp_buff = buff;
	while (size) {
		WARN_ON_ONCE(!tmp_buff);
		if (size > HCLGE_SFP_INFO_SIZE)
			tmp_size = HCLGE_SFP_INFO_SIZE;
		else
			tmp_size = size;
		ret = _hclge_get_sfpinfo(handle, tmp_buff, offset, tmp_size,
					 &tmp_outlen);
		if (ret)
			return ret;
		offset += tmp_size;
		size -= tmp_size;
		tmp_buff += tmp_size;
		*outlen += tmp_outlen;
		if (tmp_size != tmp_outlen)
			break;
	}
	return 0;
}
EXPORT_SYMBOL(hclge_get_sfpinfo);

int hclge_set_sfp_state(struct hnae3_handle *handle, bool en)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_sfp_enable_cmd *req = NULL;
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_SFP_SET_STATUS, false);
	req = (struct hclge_sfp_enable_cmd *)desc.data;
	req->set_sfp_enable_flag = en;

	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret)
		dev_err(&hdev->pdev->dev,
			"set spf on/off cmd failed %d\n", ret);

	return ret;
}
EXPORT_SYMBOL(hclge_set_sfp_state);

int hclge_get_chip_num(struct hnae3_handle *handle, u32 *chip_num)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_GET_CHIP_NUM, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "get chip number failed %d\n", ret);
		return ret;
	}
	*chip_num = desc.data[0];
	return 0;
}
EXPORT_SYMBOL(hclge_get_chip_num);

int hclge_ext_get_sfp_speed(struct hnae3_handle *handle, u32 *speed)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc;
	int ret = 0;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_GET_SFP_INFO, true);

	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret == -EOPNOTSUPP) {
		dev_warn(&hdev->pdev->dev,
			 "IMP do not support get SFP speed %d\n", ret);
		return ret;
	} else if (ret) {
		dev_err(&hdev->pdev->dev, "get sfp speed failed %d\n", ret);
		return ret;
	}

	*speed = desc.data[0];

	return 0;
}
EXPORT_SYMBOL(hclge_ext_get_sfp_speed);

int hclge_get_port_num(struct hnae3_handle *handle, u32 *port_num)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_GET_PORT_NUM, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "get port number failed %d\n", ret);
		return ret;
	}
	*port_num = desc.data[0];
	return 0;
}
EXPORT_SYMBOL(hclge_get_port_num);

int hclge_set_led(struct hnae3_handle *handle, u32 type, u32 status)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_SET_LED, false);
	desc.data[0] = type;
	desc.data[1] = status;
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "get set led failed %d\n", ret);
		return ret;
	}

	return 0;
}
EXPORT_SYMBOL(hclge_set_led);

int hclge_get_led_signal(struct hnae3_handle *handle,
			 struct hns3_lamp_signal *signal)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_SET_LED, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"hclge_get_sgpio_tx_reg failed %d\n", ret);
		return ret;
	}

	signal->error = desc.data[2] & 0xFF;
	signal->locate = (desc.data[2] >> 8) & 0xFF;
	signal->activity = (desc.data[2] >> 16) & 0xFF;

	return 0;
}
EXPORT_SYMBOL(hclge_get_led_signal);

int hclge_get_sfp_present(struct hnae3_handle *handle, u32 *present)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_sfp_present_cmd *resp = NULL;
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc;
	int ret = 0;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_SFP_GET_PRESENT, true);
	resp = (struct hclge_sfp_present_cmd *)desc.data;
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "get spf present failed %d\n", ret);
		return ret;
	}

	*present = resp->sfp_present;
	return 0;
}
EXPORT_SYMBOL(hclge_get_sfp_present);

int hclge_disable_net_lane(struct hnae3_handle *handle)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc;
	int ret = 0;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_DISABLE_NET_LANE, false);
	desc.data[0] = 0;
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "disable net lane failed %d\n", ret);
		return ret;
	}
	return 0;
}
EXPORT_SYMBOL(hclge_disable_net_lane);

int hclge_get_net_lane_status(struct hnae3_handle *handle, u32 *status)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc;
	int ret = 0;

	desc.data[0] = 0;
	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_DISABLE_NET_LANE, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "disable net lane failed %d\n", ret);
		return ret;
	}
	*status = desc.data[0];
	return 0;
}
EXPORT_SYMBOL(hclge_get_net_lane_status);

int hclge_set_mac_state(struct hnae3_handle *handle, bool enable)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc;
	struct hclge_config_mac_mode_cmd *req =
		(struct hclge_config_mac_mode_cmd *)desc.data;
	u32 loop_en = 0;
	int ret = 0;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_CONFIG_MAC_MODE, false);
	hnae3_set_bit(loop_en, HCLGE_MAC_TX_EN_B, enable);
	hnae3_set_bit(loop_en, HCLGE_MAC_RX_EN_B, enable);
	hnae3_set_bit(loop_en, HCLGE_MAC_PAD_TX_B, enable);
	hnae3_set_bit(loop_en, HCLGE_MAC_PAD_RX_B, enable);
	hnae3_set_bit(loop_en, HCLGE_MAC_1588_TX_B, 0);
	hnae3_set_bit(loop_en, HCLGE_MAC_1588_RX_B, 0);
	hnae3_set_bit(loop_en, HCLGE_MAC_APP_LP_B, 0);
	hnae3_set_bit(loop_en, HCLGE_MAC_LINE_LP_B, 0);
	hnae3_set_bit(loop_en, HCLGE_MAC_FCS_TX_B, enable);
	hnae3_set_bit(loop_en, HCLGE_MAC_RX_FCS_B, enable);
	hnae3_set_bit(loop_en, HCLGE_MAC_RX_FCS_STRIP_B, enable);
	hnae3_set_bit(loop_en, HCLGE_MAC_TX_OVERSIZE_TRUNCATE_B, enable);
	hnae3_set_bit(loop_en, HCLGE_MAC_RX_OVERSIZE_TRUNCATE_B, enable);
	hnae3_set_bit(loop_en, HCLGE_MAC_TX_UNDER_MIN_ERR_B, enable);
	req->txrx_pad_fcs_loop_en = cpu_to_le32(loop_en);

	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret)
		dev_err(&hdev->pdev->dev,
			"set mac state %x fail, ret =%d.\n", enable, ret);
	return ret;
}
EXPORT_SYMBOL(hclge_set_mac_state);

int hclge_config_nic_clock(struct hnae3_handle *handle, bool enable)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	u32 nic_clock_en = enable;
	struct hclge_desc desc;
	int ret = 0;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_CONFIG_NIC_CLOCK, false);
	desc.data[0] = nic_clock_en;

	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret)
		dev_err(&hdev->pdev->dev,
			"config_nic_clock %x fail, ret = %d.\n",
			nic_clock_en, ret);
	return ret;
}
EXPORT_SYMBOL(hclge_config_nic_clock);

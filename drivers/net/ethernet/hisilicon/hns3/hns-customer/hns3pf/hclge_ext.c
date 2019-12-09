// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#ifdef CONFIG_IT_VALIDATION
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
#include "hclge_main.h"
#include "hnae3.h"
#include "hclge_cmd.h"
#include "hclge_ext.h"

#define BD0_DATA_LEN	20
#define BD1_DATA_LEN	24

void hclge_reset_task_schedule_it(struct hclge_dev *hdev)
{
	if (!test_bit(HCLGE_STATE_REMOVING, &hdev->state) &&
	    !test_and_set_bit(HCLGE_STATE_RST_SERVICE_SCHED, &hdev->state))
		mod_delayed_work_on(cpumask_first(&hdev->affinity_mask),
				    system_wq, &hdev->service_task, 0);
}

#ifdef CONFIG_HNS3_TEST
static int hclge_clean_stats64(struct hnae3_handle *handle, int opcode,
			       void *data, int length)
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
	memset(&hdev->mac_stats, 0, sizeof(struct hclge_mac_stats));
	return 0;
}

static int hclge_get_chipid(struct hnae3_handle *handle, int opcode,
			    void *data, int length)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	struct hclge_chip_id_cmd *resp = NULL;
	struct hclge_desc desc;
	u32 *chip_id;
	int ret;

	chip_id = (u32 *)data;
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

static int hclge_get_mac_id(struct hnae3_handle *handle, int opcode,
			    void *data, int length)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc;
	u32 *mac_id;
	int ret;

	mac_id = (u32 *)data;
	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_CHIP_ID_GET, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "get mac id failed, ret = %d\n", ret);
		return ret;
	}

	*mac_id = desc.data[1];
	return 0;
}

static int _hclge_get_sfpinfo(struct hnae3_handle *handle, u8 *buff,
			      u16 offset, u16 size, u16 *outlen)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_desc desc[HCLGE_SFP_INFO_LEN];
	struct hclge_dev *hdev = vport->back;
	struct hclge_sfp_info *resp = NULL;
	int ret;
	u32 i;
	u32 j;
	u32 temp_len;
	u32 data_len;
	u8 *temp_data;

	memset(desc, 0x0, sizeof(desc));

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
			"get spf information cmd failed %d\n", ret);
		return ret;
	}

	for (i = 0; i < HCLGE_SFP_INFO_LEN; i++) {
		resp = (struct hclge_sfp_info *)desc[i].data;
		if (i == 0) {
			*outlen = (resp[i].sfpinfo[0] >> 16) & 0xFFFF;
			temp_len = *outlen;
			data_len =
			    (temp_len > BD0_DATA_LEN) ? BD0_DATA_LEN : temp_len;
			temp_data = (u8 *)&resp->sfpinfo[1];
		} else {
			data_len =
			    (temp_len > BD1_DATA_LEN) ? BD1_DATA_LEN : temp_len;
			temp_data = (u8 *)&resp->sfpinfo[0];
		}

		for (j = 0; j < data_len; j++)
			*buff++ = *temp_data++;

		temp_len -= data_len;
		if (temp_len == 0)
			break;
	}
	return 0;
}

static int hclge_get_sfpinfo(struct hnae3_handle *handle, int opcode,
			     void *data, int length)
{
	struct hclge_sfp_info_para *para;
	u16 tmp_size;
	u8 *tmp_buff;
	u16 tmp_outlen;
	int ret;
	para = (struct hclge_sfp_info_para *)data;
	tmp_buff = para->buff;

	while (para->size) {
		WARN_ON_ONCE(!tmp_buff);
		if (para->size > HCLGE_SFP_INFO_SIZE)
			tmp_size = HCLGE_SFP_INFO_SIZE;
		else
			tmp_size = para->size;
		ret = _hclge_get_sfpinfo(handle, tmp_buff, para->offset,
					 tmp_size, &tmp_outlen);
		if (ret)
			return ret;
		para->offset += tmp_size;
		para->size -= tmp_size;
		tmp_buff += tmp_size;
		*para->outlen += tmp_outlen;
		if (tmp_size != tmp_outlen)
			break;
	}

	return 0;
}

static int hclge_set_sfp_state(struct hnae3_handle *handle, int opcode,
			       void *data, int length)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_sfp_enable_cmd *req = NULL;
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_SFP_SET_STATUS, false);
	req = (struct hclge_sfp_enable_cmd *)desc.data;
	req->set_sfp_enable_flag = *(bool *)data;

	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret)
		dev_err(&hdev->pdev->dev,
			"set spf on/off cmd failed %d\n", ret);

	return ret;
}

static int hclge_get_chip_num(struct hnae3_handle *handle, int opcode,
			      void *data, int length)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	u32 *chip_num = (u32 *)data;
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

static int hclge_get_port_num(struct hnae3_handle *handle, int opcode,
			      void *data, int length)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc;
	u32 *port_num;
	int ret;

	port_num = (u32 *)data;
	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_GET_PORT_NUM, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "get port number failed %d\n", ret);
		return ret;
	}
	*port_num = desc.data[0];
	return 0;
}

static int hclge_set_led(struct hnae3_handle *handle, int opcode,
			 void *data, int length)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	struct hclge_led_state *para;
	struct hclge_desc desc;
	int ret;

	para = (struct hclge_led_state *)data;
	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_SET_LED, false);
	desc.data[0] = para->type;
	desc.data[1] = para->status;
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "get set led failed %d\n", ret);
		return ret;
	}

	return 0;
}

static int hclge_get_led_signal(struct hnae3_handle *handle, int opcode,
				void *data, int length)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	struct hclge_lamp_signal *signal;
	struct hclge_desc desc;
	int ret;

	signal = (struct hclge_lamp_signal *)data;
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

static int hclge_get_sfp_present(struct hnae3_handle *handle, int opcode,
				 void *data, int length)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_sfp_present_cmd *resp = NULL;
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc;
	u32 *present;
	int ret = 0;

	present = (u32 *)data;
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

static int hclge_disable_net_lane(struct hnae3_handle *handle, int opcode,
				  void *data, int length)
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

static int hclge_get_net_lane_status(struct hnae3_handle *handle, int opcode,
				     void *data, int length)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc;
	u32 *status;
	int ret = 0;

	status = (u32 *)data;
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

static void hclge_set_phy_state(struct hnae3_handle *handle, bool enable)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	struct phy_device *phydev = hdev->hw.mac.phydev;

	if (!phydev)
		return;

	if (enable)
		phy_start(phydev);
	else
		phy_stop(phydev);
}

static int hclge_set_mac_state(struct hnae3_handle *handle, int opcode,
			       void *data, int length)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_config_mac_mode_cmd *req;
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc;
	u32 loop_en = 0;
	bool enable;
	int ret;

	enable = *(bool *)data;
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
	req = (struct hclge_config_mac_mode_cmd *)desc.data;
	req->txrx_pad_fcs_loop_en = cpu_to_le32(loop_en);

	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret)
		dev_err(&hdev->pdev->dev,
			"set mac state %x fail, ret = %d.\n", enable, ret);
	hclge_set_phy_state(handle, enable);
	return ret;
}

static int hclge_config_nic_clock(struct hnae3_handle *handle, int opcode,
				  void *data, int length)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	u32 nic_clock_en = *(u32 *)data;
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

static int hclge_set_pfc_storm_para(struct hnae3_handle *handle, int opcode,
				    void *data, int length)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	struct hclge_pfc_storm_para *para;
	struct hclge_desc desc;
	int ret = 0;

	para = (struct hclge_pfc_storm_para *)data;
	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_CFG_PAUSE_STORM_PARA,
				   false);
	desc.data[0] = para->dir;
	desc.data[1] = para->enable;
	desc.data[2] = para->period_ms;
	desc.data[3] = para->times;
	desc.data[4] = para->recovery_period_ms;
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "set pfc storm para failed %d\n",
			ret);
		return ret;
	}
	return 0;
}

static int hclge_get_pfc_storm_para(struct hnae3_handle *handle, int opcode,
				    void *data, int length)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	struct hclge_pfc_storm_para *para;
	struct hclge_desc desc;
	int ret = 0;

	para = (struct hclge_pfc_storm_para *)data;
	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_CFG_PAUSE_STORM_PARA, true);
	desc.data[0] = para->dir;
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "get pfc storm para failed %d\n",
			ret);
		return ret;
	}
	para->enable = desc.data[1];
	para->period_ms = desc.data[2];
	para->times = desc.data[3];
	para->recovery_period_ms = desc.data[4];
	return 0;
}

enum hclge_phy_op_code {
	PHY_OP_READ,
	PHY_OP_WRITE,
	PHY_OP_MAX,
};

static int hclge_phy_need_page_select(struct hclge_dev *hdev,
				      enum hclge_phy_op_code opt_type,
				      struct hclge_phy_para *para,
				      u16 *cur_page)
{
	struct hclge_mac *mac = &hdev->hw.mac;
	struct mii_bus *mdio_bus = mac->mdio_bus;
	u32 phyid = mac->phy_addr;
	int ret;

	/* no need to change page when page param is 0 */
	if (opt_type != PHY_OP_READ || para->page != 0) {
		ret = mdio_bus->read(mdio_bus, phyid, para->page_select_addr);
		if (ret < 0) {
			dev_err(&hdev->pdev->dev,
				"record current phy %d reg page failed.\n",
				phyid);
			return ret;
		}
		*cur_page = ret;
		if (para->page != *cur_page)
			return 1;
		else
			return 0;
	}

	return 0;
}

static int hclge_check_phy_opt_param(struct hclge_dev *hdev,
				     struct mii_bus *mdio_bus,
				     struct phy_device *phydev,
				     enum hclge_phy_op_code opt_type)
{
	if (!phydev) {
		dev_err(&hdev->pdev->dev, "this net dev has no phy.\n");
		return -EINVAL;
	}

	if (!mdio_bus) {
		dev_err(&hdev->pdev->dev, "this net dev has no mdio bus.\n");
		return -EINVAL;
	}

	if (opt_type >= PHY_OP_MAX) {
		dev_err(&hdev->pdev->dev, "unsupported phy operate type %d.",
			opt_type);
		return -EINVAL;
	}

	return 0;
}

static int hclge_mdio_bus_opt(struct hclge_phy_para *para,
			      struct hclge_dev *hdev,
			      struct mii_bus *mdio_bus, u32 phyid,
			      enum hclge_phy_op_code opt_type)
{
	int op_ret;

	if (opt_type == PHY_OP_READ) {
		op_ret = mdio_bus->read(mdio_bus, phyid, para->reg_addr);
		if (op_ret < 0) {
			dev_err(&hdev->pdev->dev,
				"read phy %d page %d reg %d failed.\n",
				phyid, para->page, para->reg_addr);
		} else {
			para->data = (u16)op_ret;
			op_ret = 0;
		}
	} else {
		op_ret = mdio_bus->write(mdio_bus, phyid, para->reg_addr,
					 para->data);
		if (op_ret < 0) {
			dev_err(&hdev->pdev->dev,
				"write phy %d page %d reg %d failed.\n",
				phyid, para->page, para->reg_addr);
		}
	}

	return op_ret;
}

static int hclge_phy_reg_opt(struct hnae3_handle *handle, void *data,
			     enum hclge_phy_op_code opt_type)
{
	struct hclge_phy_para *para = (struct hclge_phy_para *)data;
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	struct hclge_mac *mac = &hdev->hw.mac;
	struct mii_bus *mdio_bus = mac->mdio_bus;
	u32 phyid = mac->phy_addr;
	int need_page_select;
	u16 cur_page;
	int op_ret;
	int ret;

	ret = hclge_check_phy_opt_param(hdev, mdio_bus, mac->phydev, opt_type);
	if (ret < 0)
		return ret;

	/* operate flow:
	 * 1 record current page address
	 * 2 jump to operated page
	 * 3 operate register(read or write)
	 * 4 come back to the page recorded in the first step.
	 */
	mutex_lock(&mdio_bus->mdio_lock);

	/* check if page select is needed and record current page address */
	ret = hclge_phy_need_page_select(hdev, opt_type, para, &cur_page);
	if (ret < 0) {
		mutex_unlock(&mdio_bus->mdio_lock);
		return ret;
	}
	need_page_select = ret;

	/* jump to operated page */
	if (need_page_select) {
		ret = mdio_bus->write(mdio_bus, phyid, para->page_select_addr,
				      para->page);
		if (ret < 0) {
			mutex_unlock(&mdio_bus->mdio_lock);
			dev_err(&hdev->pdev->dev,
				"change phy %d page %d to page %d failed.\n",
				phyid, cur_page, para->page);
			return ret;
		}
	}

	/* operate register(read or write) */
	op_ret = hclge_mdio_bus_opt(para, hdev, mdio_bus, phyid, opt_type);

	/* come back to the page recorded in the first step. */
	if (need_page_select) {
		ret = mdio_bus->write(mdio_bus, phyid, para->page_select_addr,
				      cur_page);
		if (ret < 0) {
			mutex_unlock(&mdio_bus->mdio_lock);
			dev_err(&hdev->pdev->dev,
				"restore phy %d reg page %u failed.\n",
				phyid, cur_page);
			return ret;
		}
	}

	mutex_unlock(&mdio_bus->mdio_lock);

	return op_ret;
}

static int hclge_get_phy_reg(struct hnae3_handle *handle, int opcode,
			     void *data, int length)
{
	return hclge_phy_reg_opt(handle, data, PHY_OP_READ);
}

static int hclge_set_phy_reg(struct hnae3_handle *handle, int opcode,
			     void *data, int length)
{
	return hclge_phy_reg_opt(handle, data, PHY_OP_WRITE);
}

static int hclge_8211_phy_indirect_opt(struct hclge_phy_para *para,
				       struct hclge_dev *hdev,
				       struct mii_bus *mdio_bus,
				       u32 phyid,
				       enum hclge_phy_op_code opt_type)
{
	u32 indirect_reg_data;
	int op_ret;

	/* select indirect page 0xa43 */
	op_ret = mdio_bus->write(mdio_bus, phyid, para->page_select_addr,
				 HCLGE_8211_PHY_INDIRECT_PAGE);
	if (op_ret < 0) {
		dev_err(&hdev->pdev->dev,
			"change phy %d indirect page 0xa43 failed.\n", phyid);
		return op_ret;
	}
	/* ndirect access address = page_no*16 + 2*(reg_no%16) */
	indirect_reg_data = (para->page << 4) + ((para->reg_addr % 16) << 1);
	op_ret = mdio_bus->write(mdio_bus, phyid,
				 HCLGE_8211_PHY_INDIRECT_REG,
				 indirect_reg_data);
	if (op_ret < 0) {
		dev_err(&hdev->pdev->dev,
			"write phy %d indirect reg failed.\n", phyid);
		return op_ret;
	}

	if (opt_type == PHY_OP_READ) {
		op_ret = mdio_bus->read(mdio_bus, phyid,
					HCLGE_8211_PHY_INDIRECT_DATA);
		if (op_ret < 0) {
			dev_err(&hdev->pdev->dev,
				"read phy %d indirect data failed.\n", phyid);
		} else {
			para->data = (u16)op_ret;
			op_ret = 0;
		}
	} else {
		op_ret = mdio_bus->write(mdio_bus, phyid,
					 HCLGE_8211_PHY_INDIRECT_DATA,
					 para->data);
		if (op_ret < 0) {
			dev_err(&hdev->pdev->dev,
				"write phy %d indirect data failed.\n", phyid);
		}
	}

	return op_ret;
}

static int hclge_8211_phy_reg_opt(struct hnae3_handle *handle, void *data,
				  enum hclge_phy_op_code opt_type)
{
	struct hclge_phy_para *para = (struct hclge_phy_para *)data;
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	struct hclge_mac *mac = &hdev->hw.mac;
	struct mii_bus *mdio_bus = mac->mdio_bus;
	u32 phyid = mac->phy_addr;
	u16 save_page;
	int ret;

	ret = hclge_check_phy_opt_param(hdev, mdio_bus, mac->phydev, opt_type);
	if (ret < 0)
		return ret;

	mutex_lock(&mdio_bus->mdio_lock);
	ret = mdio_bus->read(mdio_bus, phyid, para->page_select_addr);
	if (ret < 0) {
		dev_err(&hdev->pdev->dev,
			"record phy %d reg page failed.\n",
			phyid);
		mutex_unlock(&mdio_bus->mdio_lock);
		return ret;
	}
	save_page = ret;
	ret = hclge_8211_phy_indirect_opt(para, hdev, mdio_bus, phyid,
					  opt_type);
	if (ret)
		dev_err(&hdev->pdev->dev,
			"8211 phy %d indirect access failed.\n", phyid);
	ret = mdio_bus->write(mdio_bus, phyid, para->page_select_addr,
			      save_page);
	if (ret < 0)
		dev_err(&hdev->pdev->dev,
			"restore phy %d reg page %u failed.\n",
			phyid, save_page);
	mutex_unlock(&mdio_bus->mdio_lock);

	return ret;
}

static int hclge_8211_phy_need_indirect_access(u16 page)
{
	if (page >= HCLGE_8211_PHY_INDIRECT_RANGE1_S &&
	    page <= HCLGE_8211_PHY_INDIRECT_RANGE1_E)
		return true;
	else if (page >= HCLGE_8211_PHY_INDIRECT_RANGE2_S &&
		 page <= HCLGE_8211_PHY_INDIRECT_RANGE2_E)
		return true;
	else
		return false;
}


static int hclge_opt_lookup_mac_tbl(struct hclge_vport *vport,
				    unsigned char *addr)
{
	u32 low_val = addr[4] | (addr[5] << 8);
	struct hclge_mac_vlan_tbl_entry_cmd req = {0};
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc;
	u8 resp_code;
	u32 high_val;
	u16 retval;
	int ret;

	high_val = addr[2] << 16 | (addr[3] << 24) | (addr[0]) | (addr[1] << 8);
	hnae3_set_bit(req.flags, HCLGE_MAC_VLAN_BIT0_EN_B, 1);
	req.mac_addr_hi32 = cpu_to_le32(high_val);
	req.mac_addr_lo16 = cpu_to_le16(low_val & 0xffff);

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_MAC_VLAN_ADD, true);
	memcpy(desc.data, &req, sizeof(struct hclge_mac_vlan_tbl_entry_cmd));
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"lookup mac addr failed for cmd_send, ret = %d.\n",
			ret);
		return ret;
	}

	resp_code = (le32_to_cpu(desc.data[0]) >> 8) & 0xff;
	retval = le16_to_cpu(desc.retval);
	if (retval) {
		dev_err(&hdev->pdev->dev,
			"cmdq execute failed for %s, retval = %d.\n",
			__func__, retval);
		return -EIO;
	}

	if (!resp_code) {
		return 0;
	} else if (resp_code == 1) {
		dev_dbg(&hdev->pdev->dev, "lookup mac addr failed for miss.\n");
		return -ENOENT;
	}

	dev_err(&hdev->pdev->dev,
		"lookup mac addr failed for undefined, code = %d.\n",
		resp_code);
	return -EIO;
}

static int hclge_opt_mac_table(struct hnae3_handle *handle, int opcode,
			       void *data, int length)
{
	struct hclge_mac_table_para *info = (struct hclge_mac_table_para *)data;
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev;
	int ret;

	if (!info || !vport)
		return -EIO;

	hdev = vport->back;
	switch (info->op_cmd) {
	case HCLGE_OPT_TABLE_LOOKUP:
		ret = hclge_opt_lookup_mac_tbl(vport, info->mac_addr);
		if (ret == -ENOENT) {
			return ret;
		} else if (ret) {
			dev_err(&hdev->pdev->dev,
				"ext lookup uc mac address(%pM) fail, ret = %d.\n",
				info->mac_addr, ret);
			return -EIO;
		}
		break;
	case HCLGE_OPT_TABLE_ADD:
		ret = hclge_add_uc_addr_common(vport, info->mac_addr);
		if (ret == -ENOSPC) {
			return ret;
		} else if (ret) {
			dev_err(&hdev->pdev->dev,
				"ext add uc mac address(%pM) fail, ret = %d.\n",
				info->mac_addr, ret);
			return -EIO;
		}
		break;
	case HCLGE_OPT_TABLE_DEL:
		ret = hclge_rm_uc_addr_common(vport, info->mac_addr);
		if (ret == -ENOENT) {
			return ret;
		} else if (ret) {
			dev_warn(&hdev->pdev->dev,
				 "ext remove uc mac address(%pM) fail, ret = %d.\n",
				 info->mac_addr, ret);
			return -EIO;
		}
		break;
	default:
		dev_err(&hdev->pdev->dev, "ext opcode error.\n");
		return -EIO;
	}

	return ret;
}

static int hclge_set_reset_task(struct hnae3_handle *handle, int opcode,
				void *data, int length)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	u32 *reset_level = (u32 *)data;

	dev_warn(&hdev->pdev->dev, "reset level is %d\n", *reset_level);

	/* request reset & schedule reset task */
	set_bit(*reset_level, &hdev->reset_request);
	hclge_reset_task_schedule_it(hdev);
	return 0;
}

static int hclge_get_hilink_ref_los(struct hnae3_handle *handle, int opcode,
				    void *data, int length)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc;
	u32 *hilink_ref_los_status;
	int ret;

	hilink_ref_los_status = (u32 *)data;
	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_CFG_GET_HILINK_REF_LOS,
				   true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"get hilink ref los failed, ret = %d\n", ret);
		return ret;
	}

	*hilink_ref_los_status = desc.data[0];
	return 0;
}

static int hclge_get_8211_phy_reg(struct hnae3_handle *handle, int opcode,
				  void *data, int length)
{
	struct hclge_phy_para *para = (struct hclge_phy_para *)data;

	if (hclge_8211_phy_need_indirect_access(para->page))
		return hclge_8211_phy_reg_opt(handle, data, PHY_OP_READ);
	else
		return hclge_phy_reg_opt(handle, data, PHY_OP_READ);
}

static int hclge_set_8211_phy_reg(struct hnae3_handle *handle, int opcode,
				  void *data, int length)
{
	struct hclge_phy_para *para = (struct hclge_phy_para *)data;

	if (hclge_8211_phy_need_indirect_access(para->page))
		return hclge_8211_phy_reg_opt(handle, data, PHY_OP_WRITE);
	else
		return hclge_phy_reg_opt(handle, data, PHY_OP_WRITE);
}

static int hclge_get_port_wire_type(struct hnae3_handle *handle, int opcode,
				    void *data, int length)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_sfp_info_cmd *resp = NULL;
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc;
	u32 *wire_type;
	int ret;

	wire_type = (u32 *)data;
	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_SFP_GET_PORT_INFO, true);
	resp = (struct hclge_sfp_info_cmd *)desc.data;
	resp->query_type = PORT_QUERY_TYPE_SFP;

	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"get port info failed, ret = %d\n", ret);
		return ret;
	}

	*wire_type = resp->module_type;
	return 0;
}

static struct hclge_ext_func hclge_ext_func_arr[] = {
	{HCLGE_EXT_OPC_CLEAN_STATS64, hclge_clean_stats64},
	{HCLGE_EXT_OPC_GET_CHIPID, hclge_get_chipid},
	{HCLGE_EXT_OPC_GET_SFPINFO, hclge_get_sfpinfo},
	{HCLGE_EXT_OPC_SET_SFP_STATE, hclge_set_sfp_state},
	{HCLGE_EXT_OPC_GET_CHIP_NUM, hclge_get_chip_num},
	{HCLGE_EXT_OPC_GET_PORT_NUM, hclge_get_port_num},
	{HCLGE_EXT_OPC_SET_LED, hclge_set_led},
	{HCLGE_EXT_OPC_GET_PRESENT, hclge_get_sfp_present},
	{HCLGE_EXT_OPC_DISABLE_LANE, hclge_disable_net_lane},
	{HCLGE_EXT_OPC_GET_LANE_STATUS, hclge_get_net_lane_status},
	{HCLGE_EXT_OPC_GET_LED_SIGNAL, hclge_get_led_signal},
	{HCLGE_EXT_OPC_SET_MAC_STATE, hclge_set_mac_state},
	{HCLGE_EXT_OPC_CONFIG_CLOCK, hclge_config_nic_clock},
	{HCLGE_EXT_OPC_GET_PFC_STORM_PARA, hclge_get_pfc_storm_para},
	{HCLGE_EXT_OPC_SET_PFC_STORM_PARA, hclge_set_pfc_storm_para},
	{HCLGE_EXT_OPC_GET_PHY_REG, hclge_get_phy_reg},
	{HCLGE_EXT_OPC_SET_PHY_REG, hclge_set_phy_reg},
	{HCLGE_EXT_OPC_GET_MAC_ID, hclge_get_mac_id},
	{HCLGE_EXT_OPC_OPT_MAC_TABLE, hclge_opt_mac_table},
	{HCLGE_EXT_OPC_RESET, hclge_set_reset_task},
	{HCLGE_EXT_OPC_GET_HILINK_REF_LOS, hclge_get_hilink_ref_los},
	{HCLGE_EXT_OPC_GET_8211_PHY_REG, hclge_get_8211_phy_reg},
	{HCLGE_EXT_OPC_SET_8211_PHY_REG, hclge_set_8211_phy_reg},
	{HCLGE_EXT_OPC_GET_PORT_TYPE, hclge_get_port_wire_type},
};

int hclge_ext_ops_handle(struct hnae3_handle *handle, int opcode,
			 void *data, int length)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	int cmd_num = ARRAY_SIZE(hclge_ext_func_arr);
	struct hclge_dev *hdev = vport->back;

	if (opcode >= cmd_num) {
		dev_err(&hdev->pdev->dev, "not support opcode %d.\n", opcode);
		return -EOPNOTSUPP;
	}

	if (opcode != hclge_ext_func_arr[opcode].opcode) {
		dev_err(&hdev->pdev->dev, "opcode %d is not equals %d.\n",
			opcode, hclge_ext_func_arr[opcode].opcode);
		return -EINVAL;
	}

	return hclge_ext_func_arr[opcode].priv_ops(handle, opcode, data,
						   length);
}
#endif
#endif

// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/phy_fixed.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_address.h>

#include "hclge_cmd.h"
#include "hnae3.h"
#include "hclge_main.h"
#include "hns3_enet.h"
#include "hns3_priv_phy.h"

#define HNS3_PHY_MAX_REG_NUM		0xFFFF
#define HNS3_PHY_READ			0
#define HNS3_PHY_WRITE			1

static int hns3_test_get_reg(struct mii_bus *mdio_bus, u32 phy_id,
			     u16 page_select_addr, u16 page, u32 addr,
			     u16 *data)
{
	u16 cur_page;
	int ret;

	if (addr > HNS3_PHY_MAX_REG_NUM) {
		pr_err("invalid phy %d page or reg.\n", phy_id);
		return -EPERM;
	}

	mutex_lock(&mdio_bus->mdio_lock);
	ret = mdio_bus->read(mdio_bus, phy_id, page_select_addr);
	if (ret < 0) {
		mutex_unlock(&mdio_bus->mdio_lock);
		pr_err("record current phy %d reg page failed.\n", phy_id);
		return ret;
	}

	cur_page = ret;

	if (page == cur_page) {
		ret = mdio_bus->read(mdio_bus, phy_id, addr);
		mutex_unlock(&mdio_bus->mdio_lock);
		if (ret >= 0) {
			*data = ret;
			return 0;
		}

		return ret;
	}

	ret = mdio_bus->write(mdio_bus, phy_id, page_select_addr, page);
	if (ret < 0) {
		mutex_unlock(&mdio_bus->mdio_lock);
		pr_err("change phy %d reg page %d to %d failed.\n", phy_id,
		       cur_page, page);
		return ret;
	}

	ret = mdio_bus->read(mdio_bus, phy_id, addr);
	if (ret < 0) {
		pr_err("read phy %d reg(%u-%u) failed.\n", phy_id, page, addr);
		if (mdio_bus->write(mdio_bus, phy_id, page_select_addr,
				    cur_page) < 0)
			pr_err("restore phy %d reg page %d failed after error read.\n",
			       phy_id, cur_page);
		mutex_unlock(&mdio_bus->mdio_lock);
		return ret;
	}

	*data = ret;
	ret = mdio_bus->write(mdio_bus, phy_id, page_select_addr, cur_page);
	if (ret < 0) {
		mutex_unlock(&mdio_bus->mdio_lock);
		pr_err("restore phy %d reg page %u failed.\n", phy_id,
		       cur_page);
		return ret;
	}

	mutex_unlock(&mdio_bus->mdio_lock);

	return 0;
}

static int hns3_test_set_reg(struct mii_bus *mdio_bus, u32 phy_id,
			     u16 page_select_addr, u16 page, u32 addr, u16 data)
{
	u16 cur_page;
	int ret;

	if (addr > HNS3_PHY_MAX_REG_NUM) {
		pr_err("invalid phy %d page reg or val.\n", phy_id);
		return -EPERM;
	}

	mutex_lock(&mdio_bus->mdio_lock);
	ret = mdio_bus->read(mdio_bus, phy_id, page_select_addr);
	if (ret < 0) {
		mutex_unlock(&mdio_bus->mdio_lock);
		pr_err("record current phy %d reg page failed.\n", phy_id);
		return ret;
	}

	cur_page = ret;
	if (page == cur_page) {
		ret = mdio_bus->write(mdio_bus, phy_id, addr, data);
		mutex_unlock(&mdio_bus->mdio_lock);
		return ret;
	}

	ret = mdio_bus->write(mdio_bus, phy_id, page_select_addr, page);
	if (ret < 0) {
		mutex_unlock(&mdio_bus->mdio_lock);
		pr_err("change phy %d reg page %d to %d failed.\n", phy_id,
		       cur_page, page);
		return ret;
	}

	ret = mdio_bus->write(mdio_bus, phy_id, addr, data);
	if (ret < 0) {
		pr_err("write phy %d reg(%d-%d) failed.\n", phy_id, page, addr);
		if (mdio_bus->write(mdio_bus, phy_id, page_select_addr,
				    cur_page) < 0)
			pr_err("restore phy %d reg page %d failed after error write\n",
			       phy_id, cur_page);

		mutex_unlock(&mdio_bus->mdio_lock);
		return ret;
	}

	ret = mdio_bus->write(mdio_bus, phy_id, page_select_addr, cur_page);
	if (ret < 0) {
		mutex_unlock(&mdio_bus->mdio_lock);
		pr_err("change phy %d reg page %d to %d failed.\n", phy_id,
		       page, cur_page);
		return ret;
	}

	mutex_unlock(&mdio_bus->mdio_lock);

	return 0;
}

int hns3_test_phy_register_cfg(struct hns3_nic_priv *net_priv,
			       void *buf_in, u16 in_size,
			       void *buf_out, u16 *out_size)
{
	struct phy_reg_param *param;
	struct hnae3_handle *handle;
	struct hclge_vport *vport;
	struct mii_bus *mdio_bus;
	struct hclge_dev *hdev;
	struct hclge_mac *mac;
	u16 data = 0;
	u32 phyid;
	int ret;

	handle = net_priv->ae_handle;
	vport = hclge_get_vport(handle);
	hdev = vport->back;
	mac = &hdev->hw.mac;
	if (!mac->phydev) {
		pr_err("this net dev has no phy.\n");
		return -EINVAL;
	}
	phyid = mac->phy_addr;
	mdio_bus = mac->mdio_bus;
	param = (struct phy_reg_param *)buf_in;
	if (param->operate == HNS3_PHY_READ) {
		ret = hns3_test_get_reg(mdio_bus, phyid,
					param->page_select_addr,
					param->page, param->addr, &data);
		if (ret == 0) {
			*out_size = sizeof(data);
			memcpy(buf_out, &data, (int)sizeof(data));
		}

	} else if (param->operate == HNS3_PHY_WRITE) {
		ret = hns3_test_set_reg(mdio_bus, phyid,
					param->page_select_addr,
					param->page, param->addr,
					param->data);
	} else {
		pr_err("%s:operate is invalid.\n", __func__);
		return -1;
	}

	return ret;
}

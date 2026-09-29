// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include <linux/wait.h>
#include <linux/sem.h>
#include <linux/semaphore.h>
#include <linux/mutex.h>
#include "mce.h"
#include "mce_base.h"
#include "mce_fwchnl.h"
#include "mce_mbx.h"
#include "mce_vf_lib.h"
#include "mce_virtchnl.h"

#define MBX_REQ_1MS 1000
#define MBX_REQ_1S (1000 * MBX_REQ_1MS)

#define mce_wait_reg_timeout_ms(reg, cond, timeout_ms)       \
	({                                                   \
		unsigned int _v;                             \
		int timeout_us = (timeout_ms) * 1000;        \
		int ret = 0;                                 \
		while (1) {                                  \
			_v = raw_rd32((reg));                \
			if ((cond))                          \
				break;                       \
			if (timeout_us < 0) {                \
				ret = -ETIMEDOUT;            \
				break;                       \
			}                                    \
			if (!mce_context_can_sleep()) {     \
				udelay(10);                  \
			} else {                             \
				usleep_range(10, 20);        \
			}                                    \
			timeout_us -= 10;                    \
		}                                            \
		ret;                                         \
	})

int mce_soc_ioread32(struct mce_hw *hw, int soc_addr, unsigned int *value)
{
	union mbx_fw_cmd_req_data req_data;
	struct mbx_resp resp = {};
	int err = 0, try_cnt = 3;

	if (!value)
		return -EINVAL;

	memset(&req_data, 0, sizeof(req_data));

	req_data.r_reg.addr = soc_addr;
	req_data.r_reg.bytes = 4;

	while (try_cnt--) {
		err = mce_mbx_send_req(&hw->fw_mbx, READ_REG, req_data.data,
				       sizeof(req_data.r_reg), &resp,
				       MBX_REQ_1MS * 500);
		if (err == 0 && resp.cmd.err_code == 0) {
			*value = ((union mbx_fw_cmd_resp_data *)resp.data)
					 ->r_reg.value[0];
			return 0;
		}
	}

	*value = 0xdeadbeaf;
	return -EIO;
}

int mce_soc_iowrite32(struct mce_hw *hw, int soc_addr, unsigned int value)
{
	union mbx_fw_cmd_req_data req_data;
	struct mbx_resp resp = {};
	int err = 0, try_cnt = 3;

	memset(&req_data, 0, sizeof(req_data));

	req_data.w_reg.addr = soc_addr;
	req_data.w_reg.bytes = 4;
	req_data.w_reg.data[0] = value;

	while (try_cnt--) {
		err = mce_mbx_send_req(&hw->fw_mbx, WRITE_REG, req_data.data,
				       sizeof(req_data.w_reg), &resp,
				       MBX_REQ_1MS * 500);
		if (err == 0 && resp.cmd.err_code == 0)
			return 0;
	}
	return -EIO;
}

int mce_soc_modify32(struct mce_hw *hw, int soc_addr, unsigned int mask,
		     unsigned int value)
{
	union mbx_fw_cmd_req_data req_data;
	struct mbx_resp resp = {};
	int err = 0, try_cnt = 3;

	memset(&req_data, 0, sizeof(req_data));

	req_data.modify_reg.addr = soc_addr;
	req_data.modify_reg.mask = mask;
	req_data.modify_reg.data = value;

	while (try_cnt--) {
		err = mce_mbx_send_req(&hw->fw_mbx, MODIFY_REG, req_data.data,
				       sizeof(req_data.modify_reg), &resp,
				       MBX_REQ_1MS * 500);
		if (err == 0 && resp.cmd.err_code == 0)
			return 0;
	}
	return -EIO;
}

int mce_mbx_get_dump(struct mce_hw *hw, int dump_v, void *buf, int bytes,
		     int *flag, int *version)
{
	union mbx_fw_cmd_req_data req_data;
	struct mbx_resp resp = {};
	union mbx_fw_cmd_resp_data *resp_data =
		(union mbx_fw_cmd_resp_data *)resp.data;
	int ret = 0, try_cnt = 3;
	dma_addr_t dma_phy = 0;
	char *dma_buf = NULL;

	memset(&req_data, 0, sizeof(req_data));

	if (bytes < 0) {
		dev_err(&hw->pdev->dev, "%s: invalid arg: bytes:%d", __func__,
			bytes);
		return -EINVAL;
	}

	if (bytes > sizeof(resp_data->get_dump.data)) {
		dma_buf = dma_alloc_coherent(&hw->pdev->dev, bytes, &dma_phy,
					     GFP_ATOMIC);
		if (!dma_buf)
			return -ENOMEM;
	}

	req_data.get_dump.bytes = bytes;
	req_data.get_dump.bin_phy_lo = (unsigned int)(dma_phy & 0xFFFFFFFF);
	req_data.get_dump.bin_phy_hi =
		(unsigned int)((dma_phy >> 32) & 0xFFFFFFFF);

	while (try_cnt--) {
		ret = mce_mbx_send_req(&hw->fw_mbx, GET_DUMP, req_data.data,
				       sizeof(req_data.get_dump), &resp,
				       MBX_REQ_1S * 1);
		if (ret == 0 && resp.cmd.err_code == 0)
			break;
		ret = -EIO;
	}
	if (ret != 0)
		goto quit;

	if (flag)
		*flag = resp_data->get_dump.flags;

	if (version)
		*version = resp_data->get_dump.version;

	if (buf) {
		if (dma_buf) {
			memcpy(buf, dma_buf, resp_data->get_dump.bytes);
		} else {
			memcpy(buf, resp_data->get_dump.data,
			       resp_data->get_dump.bytes);
		}
	}
	ret = resp_data->get_dump.bytes;

quit:
	if (dma_buf)
		dma_free_coherent(&hw->pdev->dev, bytes, dma_buf, dma_phy);

	return ret;
}

int mce_mbx_set_dump(struct mce_hw *hw, int dump_v)
{
	union mbx_fw_cmd_req_data req_data;
	int err = 0, try_cnt = 3;

	memset(&req_data, 0, sizeof(req_data));

	req_data.set_dump.flag = dump_v;

	while (try_cnt--) {
		err = mce_mbx_send_req(&hw->fw_mbx, SET_DUMP, req_data.data,
				       sizeof(req_data.set_dump), NULL,
				       MBX_REQ_1MS * 500);
		if (err == 0)
			return 0;
	}
	return -EIO;
}

int mce_mbx_axi_mhz_set(struct mce_hw *hw, int axi_mhz)
{
	int ret = 0;

	if (axi_mhz < 200 || axi_mhz > 500)
		return -EINVAL;

	ret = mce_mbx_set_dump(hw, 0x0E010000 | (axi_mhz & 0xFFFF));
	return ret;
}

int mce_mbx_axi_mhz_get(struct mce_hw *hw)
{
	int v = mce_soc_ioread32_noshm(hw, MCE_LG_SOC_AXI_MHZ);

	if (v == 0 || v == 0xdeadbeaf)
		return hw->axi_mhz;

	return v;
}

int mce_mbx_ifup_down(struct mce_hw *hw, bool up)
{
	union mbx_fw_cmd_req_data req_data;
	int err = 0, cnt = 5;

	memset(&req_data, 0, sizeof(req_data));
	req_data.ifup.up = !!up;

	while (cnt--) {
		err = mce_mbx_send_req(&hw->fw_mbx, IFUP_DOWN, req_data.data,
				       sizeof(req_data.ifup), NULL,
				       MBX_REQ_1MS * 500);
		if (err == 0)
			return 0;
	}
	return -EIO;
}

int mce_mbx_set_phy_func(struct mce_hw *hw, int func, int arg0, int arg1)
{
	union mbx_fw_cmd_req_data req_data;
	int err = 0, retrycnt = 5;

	memset(&req_data, 0, sizeof(req_data));

	req_data.set_phy_fun.func = func;
	req_data.set_phy_fun.value0 = arg0;
	req_data.set_phy_fun.value1 = arg1;

	while (retrycnt--) {
		err = mce_mbx_send_req(&hw->fw_mbx, SET_PHY_FUNC, req_data.data,
				       sizeof(req_data.set_phy_fun), NULL,
				       MBX_REQ_1MS * 500);
		if (err == 0)
			return 0;
	}
	return -EIO;
}

int mce_mbx_set_link_traning_en(struct mce_hw *hw, int enable)
{
	return mce_mbx_set_phy_func(hw, PHY_FUN_LINK_TRAING, !!enable, 0);
}

int mce_mbx_set_autoneg(struct mce_hw *hw, int enable)
{
	return mce_mbx_set_phy_func(hw, PHY_FUN_AN, !!enable, 0);
}

int mce_mbx_set_fec(struct mce_hw *hw, enum FEC_TYPE fec_type)
{
	return mce_mbx_set_phy_func(hw, PHY_FUN_FEC, fec_type, 0);
}

int mce_mbx_set_link_restart_autoneg(struct mce_hw *hw)
{
	return mce_mbx_set_phy_func(hw, PHY_FUN_AN_RESTART, 0, 0);
}

int mce_mbx_wol_set(struct mce_hw *hw, bool enable)
{
	return mce_mbx_set_phy_func(hw, PHY_FUN_WOL_SET, enable, 0);
}

int mce_fw_set_led(struct mce_hw *hw, enum LED_ACTION action)
{
	return mce_mbx_set_phy_func(hw, PHY_FUN_LED_IDENTIFY, action, 0);
}

int mce_mbx_set_duplex(struct mce_hw *hw, int full)
{
	hw->ops->update_fw_stat(hw);
	if (!hw->fw_stat.stat0.is_sgmii)
		return -EINVAL;

	return mce_mbx_set_phy_func(hw, PHY_FUN_SET_SGMII_DUPLEX, full, 0);
}

int mce_mbx_set_force_link_on_close(struct mce_hw *hw, bool force)
{
	return mce_mbx_set_phy_func(hw, PHY_FUN_FORCE_LINK_ON_CLOSE, force, 0);
}

int mce_mbx_set_force_speed(struct mce_hw *hw, enum FORCE_SPEED speed_type)
{
	u32 speed_map[] = {
		[FORCE_1G] = 1000,   [FORCE_10G] = 10000,   [FORCE_25G] = 25000,
		[FORCE_40G] = 40000, [FORCE_100G] = 100000,
	};

	if (speed_type > FORCE_100G)
		return -EINVAL;

	hw->saved_force_speed = speed_type;

	if (speed_type != NO_FORCE_SPEED) {
		if (speed_map[speed_type] > hw->max_speed)
			return -EINVAL;
	}

	return mce_mbx_set_phy_func(hw, PHY_FUN_FORCE_SPEED, speed_type, 0);
}

static int mce_mbx_sfp_read(struct mce_hw *hw, int sfp_i2c_addr, int sfp_reg,
			    char *buf, int bytes)
{
	union mbx_fw_cmd_req_data req_data;
	struct mbx_resp resp = {};
	union mbx_fw_cmd_resp_data *resp_data =
		(union mbx_fw_cmd_resp_data *)resp.data;
	int err = 0, trycnt = 3;

	memset(&req_data, 0, sizeof(req_data));

	if (bytes > MBX_SFP_READ_MAX_CNT)
		return -EINVAL;

	req_data.sfp_read.nr_phy = hw->pfvfnum.pf;
	req_data.sfp_read.cnt = bytes;
	req_data.sfp_read.sfp_i2c_adr = sfp_i2c_addr; /* 0xA0 0xA2 0xAC */
	req_data.sfp_read.reg = sfp_reg;

	while (trycnt--) {
		err = mce_mbx_send_req(&hw->fw_mbx, SFP_MODULE_READ,
				       req_data.data, sizeof(req_data.sfp_read),
				       &resp, MBX_REQ_1MS * 2000);
		if (err == 0 && resp.cmd.err_code == 0) {
			memcpy(buf, resp_data->sfp_read.value, bytes);
			return 0;
		}
	}
	dev_err(&hw->pdev->dev,
		"%s: sfp eeprom failed! addr:0x%x reg:0x%x bytes:%d err:%d, cmd.err_code:%d\n",
		__func__, sfp_i2c_addr, sfp_reg, bytes, err, resp.cmd.err_code);
	return -EIO;
}

int mce_read_sfp_module_eeprom(struct mce_hw *hw, int sfp_i2c_addr, int sfp_reg,
			       char *buf, int bytes)
{
	int left = bytes;
	int cnt, err;

	do {
		cnt = min(left, MBX_SFP_READ_MAX_CNT);
		err = mce_mbx_sfp_read(hw, sfp_i2c_addr, sfp_reg, buf, cnt);
		if (err) {
			dev_err(&hw->pdev->dev,
				"%s: sfp eeprom failed! addr:0x%x reg:0x%x bytes:%d err:%d\n",
				__func__, sfp_i2c_addr, sfp_reg, cnt, err);
			return err;
		}
		sfp_reg += cnt;
		buf += cnt;
		left -= cnt;
	} while (left > 0);

	return 0;
}

int mce_write_sfp_module_eeprom(struct mce_hw *hw, int sfp_i2c_addr,
				int sfp_reg, short val)
{
	union mbx_fw_cmd_req_data req_data;
	int err = 0, trycnt = 3;

	memset(&req_data, 0, sizeof(req_data));

	req_data.sfp_write.nr_phy = hw->pfvfnum.pf;
	req_data.sfp_write.sfp_i2c_adr = sfp_i2c_addr;
	req_data.sfp_write.reg = sfp_reg;
	req_data.sfp_write.val = val;

	while (trycnt--) {
		err = mce_mbx_send_req(&hw->fw_mbx, SFP_MODULE_WRITE,
				       req_data.data,
				       sizeof(req_data.sfp_write), NULL,
				       MBX_REQ_1MS * 1000);
		if (err == 0)
			return 0;
	}

	return -EIO;
}

int mce_mbx_dump_eeprom(struct mce_hw *hw, int offset, char *buf, int bytes)
{
	union mbx_fw_cmd_req_data req_data;
	int err = 0, trycnt = 3;
	dma_addr_t dma_phy;
	char *dma_buf;

	memset(&req_data, 0, sizeof(req_data));

	dma_buf =
		dma_alloc_coherent(&hw->pdev->dev, bytes, &dma_phy, GFP_ATOMIC);
	if (!dma_buf) {
		dev_err(&hw->pdev->dev, "%s: no memory:%d!", __func__, bytes);
		return -ENOMEM;
	}

	req_data.dump_eeprom.bytes = bytes;
	req_data.dump_eeprom.ddr_lo = (unsigned int)(dma_phy & 0xFFFFFFFF);
	req_data.dump_eeprom.ddr_hi =
		(unsigned int)((dma_phy >> 32) & 0xFFFFFFFF);
	req_data.dump_eeprom.offset = offset;

	while (trycnt--) {
		err = mce_mbx_send_req(&hw->fw_mbx, DUMP_EEPROM, req_data.data,
				       sizeof(req_data.dump_eeprom), NULL,
				       MBX_REQ_1S * 50);
		if (err == 0)
			break;
		err = -EIO;
	}
	if (err == 0)
		memcpy(buf, dma_buf, bytes);

	dma_free_coherent(&hw->pdev->dev, bytes, dma_buf, dma_phy);

	return (err) ? -EIO : 0;
}

int mce_fw_update_firmware(struct mce_hw *hw, int partition, const u8 *fw_bin,
			   int bytes)
{
	union mbx_fw_cmd_req_data req_data;
	struct mbx_resp resp = {};
	int err = 0, try_cnt = 3;
	dma_addr_t dma_phy;
	char *dma_buf;

	memset(&req_data, 0, sizeof(req_data));

	dma_buf =
		dma_alloc_coherent(&hw->pdev->dev, bytes, &dma_phy, GFP_ATOMIC);
	if (!dma_buf) {
		dev_err(&hw->pdev->dev, "%s: no memory:%d!", __func__, bytes);
		return -ENOMEM;
	}
	memcpy(dma_buf, fw_bin, bytes);

	req_data.eeprom.cmd = 1;
	req_data.eeprom.bytes = bytes;
	req_data.eeprom.ddr_lo = (unsigned int)(dma_phy & 0xFFFFFFFF);
	req_data.eeprom.ddr_hi = (unsigned int)((dma_phy >> 32) & 0xFFFFFFFF);
	req_data.eeprom.partition = partition;

	while (try_cnt--) {
		err = mce_mbx_send_req(&hw->fw_mbx, FW_EEPROM, req_data.data,
				       sizeof(req_data.eeprom), &resp,
				       MBX_REQ_1S * 50);
		if (err == 0)
			break;
	}

	dev_info(&hw->pdev->dev, "%s:%s (errcode:%d)\n", __func__,
		 err ? " failed" : " success", err);

	dma_free_coherent(&hw->pdev->dev, bytes, dma_buf, dma_phy);

	return (err) ? -EIO : 0;
}

/* Read register value without lock protection. */
int mce_soc_ioread32_noshm(struct mce_hw *hw, int soc_reg)
{
	u8 __iomem *p_reg = hw->eth_bar_base + 0x33000 + 0x14;
	u8 __iomem *p_dat = hw->eth_bar_base + 0x33000 + 0x18;
	int err, ret = 0xdeadbeaf;

	soc_reg = soc_reg & ~3;

	mutex_lock(&hw->fw_mbx.req_lock);

	raw_wr32(0, p_dat);
	raw_wr32(soc_reg, p_reg);
	err = mce_mbx_send_event(&hw->fw_mbx, EVT_REG_OP, 0);
	if (err != 0) {
		dev_err(mce_hw_to_dev(hw), "%s: failed read 0x%x err:%d\n",
			__func__, soc_reg, err);
		goto quit;
	}
	/* wait request done: p_reg BIT(1) = 1 */
	if (mce_wait_reg_timeout_ms(p_reg, (_v & BIT(1)), MBX_REQ_1MS * 40) ==
	    0) {
		ret = raw_rd32(p_dat);
	} else {
		dev_err(mce_hw_to_dev(hw), "%s: failed read 0x%x timeout\n",
			__func__, soc_reg);
	}

quit:
	mutex_unlock(&hw->fw_mbx.req_lock);
	return ret;
}

int mce_soc_iowrite32_noshm(struct mce_hw *hw, int soc_reg, int v)
{
	u8 __iomem *p_reg = hw->eth_bar_base + 0x33000 + 0x14;
	u8 __iomem *p_dat = hw->eth_bar_base + 0x33000 + 0x18;
	int ret = -EIO;

	soc_reg = soc_reg & ~3;

	mutex_lock(&hw->fw_mbx.req_lock);
	raw_wr32(v, p_dat);
	raw_wr32(soc_reg | BIT(0), p_reg);
	ret = mce_mbx_send_event(&hw->fw_mbx, EVT_REG_OP, 0);
	/* wait request done: p_reg BIT(1) = 1 */
	if (mce_wait_reg_timeout_ms(p_reg, (_v & BIT(1)), MBX_REQ_1MS * 40) ==
	    0)
		ret = 0;

	mutex_unlock(&hw->fw_mbx.req_lock);
	return ret;
}

int mce_set_port_si(struct mce_hw *hw, int port_si[4][6])
{
	union mbx_fw_cmd_req_data req_data;
	int err = 0, i, j, try_cnt = 3;

	if (!port_si || !hw)
		return -EINVAL;

	memset(&req_data, 0, sizeof(req_data));

	req_data.si.nr_phy = hw->pfvfnum.pf;
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 6; j++)
			req_data.si.v[i][j] = (int8_t)port_si[i][j];
	}

	while (try_cnt--) {
		err = mce_mbx_send_req(&hw->fw_mbx, SET_PMA_SI, req_data.data,
				       sizeof(req_data.si), NULL,
				       MBX_REQ_1MS * 500);
		if (err == 0)
			return 0;
	}
	dev_err(mce_hw_to_dev(hw), "%s: failed err:%d\n", __func__, err);
	return -EIO;
}

int mce_get_flash_si(struct mce_hw *hw, enum SERDES_SPEED serdes_type,
		     signed char port_si[4][6])
{
	union mbx_fw_cmd_req_data req_data;
	int err = 0, i, j, try_cnt = 3;
	struct mbx_resp resp = {};
	union mbx_fw_cmd_resp_data *resp_data =
		(union mbx_fw_cmd_resp_data *)resp.data;

	if (!port_si || !hw)
		return -EINVAL;

	memset(port_si, 0, 4 * 6);

	req_data.get_flash_si.nr_phy = hw->nr_pf;
	req_data.get_flash_si.nr_serdes_speed = serdes_type;
	req_data.get_flash_si.loaded_si = 1;

	while (try_cnt--) {
		err = mce_mbx_send_req(&hw->fw_mbx, GET_FLASH_SI, req_data.data,
				       sizeof(req_data.get_flash_si), &resp,
				       MBX_REQ_1MS * 500);
		if (err == 0 && resp.cmd.err_code == 0) {
			for (i = 0; i < 4; i++) {
				for (j = 0; j < 6; j++)
					port_si[i][j] =
						resp_data->port_flash_si
							.v[hw->nr_pf][i][j];
			}

			return 0;
		}
	}
	dev_err(mce_hw_to_dev(hw), "%s: failed err:%d err_code:%d\n", __func__,
		err, resp.cmd.err_code);
	return -EIO;
}

/* bit0: pf0 turn sriov, bit1: pf1 turn sriov */
int mce_get_pf_sriov_en_status(struct mce_hw *hw, int *status)
{
	union mbx_fw_cmd_req_data req_data;
	struct mbx_resp resp = {};
	union mbx_fw_cmd_resp_data *resp_data =
		(union mbx_fw_cmd_resp_data *)resp.data;
	int err = 0, try_cnt = 3;

	if (!status)
		return -EINVAL;

	req_data.sriov_vf_enabled_status.value = 0;
	while (try_cnt--) {
		err = mce_mbx_send_req(&hw->fw_mbx, GET_ENABLED_VF_NUM_STATUS,
				       req_data.data, 0, &resp,
				       MBX_REQ_1MS * 500);
		if (err == 0 && resp.cmd.err_code == 0) {
			*status = resp_data->sriov_vf_enabled_status.value;
			return 0;
		}
	}
	dev_err(mce_hw_to_dev(hw), "%s: failed err:%d err_code:%d\n", __func__,
		err, resp.cmd.err_code);
	return -EIO;
}

int mce_get_port_si(struct mce_hw *hw, signed char port_si[4][6])
{
	union mbx_fw_cmd_req_data req_data;
	int err = 0, try_cnt = 3, i, j;
	struct mbx_resp resp = {};
	union mbx_fw_cmd_resp_data *resp_data =
		(union mbx_fw_cmd_resp_data *)resp.data;

	if (!port_si || !hw)
		return -EINVAL;

	while (try_cnt--) {
		err = mce_mbx_send_req(&hw->fw_mbx, GET_PMA_SI, req_data.data,
				       0, &resp, MBX_REQ_1MS * 500);
		if (err == 0 && resp.cmd.err_code == 0) {
			for (i = 0; i < 4; i++) {
				for (j = 0; j < 6; j++)
					port_si[i][j] =
						resp_data->port_si.v[i][j];
			}
			return 0;
		}
	}
	dev_err(mce_hw_to_dev(hw), "%s: failed err:%d err_code:%d\n", __func__,
		err, resp.cmd.err_code);
	return -EIO;
}

int mce_fw_get_capability(struct mce_hw *hw, struct port_abilities *ablity)
{
	union mbx_fw_cmd_req_data req_data;
	struct mbx_resp resp = {};
	union mbx_fw_cmd_resp_data *resp_data =
		(union mbx_fw_cmd_resp_data *)resp.data;
	int try_cnt = 3;
	int err;

	req_data.get_port_ablity.whoami = I_AM_DRV;

	while (try_cnt--) {
		err = mce_mbx_send_req(&hw->fw_mbx, GET_PORT_ABALITY,
				       req_data.data,
				       sizeof(req_data.get_port_ablity), &resp,
				       MBX_REQ_1MS * 1000);
		if (err == 0)
			break;
	}

	if (err != 0) {
		dev_err(mce_hw_to_dev(hw),
			"%s: failed err:%d 0x%x,0x%x,%u,%u\n", __func__, err,
			raw_rd32(hw->fw_mbx.pf2peer_ctrl),
			raw_rd32(hw->fw_mbx.peer2pf_ctrl), rd32(hw, 0x3303c),
			rd32(hw, 0x33038));

		return -EIO;
	}

	memcpy(ablity, resp.data, sizeof(*ablity));

	hw->fw_version = resp_data->ablity.fw_version;
	hw->pfvfnum.pf = ablity->nr_pf;
	hw->nr_pf = hw->pfvfnum.pf;

	if (ablity->vf_max_ring < hw->vf_min_ring_cnt) {
		dev_warn(mce_hw_to_dev(hw),
			 "%s: change vf_max_ring from %d to %d\n", __func__,
			 ablity->vf_max_ring, hw->vf_min_ring_cnt);
		ablity->vf_max_ring = hw->vf_min_ring_cnt;
	}

	hw->pcie_isolate_on = !ablity->vf_isolation_disabled;

	dev_info(mce_hw_to_dev(hw),
		 "%s: pcie%d isolate on:%d vf_max_ring:%d fw-version:0x%08x max-speed:%d axi_mhz:%d rpu_avail:%d\n",
		__func__, ablity->nr_pf, hw->pcie_isolate_on,
		ablity->vf_max_ring, hw->fw_version, ablity->max_speed,
		ablity->axi_mhz, ablity->rpu_available);
	return 0;
}

int mce_mbx_set_vf_max_queue_cnt(struct mce_hw *hw, u32 vf_max_queue_cnt)
{
	struct mce_pf *pf = (struct mce_pf *)hw->back;
	union mbx_fw_cmd_req_data req_data;
	int err = 0, try_cnt = 4;

	if (vf_max_queue_cnt > hw->vf_max_ring_cnt ||
	    vf_max_queue_cnt < hw->vf_min_ring_cnt) {
		dev_err(hw->dev,
			"%s: vf_max_queue_cnt:%d, value range >=%d or <=%d\n",
			hw->fw_mbx.name, vf_max_queue_cnt, hw->vf_min_ring_cnt,
			hw->vf_max_ring_cnt);
		return -EINVAL;
	}

	if (!is_power_of_2(vf_max_queue_cnt)) {
		dev_err(hw->dev,
			"%s: vf_max_queue_cnt:%d should be power of 2\n",
			hw->fw_mbx.name, vf_max_queue_cnt);
		return -EINVAL;
	}

	req_data.vf_max_queue_cnt.max_cnt = vf_max_queue_cnt;
	req_data.vf_max_queue_cnt.vf_isolation_disable = 0;

	while (try_cnt--) {
		err = mce_mbx_send_req(&hw->fw_mbx, SET_VF_MAX_QUEUE,
				       req_data.data,
				       sizeof(req_data.vf_max_queue_cnt), NULL,
				       MBX_REQ_1MS * 1000);
		if (err == 0)
			break;
	}

	if (err)
		return -EIO;
	hw->vf_max_ring = vf_max_queue_cnt;
	set_bit(MCE_FLAG_PF_SET_VF_MAX_RING_PENDING, pf->flags);
	dev_info(hw->dev, "%s: config vf_max_queue_cnt:%d\n", hw->fw_mbx.name,
		 vf_max_queue_cnt);
	return 0;
}

void mce_mbx_fw_req_isr(struct mce_mbx_info *mbx, struct mbx_req *req)
{
	int opcode __maybe_unused = req->cmd.opcode;
	enum MBX_REQ_STAT stat = RESP_OR_ACK;
	struct mbx_resp resp = {};

	resp.cmd.v = req->cmd.v;
	resp.cmd.err_code = 0;
	resp.cmd.flag_no_resp = 1; /* default no resp */

	mbx_logd(LOG_MBX_IN_REQ,
		 "%s: req-opcode:%d 0x%08x 0x%08x 0x%08x 0x%08x\n", mbx->name,
		 req->cmd.opcode, req->data[0], req->data[1], req->data[2],
		 req->data[3]);

	mce_mbx_send_resp_isr(mbx, &resp);

	mce_mbx_clear_peer_req_irq_with_stat(mbx, stat);
}

static int mce_mbx_fw_handle_link_event(struct mce_mbx_info *mbx, int linkup)
{
	struct mce_hw *hw = mbx->hw;
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_port_info *pi = hw->port_info;
	struct fw_stat *fwstat = &hw->fw_stat;

	hw->ops->update_fw_stat(hw);

	pi->link_up = !!linkup;
	pi->link_speed = speed_unzip(fwstat->stat0.s_speed);
	pi->link_duplex = fwstat->stat0.duplex;

	set_bit(MCE_FLAG_PF_UPDATE_LINK, pf->flags);
	mce_service_task_schedule(pf);

	hw_logd(LOG_LINK_INFO, "%s: linkup:%d speed:%d duplex:%d\n", __func__,
		pi->link_up, pi->link_speed, pi->link_duplex);
	return 0;
}

void mce_mbx_fw_event_req_isr(struct mce_mbx_info *mbx, int event_id)
{
	struct mce_hw *hw = mbx->hw;

	mbx_logd(LOG_MBX_IN_REQ, "%s: event_id:%d\n", mbx->name, event_id);

	switch (event_id) {
	case EVT_PORT_LINK_UP:
		mce_mbx_fw_handle_link_event(mbx, 1);
		break;
	case EVT_PORT_LINK_DOWN:
		mce_mbx_fw_handle_link_event(mbx, 0);
		break;
	case EVT_SFP_PLUGIN_OUT:
		dev_info(&hw->pdev->dev, "port cable unplugged\n");
		break;
	case EVT_SFP_PLUGIN_IN:
		dev_info(&hw->pdev->dev, "port cable plugged\n");
		break;
	}
}

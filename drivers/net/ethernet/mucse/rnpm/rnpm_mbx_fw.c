// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 - 2023 Mucse Corporation. */

#include <linux/wait.h>
#include <linux/sem.h>
#include <linux/semaphore.h>
#include <linux/mutex.h>
#include "rnpm.h"
#include "rnpm_mbx.h"
#include "rnpm_mbx_fw.h"

#define RNP_FW_MAILBOX_SIZE RNPM_VFMAILBOX_SIZE

struct mbx_req_cookie *mbx_cookie_zalloc(int priv_len)
{
	struct mbx_req_cookie *cookie =
		kzalloc(sizeof(*cookie) + priv_len, GFP_KERNEL);

	if (cookie) {
		cookie->timeout_jiffes = 30 * HZ;
		cookie->magic = COOKIE_MAGIC;
		cookie->priv_len = priv_len;
	}

	return cookie;
}

int rnpm_mbx_write_posted_locked(struct rnpm_hw *hw, struct mbx_fw_cmd_req *req)
{
	int err = 0;
	int retry = 3;
	struct rnpm_pf_adapter *pf_adapter = pci_get_drvdata(hw->pdev);

	if (mutex_lock_interruptible(hw->mbx.lock)) {
		rnpm_err(
			"[%s] get mbx lock faild opcode:0x%x\n", __func__, req->opcode);
		return -EAGAIN;
	}
	if (test_bit(__RNPM_REMOVING, &pf_adapter->state)) {
		err = RNPM_MBX_ERR_IN_REMOVING;
		goto error;
	}
	rnpm_logd(LOG_MBX_LOCK,
			  "%s %d lock:%p hw:%p opcode:0x%x\n",
			  __func__,
			  hw->pfvfnum,
			  hw->mbx.lock,
			  hw,
			  req->opcode);

try_again:
	retry--;
	if (retry < 0) {
		mutex_unlock(hw->mbx.lock);
		rnpm_err("%s: write_posted faild! err:0x%x opcode:0x%x\n",
				 __func__,
				 err,
				 req->opcode);
		return -EIO;
	}

	err = hw->mbx.ops.write_posted(
		hw, (u32 *)req, (req->datalen + MBX_REQ_HDR_LEN) / 4, MBX_FW);
	if (err)
		goto try_again;

error:
	mutex_unlock(hw->mbx.lock);

	return err;
}

/*
 * force firmware report link event to driver
 */
void rnpm_link_stat_mark_reset(struct rnpm_hw *hw)
{
	wr32(hw, RNPM_DMA_DUMY, 0xa5a40000);
}

void rnpm_link_stat_mark_disable(struct rnpm_hw *hw)
{
	wr32(hw, RNPM_DMA_DUMY, 0x0);
}

int rnpm_mbx_fw_post_req(struct rnpm_hw *hw,
						 struct mbx_fw_cmd_req *req,
						 struct mbx_req_cookie *cookie)
{
	int err = 0;
	struct rnpm_pf_adapter *pf_adapter = pci_get_drvdata(hw->pdev);

	cookie->errcode = 0;
	cookie->done = 0;
	init_waitqueue_head(&cookie->wait);

	if (mutex_lock_interruptible(hw->mbx.lock)) {
		rnpm_err(
			"[%s] wait mbx lock timeout opcode:0x%x\n", __func__, req->opcode);
		return -EAGAIN;
	}

	if (test_bit(__RNPM_REMOVING, &pf_adapter->state)) {
		err = RNPM_MBX_ERR_IN_REMOVING;
		goto error;
	}

	rnpm_logd(LOG_MBX_LOCK,
			  "%s %d lock:%p hw:%p opcode:0x%x\n",
			  __func__,
			  hw->pfvfnum,
			  hw->mbx.lock,
			  hw,
			  req->opcode);

	err = rnpm_write_mbx(hw, (u32 *)req,
			     (req->datalen + MBX_REQ_HDR_LEN) / 4, MBX_FW);
	if (err) {
		rnpm_err(
			"rnpm_write_mbx faild! err:%d opcode:0x%x\n", err, req->opcode);
		mutex_unlock(hw->mbx.lock);
		return err;
	}

	if (cookie->timeout_jiffes != 0) {
retry:
		err = wait_event_interruptible_timeout(cookie->wait, cookie->done == 1,
											   cookie->timeout_jiffes);
		if (err == -ERESTARTSYS)
			goto retry;
		if (err == 0) {
			rnpm_err("%s faild! timeout err:%d opcode:%x\n",
					 __func__,
					 err,
					 req->opcode);
			err = -ETIME;
		} else {
			err = 0;
		}
	} else {
		wait_event_interruptible(cookie->wait, cookie->done == 1);
	}

	if (cookie->errcode)
		err = cookie->errcode;

error:
	mutex_unlock(hw->mbx.lock);

	return err;
}

int rnpm_fw_send_cmd_wait(struct rnpm_hw *hw,
						  struct mbx_fw_cmd_req *req,
						  struct mbx_fw_cmd_reply *reply)
{
	int err = 0;
	int retry_cnt = 3;
	struct rnpm_pf_adapter *pf_adapter = pci_get_drvdata(hw->pdev);

	if (!hw || !req || !reply || !hw->mbx.ops.read_posted) {
		rnpm_info("error: hw:%p req:%p reply:%p\n", hw, req, reply);
		return -EINVAL;
	}

	if (mutex_lock_interruptible(hw->mbx.lock)) {
		rnpm_err(
			"[%s] get mbx lock faild opcode:0x%x\n", __func__, req->opcode);
		return -EAGAIN;
	}

	if (test_bit(__RNPM_REMOVING, &pf_adapter->state)) {
		err = RNPM_MBX_ERR_IN_REMOVING;
		goto error;
	}

	rnpm_logd(LOG_MBX_LOCK,
			  "%s %d lock:%p hw:%p opcode:0x%x\n",
			  __func__,
			  hw->pfvfnum,
			  hw->mbx.lock,
			  hw,
			  req->opcode);

	err = hw->mbx.ops.write_posted(
		hw, (u32 *)req, (req->datalen + MBX_REQ_HDR_LEN) / 4, MBX_FW);
	if (err) {
		rnpm_err("%s: write_posted faild! err:0x%x opcode:0x%x\n",
				 __func__,
				 err,
				 req->opcode);
		goto quit;
	}

// ignore link-status event
retry:
	retry_cnt--;
	if (retry_cnt < 0) {
		err = -EIO;
		goto quit;
	}
	err = hw->mbx.ops.read_posted(hw, (u32 *)reply, sizeof(*reply) / 4, MBX_FW);
	if (err) {
		rnpm_err("%s: read_posted faild! err:0x%x opcode:0x%x\n",
				 __func__,
				 err,
				 req->opcode);
		mutex_unlock(hw->mbx.lock);
		return err;
	}
	if (reply->opcode != req->opcode)
		goto retry;

	if (req->reply_lo) {
		memcpy(reply, hw->mbx.reply_dma, sizeof(*reply));
		memset(hw->mbx.reply_dma, 0, 16);
	}

	if (reply->error_code) {
		rnpm_err("%s: reply err:0x%x req:0x%x\n",
				 __func__,
				 reply->error_code,
				 req->opcode);
		err = -reply->error_code;
		goto quit;
	}
quit:
error:
	mutex_unlock(hw->mbx.lock);
	return err;
}

int rnpm_mbx_get_link(struct rnpm_hw *hw)
{
	struct rnpm_adapter *adpt = hw->back;
	int v = rd32(hw, RNPM_TOP_NIC_DUMMY);

	if ((v & 0xff000000) == 0xa5000000) {
		hw->link = (v & BIT(hw->nr_lane)) ? 1 : 0;
		adpt->flags |= RNPM_FLAG_NEED_LINK_UPDATE;

		return 0;
	}
	return -1;
}

int rnpm_mbx_get_lane_stat(struct rnpm_hw *hw)
{
	int err = 0;
	struct mbx_fw_cmd_req req;
	struct rnpm_adapter *adpt = hw->back;
	struct lane_stat_data *st;
	struct mbx_req_cookie *cookie = NULL;
	struct mbx_fw_cmd_reply reply;

	memset(&req, 0, sizeof(req));

	if (hw->mbx.irq_enabled) {
		cookie = mbx_cookie_zalloc(sizeof(struct lane_stat_data));

		if (!cookie) {
			rnpm_err("%s: no memory\n", __func__);
			return -ENOMEM;
		}

		st = (struct lane_stat_data *)cookie->priv;

		build_get_lane_status_req(&req, hw->nr_lane, cookie);

		err = rnpm_mbx_fw_post_req(hw, &req, cookie);
		if (err) {
			if (err != RNPM_MBX_ERR_IN_REMOVING) {
				rnpm_err("%s: error:%d\n", __func__, err);
				WARN_ON(1);
			}
			goto quit;
		}
	} else {
		memset(&reply, 0, sizeof(reply));
		build_get_lane_status_req(&req, hw->nr_lane, &req);
		err = rnpm_fw_send_cmd_wait(hw, &req, &reply);
		if (err) {
			if (err != RNPM_MBX_ERR_IN_REMOVING)
				rnpm_err("%s: 1 error:%d\n", __func__, err);
			goto quit;
		}
		st = (struct lane_stat_data *)&(reply.data);
	}

	hw->phy_type = st->phy_type;
	hw->speed = adpt->speed = st->speed;
	if (st->is_sgmii) {
		adpt->phy_addr = st->phy_addr;
	} else {
		adpt->sfp.fault = st->sfp.fault;
		adpt->sfp.los = st->sfp.los;
		adpt->sfp.mod_abs = st->sfp.mod_abs;
		adpt->sfp.tx_dis = st->sfp.tx_dis;
	}

	adpt->si.main = st->si_main;
	adpt->si.pre = st->si_pre;
	adpt->si.post = st->si_post;
	adpt->si.tx_boost = st->si_tx_boost & 0xf;
	adpt->an = st->an;
	adpt->link_traing = st->link_traing;
	adpt->fec = st->fec;
	hw->is_sgmii = st->is_sgmii;
	hw->pci_gen = st->pci_gen;
	hw->pci_lanes = st->pci_lanes;
	adpt->speed = st->speed;
	adpt->hw.link = st->linkup;
	hw->is_backplane = st->is_backplane;
	hw->supported_link = st->supported_link;
	if (hw->fw_version <= 0x00050000)
		hw->duplex = 1;
	else
		hw->duplex = st->duplex;

	rnpm_logd(
		LOG_MBX_LINK_STAT,
		"%s:pma_type:0x%x phy_type:0x%x,linkup:%d speed=%d duplex:%d auton:%d ",
		adpt->name, st->pma_type, st->phy_type, st->linkup, st->speed,
		st->duplex, st->autoneg);
	rnpm_logd(
		LOG_MBX_LINK_STAT,
		"fec:%d an:%d lt:%d is_sgmii:%d supported_link:0x%x, backplane:%d ",
		st->fec, st->an, st->link_traing, st->is_sgmii,
		hw->supported_link, hw->is_backplane);
	rnpm_logd(LOG_MBX_LINK_STAT, "phy_addr:0x%x\n", adpt->phy_addr);
quit:
	kfree(cookie);
	return err;
}

int rnpm_mbx_get_phy_statistics(struct rnpm_hw *hw, u8 *data)
{
	int err = 0;
	struct mbx_fw_cmd_req req;

	memset(&req, 0, sizeof(req));

	if (hw->mbx.irq_enabled) {
		struct mbx_req_cookie *cookie =
			mbx_cookie_zalloc(sizeof(struct phy_statistics));

		if (!cookie)
			return -ENOMEM;

		build_get_phy_statistics_req(&req, hw->nr_lane, cookie);
		err = rnpm_mbx_fw_post_req(hw, &req, cookie);
		if (err == 0)
			memcpy(data, cookie->priv,
			       sizeof(struct phy_statistics));
		kfree(cookie);
	} else {
		struct mbx_fw_cmd_reply reply;

		memset(&reply, 0, sizeof(reply));
		build_get_phy_statistics_req(&req, hw->nr_lane, &req);
		return rnpm_fw_send_cmd_wait(hw, &req, &reply);
	}

	return err;
}

int rnpm_mbx_fw_reset_phy(struct rnpm_hw *hw)
{
	struct mbx_fw_cmd_req req;
	struct mbx_fw_cmd_reply reply;
	int ret;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	if (hw->mbx.irq_enabled) {
		struct mbx_req_cookie *cookie = mbx_cookie_zalloc(0);

		if (!cookie)
			return -ENOMEM;

		build_reset_phy_req(&req, cookie);
		ret = rnpm_mbx_fw_post_req(hw, &req, cookie);
		kfree(cookie);
		return ret;
	}
	build_reset_phy_req(&req, &req);
	return rnpm_fw_send_cmd_wait(hw, &req, &reply);
}

int rnpm_maintain_req(struct rnpm_hw *hw,
					  int cmd,
					  int arg0,
					  int req_data_bytes,
					  int reply_bytes,
					  dma_addr_t dma_phy_addr)
{
	int err;
	struct mbx_req_cookie *cookie = NULL;
	struct mbx_fw_cmd_req req;
	struct mbx_fw_cmd_reply reply;
	u64 address = dma_phy_addr;

	cookie = mbx_cookie_zalloc(0);
	if (!cookie)
		return -ENOMEM;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));
	cookie->timeout_jiffes = 60 * HZ; // 60s
	build_maintain_req(&req, cookie, cmd, arg0, req_data_bytes, reply_bytes,
			   address & 0xffffffff, (address >> 32) & 0xffffffff);
	if (hw->mbx.irq_enabled) {
		cookie->timeout_jiffes = 400 * HZ;
		err = rnpm_mbx_fw_post_req(hw, &req, cookie);
	} else {
		int old_mbx_timeout = hw->mbx.timeout;

		hw->mbx.timeout = (400 * 1000 * 1000) / hw->mbx.usec_delay; // wait 30s
		err = rnpm_fw_send_cmd_wait(hw, &req, &reply);
		hw->mbx.timeout = old_mbx_timeout;
	}
	kfree(cookie);

	return (err) ? -EIO : 0;
}

int rnpm_fw_get_macaddr(struct rnpm_hw *hw,
						int pfvfnum,
						u8 *mac_addr,
						int nr_lane)
{
	int err;
	struct mbx_fw_cmd_req req;
	struct mbx_fw_cmd_reply reply;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	rnpm_dbg("%s: pfvfnum:0x%x nr_lane:%d\n", __func__, pfvfnum, nr_lane);

	if (!mac_addr) {
		rnpm_err("%s: mac_addr is null\n", __func__);
		return -EINVAL;
	}

	if (hw->mbx.irq_enabled) {
		struct mbx_req_cookie *cookie =
			mbx_cookie_zalloc(sizeof(reply.mac_addr));
		struct mac_addr *mac;

		if (!cookie)
			return -ENOMEM;
		mac = (struct mac_addr *)cookie->priv;

		build_get_macaddress_req(&req, 1 << nr_lane, pfvfnum, cookie);

		err = rnpm_mbx_fw_post_req(hw, &req, cookie);
		if (err) {
			kfree(cookie);
			return err;
		}
		hw->ccode = mac->ccode;

		if ((1 << nr_lane) & mac->lanes) {
			memcpy(mac_addr, mac->addrs[nr_lane].mac, 6);
			kfree(cookie);
			return 0;
		}
		kfree(cookie);
		return -ENODATA;
	}
	build_get_macaddress_req(&req, 1 << nr_lane, pfvfnum, &req);
	err = rnpm_fw_send_cmd_wait(hw, &req, &reply);
	if (err) {
		if (err != RNPM_MBX_ERR_IN_REMOVING)
			rnpm_err("%s: faild. err:%d\n", __func__, err);
		return err;
	}

	hw->ccode = reply.mac_addr.ccode;
	if ((1 << nr_lane) & reply.mac_addr.lanes) {
		memcpy(mac_addr, reply.mac_addr.addrs[nr_lane].mac, 6);
		return 0;
	}

	return -ENODATA;
}

static int rnpm_mbx_sfp_read(
	struct rnpm_hw *hw, int sfp_i2c_addr, int reg, int cnt, u8 *out_buf)
{
	struct mbx_fw_cmd_req req;
	int err = -EIO;
	int nr_lane = hw->nr_lane;

	if ((cnt > MBX_SFP_READ_MAX_CNT) || !out_buf) {
		rnpm_err("%s: cnt:%d should <= %d out_buf:%p\n",
				 __func__,
				 cnt,
				 MBX_SFP_READ_MAX_CNT,
				 out_buf);
		return -EINVAL;
	}

	memset(&req, 0, sizeof(req));

	if (hw->mbx.irq_enabled) {
		struct mbx_req_cookie *cookie = mbx_cookie_zalloc(cnt);

		if (!cookie)
			return -ENOMEM;
		build_mbx_sfp_read(&req, nr_lane, sfp_i2c_addr, reg, cnt, cookie);

		err = rnpm_mbx_fw_post_req(hw, &req, cookie);
		if (err) {
			kfree(cookie);
			return err;
		}
		memcpy(out_buf, cookie->priv, cnt);
		err = 0;
		kfree(cookie);
	} else {
		struct mbx_fw_cmd_reply reply;

		memset(&reply, 0, sizeof(reply));
		build_mbx_sfp_read(&req, nr_lane, sfp_i2c_addr, reg, cnt, &reply);

		err = rnpm_fw_send_cmd_wait(hw, &req, &reply);
		if (err == 0)
			memcpy(out_buf, reply.sfp_read.value, cnt);
	}

	return err;
}

int rnpm_mbx_sfp_module_eeprom_info(
	struct rnpm_hw *hw, int sfp_addr, int reg, int data_len, u8 *buf)
{
	int left = data_len;
	int cnt, err;

	do {
		cnt = (left > MBX_SFP_READ_MAX_CNT) ? MBX_SFP_READ_MAX_CNT : left;
		err = rnpm_mbx_sfp_read(hw, sfp_addr, reg, cnt, buf);
		if (err) {
			rnpm_err("%s: error:%d\n", __func__, err);
			return err;
		}
		reg += cnt;
		buf += cnt;
		left -= cnt;
	} while (left > 0);

	return 0;
}

int rnpm_mbx_sfp_write(struct rnpm_hw *hw, int sfp_addr, int reg, short v)
{
	struct mbx_fw_cmd_req req;
	int err;
	int nr_lane = hw->nr_lane;

	memset(&req, 0, sizeof(req));

	build_mbx_sfp_write(&req, nr_lane, sfp_addr, reg, v);

	err = rnpm_mbx_write_posted_locked(hw, &req);
	return err;
}

int rnpm_mbx_fw_reg_read(struct rnpm_hw *hw, int fw_reg)
{
	struct mbx_fw_cmd_req req;
	struct mbx_fw_cmd_reply reply;
	int err, ret = 0xffffffff;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	if (hw->mbx.irq_enabled) {
		struct mbx_req_cookie *cookie = mbx_cookie_zalloc(sizeof(reply.r_reg));

		if (!cookie)
			return -ENOMEM;
		build_readreg_req(&req, fw_reg, cookie);

		err = rnpm_mbx_fw_post_req(hw, &req, cookie);
		if (err) {
			kfree(cookie);
			return ret;
		}
		ret = ((int *)(cookie->priv))[0];
	} else {
		build_readreg_req(&req, fw_reg, &reply);
		err = rnpm_fw_send_cmd_wait(hw, &req, &reply);
		if (err) {
			if (err != RNPM_MBX_ERR_IN_REMOVING)
				rnpm_err("%s: faild. err:%d\n", __func__, err);
			return err;
		}
		ret = reply.r_reg.value[0];
	}
	return ret;
}

int rnpm_mbx_reg_write(struct rnpm_hw *hw, int fw_reg, int value)
{
	struct mbx_fw_cmd_req req;
	int err;

	memset(&req, 0, sizeof(req));
	if (hw->fw_version < 0x00050200)
		return -EOPNOTSUPP;
	build_writereg_req(&req, NULL, fw_reg, 4, &value);
	err = rnpm_mbx_write_posted_locked(hw, &req);

	return err;
}

int rnpm_mbx_reg_writev(struct rnpm_hw *hw, int fw_reg, int value[4], int bytes)
{
	struct mbx_fw_cmd_req req;
	int err;

	memset(&req, 0, sizeof(req));
	build_writereg_req(&req, NULL, fw_reg, bytes, value);
	err = rnpm_mbx_write_posted_locked(hw, &req);

	return err;
}

int rnpm_mbx_lldp_all_ports_enable(struct rnpm_hw *hw, bool enable)
{
	struct mbx_fw_cmd_req req;
	int					  err;

	if (!hw->fw_lldp_ablity)
		return -EOPNOTSUPP;

	memset(&req, 0, sizeof(req));

	build_lldp_ctrl_set(&req, LLDP_TX_ALL_LANES, enable);

	err = rnpm_mbx_write_posted_locked(hw, &req);
	return err;
}

int rnpm_mbx_lldp_port_enable(struct rnpm_hw *hw, bool enable)
{
	struct mbx_fw_cmd_req req;
	int					  err;
	int					  nr_lane = hw->nr_lane;

	if (!hw->fw_lldp_ablity) {
		rnpm_warn("lldp set not supported\n");
		return -EOPNOTSUPP;
	}

	memset(&req, 0, sizeof(req));

	build_lldp_ctrl_set(&req, nr_lane, enable);

	err = rnpm_mbx_write_posted_locked(hw, &req);
	return err;
}

int rnpm_mbx_lldp_status_get(struct rnpm_hw *hw)
{
	struct mbx_fw_cmd_req	req;
	struct mbx_fw_cmd_reply reply;
	int						err, ret = 0;

	if (!hw->fw_lldp_ablity) {
		rnpm_warn("fw lldp not supported\n");
		return -EOPNOTSUPP;
	}

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	if (hw->mbx.irq_enabled) {
		struct mbx_req_cookie *cookie = mbx_cookie_zalloc(sizeof(reply.lldp));

		if (!cookie)
			return -ENOMEM;
		build_lldp_ctrl_get(&req, hw->nr_lane, cookie);

		err = rnpm_mbx_fw_post_req(hw, &req, cookie);
		if (err) {
			kfree(cookie);
			return ret;
		}
		ret = ((int *)(cookie->priv))[0];
	} else {
		build_lldp_ctrl_get(&req, hw->nr_lane, &reply);
		err = rnpm_fw_send_cmd_wait(hw, &req, &reply);
		if (err) {
			if (err != RNPM_MBX_ERR_IN_REMOVING)
				rnpm_err("%s: faild. err:%d\n", __func__, err);
			return err;
		}
		ret = reply.lldp.enable_stat;
	}
	return ret;
}

int rnpm_mbx_wol_set(struct rnpm_hw *hw, u32 mode)
{
	struct mbx_fw_cmd_req req;
	int err;
	int nr_lane = hw->nr_lane;

	memset(&req, 0, sizeof(req));

	build_mbx_wol_set(&req, nr_lane, mode);

	err = rnpm_mbx_write_posted_locked(hw, &req);
	return err;
}

int rnpm_mbx_set_dump(struct rnpm_hw *hw, int flag)
{
	int err;
	struct mbx_fw_cmd_req req;

	memset(&req, 0, sizeof(req));
	build_set_dump(&req, hw->nr_lane, flag);

	err = rnpm_mbx_write_posted_locked(hw, &req);

	return err;
}

int rnpm_mbx_get_dump(struct rnpm_hw *hw, int flags, u8 *data_out, int bytes)
{
	int err;
	struct mbx_req_cookie *cookie = NULL;

	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	struct get_dump_reply *get_dump;
	u64 address;

	void *dma_buf = NULL;
	dma_addr_t dma_phy = 0;

	cookie = mbx_cookie_zalloc(sizeof(*get_dump));
	if (!cookie)
		return -ENOMEM;

	get_dump = (struct get_dump_reply *)cookie->priv;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	if (bytes > sizeof(get_dump->data)) {
		dma_buf =
			dma_alloc_coherent(&hw->pdev->dev, bytes, &dma_phy, GFP_ATOMIC);
		if (!dma_buf) {
			dev_err(&hw->pdev->dev, "%s: no memory:%d!", __func__, bytes);
			err = -ENOMEM;
			goto quit;
		}
	}
	address = dma_phy;
	build_get_dump_req(&req, cookie, hw->nr_lane, address & 0xffffffff,
			   (address >> 32) & 0xffffffff, bytes);

	if (hw->mbx.irq_enabled) {
		err = rnpm_mbx_fw_post_req(hw, &req, cookie);
	} else {
		err = rnpm_fw_send_cmd_wait(hw, &req, &reply);
		get_dump = &reply.get_dump;
	}

quit:
	if (err == 0) {
		hw->dump.version = get_dump->version;
		hw->dump.flag = get_dump->flags;
		hw->dump.len = get_dump->bytes;
	}
	if (err == 0 && data_out) {
		if (dma_buf)
			memcpy(data_out, dma_buf, bytes);
		else
			memcpy(data_out, get_dump->data, bytes);
	}
	if (dma_buf)
		dma_free_coherent(&hw->pdev->dev, bytes, dma_buf, dma_phy);
	kfree(cookie);

	return err ? -err : 0;
}

int rnpm_mbx_force_speed(struct rnpm_hw *hw, int speed)
{
	struct rnpm_adapter *adapter = (struct rnpm_adapter *)hw->back;
	int cmd = 0x01150000;

	if ((hw->fw_version < 0x00050201) || hw->is_sgmii)
		return -EINVAL;

	if (adapter->pf_adapter->adapter_cnt == 4)
		cmd |= 0x200;

	if (speed == RNPM_LINK_SPEED_10GB_FULL) {
		cmd |= 0x2;
		hw->force_speed_stat = FORCE_SPEED_STAT_10G;
	} else if (speed == RNPM_LINK_SPEED_1GB_FULL) {
		cmd |= 0x1;
		hw->force_speed_stat = FORCE_SPEED_STAT_1G;
	} else {
		cmd |= 0x0;
		hw->force_speed_stat = FORCE_SPEED_STAT_DISABLED;
	}

	return rnpm_mbx_set_dump(hw, cmd);
}

int rnpm_fw_update(struct rnpm_hw *hw,
				   int partition,
				   const u8 *fw_bin,
				   int bytes)
{
	int err;
	struct mbx_req_cookie *cookie = NULL;
	struct mbx_fw_cmd_req req;
	struct mbx_fw_cmd_reply reply;
	void *dma_buf = NULL;
	dma_addr_t dma_phy;
	u64 address;

	cookie = mbx_cookie_zalloc(0);
	if (!cookie)
		return -ENOMEM;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	//  dma_buf = pci_alloc_consistent(hw->pdev, bytes, &dma_phy);
	dma_buf = dma_alloc_coherent(&hw->pdev->dev, bytes, &dma_phy, GFP_ATOMIC);
	if (!dma_buf) {
		err = -ENOMEM;
		goto quit;
	}

	memcpy(dma_buf, fw_bin, bytes);
	address = dma_phy;
	build_fw_update_req(&req, cookie, partition, address & 0xffffffff,
			    (address >> 32) & 0xffffffff, bytes);
	if (hw->mbx.irq_enabled) {
		cookie->timeout_jiffes = 400 * HZ;
		err = rnpm_mbx_fw_post_req(hw, &req, cookie);
	} else {
		int old_mbx_timeout = hw->mbx.timeout;

		hw->mbx.timeout = (400 * 1000 * 1000) / hw->mbx.usec_delay; // wait 400s
		err = rnpm_fw_send_cmd_wait(hw, &req, &reply);
		hw->mbx.timeout = old_mbx_timeout;
	}

quit:
	if (dma_buf)
		dma_free_coherent(&hw->pdev->dev, bytes, dma_buf, dma_phy);
	kfree(cookie);

	return (err) ? -EIO : 0;
}

int rnpm_mbx_pf_link_event_enable_nolock(struct rnpm_hw *hw, int enable)
{
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	int err, v;
#define DM_MAGIC_CODE 0xa5000000

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	if (enable) {
		v = rd32(hw, RNPM_DMA_DUMY);
		if (!!((v & GENMASK(31, 28)) - DM_MAGIC_CODE)) {
			v &= ~GENMASK(31, 28);
			v |= DM_MAGIC_CODE;
			wr32(hw, RNPM_DMA_DUMY, v);
		}
	} else {
		wr32(hw, RNPM_DMA_DUMY, 0);
	}

	build_link_set_event_mask(
		&req, BIT(EVT_LINK_UP), (enable & 1) << EVT_LINK_UP, &req);

	err = rnpm_mbx_write_posted_locked(hw, &req);

	return err;
}

int rnpm_mbx_pf_link_event_enable(struct rnpm_hw *hw, int enable)
{
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	int err;
	unsigned long flags;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	// dev_info(&hw->pdev->dev, "%s: lane%d %d\n", __func__, hw->nr_lane,
	// enable); dump_stack();

	if (enable) {
		struct rnpm_adapter *adapter = (struct rnpm_adapter *)hw->back;
		struct rnpm_pf_adapter *pf_adapter = adapter->pf_adapter;
		int v;

		spin_lock_irqsave(&pf_adapter->dummy_setup_lock, flags);
		v = rd32(hw, RNPM_DMA_DUMY);
		v &= 0x0000ffff;
		v |= 0xa5a40000;
		wr32(hw, RNPM_DMA_DUMY, v);
		spin_unlock_irqrestore(&pf_adapter->dummy_setup_lock, flags);
	} else {
		wr32(hw, RNPM_DMA_DUMY, 0);
	}

	build_link_set_event_mask(
		&req, BIT(EVT_LINK_UP), (enable & 1) << EVT_LINK_UP, &req);

	err = rnpm_mbx_write_posted_locked(hw, &req);

	return err;
}

int rnpm_mbx_pluginout_evt_en(struct rnpm_hw *hw, int in_dir, int enable)
{
	struct mbx_fw_cmd_req req;
	int err;

	build_pluginout_evt_notify(&req, hw->nr_lane, in_dir, !!enable, &req);

	err = rnpm_mbx_write_posted_locked(hw, &req);

	return err;
}

int rnpm_mbx_lane_link_changed_event_enable(struct rnpm_hw *hw, int enable)
{
	struct mbx_fw_cmd_req req;
	int err;

	if (hw->single_lane_link_evt_ctrl_ablity == 0)
		return rnpm_mbx_pf_link_event_enable(hw, enable);

	memset(&req, 0, sizeof(req));
	build_lane_link_change_notify(&req, hw->nr_lane, !!enable, &req);
	err = rnpm_mbx_write_posted_locked(hw, &req);

	return err;
}

int rnpm_fw_get_capablity(struct rnpm_hw *hw, struct phy_abilities *abil)
{
	int err;
	struct mbx_fw_cmd_req req;
	struct mbx_fw_cmd_reply reply;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	build_phy_abalities_req(&req, &req);

	err = rnpm_fw_send_cmd_wait(hw, &req, &reply);

	if (err == 0)
		memcpy(abil, &reply.phy_abilities, sizeof(*abil));
	return err;
}

int rnpm_set_lane_fun(
	struct rnpm_hw *hw, int fun, int value0, int value1, int value2, int value3)
{
	struct mbx_fw_cmd_req req;
	struct mbx_fw_cmd_reply reply;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	rnpm_logd(LOG_SET_LANE_FUN,
			  "%s: fun:%d %d-%d-%d-%d\n",
			  __func__,
			  fun,
			  value0,
			  value1,
			  value2,
			  value3);

	build_set_lane_fun(&req, hw->nr_lane, fun, value0, value1, value2, value3);

	return rnpm_mbx_write_posted_locked(hw, &req);
}

int rnpm_mbx_ifup_down(struct rnpm_hw *hw, int up)
{
	int err;
	struct mbx_fw_cmd_req req;
	struct mbx_fw_cmd_reply reply;
	struct rnpm_adapter *adpt = hw->back;
	// struct rnpm_pf_adapter *pf_adapter = pci_get_drvdata(hw->pdev);

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	build_ifup_down(&req, hw->nr_lane, up);

	rnpm_logd(LOG_MBX_IFUP_DOWN,
			  "%s:%s lane:%d up:%d\n",
			  __func__,
			  adpt->name,
			  hw->nr_lane,
			  up);

	if (mutex_lock_interruptible(hw->mbx.lock)) {
		rnpm_err("%s: get lock faild!\n", __func__);
		return -EAGAIN;
	}
	// if (test_bit(__RNPM_REMOVING, &pf_adapter->state))
	//	return RNPM_MBX_ERR_IN_REMOVING;

	err = hw->mbx.ops.write(
		hw, (u32 *)&req, (req.datalen + MBX_REQ_HDR_LEN) / 4, MBX_FW);
	mdelay(1);
	mutex_unlock(hw->mbx.lock);

	// force firmware report link-status
	// if (up) {
	//	rnpm_link_stat_mark_reset(hw);
	//}
	return err;
}

int rnpm_mbx_led_set(struct rnpm_hw *hw, int value)
{
	struct mbx_fw_cmd_req req;
	struct mbx_fw_cmd_reply reply;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	build_led_set(&req, hw->nr_lane, value, &reply);

	return rnpm_mbx_write_posted_locked(hw, &req);
}

__always_unused static int rnpm_nic_mode_convert_to_adapter_cnt(struct phy_abilities *ability)
{
	int adapter_cnt = 0;

	switch (ability->nic_mode) {
	case MODE_NIC_MODE_1PORT_40G:
	case MODE_NIC_MODE_1PORT:
		adapter_cnt = 1;
		break;
	case MODE_NIC_MODE_2PORT:
		adapter_cnt = 2;
		break;
	case MODE_NIC_MODE_4PORT:
		adapter_cnt = 4;
		break;
	default:
		adapter_cnt = 0;
		break;
	}

	return adapter_cnt;
}

int rnpm_mbx_get_capability(struct rnpm_hw *hw, struct rnpm_info *info)
{
	// struct rnpm_mbx_info *mbx = &hw->mbx;
	int err;
	struct phy_abilities ablity;
	int try_cnt = 3;

	// rnpm_mbx_reset(hw);

	memset(&ablity, 0, sizeof(ablity));

	rnpm_link_stat_mark_disable(hw);

	// enable CM3CPU to PF MBX IRQ
	// wr32(hw, CPU_PF_MBOX_MASK, 0);

	while (try_cnt--) {
		err = rnpm_fw_get_capablity(hw, &ablity);
		if (err == 0 && info) {
			hw->lane_mask = ablity.lane_mask & 0xf;
			// info->mac = to_mac_type(&ablity);
			info->adapter_cnt = Hamming_weight_1(hw->lane_mask);
			hw->mode = ablity.nic_mode;
			hw->pfvfnum = ablity.pfnum;
			hw->ablity_speed = hw->speed = ablity.speed;
			hw->nr_lane = 0; // PF1
			hw->fw_version = ablity.fw_version;
			// hw->mac_type = info->mac;
			hw->phy_type = rnpm_phy_unknown;
			hw->axi_mhz = ablity.axi_mhz;
			hw->port_ids = ablity.port_ids;
			hw->fw_uid = ablity.fw_uid;
			hw->phy.id = ablity.phy_id;
			hw->wol = ablity.wol_status;
			if (ablity.phy_type == PHY_TYPE_SGMII)
				hw->is_sgmii = 1;
			if (ablity.fw_version >= 0x00050200)
				hw->single_lane_link_evt_ctrl_ablity = 1;

			if (ablity.ext_ablity != 0xffffffff && ablity.valid) {
				hw->fw_lldp_ablity	 = ablity.fw_lldp_ablity;
				hw->ncsi_en = ablity.ncsi_en;
				hw->ncsi_rar_entries = 1;
				hw->rpu_en			 = ablity.rpu_en;
				if (hw->rpu_en)
					ablity.rpu_availble = 1;
				hw->rpu_availble = ablity.rpu_availble;
			} else {
				hw->ncsi_rar_entries = 0;
			}

			pr_info("%s: nic-mode:%d  adpt_cnt:%d lane_mask:0x%x, ",
				__func__, hw->mode, info->adapter_cnt,
				hw->lane_mask);
			pr_info("pfvfnum:0x%x, fw-version:0x%08x, axi:%d Mhz ",
				hw->pfvfnum, ablity.fw_version, ablity.axi_mhz);
			pr_info("port_id:%d-%d-%d-%d, uid:0x%08x sgmii:%d ext-ablity:0x%x",
				ablity.port_id[0], ablity.port_id[1],
				ablity.port_id[2], ablity.port_id[3],
				hw->fw_uid, hw->is_sgmii, ablity.ext_ablity);
			pr_info("ncsi:%u wol=0x%x rpu:%d-%d\n", hw->ncsi_en & 1,
				hw->wol, hw->rpu_en, hw->rpu_availble);
			if (info->adapter_cnt > 0)
				return 0;
		}
	}

	dev_err(&hw->pdev->dev, "%s: error!\n", __func__);

	return -EIO;
}

int rnpm_mbx_get_temp(struct rnpm_hw *hw, int *voltage)
{
	int err;
	struct mbx_req_cookie *cookie = NULL;
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	struct get_temp *temp;
	int temp_v = 0;

	cookie = mbx_cookie_zalloc(sizeof(*temp));
	if (!cookie)
		return -ENOMEM;
	temp = (struct get_temp *)cookie->priv;

	memset(&req, 0, sizeof(req));

	build_get_temp(&req, cookie);

	if (hw->mbx.irq_enabled) {
		err = rnpm_mbx_fw_post_req(hw, &req, cookie);
	} else {
		memset(&reply, 0, sizeof(reply));
		err = rnpm_fw_send_cmd_wait(hw, &req, &reply);
		temp = &reply.get_temp;
	}

	if (voltage)
		*voltage = temp->volatage;
	temp_v = temp->temp;
	kfree(cookie);

	return temp_v;
}
int rnpm_fw_reg_read(struct rnpm_hw *hw, int addr, int sz)
{
	struct mbx_req_cookie *cookie;
	struct mbx_fw_cmd_req req;
	int value;

	cookie = mbx_cookie_zalloc(sizeof(int));
	if (!cookie)
		return -ENOMEM;

	build_readreg_req(&req, addr, cookie);
	rnpm_mbx_fw_post_req(hw, &req, cookie);
	value = *((int *)cookie->priv);
	kfree(cookie);

	return 0;
}

void rnpm_link_stat_mark(struct rnpm_hw *hw, int nr_lane, int up)
{
	u32 v;
	struct rnpm_adapter *adapter = (struct rnpm_adapter *)hw->back;
	struct rnpm_pf_adapter *pf_adapter = adapter->pf_adapter;
	unsigned long flags;

	spin_lock_irqsave(&pf_adapter->dummy_setup_lock, flags);
	v = rd32(hw, RNPM_DMA_DUMY);
	v &= ~(0xffff0000);
	v |= 0xa5a40000;
	if (up)
		v |= BIT(nr_lane);
	else
		v &= ~BIT(nr_lane);
	wr32(hw, RNPM_DMA_DUMY, v);
	spin_unlock_irqrestore(&pf_adapter->dummy_setup_lock, flags);
}

void rnpm_mbx_probe_stat_set(struct rnpm_pf_adapter *pf_adapter, int stat)
{
#define RNPM_DMA_DUMMY_PROBE_STAT_BIT (4)
	unsigned long flags;
	struct rnpm_hw *hw = &pf_adapter->hw;
	u32 v;

	spin_lock_irqsave(&pf_adapter->dummy_setup_lock, flags);
	v = rd32(hw, RNPM_DMA_DUMY);
	v &= ~(0xffff0000);
	v |= 0xa5a40000;
	if (stat == MBX_PROBE)
		v |= BIT(RNPM_DMA_DUMMY_PROBE_STAT_BIT);
	else if (stat == MBX_REMOVE)
		v = 0xFFA5A6A7;
	else
		v &= ~BIT(RNPM_DMA_DUMMY_PROBE_STAT_BIT);
	wr32(hw, RNPM_DMA_DUMY, v);
	spin_unlock_irqrestore(&pf_adapter->dummy_setup_lock, flags);
}

int rnpm_hw_set_fw_10g_1g_auto_detch(struct rnpm_hw *hw, int enable)
{
	return rnpm_mbx_set_dump(hw, 0x01140000 | (enable & 1));
}

int rnpm_hw_set_clause73_autoneg_enable(struct rnpm_hw *hw, int enable)
{
	return rnpm_mbx_set_dump(hw, 0x010e0000 | (enable & 1));
}

static inline int rnpm_mbx_fw_req_handler(struct rnpm_pf_adapter *adapter,
										  struct mbx_fw_cmd_req *req)
{
	struct rnpm_hw *hw;
	// u32 value;
	int i, nr_lane;
	struct rnpm_adapter *adpt;
	struct port_stat *st;

	switch (req->opcode) {
	case PTP_EVENT: {
		rnpm_logd(LOG_PTP_EVT, "ptp event:lanes:0x%x\n",
			  req->ptp.lanes);
		rnpm_info("%s:ptp event:lanes:0x%x\n", __func__,
			  req->ptp.lanes);
		break;
	}
	case PLUG_EVENT: {
		for (i = 0; i < adapter->adapter_cnt; i++) {
			if (!rnpm_port_is_valid(adapter, i))
				continue;

			adpt = adapter->adapter[i];
			if (adpt == NULL)
				continue;
			hw = &adpt->hw;
			nr_lane = adpt->hw.nr_lane & 0b11;

			if (nr_lane == req->plugin_out.nr_lane) {
				rnpm_info("%s plu%s\n", adpt->name,
					  req->plugin_out.action ? "out" :
								   "in");
				break;
			}
		}
		break;
	}
	case LINK_STATUS_EVENT:
		rnpm_logd(
			LOG_LINK_EVENT,
			"link changed:changed_lane:0x%x status:0x%x speed:%d-%d-%d-%d\n",
			req->link_stat.changed_lanes,
			req->link_stat.lane_status, req->link_stat.st[0].speed,
			req->link_stat.st[1].speed, req->link_stat.st[2].speed,
			req->link_stat.st[3].speed);

		for (i = 0; i < adapter->adapter_cnt; i++) {
			if (!rnpm_port_is_valid(adapter, i))
				continue;

			adpt = adapter->adapter[i];
			if (adpt == NULL)
				continue;
			hw = &adpt->hw;
			nr_lane = adpt->hw.nr_lane & 0b11;

			if (BIT(nr_lane) &
			    req->link_stat.lane_status) { // linkup
				adpt->hw.link = 1;
				// rnpm_link_stat_mark(&adpt->hw, nr_lane, 1);
			} else {
				adpt->hw.link = 0;
				// rnpm_link_stat_mark(&adpt->hw, nr_lane, 0);
			}
			if ((BIT(i) & req->link_stat.changed_lanes) &&
			    req->link_stat.port_st_magic == SPEED_VALID_MAGIC) {
				st = &req->link_stat.st[nr_lane];
				adpt->speed = st->speed;
				adpt->phy_addr = st->phy_addr;
				adpt->an = st->autoneg ? true : false;
				adpt->duplex = st->duplex;
				adpt->flags |= RNPM_FLAG_NEED_LINK_UPDATE;
			}

			rnpm_logd(
				LOG_LINK_EVENT,
				"%s:%s:lane:%d link:%d speed:%d hw:%p phy_addr:0x%x\n",
				__func__, adpt->name, nr_lane, adpt->hw.link,
				adpt->speed, &adpt->hw, adpt->phy_addr);

			// rnpm_service_event_schedule(adpt);
		}
		set_bit(RNPM_PF_LINK_CHANGE, &adapter->flags);

		break;
	}

	return 0;
}

static inline int rnpm_mbx_fw_reply_handler(struct rnpm_pf_adapter *adapter,
											struct mbx_fw_cmd_reply *reply)
{
	struct mbx_req_cookie *cookie;

	// buf_dump("reply:", reply, sizeof(*reply));

	cookie = reply->cookie;
	if (!cookie || cookie->magic != COOKIE_MAGIC)
		return -EIO;

	if (cookie->priv_len > 0)
		memcpy(cookie->priv, reply->data, cookie->priv_len);
	cookie->done = 1;

	if (reply->flags & FLAGS_ERR)
		cookie->errcode = reply->error_code;
	else
		cookie->errcode = 0;
	wake_up_interruptible(&cookie->wait);

	return 0;
}

static inline int rnpm_rcv_msg_from_fw(struct rnpm_pf_adapter *adapter)
{
	u32 msgbuf[RNP_FW_MAILBOX_SIZE];
	struct rnpm_hw *hw = &adapter->hw;
	s32 retval;

	retval = rnpm_read_mbx(hw, msgbuf, RNP_FW_MAILBOX_SIZE, MBX_FW);
	if (retval) {
		rnpm_err("Error receiving message from FW:#%d ret:%d\n",
			 __LINE__, retval);
		return retval;
	}

	rnpm_logd(LOG_MBX_MSG_IN,
			  "msg[0]=0x%08x_0x%08x_0x%08x_0x%08x\n",
			  msgbuf[0],
			  msgbuf[1],
			  msgbuf[2],
			  msgbuf[3]);

	/* this is a message we already processed, do nothing */
	if (((unsigned short *)msgbuf)[0] & FLAGS_DD)
		return rnpm_mbx_fw_reply_handler(adapter,
										 (struct mbx_fw_cmd_reply *)msgbuf);
	else
		return rnpm_mbx_fw_req_handler(adapter,
					       (struct mbx_fw_cmd_req *)msgbuf);
}

static void rnpm_rcv_ack_from_fw(struct rnpm_pf_adapter *adapter)
{
}

int rnpm_fw_msg_handler(struct rnpm_pf_adapter *pf_adapter)
{
	// == check cpureq
	if (!rnpm_check_for_msg(&pf_adapter->hw, MBX_FW))
		rnpm_rcv_msg_from_fw(pf_adapter);

	/* process any acks */
	if (!rnpm_check_for_ack(&pf_adapter->hw, MBX_FW))
		rnpm_rcv_ack_from_fw(pf_adapter);

	return 0;
}

int rnpm_mbx_phy_write(struct rnpm_hw *hw, u32 reg, u32 val)
{
	struct mbx_fw_cmd_req req;
	char nr_lane = hw->nr_lane;

	memset(&req, 0, sizeof(req));
	build_set_phy_reg(&req, NULL, PHY_EXTERNAL_PHY_MDIO, nr_lane, reg, val, 0);

	return rnpm_mbx_write_posted_locked(hw, &req);
}

int rnpm_mbx_phy_read(struct rnpm_hw *hw, u32 reg, u32 *val)
{
	struct mbx_fw_cmd_req req;
	int err = -EIO;
	char nr_lane = hw->nr_lane;

	memset(&req, 0, sizeof(req));

	// dump_stack();

	if (hw->mbx.irq_enabled) {
		struct mbx_req_cookie *cookie = mbx_cookie_zalloc(4);

		if (!cookie)
			return -ENOMEM;
		build_get_phy_reg(&req, cookie, PHY_EXTERNAL_PHY_MDIO, nr_lane, reg);

		err = rnpm_mbx_fw_post_req(hw, &req, cookie);
		if (err) {
			kfree(cookie);
			return err;
		}
		memcpy(val, cookie->priv, 4);
		err = 0;
		kfree(cookie);
	} else {
		struct mbx_fw_cmd_reply reply;

		memset(&reply, 0, sizeof(reply));
		build_get_phy_reg(&req, &reply, PHY_EXTERNAL_PHY_MDIO, nr_lane, reg);

		err = rnpm_fw_send_cmd_wait(hw, &req, &reply);
		if (err == 0)
			*val = reply.r_reg.value[0];
	}
	return err;
}

int rnpm_mbx_phy_link_set(struct rnpm_hw *hw, int speeds)
{
	struct mbx_fw_cmd_req req;

	memset(&req, 0, sizeof(req));

	rnpm_info("%s:lane:%d speed:0x%x\n", __func__, hw->nr_lane, speeds);

	build_phy_link_set(&req, speeds, hw->nr_lane);

	return rnpm_mbx_write_posted_locked(hw, &req);
}

/*
 */
int rnpm_get_port_stats2(struct rnpm_hw *hw, int *pabs, int *pspeed, int *plink)
{
	unsigned int v;
	int link = 0, abs = 0, idx = 0, speed = 0;
	int speed_tb[6] = {10, 100, 1000, 10 * 1000, 25 * 1000, 40 * 1000};
#define LANES_STAT (0xa8000 + 64 * 64 - 4)
	v = rd32(hw, LANES_STAT);

	if ((v & 0xF0000000) != 0xA0000000)
		return -1;

	link = !!(v & BIT(hw->nr_lane));
	abs = !!(v & BIT(hw->nr_lane + 4));
	idx = (v >> 8) & 0xf;
	if ((idx <= 5))
		speed = speed_tb[idx];
	if (plink)
		*plink = link;
	if (pspeed)
		*pspeed = speed;
	if (pabs)
		*pabs = abs;

	return link;
}

int rnpm_mbx_sdram_simm(struct rnpm_hw *hw,
						u32 flags,
						u32 offset,
						void *dma_buf,
						dma_addr_t dma_phy,
						u32 len)
{
	int err;
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	u64 address;

	if (!dma_buf || dma_phy == 0) {
		dev_err(&hw->pdev->dev, "%s: no memory:%d!", __func__, len);
		return -ENOMEM;
	}

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));
	address = dma_phy;
	build_comm_sdram_req(&req, NULL, flags, offset, address & 0xffffffff,
			     (address >> 32) & 0xffffffff, len);

	if (hw->mbx.irq_enabled)
		rnpm_mbx_write_posted_locked(hw, &req);

	return err ? -err : 0;
}

// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 - 2026 Mucse Corporation. */

#include <linux/wait.h>
#include <linux/sem.h>
#include <linux/semaphore.h>
#include <linux/mutex.h>

#include "rnpgbe.h"
#include "rnpgbe_mbx.h"
#include "rnpgbe_mbx_fw.h"

#define RNP_FW_MAILBOX_SIZE RNP_VFMAILBOX_SIZE

static struct mbx_req_cookie *mbx_cookie_zalloc(int priv_len)
{
	struct mbx_req_cookie *cookie =
		kzalloc(sizeof(*cookie) + priv_len, GFP_KERNEL);

	if (cookie) {
		cookie->timeout_jiffes = 30 * HZ;
		cookie->magic = COOKIE_MAGIC;
		cookie->priv_len = priv_len;
		init_waitqueue_head(&cookie->wait);
	}

	return cookie;
}

static int rnpgbe_mbx_write_posted_locked(struct rnpgbe_hw *hw,
					  struct mbx_fw_cmd_req *req)
{
	int retry = 3;
	int err = 0;
	int length;

	/* if pcie off, nothing todo */
	if (pci_device_check_offline(hw->pdev))
		return -EIO;

	if (mutex_lock_interruptible(&hw->mbx.lock)) {
		rnpgbe_err("[%s] get mbx lock failed opcode:0x%x\n", __func__,
			   req->opcode);
		return -EAGAIN;
	}

	rnpgbe_logd(LOG_MBX_LOCK, "%s %d lock:%p hw:%p opcode:0x%x\n", __func__,
		    hw->pfvfnum, &hw->mbx.lock, hw, req->opcode);

try_again:
	retry--;
	if (retry < 0) {
		mutex_unlock(&hw->mbx.lock);
		rnpgbe_err("%s: write_posted failed! err:0x%x opcode:0x%x\n",
			   __func__, err, req->opcode);
		return -EIO;
	}

	length = (le16_to_cpu(req->datalen) + MBX_REQ_HDR_LEN) / 4;
	err = hw->mbx.ops.write_posted(hw, (u32 *)req, length, MBX_FW);
	if (err)
		goto try_again;

	mutex_unlock(&hw->mbx.lock);

	return err;
}

static void rnpgbe_link_stat_mark_reset(struct rnpgbe_hw *hw)
{
	hw_wr32(hw, RNP_DMA_DUMY, 0xa0000000);
}

static void rnpgbe_link_stat_mark_disable(struct rnpgbe_hw *hw)
{
	hw_wr32(hw, RNP_DMA_DUMY, 0);
}

static int rnpgbe_mbx_fw_post_req(struct rnpgbe_hw *hw,
				  struct mbx_fw_cmd_req *req,
				  struct mbx_req_cookie *cookie)
{
	struct rnpgbe_adapter *adpt = hw->back;
	int err = 0;
	int length;

	/* if pcie off, nothing todo */
	if (pci_device_check_offline(hw->pdev))
		return -EIO;

	cookie->errcode = 0;
	cookie->done = 0;
	//init_waitqueue_head(&cookie->wait);

	if (mutex_lock_interruptible(&hw->mbx.lock)) {
		rnpgbe_err("[%s] wait mbx lock timeout opcode:0x%x\n", __func__,
			   req->opcode);
		return -EAGAIN;
	}

	rnpgbe_logd(LOG_MBX_LOCK, "%s %d lock:%p hw:%p opcode:0x%x\n", __func__,
		    hw->pfvfnum, &hw->mbx.lock, hw, req->opcode);

	length = (le16_to_cpu(req->datalen) + MBX_REQ_HDR_LEN) / 4;
	err = rnpgbe_write_mbx(hw, (u32 *)req,
			       length, MBX_FW);
	if (err) {
		rnpgbe_err("rnpgbe_write_mbx failed! err:%d opcode:0x%x\n", err,
			   req->opcode);
		mutex_unlock(&hw->mbx.lock);
		return err;
	}

	if (cookie->timeout_jiffes != 0) {
		err = wait_event_timeout(cookie->wait,
					 cookie->done == 1,
					 cookie->timeout_jiffes);
		if (err == 0) {
			pr_debug("timeout?\n");
			rnpgbe_err("[%s] %s failed! pfvfnum:0x%x hw:%p timeout err:%d opcode:%x\n",
				   adpt->name, __func__, hw->pfvfnum, hw, err,
				   req->opcode);
			err = -ETIME;
		} else {
			err = 0;
		}
	} else {
		wait_event_interruptible(cookie->wait, cookie->done == 1);
	}

	mutex_unlock(&hw->mbx.lock);

	if (cookie->errcode)
		err = cookie->errcode;

	return err;
}

static int rnpgbe_fw_send_cmd_wait(struct rnpgbe_hw *hw,
				   struct mbx_fw_cmd_req *req,
				   struct mbx_fw_cmd_reply *reply)
{
	int retry_cnt = 3;
	int length;
	int err;

	if (!hw || !req || !reply || !hw->mbx.ops.read_posted) {
		rnpgbe_err("error: hw:%p req:%p reply:%p\n", hw, req,
			   reply);
		return -EINVAL;
	}

	/* if pcie off, nothing todo */
	if (pci_device_check_offline(hw->pdev))
		return -EIO;

	if (mutex_lock_interruptible(&hw->mbx.lock)) {
		rnpgbe_err("[%s] get mbx lock failed opcode:0x%x\n", __func__,
			   req->opcode);
		return -EAGAIN;
	}

	rnpgbe_logd(LOG_MBX_LOCK, "%s %d lock:%p hw:%p opcode:0x%x\n", __func__,
		    hw->pfvfnum, &hw->mbx.lock, hw, req->opcode);
	length = (le16_to_cpu(req->datalen) + MBX_REQ_HDR_LEN) / 4;
	err = hw->mbx.ops.write_posted(hw, (u32 *)req, length, MBX_FW);
	if (err) {
		rnpgbe_err("%s: write_posted failed! err:0x%x opcode:0x%x\n",
			   __func__, err, req->opcode);
		mutex_unlock(&hw->mbx.lock);
		return err;
	}

retry:
	retry_cnt--;
	if (retry_cnt < 0) {
		mutex_unlock(&hw->mbx.lock);
		return -EIO;
	}

	err = hw->mbx.ops.read_posted(hw, (u32 *)reply, sizeof(*reply) / 4,
				      MBX_FW);
	if (err) {
		rnpgbe_err("%s: read_posted failed! err:0x%x opcode:0x%x\n",
			   __func__, err, req->opcode);
		mutex_unlock(&hw->mbx.lock);
		return err;
	}
	if (reply->opcode != req->opcode)
		goto retry;

	mutex_unlock(&hw->mbx.lock);

	if (reply->error_code) {
		rnpgbe_err("%s: reply err:0x%x req:0x%x\n", __func__,
			   reply->error_code, req->opcode);
		return -le16_to_cpu(reply->error_code);
	}
	return 0;
}

int rnpgbe_mbx_get_lane_stat(struct rnpgbe_hw *hw)
{
	struct rnpgbe_adapter *adpt = hw->back;
	struct mbx_req_cookie *cookie = NULL;
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	struct lane_stat_data *st;
	int err = 0;

	memset(&req, 0, sizeof(req));

	if (hw->mbx.other_irq_enabled) {
		cookie = mbx_cookie_zalloc(sizeof(struct lane_stat_data));

		if (!cookie) {
			rnpgbe_err("%s: no memory\n", __func__);
			return -ENOMEM;
		}

		st = (struct lane_stat_data *)cookie->priv;
		build_get_lane_status_req(&req, hw->nr_lane, cookie);
		err = rnpgbe_mbx_fw_post_req(hw, &req, cookie);

		if (err) {
			rnpgbe_err("%s: error:%d\n", __func__, err);
			goto quit;
		}
	} else {
		memset(&reply, 0, sizeof(reply));

		build_get_lane_status_req(&req, hw->nr_lane, &req);
		err = rnpgbe_fw_send_cmd_wait(hw, &req, &reply);
		if (err) {
			rnpgbe_err("%s: 1 error:%d\n", __func__, err);
			goto quit;
		}
		st = (struct lane_stat_data *)&reply.data;
	}
	lane_update_host_endian(st);
	hw->phy_type = st->phy_type;
	hw->speed = le32_to_cpu(st->speed);
	hw->is_sgmii = st->st_host.is_sgmii;
	hw->pci_gen = st->pci_gen;
	hw->pci_lanes = st->pci_lanes;
	adpt->speed = le32_to_cpu(st->speed);
	adpt->hw.link = st->st_host.linkup;
	hw->supported_link = le32_to_cpu(st->supported_link);
	hw->advertised_link = le32_to_cpu(st->advertised_link);
	hw->tp_mdx = st->st_host.tp_mdx;
quit:
	kfree(cookie);
	return err;
}

int rnpgbe_mbx_fw_reset_phy(struct rnpgbe_hw *hw)
{
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	int ret;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	if (hw->mbx.other_irq_enabled) {
		struct mbx_req_cookie *cookie = mbx_cookie_zalloc(0);

		if (!cookie)
			return -ENOMEM;

		build_reset_phy_req(&req, cookie);

		ret = rnpgbe_mbx_fw_post_req(hw, &req, cookie);
		kfree(cookie);
		return ret;

	} else {
		build_reset_phy_req(&req, &req);
		return rnpgbe_fw_send_cmd_wait(hw, &req, &reply);
	}
}

int rnpgbe_maintain_req(struct rnpgbe_hw *hw, int cmd, int arg0,
			int req_data_bytes, int reply_bytes,
			dma_addr_t dma_phy_addr)
{
	struct mbx_req_cookie *cookie = NULL;
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	int err;
	u64 address = dma_phy_addr;

	cookie = mbx_cookie_zalloc(0);
	if (!cookie)
		return -ENOMEM;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));
	cookie->timeout_jiffes = 60 * HZ;

	build_maintain_req(&req, cookie, cmd, arg0, req_data_bytes, reply_bytes,
			   address & 0xffffffff,
			   (address >> 32) & 0xffffffff);

	if (hw->mbx.other_irq_enabled) {
		err = rnpgbe_mbx_fw_post_req(hw, &req, cookie);
	} else {
		int old_mbx_timeout = hw->mbx.timeout;

		hw->mbx.timeout =
			(60 * 1000 * 1000) / hw->mbx.usec_delay;
		err = rnpgbe_fw_send_cmd_wait(hw, &req, &reply);
		hw->mbx.timeout = old_mbx_timeout;
	}

	kfree(cookie);

	return (err) ? -EIO : 0;
}

int rnpgbe_fw_get_macaddr(struct rnpgbe_hw *hw, int pfvfnum, u8 *mac_addr,
			  int nr_lane)
{
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	int err;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	if (!mac_addr) {
		rnpgbe_err("%s: mac_addr is null\n", __func__);
		return -EINVAL;
	}

	if (hw->mbx.other_irq_enabled) {
		struct mbx_req_cookie *cookie =
			mbx_cookie_zalloc(sizeof(reply.mac_addr));
		struct mac_addr *mac = (struct mac_addr *)cookie->priv;

		if (!cookie)
			return -ENOMEM;

		build_get_macaddress_req(&req, 1 << nr_lane, pfvfnum, cookie);

		err = rnpgbe_mbx_fw_post_req(hw, &req, cookie);
		if (err) {
			kfree(cookie);
			return err;
		}

		if ((1 << nr_lane) & le32_to_cpu(mac->lanes))
			memcpy(mac_addr, mac->addrs[nr_lane].mac, 6);

		kfree(cookie);
		return 0;

	} else {
		build_get_macaddress_req(&req, 1 << nr_lane, pfvfnum, &req);
		err = rnpgbe_fw_send_cmd_wait(hw, &req, &reply);
		if (err) {
			rnpgbe_err("%s: failed. err:%d\n", __func__, err);
			return err;
		}

		if ((1 << nr_lane) & le32_to_cpu(reply.mac_addr.lanes)) {
			memcpy(mac_addr, reply.mac_addr.addrs[nr_lane].mac, 6);
			return 0;
		}
	}

	return -ENODATA;
}

static int rnpgbe_mbx_sfp_read(struct rnpgbe_hw *hw, int sfp_i2c_addr, int reg,
			       int cnt, u8 *out_buf)
{
	struct mbx_fw_cmd_req req;
	int nr_lane = hw->nr_lane;
	int err = -EIO;

	if (cnt > MBX_SFP_READ_MAX_CNT || !out_buf) {
		rnpgbe_err("%s: cnt:%d should <= %d out_buf:%p\n", __func__,
			   cnt, MBX_SFP_READ_MAX_CNT, out_buf);
		return -EINVAL;
	}

	memset(&req, 0, sizeof(req));

	if (hw->mbx.other_irq_enabled) {
		struct mbx_req_cookie *cookie = mbx_cookie_zalloc(cnt);

		if (!cookie)
			return -ENOMEM;

		build_mbx_sfp_read(&req, nr_lane, sfp_i2c_addr, reg, cnt,
				   cookie);

		err = rnpgbe_mbx_fw_post_req(hw, &req, cookie);
		if (err) {
			kfree(cookie);
			return err;

		} else {
			memcpy(out_buf, cookie->priv, cnt);
			err = 0;
		}
		kfree(cookie);
	} else {
		struct mbx_fw_cmd_reply reply;

		memset(&reply, 0, sizeof(reply));
		build_mbx_sfp_read(&req, nr_lane, sfp_i2c_addr, reg, cnt,
				   &reply);

		err = rnpgbe_fw_send_cmd_wait(hw, &req, &reply);
		if (err == 0)
			memcpy(out_buf, reply.sfp_read.value, cnt);
	}

	return err;
}

int rnpgbe_mbx_sfp_module_eeprom_info(struct rnpgbe_hw *hw, int sfp_addr,
				      int reg, int data_len, u8 *buf)
{
	int left = data_len;
	int cnt, err;

	do {
		cnt = (left > MBX_SFP_READ_MAX_CNT) ? MBX_SFP_READ_MAX_CNT :
						      left;
		err = rnpgbe_mbx_sfp_read(hw, sfp_addr, reg, cnt, buf);
		if (err) {
			rnpgbe_err("%s: error:%d\n", __func__, err);
			return err;
		}
		reg += cnt;
		buf += cnt;
		left -= cnt;
	} while (left > 0);

	return 0;
}

int rnpgbe_mbx_sfp_write(struct rnpgbe_hw *hw, int sfp_addr, int reg, short v)
{
	struct mbx_fw_cmd_req req;
	int nr_lane = hw->nr_lane;
	int err;

	memset(&req, 0, sizeof(req));

	build_mbx_sfp_write(&req, nr_lane, sfp_addr, reg, v);

	err = rnpgbe_mbx_write_posted_locked(hw, &req);
	return err;
}

int rnpgbe_mbx_fw_reg_read(struct rnpgbe_hw *hw, int fw_reg)
{
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	int err, ret = 0xffffffff;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	if (hw->fw_version < 0x00050200)
		return -EOPNOTSUPP;

	if (hw->mbx.other_irq_enabled) {
		struct mbx_req_cookie *cookie =
			mbx_cookie_zalloc(sizeof(reply.r_reg));

		build_readreg_req(&req, fw_reg, cookie);

		err = rnpgbe_mbx_fw_post_req(hw, &req, cookie);
		if (err) {
			kfree(cookie);
			return ret;
		}
		ret = ((int *)(cookie->priv))[0];
	} else {
		build_readreg_req(&req, fw_reg, &reply);
		err = rnpgbe_fw_send_cmd_wait(hw, &req, &reply);
		if (err) {
			rnpgbe_err("%s: failed. err:%d\n", __func__, err);
			return err;
		}
		ret = le32_to_cpu(reply.r_reg.value[0]);
	}
	return ret;
}

int rnpgbe_mbx_reg_write(struct rnpgbe_hw *hw, int fw_reg, int value)
{
	struct mbx_fw_cmd_req req;
	int err;

	memset(&req, 0, sizeof(req));
	if (hw->fw_version < 0x00050200)
		return -EOPNOTSUPP;

	build_writereg_req(&req, NULL, fw_reg, 4, &value);

	err = rnpgbe_mbx_write_posted_locked(hw, &req);
	return err;
}

int rnpgbe_mbx_wol_set(struct rnpgbe_hw *hw, u32 mode)
{
	struct mbx_fw_cmd_req req;
	int nr_lane = hw->nr_lane;
	int err;

	memset(&req, 0, sizeof(req));

	build_mbx_wol_set(&req, nr_lane, mode);

	err = rnpgbe_mbx_write_posted_locked(hw, &req);
	return err;
}

int rnpgbe_mbx_gephy_test_set(struct rnpgbe_hw *hw, u32 mode)
{
	struct mbx_fw_cmd_req req;
	int nr_lane = hw->nr_lane;

	memset(&req, 0, sizeof(req));
	build_mbx_gephy_test_set(&req, nr_lane, mode);

	return rnpgbe_mbx_write_posted_locked(hw, &req);
}

int rnpgbe_mbx_lldp_set(struct rnpgbe_hw *hw, u32 enable)
{
	struct mbx_fw_cmd_req req;
	int nr_lane = hw->nr_lane;

	memset(&req, 0, sizeof(req));
	build_mbx_lldp_set(&req, nr_lane, enable);

	return rnpgbe_mbx_write_posted_locked(hw, &req);
}

int rnpgbe_mbx_lldp_get(struct rnpgbe_hw *hw)
{
	struct mbx_req_cookie *cookie = NULL;
	struct get_lldp_reply *get_lldp;
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	int err;

	cookie = mbx_cookie_zalloc(sizeof(*get_lldp));
	if (!cookie)
		return -ENOMEM;
	get_lldp = (struct get_lldp_reply *)cookie->priv;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	build_get_lldp_req(&req, cookie, hw->nr_lane);

	if (hw->mbx.other_irq_enabled) {
		err = rnpgbe_mbx_fw_post_req(hw, &req, cookie);
	} else {
		err = rnpgbe_fw_send_cmd_wait(hw, &req, &reply);
		get_lldp = &reply.get_lldp;
	}

	if (err == 0) {
		hw->lldp_status.enable = le32_to_cpu(get_lldp->value);
		hw->lldp_status.interval = le32_to_cpu(get_lldp->interval);
	}

	kfree(cookie);

	return err ? -err : 0;
}

int rnpgbe_mbx_set_dump(struct rnpgbe_hw *hw, int flag)
{
	struct mbx_fw_cmd_req req;
	int err;

	memset(&req, 0, sizeof(req));
	build_set_dump(&req, hw->nr_lane, flag);

	err = rnpgbe_mbx_write_posted_locked(hw, &req);

	return err;
}

int rnpgbe_mbx_get_dump_flags(struct rnpgbe_hw *hw)
{
	struct mbx_req_cookie *cookie = NULL;
	struct get_dump_reply *get_dump;
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	int err;

	cookie = mbx_cookie_zalloc(sizeof(*get_dump));
	if (!cookie)
		return -ENOMEM;
	get_dump = (struct get_dump_reply *)cookie->priv;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	build_get_dump_req(&req, cookie, hw->nr_lane, 0, 0, 0);

	if (hw->mbx.other_irq_enabled) {
		err = rnpgbe_mbx_fw_post_req(hw, &req, cookie);
	} else {
		err = rnpgbe_fw_send_cmd_wait(hw, &req, &reply);
		get_dump = &reply.get_dump;
	}

	if (err == 0) {
		hw->dump.version = le32_to_cpu(get_dump->version);
		hw->dump.flag = le32_to_cpu(get_dump->flags);
		hw->dump.len = le32_to_cpu(get_dump->bytes);
	}
	kfree(cookie);

	return err ? -err : 0;
}

int rnpgbe_mbx_get_dump(struct rnpgbe_hw *hw, int flags, u32 *data_out,
			int bytes)
{
	struct rnpgbe_mbx_info *mbx = &hw->mbx;
	struct mbx_req_cookie *cookie = NULL;
	struct get_dump_reply *get_dump;
	int ram_size = mbx->share_size;
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	int i, offset = 0;
	int err;

	cookie = mbx_cookie_zalloc(sizeof(*get_dump));
	if (!cookie)
		return -ENOMEM;

	get_dump = (struct get_dump_reply *)cookie->priv;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	do {
		build_get_dump_req(&req, cookie, hw->nr_lane, offset, 0,
				   ram_size);

		if (hw->mbx.other_irq_enabled) {
			err = rnpgbe_mbx_fw_post_req(hw, &req, cookie);
		} else {
			err = rnpgbe_fw_send_cmd_wait(hw, &req, &reply);
			get_dump = &reply.get_dump;
		}

		if (err == 0 && data_out) {
			int len = ram_size;

			if ((bytes - offset) < ram_size)
				len = bytes - offset;

			for (i = 0; i < len; i = i + 4) {
				*(data_out + offset / 4 + i / 4) =
					rnpgbe_rd_reg(hw->hw_addr +
						      mbx->cpu_vf_share_ram +
						      i);
			}
		}

		offset += ram_size;

	} while (offset < bytes);

	kfree(cookie);

	return err ? -err : 0;
}

int rnpgbe_fw_update(struct rnpgbe_hw *hw, int partition, const u8 *fw_bin,
		     int bytes)
{
	struct rnpgbe_mbx_info *mbx = &hw->mbx;
	struct mbx_req_cookie *cookie = NULL;
	int ram_size = mbx->share_size;
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	u32 *msg = (u32 *)fw_bin;
	int offset = 0;
	int err = 0;
	int i;

	cookie = mbx_cookie_zalloc(0);
	if (!cookie) {
		dev_err(&hw->pdev->dev, "%s: no memory:%d!", __func__, 0);
		return -ENOMEM;
	}

	/* if bytes more than ram_size, we update header at last */
	if (bytes > ram_size) {
		offset += ram_size;

		/* n210 should clean header first */
		if (hw->hw_type == rnpgbe_hw_n210 ||
		    hw->hw_type == rnpgbe_hw_n210L) {
			memset(&req, 0, sizeof(req));
			memset(&reply, 0, sizeof(reply));

			for (i = 0; i < ram_size; i = i + 4)
				rnpgbe_wr_reg(hw->hw_addr + mbx->cpu_vf_share_ram + i,
					      0xffffffff);

			build_fw_update_gbe_req(&req, cookie, partition, 0);
			if (hw->mbx.other_irq_enabled) {
				err = rnpgbe_mbx_fw_post_req(hw, &req, cookie);
			} else {
				int old_mbx_timeout = hw->mbx.timeout;

				hw->mbx.timeout = (20 * 1000 * 1000) /
					hw->mbx.usec_delay; // wait 20s
				err = rnpgbe_fw_send_cmd_wait(hw, &req, &reply);
				hw->mbx.timeout = old_mbx_timeout;
			}
		}
	}

	while (offset < bytes) {
		memset(&req, 0, sizeof(req));
		memset(&reply, 0, sizeof(reply));

		for (i = 0; i < ram_size; i = i + 4)
			rnpgbe_wr_reg(hw->hw_addr + mbx->cpu_vf_share_ram + i,
				      *(msg + offset / 4 + i / 4));

		build_fw_update_gbe_req(&req, cookie, partition, offset);
		if (hw->mbx.other_irq_enabled) {
			err = rnpgbe_mbx_fw_post_req(hw, &req, cookie);
		} else {
			int old_mbx_timeout = hw->mbx.timeout;

			hw->mbx.timeout = (20 * 1000 * 1000) /
					  hw->mbx.usec_delay; // wait 20s
			err = rnpgbe_fw_send_cmd_wait(hw, &req, &reply);
			hw->mbx.timeout = old_mbx_timeout;
		}

		if (err)
			goto out;
		offset += ram_size;
	}
	// we write header at last
	if (bytes > ram_size) {
		offset = 0;
		memset(&req, 0, sizeof(req));
		memset(&reply, 0, sizeof(reply));

		for (i = 0; i < ram_size; i = i + 4)
			rnpgbe_wr_reg(hw->hw_addr + mbx->cpu_vf_share_ram + i,
				      *(msg + offset / 4 + i / 4));

		build_fw_update_gbe_req(&req, cookie, partition, offset);
		if (hw->mbx.other_irq_enabled) {
			err = rnpgbe_mbx_fw_post_req(hw, &req, cookie);
		} else {
			int old_mbx_timeout = hw->mbx.timeout;

			hw->mbx.timeout = (20 * 1000 * 1000) /
					  hw->mbx.usec_delay; // wait 20s
			err = rnpgbe_fw_send_cmd_wait(hw, &req, &reply);
			hw->mbx.timeout = old_mbx_timeout;
		}
	}
out:
	return err ? -err : 0;
}

int rnpgbe_mbx_link_event_enable(struct rnpgbe_hw *hw, int enable)
{
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	int err;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	if (enable)
		hw_wr32(hw, RNP_DMA_DUMY, 0xa0000000);

	build_link_set_event_mask(&req, BIT(EVT_LINK_UP),
				  (enable & 1) << EVT_LINK_UP, &req);

	err = rnpgbe_mbx_write_posted_locked(hw, &req);
	if (!enable)
		hw_wr32(hw, RNP_DMA_DUMY, 0);

	return err;
}

int rnpgbe_fw_get_capability(struct rnpgbe_hw *hw, struct phy_abilities *abil)
{
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	int err;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));
	build_phy_abalities_req(&req);
	err = rnpgbe_fw_send_cmd_wait(hw, &req, &reply);

	if (err == 0)
		memcpy(abil, &reply.phy_abilities, sizeof(*abil));

	return err;
}

int rnpgbe_mbx_ifinsmod(struct rnpgbe_hw *hw, int status)
{
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	int length;
	int err;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	build_ifinsmod(&req, hw->driver_version, status);

	if (mutex_lock_interruptible(&hw->mbx.lock))
		return -EAGAIN;
	length = (le16_to_cpu(req.datalen) + MBX_REQ_HDR_LEN) / 4;
	if (status) {
		err = hw->mbx.ops.write_posted(hw, (u32 *)&req, length,
					       MBX_FW);
	} else {
		err = hw->mbx.ops.write(hw, (u32 *)&req,
					length, MBX_FW);
	}

	mutex_unlock(&hw->mbx.lock);

	rnpgbe_logd(LOG_MBX_IFUP_DOWN, "%s: lane:%d status:%d\n", __func__,
		    hw->nr_lane, status);

	return err;
}

int rnpgbe_mbx_ifsuspuse(struct rnpgbe_hw *hw, int status)
{
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	int length;
	int err;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	build_ifsuspuse(&req, hw->nr_lane, status);

	if (mutex_lock_interruptible(&hw->mbx.lock))
		return -EAGAIN;
	length = (le16_to_cpu(req.datalen) + MBX_REQ_HDR_LEN) / 4;
	err = hw->mbx.ops.write_posted(hw, (u32 *)&req, length, MBX_FW);
	mutex_unlock(&hw->mbx.lock);
	rnpgbe_logd(LOG_MBX_IFUP_DOWN, "%s: lane:%d status:%d\n", __func__,
		    hw->nr_lane, status);

	return err;
}

int rnpgbe_mbx_ifforce_control_mac(struct rnpgbe_hw *hw, int status)
{
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	int length;
	int err;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	build_ifforce(&req, hw->nr_lane, status);

	if (mutex_lock_interruptible(&hw->mbx.lock))
		return -EAGAIN;
	length = (le16_to_cpu(req.datalen) + MBX_REQ_HDR_LEN) / 4;
	err = hw->mbx.ops.write_posted(hw, (u32 *)&req, length, MBX_FW);

	mutex_unlock(&hw->mbx.lock);

	rnpgbe_logd(LOG_MBX_IFUP_DOWN, "%s: lane:%d status:%d\n", __func__,
		    hw->nr_lane, status);

	return err;
}

int rnpgbe_mbx_tstamps_show(struct rnpgbe_hw *hw, u32 sec, u32 nanosec)
{
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	int length;
	int err;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	build_tstamp_show(&req, sec, nanosec);

	if (mutex_lock_interruptible(&hw->mbx.lock))
		return -EAGAIN;
	length = (le16_to_cpu(req.datalen) + MBX_REQ_HDR_LEN) / 4;
	err = hw->mbx.ops.write_posted(hw, (u32 *)&req, length, MBX_FW);

	mutex_unlock(&hw->mbx.lock);

	return err;
}

int rnpgbe_mbx_ifup_down(struct rnpgbe_hw *hw, int up)
{
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	int length;
	int err;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	build_ifup_down(&req, hw->nr_lane, up);

	if (mutex_lock_interruptible(&hw->mbx.lock))
		return -EAGAIN;
	length = (le16_to_cpu(req.datalen) + MBX_REQ_HDR_LEN) / 4;
	err = hw->mbx.ops.write_posted(hw, (u32 *)&req, length, MBX_FW);

	mutex_unlock(&hw->mbx.lock);

	rnpgbe_logd(LOG_MBX_IFUP_DOWN, "%s: lane:%d up:%d\n", __func__,
		    hw->nr_lane, up);

	if (up)
		rnpgbe_link_stat_mark_reset(hw);

	return err;
}

int rnpgbe_mbx_led_set(struct rnpgbe_hw *hw, int value)
{
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	build_led_set(&req, hw->nr_lane, value, &reply);

	return rnpgbe_mbx_write_posted_locked(hw, &req);
}

int rnpgbe_mbx_get_eee_capability(struct rnpgbe_hw *hw,
				  struct rnpgbe_eee_cap *eee_cap)
{
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	int err;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	build_phy_eee_abalities_req(&req, &req);

	err = rnpgbe_fw_send_cmd_wait(hw, &req, &reply);

	if (err == 0) {
		memcpy(eee_cap, &reply.phy_eee_abilities, sizeof(*eee_cap));
		return 0;
	}

	return err;
}

int rnpgbe_mbx_phy_eee_set(struct rnpgbe_hw *hw, u32 tx_lpi_timer,
			   u32 local_eee)
{
	struct mbx_fw_cmd_req req;
	int length;
	int err;

	memset(&req, 0, sizeof(req));

	build_phy_eee_set(&req, local_eee, tx_lpi_timer, hw->nr_lane);

	if (mutex_lock_interruptible(&hw->mbx.lock))
		return -EAGAIN;

	length = (le16_to_cpu(req.datalen) + MBX_REQ_HDR_LEN) / 4;
	err = hw->mbx.ops.write_posted(hw, (u32 *)&req, length, MBX_FW);
	mutex_unlock(&hw->mbx.lock);

	return err;
}

int rnpgbe_mbx_get_capability(struct rnpgbe_hw *hw, struct rnpgbe_info *info)
{
	struct phy_abilities ability;
	int try_cnt = 3;
	int err;

	memset(&ability, 0, sizeof(ability));
	rnpgbe_link_stat_mark_disable(hw);

	while (try_cnt--) {
		err = rnpgbe_fw_get_capability(hw, &ability);
		ability_update_host_endian(&ability);
		if (err)
			continue;
		hw->lane_mask = ability.lane_mask & 0xf;
		hw->sfc_boot = (le16_to_cpu(ability.nic_mode) & 0x1) ? 1 : 0;
		hw->pxe_en = (le16_to_cpu(ability.nic_mode) & 0x2) ? 1 : 0;
		hw->ncsi_en = (le16_to_cpu(ability.nic_mode) & 0x4) ? 1 : 0;
		hw->pfvfnum = le16_to_cpu(ability.pfnum);
		hw->speed = le32_to_cpu(ability.speed);
		hw->nr_lane = 0;
		hw->fw_version = le32_to_cpu(ability.fw_version);
		hw->phy_type = le16_to_cpu(ability.phy_type);
		hw->axi_mhz = le32_to_cpu(ability.axi_mhz);
		hw->port_ids = le32_to_cpu(ability.port_ids);
		hw->bd_uid = le32_to_cpu(ability.bd_uid);
		hw->phy_id = le32_to_cpu(ability.phy_id);

		if (hw->fw_version >= 0x0001012C) {
			/* this version can get wol_en from hw */
			hw->wol = le32_to_cpu(ability.wol_status) & 0xff;
			hw->wol_en = le32_to_cpu(ability.wol_status) & 0x100;
		} else {
			/* other version only pf0 or ncsi can wol */
			hw->wol = le32_to_cpu(ability.wol_status) & 0xff;
			if (hw->ncsi_en || !hw->pfvfnum)
				hw->wol_en = 1;
		}
		/* 0.1.5.0 can get force status from fw */
		if (hw->fw_version >= 0x00010500) {
			hw->force_en = ability.e.force_down_en;
			hw->force_cap = 1;
		}

		/* 0.1.6.0 can get trim valid from hw */
		if (hw->fw_version >= 0x00010600)
			hw->trim_valid = (le16_to_cpu(ability.nic_mode) & 0x8) ? 1 : 0;
		return 0;
	}

	dev_err(&hw->pdev->dev, "%s: error!\n", __func__);
	return -EIO;
}

int rnpgbe_mbx_get_temp(struct rnpgbe_hw *hw, int *voltage)
{
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

	if (hw->mbx.other_irq_enabled) {
		rnpgbe_mbx_fw_post_req(hw, &req, cookie);
	} else {
		memset(&reply, 0, sizeof(reply));
		rnpgbe_fw_send_cmd_wait(hw, &req, &reply);
		temp = &reply.get_temp;
	}

	if (voltage)
		*voltage = le32_to_cpu(temp->voltage);
	temp_v = le32_to_cpu(temp->temp);

	kfree(cookie);
	return temp_v;
}

enum speed_enum {
	speed_10,
	speed_100,
	speed_1000,
};

static void rnpgbe_link_stat_mark(struct rnpgbe_hw *hw, int up)
{
	struct rnpgbe_adapter *adapter = (struct rnpgbe_adapter *)hw->back;
	u32 v;

	v = hw_rd32(hw, RNP_DMA_DUMY);
	v &= ~(0x0f000f11);
	v |= 0xa0000000;
	if (up) {
		v |= BIT(0);
		switch (hw->speed) {
		case 10:
			v |= (speed_10 << 8);
			break;
		case 100:
			v |= (speed_100 << 8);
			break;
		case 1000:
			v |= (speed_1000 << 8);
			break;
		}
		v |= (hw->duplex << 4);
		v |= (hw->fc.current_mode << 24);
	} else {
		v &= ~BIT(0);
	}
	/* we should update lldp_status */
	if (hw->fw_version >= 0x00010500) {
		if (adapter->priv_flags & RNP_PRIV_FLAG_LLDP)
			v |= BIT(6);
		else
			v &= (~BIT(6));
	}
	hw_wr32(hw, RNP_DMA_DUMY, v);
}

static inline int rnpgbe_mbx_fw_req_handler(struct rnpgbe_adapter *adapter,
					    struct mbx_fw_cmd_req *req)
{
	struct rnpgbe_hw *hw = &adapter->hw;

	switch (le16_to_cpu(req->opcode)) {
	case LINK_STATUS_EVENT:
		rnpgbe_logd(LOG_LINK_EVENT,
			    "[LINK_STATUS_EVENT:0x%x] %s:link changed: changed_lane:0x%x, "
			    "status:0x%x, speed:%d, duplex:%d\n",
			    req->opcode, adapter->name, req->link_stat.changed_lanes,
			    req->link_stat.lane_status, req->link_stat.st[0].speed,
			    req->link_stat.st[0].duplex);

		if (req->link_stat.lane_status)
			adapter->hw.link = 1;
		else
			adapter->hw.link = 0;
		port_stat_update_host_endian(&req->link_stat.st[0]);
		adapter->local_eee = req->link_stat.st[0].v_host.local_eee;
		adapter->partner_eee = req->link_stat.st[0].v_host.partner_eee;
		/* fw_version more than 0.1.5.0 can up lldp_status */
		if (hw->fw_version >= 0x00010500) {
			if (req->link_stat.st[0].v_host.lldp_status)
				adapter->priv_flags |=  RNP_PRIV_FLAG_LLDP;
			else
				adapter->priv_flags &= (~RNP_PRIV_FLAG_LLDP);
		}

		if (le32_to_cpu(req->link_stat.port_st_magic) == SPEED_VALID_MAGIC) {
			hw->speed = req->link_stat.st[0].speed;
			hw->duplex = req->link_stat.st[0].duplex;
			/* n500 can update pause and tp */
			hw->fc.current_mode = req->link_stat.st[0].v_host.pause;
			hw->tp_mdx = req->link_stat.st[0].v_host.tp_mdx;

			switch (hw->speed) {
			case 10:
				adapter->speed = RNP_LINK_SPEED_10_FULL;
				break;
			case 100:
				adapter->speed = RNP_LINK_SPEED_100_FULL;
				break;
			case 1000:
				adapter->speed = RNP_LINK_SPEED_1GB_FULL;
				break;
			}
		}
		if (req->link_stat.lane_status)
			rnpgbe_link_stat_mark(hw, 1);
		else
			rnpgbe_link_stat_mark(hw, 0);

		adapter->flags |= RNP_FLAG_NEED_LINK_UPDATE;
		break;
	}
	rnpgbe_service_event_schedule(adapter);

	return 0;
}

static inline int rnpgbe_mbx_fw_reply_handler(struct rnpgbe_adapter *adapter,
					      struct mbx_fw_cmd_reply *reply)
{
	struct mbx_req_cookie *cookie;

	cookie = reply->cookie;
	if (!cookie || cookie->magic != COOKIE_MAGIC)
		return -EIO;

	if (cookie->priv_len > 0)
		memcpy(cookie->priv, reply->data, cookie->priv_len);

	cookie->done = 1;

	if (le16_to_cpu(reply->flags) & FLAGS_ERR)
		cookie->errcode = le16_to_cpu(reply->error_code);
	else
		cookie->errcode = 0;

	wake_up(&cookie->wait);

	return 0;
}

static inline int rnpgbe_rcv_msg_from_fw(struct rnpgbe_adapter *adapter)
{
	struct rnpgbe_hw *hw = &adapter->hw;
	struct device *dev = &hw->pdev->dev;
	u32 msgbuf[RNP_FW_MAILBOX_SIZE];
	s32 retval;

	retval = rnpgbe_read_mbx(hw, msgbuf, RNP_FW_MAILBOX_SIZE, MBX_FW);
	if (retval) {
		dev_info(dev, "Error receiving message from FW:%d\n",
			 retval);
		return retval;
	}

	rnpgbe_logd(LOG_MBX_MSG_IN,
		    "msg from fw: msg[0]=0x%08x_0x%08x_0x%08x_0x%08x\n",
		    msgbuf[0], msgbuf[1], msgbuf[2], msgbuf[3]);

	/* this is a message we already processed, do nothing */
	if (((unsigned short *)msgbuf)[0] & FLAGS_DD)
		return rnpgbe_mbx_fw_reply_handler(adapter, (struct mbx_fw_cmd_reply *)msgbuf);
	else
		return rnpgbe_mbx_fw_req_handler(adapter, (struct mbx_fw_cmd_req *)msgbuf);
}

static void rnpgbe_rcv_ack_from_fw(struct rnpgbe_adapter *adapter)
{
	/* do-nothing */
}

int rnpgbe_fw_msg_handler(struct rnpgbe_adapter *adapter)
{
	/* == check fw-req */
	if (!rnpgbe_check_for_msg(&adapter->hw, MBX_FW)) {
		/* printk("check msg from fw\n"); */
		rnpgbe_rcv_msg_from_fw(adapter);
	}

	/* process any acks */
	if (!rnpgbe_check_for_ack(&adapter->hw, MBX_FW))
		rnpgbe_rcv_ack_from_fw(adapter);

	return 0;
}

int rnpgbe_mbx_phy_link_set(struct rnpgbe_hw *hw, int adv, int autoneg,
			    int speed, int duplex, int mdix_ctrl)
{
	struct mbx_fw_cmd_req req;
	int length;
	int err;

	memset(&req, 0, sizeof(req));

	build_phy_link_set(&req, adv, hw->nr_lane, autoneg, speed, duplex,
			   mdix_ctrl);

	if (mutex_lock_interruptible(&hw->mbx.lock))
		return -EAGAIN;
	length = (le16_to_cpu(req.datalen) + MBX_REQ_HDR_LEN) / 4;
	err = hw->mbx.ops.write_posted(hw, (u32 *)&req, length, MBX_FW);

	mutex_unlock(&hw->mbx.lock);

	return err;
}

int rnpgbe_mbx_phy_pause_set(struct rnpgbe_hw *hw, u32 pause_mode)
{
	struct mbx_fw_cmd_req req;
	int length;
	int err;

	memset(&req, 0, sizeof(req));

	build_phy_pause_set(&req, pause_mode, hw->nr_lane);

	if (mutex_lock_interruptible(&hw->mbx.lock))
		return -EAGAIN;
	length = (le16_to_cpu(req.datalen) + MBX_REQ_HDR_LEN) / 4;
	err = hw->mbx.ops.write_posted(hw, (u32 *)&req, length, MBX_FW);

	mutex_unlock(&hw->mbx.lock);

	return err;
}

int rnpgbe_mbx_phy_pause_get(struct rnpgbe_hw *hw, u32 *pause_mode)
{
	struct mbx_req_cookie *cookie = NULL;
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	struct phy_pause_data *st;
	int err = -EIO;

	memset(&req, 0, sizeof(req));

	if (hw->mbx.other_irq_enabled) {
		cookie = mbx_cookie_zalloc(sizeof(struct lane_stat_data));

		if (!cookie) {
			rnpgbe_err("%s: no memory\n", __func__);
			return -ENOMEM;
		}

		st = (struct phy_pause_data *)cookie->priv;
		build_get_phy_pause_req(&req, hw->nr_lane, cookie);
		err = rnpgbe_mbx_fw_post_req(hw, &req, cookie);
		if (err) {
			rnpgbe_err("%s: error:%d\n", __func__, err);
			goto quit;
		}
	} else {
		memset(&reply, 0, sizeof(reply));

		build_get_phy_pause_req(&req, hw->nr_lane, &req);
		err = rnpgbe_fw_send_cmd_wait(hw, &req, &reply);
		if (err) {
			rnpgbe_err("%s: 1 error:%d\n", __func__, err);
			goto quit;
		}
		st = (struct phy_pause_data *)&reply.data;
	}

	*pause_mode = le32_to_cpu(st->pause_mode);
quit:
	kfree(cookie);
	return err;
}

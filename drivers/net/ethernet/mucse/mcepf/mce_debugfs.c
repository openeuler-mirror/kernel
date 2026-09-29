// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/irq.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include "mce.h"
#include "mce_fwchnl.h"
#include "mce_virtchnl.h"
#include "mce_debugfs_regs.h"
#include "mce_irq.h"
#include "mce_lib.h"
#include "mucse_auxiliary/mce_idc.h"
#include "mce_n20/mce_hw_n20.h"
#include "mce_dcbnl.h"

typedef int (*SHOW_OP)(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			       int buf_sz);
typedef int (*SHOW_PRE_OP)(struct mce_pf *pf, struct mce_hw *hw,
				  char __user *buf, int buf_sz);
typedef int (*STORE_OP)(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			size_t count);

#define SNPRINTF(args...) snprintf(buf + cnt, buf_sz - cnt, args)

#define DECLEAR_DEBUGFS_OPS(fname, op_show_pre, op_show, op_store)            \
	static ssize_t mce_debugfs_##fname##_read(struct file *file,          \
						  char __user *buf,           \
						  size_t count, loff_t *pos)  \
	{                                                                     \
		struct mce_pf *pf = file->private_data;                       \
		struct mce_hw *hw = &pf->hw;                                \
		int err;                                                      \
		SHOW_PRE_OP pre_op = op_show_pre;                              \
		SHOW_OP show_op = op_show;                                    \
		if (*pos == 0 && pre_op) {                            \
			err = pre_op(pf, hw, buf, count);                     \
			if (err) {                                            \
				return err;                                   \
			}                                                     \
		}                                                             \
		return mce_debugfs_common_read(pf, buf, count, pos, show_op); \
	}                                                                     \
	static ssize_t mce_debugfs_##fname##_write(struct file *file,         \
						   const char __user *buf,    \
						   size_t count, loff_t *pos) \
	{                                                                     \
		struct mce_pf *pf = file->private_data;                       \
		struct mce_hw *hw = &pf->hw;                                \
		int err;                                                      \
		char *tmp_buf;                                                \
		STORE_OP store_op = op_store;                                 \
		if (*pos != 0)                                                \
			return 0;                                             \
		tmp_buf = kmalloc(count + 1, GFP_KERNEL);                     \
		if (!tmp_buf) {                                               \
			return -ENOMEM;                                       \
		}                                                             \
		if (copy_from_user(tmp_buf, buf, count))                      \
			return -EFAULT;                                       \
		tmp_buf[count] = 0;                                           \
		if (store_op) {                                       \
			err = store_op(pf, hw, tmp_buf, count);               \
			if (err < 0) {                                        \
				kfree(tmp_buf);                               \
				return err;                                   \
			}                                                     \
		}                                                             \
		kfree(tmp_buf);                                               \
		return count;                                                 \
	}                                                                     \
	static const struct file_operations mce_debugfs_##fname##_fops = {    \
		.owner = THIS_MODULE,                                         \
		.open = mce_debugfs_common_open,                              \
		.read = mce_debugfs_##fname##_read,                           \
		.write = mce_debugfs_##fname##_write,                         \
	}

static struct dentry *mce_debugfs_root;

static int check_pri2buf(struct mce_pfc_cfg *pfccfg, int fifo)
{
	int ret = 0;
	int i;

	for (i = 0; i < MCE_MAX_PRIORITY; i++) {
		if (pfccfg->rx_pri2buf[i] == fifo)
			ret = 1;
	}

	return ret;
}

static int __print_desc(char *buf, void *data, int len)
{
	u8 *ptr = (u8 *)data;
	int ret = 0;
	int i = 0;

	for (i = 0; i < len; i++)
		ret += sprintf(buf + ret, "%02x ", *(ptr + i));

	return ret;
}

static int init_debugfs_buffer(struct mce_pf *pf, struct mce_hw *hw)
{
	int buf_sz = 64 * 1024;
	char *buf;

	if (!pf->debugfs_buf) {
		buf = kmalloc(buf_sz, GFP_KERNEL);
		if (!buf)
			return -ENOMEM;
		pf->debugfs_buf = buf;
		pf->debugfs_buf_bytes = buf_sz;
	} else {
		buf = pf->debugfs_buf;
		buf_sz = pf->debugfs_buf_bytes;
	}

	return 0;
}

static ssize_t mce_debugfs_common_read(struct mce_pf *pf, char __user *buf,
				       size_t count, loff_t *pos,
				       int (*fill_msg_buf)(struct mce_pf *pf, struct mce_hw *hw,
							   char *buf,
							    int buf_sz))
{
	struct device *dev = mce_pf_to_dev(pf);
	struct mce_hw *hw = &pf->hw;
	int err, off = (int)(*pos);
	int rcnt = count;

	if (off == 0) {
		if (fill_msg_buf) {
			err = init_debugfs_buffer(pf, hw);
			if (err < 0)
				return err;

			pf->debugfs_buf_msg_size =
				fill_msg_buf(pf, hw, (char *)pf->debugfs_buf,
					     pf->debugfs_buf_bytes);
			if (pf->debugfs_buf_msg_size < 0)
				return pf->debugfs_buf_msg_size;
		} else if (!pf->debugfs_buf) {
			return -EINVAL;
		}
	}

	if (off >= pf->debugfs_buf_msg_size)
		goto end_of_file;
	else if ((off + count) > pf->debugfs_buf_msg_size)
		rcnt = pf->debugfs_buf_msg_size - off;
	if (rcnt == 0)
		goto end_of_file;

	if (pf->debugfs_buf) {
		if (copy_to_user(buf, pf->debugfs_buf + off, rcnt)) {
			dev_err(dev, "%s: copy to user failed!\n", __func__);
			return -EFAULT;
		}
	}

	*pos += rcnt;

	return rcnt;

end_of_file:
	kfree(pf->debugfs_buf);
	pf->debugfs_buf = NULL;
	pf->debugfs_buf_msg_size = 0;
	pf->debugfs_buf_bytes = 0;

	return 0;
}

static int mce_debugfs_common_open(struct inode *inode, struct file *file)
{
	struct mce_pf *pf;

	if (!inode->i_private)
		return -EINVAL;
	file->private_data = inode->i_private;
	pf = file->private_data;

	if (pf->debugfs_queue_setted == 0) {
		pf->debugfs_queue_start = 0;
		pf->debugfs_queue_end = 3;
		pf->debugfs_queue_setted = 1;
	}
	return 0;
}

static const char *const logd_lvl_names[LOG_NET_MAX] = {
	[LOG_MBX_IN_REQ] = "MBX_IN_REQ", /* 0 */
	[LOG_MBX_REQ_OUT] = "MBX_REQ_OUT", /* 1 */
	[LOG_VECTOR_ALLOC] = "VECTOR_ALLOC", /* 2 */
	[LOG_MISC_IRQ] = "MISC_IRQ", /* 3*/
	[LOG_CDEV] = "CDEV", /* 4 */
	[LOG_LINK_INFO] = "LINK INFO", /* 5 */
	[LOG_PTP_HW] = "PTP_HW", /* 6 */
	[LOG_PTP_WORK] = "PTP_WORK", /* 7 */
	[LOG_QUEUE_INFO] = "QUEUE_INFO", /* 8 */
	[LOG_NTUPLE_INFO] = "NTUPLE_INFO", /* 9 */
	[LOG_FEC] = "FEC", /* 10 */
	[LOG_NET_DEV_EVENT] = "NET_DEV_EVENT", /* 11 */
	[LOG_FDIR_INFO] = "FDIR_INFO", /* 12 */
	[LOG_FDIR_DEBUG] = "FDIR_DEBUG", /* 13 */
	[LOG_ARFS] = "ARFS", /* 14 */
};

static int logd_lvl_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			 int buf_sz)
{
	int cnt = 0, i;

	cnt += snprintf(buf, buf_sz, "logd_lvl:0x%x\n", mce_loglevel);
	for (i = 0; i < LOG_NET_MAX; i++) {
		cnt += snprintf(buf + cnt, buf_sz - cnt, "i:%d %s %s\n", i,
				logd_lvl_names[i],
				!!(mce_loglevel & BIT(i)) ? "on" : "off");
	}
	return cnt;
}

static int logd_lvl_store(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			  size_t count)
{
	struct net_device *netdev = mce_get_main_net_dev(pf);
	int logd_idx, en, cnt;

	cnt = sscanf(buf, "%d %d", &logd_idx, &en);
	if (cnt != 2 || logd_idx >= LOG_NET_MAX) {
		netdev_info(netdev, "logd_lvl: logd_idx <en 0|1>\n");
		return -EINVAL;
	}

	if (en)
		mce_loglevel |= BIT(logd_idx);
	else
		mce_loglevel &= ~BIT(logd_idx);

	return count;
}

DECLEAR_DEBUGFS_OPS(logd_lvl, NULL, logd_lvl_show, logd_lvl_store);

static int vf_recv_xmit_by_self_show(struct mce_pf *pf, struct mce_hw *hw,
				     char *buf, int buf_sz)
{
	int cnt = 0;

	cnt += snprintf(buf, buf_sz, "vf_recv_xmit_by_self: %s\n",
			test_bit(MCE_FLAG_VF_RECV_XMIT_BY_SELF, pf->flags) ?
				"on" :
				"off");
	return cnt;
}

static int vf_recv_xmit_by_self_store(struct mce_pf *pf, struct mce_hw *hw,
				      char *buf, size_t count)
{
	struct net_device *netdev = mce_get_main_net_dev(pf);
	int en;

	if (kstrtoint(buf, 10, &en)) {
		netdev_info(netdev, "vf_recv_xmit_by_self: en 0|1\n");
		return -EINVAL;
	}

	if (en)
		set_bit(MCE_FLAG_VF_RECV_XMIT_BY_SELF, pf->flags);
	else
		clear_bit(MCE_FLAG_VF_RECV_XMIT_BY_SELF, pf->flags);
	hw->vf.ops->set_vf_recv_ximit_by_self(hw, en);
	return count;
}

DECLEAR_DEBUGFS_OPS(vf_recv_xmit_by_self, NULL, vf_recv_xmit_by_self_show,
		    vf_recv_xmit_by_self_store);

static int nb_vlan_maps_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			     int buf_sz)
{
	int i, bytes = 0, cnt = 0;

	for_each_set_bit(i, pf->nb_vlan_bitmap, VLAN_N_VID) {
		bytes += snprintf(buf + bytes, buf_sz - bytes, "%d ", i);
		cnt++;
	}
	bytes += snprintf(buf + bytes, buf_sz - bytes, "\ntotal cnt:%d ", cnt);

	bytes += snprintf(buf + bytes, buf_sz - bytes, "\n == ndo vlan ==\n");
	cnt = 0;
	for_each_set_bit(i, pf->vlan_bitmap, VLAN_N_VID) {
		bytes += snprintf(buf + bytes, buf_sz - bytes, "%d ", i);
		cnt++;
	}
	bytes += snprintf(buf + bytes, buf_sz - bytes, "\ntotal cnt:%d ", cnt);
	return bytes;
}

DECLEAR_DEBUGFS_OPS(nb_vlan_maps, NULL, nb_vlan_maps_show, NULL);

static int eth_name_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			 int buf_sz)
{
	struct net_device *netdev = mce_get_main_net_dev(pf);

	if (netdev)
		return snprintf(buf, buf_sz, "%s", netdev->name);
	return snprintf(buf, buf_sz, "unknown");
}

DECLEAR_DEBUGFS_OPS(eth_name, NULL, eth_name_show, NULL);

static int select_queue_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			     int buf_sz)
{
	int ret = 0;

	ret += sprintf(buf + ret, "enable:%d s_id:%d e_id:%d r_id:%d\n",
		       pf->d_txqueue.en, pf->d_txqueue.s_id, pf->d_txqueue.e_id,
		       pf->d_txqueue.r_id);
	return ret;
}

static int select_queue_store(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			      size_t count)
{
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	int en, s_id, e_id, cnt;

	/* start ring id + end ring id */
	cnt = sscanf(buf, "%d %d %d", &en, &s_id, &e_id);
	if (cnt != 3 || s_id > e_id)
		return -EINVAL;
	if (e_id >= vsi->num_txq)
		return -EINVAL;
	pf->d_txqueue.s_id = s_id;
	pf->d_txqueue.e_id = e_id;
	pf->d_txqueue.en = !!en;
	return count;
}

DECLEAR_DEBUGFS_OPS(select_queue, NULL, select_queue_show, select_queue_store);

static int txring_intr_mask_store(struct mce_pf *pf, struct mce_hw *hw,
				  char *buf, size_t count)
{
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	int en, ring_id, cnt;

	/* start ring id + end ring id */
	cnt = sscanf(buf, "%d %d", &en, &ring_id);
	if (cnt != 2 || ring_id >= vsi->num_txq || ring_id < 0)
		return -EINVAL;

	pf->d_txqueue.s_id = ring_id;
	pf->d_txqueue.e_id = ring_id;
	pf->d_txqueue.en = !!en;
	if (en)
		hw->ops->disable_txrxring_irq(vsi->tx_rings[ring_id]);
	else
		hw->ops->enable_txrxring_irq(vsi->tx_rings[ring_id]);
	dev_warn(mce_pf_to_dev(pf), "%s en:%d txring_id:%d\n", __func__, en,
		 ring_id);
	return count;
}

DECLEAR_DEBUGFS_OPS(txring_intr_mask, NULL, NULL, txring_intr_mask_store);

static int set_dvlan_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			  int buf_sz)
{
	struct mce_dvlan_ctrl *dvc = &pf->dvlan_ctrl;
	int ret = 0;

	ret = sprintf(buf,
		      "double vlan: enable:%d\n"
		"outer_vlan_type:0x%s outer_vlan_vid:%d\n"
		"inner_vlan_type:0x%s inner_vlan_vid:%d\n",
		dvc->en,
		dvc->outer_hdr.type == MCE_VLAN_TYPE_8100 ? "8100" : "88a8",
		dvc->outer_hdr.vid,
		dvc->inner_hdr.type == MCE_VLAN_TYPE_8100 ? "8100" : "88a8",
		dvc->inner_hdr.vid);
	return ret;
}

static int __mce_check_dvlan(u32 proto, u32 id, enum mce_dvlan_type *type)
{
	if (proto == 0x8100)
		*type = MCE_VLAN_TYPE_8100;
	else if (proto == 0x88a8)
		*type = MCE_VLAN_TYPE_88A8;
	else
		return -EINVAL;
	if (id <= 0 || id >= 4095)
		return -EINVAL;

	return 0;
}

static int set_dvlan_store(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			   size_t count)
{
	struct net_device *netdev = pf->vsi[0]->netdev;
	struct mce_dvlan_ctrl *dvc = &pf->dvlan_ctrl;
	struct mce_vf *vf = NULL;
	int o_proto, i_proto;
	int cnt = 0;

	memset(dvc, 0, sizeof(struct mce_dvlan_ctrl));
	/* enable(1/0) + outer_vlan_type(8100/88a8) + outer_vlan_vla(vid) +
	 * inner_vlan_type(8100/88a8) + inner_vlan_val(vid)
	 */
	cnt = sscanf(buf, "%d %x %hd %x %hd", &dvc->en, &o_proto,
		     &dvc->outer_hdr.vid, &i_proto, &dvc->inner_hdr.vid);
	if (cnt != 5)
		return -EINVAL;

	if (__mce_check_dvlan(o_proto, dvc->outer_hdr.vid,
			      &dvc->outer_hdr.type))
		return -EINVAL;
	if (__mce_check_dvlan(i_proto, dvc->inner_hdr.vid,
			      &dvc->inner_hdr.type))
		return -EINVAL;

	if (dvc->en) {
		set_bit(MCE_FLAG_VF_INSERT_VLAN, pf->flags);
		pf->vlan_strip_cnt = 2;
		dvc->cnt = 2;
		hw->ops->set_vlan_strip(hw, netdev->features);

		netdev->features &= ~NETIF_F_HW_VLAN_CTAG_RX;
		netdev->features &= ~NETIF_F_HW_VLAN_CTAG_TX;

		netdev->features &= ~NETIF_F_HW_VLAN_STAG_RX;
		netdev->features &= ~NETIF_F_HW_VLAN_STAG_TX;
		/* enable vlan filter */
		hw->ops->add_vlan_filter(hw, dvc->outer_hdr.vid);
		if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
			return count;
		vf = mce_pf_to_vf(pf);
		if (!vf || !vf->vfinfo)
			return count;
		/* pf take as vf 0, when turn on sriov */
		mce_vf_setup_flr_vlan(pf, PFINFO_IDX, dvc->outer_hdr.vid);
	} else {
		/* disable vlan filter */
		hw->ops->del_vlan_filter(hw, pf->dvlan_ctrl.outer_hdr.vid);
		if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags)) {
			vf = mce_pf_to_vf(pf);
			if (vf && vf->vfinfo) {
				mce_vf_del_flr_vlan(pf, PFINFO_IDX,
						    pf->dvlan_ctrl.outer_hdr.vid);
			}
		}
		memset(&pf->dvlan_ctrl, 0, sizeof(struct mce_dvlan_ctrl));
		clear_bit(MCE_FLAG_VF_INSERT_VLAN, pf->flags);
		netdev->features |= NETIF_F_HW_VLAN_CTAG_RX;
		netdev->features |= NETIF_F_HW_VLAN_CTAG_TX;

		netdev->features |= NETIF_F_HW_VLAN_STAG_RX;
		netdev->features |= NETIF_F_HW_VLAN_STAG_TX;
		pf->vlan_strip_cnt = 1;
		hw->ops->set_vlan_strip(hw, netdev->features);
	}

	return count;
}

DECLEAR_DEBUGFS_OPS(set_dvlan, NULL, set_dvlan_show, set_dvlan_store);

static int priv_header_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			    int buf_sz)
{
	int ret = 0;

	ret += sprintf(buf + ret, "private header enabled: %s\n",
		       pf->priv_h.en ? "yes" : "no");
	if (pf->priv_h.len && pf->priv_h.len < MCE_PRIV_HEADER_LEN_LINIT) {
		ret += sprintf(buf + ret, "data: %s\n", pf->priv_h.priv_header);
		ret += sprintf(buf + ret, "len: %d\n", pf->priv_h.len);
	}
	return ret;
}

static int priv_header_store(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			     size_t count)
{
	struct net_device *netdev = pf->vsi[0]->netdev;
	int cnt;
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

	memset(&pf->priv_h, 0, sizeof(pf->priv_h));
	/* enable + strings */
	cnt = sscanf(buf, "%d %" TOSTRING(MCE_PRIV_HEADER_LEN) "s",
		     &pf->priv_h.en, pf->priv_h.priv_header);
	if (cnt != 2)
		return -EINVAL;

	pf->priv_h.len = pf->priv_h.en ? strlen(pf->priv_h.priv_header) : 0;
	if (pf->priv_h.en) {
		hw->ops->set_dma_tso_cnts_en(hw, pf->priv_h.en);
		hw->ops->set_max_pktlen(hw, netdev->mtu);
	}
	return count;
}

DECLEAR_DEBUGFS_OPS(priv_header, NULL, priv_header_show, priv_header_store);

static int mbx_event_debug_store(struct mce_pf *pf, struct mce_hw *hw,
				 char *buf, size_t count)
{
	int cnt, nr_vf, event_id;

	cnt = sscanf(buf, "%d %d", &nr_vf, &event_id);
	if (cnt != 2)
		return -EINVAL;

	if (nr_vf == -1) {
		mce_broadcast_event_to_vf(pf, event_id, 1000);
	} else if (nr_vf < 128) {
		mce_mbx_send_event_to_vf(&pf->hw, nr_vf, event_id, 1000);
	} else { /* to fw */
		mce_mbx_send_event(&pf->hw.fw_mbx, event_id, 1000);
	}

	return count;
}

DECLEAR_DEBUGFS_OPS(mbx_event_debug, NULL, NULL, mbx_event_debug_store);

static int rxring_info_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			    int buf_sz)
{
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct mce_rx_desc_up *rx_desc = NULL;
	struct mce_ring *rx_ring = NULL;
	int s_id, e_id;
	int ret = 0, i;
#define __DMA_REG_RX_DESC_HEAD (0x3c)
#define __DMA_REG_RX_DESC_TAIL (0x40)

	if (!pf->d_ringinfo.rxring_valid) {
		ret = sprintf(buf,
			      "error: need setup debug rx ring num range first\n");
		return ret;
	}

	s_id = pf->d_ringinfo.rxring_start;
	e_id = pf->d_ringinfo.rxring_end;
	for (i = s_id; i <= e_id; i++) {
		rx_ring = vsi->rx_rings[i];
		ret += sprintf(buf + ret,
			       "====== rx ring num %d info: ======\n", i);
		ret += sprintf(buf + ret, "next_to_use: %d\n",
			       rx_ring->next_to_use);
		ret += sprintf(buf + ret, "next_to_clean: %d\n",
			       rx_ring->next_to_clean);
		ret += sprintf(buf + ret, "hw_head: %d   hw_tail: %d\n",
			       ring_rd32(rx_ring, __DMA_REG_RX_DESC_HEAD),
			       ring_rd32(rx_ring, __DMA_REG_RX_DESC_TAIL));
		rx_desc = MCE_RXDESC_UP(rx_ring, rx_ring->next_to_clean);
		if (rx_desc) {
			ret += sprintf(buf + ret, "next_to_clean desc:\n");
			ret += __print_desc(buf + ret, rx_desc,
					    sizeof(*rx_desc));
			ret += sprintf(buf + ret, "\n");
			rx_desc =
				MCE_RXDESC_UP(rx_ring, rx_ring->next_to_clean);
		} else {
			ret += sprintf(buf + ret, "next_to_clean desc: no\n");
		}
	}
	return ret;
}

static int rxring_info_store(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			     size_t count)
{
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	int s_id, e_id, cnt;

	/* start ring id + end ring id */
	cnt = sscanf(buf, "%d %d", &s_id, &e_id);
	if (cnt != 2 || s_id > e_id)
		return -EINVAL;
	if (e_id >= vsi->num_rxq)
		return -EINVAL;
	pf->d_ringinfo.rxring_start = s_id;
	pf->d_ringinfo.rxring_end = e_id;
	pf->d_ringinfo.rxring_valid = true;
	return count;
}

DECLEAR_DEBUGFS_OPS(rxring_info, NULL, rxring_info_show, rxring_info_store);

static struct netdev_queue *__mce_txring_txq(const struct mce_ring *ring)
{
	return netdev_get_tx_queue(ring->netdev, ring->q_index);
}

static int txring_info_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			    int buf_sz)
{
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct mce_tx_buf *tx_buf = NULL;
	struct mce_ring *tx_ring = NULL;
	struct mce_tx_desc *eop_desc;
	int s_id, e_id;
	int ret = 0, i;
#define __DMA_REG_TX_DESC_HEAD (0x6c)
#define __DMA_REG_TX_DESC_TAIL (0x70)

	if (!pf->d_ringinfo.txring_valid) {
		ret = sprintf(buf,
			      "error: need setup debug tx ring num range first\n");
		return ret;
	}

	s_id = pf->d_ringinfo.txring_start;
	e_id = pf->d_ringinfo.txring_end;
	for (i = s_id; i <= e_id; i++) {
		struct netdev_queue *q;
		struct dql *dql;

		if (i >= vsi->num_txq) {
			ret = sprintf(buf,
				      "error: tx queue id:%d larger than num_txq:%d, exit!\n",
				i, vsi->num_txq);
			return ret;
		}

		tx_ring = vsi->tx_rings[i];
		q = __mce_txring_txq(tx_ring);
		dql = &q->dql;
		ret += sprintf(buf + ret,
			       "====== tx ring num %d info: ======\n", i);
		ret += sprintf(buf + ret, "BQL queue state:0x%lx:\n",
			       q->state);
		ret += sprintf(buf + ret,
			       "1: num_queued:%u adj_limit:%u limit:%u\n",
			       dql->num_queued, dql->adj_limit, dql->limit);
		ret += sprintf(buf + ret,
			"2: num_completed:%u p_ovlimit:%u p_num_queued:%u\n",
			dql->num_completed, dql->prev_ovlimit,
			dql->prev_num_queued);
		ret += sprintf(buf + ret, "3: max_limit:%u min_limit:%u\n",
			       dql->max_limit, dql->min_limit);
		ret += sprintf(buf + ret, "next_to_use: %d\n",
			       tx_ring->next_to_use);
		ret += sprintf(buf + ret, "next_to_clean: %d\n",
			       tx_ring->next_to_clean);
		ret += sprintf(buf + ret, "hw_head: %d   hw_tail: %d\n",
			       ring_rd32(tx_ring, __DMA_REG_TX_DESC_HEAD),
			       ring_rd32(tx_ring, __DMA_REG_TX_DESC_TAIL));
		tx_buf = &tx_ring->tx_buf[tx_ring->next_to_clean];
		eop_desc = tx_buf->next_to_watch;
		if (eop_desc) {
			ret += sprintf(buf + ret, "next_to_watch:\n");
			ret += __print_desc(buf + ret, eop_desc,
					sizeof(*eop_desc));
			ret += sprintf(buf + ret, "\n");
		} else {
			ret += sprintf(buf + ret, "next_to_watch: no\n");
		}
	}

	return ret;
}

static int txring_info_store(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			     size_t count)
{
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	int s_id, e_id, cnt;

	/* start ring id + end ring id */
	cnt = sscanf(buf, "%d %d", &s_id, &e_id);
	if (cnt != 2 || s_id > e_id)
		return -EINVAL;
	if (e_id >= vsi->num_txq)
		return -EINVAL;
	pf->d_ringinfo.txring_start = s_id;
	pf->d_ringinfo.txring_end = e_id;
	pf->d_ringinfo.txring_valid = true;
	return count;
}

DECLEAR_DEBUGFS_OPS(txring_info, NULL, txring_info_show, txring_info_store);

static int rx_wrr_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
		       int buf_sz)
{
	int i, ret = 0;

	ret += sprintf(buf + ret, "rx wrr %s:\n",
		       hw->rx_wrr_en ? "enable" : "disable");
	for (i = 0; i < 8; i++)
		ret += sprintf(buf + ret, "vmark[%d] %d\n", i, hw->vmark[i]);

	return ret;
}

static int rx_wrr_store(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			size_t count)
{
	int cnt, en, vmark[8];

	/* set|clear + vfnum */
	cnt = sscanf(buf, "%d %d %d %d %d %d %d %d %d", &en, &vmark[0],
		     &vmark[1], &vmark[2], &vmark[3], &vmark[4], &vmark[5],
		     &vmark[6], &vmark[7]);
	if (cnt != 9)
		return -EINVAL;
	if (en)
		hw->rx_wrr_en = true;
	else
		hw->rx_wrr_en = false;

	memcpy(hw->vmark, vmark, sizeof(vmark));

	return count;
}

DECLEAR_DEBUGFS_OPS(rx_wrr, NULL, rx_wrr_show, rx_wrr_store);

static int ring_mbx_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			 int buf_sz)
{
	bool en = false;
	int ret = 0;

	en = !!test_bit(MCE_FLAG_MBX_CTRL_ENA, pf->flags);
	ret += sprintf(buf + ret, "ring mbx ctrl enable: %s\n",
		       en ? "yes" : "no");
	en = !!test_bit(MCE_FLAG_MBX_DATA_ENA, pf->flags);
	ret += sprintf(buf + ret, "ring mbx data enable: %s\n",
		       en ? "yes" : "no");
	return ret;
}

static int ring_mbx_store(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			  size_t count)
{
	int cmd, ring_num, cnt;

	/* cmd + ring num
	 * cmd:
	 *    0: clear mbx flags
	 *    1: set mbx ctrl
	 *    2: set mbx data
	 * ring num: 0~15
	 **/
	cnt = sscanf(buf, "%d %d", &cmd, &ring_num);
	if (cnt != 2)
		return -EINVAL;
	if (cmd == 0) {
		clear_bit(MCE_FLAG_MBX_CTRL_ENA, pf->flags);
		clear_bit(MCE_FLAG_MBX_DATA_ENA, pf->flags);
		pf->mbx_ring_id = 0xffff;
	} else if (cmd == 1) {
		pf->mbx_ring_id = ring_num;
		set_bit(MCE_FLAG_MBX_CTRL_ENA, pf->flags);
	} else {
		pf->mbx_ring_id = ring_num;
		set_bit(MCE_FLAG_MBX_DATA_ENA, pf->flags);
	}

	return count;
}

DECLEAR_DEBUGFS_OPS(ring_mbx, NULL, ring_mbx_show, ring_mbx_store);

static int mbx_debug_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			  int buf_sz)
{
	struct mce_mbx_info *mbx = &hw->fw_mbx;
	int i, ret = 0;

	ret += sprintf(buf,
		"%s: tx_event:%d tx_event_err:%d, tx_req:%d tx_shm_lock_timeout:%d\n\t"
		"rx_resp:%d rx_req_shm_lock_err:%d rx_resp_shm_lock_err:%d\n\n",
		mbx->name, mbx->stats.tx_event_cnt, mbx->stats.tx_event_err_cnt,
		mbx->stats.tx_req_cnt, mbx->stats.tx_shm_lock_timeout,
		mbx->stats.rx_resp_cnt, mbx->stats.rx_req_shm_lock_timeout,
		mbx->stats.rx_resp_shm_lock_timeout);

	ret += sprintf(buf + ret, " num_vf:%d\n", hw->num_vfs);

	for (i = 0; i < hw->num_vfs; i++) {
		mbx = &hw->vf_mbx[i];

		ret += sprintf(buf + ret,
			"%s: tx_event:%d tx_event_err:%d, tx_req:%d "
			"tx_shm_lock_timeout:%d\n\t"
			"rx_resp:%d rx_req_shm_lock_err:%d rx_resp_shm_lock_err:%d\n",
			mbx->name, mbx->stats.tx_event_cnt,
			mbx->stats.tx_event_err_cnt, mbx->stats.tx_req_cnt,
			mbx->stats.tx_shm_lock_timeout, mbx->stats.rx_resp_cnt,
			mbx->stats.rx_req_shm_lock_timeout,
			mbx->stats.rx_resp_shm_lock_timeout);
	}

	return ret;
}

DECLEAR_DEBUGFS_OPS(mbx_debug, NULL, mbx_debug_show, NULL);

static int tx_drop_en_store(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			    size_t count)
{
	s32 debug_tx = 0;

	if (kstrtos32(buf, 10, &debug_tx))
		return -EINVAL;

	pf->tx_drop_en = debug_tx;
	return count;
}

DECLEAR_DEBUGFS_OPS(tx_drop_en, NULL, NULL, tx_drop_en_store);

static int temperature_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			    int buf_sz)
{
	int ret = 0, voltage = 0;
	signed char temp = 0;

	hw->ops->update_fw_stat(hw);
	temp = (signed char)hw->fw_stat.stat1.temp;
	voltage = mce_soc_ioread32_noshm(hw, MCE_LG_SOC_VOLTAGE_REG);
	ret += sprintf(buf, "temp:%d oC  volatage:%d mV\n", temp, voltage);
	return ret;
}

DECLEAR_DEBUGFS_OPS(temperature, NULL, temperature_show, NULL);

static int pf_sriov_en_st_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			       int buf_sz)
{
	int pf_sriov_en_st = 0;
	int err = 0;
	int ret = 0;

	err = mce_get_pf_sriov_en_status(hw, &pf_sriov_en_st);
	if (err) {
		ret += sprintf(buf + ret,
			"get pf sriov status failed because of mbx is busy!\n");
		return -EBUSY;
	}

	ret += sprintf(buf + ret, "pf0 sriov is: %s!\n",
		       pf_sriov_en_st & BIT(0) ? "on" : "off");

	ret += sprintf(buf + ret, "pf1 sriov is: %s!\n",
		       pf_sriov_en_st & BIT(1) ? "on" : "off");
	return ret;
}

DECLEAR_DEBUGFS_OPS(pf_sriov_en_st, NULL, pf_sriov_en_st_show, NULL);

static int autoneg_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			int buf_sz)
{
	int ret = 0;

	hw->ops->update_fw_stat(hw);
	ret += sprintf(buf, "%d\n", hw->fw_stat.stat0.autoneg);
	return ret;
}

static int autoneg_store(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			 size_t count)
{
	int err = -EINVAL;
	long enable = 0;

	if (kstrtol(buf, 10, &enable))
		return -EINVAL;

	err = mce_mbx_set_autoneg(hw, !!enable);
	return err ? err : count;
}

DECLEAR_DEBUGFS_OPS(autoneg, NULL, autoneg_show, autoneg_store);

static int disable_40_100g_card_25g_and_below_show(struct mce_pf *pf,
						   struct mce_hw *hw, char *buf,
						   int buf_sz)
{
	return snprintf(buf, buf_sz, "%d\n",
			READ_ONCE(hw->disable_40_100g_card_25g_and_below));
}

static int disable_40_100g_card_25g_and_below_store(struct mce_pf *pf,
						    struct mce_hw *hw, char *buf,
						    size_t count)
{
	long enable;

	if (kstrtol(buf, 10, &enable) || (enable != 0 && enable != 1))
		return -EINVAL;

	WRITE_ONCE(hw->disable_40_100g_card_25g_and_below, !!enable);
	return count;
}

DECLEAR_DEBUGFS_OPS(disable_40_100g_card_25g_and_below, NULL,
		    disable_40_100g_card_25g_and_below_show,
		    disable_40_100g_card_25g_and_below_store);

static int is_valid_si(int si_main, int si_pre, int si_post1, int si_post2,
		       int si_post3)
{
	if (si_main > 63 || si_pre > 63 || si_post1 > 63 || si_post2 > 63 ||
	    si_post3 > 63) {
		return 0;
	}

	if (si_main < -63 || si_pre < -63 || si_post1 < -63 || si_post2 < -63 ||
	    si_post3 < -63) {
		return 0;
	}
	return 1;
}

static int snprintf_si(char *buf, int buf_sz, signed char port_si[4][6])
{
	int i, cnt = 0, lane;

	cnt += SNPRINTF("        main pre post1 post2 post3\n");
	for (lane = 0; lane < 4; lane++) {
		cnt += SNPRINTF(" lane%d \t", lane);
		if (!(port_si[lane][5] & BIT(7))) {
			cnt += SNPRINTF(" -    -    -    -   -\n");
		} else {
			for (i = 0; i < 5; i++)
				cnt += SNPRINTF(" %02d  ", port_si[lane][i]);
			cnt += SNPRINTF("\n");
		}
	}

	return cnt;
}

static int si_show(struct mce_pf *pf, struct mce_hw *hw, char *buf, int buf_sz)
{
	static const char * const serdes_str[] = {
		[SERDES_25G_100G] = "SERDES_25G_100G",
		[SERDES_10G_40G] = "SERDES_10G_40G",
		[SERDES_1G] = "SERDES_1G",
	};
	signed char port_si[4][6];
	int j, err, cnt = 0;

	if (mce_get_port_si(hw, port_si))
		return sprintf(buf, " IO Error\n");

	cnt += SNPRINTF("== running pma si ==\n");
	cnt += snprintf_si(buf + cnt, buf_sz - cnt, port_si);

	cnt += SNPRINTF("\n== si for all speed ==\n");
	for (j = 0; j < SERDERS_SPEED_CNT; j++) {
		cnt += SNPRINTF("%s SI:\n", serdes_str[j]);
		err = mce_get_flash_si(hw, j, port_si);

		if (err == 0)
			cnt += snprintf_si(buf + cnt, buf_sz - cnt, port_si);
		cnt += SNPRINTF("\n");
	}

	return cnt;
}

static int si_store(struct mce_pf *pf, struct mce_hw *hw, char *buf,
		    size_t count)
{
	struct net_device *netdev = mce_get_main_net_dev(pf);
	int i, cnt, err = -EINVAL;
	int port_si[4][6];

	memset(port_si, 0, sizeof(port_si));

	if (count > 100) {
		netdev_err(netdev, "Error: Input size >100: too large\n");
		return -EINVAL;
	}
	if (hw->max_speed >= SPEED_40000) {
		cnt = sscanf(buf,
			     "%d %d %d %d %d,%d %d %d %d %d,%d %d %d %d %d,%d %d %d %d %d",
			&port_si[0][0], &port_si[0][1], &port_si[0][2],
			&port_si[0][3], &port_si[0][4], &port_si[1][0],
			&port_si[1][1], &port_si[1][2], &port_si[1][3],
			&port_si[1][4], &port_si[2][0], &port_si[2][1],
			&port_si[2][2], &port_si[2][3], &port_si[2][4],
			&port_si[3][0], &port_si[3][1], &port_si[3][2],
			&port_si[3][3], &port_si[3][4]);
		if (cnt != 5 * 4) {
			netdev_err(netdev,
				   "Error: Invalid Input: "
				   "<main> <pre> <post1> <post2> <post3>,"
				   "<main> <pre> <post1> <post2> <post3>,"
				   "<main> <pre> <post1> <post2> <post3>,"
				   "<main> <pre> <post1> <post2> <post3>\n");
			return -EINVAL;
		}

		for (i = 0; i < 5; i++) {
			if (is_valid_si(port_si[i][0], port_si[i][1],
					port_si[i][2], port_si[i][3],
					port_si[i][4]) == 0) {
				netdev_err(netdev,
					   "Error: Invalid value. should in ~63~63\n");
				return -EINVAL;
			}

			port_si[i][5] = BIT(7);
		}
	} else {
		cnt = sscanf(buf, "%d %d %d %d %d", &port_si[0][0],
			     &port_si[0][1], &port_si[0][2], &port_si[0][3],
			     &port_si[0][4]);
		if (cnt != 5) {
			netdev_err(netdev,
				   "Error: Invalid Input: <main> <pre> <post1> <post2> <post3>\n");
			return -EINVAL;
		}

		if (is_valid_si(port_si[0][0], port_si[0][1], port_si[0][2],
				port_si[0][3], port_si[0][4]) == 0) {
			netdev_err(netdev,
				   "Error: Invalid value. should in ~63~63\n");
			return -EINVAL;
		}
		port_si[0][5] = BIT(7);
	}

	err = mce_set_port_si(hw, port_si);
	return err ? err : count;
}

DECLEAR_DEBUGFS_OPS(si, NULL, si_show, si_store);

static int sfp_show(struct mce_pf *pf, struct mce_hw *hw, char *buf, int buf_sz)
{
	int ret = 0;

	hw->ops->update_fw_stat(hw);

	if (hw->fw_stat.stat0.s_speed >= Z_SPEED_40G) {
		ret += sprintf(buf,
			"mod-abs:%d\nmodsel:%d\nlpmode:%d\nintl:%d\nresetl:%d\n",
			hw->fw_stat.stat0.sfp_mod_abs,
			hw->fw_stat.stat0.sfp_fault,
			hw->fw_stat.stat0.sfp_tx_dis, hw->fw_stat.stat0.sfp_los,
			hw->fw_stat.stat0.qsfp_resetl_rs0);
	} else {
		ret += sprintf(buf,
			"mod-abs:%d\ntx-fault:%d\ntx-dis:%d\nrx-los:%d\nrs0:%d\n",
			hw->fw_stat.stat0.sfp_mod_abs,
			hw->fw_stat.stat0.sfp_fault,
			hw->fw_stat.stat0.sfp_tx_dis, hw->fw_stat.stat0.sfp_los,
			hw->fw_stat.stat0.qsfp_resetl_rs0);
	}

	return ret;
}

DECLEAR_DEBUGFS_OPS(sfp, NULL, sfp_show, NULL);

static int sfp_tx_disable_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			       int buf_sz)
{
	int ret = 0;

	hw->ops->update_fw_stat(hw);

	ret += sprintf(buf, "%d\n", hw->fw_stat.stat0.sfp_tx_dis);
	return ret;
}

static int sfp_tx_disable_store(struct mce_pf *pf, struct mce_hw *hw, char *buf,
				size_t count)
{
	int err = -EINVAL;
	long enable = 0;

	if (kstrtol(buf, 10, &enable))
		return -EINVAL;

	err = mce_mbx_set_phy_func(hw, PHY_FUN_SFP_TX_DISABLE, !!enable, 0);
	return err ? err : count;
}

DECLEAR_DEBUGFS_OPS(sfp_tx_disable, NULL, sfp_tx_disable_show,
		    sfp_tx_disable_store);

/* Export per-RX-ring page and traffic counters in a stable, machine-readable
 * form. The counters are cumulative from ring creation; userspace computes
 * interval deltas when it needs rates or reuse ratios.
 */
static int rx_page_stats_show(struct mce_pf *pf, struct mce_hw *hw,
			      char *buf, int buf_sz)
{
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	int cnt = 0;
	u16 i;

	for (i = 0; i < vsi->num_rxq; i++) {
		struct mce_ring_stats *ring_stats;
		int pp_stats_supported = 0;
		struct mce_ring *rx_ring;
		int pp_release = 0;
		unsigned int start;
		u32 pp_hold = 0;
		u64 bytes;
		u64 pkts;

		rx_ring = READ_ONCE(vsi->rx_rings[i]);
		if (!rx_ring)
			continue;

		ring_stats = READ_ONCE(rx_ring->ring_stats);
		if (!ring_stats)
			continue;

		do {
			start = u64_stats_fetch_begin(&ring_stats->syncp);
			pkts = ring_stats->stats.pkts;
			bytes = ring_stats->stats.bytes;
		} while (u64_stats_fetch_retry(&ring_stats->syncp, start));

		if (cnt >= buf_sz)
			break;

		cnt += scnprintf(buf + cnt, buf_sz - cnt,
				 "queue=%u packets=%llu bytes=%llu "
				 "alloc_page_ok=%llu alloc_page_failed=%llu "
				 "page_reuse_ok=%llu page_reuse_reserved=%llu "
				 "page_reuse_refcnt=%llu page_reuse_offset=%llu "
				 "pp_alloc_ok=%llu pp_alloc_fail=%llu "
				 "pp_recycle=%llu pp_put=%llu pp_re_poll=%llu "
				 "page_pool_stats_supported=%d page_pool_hold=%u "
				 "page_pool_release=%d\n",
				 i, pkts, bytes,
				 READ_ONCE(ring_stats->rx_stats.alloc_page_ok),
				 READ_ONCE(ring_stats->rx_stats.alloc_page_failed),
				 READ_ONCE(ring_stats->rx_stats.page_reuse_ok),
				 READ_ONCE(ring_stats->rx_stats.page_reuse_reserved),
				 READ_ONCE(ring_stats->rx_stats.page_reuse_refcnt),
				 READ_ONCE(ring_stats->rx_stats.page_reuse_offset),
				 READ_ONCE(ring_stats->rx_stats.pp_alloc_ok),
				 READ_ONCE(ring_stats->rx_stats.pp_alloc_fail),
				 READ_ONCE(ring_stats->rx_stats.pp_recycle),
				 READ_ONCE(ring_stats->rx_stats.pp_put),
				 READ_ONCE(ring_stats->rx_stats.pp_re_poll),
				 pp_stats_supported, pp_hold, pp_release);
	}

	return cnt;
}

DECLEAR_DEBUGFS_OPS(rx_page_stats, NULL, rx_page_stats_show, NULL);

static int prbs_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
		     int buf_sz)
{
	return sprintf(buf,
		       "supported prbs: 0(disable prbs), 9, 15, 23, 31 8081\n");
}

static int prbs_store(struct mce_pf *pf, struct mce_hw *hw, char *buf,
		      size_t count)
{
	int err = -EINVAL;
	long prbs = 0;

	if (kstrtol(buf, 10, &prbs))
		return -EINVAL;
	if (prbs != 0 && prbs != 8081 && prbs != 9 && prbs != 15 &&
	    prbs != 23 && prbs != 31) {
		dev_err(mce_pf_to_dev(pf),
			"invalid input: valid value is:0,9,15,23,31,8081\n");
		return -EINVAL;
	}

	err = mce_mbx_set_phy_func(hw, PHY_FUN_PRBS, prbs, 0);
	return err ? err : count;
}

DECLEAR_DEBUGFS_OPS(prbs, NULL, prbs_show, prbs_store);

static int link_traing_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			    int buf_sz)
{
	int ret = 0;

	hw->ops->update_fw_stat(hw);

	ret += sprintf(buf, "%d\n", hw->fw_stat.stat0.link_traing);
	return ret;
}

static int link_traing_store(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			     size_t count)
{
	int err = -EINVAL;
	long enable = 0;

	if (kstrtol(buf, 10, &enable))
		return -EINVAL;

	err = mce_mbx_set_link_traning_en(hw, enable);
	return err ? err : count;
}

DECLEAR_DEBUGFS_OPS(link_traing, NULL, link_traing_show, link_traing_store);

static int pf_reset_store(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			  size_t count)
{
	set_bit(MCE_FLAG_PF_RESET_ENA, pf->flags);
	return count;
}

DECLEAR_DEBUGFS_OPS(pf_reset, NULL, NULL, pf_reset_store);

static int pci_show(struct mce_pf *pf, struct mce_hw *hw, char *buf, int buf_sz)
{
	int ret = 0;

	int pci_status = mce_soc_ioread32_noshm(hw, MCE_LG_SOC_PCI_SPEED);

	ret += sprintf(buf, "gen%dx%d\n", (pci_status >> 4) & 0b111,
		       pci_status & 0xf);
	return ret;
}

static int pci_store(struct mce_pf *pf, struct mce_hw *hw, char *buf,
		     size_t count)
{
	struct net_device *netdev = mce_get_main_net_dev(pf);
	int gen = 4, lanes = 8;
	int err = -EINVAL;

	if (count > 30)
		return -EINVAL;

	if (sscanf(buf, "gen%dx%d", &gen, &lanes) != 2) {
		netdev_err(netdev, "Error: invalid input. example: gen3x8\n");
		return -EINVAL;
	}
	if (gen > 4 || lanes > 16)
		return -EINVAL;

	err = mce_mbx_set_phy_func(hw, PHY_FUN_PCI_LANE, gen, lanes);
	return err ? err : count;
}

DECLEAR_DEBUGFS_OPS(pci, NULL, pci_show, pci_store);

static int pri2buf_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			int buf_sz)
{
	struct mce_dcb *dcb = pf->dcb;
	struct mce_pfc_cfg *pfccfg = &dcb->cur_pfccfg;
	int ret = 0;

	ret += sprintf(buf + ret, "Priority Buffer: %d %d %d %d %d %d %d %d\n",
		       pfccfg->rx_pri2buf[0], pfccfg->rx_pri2buf[1],
		       pfccfg->rx_pri2buf[2], pfccfg->rx_pri2buf[3],
		       pfccfg->rx_pri2buf[4], pfccfg->rx_pri2buf[5],
		       pfccfg->rx_pri2buf[6], pfccfg->rx_pri2buf[7]);
	return ret;
}

static int pri2buf_store(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			 size_t count)
{
	struct mce_dcb *dcb = pf->dcb;
	struct mce_pfc_cfg *pfccfg = &dcb->cur_pfccfg;
	int pri2buf[MCE_MAX_PRIORITY];
	int cnt, i;

	if (!test_bit(MCE_FLAG_RX_BUFFER_MANUALLY, pf->flags))
		return -EINVAL;

	cnt = sscanf(buf, "%d %d %d %d %d %d %d %d", &pri2buf[0], &pri2buf[1],
		     &pri2buf[2], &pri2buf[3], &pri2buf[4], &pri2buf[5],
		     &pri2buf[6], &pri2buf[7]);
	if (cnt != 8)
		return -EINVAL;

	for (i = 0; i < MCE_MAX_PRIORITY; i++) {
		if (pri2buf[i] >= MCE_MAX_PRIORITY)
			return -EINVAL;
		pfccfg->rx_pri2buf[i] = pri2buf[i];
	}

	return count;
}

DECLEAR_DEBUGFS_OPS(pri2buf, NULL, pri2buf_show, pri2buf_store);

static int buffer_size_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			    int buf_sz)
{
	struct mce_dcb *dcb = pf->dcb;
	struct mce_pfc_cfg *pfccfg = &dcb->cur_pfccfg;
	int ret = 0;

	if (test_bit(MCE_FLAG_RX_BUFFER_MANUALLY, pf->flags))
		ret += sprintf(buf + ret, "Manually on\n");
	else
		ret += sprintf(buf + ret, "Manually off\n");

	ret += sprintf(buf + ret,
		       "Buffer size(bytes): %d %d %d %d %d %d %d %d\n",
		       pfccfg->fifo_depth[0] * 64, pfccfg->fifo_depth[1] * 64,
		       pfccfg->fifo_depth[2] * 64, pfccfg->fifo_depth[3] * 64,
		       pfccfg->fifo_depth[4] * 64, pfccfg->fifo_depth[5] * 64,
		       pfccfg->fifo_depth[6] * 64, pfccfg->fifo_depth[7] * 64);
	/* setup the new rx setup */
	return ret;
}

static int buffer_size_store(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			     size_t count)
{
	struct mce_dcb *dcb = pf->dcb;
	struct mce_pfc_cfg *pfccfg = &dcb->cur_pfccfg;
	int fifo[MCE_MAX_PRIORITY];
	int tmp = 0, cnt;
	int sum = 0, i;
	/* at least 1024 */
	if (!test_bit(MCE_FLAG_RX_BUFFER_MANUALLY, pf->flags))
		return -EINVAL;

	cnt = sscanf(buf, "%d %d %d %d %d %d %d %d", &fifo[0], &fifo[1],
		     &fifo[2], &fifo[3], &fifo[4], &fifo[5], &fifo[6],
		     &fifo[7]);
	if (cnt != 8)
		return -EINVAL;

	/* check total */
	for (i = 0; i < MCE_MAX_PRIORITY; i++) {
		/* low-assign to 16 */
		fifo[i] = fifo[i] / 64;
		/* if this fifo is used, min 0x400 */
		if (check_pri2buf(pfccfg, i) && fifo[i] < 0x400)
			return -EINVAL;
		sum += fifo[i];
	}

	if (sum > N20_FIFO_TAL_DEEP)
		return -EINVAL;
	/* store it to hw */
	for (i = 0; i < MCE_MAX_PRIORITY; i++) {
		pfccfg->fifo_head[i] = tmp;
		pfccfg->fifo_tail[i] = tmp + fifo[i] - 1;
		pfccfg->fifo_depth[i] = fifo[i];
		tmp += fifo[i];
	}

	hw->ops->setup_rx_buffer(hw);

	return count;
}

DECLEAR_DEBUGFS_OPS(buffer_size, NULL, buffer_size_show, buffer_size_store);

static int tx_debug_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			 int buf_sz)
{
	int ret = 0;

	ret = sprintf(buf, "debug tx queue:%d\n", pf->debug_tx);
	return ret;
}

static int tx_debug_store(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			  size_t count)
{
	s32 debug_tx = 0;

	if (kstrtos32(buf, 10, &debug_tx))
		return -EINVAL;

	pf->debug_tx = debug_tx;
	return count;
}

DECLEAR_DEBUGFS_OPS(tx_debug, NULL, tx_debug_show, tx_debug_store);

static int vport_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
		      int buf_sz)
{
	int cnt =
		snprintf(buf, buf_sz, "default vport:%d\n", pf->default_vport);

	return cnt;
}

static int vport_store(struct mce_pf *pf, struct mce_hw *hw, char *buf,
		       size_t count)
{
	s32 d_vport = 0;

	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return -EPERM;

	if (kstrtos32(buf, 10, &d_vport))
		return -EINVAL;

	/* if d_vport less than zero, restore default config,
	 * other setup the default vport.
	 */
	if (d_vport < 0)
		d_vport = PFINFO_IDX;
	if (d_vport >= pf->num_vfs)
		return -EINVAL;
	pf->default_vport = d_vport;
	hw->vf.ops->set_vf_default_vport(hw, d_vport);
	return count;
}

DECLEAR_DEBUGFS_OPS(default_vport, NULL, vport_show, vport_store);

static int axi_mhz_states_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			       int buf_sz)
{
	int cnt = snprintf(buf, buf_sz, "%d Mhz", mce_mbx_axi_mhz_get(hw));

	return cnt;
}

static int axi_mhz_states_store(struct mce_pf *pf, struct mce_hw *hw, char *buf,
				size_t count)
{
	u32 axi_mhz = 0;
	int err = 0;

	if (kstrtou32(buf, 0, &axi_mhz))
		return -EINVAL;

	err = mce_mbx_axi_mhz_set(hw, axi_mhz);
	if (err)
		return err;

	return count;
}

DECLEAR_DEBUGFS_OPS(axi_mhz, NULL, axi_mhz_states_show, axi_mhz_states_store);

static void to_binary(u16 num, char *binary_str, int bits)
{
	int i;

	for (i = bits - 1; i >= 0; i--)
		binary_str[bits - 1 - i] = (num & (1 << i)) ? '1' : '0';

	binary_str[bits] = '\0';
}

static int rdma_prio_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			  int buf_sz)
{
	struct iidc_core_dev_info *cdev_info = pf->cdev_infos;
	char string[30];
	int cnt = 0;

	if (!cdev_info)
		return -ENODEV;

	to_binary(cdev_info->valid_prio, string, 8);

	cnt += SNPRINTF("rdma prio %s\n", string);
	return cnt;
}

static int rdma_prio_store(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			   size_t count)
{
	struct iidc_core_dev_info *cdev_info = pf->cdev_infos;
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct net_device *netdev;
	struct iidc_event *event;
	u16 valid = 0;

	netdev = mce_get_main_net_dev(pf);
	if (!cdev_info)
		return -ENODEV;

	if (kstrtos16(buf, 2, &valid))
		return -EINVAL;
	if (valid == 0xff)
		return -EINVAL;
	if (valid == 0x7f) {
		dev_err(mce_pf_to_dev(pf), "at least 1 for nic\n");
		return -EINVAL;
	}

	if (valid & 0x80) {
		dev_err(mce_pf_to_dev(pf),
			"never use prio 7, reserved for qp1\n");
		return -EINVAL;
	}

	cdev_info->valid_prio = valid & 0xff;

	vsi->valid_prio = (~cdev_info->valid_prio);

	/* if mrdma insmod, should never use prio7 */
	if (pf->m_status == MRDMA_INSMOD)
		vsi->valid_prio &= 0x7f;

	mce_force_close_dcb(pf);
	event = kzalloc(sizeof(*event), GFP_KERNEL);

	set_bit(IIDC_EVENT_PRIO_CHNG, event->type);
	mce_send_event_to_auxs(pf, event);
	kfree(event);
	mce_recover_dcb(pf);
	mce_reset_vf(netdev);

	return count;
}

DECLEAR_DEBUGFS_OPS(rdma_prio, NULL, rdma_prio_show, rdma_prio_store);

static int debugfs_cdev_name_show(struct mce_pf *pf, struct mce_hw *hw,
				  char *buf, int buf_sz)
{
	int cnt = snprintf(buf, buf_sz, "%s", pf->name);

	return cnt;
}

DECLEAR_DEBUGFS_OPS(cdev_name, NULL, debugfs_cdev_name_show, NULL);

static int fdir_usage_show(struct mce_pf *pf, struct mce_hw *hw,
			   char *buf, int buf_sz)
{
	int cnt = 0;

	cnt += SNPRINTF("fdir flow engine: unsupported\n");

	return cnt;
}

DECLEAR_DEBUGFS_OPS(fdir_usage, NULL, fdir_usage_show, NULL);

DECLEAR_DEBUGFS_OPS(rx_states, NULL, debugfs_rx_states_show,
		    mce_debugfs_queue_write);
DECLEAR_DEBUGFS_OPS(tx_states, NULL, debugfs_tx_states_show,
		    mce_debugfs_queue_write);
DECLEAR_DEBUGFS_OPS(rx_queue_state, NULL, debugfs_rx_queue_show,
		    mce_debugfs_queue_write);
DECLEAR_DEBUGFS_OPS(tx_queue_state, NULL, debugfs_tx_queue_show,
		    mce_debugfs_queue_write);
DECLEAR_DEBUGFS_OPS(fd_rx_debug, NULL, fd_rx_debug_show, NULL);
DECLEAR_DEBUGFS_OPS(fd_query_rule, NULL, fd_query_rule_show, NULL);

DECLEAR_DEBUGFS_OPS(tc_states, NULL, tc_states_show, NULL);
DECLEAR_DEBUGFS_OPS(hwpfc_states, NULL, hwpfc_states_show, NULL);
DECLEAR_DEBUGFS_OPS(hwets_states, NULL, hwets_states_show, NULL);

#define PCS_OFF 0x60000
#define PMA_OFF(off) ((((off) - 0x6000) << 2))

struct dst_info {
	u8 __iomem *addr_base;
	bool is_pma;
	bool is_soc;
	int max_size;
};

static u8 __iomem *dst_to_addr(struct mce_hw *hw, const char *dst_name,
			       struct dst_info *dst)
{
	memset(dst, 0, sizeof(*dst));

	if (!strcmp(dst_name, "bar0")) {
		if (hw->bar_1th) {
			dst->addr_base = hw->bar_1th;
			dst->max_size = pci_resource_len(hw->pdev, 0);
		}
	} else if (!strcmp(dst_name, "bar2")) {
		if (hw->bar_2th) {
			dst->addr_base = hw->bar_2th;
			dst->max_size = pci_resource_len(hw->pdev, 2);
		}
	} else if (!strcmp(dst_name, "bar4")) {
		if (hw->bar_3th) {
			dst->addr_base = hw->bar_3th;
			dst->max_size = pci_resource_len(hw->pdev, 4);
		}
	} else if (!strcmp(dst_name, "rdma")) {
		if (hw->rdma_bar_base) {
			dst->addr_base = hw->rdma_bar_base;
			dst->max_size = 1 * 1024 * 1024;
		}
	} else if (!strcmp(dst_name, "rpu")) {
		if (hw->npu_bar_base) {
			dst->addr_base = hw->npu_bar_base;
			dst->max_size = 16 * 1024 * 1024;
		}
	} else if (!strcmp(dst_name, "pma")) {
		if (hw->eth_bar_base) {
			dst->addr_base = hw->eth_bar_base + 0x50000;
			dst->is_pma = 1;
			dst->max_size = 0x10000;
		}
	} else if (!strcmp(dst_name, "pcs")) {
		if (hw->eth_bar_base) {
			dst->addr_base = hw->eth_bar_base + PCS_OFF;
			dst->max_size = 0x7400;
		}
	} else if (!strcmp(dst_name, "cesoc")) {
		if (hw->eth_bar_base) {
			dst->addr_base = hw->eth_bar_base + PCS_OFF + 0x6800;
			dst->max_size = 0x400;
		}
	} else if (!strcmp(dst_name, "cemdio")) {
		if (hw->eth_bar_base) {
			dst->addr_base = hw->eth_bar_base + PCS_OFF + 0x6c00;
			dst->max_size = 0x400;
		}
	} else if (!strcmp(dst_name, "cean")) {
		if (hw->eth_bar_base) {
			dst->addr_base = hw->eth_bar_base + PCS_OFF + 0x7000;
			dst->max_size = 0x400;
		}
	} else if (!strcmp(dst_name, "cemac")) {
		if (hw->eth_bar_base) {
			dst->addr_base = hw->eth_bar_base + PCS_OFF + 0x4000;
			dst->max_size = 0x2800;
		}
	} else if (!strcmp(dst_name, "soc")) {
		dst->is_soc = true;
		dst->max_size = 0x60000000;
	} else if (!strcmp(dst_name, "nic")) {
		if (hw->eth_bar_base) {
			dst->addr_base = hw->eth_bar_base;
			dst->max_size = pci_resource_len(hw->pdev, 4);
		}
	}
	return dst->addr_base;
}

static int reg_rw_store(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			size_t count)
{
	int err = 0, reg_off = 0, reg_v = 0, reg_cnt = 1, cnt, i;
	struct device *dev = mce_pf_to_dev(pf);
	struct dst_info dst_base;
	u8 __iomem *reg_base_addr;
	char dst_name[32];

	pf->debugfs_reg_rd_has_output = false;

	if (strstr(buf, "help")) {
		goto err_quit_usage;
	} else if (strstr(buf, "rd")) {
		cnt = sscanf(buf, "%s rd 0x%x %d", dst_name, &reg_off,
			     &reg_cnt);
		if (cnt < 2) {
			err = -EINVAL;
			goto err_quit_usage;
		}
		reg_base_addr = dst_to_addr(hw, dst_name, &dst_base);
		if (dst_base.is_soc == 0 && !reg_base_addr) {
			err = -EINVAL;
			dev_err(dev, "can't find reg for %s\n", dst_name);
			goto err_quit;
		}
		if (dst_base.is_soc == 0 && reg_off > dst_base.max_size) {
			err = -EINVAL;
			dev_err(dev, "off:0x%x > max_size:0x%x\n", reg_off,
				dst_base.max_size);
			goto err_quit;
		}

		reg_cnt = min(reg_cnt, 1024);
		reg_cnt = min(reg_cnt, dst_base.max_size);

		err = init_debugfs_buffer(pf, hw);
		if (err < 0)
			return err;

		cnt = 0;
		for (i = 0; i < reg_cnt; i++) {
			if (dst_base.is_soc) {
				err = mce_soc_ioread32(hw, reg_off, &reg_v);
				if (err) {
					dev_err(dev, "soc read 0x%x failed!\n",
						reg_off);
					return -EIO;
				}
				reg_off += 4;
			} else {
				if (dst_base.is_pma) {
					reg_v = raw_rd32(reg_base_addr +
							 PMA_OFF(reg_off));
					reg_off += 1;
				} else {
					reg_v = raw_rd32(reg_base_addr +
							 reg_off);
					reg_off += 4;
				}
			}
			cnt += snprintf(pf->debugfs_buf + cnt,
					pf->debugfs_buf_bytes - cnt, "0x%08x\n",
					reg_v);
		}
		pf->debugfs_buf_msg_size = cnt;
		pf->debugfs_reg_rd_has_output = true;
	} else if (strstr(buf, "wr")) {
		cnt = sscanf(buf, "%s wr 0x%x 0x%x", dst_name, &reg_off,
			     &reg_v);
		if (cnt != 3) {
			err = -EINVAL;
			goto err_quit_usage;
		}

		reg_base_addr = dst_to_addr(hw, dst_name, &dst_base);
		if (dst_base.is_soc == 0 && !reg_base_addr) {
			err = -EINVAL;
			dev_err(dev, "can't find reg for %s\n", dst_name);
			goto err_quit;
		}
		if (dst_base.is_soc == 0 && reg_off > dst_base.max_size) {
			err = -EINVAL;
			dev_err(dev, "off:0x%x > max_size:0x%x\n", reg_off,
				dst_base.max_size);
			goto err_quit;
		}

		if (dst_base.is_soc) {
			err = mce_soc_iowrite32(hw, reg_off, reg_v);
			if (err) {
				dev_err(dev, "soc read 0x%x failed!\n",
					reg_off);
				return -EIO;
			}
		} else {
			if (dst_base.is_pma) {
				raw_wr32(reg_v,
					 reg_base_addr + PMA_OFF(reg_off));
			} else {
				raw_wr32(reg_v, reg_base_addr + reg_off);
			}
		}
	} else {
		err = -EINVAL;
		goto err_quit_usage;
	}

	return count;
err_quit_usage:
	dev_info(dev,
		 "Usage:\n\t<dst> rd <reg_off:hex> [cnt]\n\t"
		"<dst> wr <reg_off:hex> <reg_v:hex>\n\t"
		"\n\t"
		"dst: bar0|bar2|bar4|rdma|rpu|pma|pcs|mac|phy|cemdio|cesoc|nic|soc");
err_quit:
	return err;
}

static int reg_rw_show_pre(struct mce_pf *pf, struct mce_hw *hw __maybe_unused,
			   char __user *buf __maybe_unused,
			   int buf_sz __maybe_unused)
{
	if (!pf->debugfs_reg_rd_has_output)
		return -ENOBUFS;
	pf->debugfs_reg_rd_has_output = false;
	return 0;
}

DECLEAR_DEBUGFS_OPS(reg_rw, reg_rw_show_pre, NULL, reg_rw_store);

static int get_dump_buf(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			int buf_sz)
{
	int ret = mce_mbx_get_dump(hw, 0, buf, (buf_sz > 4096) ? 4096 : buf_sz,
				   NULL, NULL);
	if (ret < 0) {
		dev_err(mce_pf_to_dev(pf), "%s: get dump data  failed\n",
			pci_name(pf->pdev));
		return 0;
	}
	return ret;
}

static int dump_v_store(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			size_t count)
{
	u32 dump_v = 0;

	if (kstrtou32(buf, 0, &dump_v))
		return -EINVAL;

	if (mce_mbx_set_dump(hw, dump_v))
		return -EIO;

	return count;
}

DECLEAR_DEBUGFS_OPS(dump_v, NULL, get_dump_buf, dump_v_store);

static int dump_link_pre(struct mce_pf *pf, struct mce_hw *hw, char __user *buf,
			 int count)
{
	int err = mce_mbx_set_dump(hw, 0x010d0000);

	if (err)
		return -EIO;
	return 0;
}

DECLEAR_DEBUGFS_OPS(dump_link, dump_link_pre, get_dump_buf, NULL);

static int dump_port_pre(struct mce_pf *pf, struct mce_hw *hw, char __user *buf,
			 int count)
{
	int err = mce_mbx_set_dump(hw, 0x01020000);

	if (err)
		return -EIO;
	return 0;
}

DECLEAR_DEBUGFS_OPS(dump_port, dump_port_pre, get_dump_buf, NULL);

static int sfp_info_show_pre(struct mce_pf *pf, struct mce_hw *hw,
			     char __user *buf, int count)
{
	int err = mce_mbx_set_dump(hw, hw->nr_pf ? 0x01020002 : 0x01020001);

	if (err)
		return -EIO;
	return 0;
}

DECLEAR_DEBUGFS_OPS(dump_sfp_info, sfp_info_show_pre, get_dump_buf, NULL);

static ssize_t mce_emit_cpumask_cpulist(char *buf, size_t size,
					const struct cpumask *mask)
{
	ssize_t len = 0;
	int range_start = -1;
	int prev_cpu = -1;
	bool first = true;
	int cpu;

	for_each_cpu(cpu, mask) {
		if (range_start < 0) {
			range_start = cpu;
			prev_cpu = cpu;
			continue;
		}

		if (cpu == prev_cpu + 1) {
			prev_cpu = cpu;
			continue;
		}

		len += scnprintf(buf + len, size - len, first ? "%d" : ",%d",
				 range_start);
		if (prev_cpu != range_start)
			len += scnprintf(buf + len, size - len, "-%d",
					 prev_cpu);
		first = false;
		range_start = cpu;
		prev_cpu = cpu;
	}

	if (range_start >= 0) {
		len += scnprintf(buf + len, size - len, first ? "%d" : ",%d",
				 range_start);
		if (prev_cpu != range_start)
			len += scnprintf(buf + len, size - len, "-%d",
					 prev_cpu);
	} else {
		len += scnprintf(buf + len, size - len, "none");
	}

	return len;
}

static ssize_t mce_emit_q_range(char *buf, size_t size, u16 base, u8 count)
{
	if (!count)
		return scnprintf(buf, size, "none");

	if (count == 1)
		return scnprintf(buf, size, "%u", base);

	return scnprintf(buf, size, "%u-%u", base, base + count - 1);
}

static int q_vector_affinity_show(struct mce_pf *pf, struct mce_hw *hw,
				  char *buf, int buf_sz)
{
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	int cnt = 0;
	int i;

	if (!vsi)
		return SNPRINTF("main vsi unavailable\n");

	cnt += SNPRINTF("vsi=%u num_q_vectors=%u base_vector=%u numa_node=%d\n",
			vsi->idx, vsi->num_q_vectors, vsi->base_vector,
			dev_to_node(&pf->pdev->dev));

	mce_for_each_q_vector(vsi, i) {
		struct mce_q_vector *q_vector = vsi->q_vectors[i];
		const struct cpumask *effective_mask = NULL;
		const struct cpumask *irq_mask = NULL;
		u16 tx_base = 0, rx_base = 0;
		char effective_cpulist[128];
		char qvec_cpulist[128];
		char irq_cpulist[128];
		char tx_range[32];
		char rx_range[32];
		int irq_num = -1;

		if (!q_vector)
			continue;

		mce_vsi_get_q_vector_q_base(vsi, i, &tx_base, &rx_base);
		mce_emit_cpumask_cpulist(qvec_cpulist, sizeof(qvec_cpulist),
					 &q_vector->affinity_mask);
		mce_emit_q_range(tx_range, sizeof(tx_range), tx_base,
				 q_vector->num_ring_tx);
		mce_emit_q_range(rx_range, sizeof(rx_range), rx_base,
				 q_vector->num_ring_rx);
		if (vsi->irqs_ready) {
			irq_num = mce_get_irq_num(pf, vsi->base_vector + i);
			irq_mask = irq_get_affinity_mask(irq_num);
			effective_mask = irq_get_affinity_mask(irq_num);
		}

		if (irq_mask)
			mce_emit_cpumask_cpulist(irq_cpulist, sizeof(irq_cpulist),
						 irq_mask);
		else
			scnprintf(irq_cpulist, sizeof(irq_cpulist), "none");

		if (effective_mask)
			mce_emit_cpumask_cpulist(effective_cpulist,
						 sizeof(effective_cpulist),
						 effective_mask);
		else
			scnprintf(effective_cpulist, sizeof(effective_cpulist), "none");

		cnt += SNPRINTF("vec=%d irq=%d txq=%s rxq=%s qvec_cpus=%s irq_cpus=%s "
				"effective_cpus=%s %s\n",
				i, irq_num, tx_range, rx_range, qvec_cpulist,
				irq_cpulist, effective_cpulist,
				q_vector->name[0] ? q_vector->name : "-");
		if (cnt >= buf_sz - 1)
			break;
	}

	return cnt;
}

DECLEAR_DEBUGFS_OPS(q_vector_affinity, NULL, q_vector_affinity_show, NULL);

static int vf_rate_info_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			     int buf_sz)
{
	int ret = 0;

	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return -EPERM;

	ret += sprintf(buf + ret, "vf rate qos_ms:%d\n",
		       hw->vf_rate_qos.interal);
	return ret;
}

static int vf_rate_info_store(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			      size_t count)
{
	u32 qos_ms;

	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return -EPERM;

	if (kstrtou32(buf, 10, &qos_ms))
		return -EINVAL;

	hw->vf_rate_qos.interal = qos_ms % 100;
	mce_set_bw_limit_init(pf);
	return count;
}

DECLEAR_DEBUGFS_OPS(vf_rate_info, NULL, vf_rate_info_show, vf_rate_info_store);

static void debugfs_command_help(struct device *dev, char *cmd_buf)
{
	dev_info(dev, "unknown or invalid command '%s'\n", cmd_buf);
	dev_info(dev, "available commands\n");
	dev_info(dev, "\t dump all\n");
	dev_info(dev, "\t dump ring\n");
	dev_info(dev, "\t dump dma\n");
	dev_info(dev, "\t dump mux\n");
	dev_info(dev, "\t dump parser\n");
	dev_info(dev, "\t dump fwd_proc\n");
	dev_info(dev, "\t dump editor\n");
	dev_info(dev, "\t dump fwd_attr\n");
	dev_info(dev, "\t dump oop\n");
	dev_info(dev, "\t dump tc\n");
	dev_info(dev, "\t dump hwpfc\n");
}

/**
 * mce_debugfs_command_write - write into command datum
 * @filp: the opened file
 * @buf: where to find the user's data
 * @count: the length of the user's data
 * @ppos: file position offset
 * Returns: The result of the operation.
 */
static ssize_t mce_debugfs_command_write(struct file *filp,
					 const char __user *buf, size_t count,
					 loff_t *ppos)
{
	struct mce_pf *pf = filp->private_data;
	struct device *dev = mce_pf_to_dev(pf);
	struct mce_hw *hw = &pf->hw;
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;

	/* don't allow partial writes */
	if (*ppos != 0)
		return 0;

	cmd_buf = memdup_user(buf, count + 1);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);
	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = (size_t)cmd_buf_tmp - (size_t)cmd_buf + 1;
	}

	argv = argv_split(GFP_KERNEL, cmd_buf, &argc);
	if (!argv) {
		ret = -ENOMEM;
		goto err_copy_from_user;
	}

	if (argc == 2 && !strncmp(argv[0], "dump", 4)) {
		ret = hw->ops->dump_debug_regs(hw, argv[1]);
		if (ret) {
			debugfs_command_help(dev, cmd_buf);
			ret = -EINVAL;
			goto command_write_error;
		}
	} else {
		debugfs_command_help(dev, cmd_buf);
		ret = -EINVAL;
		goto command_write_error;
	}

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_error:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	/* This function always consumes all of the written input, or produces
	 * an error. Check and enforce this. Otherwise, the write operation
	 * won't complete properly.
	 */
	if (WARN_ON(ret != (ssize_t)count && ret >= 0))
		ret = -EIO;

	return ret;
}

static const struct file_operations mce_debugfs_command_fops = {
	.owner = THIS_MODULE,
	.open = mce_debugfs_common_open,
	.write = mce_debugfs_command_write,
};

#define DEBUGFS_CREATE_FILE(fname, mode)                                       \
	do {                                                                   \
		if (!debugfs_create_file(#fname, mode, pf->mce_debugfs_hw, pf, \
					 &mce_debugfs_##fname##_fops)) {       \
			dev_err(mce_pf_to_dev(pf),                             \
				"create debugfs " #fname " failed\n");         \
			goto err_quit;                                         \
		}                                                              \
	} while (0)

void mce_debugfs_eth_link_rename(struct mce_pf *pf, const char *new_name)
{
	if (pf->mce_debugfs_eth_symlink && mce_debugfs_root) {
		debugfs_rename(mce_debugfs_root, pf->mce_debugfs_eth_symlink,
			       mce_debugfs_root, new_name);
	}
}

/**
 * mce_debugfs_pf_init - setup the debugfs directory
 * @pf: the ice that is starting up
 */
void mce_debugfs_pf_init(struct mce_pf *pf)
{
	const char *name = pci_name(pf->pdev);

	if (!mce_debugfs_root) {
		pf->mce_debugfs_hw = NULL;
		return;
	}

	pf->mce_debugfs_hw = debugfs_create_dir(name, mce_debugfs_root);
	if (IS_ERR(pf->mce_debugfs_hw))
		return;

	if (pf->vsi && pf->vsi[0]) {
		struct net_device *netdev = pf->vsi[0]->netdev;

		if (netdev) {
			pf->mce_debugfs_eth_symlink = debugfs_create_symlink(netdev_name(netdev),
									     mce_debugfs_root,
									pci_name(pf->hw.pdev));
		}
	}

	DEBUGFS_CREATE_FILE(logd_lvl, 0644);
	DEBUGFS_CREATE_FILE(vf_recv_xmit_by_self, 0644);
	DEBUGFS_CREATE_FILE(nb_vlan_maps, 0644);
	DEBUGFS_CREATE_FILE(eth_name, 0644);
	DEBUGFS_CREATE_FILE(select_queue, 0644);
	DEBUGFS_CREATE_FILE(txring_intr_mask, 0644);
	DEBUGFS_CREATE_FILE(set_dvlan, 0644);
	DEBUGFS_CREATE_FILE(priv_header, 0644);
	DEBUGFS_CREATE_FILE(mbx_event_debug, 0644);
	DEBUGFS_CREATE_FILE(rxring_info, 0644);
	DEBUGFS_CREATE_FILE(txring_info, 0644);
	DEBUGFS_CREATE_FILE(rx_wrr, 0644);
	DEBUGFS_CREATE_FILE(ring_mbx, 0644);
	DEBUGFS_CREATE_FILE(mbx_debug, 0644);
	DEBUGFS_CREATE_FILE(tx_drop_en, 0644);
	DEBUGFS_CREATE_FILE(temperature, 0644);
	DEBUGFS_CREATE_FILE(pf_sriov_en_st, 0644);
	DEBUGFS_CREATE_FILE(autoneg, 0644);
	DEBUGFS_CREATE_FILE(disable_40_100g_card_25g_and_below, 0644);
	DEBUGFS_CREATE_FILE(si, 0644);
	DEBUGFS_CREATE_FILE(sfp, 0644);
	DEBUGFS_CREATE_FILE(sfp_tx_disable, 0644);
	DEBUGFS_CREATE_FILE(rx_page_stats, 0444);
	DEBUGFS_CREATE_FILE(prbs, 0644);
	DEBUGFS_CREATE_FILE(link_traing, 0644);
	DEBUGFS_CREATE_FILE(pf_reset, 0644);
	DEBUGFS_CREATE_FILE(pci, 0644);
	DEBUGFS_CREATE_FILE(pri2buf, 0600);
	DEBUGFS_CREATE_FILE(buffer_size, 0600);
	DEBUGFS_CREATE_FILE(tx_debug, 0600);
	DEBUGFS_CREATE_FILE(fd_rx_debug, 0600);
	DEBUGFS_CREATE_FILE(fd_query_rule, 0600);
	DEBUGFS_CREATE_FILE(fdir_usage, 0444);
	DEBUGFS_CREATE_FILE(default_vport, 0600);
	DEBUGFS_CREATE_FILE(cdev_name, 0600);
	DEBUGFS_CREATE_FILE(command, 0600);
	DEBUGFS_CREATE_FILE(rx_states, 0600);
	DEBUGFS_CREATE_FILE(tx_states, 0600);
	DEBUGFS_CREATE_FILE(tx_queue_state, 0600);
	DEBUGFS_CREATE_FILE(rx_queue_state, 0600);
	DEBUGFS_CREATE_FILE(reg_rw, 0600);
	DEBUGFS_CREATE_FILE(dump_v, 0600);
	DEBUGFS_CREATE_FILE(dump_link, 0600);
	DEBUGFS_CREATE_FILE(dump_port, 0600);
	DEBUGFS_CREATE_FILE(dump_sfp_info, 0600);
	DEBUGFS_CREATE_FILE(vf_rate_info, 0644);
	DEBUGFS_CREATE_FILE(tc_states, 0600);
	DEBUGFS_CREATE_FILE(hwpfc_states, 0600);
	DEBUGFS_CREATE_FILE(hwets_states, 0600);
	DEBUGFS_CREATE_FILE(rdma_prio, 0644);
	DEBUGFS_CREATE_FILE(axi_mhz, 0600);
	DEBUGFS_CREATE_FILE(q_vector_affinity, 0444);

	dev_info(mce_pf_to_dev(pf), "debugfs ok\n");
	return;
err_quit:
	dev_err(mce_pf_to_dev(pf), "debugfs err quit\n");
	debugfs_remove_recursive(pf->mce_debugfs_hw);
	pf->mce_debugfs_hw = NULL;
}

/**
 * mce_debugfs_pf_exit - clear out the ices debugfs entries
 * @pf: the ice that is stopping
 */
void mce_debugfs_pf_exit(struct mce_pf *pf)
{
	debugfs_remove(pf->mce_debugfs_eth_symlink);
	pf->mce_debugfs_eth_symlink = NULL;

	debugfs_remove_recursive(pf->mce_debugfs_hw);
	pf->mce_debugfs_hw = NULL;
}

/**
 * mce_debugfs_init - create root directory for debugfs entries
 */
void mce_debugfs_init(void)
{
	mce_debugfs_root = debugfs_create_dir(KBUILD_MODNAME, NULL);
	if (IS_ERR(mce_debugfs_root))
		pr_info("init of debugfs failed\n");
}

/**
 * mce_debugfs_exit - remove debugfs entries
 */
void mce_debugfs_exit(void)
{
	debugfs_remove_recursive(mce_debugfs_root);
	mce_debugfs_root = NULL;
}

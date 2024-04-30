// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#ifdef ROCE_PKT_CAP_EN

#include <linux/mutex.h>
#include <linux/kthread.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>
#include <linux/etherdevice.h>
#include <rdma/ib_verbs.h>

#include "hinic3_hw.h"

#include "roce.h"
#include "roce_cmd.h"
#include "roce_pub_cmd.h"
#include "roce_dfx.h"
#include "roce_dfx_cap.h"
#ifdef ROCE_BONDING_EN
#include "roce_bond.h"
#endif

static struct roce3_cap_block_num_attr g_nattr[8] = {
	{ .block_num_idx = 0, .shift = 4,  .num = 16 },
	{ .block_num_idx = 1, .shift = 5,  .num = 32 },
	{ .block_num_idx = 2, .shift = 6,  .num = 64 },
	{ .block_num_idx = 3, .shift = 7,  .num = 128 },
	{ .block_num_idx = 4, .shift = 8,  .num = 256 },
	{ .block_num_idx = 5, .shift = 9,  .num = 512 },
	{ .block_num_idx = 6, .shift = 10, .num = 1024 },
	{ .block_num_idx = 7, .shift = 11, .num = 2048 },
};

struct roce3_pkt_cap_info g_roce3_cap_info = {
	.cap_status = ROCE_CAPTURE_STOP,
	.cap_mode = 1,
	.poll_ci = 0,
	.rdev = NULL,
	.func_id = 0,
	// Configurable, currently using 4, when modifying,
	// the size of cfg bl needs to be modified synchronously
	.block_num_idx = 4,
	.mode = 0,
	.qp_list_cnt = 0,
	.qp_list_head = LIST_HEAD_INIT(g_roce3_cap_info.qp_list_head),
};

static void roce3_stop_thread(struct sdk_thread_info *thread_info)
{
	if (thread_info->thread_obj) {
		(void)kthread_stop(thread_info->thread_obj);
		thread_info->thread_obj = NULL;
	}
}

static int roce3_linux_thread_func(void *thread)
{
	struct sdk_thread_info *info = (struct sdk_thread_info *)thread;

	while (!kthread_should_stop()) {
		info->thread_fn(info->data);

		// Warning: kernel thread should reschedule
		schedule();
	}

	return 0;
}
#ifdef ROCE_BONDING_EN
static struct net_device *roce3_get_roce_bond_ndev(struct roce3_device *rdev)
{
	struct bonding *bond = NULL;
	struct slave *slave = NULL;
	struct net_device *netdev = rdev->ndev;

	if (netif_is_lag_master(netdev)) {
		bond = netdev_priv(netdev);
	} else if (netif_is_bond_slave(netdev)) {
		rcu_read_lock();
		slave = bond_slave_get_rcu(netdev);
		rcu_read_unlock();
		if (slave)
			bond = bond_get_bond_by_slave(slave);
	}

	if ((bond == NULL) || (bond->dev == NULL)) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Bond/bond->dev is NULL\n", __func__);
		return NULL;
	}

	return bond->dev;
}
#endif
static void roce3_netif_skb_info(struct roce3_device *rdev, const char *pkt, u8 len)
{
	struct sk_buff *skb = NULL;
	unsigned char *packet = NULL;
	struct net_device *netdev = rdev->ndev;
#ifdef ROCE_BONDING_EN
	if (roce3_bond_is_active(rdev)) {
		netdev = roce3_get_roce_bond_ndev(rdev);
		if (netdev == NULL) {
			dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to get roce_bond ndev\n",
				__func__);
			return;
		}
	}
#endif
	/* alloc skb and set skb->dev */
	skb = netdev_alloc_skb_ip_align(netdev, CAP_NUM_PER_BLOCK + 1);
	if (unlikely(skb == NULL)) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to alloc skb\n", __func__);
		return;
	}

	skb_reserve(skb, CAP_COUNTER_TWO);

	/* put space for pkt */
	packet = (unsigned char *)skb_put(skb, len);
	if (packet == NULL) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to get packet\n", __func__);
		kfree_skb(skb);
		return;
	}

	/* copy pkt hdr */
	memcpy(packet, pkt, len);

	prefetchw(skb->data);

	/* resolve protocol and type */
	skb->protocol = eth_type_trans(skb, netdev);

	/* force to host */
	skb->pkt_type = 0;

	netif_receive_skb(skb);
}

static int roce3_set_cap_func_disable(struct roce3_device *rdev)
{
	int ret;

	ret = hinic3_set_func_capture_en(rdev->hwdev, rdev->glb_func_id, 0);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE] %s: Failed to set capture disable, ret(%d)\n",
			__func__, ret);
		return ret;
	}

	return 0;
}

static int roce3_create_thread(struct sdk_thread_info *thread_info)
{
	thread_info->thread_obj = kthread_run(roce3_linux_thread_func,
		thread_info, thread_info->name);
	if (!thread_info->thread_obj) {
		pr_err("[ROCE, ERR] %s: Failed to create thread\n", __func__);
		return (-EFAULT);
	}

	return 0;
}

static int roce3_set_cap_func_en(struct roce3_device *rdev)
{
	int ret;

	ret = hinic3_set_func_capture_en(rdev->hwdev, rdev->glb_func_id, 1);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE] %s: Failed to set capture func enable, ret(%d)\n",
			__func__, ret);
		return ret;
	}

	return 0;
}

static int roce3_pkt_cap_poll_check(struct roce3_device *rdev)
{
	if (rdev == NULL) {
		pr_err("[ROCE] %s: Rdev is null\n", __func__);
		return (-EINVAL);
	}

	if (rdev->hwdev == NULL) {
		dev_err(rdev->hwdev_hdl, "[ROCE] %s: Rdev->hwdev is null\n", __func__);
		return (-EINVAL);
	}

	if (g_roce3_cap_info.cap_status == ROCE_CAPTURE_STOP) {
		/* Don't add log here */
		return (-EINVAL);
	}

	return 0;
}

static int roce3_cap_hdr_vld(const roce3_cap_hdr_u *cap_hdr)
{
	return (cap_hdr->value != 0);
}

static void roce3_fill_cap_cfg(struct roce3_dfx_cap_cfg_tbl *cfg_info,
	u32 state, u32 ci_index, u8 mode)
{
	cfg_info->ci_index = ci_index;

	cfg_info->dw1.bs.cap_block_num_shift =
		(u8)g_nattr[g_roce3_cap_info.block_num_idx].shift; // 8
	cfg_info->dw1.bs.cap_mode = (u8)g_roce3_cap_info.cap_mode;
	cfg_info->dw1.bs.qp_mode = mode;

	cfg_info->dw2.bs.state = state;
	cfg_info->dw2.bs.cap_func = g_roce3_cap_info.func_id;

	cfg_info->maxnum = g_nattr[g_roce3_cap_info.block_num_idx].num * CAP_NUM_PER_BLOCK;
}

static void roce3_pkt_cap_poll_hdr(struct roce3_pkt_cap_info *cap_info,
	union roce3_cap_hdr **cap_hdr, union roce3_cap_hdr *hdr_value)
{
	u32 lt_index;
	u32 lt_offset;
	u8 sel;
	u32 block_num_per_entry = g_nattr[g_roce3_cap_info.block_num_idx].num;
	u32 block_num_shift = g_nattr[g_roce3_cap_info.block_num_idx].shift;

	/* resolve index and offset */
	lt_index = (((cap_info->poll_ci) / block_num_per_entry) % CAP_PA_TBL_ENTRY_NUM);
	lt_offset = ((cap_info->poll_ci) % (block_num_per_entry >> 1));
	sel = ((cap_info->poll_ci >> (block_num_shift - 1)) & 0x1);

	*cap_hdr = (roce3_cap_hdr_u *)(cap_info->que_addr[sel][0][lt_index] +
		(lt_offset * CAP_PKT_ITEM_SIZE));

	hdr_value->value = (*cap_hdr)->value;
	/* First, execute big endian and small endian switch operation for ctrl information */
	hdr_value->value = ntohl(hdr_value->value);
}

static void roce3_pkt_cap_poll(void *data)
{
	int ret;
	u32 count = 0;
	struct roce3_dfx_cap_cfg_tbl cfg_info = { 0 };
	union roce3_cap_hdr hdr_value = { { 0 } };
	struct roce3_pkt_cap_info *cap_info = (struct roce3_pkt_cap_info *)data;
	struct roce3_device *rdev = cap_info->rdev;
	union roce3_cap_hdr *cap_hdr = NULL;

	if (roce3_pkt_cap_poll_check(rdev) != 0)
		return;

	roce3_pkt_cap_poll_hdr(cap_info, &cap_hdr, &hdr_value);

	if (roce3_cap_hdr_vld(&hdr_value) == 0)
		return;

	do {
		if (g_roce3_cap_info.cap_status == ROCE_CAPTURE_STOP) {
			dev_err(rdev->hwdev_hdl, "[ROCE] %s: Cap is stopped\n", __func__);
			return;
		}

		roce3_netif_skb_info(rdev, ((u8 *)cap_hdr + CAP_HDR_OFFSET +
			hdr_value.cap_ctrl_info.pad), CAP_SKB_LEN);

		/* reset to 0 */
		cap_hdr->value = 0;
		cap_info->poll_ci++;

		if (g_roce3_cap_info.cap_mode != 0) {
			count++;
			if (count >= (FILL_CAP_CFG_PKT_NUM)) {
				roce3_fill_cap_cfg(&cfg_info, 0, cap_info->poll_ci, 0);

				(void)roce3_set_cap_cfg(rdev->hwdev, CAP_PA_TBL_ENTRY_NUM,
					(u32 *)&cfg_info);

				count = 0;
			}
		}

		roce3_pkt_cap_poll_hdr(cap_info, &cap_hdr, &hdr_value);

		if (unlikely(kthread_should_stop()))
			break;

		schedule();
	} while (roce3_cap_hdr_vld(&hdr_value) != 0);

	roce3_fill_cap_cfg(&cfg_info, 0, cap_info->poll_ci, 0);

	ret = roce3_set_cap_cfg(rdev->hwdev, CAP_PA_TBL_ENTRY_NUM, (u32 *)&cfg_info);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE] %s: Failed to set cap cfg, ret(%d)\n",
			__func__, ret);
		return;
	}
}

static int roce3_dfx_dma_alloc_addr(struct roce3_device *rdev, int cap_index, int que_index,
	struct roce3_dfx_cap_tbl *pa_info)
{
	u64 v_addr;
	u64 p_addr = 0;

	v_addr = dma_alloc_coherent(&rdev->pdev->dev,
		(unsigned long)(CAP_PKT_ITEM_SIZE *
		((g_nattr[g_roce3_cap_info.block_num_idx].num) >> 1)), &p_addr, GFP_KERNEL);
	if (v_addr == 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE] %s: Failed to alloc v_addr for que_index %d\n",
			__func__, que_index);
		return -ENOMEM;
	}

	g_roce3_cap_info.que_addr[que_index][0][cap_index] = v_addr;
	g_roce3_cap_info.que_addr[que_index][1][cap_index] = p_addr;

	pa_info->pa[que_index].wr_init_pc_h32 =
		(u32)((p_addr >> CAP_ADDR_COMBIN_SHIFT) & 0xffffffff);
	pa_info->pa[que_index].wr_init_pc_l32 = (u32)(p_addr & 0xffffffff);

	dev_info(rdev->hwdev_hdl, "[ROCE] %s: v_addr que_index(%d), cap_index(%d), PA:0x%x %x\n",
		__func__, que_index, cap_index,
		pa_info->pa[que_index].wr_init_pc_h32, pa_info->pa[que_index].wr_init_pc_l32);

	return 0;
}

static void roce3_dfx_dma_free_addr(struct roce3_device *rdev, int cap_index, int que_index)
{
	u64 v_addr;
	u64 p_addr;

	v_addr = g_roce3_cap_info.que_addr[que_index][0][cap_index];
	p_addr = g_roce3_cap_info.que_addr[que_index][1][cap_index];
	dma_free_coherent(&rdev->pdev->dev,
		(unsigned long)(CAP_PKT_ITEM_SIZE *
		((g_nattr[g_roce3_cap_info.block_num_idx].num) >> 1)), (void *)v_addr,
		(dma_addr_t)p_addr);
}

static int roce3_dfx_alloc_mem_for_one_cap(struct roce3_device *rdev, int cap_index)
{
	struct roce3_dfx_cap_tbl pa_info;
	int ret;

	memset(&pa_info, 0x0, sizeof(pa_info));

	ret = roce3_dfx_dma_alloc_addr(rdev, cap_index, 0, &pa_info);
	if (ret != 0)
		return ret;

	ret = roce3_dfx_dma_alloc_addr(rdev, cap_index, 1, &pa_info);
	if (ret != 0)
		goto err_dma_mem_alloc_free_1;

	ret = roce3_set_cap_cfg(rdev->hwdev, (u16)cap_index, (u32 *)&pa_info);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE] %s: Failed to set cap cfg, ret(%d)\n",
			__func__, ret);
		goto err_dma_mem_alloc_free;
	}

	return 0;

err_dma_mem_alloc_free:
	roce3_dfx_dma_free_addr(rdev, cap_index, 1);

err_dma_mem_alloc_free_1:
	roce3_dfx_dma_free_addr(rdev, cap_index, 0);
	return ret;
}

static void roce3_dfx_free_mem_for_one_cap(struct roce3_device *rdev, int cap_index)
{
	roce3_dfx_dma_free_addr(rdev, cap_index, 1);
	roce3_dfx_dma_free_addr(rdev, cap_index, 0);
}

static int roce3_dfx_alloc_cap(struct roce3_device *rdev)
{
	u32 counter, times;
	int ret;
	int i;

	/* alloc lt memory resource */
	for (i = 0; i < CAP_PA_TBL_ENTRY_NUM; i++) {
		ret = roce3_dfx_alloc_mem_for_one_cap(rdev, i);
		if (ret != 0)
			goto err_dma_mem_alloc_free;
	}

	for (times = 0; times < CLEAR_CAP_TRYING_TIMES; times++) {
		if (times == CLEAR_CAP_TRYING_TIMES - 1) {
			dev_err(rdev->hwdev_hdl, "[ROCE] %s: Failed to clear pi\n", __func__);
			goto err_dma_mem_alloc_free;
		}

		/* clear pi */
		ret = roce3_clear_cap_counter(rdev->hwdev, ROCE_CAP_COUNTER_INDEX, &counter);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl, "[ROCE] %s: Failed to read counter(lt index %x), ret(%d)\n",
				__func__, ROCE_CAP_COUNTER_INDEX, ret);
			goto err_dma_mem_alloc_free;
		}

		if (counter == 0)
			break;

		msleep(CLEAR_SLEEP_TIME);
	}

	return 0;

err_dma_mem_alloc_free:
	for (i--; i >= 0; i--)
		roce3_dfx_free_mem_for_one_cap(rdev, i);

	return ret;
}

static void roce3_dfx_free_cap(struct roce3_device *rdev)
{
	int i;

	for (i = 0; i < CAP_PA_TBL_ENTRY_NUM; i++)
		roce3_dfx_free_mem_for_one_cap(rdev, i);
}

static void roce3_dfx_init_g_cap_info(struct roce3_device *rdev,
	const struct roce3_dfx_capture_inbuf *inbuf)
{
	u32 mode = inbuf->mode;

	g_roce3_cap_info.func_id = rdev->glb_func_id;
	g_roce3_cap_info.task.data = &g_roce3_cap_info;
	g_roce3_cap_info.task.thread_fn = roce3_pkt_cap_poll;
	g_roce3_cap_info.task.name = "capture_thread";
	g_roce3_cap_info.rdev = rdev;
	g_roce3_cap_info.poll_ci = 0;
	g_roce3_cap_info.block_num_per_entry = g_nattr[g_roce3_cap_info.block_num_idx].num;
	g_roce3_cap_info.maxnum =
		(g_nattr[g_roce3_cap_info.block_num_idx].num) * CAP_PA_TBL_ENTRY_NUM;
	g_roce3_cap_info.mode = mode;
	g_roce3_cap_info.qp_list_cnt = 0;
}

static int roce3_dfx_start_cap_pkt(struct roce3_device *rdev,
	const struct roce3_dfx_capture_inbuf *inbuf, union roce3_dfx_capture_outbuf *outbuf)
{
	struct roce3_dfx_cap_cfg_tbl cfg_info;
	int ret;

	mutex_lock(&cap_mutex);
	if (g_roce3_cap_info.cap_status == ROCE_CAPTURE_START) {
		dev_err(rdev->hwdev_hdl, "[ROCE] %s: Capture is running\n", __func__);
		mutex_unlock(&cap_mutex);
		return (-EBUSY);
	}

	ret = roce3_dfx_alloc_cap(rdev);
	if (ret != 0) {
		mutex_unlock(&cap_mutex);
		return ret;
	}

	roce3_dfx_init_g_cap_info(rdev, inbuf);

	memset(&cfg_info, 0, sizeof(cfg_info));
	roce3_fill_cap_cfg(&cfg_info, 0, 0, 0);

	ret = roce3_set_cap_cfg(rdev->hwdev, CAP_PA_TBL_ENTRY_NUM, (u32 *)&cfg_info);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE] %s: Failed to set cap cfg, ret(%d)\n",
			__func__, ret);
		goto err_alloc_cap;
	}

	dev_err(rdev->hwdev_hdl, "[ROCE] %s: roce create thread\n", __func__);
	ret = roce3_create_thread(&(g_roce3_cap_info.task));
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE] %s: Failed to create thread, ret(%d)\n",
			__func__, ret);
		goto err_alloc_cap;
	}

	ret = roce3_set_cap_func_en(rdev);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE] %s: Failed to set cap enable, ret(%d)\n",
			__func__, ret);
		goto err_thread_release;
	}

	g_roce3_cap_info.cap_status = ROCE_CAPTURE_START;
	INIT_LIST_HEAD(&g_roce3_cap_info.qp_list_head);
	mutex_unlock(&cap_mutex);

	dev_info(rdev->hwdev_hdl, "[ROCE] %s: Start to capture pkt, func(%u)\n",
		__func__, g_roce3_cap_info.func_id);
	return 0;

err_thread_release:
	roce3_stop_thread(&(g_roce3_cap_info.task));
	msleep(CAP_STOP_SLEEP_TIME);

err_alloc_cap:
	roce3_dfx_free_cap(rdev);

	g_roce3_cap_info.cap_status = ROCE_CAPTURE_STOP;
	mutex_unlock(&cap_mutex);

	return ret;
}

static int roce3_clear_cap_counter_encap(struct roce3_device *rdev, u16 lt_index)
{
	int ret;
	u32 counter = 0;
	u32 times;

	for (times = 0; times < CLEAR_CAP_TRYING_TIMES; times++) {
		if (times == CLEAR_CAP_TRYING_TIMES - 1) {
			dev_err(rdev->hwdev_hdl, "[ROCE] %s: Failed to clear pi\n", __func__);
			return -EFAULT;
		}

		ret = roce3_clear_cap_counter(rdev->hwdev, lt_index, &counter);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl, "[ROCE] %s: Failed to clear cap counter(lt index 1), ret(%d)\n",
				__func__, ret);
			return -EFAULT;
		}

		if (counter == 0)
			break;

		msleep(CLEAR_SLEEP_TIME);
	}

	return 0;
}

int roce3_dfx_stop_cap_pkt(struct roce3_device *rdev, const struct roce3_dfx_capture_inbuf *inbuf,
	union roce3_dfx_capture_outbuf *outbuf)
{
	int ret = 0;

	dev_info(rdev->hwdev_hdl, "[ROCE] %s: start to stop cap,\n", __func__);

	mutex_lock(&cap_mutex);
	if (g_roce3_cap_info.cap_status != ROCE_CAPTURE_START) { // 1:RUNNING
		mutex_unlock(&cap_mutex);
		return 0;
	}

	if (g_roce3_cap_info.func_id != rdev->glb_func_id) {
		mutex_unlock(&cap_mutex);
		return 0;
	}

	roce3_stop_thread(&(g_roce3_cap_info.task));

	/* stop cap */
	ret = roce3_set_cap_func_disable(rdev);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE] %s: Failed to set cap enable, ret(%d)\n",
			__func__, ret);
		ret = -EFAULT;
		goto err;
	}

	msleep(CAP_STOP_SLEEP_TIME);

	/* release lt mem resource */
	roce3_dfx_free_cap(rdev);

	/* lt index_1 */
	ret = roce3_clear_cap_counter_encap(rdev, ROCE_CAP_COUNTER_INDEX);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE] %s: Failed to clear pi(lt index %x), ret(%d)\n",
			__func__, ROCE_CAP_COUNTER_INDEX, ret);
		goto err;
	}

	g_roce3_cap_info.cap_status = ROCE_CAPTURE_STOP;
	g_roce3_cap_info.poll_ci = 0;
	g_roce3_cap_info.func_id = 0;
	g_roce3_cap_info.rdev = NULL;
	dev_info(rdev->hwdev_hdl, "[ROCE] %s: Stop capture pkt, func(%d)\n",
		__func__, rdev->glb_func_id);

err:
	mutex_unlock(&cap_mutex);
	return ret;
}

static int roce3_dfx_query_cap_pkt(struct roce3_device *rdev,
	const struct roce3_dfx_capture_inbuf *inbuf, union roce3_dfx_capture_outbuf *outbuf)
{
	int ret;
	u32 pi = 0;
	u32 total = 0;
	struct roce3_dfx_cap_cfg_tbl cfg_info;
	struct roce3_dfx_capture_info *capture_info = &outbuf->capture_info;

	memset(&cfg_info, 0, sizeof(cfg_info));
	ret = roce3_get_cap_cfg(rdev->hwdev, CAP_NUM_PER_BLOCK, (u32 *)&cfg_info);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to read table, ret(%d)\n",
			__func__, ret);
		return -EFAULT;
	}

	ret = roce3_read_cap_counter(rdev->hwdev, CAP_COUNTER_TWO, &total);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to read counter(lt index 2), ret(%d)\n",
			__func__, ret);
		return -EFAULT;
	}

	ret = roce3_read_cap_counter(rdev->hwdev, ROCE_CAP_COUNTER_INDEX, &pi);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to read counter(lt index %x), ret(%d)\n",
			__func__, ROCE_CAP_COUNTER_INDEX, ret);
		return -EFAULT;
	}

	capture_info->cap_status = g_roce3_cap_info.cap_status;
	capture_info->cap_mode = cfg_info.dw1.bs.cap_mode;
	capture_info->qp_mode = cfg_info.dw1.bs.qp_mode;
	capture_info->cap_block_num_shift = cfg_info.dw1.bs.cap_block_num_shift;
	capture_info->cap_func = cfg_info.dw2.bs.cap_func;
	capture_info->cap_state = cfg_info.dw2.bs.state;
	capture_info->cap_max_num = cfg_info.maxnum;
	capture_info->cap_ci = g_roce3_cap_info.poll_ci;
	capture_info->cap_pi = pi;
	capture_info->cap_total = total;

	return 0;
}

typedef int (*roce3_adm_dfx_capture_func_t)(struct roce3_device *rdev,
	const struct roce3_dfx_capture_inbuf *inbuf, union roce3_dfx_capture_outbuf *outbuf);

/*lint -e26*/
static roce3_adm_dfx_capture_func_t g_roce3_adm_dfx_capture_funcs[COMMON_CMD_VM_COMPAT_TEST] = {
	[ROCE_CMD_START_CAP_PACKET] = roce3_dfx_start_cap_pkt,
	[ROCE_CMD_STOP_CAP_PACKET] = roce3_dfx_stop_cap_pkt,
	[ROCE_CMD_QUERY_CAP_INFO] = roce3_dfx_query_cap_pkt,
	[ROCE_CMD_ENABLE_QP_CAP_PACKET] = NULL,
	[ROCE_CMD_DISABLE_QP_CAP_PACKET] = NULL,
	[ROCE_CMD_QUERY_QP_CAP_INFO] = NULL,
};
/*lint +e26*/

int roce3_adm_dfx_capture(struct roce3_device *rdev, const void *buf_in, u32 in_size,
	void *buf_out, u32 *out_size)
{
	int ret;
	const struct roce3_dfx_capture_inbuf *inbuf = (struct roce3_dfx_capture_inbuf *)buf_in;
	union roce3_dfx_capture_outbuf *outbuf = (union roce3_dfx_capture_outbuf *)buf_out;
	roce3_adm_dfx_capture_func_t roce3_adm_dfx_capture_func;

	memset(buf_out, 0, sizeof(union roce3_dfx_capture_outbuf));
	*out_size = sizeof(union roce3_dfx_capture_outbuf);

	if (inbuf->cmd_type >= COMMON_CMD_VM_COMPAT_TEST) {
		dev_err(rdev->hwdev_hdl, "Not support this type(%d)\n", inbuf->cmd_type);
		return -EINVAL;
	}

	roce3_adm_dfx_capture_func = g_roce3_adm_dfx_capture_funcs[inbuf->cmd_type];
	if (roce3_adm_dfx_capture_func == NULL) {
		dev_err(rdev->hwdev_hdl, "Not support this type(%d)\n", inbuf->cmd_type);
		return -EINVAL;
	}

	return roce3_adm_dfx_capture_func(rdev, inbuf, outbuf);
}

#endif /* ROCE_PKT_CAP_EN */

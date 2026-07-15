/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_ethtool_lb_test.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt

#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/vmalloc.h>

#include "drv_nic_api.h"
#include "ossl_knl.h"
#include "hinic5_hw.h"
#include "hinic5_crm.h"
#include "hinic5_nic_dev.h"
#include "hinic5_tx.h"
#include "hinic5_rx.h"
#include "hinic5_ethtool.h"
#include "hinic5_ethtool_lb_test.h"

void hinic5_run_lp_init_data(struct ethhdr *eth_hdr, struct sk_buff *skb_tmp,
			     const struct hinic5_nic_dev *nic_dev)
{
	u32 i;
	u8 *test_data = NULL;

	eth_hdr = __skb_put(skb_tmp, ETH_HLEN);
	eth_hdr->h_proto = htons(ETH_P_ARP);
	ether_addr_copy(eth_hdr->h_dest, nic_dev->netdev->dev_addr);
	eth_zero_addr(eth_hdr->h_source);
	skb_reset_mac_header(skb_tmp);

	test_data = __skb_put(skb_tmp, LP_PKT_LEN - ETH_HLEN);
	for (i = 0; i < LP_PKT_LEN - ETH_HLEN; i++)
		test_data[i] = i & 0xFF;

	skb_tmp->queue_mapping = 0;
	skb_tmp->dev = nic_dev->netdev;
	skb_tmp->protocol = htons(ETH_P_ARP);
}

int hinic5_run_lp_test(struct hinic5_nic_dev *nic_dev, u32 test_time)
{
	u8 *lb_test_rx_buf = nic_dev->lb_test_rx_buf;
	struct net_device *netdev = nic_dev->netdev;
	u32 cnt = test_time * TEST_TIME_MULTIPLE;
	struct sk_buff *skb_tmp = NULL;
	struct ethhdr *eth_hdr = NULL;
	struct sk_buff *skb = NULL;
	u32 i;
	u8 j;

	skb_tmp = alloc_skb(LP_PKT_LEN, GFP_ATOMIC);
	if (!skb_tmp)
		return -ENOMEM;

	hinic5_run_lp_init_data(eth_hdr, skb_tmp, nic_dev);

	for (i = 0; i < cnt; i++) {
		nic_dev->lb_test_rx_idx = 0;
		memset(lb_test_rx_buf, 0, LP_PKT_CNT * LP_PKT_LEN);

		for (j = 0; j < LP_PKT_CNT; j++) {
			skb = pskb_copy(skb_tmp, GFP_ATOMIC);
			if (!skb) {
				dev_kfree_skb_any(skb_tmp);
				nicif_err(nic_dev, drv, netdev,
					  "Copy skb failed for loopback test\n");
				return -ENOMEM;
			}

			/* mark index for every pkt */
			skb->data[LP_PKT_LEN - 1] = j;

			if (hinic5_lb_xmit_frame(skb, netdev) != NETDEV_TX_OK) {
				dev_kfree_skb_any(skb);
				dev_kfree_skb_any(skb_tmp);
				nicif_err(nic_dev, drv, netdev,
					  "Xmit pkt failed for loopback test\n");
				return -EBUSY;
			}
		}

		/* wait till all pkts received to RX buffer */
		msleep(HINIC5_WAIT_PKTS_TO_RX_BUFFER);

		for (j = 0; j < LP_PKT_CNT; j++) {
			if ((memcmp((lb_test_rx_buf + (u16)(j * LP_PKT_LEN)),
				    skb_tmp->data, (LP_PKT_LEN - 1)) != 0) ||
			   (*(lb_test_rx_buf + (u16)((j * LP_PKT_LEN) + (LP_PKT_LEN - 1))) != j)) {
				dev_kfree_skb_any(skb_tmp);
				nicif_err(nic_dev, drv, netdev,
					  "Compare pkt failed in loopback test(index=0x%02x, data[%d]=0x%02x)\n",
					  (j + (i * LP_PKT_CNT)), (LP_PKT_LEN - 1),
					  *((lb_test_rx_buf + ((u64)j * LP_PKT_LEN)) +
					    (LP_PKT_LEN - 1)));
				return -EIO;
			}
		}
	}

	dev_kfree_skb_any(skb_tmp);
	nicif_info(nic_dev, drv, netdev, "Loopback test succeed.\n");
	return 0;
}

int do_lp_test(struct hinic5_nic_dev *nic_dev, u32 *flags, u32 test_time,
	       enum diag_test_index *test_index)
{
	struct net_device *netdev = nic_dev->netdev;
	u8 *lb_test_rx_buf = NULL;
	u16 cur_veb_offload = 0;
	int err = 0;
	u16 glb_func_id;

	if (HINIC5_SUPPORT_FEATURE(nic_dev->hwdev, VEB_OFFLOAD)) {
		err = hinic5_get_veb_offload(nic_dev->hwdev, &cur_veb_offload);
		if (err != 0)
			goto err_out;

		if (cur_veb_offload != 0) {
			err = hinic5_set_veb_offload(nic_dev->hwdev, 0);
			if (err != 0)
				goto err_out;
		}
	}

	if ((*flags & ETH_TEST_FL_EXTERNAL_LB) == 0) {
		*test_index = INTERNAL_LP_TEST;
		if (hinic5_set_loopback_mode(nic_dev->hwdev,
					     HINIC5_INTERNAL_LP_MODE, true)) {
			nicif_err(nic_dev, drv, netdev,
				  "Failed to set port loopback mode before loopback test\n");
			err = -EFAULT;
			goto restore_veb_offload;
		}

		glb_func_id = hinic5_global_func_id(nic_dev->hwdev);

		err = hinic5_set_vport_enable(nic_dev->hwdev, glb_func_id, false,
					      HINIC5_CHANNEL_NIC);
		if (err != 0) {
			nicif_err(nic_dev, drv, netdev, "Failed to disable vport\n");
			goto restore_veb_offload;
		}

		msleep(nic_dev->timeout.wait_flush_qp_res_timeout);

		err = hinic5_set_vport_enable(nic_dev->hwdev, glb_func_id, true,
					      HINIC5_CHANNEL_NIC);
		if (err != 0) {
			nicif_err(nic_dev, drv, netdev, "Failed to enable vport\n");
			goto restore_veb_offload;
		}
	} else {
		*test_index = EXTERNAL_LP_TEST;
	}

	lb_test_rx_buf = vmalloc(LP_PKT_CNT * LP_PKT_LEN);
	if (!lb_test_rx_buf) {
		err = -ENOMEM;
	} else {
		nic_dev->lb_test_rx_buf = lb_test_rx_buf;
		nic_dev->lb_pkt_len = LP_PKT_LEN;
		set_bit(HINIC5_LP_TEST, &nic_dev->flags);

		if (hinic5_run_lp_test(nic_dev, test_time) != 0)
			err = -EFAULT;

		clear_bit(HINIC5_LP_TEST, &nic_dev->flags);
		msleep(HINIC5_WAIT_CLEAR_LP_TEST);
		vfree(lb_test_rx_buf);
		nic_dev->lb_test_rx_buf = NULL;
	}

	if ((*flags & ETH_TEST_FL_EXTERNAL_LB) == 0) {
		if (hinic5_set_loopback_mode(nic_dev->hwdev,
					     HINIC5_INTERNAL_LP_MODE, false)) {
			nicif_err(nic_dev, drv, netdev,
				  "Failed to cancel port loopback mode after loopback test\n");
			err = -EFAULT;
		}
	} else {
		*flags |= ETH_TEST_FL_EXTERNAL_LB_DONE;
	}

restore_veb_offload:
	if (cur_veb_offload != 0)
		err = hinic5_set_veb_offload(nic_dev->hwdev, cur_veb_offload);
err_out:
	return err;
}

void hinic5_lp_test(struct net_device *netdev, struct ethtool_test *eth_test,
		    u64 *data, u32 test_time)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	enum diag_test_index test_index = 0;
	u8 link_status = 0;
	int err;
	u32 test_time_real = test_time;

	/* don't support loopback test when netdev is closed. */
	if (test_bit(HINIC5_INTF_UP, &nic_dev->flags) == 0) {
		nicif_err(nic_dev, drv, netdev,
			  "Do not support loopback test when netdev is closed\n");
		eth_test->flags |= ETH_TEST_FL_FAILED;
		data[PORT_DOWN_ERR_IDX] = 1;
		return;
	}
	if (test_time_real == 0)
		test_time_real = LP_DEFAULT_TIME;

	netif_carrier_off(netdev);
	netif_tx_disable(netdev);

	err = do_lp_test(nic_dev, &eth_test->flags, test_time_real, &test_index);
	if (err != 0) {
		eth_test->flags |= ETH_TEST_FL_FAILED;
		data[test_index] = 1;
	}

	netif_tx_wake_all_queues(netdev);

	err = hinic5_get_link_state(nic_dev->hwdev, &link_status);
	if (err == 0 && link_status != 0)
		netif_carrier_on(netdev);
}

void hinic5_diag_test(struct net_device *netdev,
		      struct ethtool_test *eth_test, u64 *data)
{
	memset(data, 0, DIAG_TEST_MAX * sizeof(u64));

	hinic5_lp_test(netdev, eth_test, data, 0);
}

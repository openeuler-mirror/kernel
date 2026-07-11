// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/dinghai/dh_cmd.h>
#include "en_aux_ioctl.h"
#include "en_aux_cmd.h"
#include "../zxdh_tools/zxdh_tools_ioctl.h"
#include "queue.h"
#include "priv_queue.h"
#include "../en_np/table/include/dpp_tbl_api.h"
#include "../en_pf/msg_func.h"
#include "../en_pf/en_pf_eq.h"
#ifdef CONFIG_DINGHAI_TSN
#include "../en_tsn/zxdh_tsn_ioctl.h"
#endif

#ifdef PTP_DRIVER_INTERFACE_EN
extern s32 tod_device_set_bar_virtual_addr(u64 virtaddr, u16 pcieid);
#endif
s32 print_data(u8 *data, u32 len)
{
	s32 i = 0;
	u32 loopcnt = 0;
	u32 last_line_len = 0;
	u32 line_len = PKT_PRINT_LINE_LEN;
	u8 last_line_data[PKT_PRINT_LINE_LEN] = { 0 };

	if (len == 0)
		return 0;
	loopcnt = len / line_len;
	last_line_len = len % line_len;

	LOG_DEBUG("***************packet data[len: %d]***************\n", len);
	for (i = 0; i < loopcnt; i++) {
		LOG_INFO(
			"%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n",
			*(data + (line_len * i) + 0), *(data + (line_len * i) + 1),
			*(data + (line_len * i) + 2), *(data + (line_len * i) + 3),
			*(data + (line_len * i) + 4), *(data + (line_len * i) + 5),
			*(data + (line_len * i) + 6), *(data + (line_len * i) + 7),
			*(data + (line_len * i) + 8), *(data + (line_len * i) + 9),
			*(data + (line_len * i) + 10), *(data + (line_len * i) + 11),
			*(data + (line_len * i) + 12), *(data + (line_len * i) + 13),
			*(data + (line_len * i) + 14), *(data + (line_len * i) + 15));
	}
	if (last_line_len != 0) {
		memcpy(last_line_data, (data + (line_len * i)), last_line_len);
		LOG_INFO(
			"%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n",
			last_line_data[0], last_line_data[1], last_line_data[2], last_line_data[3],
			last_line_data[4], last_line_data[5], last_line_data[6], last_line_data[7],
			last_line_data[8], last_line_data[9], last_line_data[10],
			last_line_data[11], last_line_data[12], last_line_data[13],
			last_line_data[14], last_line_data[15]);
	}
	LOG_INFO("****************end packet data**************\n");

	return 0;
}

s32 zxdh_read_reg_cmd(struct net_device *netdev, struct ifreq *ifr)
{
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	struct zxdh_en_reg *reg = NULL;
	u32 size = sizeof(struct zxdh_en_reg);
	u64 base_addr = 0;
	u64 bar_size = 0;
	u32 num = 0;
	s32 err = 0;

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	en_priv = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_priv, NULL, -EADDRNOTAVAIL, "netdev priv is null!\n");
	en_dev = &en_priv->edev;

	reg = kzalloc(size, GFP_KERNEL);
	CHECK_EQUAL_ERR(reg, NULL, -EADDRNOTAVAIL, "reg is null!\n");

	if (copy_from_user(reg, ifr->ifr_ifru.ifru_data, size)) {
		LOG_ERR("copy_from_user failed\n");
		err = -EFAULT;
		goto err_ret;
	}

	if ((reg->num == 0) || (reg->num > MAX_ACCESS_NUM)) {
		LOG_ERR("transmit failed, reg->num=%u\n", reg->num);
		err = -EINVAL;
		goto err_ret;
	}

	base_addr = en_dev->ops->get_bar_virt_addr(en_dev->parent, 0);
	bar_size = en_dev->ops->get_bar_size(en_dev->parent, 0);

	for (num = 0; num < reg->num; num++) {
		if (((u64)(reg->offset & 0xfffffffc) + num * 4) > bar_size)
			break;
		reg->data[num] =
			readl((const void *)(base_addr + (reg->offset & 0xfffffffc) + num * 4));
	}

	if (copy_to_user(ifr->ifr_ifru.ifru_data, reg, size)) {
		LOG_ERR("copy_to_user failed\n");
		err = -EFAULT;
	}

err_ret:
	kfree(reg);
	return err;
}

s32 zxdh_write_reg_cmd(struct net_device *netdev, struct ifreq *ifr)
{
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	struct zxdh_en_reg *reg = NULL;
	u32 size = sizeof(struct zxdh_en_reg);
	u64 base_addr = 0;
	u64 bar_size = 0;
	u64 access_end = 0;
	u32 num = 0;
	s32 err = 0;

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	en_priv = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_priv, NULL, -EADDRNOTAVAIL, "netdev priv is null!\n");
	en_dev = &en_priv->edev;

	reg = kzalloc(size, GFP_KERNEL);
	CHECK_EQUAL_ERR(reg, NULL, -EADDRNOTAVAIL, "reg is null!\n");

	if (copy_from_user(reg, ifr->ifr_ifru.ifru_data, size)) {
		LOG_ERR("copy_from_user failed\n");
		err = -EFAULT;
		goto err_ret;
	}

	if ((reg->num == 0) || (reg->num > MAX_ACCESS_NUM)) {
		LOG_ERR("transmit failed, reg->num=%u\n", reg->num);
		err = -EINVAL;
		goto err_ret;
	}

	base_addr = en_dev->ops->get_bar_virt_addr(en_dev->parent, 0);
	bar_size = en_dev->ops->get_bar_size(en_dev->parent, 0);
	access_end = (u64)(reg->offset & 0xfffffffc) + (u64)reg->num * 4;
	if (access_end > bar_size) {
		LOG_ERR("reg access out of bar0 range, offset=0x%x num=%u bar_size=0x%llx\n",
			reg->offset, reg->num, bar_size);
		err = -EINVAL;
		goto err_ret;
	}

	for (num = 0; num < reg->num; num++)
		writel(reg->data[num], (void *)(base_addr + (reg->offset & 0xfffffffc) + num * 4));

err_ret:
	kfree(reg);
	return err;
}

s32 print_vring_info(struct virtqueue *vq, struct zxdh_en_reg *reg)
{
	struct vring_virtqueue *vvq = to_vvq(vq);

	if ((reg->num + reg->data[0]) > vvq->packed.vring.num) {
		LOG_ERR("desc_index sum %u and desc_num %u over depth %u, should be [0-%u]\n",
			reg->num, reg->data[0], vvq->packed.vring.num, vvq->packed.vring.num - 1);
		return -EINVAL;
	}

	zxdh_print_vring_info(vq, reg->num, reg->num + reg->data[0]);

	return 0;
}

s32 zxdh_get_vring_info(struct net_device *netdev, struct ifreq *ifr)
{
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	struct zxdh_en_reg *reg = NULL;
	u32 size = sizeof(struct zxdh_en_reg);
	struct virtqueue *vq = NULL;
	s32 ret = 0;

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	en_priv = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_priv, NULL, -EADDRNOTAVAIL, "netdev priv is null!\n");
	en_dev = &en_priv->edev;

	reg = kzalloc(size, GFP_KERNEL);
	CHECK_EQUAL_ERR(reg, NULL, -EADDRNOTAVAIL, "reg is null!\n");

	if (copy_from_user(reg, ifr->ifr_ifru.ifru_data, size)) {
		LOG_ERR("copy_from_user failed\n");
		ret = -EFAULT;
		goto err_ret;
	}

	if (reg->offset >= en_dev->max_queue_pairs) {
		LOG_ERR("the queue index %u over the curr_queue_pairs %u, should be [0-%u]\n",
			reg->offset, en_dev->curr_queue_pairs, en_dev->curr_queue_pairs - 1);
		ret = -EINVAL;
		goto err_ret;
	}

	vq = en_dev->sq[reg->offset].vq;
	LOG_INFO("******************************tx vring info****************************\n");
	ret = print_vring_info(vq, reg);
	if (ret != 0) {
		LOG_ERR("print tx vring info failed!\n");
		ret = -EINVAL;
		goto err_ret;
	}

	vq = en_dev->rq[reg->offset].vq;
	LOG_INFO("******************************rx vring info****************************\n");
	ret = print_vring_info(vq, reg);
	if (ret != 0) {
		LOG_ERR("print rx vring info failed!\n");
		ret = -EINVAL;
	}

err_ret:
	kfree(reg);
	return ret;
}

s32 zxdh_en_set_clock_no(struct net_device *netdev, struct ifreq *ifr, struct zxdh_en_reg *reg)
{
	u32 reg_size = sizeof(struct zxdh_en_reg);
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	en_priv = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_priv, NULL, -EADDRNOTAVAIL, "netdev priv is null!\n");
	en_dev = &en_priv->edev;

	if (reg->num != 1) {
		LOG_ERR("Transmit failed[len = %d]!\n", reg->num);
		goto err_ret;
	}

	en_dev->clock_no = reg->data[0];
	LOG_INFO("en_dev %s clock_no = %d\n", en_dev->netdev->name, en_dev->clock_no);

	reg->num = 0;
	if (unlikely(copy_to_user(ifr->ifr_ifru.ifru_data, reg, reg_size))) {
		LOG_ERR("copy_to_user failed!\n");
		goto err_ret;
	}

	return 0;

err_ret:
	return -1;
}

void copy_u32_to_u8(u8 *data_pkt, u32 *data, u32 pktlen)
{
	u32 i = 0;

	for (i = 0; i < pktlen; i++)
		*data_pkt++ = data[i];
}

s32 zxdh_tx_file_pkts(struct zxdh_en_priv *en_priv, struct zxdh_en_reg *reg)
{
	s32 total_sg = 0;
	u8 *data_pkt = NULL;
	struct scatterlist *sg = NULL;
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct send_queue *sq = en_dev->sq;
	struct page *page = NULL;
	struct data_packet pkt = { 0 };
	u16 i = 0;
	u32 len = 0;
	void *ptr = NULL;
	u32 last_buff_len = 0;
	u32 pktLen = reg->num;
	u32 buffLen = 4096;

	while ((ptr = zxdh_virtqueue_get_buf(sq->vq, &len)) != NULL) {
		LOG_ERR("zxdh_virtqueue_get_buf() != NULL, ptr=0x%llx, len=0x%x\n", (u64)ptr,
			len);
	};

	sg = sq->sg;
	pkt.buf_size = 16 * PAGE_SIZE;
	page = alloc_pages(GFP_KERNEL, 4);
	if (unlikely(!page)) {
		LOG_ERR("page is null\n");
		goto err;
	}

	pkt.buf = page_address(page);
	if (unlikely(!pkt.buf)) {
		LOG_ERR("pkt.buf is null\n");
		goto err1;
	}
	memset(pkt.buf, 0, pkt.buf_size);

	data_pkt = (u8 *)pkt.buf;
	copy_u32_to_u8(data_pkt, reg->data, pktLen);
	print_data(data_pkt, (pktLen > PKT_PRINT_LEN_MAX) ? PKT_PRINT_LEN_MAX : pktLen);

	total_sg = pktLen / buffLen;
	last_buff_len = pktLen % buffLen;
	if (last_buff_len != 0)
		total_sg += 1;

	sg_init_table(sg, total_sg);
	for (i = 0; i < total_sg; i++) {
		if (i == (total_sg - 1)) {
			sg_set_buf(&sg[i], data_pkt + (i * buffLen),
				   ((last_buff_len != 0) ? last_buff_len : buffLen));
		} else {
			sg_set_buf(&sg[i], data_pkt + (i * buffLen), buffLen);
		}
	}

	if (unlikely(zxdh_virtqueue_add_outbuf(sq->vq, sg, total_sg, data_pkt, GFP_ATOMIC) != 0)) {
		LOG_ERR("zxdh_virtqueue_add_outbuf failure!\n");
		goto err1;
	}

	if (virtqueue_kick_prepare_packed(sq->vq) && zxdh_virtqueue_notify(sq->vq)) {
		u64_stats_update_begin(&sq->stats.syncp);
		sq->stats.kicks++;
		u64_stats_update_end(&sq->stats.syncp);
	}

	en_dev->netdev->stats.tx_packets++;
	en_dev->netdev->stats.tx_bytes += pktLen;
	LOG_INFO("en_dev->netdev->stats.tx_packets=%ld, tx pktLen=%d\n",
		 en_dev->netdev->stats.tx_packets, pktLen);

	return 0;

err1:
	free_pages((u64)pkt.buf, 4);
err:
	return -1;
}

s32 zxdh_send_file_pkt(struct net_device *netdev, struct ifreq *ifr)
{
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_reg *reg = NULL;
	u32 size = sizeof(struct zxdh_en_reg);
	s32 ret = 0;

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	en_priv = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_priv, NULL, -EADDRNOTAVAIL, "netdev priv is null!\n");

	reg = kzalloc(size, GFP_KERNEL);
	CHECK_EQUAL_ERR(reg, NULL, -EADDRNOTAVAIL, "reg is null!\n");

	if (copy_from_user(reg, ifr->ifr_ifru.ifru_data, size)) {
		LOG_ERR("copy_from_user failed\n");
		ret = -EFAULT;
		goto err_ret;
	}

	if ((reg->num == 0) || (reg->num > MAX_ACCESS_NUM)) {
		LOG_ERR("transmit failed, reg->num=%d\n", reg->num);
		ret = -EFAULT;
		goto err_ret;
	}

	ret = zxdh_tx_file_pkts(en_priv, reg);
	if (unlikely(ret != 0)) {
		LOG_ERR("transmit failed[ret = %d]!", ret);
		ret = -1;
		goto err_ret;
	}

	reg->num = 0;
	if (copy_to_user(ifr->ifr_ifru.ifru_data, reg, size)) {
		LOG_ERR("copy_to_user failed\n");
		ret = -EFAULT;
	}

err_ret:
	kfree(reg);
	return ret;
}

s32 zxdh_en_enable_ptp_encrypted_msg(struct net_device *netdev, struct ifreq *ifr,
				     struct zxdh_en_reg *reg)
{
	u32 reg_size = sizeof(struct zxdh_en_reg);
	s32 mac_num = 0; //0-2
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	u32 enable = 0;
	s32 ret = 0;

	LOG_INFO("enter in %s\n", __func__);
	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	en_priv = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_priv, NULL, -EADDRNOTAVAIL, "netdev priv is null!\n");
	en_dev = &en_priv->edev;

	mac_num = zxdh_pf_macpcs_num_get(en_dev);
	if (mac_num < 0) {
		LOG_ERR("get mac num %d err, its value should is 0-2!\n", mac_num);
		goto err_ret;
	}

	if (unlikely(copy_from_user(reg, ifr->ifr_ifru.ifru_data, reg_size))) {
		LOG_ERR("copy_from_user failed!\n");
		goto err_ret;
	}
	if (reg->num != 1) {
		LOG_ERR("Transmit failed[len = %d]!\n", reg->num);
		goto err_ret;
	}

	enable = reg->data[0];
	if ((enable != 0) && (enable != 1)) {
		LOG_ERR("Transmit failed[enable = %u]!\n", enable);
		goto err_ret;
	}

	LOG_INFO("enable = %u\n", enable);

#ifdef PTP_DRIVER_INTERFACE_EN

	ret = enable_write_ts_to_fifo(en_dev, enable, mac_num);
	CHECK_UNEQUAL_ERR(ret, 0, -EFAULT, "enable ptp encrypted msg failed!!\n");
#endif /* PTP_DRIVER_INTERFACE_EN */

	reg->num = 0;
	if (unlikely(copy_to_user(ifr->ifr_ifru.ifru_data, reg, reg_size))) {
		LOG_ERR("copy_to_user failed!\n");
		goto err_ret;
	}

	return ret;

err_ret:
	return -1;
}

s32 zxdh_en_set_intr_capture_timer(struct net_device *netdev, struct ifreq *ifr,
				   struct zxdh_en_reg *reg)
{
	u_int32_t index;
	u32 reg_size = sizeof(struct zxdh_en_reg);
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	s32 ret = 0;

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	en_priv = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_priv, NULL, -EADDRNOTAVAIL, "netdev priv is null!\n");
	en_dev = &en_priv->edev;

	if (reg->num != 1) {
		LOG_ERR("Transmit failed[len = %d]!", reg->num);
		goto err_ret;
	}

	index = reg->data[0];
	LOG_INFO("index = %d\n", index);
	if (index > 4) {
		LOG_ERR("capture timer out of range!");
		goto err_ret;
	}
#ifdef PTP_DRIVER_INTERFACE_EN
	ret = set_interrupt_capture_timer(en_dev, index);
	CHECK_UNEQUAL_ERR(ret, 0, -EFAULT, "set interrupt capture timer failed!!\n");
#endif /* PTP_DRIVER_INTERFACE_EN */

	reg->num = 0;
	if (unlikely(copy_to_user(ifr->ifr_ifru.ifru_data, reg, reg_size))) {
		LOG_ERR("copy_to_user failed!!!\n");
		goto err_ret;
	}

	return ret;

err_ret:
	return -1;
}

s32 zxdh_en_set_pps_selection(struct net_device *netdev, struct ifreq *ifr, struct zxdh_en_reg *reg)
{
	u32 pps_type;
	u32 selection;
	u32 reg_size = sizeof(struct zxdh_en_reg);
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	s32 ret = 0;

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	en_priv = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_priv, NULL, -EADDRNOTAVAIL, "netdev priv is null!\n");
	en_dev = &en_priv->edev;

	if (reg->num != 2) {
		LOG_ERR("Transmit failed[len = %d]!", reg->num);
		goto err_ret;
	}

	pps_type = reg->data[0];
	selection = reg->data[1];
	LOG_INFO("pps_type = %u, selection = %u\n", pps_type, selection);
#ifdef PTP_DRIVER_INTERFACE_EN
	ret = zxdh_set_pps_selection(en_dev, pps_type, selection);
	CHECK_UNEQUAL_ERR(ret, 0, -EFAULT, "set pps selection failed!!\n");
#endif /* PTP_DRIVER_INTERFACE_EN */

	reg->num = 0;
	if (unlikely(copy_to_user(ifr->ifr_ifru.ifru_data, reg, reg_size))) {
		LOG_ERR("copy_to_user failed!!!\n");
		goto err_ret;
	}

	return ret;

err_ret:
	return -1;
}

s32 zxdh_en_set_phase_detection(struct net_device *netdev, struct ifreq *ifr,
				struct zxdh_en_reg *reg)
{
	u32 pd_index;
	u32 pd_input1;
	u32 pd_input2;
	u32 reg_size = sizeof(struct zxdh_en_reg);
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	s32 ret = 0;

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	en_priv = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_priv, NULL, -EADDRNOTAVAIL, "netdev priv is null!\n");
	en_dev = &en_priv->edev;

	if (reg->num != 3) {
		LOG_ERR("Transmit failed[len = %d]!", reg->num);
		goto err_ret;
	}

	pd_index = reg->data[0];
	pd_input1 = reg->data[1];
	pd_input2 = reg->data[2];
	LOG_INFO("pd_index = %u, pd_input1 = %u, pd_input2 = %u\n", pd_index, pd_input1, pd_input2);
#ifdef PTP_DRIVER_INTERFACE_EN
	ret = zxdh_set_pd_detection(en_dev, pd_index, pd_input1, pd_input2);
	CHECK_UNEQUAL_ERR(ret, 0, -EFAULT, "set pd detection failed!!\n");
#endif /* PTP_DRIVER_INTERFACE_EN */

	reg->num = 0;
	if (unlikely(copy_to_user(ifr->ifr_ifru.ifru_data, reg, reg_size))) {
		LOG_ERR("copy_to_user failed!!!\n");
		goto err_ret;
	}

	return ret;

err_ret:
	return -1;
}

s32 zxdh_en_get_pd_value(struct net_device *netdev, struct ifreq *ifr, struct zxdh_en_reg *reg)
{
	u32 pd_index;
	u32 pd_result;
	u32 reg_size = sizeof(struct zxdh_en_reg);
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	s32 ret = 0;

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	en_priv = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_priv, NULL, -EADDRNOTAVAIL, "netdev priv is null!\n");
	en_dev = &en_priv->edev;

	if (reg->num != 1) {
		LOG_ERR("Transmit failed[len = %d]!", reg->num);
		goto err_ret;
	}

	pd_index = reg->data[0];
	LOG_INFO("pd_index = %u\n", pd_index);
#ifdef PTP_DRIVER_INTERFACE_EN
	ret = zxdh_get_pd_value(en_dev, pd_index, &pd_result);
	CHECK_UNEQUAL_ERR(ret, 0, -EFAULT, "get pd value failed!!\n");
#endif /* PTP_DRIVER_INTERFACE_EN */

	reg->num = 1;
	reg->data[0] = pd_result;
	if (unlikely(copy_to_user(ifr->ifr_ifru.ifru_data, reg, reg_size))) {
		LOG_ERR("copy_to_user failed!!!\n");
		goto err_ret;
	}

	return ret;

err_ret:
	return -1;
}

s32 zxdh_en_set_l2_ptp_port(struct net_device *netdev, struct ifreq *ifr, struct zxdh_en_reg *reg)
{
	u32 reg_size = sizeof(struct zxdh_en_reg);
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	s32 ret = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	en_priv = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_priv, NULL, -EADDRNOTAVAIL, "netdev priv is null!\n");
	en_dev = &en_priv->edev;
	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	LOG_INFO("reg->num: %d", reg->num);
	LOG_INFO("reg->offset: %d", reg->offset);
	if (reg->num != 1) {
		LOG_ERR("Transmit failed[len = %d]!", reg->num);
		goto err_ret;
	}

	en_dev->vf_1588_call_np_num = PTP_PORT_VFID_SET;
	LOG_INFO("en_dev->vport: 0x%x, IS_PF(en_dev->vport): %d", en_dev->vport,
		 IS_PF(en_dev->vport));
	if (IS_PF(en_dev->vport)) {
		ret = dpp_ptp_port_vfid_set(&pf_info, VQM_VFID(en_dev->vport));
		if (ret != 0) {
			LOG_ERR("dpp_ptp_port_vfid_set failed!!!\n");
			goto err_ret;
		}
	} else {
		ret = zxdh_vf_1588_call_np_interface(en_dev);
		if (ret != 0) {
			LOG_ERR("zxdh_vf_1588_call_np_interface failed!!!\n");
			goto err_ret;
		}
	}

	reg->num = 0;
	if (unlikely(copy_to_user(ifr->ifr_ifru.ifru_data, reg, reg_size))) {
		LOG_ERR("copy_to_user failed!!!\n");
		goto err_ret;
	}
	LOG_INFO("dpp_ptp_port_vfid_set success");

	return ret;

err_ret:
	return -1;
}

s32 zxdh_en_set_ptp_tc_enable(struct net_device *netdev, struct ifreq *ifr, struct zxdh_en_reg *reg)
{
	u32 reg_size = sizeof(struct zxdh_en_reg);
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	s32 ret = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	en_priv = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_priv, NULL, -EADDRNOTAVAIL, "netdev priv is null!\n");
	en_dev = &en_priv->edev;
	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (reg->num != 1) {
		LOG_ERR("Transmit failed[len = %d]!", reg->num);
		goto err_ret;
	}

	en_dev->ptp_tc_enable_opt = reg->data[0];
	LOG_INFO("en_dev->ptp_tc_enable_opt = %u\n", en_dev->ptp_tc_enable_opt);

	en_dev->vf_1588_call_np_num = PTP_TC_ENABLE_SET;

	if (IS_PF(en_dev->vport)) {
		ret = dpp_ptp_tc_enable_set(&pf_info, en_dev->ptp_tc_enable_opt);
		if (ret != 0) {
			LOG_ERR("dpp_ptp_tc_enable_set failed!!!\n");
			goto err_ret;
		}
	} else {
		ret = zxdh_vf_1588_call_np_interface(en_dev);
		if (ret != 0) {
			LOG_ERR("zxdh_vf_1588_call_np_interface failed!!!\n");
			goto err_ret;
		}
	}

	reg->num = 0;
	if (unlikely(copy_to_user(ifr->ifr_ifru.ifru_data, reg, reg_size)))
		goto err_ret;

	return ret;

err_ret:
	return -1;
}

s32 zxdh_en_set_synce_recovery_port(struct net_device *netdev, struct ifreq *ifr,
				    struct zxdh_en_reg *reg)
{
	u32 reg_size = sizeof(struct zxdh_en_reg);
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	en_priv = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_priv, NULL, -EADDRNOTAVAIL, "netdev priv is null!\n");
	en_dev = &en_priv->edev;

	if (reg->num != 1) {
		LOG_ERR("Transmit failed[len = %d]!", reg->num);
		return -1;
	}

	if (en_dev->phy_port == INVALID_PHY_PORT) {
		LOG_ERR("phyport is invalid!");
		return -EOPNOTSUPP;
	}

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}
	msg->payload.hdr_to_agt.op_code = AGENT_MAC_RECOVERY_CLK_SET;
	msg->payload.hdr_to_agt.phyport = en_dev->phy_port;
	msg->payload.synce_clk_recovery_port.clk_speed = reg->data[0];
	LOG_INFO("phyport = %u, clk_speed = %u\n", msg->payload.hdr_to_agt.phyport,
		 msg->payload.synce_clk_recovery_port.clk_speed);
	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_MAC, msg, msg, &para);
	if (err != 0) {
		LOG_ERR("%s failed, err: %d\n", __func__, err);
		goto free_msg;
	}

	reg->num = 0;
	err = copy_to_user(ifr->ifr_ifru.ifru_data, reg, reg_size);

free_msg:
	kfree(msg);
	return err;
}

s32 zxdh_en_get_synce_clk_stats(struct net_device *netdev, struct ifreq *ifr,
				struct zxdh_en_reg *reg)
{
	u32 reg_size = sizeof(struct zxdh_en_reg);
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	en_priv = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_priv, NULL, -EADDRNOTAVAIL, "netdev priv is null!\n");
	en_dev = &en_priv->edev;

	if (reg->num != 1) {
		LOG_ERR("Transmit failed[len = %d]!", reg->num);
		return -1;
	}

	if (en_dev->phy_port == INVALID_PHY_PORT) {
		LOG_ERR("phyport is invalid!");
		return -EOPNOTSUPP;
	}

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}
	msg->payload.hdr_to_agt.op_code = AGENT_MAC_SYNCE_CLK_STATS_GET;
	msg->payload.hdr_to_agt.phyport = en_dev->phy_port;
	LOG_INFO("phyport = %u\n", msg->payload.hdr_to_agt.phyport);
	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_MAC, msg, msg, &para);
	if (err != 0) {
		LOG_ERR("%s failed, err: %d\n", __func__, err);
		goto free_msg;
	}

	reg->num = 1;
	reg->data[0] = msg->reps.synce_clk_recovery_port.clk_stats;
	err = copy_to_user(ifr->ifr_ifru.ifru_data, reg, reg_size);
	LOG_INFO("num = %u, clk_stats: 0x%x\n", reg->num, reg->data[0]);

free_msg:
	kfree(msg);
	return err;
}

s32 zxdh_en_set_spm_port_tstamp_enable(struct net_device *netdev, struct ifreq *ifr,
				       struct zxdh_en_reg *reg)
{
	u32 reg_size = sizeof(struct zxdh_en_reg);
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	s32 ret = 0;
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	en_priv = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_priv, NULL, -EADDRNOTAVAIL, "netdev priv is null!\n");
	en_dev = &en_priv->edev;

	if (reg->num != 2) {
		LOG_ERR("Transmit failed[len = %d]!", reg->num);
		return -1;
	}

	if (en_dev->phy_port == INVALID_PHY_PORT) {
		LOG_ERR("phyport is invalid!");
		return -EOPNOTSUPP;
	}

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}
	msg->payload.hdr_to_agt.op_code = AGENT_MAC_PORT_TSTAMP_ENABLE_SET;
	msg->payload.hdr_to_agt.phyport = en_dev->phy_port; // 0~9
	msg->payload.mac_tstamp_msg.tx_enable = reg->data[0];
	msg->payload.mac_tstamp_msg.rx_enable = reg->data[1];
	LOG_INFO("phyport = %u, tx_enable: %u, rx_enable: %u\n", msg->payload.hdr_to_agt.phyport,
		 msg->payload.mac_tstamp_msg.tx_enable, msg->payload.mac_tstamp_msg.rx_enable);
	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_MAC, msg, msg, &para);
	if (err != 0) {
		LOG_ERR("zxdh set spm_port_tstamp_enable failed, err: %d\n", err);
		goto free_msg;
	}

	reg->num = 0;
	ret = copy_to_user(ifr->ifr_ifru.ifru_data, reg, reg_size);

free_msg:
	kfree(msg);
	return ret;
}

s32 zxdh_en_get_spm_port_tstamp_enable(struct net_device *netdev, struct ifreq *ifr,
				       struct zxdh_en_reg *reg)
{
	u32 reg_size = sizeof(struct zxdh_en_reg);
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	s32 ret = 0;
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	en_priv = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_priv, NULL, -EADDRNOTAVAIL, "netdev priv is null!\n");
	en_dev = &en_priv->edev;

	if (en_dev->phy_port == INVALID_PHY_PORT) {
		LOG_ERR("phyport is invalid!");
		return -EOPNOTSUPP;
	}

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}
	msg->payload.hdr_to_agt.op_code = AGENT_MAC_PORT_TSTAMP_ENABLE_GET;
	msg->payload.hdr_to_agt.phyport = en_dev->phy_port; // 0~9
	LOG_INFO("phyport = %u\n", msg->payload.hdr_to_agt.phyport);
	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_MAC, msg, msg, &para);
	if (err != 0) {
		LOG_ERR("zxdh get spm_port_tstamp_enable failed, err: %d\n", err);
		goto free_msg;
	}

	reg->num = 2;
	reg->data[0] = msg->reps.mac_tstamp_msg.tx_enable;
	reg->data[1] = msg->reps.mac_tstamp_msg.rx_enable;
	LOG_INFO("tx_enable: %u, rx_enable: %u\n", msg->reps.mac_tstamp_msg.tx_enable,
		 msg->reps.mac_tstamp_msg.rx_enable);

	ret = copy_to_user(ifr->ifr_ifru.ifru_data, reg, reg_size);

free_msg:
	kfree(msg);
	return ret;
}

s32 zxdh_en_set_spm_port_tstamp_mode(struct net_device *netdev, struct ifreq *ifr,
				     struct zxdh_en_reg *reg)
{
	u32 reg_size = sizeof(struct zxdh_en_reg);
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	s32 ret = 0;
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	en_priv = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_priv, NULL, -EADDRNOTAVAIL, "netdev priv is null!\n");
	en_dev = &en_priv->edev;

	if (en_dev->phy_port == INVALID_PHY_PORT) {
		LOG_ERR("phyport is invalid!");
		return -EOPNOTSUPP;
	}

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (unlikely(!msg)) {
		LOG_ERR("failed to kzalloc\n");
		return -ENOMEM;
	}

	if (reg->num != 2) {
		LOG_ERR("Transmit failed[len = %d]!", reg->num);
		goto err_ret;
	}

	msg->payload.hdr_to_agt.op_code = AGENT_MAC_PORT_TSTAMP_MODE_SET;
	msg->payload.hdr_to_agt.phyport = en_dev->phy_port; // 0~9
	msg->payload.mac_tstamp_msg.tx_mode = reg->data[0];
	msg->payload.mac_tstamp_msg.rx_mode = reg->data[1];
	LOG_INFO("phyport = %u, tx_mode: %u, rx_mode: %u\n", msg->payload.hdr_to_agt.phyport,
		 msg->payload.mac_tstamp_msg.tx_mode, msg->payload.mac_tstamp_msg.rx_mode);
	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_MAC, msg, msg, &para);
	if (err != 0) {
		LOG_ERR("zxdh set spm_port_tstamp_mode failed, err: %d\n", err);
		kfree(msg);
		return err;
	}

	reg->num = 0;
	if (unlikely(copy_to_user(ifr->ifr_ifru.ifru_data, reg, reg_size)))
		goto err_ret;
	kfree(msg);
	return ret;

err_ret:
	kfree(msg);
	return -1;
}

s32 zxdh_en_get_spm_port_tstamp_mode(struct net_device *netdev, struct ifreq *ifr,
				     struct zxdh_en_reg *reg)
{
	u32 reg_size = sizeof(struct zxdh_en_reg);
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	en_priv = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_priv, NULL, -EADDRNOTAVAIL, "netdev priv is null!\n");
	en_dev = &en_priv->edev;

	if (en_dev->phy_port == INVALID_PHY_PORT) {
		LOG_ERR("phyport is invalid!");
		return -EOPNOTSUPP;
	}

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (unlikely(!msg)) {
		LOG_ERR("failed to kzalloc\n");
		return -ENOMEM;
	}

	msg->payload.hdr_to_agt.op_code = AGENT_MAC_PORT_TSTAMP_MODE_GET;
	msg->payload.hdr_to_agt.phyport = en_dev->phy_port; // 0~9
	LOG_INFO("phyport = %u\n", msg->payload.hdr_to_agt.phyport);
	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_MAC, msg, msg, &para);
	if (err != 0) {
		LOG_ERR("zxdh get spm_port_tstamp_mode failed, err: %d\n", err);
		kfree(msg);
		return err;
	}

	reg->num = 2;
	reg->data[0] = msg->reps.mac_tstamp_msg.tx_mode;
	reg->data[1] = msg->reps.mac_tstamp_msg.rx_mode;
	LOG_INFO("tx_mode: %u, rx_mode: %u\n", msg->reps.mac_tstamp_msg.tx_mode,
		 msg->reps.mac_tstamp_msg.rx_mode);

	if (unlikely(copy_to_user(ifr->ifr_ifru.ifru_data, reg, reg_size)))
		goto err_ret;

	kfree(msg);
	return 0;

err_ret:
	kfree(msg);
	return -1;
}

s32 zxdh_en_set_delay_statistics_enable(struct net_device *netdev, struct ifreq *ifr,
					struct zxdh_en_reg *reg)
{
	u32 reg_size = sizeof(struct zxdh_en_reg);
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	s32 ret = 0;

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	en_priv = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_priv, NULL, -EADDRNOTAVAIL, "netdev priv is null!\n");
	en_dev = &en_priv->edev;

	if (reg->num != 1) {
		LOG_ERR("Transmit failed[len = %d]!", reg->num);
		goto err_ret;
	}

	en_dev->delay_statistics_enable = reg->data[0];
	LOG_INFO("en_dev->delay_statistics_enable = %u\n", en_dev->delay_statistics_enable);

	reg->num = 0;
	if (unlikely(copy_to_user(ifr->ifr_ifru.ifru_data, reg, reg_size)))
		goto err_ret;

	return ret;

err_ret:
	return -1;
}

s32 zxdh_en_get_delay_statistics_value(struct net_device *netdev, struct ifreq *ifr,
				       struct zxdh_en_reg *reg)
{
	u32 reg_size = sizeof(struct zxdh_en_reg);
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	s32 ret = 0;
	union zxdh_msg *msg = NULL;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	en_priv = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_priv, NULL, -EADDRNOTAVAIL, "netdev priv is null!\n");
	en_dev = &en_priv->edev;

	if (en_dev->phy_port == INVALID_PHY_PORT) {
		LOG_ERR("phyport is invalid!");
		return -EOPNOTSUPP;
	}

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (unlikely(!msg)) {
		LOG_ERR("failed to kzalloc\n");
		return -ENOMEM;
	}

	msg->payload.hdr_to_agt.op_code = AGENT_MAC_PORT_DELAY_VALUE_GET;
	msg->payload.hdr_to_agt.phyport = en_dev->phy_port; // 0~9
	LOG_INFO("phyport = %u\n", msg->payload.hdr_to_agt.phyport);
	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_MAC, msg, msg, &para);
	if (ret != 0) {
		LOG_ERR("zxdh get delay_statistics_value failed, ret: %d\n", ret);
		kfree(msg);
		return ret;
	}

	reg->num = 4;
	reg->data[0] = (u32)(msg->reps.delay_statistics_val.min_delay & 0xffffffff);
	reg->data[1] = (u32)((msg->reps.delay_statistics_val.min_delay >> 32) & 0xffffffff);
	reg->data[2] = (u32)(msg->reps.delay_statistics_val.max_delay & 0xffffffff);
	reg->data[3] = (u32)((msg->reps.delay_statistics_val.max_delay >> 32) & 0xffffffff);
	LOG_INFO("delay val: min_delay: %llu, max_delay: %llu\n",
		 msg->reps.delay_statistics_val.min_delay,
		 msg->reps.delay_statistics_val.max_delay);
	if (unlikely(copy_to_user(ifr->ifr_ifru.ifru_data, reg, reg_size)))
		goto err_ret;
	kfree(msg);
	return 0;

err_ret:
	kfree(msg);
	return -1;
}

s32 zxdh_en_clear_delay_statistics_value(struct net_device *netdev, struct ifreq *ifr,
					 struct zxdh_en_reg *reg)
{
	u32 reg_size = sizeof(struct zxdh_en_reg);
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	s32 ret = 0;
	union zxdh_msg *msg = NULL;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	en_priv = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_priv, NULL, -EADDRNOTAVAIL, "netdev priv is null!\n");
	en_dev = &en_priv->edev;

	if (en_dev->phy_port == INVALID_PHY_PORT) {
		LOG_ERR("phyport is invalid!");
		return -EOPNOTSUPP;
	}

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}

	msg->payload.hdr_to_agt.op_code = AGENT_MAC_PORT_DELAY_VALUE_CLR;
	msg->payload.hdr_to_agt.phyport = en_dev->phy_port; // 0~9
	LOG_INFO("phyport = %u\n", msg->payload.hdr_to_agt.phyport);
	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_MAC, msg, msg, &para);
	if (ret != 0) {
		LOG_ERR("zxdh clear_delay_statistics_value failed, ret: %d\n", ret);
		kfree(msg);
		return ret;
	}

	reg->num = 0;
	if (unlikely(copy_to_user(ifr->ifr_ifru.ifru_data, reg, reg_size))) {
		kfree(msg);
		goto err_ret;
	}

	kfree(msg);
	return 0;

err_ret:
	return -1;
}

s32 zxdh_en_set_local_pps_interrupt_enable(struct net_device *netdev, struct ifreq *ifr,
					   struct zxdh_en_reg *reg)
{
#ifdef PTP_DRIVER_INTERFACE_EN
	u32 enable;
	u32 support;
	u32 reg_size = sizeof(struct zxdh_en_reg);
#endif
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	s32 ret = 0;

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	en_priv = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_priv, NULL, -EADDRNOTAVAIL, "netdev priv is null!\n");
	en_dev = &en_priv->edev;

	if (reg->num != 1) {
		LOG_ERR("Transmit failed[len = %d]!", reg->num);
		goto err_ret;
	}

#ifdef PTP_DRIVER_INTERFACE_EN
	ret = zxdh_get_pps_interrupt_support(en_dev, &support);
	CHECK_UNEQUAL_ERR(ret, 0, -EFAULT, "get pps interrupt support failed!!\n");
	enable = reg->data[0];
	LOG_INFO("enable = %u\n", enable);
	// not support
	if (support != 1) {
		reg->num = 1;
		reg->data[0] = 1; // notify user not support pps interrupt
		if (unlikely(copy_to_user(ifr->ifr_ifru.ifru_data, reg, reg_size))) {
			LOG_ERR("copy_to_user failed!!!\n");
			goto err_ret;
		}
		goto err_ret;
	}

	ret = zxdh_set_local_pps_interrupt_enable(en_dev, enable);
	CHECK_UNEQUAL_ERR(ret, 0, -EFAULT, "set local pps interrupt failed!!\n");

	reg->num = 1;
	reg->data[0] = 0; // notify user support pps interrupt
	if (unlikely(copy_to_user(ifr->ifr_ifru.ifru_data, reg, reg_size))) {
		LOG_ERR("copy_to_user failed!!!\n");
		goto err_ret;
	}
#endif /* PTP_DRIVER_INTERFACE_EN */
	return ret;

err_ret:
	return -1;
}

s32 zxdh_en_set_ext_pps_interrupt_enable(struct net_device *netdev, struct ifreq *ifr,
					 struct zxdh_en_reg *reg)
{
#ifdef PTP_DRIVER_INTERFACE_EN
	u32 pps_type;
	u32 enable;
	u32 support;
	u32 reg_size = sizeof(struct zxdh_en_reg);
#endif
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	s32 ret = 0;

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	en_priv = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_priv, NULL, -EADDRNOTAVAIL, "netdev priv is null!\n");
	en_dev = &en_priv->edev;

	if (reg->num != 2) {
		LOG_ERR("Transmit failed[len = %d]!", reg->num);
		goto err_ret;
	}

#ifdef PTP_DRIVER_INTERFACE_EN
	ret = zxdh_get_pps_interrupt_support(en_dev, &support);
	CHECK_UNEQUAL_ERR(ret, 0, -EFAULT, "get pps interrupt support failed!!\n");
	pps_type = reg->data[0];
	enable = reg->data[1];
	LOG_INFO("pps_type = %u, enable = %u\n", pps_type, enable);
	// not support
	if (support != 1) {
		reg->num = 1;
		reg->data[0] = 1; // notify user not support pps interrupt
		if (unlikely(copy_to_user(ifr->ifr_ifru.ifru_data, reg, reg_size))) {
			LOG_ERR("copy_to_user failed!!!\n");
			goto err_ret;
		}
		goto err_ret;
	}

	ret = zxdh_set_ext_pps_interrupt_enable(en_dev, pps_type, enable);
	CHECK_UNEQUAL_ERR(ret, 0, -EFAULT, "set ext pps interrupt enable failed!!\n");

	reg->num = 1;
	reg->data[0] = 0; // notify user support pps interrupt
	if (unlikely(copy_to_user(ifr->ifr_ifru.ifru_data, reg, reg_size))) {
		LOG_ERR("copy_to_user failed!!!\n");
		goto err_ret;
	}
#endif /* PTP_DRIVER_INTERFACE_EN */
	return ret;

err_ret:
	return -1;
}

s32 zxdh_en_set_pd_sel_shift(struct net_device *netdev, struct ifreq *ifr, struct zxdh_en_reg *reg)
{
	u32 pd_index;
	u32 pd_sel;
	u32 shift;
	u32 reg_size = sizeof(struct zxdh_en_reg);
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	s32 ret = 0;

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	en_priv = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_priv, NULL, -EADDRNOTAVAIL, "netdev priv is null!\n");
	en_dev = &en_priv->edev;

	if (reg->num != 3) {
		LOG_ERR("Transmit failed[len = %d]!", reg->num);
		goto err_ret;
	}

	pd_index = reg->data[0];
	pd_sel = reg->data[1];
	shift = reg->data[2];
	LOG_INFO("pd_index = %u, pd_sel = %u, shift = %u\n", pd_index, pd_sel, shift);

#ifdef PTP_DRIVER_INTERFACE_EN
	ret = zxdh_set_pd_sel_shift(en_dev, pd_index, pd_sel, shift);
	CHECK_UNEQUAL_ERR(ret, 0, -EFAULT, "set pd sel shift failed!!\n");
#endif /* PTP_DRIVER_INTERFACE_EN */
	reg->num = 1;
	reg->data[0] = 0; // notify user support pps interrupt
	if (unlikely(copy_to_user(ifr->ifr_ifru.ifru_data, reg, reg_size))) {
		LOG_ERR("copy_to_user failed!!!\n");
		goto err_ret;
	}

	return ret;

err_ret:
	return -1;
}

s32 zxdh_en_get_ptp_clock_index(struct net_device *netdev, struct ifreq *ifr,
				struct zxdh_en_reg *reg)
{
	u32 ptp_clock_index;
	u32 reg_size = sizeof(struct zxdh_en_reg);
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	s32 ret = 0;

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	en_priv = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_priv, NULL, -EADDRNOTAVAIL, "netdev priv is null!\n");
	en_dev = &en_priv->edev;

#ifdef PTP_DRIVER_INTERFACE_EN
	ret = zxdh_get_ptp_clock_index(en_dev, &ptp_clock_index);
	CHECK_UNEQUAL_ERR(ret, 0, -EFAULT, "get ptp clock index failed!!\n");
#endif /* PTP_DRIVER_INTERFACE_EN */

	reg->num = 1;
	reg->data[0] = ptp_clock_index;
	if (unlikely(copy_to_user(ifr->ifr_ifru.ifru_data, reg, reg_size))) {
		LOG_ERR("copy_to_user failed!!!\n");
		goto err_ret;
	}

	return ret;

err_ret:
	return -1;
}

struct zxdh_en_ptp_ioctl_table ioctl_ptp_table[] = {
	{ PTP_SET_CLOCK_NO, zxdh_en_set_clock_no },
	{ PTP_ENABLE_PTP_ENCRYPTED_MSG, zxdh_en_enable_ptp_encrypted_msg },
	{ PTP_SET_INTR_CAPTURE_TIMER, zxdh_en_set_intr_capture_timer },
	{ PTP_SET_PP1S_SELECTION, zxdh_en_set_pps_selection },
	{ PTP_SET_PHASE_DETECTION, zxdh_en_set_phase_detection },
	{ PTP_GET_PD_VALUE, zxdh_en_get_pd_value },
	{ PTP_SET_L2PTP_PORT, zxdh_en_set_l2_ptp_port },
	{ PTP_SET_PTP_EC_ENABLE, zxdh_en_set_ptp_tc_enable },
	{ PTP_SET_SYNCE_CLK_PORT, zxdh_en_set_synce_recovery_port },
	{ PTP_GET_SYNCE_CLK_STATS, zxdh_en_get_synce_clk_stats },
	{ PTP_SET_SPM_PORT_TSTAMP_ENABLE, zxdh_en_set_spm_port_tstamp_enable },
	{ PTP_GET_SPM_PORT_TSTAMP_ENABLE, zxdh_en_get_spm_port_tstamp_enable },
	{ PTP_SET_SPM_PORT_TSTAMP_MODE, zxdh_en_set_spm_port_tstamp_mode },
	{ PTP_GET_SPM_PORT_TSTAMP_MODE, zxdh_en_get_spm_port_tstamp_mode },
	{ PTP_SET_DELAY_STATISTICS_ENABLE, zxdh_en_set_delay_statistics_enable },
	{ PTP_GET_DELAY_STATISTICS_VALUE, zxdh_en_get_delay_statistics_value },
	{ PTP_CLR_DELAY_STATISTICS_VALUE, zxdh_en_clear_delay_statistics_value },
	{ PTP_SET_LOCAL_PPS_INTERRUPT_ENABLE, zxdh_en_set_local_pps_interrupt_enable },
	{ PTP_SET_EXT_PPS_INTERRUPT_ENABLE, zxdh_en_set_ext_pps_interrupt_enable },
	{ PTP_SET_PD_SEL_SHIFT, zxdh_en_set_pd_sel_shift },
	{ PTP_GET_PTP_CLOCK_INDEX, zxdh_en_get_ptp_clock_index }
};

s32 ptp_table_match_func(struct net_device *netdev, struct ifreq *ifr, struct zxdh_en_reg *reg)
{
	u32 i = 0;
	u32 ret = 0;
	u32 table_size = sizeof(ioctl_ptp_table) / sizeof(struct zxdh_en_ioctl_table);

	for (i = 0; i < table_size; i++) {
		if ((reg->offset == ioctl_ptp_table[i].cmd) && (ioctl_ptp_table[i].func)) {
			ret = ioctl_ptp_table[i].func(netdev, ifr, reg);
			break;
		}
	}
	return ret;
}

s32 zxdh_en_ptp_func(struct net_device *netdev, struct ifreq *ifr)
{
	struct zxdh_en_reg *reg = NULL;
	u32 reg_size = sizeof(struct zxdh_en_reg);

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	reg = kzalloc(reg_size, GFP_KERNEL);
	CHECK_EQUAL_ERR(reg, NULL, -EADDRNOTAVAIL, "reg is null!\n");

	if (unlikely(copy_from_user(reg, ifr->ifr_ifru.ifru_data, reg_size))) {
		LOG_ERR("copy_from_user failed!\n");
		goto err_ret;
	}

	if (-1 == ptp_table_match_func(netdev, ifr, reg)) {
		LOG_ERR("ptp_table_match_func failed!\n");
		goto err_ret;
	}

	kfree(reg);
	return 0;

err_ret:
	kfree(reg);
	return -1;
}

s32 zxdh_en_pps_func(struct net_device *netdev, struct ifreq *ifr)
{
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	struct dh_core_dev *dh_dev = NULL;
	struct zxdh_pf_device *pf_dev = NULL;
	struct dh_eq_table *table = NULL;
	struct dh_pf_eq_table *table_priv = NULL;
	u64 virtaddr = 0x0;
	struct dh_irq *expps = NULL;
	struct dh_irq *lopps = NULL;
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

#ifdef PTP_DRIVER_INTERFACE_EN
	s32 ret = 0;
#endif /* PTP_DRIVER_INTERFACE_EN */

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");

	en_priv = netdev_priv(netdev);
	en_dev = &en_priv->edev;
	dh_dev = en_dev->parent->parent;
	pf_dev = dh_core_priv(dh_dev);

	table = &dh_dev->eq_table;
	table_priv = table->priv;

	LOG_ERR("pf_dev->pci_ioremap_addr[0]: 0x%llx\n", pf_dev->pci_ioremap_addr[0]);

	virtaddr = pf_dev->pci_ioremap_addr[0] + ZXDH_BAR_MSG_OFFSET;
#ifdef PTP_DRIVER_INTERFACE_EN
	tod_device_set_bar_virtual_addr(virtaddr, pf_dev->pcie_id);
#endif

	expps = table_priv->async_irq_tbl[3];
	lopps = table_priv->async_irq_tbl[4];

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (unlikely(!msg)) {
		LOG_ERR("failed to kzalloc\n");
		return -ENOMEM;
	}

	msg->payload.msg_pps.pcieid = pf_dev->pcie_id;
	msg->payload.msg_pps.extern_pps_vector = expps->index;
	msg->payload.msg_pps.local_pps_vector = lopps->index;
	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_PPS, msg, msg, &para);
	if (err != 0) {
		LOG_ERR("zxdh pps_func failed, err: %d\n", err);
		goto free_msg;
	}

#ifdef PTP_DRIVER_INTERFACE_EN
	ret = zxdh_set_pps_interrupt_support(en_dev, msg->reps.msg_pps.pps_intr_support);
	if (unlikely(ret != 0)) {
		LOG_ERR("set pps interrupt support failed!!\n");
		err = -EFAULT;
		goto free_msg;
	}
#endif /* PTP_DRIVER_INTERFACE_EN */

free_msg:
	kfree(msg);

	return err;
}

#ifdef ZXDH_MSGQ
s32 zxdh_msgq_msg_send(struct net_device *netdev, struct ifreq *ifr)
{
	struct zxdh_en_device *en_dev = NULL;
	struct msgq_dev *msgq_dev = NULL;
	struct zxdh_en_reg *reg = NULL;
	struct msgq_pkt_info pkt_info = { 0 };
	u32 size = sizeof(struct zxdh_en_reg);
	struct reps_info reps = { 0 };
	u32 loop_cnt = 0;
	u32 i = 0;
	s32 err = -2;
	u64 start_us = 0;
	u64 end_us = 0;

	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");
	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	en_dev = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_dev, NULL, -EADDRNOTAVAIL, "en_dev is null!\n");
	msgq_dev = (struct msgq_dev *)en_dev->msgq_dev;
	CHECK_EQUAL_ERR(msgq_dev, NULL, -EADDRNOTAVAIL, "msgq_dev is null!\n");

	reg = kzalloc(size, GFP_KERNEL);
	CHECK_EQUAL_ERR(reg, NULL, -EADDRNOTAVAIL, "reg is null!\n");

	if (unlikely(copy_from_user(reg, ifr->ifr_ifru.ifru_data, size))) {
		LOG_ERR("copy_from_user failed!\n");
		goto err_ret;
	}

	pkt_info.event_id = MODULE_DEMO;
	pkt_info.timeout_us = 500000;
	pkt_info.len = reg->data[0] + PRIV_HEADER_LEN;
	pkt_info.no_reps = (reg->data[1] == 0) ? false : true;
	loop_cnt = reg->data[2];
	if (loop_cnt == 0 || pkt_info.len > MSGQ_MAX_ADDR_LEN)
		goto err_ret;

	if (loop_cnt > 100000000)
		loop_cnt = 100000000;

	reps.len = 14000;
	reps.addr = vmalloc(reps.len);
	if (!reps.addr) {
		LOG_ERR("vmalloc failed!\n");
		goto err_ret;
	}

	LOG_DEBUG("len: %d, no_reps: %d, loop_cnt: %d\n", pkt_info.len, pkt_info.no_reps, loop_cnt);

	start_us = jiffies_to_usecs(jiffies);
	for (i = 0; i < loop_cnt; ++i) {
		pkt_info.addr = kzalloc(pkt_info.len, GFP_KERNEL);
		if (!pkt_info.addr) {
			err = -3;
			break;
		};
		err = zxdh_msgq_send_cmd(msgq_dev, &pkt_info, &reps);
	}

	end_us = jiffies_to_usecs(jiffies);
	if (i != 0) {
		LOG_DEBUG("exec_time: %lld us, single_time: %lld us\n", end_us - start_us,
			  (end_us - start_us) / i);
	}

	reg->num = -err;
	if (unlikely(copy_to_user(ifr->ifr_ifru.ifru_data, reg, size)))
		LOG_ERR("copy_to_user failed!\n");

	if (pkt_info.is_async && !pkt_info.no_reps)
		usleep_range(pkt_info.timeout_us, pkt_info.timeout_us + 100);

	vfree(reps.addr);
err_ret:
	kfree(reg);
	return err;
}

s32 zxdh_msgq_dev_config(struct net_device *netdev, struct ifreq *ifr)
{
	u32 reg_size = sizeof(struct zxdh_en_reg);
	struct zxdh_en_device *en_dev = NULL;
	struct msgq_dev *msgq_dev = NULL;
	struct zxdh_en_reg *reg = NULL;

	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");
	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");
	en_dev = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_dev, NULL, -EADDRNOTAVAIL, "en_dev is null!\n");
	msgq_dev = (struct msgq_dev *)en_dev->msgq_dev;
	CHECK_EQUAL_ERR(msgq_dev, NULL, -EADDRNOTAVAIL, "msgq_dev is null!\n");

	reg = kzalloc(reg_size, GFP_KERNEL);
	CHECK_EQUAL_ERR(reg, NULL, -EADDRNOTAVAIL, "reg is null!\n");

	if (unlikely(copy_from_user(reg, ifr->ifr_ifru.ifru_data, reg_size))) {
		LOG_ERR("copy_from_user failed!\n");
		goto err_ret;
	}

	if (reg->data[1] == MSGQ_PRINT_STA) {
		LOG_DEBUG("msgq_rx_pkts: %lld\n", msgq_dev->rq_priv->stats.packets);
		LOG_DEBUG("msgq_rx_kicks: %lld\n", msgq_dev->rq_priv->stats.kicks);
		LOG_DEBUG("msgq_rx_bytes: %lld\n", msgq_dev->rq_priv->stats.bytes);
		LOG_DEBUG("msgq_rx_drops: %lld\n", msgq_dev->rq_priv->stats.drops);
		LOG_DEBUG("msgq_rx_errs: %lld\n", msgq_dev->rq_priv->stats.xdp_drops);

		LOG_DEBUG("msgq_tx_pkts: %lld\n", msgq_dev->sq_priv->stats.packets);
		LOG_DEBUG("msgq_tx_bytes: %lld\n", msgq_dev->sq_priv->stats.bytes);
		LOG_DEBUG("msgq_tx_kicks: %lld\n", msgq_dev->sq_priv->stats.kicks);
		LOG_DEBUG("msgq_tx_timeouts: %lld\n", msgq_dev->sq_priv->stats.tx_timeouts);
		LOG_DEBUG("msgq_tx_errs: %lld\n", msgq_dev->sq_priv->stats.xdp_tx_drops);

		kfree(reg);
		return 0;
	}

	msgq_dev->loopback = (reg->data[0] != 0 ? true : false);
	msgq_dev->print_flag = reg->data[1];
	LOG_INFO("msgq_dev->print_flag = %d\n", msgq_dev->print_flag);
	LOG_INFO("msgq_dev->loopback = %d\n", msgq_dev->loopback);

	if (unlikely(copy_to_user(ifr->ifr_ifru.ifru_data, reg, reg_size))) {
		LOG_ERR("copy_to_user failed!\n");
		goto err_ret;
	}

	kfree(reg);
	return 0;

err_ret:
	kfree(reg);
	return -1;
}
#endif

struct zxdh_en_ioctl_table ioctl_table[] = {
	{ SIOCGMIIREG, zxdh_read_reg_cmd },
	{ SIOCSMIIREG, zxdh_write_reg_cmd },
	{ SIOCDEVPRIVATE_VQ_INFO, zxdh_get_vring_info },
	{ SIOCDEVPRIVATE_SEND_FILE_PKT, zxdh_send_file_pkt },
#ifdef ZXDH_MSGQ
	{ SIOCDEVPRIVATE_MSGQ_SNED, zxdh_msgq_msg_send },
	{ SIOCDEVPRIVATE_MSGQ_CONFIG, zxdh_msgq_dev_config },
#endif
	{ SIOCDEVPRIVATE_PTP_FUNC, zxdh_en_ptp_func },
	{ SIOCDEVPRIVATE_PPS_FUNC, zxdh_en_pps_func },
#ifdef CONFIG_DINGHAI_TSN
	{ SIOCDEVPRIVATE_TSN_FUNC, zxdh_en_tsn_func },
#endif
	{ SIOCDEVPRIVATE_DH_TOOLS, zxdh_tools_ioctl_dispatcher },
};

s32 ioctl_table_match_func(struct net_device *netdev, struct ifreq *ifr, s32 cmd,
			   struct zxdh_en_ioctl_table *func_table, u32 table_size)
{
	s32 ret = 0;
	u32 i = 0;

	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");
	for (i = 0; i < table_size; i++) {
		if ((func_table[i].cmd == cmd) && (func_table[i].func)) {
			ret = func_table[i].func(netdev, ifr);
			break;
		}
	}

	return ret;
}

s32 zxdh_en_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd)
{
	u32 table_size = sizeof(ioctl_table) / sizeof(struct zxdh_en_ioctl_table);
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	return ioctl_table_match_func(netdev, ifr, cmd, ioctl_table, table_size);
}

s32 zxdh_en_private_ioctl(struct net_device *netdev, struct ifreq *ifr, void *data, int cmd)
{
	u32 table_size = sizeof(ioctl_table) / sizeof(struct zxdh_en_ioctl_table);
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	return ioctl_table_match_func(netdev, ifr, cmd, ioctl_table, table_size);
}

/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __EN_SF_EQ_H__
#define __EN_SF_EQ_H__
#include <linux/dinghai/driver.h>
#include <linux/notifier.h>
#include <linux/types.h>
#include <linux/dinghai/pci_irq.h>
#include <linux/dinghai/eq.h>
#include <linux/dinghai/en_sf.h>

void dh_en_sf_eq_table_destroy(struct dh_core_dev *dev);
s32 dh_en_sf_eq_table_init(struct dh_core_dev *dev);
s32 dh_en_sf_eq_table_create(struct dh_core_dev *dev, struct zxdh_en_sf_if *ops);
void dh_sf_eq_table_destroy(struct dh_core_dev *dev);

u16 zxdh_en_sf_get_vqs_channels_num(struct dh_core_dev *dh_dev);
s32 zxdh_en_sf_create_vqs_channels(struct dh_core_dev *dh_dev, void *data);
void zxdh_en_sf_destroy_vqs_channels(struct dh_core_dev *dh_dev);
void zxdh_en_sf_switch_vqs_channel(struct dh_core_dev *dh_dev, s32 channel, s32 op);
s32 zxdh_en_sf_vqs_channel_bind_handler(struct dh_core_dev *dh_dev, s32 vqs_channel_num,
					struct dh_vq_handler *handler);
void zxdh_en_sf_vqs_channel_unbind_handler(struct dh_core_dev *dh_dev, s32 vqs_channel_num);
s32 zxdh_en_sf_vq_bind_channel(struct dh_core_dev *dh_dev, s32 channel_num, s32 queue_index,
			       u16 vq_idx);
void zxdh_en_sf_vq_unbind_channel(struct dh_core_dev *dh_dev, s32 queue_index);
s32 zxdh_en_sf_vqs_bind_eqs(struct dh_core_dev *dh_dev, s32 vqs_channel_num,
			    struct list_head *vq_node);
void zxdh_en_sf_vqs_unbind_eqs(struct dh_core_dev *dh_dev, s32 vqs_channel_num);
void __iomem *zxdh_en_sf_map_vq_notify(struct dh_core_dev *dh_dev, u32 index, resource_size_t *pa);
void zxdh_en_sf_unmap_vq_notify(struct dh_core_dev *dh_dev, void *priv);
void zxdh_en_sf_activate_phy_vq(struct dh_core_dev *dh_dev, u32 phy_index, s32 queue_size,
				u64 desc_addr, u64 avail_addr, u64 used_addr);
void zxdh_en_sf_set_queue_enable(struct dh_core_dev *dh_dev, u16 index, bool enable);
u16 zxdh_en_sf_get_epbdf(struct dh_core_dev *dh_dev);
u64 zxdh_en_sf_get_spec_sbdf(struct dh_core_dev *dh_dev);
u16 zxdh_en_sf_get_vport(struct dh_core_dev *dh_dev);
u16 zxdh_en_sf_get_pcie_id(struct dh_core_dev *dh_dev);
u16 zxdh_en_sf_get_slot_id(struct dh_core_dev *dh_dev);
enum dh_coredev_type zxdh_en_sf_get_coredev_type(struct dh_core_dev *dh_dev);
void zxdh_en_sf_dpp_np_init(struct dh_core_dev *dh_dev, u32 vport);
struct pci_dev *zxdh_en_sf_get_pdev(struct dh_core_dev *dh_dev);
u64 zxdh_en_sf_get_bar_virt_addr(struct dh_core_dev *dh_dev, u8 bar_num);
s32 zxdh_en_sf_do_cmd_exec(struct dh_core_dev *dh_dev, u32 dst, u32 id, u32 len, void *payload,
			   void *ack);
struct zxdh_vf_item *zxdh_en_sf_get_vf_item(struct dh_core_dev *dh_dev, u16 vf_idx);

struct dh_en_sf_eq_table {
	struct dh_irq **vq_irqs;
	struct dh_irq *async_irq;
	struct dh_eq_async async_eq;
	s32 vq_irq_num;
	struct list_head vqs_eqs_list;
};

#endif

/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __EN_PF_EQ_H__
#define __EN_PF_EQ_H__
#include <linux/dinghai/driver.h>
#include <linux/notifier.h>
#include <linux/types.h>
#include <linux/dinghai/pci_irq.h>
#include <linux/dinghai/eq.h>

#define ZXDH_PF_INVALID_MSIX_VEC 0xffff
#define ZXDH_MAC_FLAG_BAR_OFFSET 0xFB030
#define ZXDH_EP_FLAG_SIZE 2048
#define ZXDH_PF_FLAG_SIZE 256
#define ZXDH_VF_NUM 256

s32 dh_pf_eq_table_create(struct dh_core_dev *dev);
void dh_pf_eq_table_destroy(struct dh_core_dev *dev);
s32 dh_pf_eq_table_init(struct dh_core_dev *dev);
u16 zxdh_pf_get_vqs_channels_num(struct dh_core_dev *dh_dev);

void zxdh_pf_switch_irq(struct dh_core_dev *dh_dev, s32 i, s32 op);
s32 zxdh_pf_vq_irqs_request(struct dh_core_dev *dh_dev, struct dh_irq **vq_irqs, s32 vq_channels,
			    void *data);
void zxdh_pf_affinity_irqs_release(struct dh_core_dev *dh_dev, struct dh_irq **vq_irqs,
				   s32 num_irqs);
void zxdh_enable_irq(struct dh_core_dev *dh_dev, s32 irq_index);

s32 zxdh_pf_async_eq_enable(struct dh_core_dev *dev, struct dh_eq_async *eq, const char *name,
			    bool attach);
void zxdh_pf_set_pf_link_up(struct dh_core_dev *dh_dev, bool link_up);
bool zxdh_pf_get_pf_link_up(struct dh_core_dev *dh_dev);
void zxdh_pf_set_vf_link_info(struct dh_core_dev *dh_dev, u16 vf_idx, u8 link_up);
bool zxdh_pf_get_vf_is_probe(struct dh_core_dev *dh_dev, u16 vf_idx);
void zxdh_pf_get_link_info_from_vqm(struct dh_core_dev *dh_dev, u8 *link_up);
void zxdh_pf_set_pf_phy_port(struct dh_core_dev *dh_dev, u8 phy_port);
u8 zxdh_pf_get_pf_phy_port(struct dh_core_dev *dh_dev);
s32 zxdh_pf_call_aux_events(struct dh_core_dev *dev, s32 event_type);
s32 zxdh_pf_call_aux_events_with_data(struct dh_core_dev *dev, s32 event_type, void *data);

struct dh_pf_eq_table {
	struct dh_irq **vq_irqs;
	s32 vq_irq_num;
	struct list_head vqs_eqs_list;
	struct dh_irq *async_irq_tbl[ZXDH_ASYNC_CHANNELS_NUM];
	struct dh_eq_async async_eq_tbl[ZXDH_ASYNC_CHANNELS_NUM];
};

struct dh_pf_async_irq_table {
	char name[64];
	notifier_fn_t async_int;
};

#endif

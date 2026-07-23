// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/dinghai/eq.h>
#include <linux/dinghai/driver.h>
#include <linux/dinghai/helper.h>
#include <linux/list.h>
#include <linux/dinghai/en_sf.h>
#include <linux/dinghai/queue.h>
#include "en_sf_irq.h"
#include "en_sf_eq.h"
#include "../en_sf.h"

static s32 create_async_eqs(struct dh_core_dev *dev)
{
	return 0;
}

s32 dh_en_sf_eq_table_create(struct dh_core_dev *dev, struct zxdh_en_sf_if *ops)
{
	s32 err;

	err = create_async_eqs(dev);

	return err;
}

void dh_sf_eq_table_destroy(struct dh_core_dev *dev)
{
}

void zxdh_set_queue_size(struct dh_core_dev *dh_dev, u32 index, u16 size)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	en_sf_dev->sf_ops->en_sf_set_queue_size(dh_dev->parent, index, size);
}

void zxdh_queue_address(struct dh_core_dev *dh_dev, u32 index, u64 desc_addr, u64 driver_addr,
			u64 device_addr)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	en_sf_dev->sf_ops->en_sf_set_queue_address(dh_dev->parent, index, desc_addr, driver_addr,
						   device_addr);
}

void zxdh_en_sf_activate_phy_vq(struct dh_core_dev *dh_dev, u32 phy_index, s32 queue_size,
				u64 desc_addr, u64 avail_addr, u64 used_addr)
{
	zxdh_set_queue_size(dh_dev, phy_index, queue_size);
	zxdh_queue_address(dh_dev, phy_index, desc_addr, avail_addr, used_addr);
}

s32 dh_en_sf_eq_table_init(struct dh_core_dev *dev)
{
	struct dh_eq_table *eq_table = &dev->eq_table;
	struct dh_en_sf_eq_table *table_priv = NULL;
	s32 err = 0;

	table_priv = kvzalloc(sizeof(*table_priv), GFP_KERNEL);
	if (unlikely(!table_priv)) {
		LOG_ERR("dh_en_sf_eq_table kvzalloc failed\n");
		err = -ENOMEM;
		goto err_table_priv;
	}
	dh_eq_table_init(dev, table_priv);

	return 0;

err_table_priv:
	kvfree(eq_table);
	return err;
}

static void vqs_irqs_release(struct dh_core_dev *dh_dev)
{
	struct dh_eq_table *table = &dh_dev->eq_table;
	struct dh_en_sf_eq_table *sf_eq_table = table->priv;
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);
	s32 vqs_channel_num = 0;

	vqs_channel_num = zxdh_en_sf_get_vqs_channels_num(dh_dev);

	en_sf_dev->sf_ops->en_sf_affinity_irqs_release(dh_dev->parent, sf_eq_table->vq_irqs,
						       vqs_channel_num);

	dh_irqs_release_vectors(sf_eq_table->vq_irqs, sf_eq_table->vq_irq_num);
}

static void clean_vqs_eqs(struct dh_core_dev *dh_dev)
{
	struct dh_eq_table *table = &dh_dev->eq_table;
	struct dh_en_sf_eq_table *sf_eq_table = table->priv;
	struct dh_eq_vqs *eq;
	struct dh_eq_vqs *n;

	list_for_each_entry_safe(eq, n, &sf_eq_table->vqs_eqs_list, list) {
		list_del(&eq->list);
		kfree(eq);
	}
}

static void destroy_vqs_eqs(struct dh_core_dev *dh_dev, s32 vqs_channel_num)
{
	struct dh_eq_table *table = &dh_dev->eq_table;
	struct dh_en_sf_eq_table *sf_eq_table = table->priv;
	struct dh_eq_vqs *eq;
	struct dh_eq_vqs *n;
	s32 i = 0;

	list_for_each_entry_safe(eq, n, &sf_eq_table->vqs_eqs_list, list) {
		if (i <= vqs_channel_num)
			dh_eq_disable(dh_dev, &eq->vq_s.core, &eq->vq_s.irq_nb);
		i++;
	}
}

u16 zxdh_en_sf_get_vqs_channels_num(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);
	u16 channels_num = 0;

	channels_num = en_sf_dev->sf_ops->en_sf_get_channels_num(dh_dev->parent);

	return channels_num;
}

static s32 create_map_eq(struct dh_core_dev *dev, struct dh_eq *eq, struct dh_eq_param *param)
{
	eq->irq = param->irq;

	return 0;
}

void zxdh_en_sf_destroy_vqs_channels(struct dh_core_dev *dh_dev)
{
	struct dh_eq_table *table = &dh_dev->eq_table;
	struct dh_en_sf_eq_table *sf_eq_table = table->priv;

	clean_vqs_eqs(dh_dev);
	vqs_irqs_release(dh_dev);
	kfree(sf_eq_table->vq_irqs);
}

void zxdh_en_sf_switch_vqs_channel(struct dh_core_dev *dh_dev, s32 channel, s32 op)
{
	struct dh_eq_table *table = &dh_dev->eq_table;
	struct dh_en_sf_eq_table *sf_eq_table = table->priv;
	struct dh_irq *irq = sf_eq_table->vq_irqs[channel];
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	en_sf_dev->sf_ops->en_sf_switch_irq(dh_dev->parent, irq->irqn, op);
}

s32 zxdh_en_sf_create_vqs_channels(struct dh_core_dev *dh_dev, void *data)
{
	struct dh_eq_table *table = &dh_dev->eq_table;
	struct dh_en_sf_eq_table *sf_eq_table = table->priv;
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);
	s32 vqs_channel_num = 0;
	s32 i = 0;
	struct dh_eq_vqs *eq_vqs = NULL;
	s32 err = 0;

	vqs_channel_num = zxdh_en_sf_get_vqs_channels_num(dh_dev);

	sf_eq_table->vq_irqs = kcalloc(vqs_channel_num, sizeof(*sf_eq_table->vq_irqs), GFP_KERNEL);
	if (unlikely(!sf_eq_table->vq_irqs)) {
		LOG_ERR("sf_eq_table->vq_irqs kcalloc null\n");
		return -ENOMEM;
	}

	vqs_channel_num = en_sf_dev->sf_ops->en_sf_vq_irqs_request(
		dh_dev->parent, sf_eq_table->vq_irqs, vqs_channel_num, data);
	if (vqs_channel_num < 0) {
		LOG_ERR("en_sf_vq_irqs_request failed: %d\n", vqs_channel_num);
		kfree(sf_eq_table->vq_irqs);
		return vqs_channel_num;
	}

	sf_eq_table->vq_irq_num = vqs_channel_num;

	INIT_LIST_HEAD(&sf_eq_table->vqs_eqs_list);

	for (i = 0; i < vqs_channel_num; i++) {
		eq_vqs = kzalloc(sizeof(struct dh_eq_vqs), GFP_KERNEL);
		if (unlikely(!eq_vqs)) {
			LOG_ERR("eq_vqs %d kzalloc null\n", i);
			err = -ENOMEM;
			goto clean;
		}

		INIT_LIST_HEAD(&eq_vqs->vqs);

		list_add_tail(&eq_vqs->list, &sf_eq_table->vqs_eqs_list);
	}

	return vqs_channel_num;

clean:
	zxdh_en_sf_destroy_vqs_channels(dh_dev);
	return err;
}

void zxdh_en_sf_vqs_unbind_eqs(struct dh_core_dev *dh_dev, s32 vqs_channel_num)
{
	struct dh_eq_table *table = &dh_dev->eq_table;
	struct dh_en_sf_eq_table *sf_eq_table = table->priv;
	struct dh_eq_vqs *eq;
	struct dh_eq_vqs *n;
	s32 i = 0;

	list_for_each_entry_safe(eq, n, &sf_eq_table->vqs_eqs_list, list) {
		if (i++ <= vqs_channel_num)
			list_del(&eq->vqs);
	}
}

s32 zxdh_en_sf_vqs_bind_eqs(struct dh_core_dev *dh_dev, s32 vqs_channel_num,
			    struct list_head *vq_node)
{
	struct dh_eq_table *table = &dh_dev->eq_table;
	struct dh_en_sf_eq_table *sf_eq_table = table->priv;
	struct dh_eq_vqs *eq;
	struct dh_eq_vqs *n;
	s32 i = 0;

	list_for_each_entry_safe(eq, n, &sf_eq_table->vqs_eqs_list, list) {
		if (i++ == vqs_channel_num) {
			list_add_tail(vq_node, &eq->vqs);
			return 0;
		}
	}

	return -ENOENT;
}

void __iomem *zxdh_en_sf_map_vq_notify(struct dh_core_dev *dh_dev, u32 index, resource_size_t *pa)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);
	void __iomem *notify_addr = NULL;

	notify_addr = en_sf_dev->sf_ops->en_sf_map_vq_notify(dh_dev->parent, index, pa);

	return notify_addr;
}

void zxdh_en_sf_unmap_vq_notify(struct dh_core_dev *dh_dev, void *priv)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	en_sf_dev->sf_ops->en_sf_unmap_vq_notify(dh_dev->parent, priv);
}

void zxdh_en_sf_set_queue_enable(struct dh_core_dev *dh_dev, u16 index, bool enable)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	en_sf_dev->sf_ops->en_sf_set_queue_enable(dh_dev->parent, index, enable);
}

u16 zxdh_en_sf_get_queue_vector(struct dh_core_dev *dh_dev, u16 channel, u16 queue_index,
				u16 vq_idx)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);
	struct dh_eq_table *table = &dh_dev->eq_table;
	struct dh_en_sf_eq_table *sf_eq_table = table->priv;
	s32 msix_vec = ZXDH_MSI_NO_VECTOR;

	msix_vec = en_sf_dev->sf_ops->en_sf_get_queue_vector(
		dh_dev->parent, channel, &sf_eq_table->vqs_eqs_list, queue_index, vq_idx);

	return msix_vec;
}

void zxdh_en_sf_vq_unbind_channel(struct dh_core_dev *dh_dev, s32 queue_index)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	en_sf_dev->sf_ops->en_sf_release_queue_vector(dh_dev->parent, queue_index);
}

s32 zxdh_en_sf_vq_bind_channel(struct dh_core_dev *dh_dev, s32 channel_num, s32 queue_index,
			       u16 vq_idx)
{
	s32 msix_vec = ZXDH_MSI_NO_VECTOR;

	msix_vec = zxdh_en_sf_get_queue_vector(dh_dev, channel_num, queue_index, vq_idx);

	if (msix_vec == ZXDH_MSI_NO_VECTOR)
		return -EBUSY;

	return msix_vec;
}

void zxdh_en_sf_vqs_channel_unbind_handler(struct dh_core_dev *dh_dev, s32 vqs_channel_num)
{
	destroy_vqs_eqs(dh_dev, vqs_channel_num);
}

s32 zxdh_en_sf_vqs_channel_bind_handler(struct dh_core_dev *dh_dev, s32 vqs_channel_num,
					struct dh_vq_handler *handler)
{
	struct dh_eq_table *table = &dh_dev->eq_table;
	struct dh_en_sf_eq_table *sf_eq_table = table->priv;
	s32 i = 0;
	struct dh_eq_vqs *eq_vqs;
	struct dh_eq_vqs *n;
	s32 err = 0;

	list_for_each_entry_safe(eq_vqs, n, &sf_eq_table->vqs_eqs_list, list) {
		if (i == vqs_channel_num) {
			struct dh_eq_param param = {};

			eq_vqs->vq_s.irq_nb.notifier_call = handler->callback;
			eq_vqs->vq_s.para = handler->para;
			param = (struct dh_eq_param){
				.irq = sf_eq_table->vq_irqs[i],
				.nent = 0,
			};
			create_map_eq(dh_dev, &eq_vqs->vq_s.core, &param);

			err = dh_eq_enable(dh_dev, &eq_vqs->vq_s.core, &eq_vqs->vq_s.irq_nb);
			if (err != 0) {
				LOG_ERR("dh_eq_enable failed: %d\n", err);
				goto clean_eq;
			}
			return 0;
		}
		i++;
	}

clean_eq:
	destroy_vqs_eqs(dh_dev, vqs_channel_num);
	return err;
}

u16 zxdh_en_sf_get_epbdf(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_epbdf(dh_dev->parent);
}

u64 zxdh_en_sf_get_spec_sbdf(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_spec_sbdf(dh_dev->parent);
}

u16 zxdh_en_sf_get_vport(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_vport(dh_dev->parent);
}

enum dh_coredev_type zxdh_en_sf_get_coredev_type(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_coredev_type(dh_dev->parent);
}

u16 zxdh_en_sf_get_pcie_id(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_pcie_id(dh_dev->parent);
}

u16 zxdh_en_sf_get_slot_id(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_slot_id(dh_dev->parent);
}

struct zxdh_vf_item *zxdh_en_sf_get_vf_item(struct dh_core_dev *dh_dev, u16 vf_idx)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_vf_item(dh_dev->parent, vf_idx);
}

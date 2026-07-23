// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/dinghai/driver.h>
#include <linux/dinghai/zxdh_auxiliary_bus.h>
#ifdef HAVE_DEV_PRINTK_OPS
#include <linux/dev_printk.h>
#endif
#include <linux/dinghai/devlink.h>
#include <linux/dinghai/helper.h>
#include <linux/dinghai/en_aux.h>
#include <linux/dinghai/dh_cmd.h>
#include "en_aux.h"
#include "en_sf.h"
#include "./en_sf/en_sf_eq.h"
#ifdef CONFIG_DINGHAI_EN_AUX
#include <linux/dinghai/en_aux.h>
#endif

s32 zxdh_en_sf_get_vq_lock(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_vq_lock(dh_dev->parent);
}

s32 zxdh_en_sf_release_vq_lock(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_release_vq_lock(dh_dev->parent);
}

s32 zxdh_en_sf_find_valid_vqs(struct dh_core_dev *dh_dev, u16 vqs_cnt, u32 vq_index[])
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_find_valid_vqs(dh_dev->parent, vqs_cnt, vq_index);
}

s32 zxdh_en_sf_write_vqs_bit(struct dh_core_dev *dh_dev, u16 vqs_cnt, u32 vq_index[])
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_write_vqs_bit(dh_dev->parent, vqs_cnt, vq_index);
}

s32 zxdh_en_sf_write_queue_tlb(struct dh_core_dev *dh_dev, u16 vqs_cnt, u32 vq_index[],
			       bool need_msgq)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_write_queue_tlb(dh_dev->parent, vqs_cnt, vq_index,
							need_msgq);
}

u16 zxdh_en_sf_get_fw_patch(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_fw_patch(dh_dev->parent);
}

bool zxdh_en_sf_is_bond(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_is_bond(dh_dev->parent);
}

bool zxdh_en_sf_is_upf(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_is_upf(dh_dev->parent);
}

void zxdh_en_sf_set_status(struct dh_core_dev *dh_dev, u8 status)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	en_sf_dev->sf_ops->en_sf_set_status(dh_dev->parent, status);
}

u8 zxdh_en_sf_get_status(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);
	u8 status = 0;

	status = en_sf_dev->sf_ops->en_sf_get_status(dh_dev->parent);

	return status;
}

u8 zxdh_en_sf_get_cfg_gen(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_cfg_gen(dh_dev->parent);
}

bool zxdh_en_sf_get_rp_link_status(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_rp_link_status(dh_dev->parent);
}

void zxdh_en_sf_set_vf_mac(struct dh_core_dev *dh_dev, u8 *mac, s32 vf_id)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	en_sf_dev->sf_ops->en_sf_set_vf_mac(dh_dev->parent, mac, vf_id);
}

void zxdh_en_sf_get_vf_mac(struct dh_core_dev *dh_dev, u8 *mac, s32 vf_id)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	en_sf_dev->sf_ops->en_sf_get_vf_mac(dh_dev->parent, mac, vf_id);
}

void zxdh_en_sf_set_mac(struct dh_core_dev *dh_dev, u8 *mac)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	en_sf_dev->sf_ops->en_sf_set_mac(dh_dev->parent, mac);
}

void zxdh_en_sf_get_mac(struct dh_core_dev *dh_dev, u8 *mac)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	en_sf_dev->sf_ops->en_sf_get_mac(dh_dev->parent, mac);
}

u64 zxdh_en_sf_get_features(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);
	u64 device_feature = 0;

	device_feature = en_sf_dev->sf_ops->en_sf_get_features(dh_dev->parent);

	return device_feature;
}

void zxdh_en_sf_set_features(struct dh_core_dev *dh_dev, u64 features)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	en_sf_dev->sf_ops->en_sf_set_features(dh_dev->parent, features);
}

u16 zxdh_en_sf_get_queue_num(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);
	u16 qnum = 0;

	qnum = en_sf_dev->sf_ops->en_sf_get_queue_num(dh_dev->parent);

	return qnum;
}

u16 zxdh_en_sf_get_queue_size(struct dh_core_dev *dh_dev, u32 index)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);
	u16 queue_size = 0;

	queue_size = en_sf_dev->sf_ops->en_sf_get_queue_size(dh_dev->parent, index);

	return queue_size;
}

void zxdh_en_sf_set_queue_size(struct dh_core_dev *dh_dev, u32 index, u16 size)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	en_sf_dev->sf_ops->en_sf_set_queue_size(dh_dev->parent, index, size);
}

struct pci_dev *zxdh_en_sf_get_pdev(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_pdev(dh_dev->parent);
}

u64 zxdh_en_sf_get_bar_virt_addr(struct dh_core_dev *dh_dev, u8 bar_num)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_bar_virt_addr(dh_dev->parent, bar_num);
}

u64 zxdh_en_sf_get_bar_phy_addr(struct dh_core_dev *dh_dev, u8 bar_num)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_bar_phy_addr(dh_dev->parent, bar_num);
}

u64 zxdh_en_sf_get_bar_size(struct dh_core_dev *dh_dev, u8 bar_num)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_bar_size(dh_dev->parent, bar_num);
}

s32 zxdh_en_sf_msg_send_cmd(struct dh_core_dev *dh_dev, u16 module_id, void *msg, void *ack,
			    struct zxdh_bar_extra_para *para)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_msg_send_cmd(dh_dev->parent, module_id, msg, ack, para);
}

s32 zxdh_en_sf_async_eq_enable(struct dh_core_dev *dh_dev, struct dh_eq_async *eq, const char *name,
			       bool attach)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_async_eq_enable(dh_dev->parent, eq, name, attach);
}

void zxdh_en_sf_nh_attach(struct dh_core_dev *dh_dev, struct dh_nb *nb, bool attach)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	en_sf_dev->sf_ops->en_sf_nh_attach(dh_dev->parent, nb, attach);
}

void zxdh_en_sf_set_pf_link_up(struct dh_core_dev *dh_dev, bool link_up)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	en_sf_dev->sf_ops->en_sf_set_pf_link_up(dh_dev->parent, link_up);
}

bool zxdh_en_sf_get_pf_link_up(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_pf_link_up(dh_dev->parent);
}

void zxdh_en_sf_update_pf_link_info(struct dh_core_dev *dh_dev,
				    struct link_info_struct *link_info_val)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	en_sf_dev->sf_ops->en_sf_update_pf_link_info(dh_dev->parent, link_info_val);
}

s32 zxdh_en_sf_get_pf_drv_msg(struct dh_core_dev *dh_dev, u8 *drv_version, u8 *drv_version_len)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_drv_msg(dh_dev, drv_version, drv_version_len);
}

void zxdh_en_sf_set_vepa(struct dh_core_dev *dh_dev, bool setting)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	en_sf_dev->sf_ops->en_sf_set_vepa(dh_dev->parent, setting);
}

bool zxdh_en_sf_get_vepa(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_vepa(dh_dev->parent);
}

void zxdh_en_sf_get_link_info_from_vqm(struct dh_core_dev *dh_dev, u8 *link_up)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	en_sf_dev->sf_ops->en_sf_get_link_info_from_vqm(dh_dev->parent, link_up);
}

void zxdh_en_sf_set_vf_link_info(struct dh_core_dev *dh_dev, u16 vf_idx, u8 link_up)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	en_sf_dev->sf_ops->en_sf_set_vf_link_info(dh_dev->parent, vf_idx, link_up);
}

bool zxdh_en_sf_get_vf_is_probe(struct dh_core_dev *dh_dev, u16 vf_idx)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_vf_is_probe(dh_dev->parent, vf_idx);
}

void zxdh_en_sf_set_pf_phy_port(struct dh_core_dev *dh_dev, u8 phy_port)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	en_sf_dev->sf_ops->en_sf_set_pf_phy_port(dh_dev->parent, phy_port);
}

u8 zxdh_en_sf_get_pf_phy_port(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_pf_phy_port(dh_dev->parent);
}

void zxdh_en_sf_set_rdma_netdev(struct dh_core_dev *dh_dev, void *data)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	en_sf_dev->netdev = data;
}

void *zxdh_en_sf_get_rdma_netdev(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->netdev;
}

struct zxdh_rdma_if rdma_ops = {
	.get_rdma_netdev = zxdh_en_sf_get_rdma_netdev,
};

void zxdh_en_sf_set_sec_info(struct dh_core_dev *dh_dev, void *data)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	en_sf_dev->sec_info = data;
}

void *zxdh_en_sf_get_sec_info(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sec_info;
}

struct zxdh_sec_if sec_ops = {
	.get_sec_info = zxdh_en_sf_get_sec_info,
};

bool zxdh_en_sf_is_drs_sec_enable(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_is_drs_sec_enable(dh_dev->parent);
}

bool zxdh_en_sf_is_fw_feature_support(struct dh_core_dev *dh_dev, u32 feature)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_is_fw_feature_support(dh_dev->parent, feature);
}

u16 zxdh_en_sf_get_ovs_pf_vfid(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_ovs_pf_vfid(dh_dev->parent);
}

bool zxdh_en_sf_is_hwbond(struct dh_core_dev *dh_dev, bool is_hwbond, bool update_pf)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_is_hwbond(dh_dev->parent, is_hwbond, update_pf);
}

bool zxdh_en_sf_is_rdma_aux_plug(struct dh_core_dev *dh_dev, bool is_rdma_aux_plug, bool update_pf)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_is_rdma_aux_plug(dh_dev->parent, is_rdma_aux_plug,
							 update_pf);
}

bool zxdh_en_sf_is_primary_port(struct dh_core_dev *dh_dev, bool is_primary_port, bool update_pf)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_is_primary_port(dh_dev->parent, is_primary_port, update_pf);
}

void zxdh_en_sf_optim_hardware_bond_time(struct dh_core_dev *dh_dev, bool enable)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_optim_hardware_bond_time(dh_dev->parent, enable);
}

s32 zxdh_en_sf_update_hb_file_val(struct dh_core_dev *dh_dev, u64 spec_sbdf,
				  const char *file_name, bool flag)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_update_hb_file_val(dh_dev->parent, spec_sbdf, file_name,
							   flag);
}

bool zxdh_en_sf_is_rdma_enable(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_is_rdma_enable(dh_dev->parent);
}

static s32 zxdh_en_sf_request_port(struct dh_core_dev *dh_dev, void *data)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_request_port_info(dh_dev->parent, data);
}

static s32 zxdh_en_sf_release_port(struct dh_core_dev *dh_dev, u32 pnl_id)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_release_port_info(dh_dev->parent, pnl_id);
}

static void zxdh_en_sf_set_bond_num(struct dh_core_dev *dh_dev, bool add)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_set_bond_num(dh_dev->parent, add);
}

static bool zxdh_en_sf_if_init(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_if_init(dh_dev->parent);
}

void zxdh_en_sf_set_init_comp_flag(struct dh_core_dev *dh_dev, u8 flag)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	en_sf_dev->sf_ops->en_sf_set_init_comp_flag(dh_dev->parent, flag);
}

struct zxdh_ipv6_mac_tbl *zxdh_en_sf_get_ip6mac_tbl(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_ip6mac_tbl(dh_dev->parent);
}

static s32 zxdh_en_sf_get_cpl_timeout_if_mask(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_cpl_timeout_if_mask(dh_dev->parent);
}

static s32 zxdh_en_sf_set_cpl_timeout_mask(struct dh_core_dev *dh_dev, u32 mask)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_set_cpl_timeout_mask(dh_dev->parent, mask);
}

static s32 zxdh_en_sf_get_hp_irq_ctrl_status(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_hp_irq_ctrl_status(dh_dev->parent);
}

static s32 zxdh_en_sf_set_hp_irq_ctrl_status(struct dh_core_dev *dh_dev, u32 status)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_set_hp_irq_ctrl_status(dh_dev->parent, status);
}

struct device *zxdh_en_sf_get_dma_dev(struct dh_core_dev *dh_dev)
{
	return dh_dev->parent->device;
}

bool zxdh_en_sf_is_nic(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_is_nic(dh_dev->parent);
}

bool zxdh_en_sf_is_special_bond(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_is_special_bond(dh_dev->parent);
}

bool zxdh_en_sf_suport_np_ext_stats(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_pf_suport_np_ext_stats(dh_dev->parent);
}

struct zxdh_np_ext_stats *zxdh_en_sf_get_np_ext_stats(struct dh_core_dev *dh_dev, u8 panel_id)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_np_ext_stats(dh_dev->parent, panel_id);
}

u8 zxdh_en_sf_get_queue_pairs(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_queue_pairs(dh_dev->parent);
}

static s32 zxdh_aux_events_call_chain(struct dh_core_dev *dh_dev, unsigned long type, void *data)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_events_call_chain(dh_dev->parent, type, data);
}

u32 zxdh_en_sf_get_dev_type(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_dev_type(dh_dev->parent);
}

bool zxdh_en_sf_is_pf_rate_enable(struct dh_core_dev *dh_dev, u32 *pf_fc_val)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev->parent);
	struct firmware_capability *fwcap = &pf_dev->fwcap;

	if (FW_FEATURE_GET(fwcap->fw_feature, FW_FEATURE_PFM) == 1) {
		if (pf_fc_val)
			*pf_fc_val = fwcap->pf_rate_default;
		else
			LOG_ERR("NULL pointer!\n");

		return true;
	}

	return false;
}

u8 zxdh_en_sf_get_board_type(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_get_board_type(dh_dev->parent);
}

bool zxdh_en_sf_is_multi_ep(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = dh_core_priv(dh_dev);

	return en_sf_dev->sf_ops->en_sf_is_multi_ep(dh_dev->parent);
}

struct zxdh_en_if en_ops = {
	.get_channels_num = zxdh_en_sf_get_vqs_channels_num,
	.create_vqs_channels = zxdh_en_sf_create_vqs_channels,
	.destroy_vqs_channels = zxdh_en_sf_destroy_vqs_channels,
	.switch_vqs_channel = zxdh_en_sf_switch_vqs_channel,
	.vqs_channel_bind_handler = zxdh_en_sf_vqs_channel_bind_handler,
	.vqs_channel_unbind_handler = zxdh_en_sf_vqs_channel_unbind_handler,
	.vq_bind_channel = zxdh_en_sf_vq_bind_channel,
	.vq_unbind_channel = zxdh_en_sf_vq_unbind_channel,
	.vqs_bind_eqs = zxdh_en_sf_vqs_bind_eqs,
	.vqs_unbind_eqs = zxdh_en_sf_vqs_unbind_eqs,
	.vp_modern_map_vq_notify = zxdh_en_sf_map_vq_notify,
	.vp_modern_unmap_vq_notify = zxdh_en_sf_unmap_vq_notify,
	.activate_phy_vq = zxdh_en_sf_activate_phy_vq,
	.get_vq_lock = zxdh_en_sf_get_vq_lock,
	.find_valid_vqs = zxdh_en_sf_find_valid_vqs,
	.write_vqs_bit = zxdh_en_sf_write_vqs_bit,
	.write_queue_tlb = zxdh_en_sf_write_queue_tlb,
	.get_fw_patch = zxdh_en_sf_get_fw_patch,
	.release_vq_lock = zxdh_en_sf_release_vq_lock,
	.set_status = zxdh_en_sf_set_status,
	.get_status = zxdh_en_sf_get_status,
	.get_cfg_gen = zxdh_en_sf_get_cfg_gen,
	.get_rp_link_status = zxdh_en_sf_get_rp_link_status,
	.set_vf_mac = zxdh_en_sf_set_vf_mac,
	.get_vf_mac = zxdh_en_sf_get_vf_mac,
	.set_mac = zxdh_en_sf_set_mac,
	.get_mac = zxdh_en_sf_get_mac,
	.get_features = zxdh_en_sf_get_features,
	.set_features = zxdh_en_sf_set_features,
	.get_queue_num = zxdh_en_sf_get_queue_num,
	.get_queue_size = zxdh_en_sf_get_queue_size,
	.set_queue_size = zxdh_en_sf_set_queue_size,
	.set_queue_enable = zxdh_en_sf_set_queue_enable,
	.get_epbdf = zxdh_en_sf_get_epbdf,
	.get_spec_sbdf = zxdh_en_sf_get_spec_sbdf,
	.get_vport = zxdh_en_sf_get_vport,
	.get_pcie_id = zxdh_en_sf_get_pcie_id,
	.get_slot_id = zxdh_en_sf_get_slot_id,
	.is_bond = zxdh_en_sf_is_bond,
	.is_upf = zxdh_en_sf_is_upf,
	.get_coredev_type = zxdh_en_sf_get_coredev_type,
	.get_pdev = zxdh_en_sf_get_pdev,
	.get_bar_virt_addr = zxdh_en_sf_get_bar_virt_addr,
	.get_bar_phy_addr = zxdh_en_sf_get_bar_phy_addr,
	.get_bar_size = zxdh_en_sf_get_bar_size,
	.msg_send_cmd = zxdh_en_sf_msg_send_cmd,
	.async_eq_enable = zxdh_en_sf_async_eq_enable,
	.aux_nh_attach = zxdh_en_sf_nh_attach,
	.get_vf_item = zxdh_en_sf_get_vf_item,
	.set_pf_link_up = zxdh_en_sf_set_pf_link_up,
	.get_pf_link_up = zxdh_en_sf_get_pf_link_up,
	.update_pf_link_info = zxdh_en_sf_update_pf_link_info,
	.get_pf_drv_msg = zxdh_en_sf_get_pf_drv_msg,
	.set_vepa = zxdh_en_sf_set_vepa,
	.get_vepa = zxdh_en_sf_get_vepa,
	.get_link_info_from_vqm = zxdh_en_sf_get_link_info_from_vqm,
	.set_vf_link_info = zxdh_en_sf_set_vf_link_info,
	.get_vf_is_probe = zxdh_en_sf_get_vf_is_probe,
	.request_port = zxdh_en_sf_request_port,
	.release_port = zxdh_en_sf_release_port,
	.set_bond_num = zxdh_en_sf_set_bond_num,
	.if_init = zxdh_en_sf_if_init,
	.set_pf_phy_port = zxdh_en_sf_set_pf_phy_port,
	.set_rdma_netdev = zxdh_en_sf_set_rdma_netdev,
	.get_pf_phy_port = zxdh_en_sf_get_pf_phy_port,
	.set_init_comp_flag = zxdh_en_sf_set_init_comp_flag,
	.get_ip6mac_tbl = zxdh_en_sf_get_ip6mac_tbl,
	.get_dma_dev = zxdh_en_sf_get_dma_dev,
	.unplug_adev = zxdh_aux_unplug_aux_dev_one,
	.plug_adev = zxdh_aux_plug_aux_dev,
	.is_nic = zxdh_en_sf_is_nic,
	.is_special_bond = zxdh_en_sf_is_special_bond,
	.get_qpairs = zxdh_en_sf_get_queue_pairs,
	.events_call_chain = zxdh_aux_events_call_chain,
	.get_cpl_timeout_if_mask = zxdh_en_sf_get_cpl_timeout_if_mask,
	.set_cpl_timeout_mask = zxdh_en_sf_set_cpl_timeout_mask,
	.get_hp_irq_ctrl_status = zxdh_en_sf_get_hp_irq_ctrl_status,
	.set_hp_irq_ctrl_status = zxdh_en_sf_set_hp_irq_ctrl_status,
	.get_dev_type = zxdh_en_sf_get_dev_type,
	.if_suport_np_ext_stats = zxdh_en_sf_suport_np_ext_stats,
	.get_np_ext_stats = zxdh_en_sf_get_np_ext_stats,
	.set_sec_info = zxdh_en_sf_set_sec_info,
	.is_drs_sec_enable = zxdh_en_sf_is_drs_sec_enable,
	.is_fw_feature_support = zxdh_en_sf_is_fw_feature_support,
	.is_pf_rate_enable = zxdh_en_sf_is_pf_rate_enable,
	.get_ovs_pf_vfid = zxdh_en_sf_get_ovs_pf_vfid,
	.get_board_type = zxdh_en_sf_get_board_type,
	.is_hwbond = zxdh_en_sf_is_hwbond,
	.is_rdma_aux_plug = zxdh_en_sf_is_rdma_aux_plug,
	.is_primary_port = zxdh_en_sf_is_primary_port,
	.optim_hardware_bond_time = zxdh_en_sf_optim_hardware_bond_time,
	.update_hb_file_val = zxdh_en_sf_update_hb_file_val,
	.is_rdma_enable = zxdh_en_sf_is_rdma_enable,
	.is_multi_ep = zxdh_en_sf_is_multi_ep,
};

void zxdh_aux_adev_release(struct device *dev)
{
}

s32 zxdh_rdma_infos_request_reset(struct zxdh_rdma_dev_info *rdma_infos,
				  enum zxdh_rdma_reset_type reset_type)
{
	return 0;
}

static struct zxdh_rdma_dev_ops rdma_handle_ops = {
	.request_reset = zxdh_rdma_infos_request_reset,
};

struct zxdh_rdma_dev_info *zxdh_rdma_infos_init(struct dh_core_dev *dh_dev,
						struct zxdh_auxiliary_device *adev)
{
	struct zxdh_en_container *en_container = container_of(adev, struct zxdh_en_container, adev);
	struct zxdh_rdma_dev_info *rdma_infos = NULL;

	en_container->rdma_infos = kzalloc(sizeof(*en_container->rdma_infos), GFP_KERNEL);
	if (unlikely(!en_container->rdma_infos)) {
		LOG_ERR("en_container->rdma_infos kzalloc failed\n");
		return NULL;
	}

	rdma_infos = en_container->rdma_infos;
	rdma_infos->pdev = zxdh_en_sf_get_pdev(dh_dev);
	rdma_infos->hw_addr = (u8 __iomem *)zxdh_en_sf_get_bar_virt_addr(dh_dev, 0);
	rdma_infos->ver.major = ZXDH_MAJOR_VER;
	rdma_infos->ver.minor = ZXDH_MINOR_VER;
	rdma_infos->ver.support = ZXDH_NET_MAJOR_VER + (ZXDH_NET_MINOR_VER << ZXDH_HIGH_8BIT) +
				  (ZXDH_RDMA_MINOR_VER << ZXDH_HIGH_16BIT);
	rdma_infos->rdma_protocol = ZXDH_RDMA_PROTOCOL_IWARP;
	rdma_infos->ops = &rdma_handle_ops;
	rdma_infos->ftype = ZXDH_FUNCTION_TYPE_PF;
	rdma_infos->vport_id = zxdh_en_sf_get_vport(dh_dev);
	rdma_infos->slot_id = zxdh_en_sf_get_slot_id(dh_dev);
	if (zxdh_en_sf_get_coredev_type(dh_dev) == DH_COREDEV_VF)
		rdma_infos->ftype = ZXDH_FUNCTION_TYPE_VF;

	rdma_infos->msix_count = ZXDH_RDMA_CHANNELS_NUM;
	rdma_infos->msix_entries.entry = ZXDH_RDMA_IRQ_START_IDX;
	rdma_infos->msix_entries.vector = pci_irq_vector(rdma_infos->pdev, ZXDH_RDMA_IRQ_START_IDX);
	if (zxdh_en_sf_get_coredev_type(dh_dev) == DH_COREDEV_VF) {
		rdma_infos->msix_entries.entry = ZXDH_VF_RDMA_IRQ_START_IDX;
		rdma_infos->msix_entries.vector =
			pci_irq_vector(rdma_infos->pdev, ZXDH_VF_RDMA_IRQ_START_IDX);
	}

	return rdma_infos;
}

s32 zxdh_net_adev_handle(struct dh_core_dev *dh_dev, struct zxdh_auxiliary_device *adev)
{
	struct zxdh_en_container *en_container = container_of(adev, struct zxdh_en_container, adev);

	adev->name = ZXDH_EN_DEV_ID_NAME;
	adev->dev.parent = dh_dev->device;
	en_container->rdma_infos = NULL;
	en_container->ops = &en_ops;

	return 0;
}

s32 zxdh_rdma_adev_handle(struct dh_core_dev *dh_dev, struct zxdh_auxiliary_device *adev)
{
	struct zxdh_en_container *en_container = container_of(adev, struct zxdh_en_container, adev);
	struct zxdh_rdma_dev_info *rdma_infos = NULL;

	adev->name = ZXDH_RDMA_DEV_NAME;
	rdma_infos = zxdh_rdma_infos_init(dh_dev, adev);
	if (unlikely(!rdma_infos)) {
		LOG_ERR("zxdh_rdma_infos_init failed, return NULL\n");
		return -1;
	}
	rdma_infos->adev = adev;
	adev->dev.parent = &rdma_infos->pdev->dev;
	en_container->rdma_ops = &rdma_ops;

	return 0;
}

s32 zxdh_sec_adev_handle(struct dh_core_dev *dh_dev, struct zxdh_auxiliary_device *adev)
{
	struct zxdh_en_container *en_container = container_of(adev, struct zxdh_en_container, adev);

	adev->name = ZXDH_SEC_DEV_NAME;

	adev->dev.parent = dh_dev->device;
	en_container->sec_ops = &sec_ops;

	return 0;
}

struct zxdh_adev_handle_table zxdh_adev_handle_table[] = {
	{ NET_AUX_DEVICE, zxdh_net_adev_handle },
	{ RDMA_AUX_DEVICE, zxdh_rdma_adev_handle },
	{ SEC_AUX_DEVICE, zxdh_sec_adev_handle },
};

s32 zxdh_adev_handle(struct dh_core_dev *dh_dev, struct zxdh_auxiliary_device *adev,
		     enum AUX_DEVICE_TYPE adev_type)
{
	u32 i = 0;
	s32 ret = 0;

	for (i = 0; i < ARRAY_SIZE(zxdh_adev_handle_table); i++) {
		if ((zxdh_adev_handle_table[i].adev_type == adev_type) &&
		    (zxdh_adev_handle_table[i].cb_fn)) {
			ret = zxdh_adev_handle_table[i].cb_fn(dh_dev, adev);
		}
	}

	return ret;
}

static DEFINE_IDA(zxdh_aux_adev_ida);

s32 zxdh_aux_plug_aux_dev(struct dh_core_dev *dh_dev, enum AUX_DEVICE_TYPE adev_type)
{
	struct zxdh_auxiliary_device *adev = NULL;
	struct zxdh_en_sf_device *en_sf_dev = NULL;
	struct zxdh_en_container *en_container = NULL;
	s32 ret = 0;

	en_sf_dev = dh_core_priv(dh_dev);

	en_container = kzalloc(sizeof(struct zxdh_en_container), GFP_KERNEL);
	if (unlikely(!en_container)) {
		LOG_ERR("sf_con kzalloc is null\n");
		return -ENOMEM;
	}

	en_container->aux_id = ida_alloc(&zxdh_aux_adev_ida, GFP_KERNEL);
	if (en_container->aux_id < 0) {
		LOG_ERR("failed to allocate device id for aux drvs\n");
		goto free_kzalloc;
	}

	adev = &en_container->adev;

	adev->id = en_container->aux_id;
	adev->dev.release = zxdh_aux_adev_release;
	ret = zxdh_adev_handle(dh_dev, adev, adev_type);
	if (ret != 0) {
		LOG_ERR("zxdh_adev_handle failed: %d\n", ret);
		goto free_ida_alloc;
	}

	if (en_sf_dev->aux_idx < 0)
		goto free_rdma_infos_alloc;
	en_sf_dev->adev[en_sf_dev->aux_idx] = adev;
	en_sf_dev->adev[en_sf_dev->aux_idx]->adev_type = adev_type;
	en_sf_dev->aux_idx++;

	en_container->parent = dh_dev;

	ret = zxdh_auxiliary_device_init(adev);
	if (ret != 0) {
		LOG_ERR("zxdh_auxiliary_device_init failed: %d\n", ret);
		goto free_rdma_infos_alloc;
	}

	ret = zxdh_auxiliary_device_add(adev);
	if (ret != 0) {
		LOG_ERR("zxdh_auxiliary_device_add failed: %d\n", ret);
		goto release_aux_init;
	}

	return 0;

release_aux_init:
	zxdh_auxiliary_device_uninit(adev);
free_rdma_infos_alloc:
	if (adev_type == RDMA_AUX_DEVICE) {
		kfree(en_container->rdma_infos);
		en_container->rdma_infos = NULL;
	}
free_ida_alloc:
	ida_free(&zxdh_aux_adev_ida, en_container->aux_id);
	en_container->aux_id = -1;
free_kzalloc:
	kfree(en_container);
	en_container = NULL;
	return ret;
}

void zxdh_aux_unplug_aux_dev(struct dh_core_dev *dh_dev)
{
	struct zxdh_en_sf_device *en_sf_dev = NULL;
	struct zxdh_en_container *en_container = NULL;
	s16 i = 0;

	en_sf_dev = dh_core_priv(dh_dev);
	for (i = en_sf_dev->aux_idx - 1; i >= 0; i--) {
		en_container = container_of(en_sf_dev->adev[i], struct zxdh_en_container, adev);

		zxdh_auxiliary_device_delete(en_sf_dev->adev[i]);
		zxdh_auxiliary_device_uninit(en_sf_dev->adev[i]);
		kfree(en_container->rdma_infos);
		en_container->rdma_infos = NULL;
		ida_free(&zxdh_aux_adev_ida, en_container->aux_id);
		en_container->aux_id = -1;
		kfree(en_container);
		en_container = NULL;
	}
}

void zxdh_aux_unplug_aux_dev_one(struct dh_core_dev *dh_dev, enum AUX_DEVICE_TYPE adev_type)
{
	struct zxdh_en_sf_device *en_sf_dev = NULL;
	struct zxdh_en_container *en_container = NULL;
	s16 i = 0;
	s16 aux_idx = 0;

	en_sf_dev = dh_core_priv(dh_dev);
	aux_idx = en_sf_dev->aux_idx - 1;
	for (i = aux_idx; i >= 0; i--) {
		if (adev_type != en_sf_dev->adev[i]->adev_type)
			continue;

		en_container = container_of(en_sf_dev->adev[i], struct zxdh_en_container, adev);

		zxdh_auxiliary_device_delete(en_sf_dev->adev[i]);
		zxdh_auxiliary_device_uninit(en_sf_dev->adev[i]);
		kfree(en_container->rdma_infos);
		en_container->rdma_infos = NULL;

		ida_free(&zxdh_aux_adev_ida, en_container->aux_id);
		en_container->aux_id = -1;

		kfree(en_container);
		en_container = NULL;

		en_sf_dev->aux_idx--;
	}
}

static s32 zxdh_en_sf_dev_probe(struct zxdh_auxiliary_device *adev,
				const struct zxdh_auxiliary_device_id *id)
{
	s32 err = 0;
	struct zxdh_en_sf_container *sf_con = container_of(adev, struct zxdh_en_sf_container, adev);
	struct dh_core_dev *dh_dev = NULL;
	struct devlink *devlink = NULL;
	struct zxdh_en_sf_device *en_sf_dev = NULL;
	struct zxdh_en_sf_if *sf_ops = sf_con->ops;

	LOG_INFO("sf level start\n");

	devlink = zxdh_devlink_alloc(&adev->dev, &dh_sf_devlink_ops,
				     sizeof(struct zxdh_en_sf_device));
	if (!devlink) {
		LOG_ERR("devlink alloc failed\n");
		return -ENOMEM;
	}

	dh_dev = devlink_priv(devlink);
	en_sf_dev = dh_core_priv(dh_dev);
	dh_dev->parent = sf_con->dh_dev;
	dh_dev->device = &adev->dev;
	dh_dev->irq_table = dh_dev->parent->irq_table;
	en_sf_dev->max_channels = sf_con->max_channels;
	en_sf_dev->sf_ops = sf_ops;
	en_sf_dev->aux_idx = 0;
	sf_con->cdev = dh_dev;
	dh_dev->devlink = devlink;
	dh_dev->devlink_ops = &dh_sf_core_devlink_ops;
	mutex_init(&dh_dev->lock);

	err = dh_en_sf_eq_table_init(dh_dev);
	if (err != 0) {
		LOG_ERR("Failed to alloc IRQs\n");
		goto err_eq_table_init;
	}

	dh_en_sf_eq_table_create(dh_dev, sf_ops);

	zxdh_devlink_register(devlink);

	zxdh_aux_plug_aux_dev(dh_dev, NET_AUX_DEVICE);

	if (sf_ops->en_sf_is_rdma_enable(dh_dev->parent) &&
	    sf_ops->en_sf_is_primary_port(dh_dev->parent, TRUE, FALSE)) {
		zxdh_aux_plug_aux_dev(dh_dev, RDMA_AUX_DEVICE);
		LOG_INFO("sf set rdma done\n");
	}
	if (sf_ops->en_sf_is_drs_sec_enable(dh_dev->parent)) {
		zxdh_aux_plug_aux_dev(dh_dev, SEC_AUX_DEVICE);
		LOG_INFO("sf set sec done\n");
	}

	LOG_INFO("sf level completed\n");

	return 0;

err_eq_table_init:
	mutex_destroy(&dh_dev->lock);
	zxdh_devlink_free(devlink);
	return -EPERM;
}

static s32 zxdh_en_sf_dev_remove(struct zxdh_auxiliary_device *adev)
{
	struct zxdh_en_sf_container *sf_con = container_of(adev, struct zxdh_en_sf_container, adev);
	struct dh_core_dev *dh_dev = NULL;
	struct devlink *devlink = NULL;

	LOG_INFO("sf level start\n");
	dh_dev = sf_con->cdev;
	devlink = dh_dev->devlink;

	zxdh_aux_unplug_aux_dev(dh_dev);
	zxdh_devlink_unregister(devlink);
	dh_sf_eq_table_destroy(dh_dev);
	dh_eq_table_cleanup(dh_dev);
	mutex_destroy(&dh_dev->lock);
	zxdh_devlink_free(devlink);
	LOG_INFO("sf level completed\n");

	return 0;
}

static void zxdh_en_sf_dev_shutdown(struct zxdh_auxiliary_device *adev)
{
	struct zxdh_en_sf_container *sf_con = container_of(adev, struct zxdh_en_sf_container, adev);
	struct dh_core_dev *dh_dev = NULL;
	struct devlink *devlink = NULL;

	LOG_INFO("sf level start\n");
	dh_dev = sf_con->cdev;
	devlink = dh_dev->devlink;

	zxdh_devlink_unregister(devlink);
	dh_sf_eq_table_destroy(dh_dev);
	dh_eq_table_cleanup(dh_dev);
	mutex_destroy(&dh_dev->lock);
	zxdh_devlink_free(devlink);
	LOG_INFO("sf level completed\n");
}

static const struct zxdh_auxiliary_device_id zxdh_en_sf_dev_id_table[] = {
	{
		.name = ZXDH_PF_NAME "." ZXDH_PF_EN_SF_DEV_ID_NAME,
	},
	{},
};

MODULE_DEVICE_TABLE(zxdh_auxiliary, zxdh_en_sf_dev_id_table);

static struct zxdh_auxiliary_driver zxdh_en_sf_driver = {
	.name = ZXDH_PF_EN_SF_DEV_ID_NAME,
	.probe = zxdh_en_sf_dev_probe,
	.remove = zxdh_en_sf_dev_remove,
	.shutdown = zxdh_en_sf_dev_shutdown,
	.id_table = zxdh_en_sf_dev_id_table,
};

s32 zxdh_en_sf_driver_register(void)
{
	s32 err = 0;

	err = zxdh_auxiliary_driver_register(&zxdh_en_sf_driver);
	if (err != 0) {
		LOG_ERR("zxdh_auxiliary_driver_register failed: %d\n", err);
		goto err_auxiliary_driver_register;
	}

#ifdef CONFIG_DINGHAI_EN_AUX
	err = zxdh_en_driver_register();
	if (err != 0) {
		LOG_ERR("zxdh_en_driver_register failed: %d\n", err);
		goto err_en_driver_register;
	}
#endif

	return 0;

#ifdef CONFIG_DINGHAI_EN_AUX
err_en_driver_register:
	zxdh_auxiliary_driver_unregister(&zxdh_en_sf_driver);
#endif
err_auxiliary_driver_register:
	return err;
}

void zxdh_en_sf_driver_unregister(void)
{
#ifdef CONFIG_DINGHAI_EN_AUX
	zxdh_en_driver_unregister();
#endif

	zxdh_auxiliary_driver_unregister(&zxdh_en_sf_driver);
}

// SPDX-License-Identifier: GPL-2.0+
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#define dev_fmt(fmt) "UDMA: " fmt
#define pr_fmt(fmt) "UDMA: " fmt

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/iommu.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/ummu_core.h>
#include <linux/bitmap.h>
#include <linux/xarray.h>
#include <ub/ubase/ubase_comm_dev.h>
#include <ub/ubase/ubase_comm_stats.h>
#include "udma_dev.h"
#include "udma_eq.h"
#include "udma_segment.h"
#include "udma_jfs.h"
#include "udma_jfc.h"
#include "udma_jfr.h"
#include "udma_cmd.h"
#include "udma_ctx.h"
#include "udma_tid.h"
#include "udma_dfx.h"
#include "udma_eid.h"
#include "udma_common.h"
#include "udma_ctrlq_tp.h"
#include "udma_mue.h"
#include "udma_jetty_group.h"

#define UDMA_DRV_VER "1.0"

bool dev_name_style;
bool cqe_mode = true;
uint32_t batch_flush_query_freq = 10;
uint32_t batch_flush_query_timeout = 64000;
bool is_rmmod;
static DEFINE_MUTEX(udma_reset_mutex);
bool sq_reserved;
uint32_t jfr_sleep_time = 1000;
uint32_t jfc_arm_mode;
bool dump_aux_info;
bool hugepage_enable = true;

static const struct auxiliary_device_id udma_id_table[] = {
	{
		.name = UBASE_ADEV_NAME ".udma",
	},
	{},
};
MODULE_DEVICE_TABLE(auxiliary, udma_id_table);

static int udma_set_eth_device_speed(struct ubcore_device *dev,
				    struct ubcore_device_status *dev_status, uint32_t speed)
{
	struct udma_dev *udma_dev = to_udma_dev(dev);

	switch (speed) {
	case SPEED_400G:
		dev_status->port_status[0].active_speed = UBCORE_SP_400G;
		break;
	case SPEED_200G:
		dev_status->port_status[0].active_speed = UBCORE_SP_200G;
		break;
	case SPEED_100G:
		dev_status->port_status[0].active_speed = UBCORE_SP_100G;
		break;
	case SPEED_50G:
		dev_status->port_status[0].active_speed = UBCORE_SP_50G;
		break;
	case SPEED_25G:
		dev_status->port_status[0].active_speed = UBCORE_SP_25G;
		break;
	default:
		dev_err(udma_dev->dev, "invalid port speed(%u) in UBOE mode.\n", speed);
		return -EINVAL;
	}

	return 0;
}

static int udma_query_device_status(struct ubcore_device *dev,
				    struct ubcore_device_status *dev_status)
{
	struct udma_dev *udma_dev = to_udma_dev(dev);
	struct udma_cmd_port_info port_info;
	struct ubase_cmd_buf in, out;
	int ret;

	dev_status->port_status[0].state = UBCORE_PORT_ACTIVE;
	dev_status->port_status[0].active_mtu = UBCORE_MTU_4096;

	udma_fill_buf(&in, UDMA_CMD_QUERY_PORT_INFO, true, 0, NULL);
	udma_fill_buf(&out, UDMA_CMD_QUERY_PORT_INFO, true,
		      sizeof(port_info), (void *)&port_info);
	ret = ubase_cmd_send_inout(udma_dev->comdev.adev, &in, &out);
	if (ret) {
		dev_err(udma_dev->dev, "failed to query speed, ret = %d.\n", ret);
		return -EINVAL;
	}

	dev_status->port_status[0].active_width = (enum ubcore_link_width)port_info.lanes;

	if (!ubase_adev_ubl_supported(udma_dev->comdev.adev))
		return udma_set_eth_device_speed(dev, dev_status, port_info.speed);

	if (port_info.speed == SPEED_200G) {
		dev_status->port_status[0].active_speed = UBCORE_SP_200G;
	} else if (port_info.speed == SPEED_400G) {
		dev_status->port_status[0].active_speed = UBCORE_SP_400G;
	} else {
		dev_err(udma_dev->dev, "invalid port speed = %u.\n", port_info.speed);
		ret = -EINVAL;
	}

	return ret;
}

static void udma_set_dev_caps(struct ubcore_device_attr *attr, struct udma_dev *udma_dev)
{
	attr->dev_cap.max_jfs_depth = udma_dev->caps.jfs.depth;
	attr->dev_cap.max_jfr_depth = udma_dev->caps.jfr.depth;
	attr->dev_cap.max_jfc_depth = udma_dev->caps.jfc.depth;
	attr->dev_cap.max_jfs = udma_dev->caps.jfs.max_cnt +
				udma_dev->caps.public_jetty.max_cnt +
				udma_dev->caps.user_ctrl_normal_jetty.max_cnt;
	attr->dev_cap.max_jfr = udma_dev->caps.jfr.max_cnt;
	attr->dev_cap.max_jfc = udma_dev->caps.jfc.max_cnt;
	attr->dev_cap.max_jetty = udma_dev->caps.jetty.max_cnt +
				  udma_dev->caps.public_jetty.max_cnt +
				  udma_dev->caps.user_ctrl_normal_jetty.max_cnt;
	attr->dev_cap.max_jetty_grp = udma_dev->caps.jetty_grp.max_cnt;
	attr->dev_cap.max_jetty_in_jetty_grp = udma_dev->caps.jetty_in_grp;
	attr->dev_cap.max_jfs_rsge = udma_dev->caps.jfs_rsge;
	attr->dev_cap.max_jfs_sge = udma_dev->caps.jfs_sge;
	attr->dev_cap.max_jfs_inline_size = udma_dev->caps.jfs_inline_sz;
	attr->dev_cap.max_jfr_sge = udma_dev->caps.jfr_sge;
	attr->dev_cap.max_msg_size = udma_dev->caps.max_msg_len;
	attr->dev_cap.trans_mode = udma_dev->caps.trans_mode;
	attr->port_cnt = udma_dev->caps.port_num;
	attr->dev_cap.ceq_cnt = udma_dev->caps.comp_vector_cnt;
	attr->dev_cap.max_ue_cnt = udma_dev->caps.ue_cnt;
	attr->dev_cap.max_rc = udma_dev->caps.rc_max_cnt;
	attr->dev_cap.max_eid_cnt = udma_dev->caps.seid.max_cnt;
	attr->dev_cap.feature.bs.jfc_inline = (udma_dev->caps.feature &
					       UDMA_CAP_FEATURE_JFC_INLINE) ? 1 : 0;
	attr->dev_cap.max_read_size = udma_dev->caps.max_read_size;
	attr->dev_cap.max_write_size = udma_dev->caps.max_write_size;
	attr->dev_cap.max_cas_size = udma_dev->caps.max_cas_size;
	attr->dev_cap.max_fetch_and_add_size = udma_dev->caps.max_fetch_and_add_size;
	attr->dev_cap.atomic_feat.value = udma_dev->caps.atomic_feat;
	(void)memcpy(attr->dev_cap.priority_info,
		     udma_dev->priority_info,
		     sizeof(struct ubcore_sl_info) * UDMA_MAX_SL_NUM);
	attr->dev_cap.feature.bs.ipourma_en = udma_dev->caps.ipourma_en;
	attr->dev_cap.feature.bs.ctp_en = udma_dev->caps.ctp_en;
}

static int udma_query_device_attr(struct ubcore_device *dev,
				  struct ubcore_device_attr *attr)
{
	struct udma_dev *udma_dev = to_udma_dev(dev);

	udma_set_dev_caps(attr, udma_dev);
	attr->ue_idx = udma_dev->caps.ue_id;
	attr->port_attr[0].max_mtu = UBCORE_MTU_4096;
	attr->reserved_jetty_id_max = udma_dev->caps.public_jetty.max_cnt - 1;

	return 0;
}

static int udma_set_sl(struct ubcore_device *dev, uint32_t priority, uint32_t SL)
{
	struct udma_dev *udma_dev = to_udma_dev(dev);

	if (priority >= UDMA_MAX_PRIORITY || SL >= UDMA_MAX_SL_NUM) {
		dev_err(udma_dev->dev,
			"invalid priority(%d) or SL(%d)\n", priority, SL);
		return -EINVAL;
	}

	for (int i = 0; i < udma_dev->udma_total_sl_num; i++) {
		if (udma_dev->udma_sl[i] == SL) {
			udma_dev->priority_info[priority].SL = SL;
			if (i < udma_dev->udma_tp_sl_num) {
				udma_dev->priority_info[priority].tp_type.bs.rtp = 1;
				udma_dev->priority_info[priority].tp_type.bs.ctp = 0;
			} else {
				udma_dev->priority_info[priority].tp_type.bs.rtp = 0;
				udma_dev->priority_info[priority].tp_type.bs.ctp = 1;
			}
			return 0;
		}
	}

	dev_err(udma_dev->dev, "SL(%d) to set is not in rtp or ctp range.\n", SL);

	return -EINVAL;
}

static int udma_query_stats(struct ubcore_device *dev, struct ubcore_stats_key *key,
			    struct ubcore_stats_val *val)
{
	struct ubcore_stats_com_val *com_val = (struct ubcore_stats_com_val *)val->addr;
	struct udma_dev *udma_dev = to_udma_dev(dev);
	struct ubase_eth_mac_stats mac_stats = {};
	struct ubase_ub_dl_stats dl_stats = {};
	int ret;

	if (ubase_adev_ubl_supported(udma_dev->comdev.adev))
		ret = ubase_get_ub_port_stats(udma_dev->comdev.adev,
					      udma_dev->port_logic_id, &dl_stats);
	else
		ret = ubase_get_eth_port_stats(udma_dev->comdev.adev, &mac_stats);
	if (ret) {
		dev_err(udma_dev->dev, "failed to query port stats, ret = %d.\n", ret);
		return ret;
	}

	if (ubase_adev_ubl_supported(udma_dev->comdev.adev)) {
		com_val->tx_pkt = dl_stats.dl_tx_busi_pkt_num;
		com_val->rx_pkt = dl_stats.dl_rx_busi_pkt_num;
		com_val->rx_pkt_err = 0;
		com_val->tx_pkt_err = 0;
		com_val->tx_bytes = 0;
		com_val->rx_bytes = 0;
	} else {
		com_val->tx_pkt = mac_stats.tx_total_pkts;
		com_val->rx_pkt = mac_stats.rx_total_pkts;
		com_val->tx_pkt_err = mac_stats.tx_bad_pkts;
		com_val->rx_pkt_err = mac_stats.rx_bad_pkts;
		com_val->tx_bytes = mac_stats.tx_total_octets;
		com_val->rx_bytes = mac_stats.rx_total_octets;
	}

	return ret;
}

static void udma_disassociate_ucontext(struct ubcore_ucontext *uctx)
{
}

static int udma_config_device(struct ubcore_device *ubcore_dev,
			      struct ubcore_device_cfg *cfg)
{
	struct udma_dev *dev = to_udma_dev(ubcore_dev);

	if ((cfg->mask.bs.reserved_jetty_id_min && cfg->reserved_jetty_id_min != 0) ||
	    (cfg->mask.bs.reserved_jetty_id_max && cfg->reserved_jetty_id_max !=
	    dev->caps.public_jetty.max_cnt - 1)) {
		dev_err(dev->dev, "public jetty range must 0-%u.\n",
			dev->caps.public_jetty.max_cnt - 1);
		return -EINVAL;
	}

	return 0;
}

static struct ubcore_ops g_dev_ops = {
	.owner = THIS_MODULE,
	.abi_version = 0,
	.query_device_attr = udma_query_device_attr,
	.query_device_status = udma_query_device_status,
	.query_res = udma_query_res,
	.config_device = udma_config_device,
	.alloc_ucontext = udma_alloc_ucontext,
	.free_ucontext = udma_free_ucontext,
	.mmap = udma_mmap,
	.alloc_token_id = udma_alloc_tid,
	.free_token_id = udma_free_tid,
	.register_seg = udma_register_seg,
	.unregister_seg = udma_unregister_seg,
	.import_seg = udma_import_seg,
	.unimport_seg = udma_unimport_seg,
	.create_jfc = udma_create_jfc,
	.modify_jfc = udma_modify_jfc,
	.destroy_jfc = udma_destroy_jfc,
	.rearm_jfc = udma_rearm_jfc,
	.alloc_jfc = udma_alloc_jfc,
	.set_jfc_opt = udma_set_jfc_opt,
	.active_jfc = udma_active_jfc,
	.get_jfc_opt = udma_get_jfc_opt,
	.deactive_jfc = udma_deactive_jfc,
	.free_jfc = udma_free_jfc,
	.create_jfs = udma_create_jfs,
	.modify_jfs = udma_modify_jfs,
	.query_jfs = udma_query_jfs,
	.flush_jfs = udma_flush_jfs,
	.destroy_jfs = udma_destroy_jfs,
	.destroy_jfs_batch = udma_destroy_jfs_batch,
	.alloc_jfs = udma_alloc_jfs,
	.set_jfs_opt = udma_set_jfs_opt,
	.active_jfs = udma_active_jfs,
	.get_jfs_opt = udma_get_jfs_opt,
	.deactive_jfs = udma_deactive_jfs,
	.free_jfs = udma_free_jfs,
	.create_jfr = udma_create_jfr,
	.modify_jfr = udma_modify_jfr,
	.query_jfr = udma_query_jfr,
	.destroy_jfr = udma_destroy_jfr,
	.destroy_jfr_batch = udma_destroy_jfr_batch,
	.import_jfr_ex = udma_import_jfr_ex,
	.unimport_jfr = udma_unimport_jfr,
	.alloc_jfr = udma_alloc_jfr,
	.set_jfr_opt = udma_set_jfr_opt,
	.active_jfr = udma_active_jfr,
	.get_jfr_opt = udma_get_jfr_opt,
	.deactive_jfr = udma_deactive_jfr,
	.free_jfr = udma_free_jfr,
	.create_jetty = udma_create_jetty,
	.modify_jetty = udma_modify_jetty,
	.query_jetty = udma_query_jetty,
	.flush_jetty = udma_flush_jetty,
	.destroy_jetty = udma_destroy_jetty,
	.destroy_jetty_batch = udma_destroy_jetty_batch,
	.import_jetty_ex = udma_import_jetty_ex,
	.unimport_jetty = udma_unimport_jetty,
	.bind_jetty_ex = udma_bind_jetty_ex,
	.unbind_jetty = udma_unbind_jetty,
	.create_jetty_grp = udma_create_jetty_grp,
	.delete_jetty_grp = udma_delete_jetty_grp,
	.alloc_jetty = udma_alloc_jetty,
	.set_jetty_opt = udma_set_jetty_opt,
	.active_jetty = udma_active_jetty,
	.get_jetty_opt = udma_get_jetty_opt,
	.deactive_jetty = udma_deactive_jetty,
	.free_jetty = udma_free_jetty,
	.get_tp_list = udma_get_tp_list,
	.set_tp_attr = udma_set_tp_attr,
	.get_tp_attr = udma_get_tp_attr,
	.active_tp = udma_active_tp,
	.deactive_tp = udma_deactive_tp,
	.user_ctl = udma_user_ctl,
	.post_jfs_wr = udma_post_jfs_wr,
	.post_jfr_wr = udma_post_jfr_wr,
	.post_jetty_send_wr = udma_post_jetty_send_wr,
	.post_jetty_recv_wr = udma_post_jetty_recv_wr,
	.poll_jfc = udma_poll_jfc,
	.query_stats = udma_query_stats,
	.query_ue_idx = udma_query_ue_idx,
	.disassociate_ucontext = udma_disassociate_ucontext,
	.set_sl = udma_set_sl,
	.get_eid_by_ip = udma_get_eid_by_ip,
	.get_ip_by_eid = udma_get_ip_by_eid,
	.get_smac = udma_get_smac,
	.get_dmac = NULL,
};

static void udma_uninit_group_table(struct udma_dev *dev, struct udma_group_table *table)
{
	if (!xa_empty(&table->xa))
		dev_err(dev->dev, "table is not empty.\n");
	xa_destroy(&table->xa);

	vfree(table->bitmap_table.bit);
	table->bitmap_table.bit = NULL;
}

static void udma_destroy_tp_ue_idx_table(struct udma_dev *udma_dev)
{
	struct udma_ue_idx_table *tp_ue_idx_info;
	unsigned long index = 0;

	xa_lock(&udma_dev->tpn_ue_idx_table);
	if (!xa_empty(&udma_dev->tpn_ue_idx_table)) {
		xa_for_each(&udma_dev->tpn_ue_idx_table, index, tp_ue_idx_info) {
			__xa_erase(&udma_dev->tpn_ue_idx_table, index);
			kfree(tp_ue_idx_info);
			tp_ue_idx_info = NULL;
		}
	}

	xa_unlock(&udma_dev->tpn_ue_idx_table);
	xa_destroy(&udma_dev->tpn_ue_idx_table);
}

void udma_destroy_tables(struct udma_dev *udma_dev)
{
	if (!udma_dev->is_ue)
		udma_destroy_eid_guid_table(udma_dev);

	udma_ctrlq_destroy_tpid_list(&udma_dev->ctrlq_tpid_table);

	udma_destroy_eid_table(udma_dev);
	mutex_destroy(&udma_dev->disable_ue_rx_mutex);
	if (!ida_is_empty(&udma_dev->rsvd_jetty_ida_table.ida))
		dev_err(udma_dev->dev,
			"IDA not empty in clean up rsvd jetty id table.\n");
	ida_destroy(&udma_dev->rsvd_jetty_ida_table.ida);

	if (!xa_empty(&udma_dev->crq_nb_table))
		dev_err(udma_dev->dev, "crq nb table is not empty.\n");
	xa_destroy(&udma_dev->crq_nb_table);

	udma_destroy_tp_ue_idx_table(udma_dev);
	udma_destroy_npu_cb_table(udma_dev);

	if (!xa_empty(&udma_dev->ksva_table))
		dev_err(udma_dev->dev, "ksva table is not empty.\n");
	xa_destroy(&udma_dev->ksva_table);
	mutex_destroy(&udma_dev->ksva_mutex);
	udma_destroy_udma_table(udma_dev, &udma_dev->jetty_grp_table, "JettyGroup");
	udma_destroy_udma_table(udma_dev, &udma_dev->jfc_table, "JFC");
	udma_destroy_udma_table(udma_dev, &udma_dev->jfr_table, "JFR");
	udma_uninit_group_table(udma_dev, &udma_dev->jetty_table);
}

static int udma_init_group_table(struct udma_dev *udma_dev, struct udma_group_table *table,
				 uint32_t max, uint32_t min)
{
	struct udma_group_bitmap *bitmap_table;
	int i;

	bitmap_table = &table->bitmap_table;
	if (max < min) {
		dev_err(udma_dev->dev,
			"max value is less than min value when init group bitmap.\n");
		return -EINVAL;
	}

	bitmap_table->max = max;
	bitmap_table->min = min;
	bitmap_table->grp_next = min;
	bitmap_table->n_bits = max - min + 1;
	bitmap_table->bitmap_cnt = ALIGN(bitmap_table->n_bits, NUM_JETTY_PER_GROUP) /
				   NUM_JETTY_PER_GROUP;
	bitmap_table->bit = vmalloc(bitmap_table->bitmap_cnt * sizeof(uint32_t));
	if (!bitmap_table->bit) {
		dev_err(udma_dev->dev, "failed to alloc jetty bitmap.\n");
		return -ENOMEM;
	}

	for (i = 0; i < bitmap_table->bitmap_cnt; ++i)
		bitmap_table->bit[i] = ~(0U);

	if (bitmap_table->n_bits % NUM_JETTY_PER_GROUP)
		bitmap_table->bit[bitmap_table->bitmap_cnt - 1] =
			GENMASK((bitmap_table->n_bits % NUM_JETTY_PER_GROUP) - 1, 0);

	spin_lock_init(&bitmap_table->lock);
	xa_init(&table->xa);

	return 0;
}

static void udma_init_managed_by_ctrl_cpu_table(struct udma_dev *udma_dev)
{
	mutex_init(&udma_dev->eid_mutex);
	xa_init(&udma_dev->eid_table);
	xa_init(&udma_dev->ctrlq_tpid_table);
}

int udma_init_tables(struct udma_dev *udma_dev)
{
	int ret;

	ret = udma_init_group_table(udma_dev, &udma_dev->jetty_table,
				    udma_dev->caps.jetty.max_cnt +
				    udma_dev->caps.jetty.start_idx - 1,
				    udma_dev->caps.jetty.start_idx);
	if (ret) {
		dev_err(udma_dev->dev,
			"failed to init jetty table when start_idx = %u, and max_cnt = %u.\n",
			udma_dev->caps.jetty.start_idx, udma_dev->caps.jetty.max_cnt);
		return ret;
	}

	udma_init_udma_table(&udma_dev->jfr_table, udma_dev->caps.jfr.max_cnt +
			     udma_dev->caps.jfr.start_idx - 1, udma_dev->caps.jfr.start_idx, false);
	udma_init_udma_table(&udma_dev->jfc_table, udma_dev->caps.jfc.max_cnt +
			     udma_dev->caps.jfc.start_idx - 1, udma_dev->caps.jfc.start_idx, true);
	udma_init_udma_table(&udma_dev->jetty_grp_table, udma_dev->caps.jetty_grp.max_cnt +
			     udma_dev->caps.jetty_grp.start_idx - 1,
			     udma_dev->caps.jetty_grp.start_idx, true);
	udma_init_udma_table_mutex(&udma_dev->ksva_table, &udma_dev->ksva_mutex, false);
	udma_init_udma_table_mutex(&udma_dev->npu_nb_table, &udma_dev->npu_nb_mutex, true);
	xa_init_flags(&udma_dev->tpn_ue_idx_table, XA_FLAGS_LOCK_IRQ);
	xa_init(&udma_dev->crq_nb_table);
	ida_init(&udma_dev->rsvd_jetty_ida_table.ida);
	mutex_init(&udma_dev->disable_ue_rx_mutex);
	udma_init_managed_by_ctrl_cpu_table(udma_dev);

	if (udma_dev->is_ue)
		return 0;

	mutex_init(&udma_dev->eid_guid_mutex);
	xa_init(&udma_dev->eid_guid_table);

	return 0;
}

static int udma_set_ubcore_dev(struct udma_dev *udma_dev)
{
	struct ubcore_device *ub_dev = &udma_dev->ub_dev;
	int ret;

	ub_dev->transport_type = UBCORE_TRANSPORT_UB;
	ub_dev->ops = &g_dev_ops;
	ub_dev->dev.parent = udma_dev->dev;
	ub_dev->dma_dev = ub_dev->dev.parent;
	ub_dev->attr.dev_cap.feature.value = udma_dev->caps.feature;

	if (dev_name_style) {
		scnprintf(udma_dev->dev_name, UBCORE_MAX_DEV_NAME,
			"udmac%ud%ue%u", udma_dev->chip_id, udma_dev->die_id, udma_dev->ue_id);
	} else {
		scnprintf(udma_dev->dev_name, UBCORE_MAX_DEV_NAME, "udma%hu", udma_dev->adev_id);
	}
	strscpy(ub_dev->dev_name, udma_dev->dev_name, UBCORE_MAX_DEV_NAME);
	scnprintf(ub_dev->ops->driver_name, UBCORE_MAX_DRIVER_NAME, "udma");

	if (!ubase_adev_ubl_supported(udma_dev->comdev.adev))
		ub_dev->netdev = udma_dev->comdev.netdev;

	ret = ubcore_register_device(ub_dev);
	if (ret)
		dev_err(udma_dev->dev, "failed to register udma_dev to ubcore, ret is %d.\n", ret);

	return ret;
}

static void udma_dump_jetty_id_range(struct udma_dev *udma_dev)
{
#define UDMA_JETTY_CNT 6
	const char *jetty_name[UDMA_JETTY_CNT] = {
		"public",
		"ccu",
		"hdc",
		"cache_lock",
		"user_ctrl_normal",
		"urma_normal",
	};
	struct udma_res *jetty_res_list[UDMA_JETTY_CNT] = {
		&udma_dev->caps.public_jetty,
		&udma_dev->caps.ccu_jetty,
		&udma_dev->caps.hdc_jetty,
		&udma_dev->caps.stars_jetty,
		&udma_dev->caps.user_ctrl_normal_jetty,
		&udma_dev->caps.jetty,
	};
	uint32_t i;

	for (i = 0; i < UDMA_JETTY_CNT; i++)
		dev_info(udma_dev->dev, "%s jetty start_idx=%u, max_cnt=%u\n",
			 jetty_name[i], jetty_res_list[i]->start_idx,
			 jetty_res_list[i]->max_cnt);
}

static void udma_get_jetty_id_range(struct udma_dev *udma_dev,
				    struct udma_cmd_ue_resource *cmd)
{
	udma_dev->caps.public_jetty.start_idx = cmd->well_known_jetty_start;
	udma_dev->caps.public_jetty.max_cnt = cmd->well_known_jetty_num;

	udma_dev->caps.ccu_jetty.start_idx = cmd->ccu_jetty_start;
	udma_dev->caps.ccu_jetty.max_cnt = cmd->ccu_jetty_num;
	udma_dev->caps.ccu_jetty.next_idx = udma_dev->caps.ccu_jetty.start_idx;

	udma_dev->caps.hdc_jetty.start_idx = cmd->drv_jetty_start;
	udma_dev->caps.hdc_jetty.max_cnt = cmd->drv_jetty_num;

	udma_dev->caps.stars_jetty.start_idx = cmd->cache_lock_jetty_start;
	udma_dev->caps.stars_jetty.max_cnt =  cmd->cache_lock_jetty_num;
	udma_dev->caps.stars_jetty.next_idx = udma_dev->caps.stars_jetty.start_idx;

	udma_dev->caps.user_ctrl_normal_jetty.start_idx = cmd->normal_jetty_start;
	udma_dev->caps.user_ctrl_normal_jetty.max_cnt = cmd->normal_jetty_num;
	udma_dev->caps.user_ctrl_normal_jetty.next_idx =
		udma_dev->caps.user_ctrl_normal_jetty.start_idx;

	udma_dev->caps.jetty.start_idx = cmd->standard_jetty_start;
	udma_dev->caps.jetty.max_cnt = cmd->standard_jetty_num;

	udma_dev->caps.rsvd_jetty_cnt = udma_dev->caps.public_jetty.max_cnt +
					udma_dev->caps.ccu_jetty.max_cnt +
					udma_dev->caps.hdc_jetty.max_cnt +
					udma_dev->caps.stars_jetty.max_cnt +
					udma_dev->caps.user_ctrl_normal_jetty.max_cnt;

	if (debug_switch)
		udma_dump_jetty_id_range(udma_dev);
}

static int query_caps_from_firmware(struct udma_dev *udma_dev)
{
	struct udma_cmd_ue_resource cmd = {};
	int ret;

	ret = udma_cmd_query_hw_resource(udma_dev, (void *)&cmd);
	if (ret) {
		dev_err(udma_dev->dev, "fail to query hw resource from FW %d\n", ret);
		return ret;
	}

	udma_dev->caps.jfs_sge = cmd.jfs_sge;
	udma_dev->caps.jfs_rsge = cmd.jfs_rsge;
	udma_dev->caps.jfr_sge = cmd.jfr_sge;
	udma_dev->caps.jfs_inline_sz = cmd.max_jfs_inline_sz;
	udma_dev->caps.jetty_grp.max_cnt = cmd.jetty_grp_num;
	udma_dev->caps.trans_mode = cmd.trans_mode;
	udma_dev->caps.seid.size = cmd.seid_upi_tbl_sz;
	udma_dev->caps.seid.max_cnt = cmd.seid_upi_tbl_num;
	udma_dev->caps.port_num = cmd.port_num;
	udma_dev->caps.max_read_size = cmd.max_read_size;
	udma_dev->caps.max_write_size = cmd.max_write_size;
	udma_dev->caps.max_cas_size = cmd.max_cas_size;
	udma_dev->caps.max_fetch_and_add_size = cmd.max_fetch_and_add_size;
	udma_dev->caps.atomic_feat = cmd.atomic_feat;

	udma_get_jetty_id_range(udma_dev, &cmd);

	udma_dev->caps.feature = cmd.cap_info;
	udma_dev->caps.ue_cnt = cmd.ue_cnt >= UDMA_DEV_UE_NUM ?
		UDMA_DEV_UE_NUM - 1 : cmd.ue_cnt;
	udma_dev->caps.ue_id = cmd.ue_id;
	udma_dev->is_ue = !!(cmd.ue_id);

	return 0;
}

static void get_dev_caps_from_ubase(struct udma_dev *udma_dev)
{
	struct ubase_caps *ubase_caps;

	ubase_caps = ubase_get_dev_caps(udma_dev->comdev.adev);
	if (ubase_caps == NULL)
		return;

	udma_dev->caps.comp_vector_cnt = ubase_caps->num_ceq_vectors;
	udma_dev->caps.ack_queue_num = ubase_caps->ack_queue_num;

	udma_dev->chip_id = ubase_caps->chip_id;
	udma_dev->die_id = ubase_caps->die_id;
	udma_dev->port_id = ubase_caps->io_port_id;
	udma_dev->port_logic_id = ubase_caps->io_port_logic_id;
	udma_dev->ue_id = ubase_caps->ue_id;
}

static int udma_construct_qos_param(struct udma_dev *dev)
{
	struct ubase_adev_qos *qos_info;
	uint8_t i;

	qos_info = ubase_get_adev_qos(dev->comdev.adev);
	if (!qos_info) {
		dev_err(dev->dev, "cannot get qos information from ubase.\n");
		return -EINVAL;
	}

	dev->udma_tp_sl_num = qos_info->tp_sl_num;
	dev->udma_ctp_sl_num = qos_info->ctp_sl_num;
	dev->unic_sl_num = qos_info->nic_sl_num;
	dev->udma_tp_resp_vl_off = qos_info->tp_resp_vl_offset;
	dev->udma_total_sl_num = dev->udma_tp_sl_num + dev->udma_ctp_sl_num;
	if (dev->udma_total_sl_num > UDMA_MAX_SL_NUM) {
		dev_err(dev->dev,
			"total sl num is invalid, tp sl num is %u, ctp sl num is %u.\n",
			dev->udma_tp_sl_num, dev->udma_ctp_sl_num);
		return -EINVAL;
	}

	(void)memcpy(dev->udma_tp_sl,
		     qos_info->tp_sl, sizeof(u8) * qos_info->tp_sl_num);
	(void)memcpy(dev->udma_ctp_sl,
		     qos_info->ctp_sl, sizeof(u8) * qos_info->ctp_sl_num);
	(void)memcpy(dev->unic_sl,
		     qos_info->nic_sl, sizeof(u8) * qos_info->nic_sl_num);
	(void)memcpy(dev->udma_sl,
		     qos_info->tp_sl, sizeof(u8) * qos_info->tp_sl_num);

	for (i = 0; i < qos_info->ctp_sl_num; i++)
		dev->udma_sl[qos_info->tp_sl_num + i] = qos_info->ctp_sl[i];

	if (qos_info->tp_sl_num != 0) {
		for (i = 0; i < UDMA_MAX_SL_NUM; i++) {
			dev->priority_info[i].SL = dev->udma_tp_sl[UDMA_DEFAULT_SL_NUM];
			dev->priority_info[i].tp_type.bs.rtp = 1;
		}
	} else {
		for (i = 0; i < UDMA_MAX_SL_NUM; i++) {
			dev->priority_info[i].SL = dev->udma_ctp_sl[UDMA_DEFAULT_SL_NUM];
			dev->priority_info[i].tp_type.bs.ctp = 1;
		}
	}

	for (i = 0; i < dev->udma_tp_sl_num; i++) {
		dev->priority_info[dev->udma_tp_sl[i]].SL = dev->udma_tp_sl[i];
		dev->priority_info[dev->udma_tp_sl[i]].tp_type.bs.rtp = 1;
		dev->priority_info[dev->udma_tp_sl[i]].tp_type.bs.ctp = 0;
	}

	for (i = 0; i < dev->udma_ctp_sl_num; i++) {
		dev->priority_info[dev->udma_ctp_sl[i]].SL = dev->udma_ctp_sl[i];
		dev->priority_info[dev->udma_ctp_sl[i]].tp_type.bs.rtp = 0;
		dev->priority_info[dev->udma_ctp_sl[i]].tp_type.bs.ctp = 1;
	}

	return 0;
}

static int udma_query_wqebb_va(struct udma_dev *dev)
{
#define UDMA_FIRST_UE_ID 2
#define UDMA_RESERVED_SQ_SIZE 2097152
	uint32_t max_jetty_num, ue_va_offset;
	struct udma_cmd_wqebb_va info = {};
	struct ubase_cmd_buf in, out;
	int ret;

	if (!sq_reserved)
		return 0;

	udma_fill_buf(&in, UDMA_CMD_WQEBB_VA_INFO, true, 0, NULL);
	udma_fill_buf(&out, UDMA_CMD_WQEBB_VA_INFO, true,
		      sizeof(info), (void *)&info);
	ret = ubase_cmd_send_inout(dev->comdev.adev, &in, &out);
	if (ret) {
		dev_err(dev->dev, "failed to query_wqebb_va, ret = %d.\n", ret);
		return -EINVAL;
	}

	if (info.die_num == 0 || info.ue_num == 0)
		return 0;

	if (dev->is_ue) {
		dev_warn(dev->dev, "ue is not supported reserved sq.\n");
		return 0;
	}

	if (dev->die_id >= info.die_num || dev->ue_id < UDMA_FIRST_UE_ID ||
	   dev->ue_id >= info.ue_num + UDMA_FIRST_UE_ID) {
		dev_warn(dev->dev,
			 "this mue not supported reserved sq, die_id=%u, ue_id=%u.\n",
			 dev->die_id, dev->ue_id);
		return 0;
	}

	max_jetty_num = dev->caps.jetty.start_idx + dev->caps.jetty.max_cnt;
	ue_va_offset = dev->die_id * info.ue_num + dev->ue_id - UDMA_FIRST_UE_ID;
	dev->sq_reserved_info.va_start = info.va_start;
	dev->sq_reserved_info.va_size = info.va_size;
	dev->sq_reserved_info.size_per_jetty = UDMA_RESERVED_SQ_SIZE;
	dev->sq_reserved_info.size_per_ue =
		ALIGN_DOWN(info.va_size / info.die_num / info.ue_num, UDMA_RESERVED_SQ_SIZE);
	dev->sq_reserved_info.va_per_ue =
		info.va_start + dev->sq_reserved_info.size_per_ue * ue_va_offset;
	dev->sq_reserved_info.sq_reserved = dev->sq_reserved_info.size_per_jetty *
					    max_jetty_num <= dev->sq_reserved_info.size_per_ue;
	if (!dev->sq_reserved_info.sq_reserved)
		dev_warn(dev->dev,
			"invalid param, the reserved size is not enough to create all sq.\n");

	return 0;
}

static int udma_set_hw_caps(struct udma_dev *udma_dev)
{
#define MAX_MSG_LEN 0x10000
	struct ubase_adev_caps *a_caps;
	uint32_t jetty_grp_cnt;
	int ret;

	get_dev_caps_from_ubase(udma_dev);

	ret = query_caps_from_firmware(udma_dev);
	if (ret)
		return ret;

	a_caps = ubase_get_udma_caps(udma_dev->comdev.adev);
	udma_dev->caps.jfs.max_cnt = a_caps->jfs.max_cnt;
	udma_dev->caps.jfs.depth = a_caps->jfs.depth / MAX_WQEBB_IN_SQE;
	udma_dev->caps.jfs.start_idx = a_caps->jfs.start_idx;
	udma_dev->caps.jfr.max_cnt = a_caps->jfr.max_cnt;
	udma_dev->caps.jfr.depth = a_caps->jfr.depth;
	udma_dev->caps.jfr.start_idx = a_caps->jfr.start_idx;
	udma_dev->caps.jfc.max_cnt = a_caps->jfc.max_cnt;
	udma_dev->caps.jfc.depth = a_caps->jfc.depth;
	udma_dev->caps.jfc.start_idx = a_caps->jfc.start_idx;
	udma_dev->caps.jetty.max_cnt = a_caps->jfs.max_cnt;
	udma_dev->caps.jetty.depth = a_caps->jfs.depth;
	udma_dev->caps.jetty.start_idx = a_caps->jfs.start_idx;
	udma_dev->caps.jetty.next_idx = udma_dev->caps.jetty.start_idx;
	udma_dev->caps.cqe_size = UDMA_CQE_SIZE;
	udma_dev->caps.ipourma_en = ubase_adev_ip_over_urma_supported(udma_dev->comdev.adev);
	udma_dev->caps.ctp_en = !(ubase_adev_ip_over_urma_utp_supported(udma_dev->comdev.adev));
	udma_dev->caps.rc_max_cnt = a_caps->rc_max_cnt;

	ret = udma_construct_qos_param(udma_dev);
	if (ret)
		return ret;

	ret = udma_query_wqebb_va(udma_dev);
	if (ret)
		return ret;

	udma_dev->caps.max_msg_len = MAX_MSG_LEN;
	udma_dev->caps.jetty_in_grp = MAX_JETTY_IN_JETTY_GRP;

	if (udma_dev->caps.jetty_in_grp) {
		jetty_grp_cnt = udma_dev->caps.jetty.max_cnt / udma_dev->caps.jetty_in_grp;
		udma_dev->caps.jetty_grp.max_cnt =
			jetty_grp_cnt < udma_dev->caps.jetty_grp.max_cnt ?
			jetty_grp_cnt : udma_dev->caps.jetty_grp.max_cnt;
	}

	return 0;
}

static int udma_init_dev_param(struct udma_dev *udma_dev)
{
	struct auxiliary_device *adev = udma_dev->comdev.adev;
	struct ubase_resource_space *mem_base = ubase_get_mem_base(adev);
	const struct ubase_adev_com *adev_com;
	int ret;
	int i;

	if (!ubase_adev_ubl_supported(udma_dev->comdev.adev)) {
		adev_com = ubase_get_mdrv_data(adev);
		if (adev_com == NULL) {
			dev_err(&adev->dev, "Failed to get mdrv data from ubase.\n");
			return -EINVAL;
		}
		udma_dev->comdev.netdev = adev_com->netdev;
	}

	udma_dev->dev = adev->dev.parent;
	udma_dev->db_base = mem_base->addr_unmapped;
	udma_dev->k_db_base = mem_base->addr;
	udma_dev->adev_id = udma_dev->comdev.adev->id;

	ret = udma_set_hw_caps(udma_dev);
	if (ret) {
		dev_err(udma_dev->dev, "failed to query hw caps, ret = %d\n", ret);
		return ret;
	}

	ret = udma_init_tables(udma_dev);
	if (ret) {
		dev_err(udma_dev->dev,
			"Failed to init tables, ret = %d\n", ret);
		return ret;
	}

	dev_set_drvdata(&adev->dev, udma_dev);

	mutex_init(&udma_dev->db_mutex);
	for (i = 0; i < UDMA_DB_TYPE_NUM; i++)
		INIT_LIST_HEAD(&udma_dev->db_list[i]);

	udma_init_hugepage(udma_dev);

	return 0;
}

static void udma_uninit_dev_param(struct udma_dev *udma_dev)
{
	udma_destroy_hugepage(udma_dev);
	mutex_destroy(&udma_dev->db_mutex);
	dev_set_drvdata(&udma_dev->comdev.adev->dev, NULL);
	udma_destroy_tables(udma_dev);
}

static void udma_disable_usva(struct udma_dev *udma_dev)
{
	int ret;

	ret = iommu_dev_disable_feature(udma_dev->dev, IOMMU_DEV_FEAT_SVA);
	if (ret)
		dev_warn(udma_dev->dev, "disable sva failed, ret = %d.\n", ret);

	ret = iommu_dev_disable_feature(udma_dev->dev, IOMMU_DEV_FEAT_IOPF);
	if (ret)
		dev_warn(udma_dev->dev, "disable iopf failed, ret = %d.\n", ret);
}

static int udma_enable_usva(struct udma_dev *udma_dev)
{
	int ret;

	ret = ummu_get_sva_mode(udma_dev->dev);
	if (ret < 0) {
		dev_err(udma_dev->dev, "invalid sva mode, ret = %d.\n", ret);
		return -EINVAL;
	}
	udma_dev->caps.sva_sep_mode_en = !!ret;

	ret = iommu_dev_enable_feature(udma_dev->dev, IOMMU_DEV_FEAT_IOPF);
	if (ret) {
		dev_err(udma_dev->dev, "enable iopf failed, ret = %d.\n", ret);
		return -EINVAL;
	}

	ret = iommu_dev_enable_feature(udma_dev->dev, IOMMU_DEV_FEAT_SVA);
	if (ret) {
		dev_err(udma_dev->dev, "enable sva failed, ret = %d.\n", ret);
		goto err_enable_sva;
	}

	return ret;

err_enable_sva:
	if (iommu_dev_disable_feature(udma_dev->dev, IOMMU_DEV_FEAT_IOPF))
		dev_warn(udma_dev->dev, "disable iopf failed.\n");
	return ret;
}

static int udma_alloc_dev_tid(struct udma_dev *udma_dev)
{
	struct ummu_seg_attr seg_attr = {.token = NULL, .e_bit = UMMU_EBIT_ON};
	struct ummu_param param = {.mode = MAPT_MODE_TABLE};
	int ret;

	ret = udma_enable_usva(udma_dev);
	if (ret) {
		dev_err(udma_dev->dev, "Failed to enable usva, ret = %d.\n", ret);
		return ret;
	}

	ret = iommu_dev_enable_feature(udma_dev->dev, IOMMU_DEV_FEAT_KSVA);
	if (ret) {
		dev_err(udma_dev->dev, "enable ksva failed, ret = %d.\n", ret);
		goto err_enable_ksva;
	}

	udma_dev->ksva = ummu_ksva_bind_device(udma_dev->dev, &param);
	if (!udma_dev->ksva) {
		dev_err(udma_dev->dev, "ksva bind device failed.\n");
		ret = -EINVAL;
		goto err_ksva_bind_device;
	}

	ret = ummu_get_tid(udma_dev->dev, udma_dev->ksva, &udma_dev->tid);
	if (ret) {
		dev_err(udma_dev->dev, "Failed to get tid for udma device.\n");
		goto err_get_tid;
	}

	ret = ummu_sva_grant_range(udma_dev->ksva, 0, UDMA_MAX_GRANT_SIZE,
				   UMMU_DEV_WRITE | UMMU_DEV_READ, &seg_attr);
	if (ret) {
		dev_err(udma_dev->dev, "Failed to sva grant range for udma device.\n");
		goto err_sva_grant_range;
	}

	return ret;

err_sva_grant_range:
err_get_tid:
	ummu_ksva_unbind_device(udma_dev->ksva);
err_ksva_bind_device:
	if (iommu_dev_disable_feature(udma_dev->dev, IOMMU_DEV_FEAT_KSVA))
		dev_warn(udma_dev->dev, "disable ksva failed.\n");
err_enable_ksva:
	udma_disable_usva(udma_dev);

	return ret;
}

static void udma_free_dev_tid(struct udma_dev *udma_dev)
{
	struct iommu_sva *ksva = NULL;
	size_t token_id;
	int ret;

	ret = ummu_sva_ungrant_range(udma_dev->ksva, 0, UDMA_MAX_GRANT_SIZE, NULL);
	if (ret)
		dev_warn(udma_dev->dev,
			 "sva ungrant range for udma device failed, ret = %d.\n",
			 ret);

	mutex_lock(&udma_dev->ksva_mutex);
	xa_for_each(&udma_dev->ksva_table, token_id, ksva) {
		__xa_erase(&udma_dev->ksva_table, token_id);
		ummu_ksva_unbind_device(ksva);
	}
	mutex_unlock(&udma_dev->ksva_mutex);

	ummu_ksva_unbind_device(udma_dev->ksva);

	ret = iommu_dev_disable_feature(udma_dev->dev, IOMMU_DEV_FEAT_KSVA);
	if (ret)
		dev_warn(udma_dev->dev, "disable ksva failed, ret = %d.\n", ret);

	udma_disable_usva(udma_dev);
}

static int udma_create_db_page(struct udma_dev *udev)
{
	udev->db_page = alloc_page(GFP_KERNEL | __GFP_ZERO | GFP_HIGHUSER_MOVABLE);
	if (!udev->db_page)
		return -ENOMEM;

	return 0;
}

static void udma_destroy_db_page(struct udma_dev *udev)
{
	put_page(udev->db_page);
	udev->db_page = NULL;
}

static const struct udma_func_map udma_dev_func_map[] = {
	{"dev param", udma_init_dev_param, udma_uninit_dev_param},
	{"cmd", udma_cmd_init, udma_cmd_cleanup},
	{"dev tid", udma_alloc_dev_tid, udma_free_dev_tid},
	{"dfx", udma_dfx_init, udma_dfx_uninit},
	{"db page", udma_create_db_page, udma_destroy_db_page},
};

static void udma_destroy_dev(struct udma_dev *udev)
{
	int i;

	for (i = ARRAY_SIZE(udma_dev_func_map) - 1; i >= 0; i--)
		if (udma_dev_func_map[i].uninit_func)
			udma_dev_func_map[i].uninit_func(udev);
	kfree(udev);
}

static struct udma_dev *udma_create_dev(struct auxiliary_device *adev)
{
	struct udma_dev *udma_dev;
	int ret, i;

	udma_dev = kzalloc((sizeof(struct udma_dev)), GFP_KERNEL);
	if (udma_dev == NULL)
		return NULL;

	udma_dev->comdev.adev = adev;

	for (i = 0; i < ARRAY_SIZE(udma_dev_func_map); i++) {
		if (!udma_dev_func_map[i].init_func)
			continue;

		ret = udma_dev_func_map[i].init_func(udma_dev);
		if (ret) {
			dev_err(udma_dev->dev, "Failed to init %s, ret = %d\n",
				udma_dev_func_map[i].err_msg, ret);
			goto err_init;
		}
	}

	return udma_dev;

err_init:
	for (i -= 1; i >= 0; i--)
		if (udma_dev_func_map[i].uninit_func)
			udma_dev_func_map[i].uninit_func(udma_dev);

	kfree(udma_dev);
	return NULL;
}

static void udma_port_handler(struct auxiliary_device *adev, bool link_up)
{
	struct udma_dev *udma_dev = get_udma_dev(adev);
	struct ubcore_event ae = {};

	ae.ub_dev = &udma_dev->ub_dev;

	if (link_up)
		ae.event_type = UBCORE_EVENT_PORT_ACTIVE;
	else
		ae.event_type = UBCORE_EVENT_PORT_DOWN;

	ae.element.port_id = udma_dev->port_id;
	dev_info(udma_dev->dev,
		 "udma report port event %s, matched udma dev(%s).\n",
		 link_up ? "ACTIVE" : "DOWN", udma_dev->dev_name);

	ubcore_dispatch_async_event(&ae);
}

static int udma_register_event(struct auxiliary_device *adev)
{
	int ret;

	ret = udma_register_ae_event(adev);
	if (ret)
		return ret;

	ret = udma_register_ce_event(adev);
	if (ret)
		goto err_ce_register;

	ret = udma_register_crq_event(adev);
	if (ret)
		goto err_crq_register;

	ret = udma_register_ctrlq_event(adev);
	if (ret)
		goto err_ctrlq_register;

	ret = udma_register_ue_msg_req_event(adev);
	if (ret)
		goto err_ue_msg_req_reg;

	ret = udma_register_ue_msg_rsp_event(adev);
	if (ret)
		goto err_ue_msg_rsp_reg;

	ubase_port_register(adev, udma_port_handler);

	return 0;

err_ue_msg_rsp_reg:
	udma_unregister_ue_msg_req_event(adev);
err_ue_msg_req_reg:
	udma_unregister_ctrlq_event(adev);
err_ctrlq_register:
	udma_unregister_crq_event(adev);
err_crq_register:
	udma_unregister_ce_event(adev);
err_ce_register:
	udma_unregister_ae_event(adev);

	return ret;
}

static void udma_unregister_none_crq_event(struct auxiliary_device *adev)
{
	ubase_port_unregister(adev);
	udma_unregister_ue_msg_rsp_event(adev);
	udma_unregister_ue_msg_req_event(adev);
	udma_unregister_ctrlq_event(adev);
	udma_unregister_ce_event(adev);
	udma_unregister_ae_event(adev);
}

static bool udma_is_need_probe(struct auxiliary_device *adev)
{
	struct udma_dev *udma_dev;

	if (is_rmmod) {
		dev_info(&adev->dev,
			 "udma drv is uninstalling, not allowed to create dev(%s.%u).\n",
			 adev->name, adev->id);
		return false;
	}

	udma_dev = get_udma_dev(adev);
	if (udma_dev) {
		dev_info(&adev->dev,
			 "dev(%s.%u) is exist, bypass probe.\n",
			 adev->name, adev->id);
		return false;
	}

	return true;
}

static void udma_report_reset_event(enum ubcore_event_type event_type,
				    struct udma_dev *udma_dev)
{
	struct ubcore_event ae = {};

	ae.ub_dev = &udma_dev->ub_dev;
	ae.event_type = event_type;

	if (event_type == UBCORE_EVENT_ELR_ERR)
		dev_info(udma_dev->dev,
			"udma report reset event elr_err, matched udma dev(%s).\n",
			udma_dev->dev_name);
	else if (event_type == UBCORE_EVENT_ELR_DONE)
		dev_info(udma_dev->dev,
			"udma report reset event elr_done, matched udma dev(%s).\n",
			udma_dev->dev_name);

	ubcore_dispatch_async_event(&ae);
}

static void udma_reset_handler(struct auxiliary_device *adev,
			       enum ubase_reset_stage stage)
{
	switch (stage) {
	case UBASE_RESET_STAGE_DOWN:
		udma_reset_down(adev);
		break;
	case UBASE_RESET_STAGE_UNINIT:
		udma_reset_uninit(adev);
		break;
	case UBASE_RESET_STAGE_INIT:
		udma_reset_init(adev);
		break;
	default:
		break;
	}
}

static int udma_init_eid_table(struct udma_dev *udma_dev)
{
	int ret;

	ret = udma_query_eid_from_ctrl_cpu(udma_dev);
	if (ret)
		dev_err(udma_dev->dev, "query eid info failed, ret = %d.\n", ret);

	return ret;
}

static int udma_init_dev(struct auxiliary_device *adev)
{
	struct udma_dev *udma_dev;
	int ret;

	mutex_lock(&udma_reset_mutex);
	dev_info(&adev->dev, "udma init dev called, matched aux dev(%s.%u).\n",
		 adev->name, adev->id);
	if (!udma_is_need_probe(adev)) {
		mutex_unlock(&udma_reset_mutex);
		return 0;
	}

	udma_dev = udma_create_dev(adev);
	if (!udma_dev)
		goto err_create;

	ret = udma_register_event(adev);
	if (ret)
		goto err_event_register;

	ret = udma_register_workqueue(udma_dev);
	if (ret) {
		dev_err(udma_dev->dev, "UDMA activate workqueue failed.\n");
		goto err_register_act_init;
	}

	ret = udma_set_ubcore_dev(udma_dev);
	if (ret) {
		dev_err(udma_dev->dev, "failed to set ubcore dev, ret is %d.\n", ret);
		goto err_set_ubcore_dev;
	}

	ret = udma_init_eid_table(udma_dev);
	if (ret) {
		dev_err(udma_dev->dev, "init eid table failed.\n");
		goto err_init_eid;
	}
	udma_dev->status = UDMA_NORMAL;
	mutex_unlock(&udma_reset_mutex);
	dev_info(udma_dev->dev, "init udma successfully.\n");

	return 0;

err_init_eid:
	ubcore_unregister_device(&udma_dev->ub_dev);
err_set_ubcore_dev:
	udma_unregister_workqueue(udma_dev);
err_register_act_init:
	udma_unregister_none_crq_event(adev);
	udma_unregister_crq_event(adev);
err_event_register:
	udma_destroy_dev(udma_dev);
err_create:
	mutex_unlock(&udma_reset_mutex);

	return -EINVAL;
}

static void check_and_wait_flush_done(struct udma_dev *udma_dev)
{
#define WAIT_MAX_TIMES 15
	uint32_t wait_times = 0;

	while (true) {
		if (udma_dev->disable_ue_rx_count == 1)
			break;

		if (ubase_adev_shutting_down(udma_dev->comdev.adev)) {
			dev_err_ratelimited(udma_dev->dev, "exit flush in shutdown process.\n");
			break;
		}

		if (wait_times > WAIT_MAX_TIMES) {
			dev_warn(udma_dev->dev, "wait flush done timeout.\n");
			break;
		}
		msleep(1 << wait_times);
		wait_times++;
	}
}

void udma_reset_down(struct auxiliary_device *adev)
{
	struct udma_dev *udma_dev;

	mutex_lock(&udma_reset_mutex);
	udma_dev = get_udma_dev(adev);
	if (!udma_dev) {
		mutex_unlock(&udma_reset_mutex);
		dev_info(&adev->dev, "udma device is not exist.\n");
		return;
	}

	if (udma_dev->status != UDMA_NORMAL) {
		mutex_unlock(&udma_reset_mutex);
		dev_info(&adev->dev, "udma device status(%u).\n", udma_dev->status);
		return;
	}

	ubcore_stop_requests(&udma_dev->ub_dev);
	udma_report_reset_event(UBCORE_EVENT_ELR_ERR, udma_dev);
	udma_dev->status = UDMA_SUSPEND;
	mutex_unlock(&udma_reset_mutex);
}

void udma_reset_uninit(struct auxiliary_device *adev)
{
	struct udma_dev *udma_dev;

	mutex_lock(&udma_reset_mutex);
	udma_dev = get_udma_dev(adev);
	if (!udma_dev) {
		dev_info(&adev->dev, "udma device is not exist.\n");
		mutex_unlock(&udma_reset_mutex);
		return;
	}

	if (udma_dev->status != UDMA_SUSPEND) {
		dev_info(&adev->dev, "udma device status(%u).\n", udma_dev->status);
		mutex_unlock(&udma_reset_mutex);
		return;
	}

	if (udma_close_ue_rx(udma_dev, false, false, true, 0)) {
		mutex_unlock(&udma_reset_mutex);
		dev_err(&adev->dev, "udma close ue rx failed in reset process.\n");
		return;
	}

	udma_unregister_none_crq_event(adev);
	ubcore_unregister_device(&udma_dev->ub_dev);
	udma_unregister_workqueue(udma_dev);
	udma_open_ue_rx(udma_dev, false, false, true, 0);
	/* Crq event should unregister after wait flush done. */
	udma_unregister_crq_event(adev);
	udma_destroy_dev(udma_dev);
	mutex_unlock(&udma_reset_mutex);
}

void udma_reset_init(struct auxiliary_device *adev)
{
	udma_init_dev(adev);
}

int udma_probe(struct auxiliary_device *adev,
	       const struct auxiliary_device_id *id)
{
	if (udma_init_dev(adev)) {
		ubase_adev_fault_log(adev, UDMA_FAULT_EVENT_ID_PROBE, NULL);
		return -EINVAL;
	}

	ubase_reset_register(adev, udma_reset_handler);
	return 0;
}

void udma_remove(struct auxiliary_device *adev)
{
#define MIN_SLEEP_TIME 100
#define MAX_SLEEP_TIME 800
#define TIME_SLEEP_RATE 2
	uint32_t wait_time = MIN_SLEEP_TIME;
	struct udma_dev *udma_dev;

	ubase_reset_unregister(adev);
	mutex_lock(&udma_reset_mutex);
	udma_dev = get_udma_dev(adev);
	if (!udma_dev) {
		mutex_unlock(&udma_reset_mutex);
		dev_info(&adev->dev, "udma device is not exist.\n");
		return;
	}
	udma_dev->status = UDMA_SUSPEND;
	ubcore_stop_requests(&udma_dev->ub_dev);
	while (true) {
		if (!udma_close_ue_rx(udma_dev, false, false, false, 0)) {
			if (wait_time != MIN_SLEEP_TIME)
				ubase_adev_fault_log(adev, UDMA_FAULT_EVENT_ID_REMOVE, NULL);
			break;
		}

		if (ubase_adev_shutting_down(adev)) {
			dev_err_ratelimited(&adev->dev, "enter shutdown process.\n");
			break;
		}

		msleep(wait_time);
		if (wait_time == MIN_SLEEP_TIME)
			ubase_adev_fault_log(adev, UDMA_FAULT_EVENT_ID_REMOVE, NULL);
		if (wait_time < MAX_SLEEP_TIME)
			wait_time *= TIME_SLEEP_RATE;
		dev_err_ratelimited(&adev->dev, "udma close ue rx failed in remove process.\n");
	}
	udma_report_reset_event(UBCORE_EVENT_ELR_ERR, udma_dev);
	udma_unregister_none_crq_event(adev);
	ubcore_unregister_device(&udma_dev->ub_dev);
	udma_unregister_workqueue(udma_dev);
	check_and_wait_flush_done(udma_dev);
	(void)ubase_activate_dev(adev);
	udma_unregister_crq_event(adev);
	udma_destroy_dev(udma_dev);
	mutex_unlock(&udma_reset_mutex);
	dev_info(&adev->dev, "udma device remove success.\n");
}

static struct auxiliary_driver udma_drv = {
	.name = "udma",
	.probe = udma_probe,
	.remove = udma_remove,
	.id_table = udma_id_table,
};

static int __init udma_init(void)
{
	int ret;

	ret = auxiliary_driver_register(&udma_drv);
	if (ret)
		pr_err("failed to register auxiliary_driver\n");

	return ret;
}

static void __exit udma_exit(void)
{
	is_rmmod = true;
	auxiliary_driver_unregister(&udma_drv);
}

module_init(udma_init);
module_exit(udma_exit);
MODULE_VERSION(UDMA_DRV_VER);
MODULE_LICENSE("GPL");

module_param(dev_name_style, bool, 0644);
MODULE_PARM_DESC(dev_name_style, "Set device name style, default: 0(0:disable, 1:enable)");

module_param(cqe_mode, bool, 0444);
MODULE_PARM_DESC(cqe_mode, "Set cqe reporting mode, default: 1 (0:BY_COUNT, 1:BY_CI_PI_GAP)");

module_param(batch_flush_query_freq, uint, 0444);
MODULE_PARM_DESC(batch_flush_query_freq, "Set flush query frequency, default: 10ms");

module_param(batch_flush_query_timeout, uint, 0444);
MODULE_PARM_DESC(batch_flush_query_timeout, "Set flush query timeout, default: 64000ms");

module_param(jfr_sleep_time, uint, 0444);
MODULE_PARM_DESC(jfr_sleep_time, "Set the destroy jfr sleep time, default: 1000 us.\n");

module_param(jfc_arm_mode, uint, 0444);
MODULE_PARM_DESC(jfc_arm_mode,
		 "Set the ARM mode of the JFC, default: 0(0:Always ARM, other: NO ARM.");

module_param(sq_reserved, bool, 0444);
MODULE_PARM_DESC(sq_reserved,
		 "Set whether reserved sq, default: false(false:not reserved, true:reserved)");

module_param(dump_aux_info, bool, 0644);
MODULE_PARM_DESC(dump_aux_info,
		 "Set whether dump aux info, default: false(false:not print, true:print)");

module_param(hugepage_enable, bool, 0644);
MODULE_PARM_DESC(hugepage_enable, "Set huge page enable, default: 1(0:disable, 1:enable)");

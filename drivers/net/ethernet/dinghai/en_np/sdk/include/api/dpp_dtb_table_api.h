/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_DTB_TABLE_API_H_
#define _DPP_DTB_TABLE_API_H_
#include "dpp_dev.h"
#include "zxic_common.h"
#include "dpp_stat_api.h"

#define DPP_DTB_DUMP_ZCAM_TYPE ((u32)(0))
#define DPP_DTB_DUMP_DDR_TYPE ((u32)(1))

struct dpp_dtb_user_entry_t {
	u32 sdt_no;
	void *p_entry_data;
};

struct dpp_dtb_eram_entry_info_t {
	u32 index;
	u32 *p_data;
};

struct dpp_dtb_ddr_entry_info_t {
	u32 index;
	u32 *p_data;
};

struct dpp_dtb_hash_entry_info_t {
	u8 *p_actu_key;
	u8 *p_rst;
};

struct dpp_dtb_acl_entry_info_t {
	u32 handle;
	u8 *key_data;
	u8 *key_mask;
	u8 *p_as_rslt;
};

struct dpp_dtb_dump_index_t {
	u32 index; /*index*/
	u32 index_type;
};

struct dtb_queue_dma_addr_info {
	u32 slot_id;
	u32 queue_id;
	u32 dma_size;
	u64 dma_phy_addr;
	u64 dma_vir_addr;
};

u32 dpp_dtb_dump_sdt_addr_get(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u64 *phy_addr,
			      u64 *vir_addr, u32 *size);
u32 dpp_dtb_queue_requst(struct dpp_dev_t *dev, const u8 *pName, u16 vPort, u32 *pQueueId);
DPP_STATUS dpp_dtb_queue_requst_ex(struct dpp_dev_t *dev, const u8 *pName, u32 *p_queue_id);
u32 dpp_dtb_queue_release(struct dpp_dev_t *dev, const u8 *pName, u32 queueId);
u32 dpp_dtb_queue_release_ex(struct dpp_dev_t *dev);
u32 dpp_dtb_queue_sync_cfg(struct dpp_dev_t *dev, const u8 *pName, u16 vPort, u32 queueId);
u32 dpp_dtb_queue_release_soft(struct dpp_dev_t *dev);
u32 dpp_dtb_user_info_set(struct dpp_dev_t *dev, u32 queueId, u16 vPort, u32 vector);
u32 dpp_dtb_queue_down_table_addr_set(struct dpp_dev_t *dev, u32 queueId, u64 phyAddr, u64 virAddr);
u32 dpp_dtb_queue_dump_table_addr_set(struct dpp_dev_t *dev, u32 queueId, u64 phyAddr, u64 virAddr);
u32 dpp_dtb_dump_sdt_addr_set(struct dpp_dev_t *dev, u32 queueId, u32 sdtNo, u64 phyAddr,
			      u64 virAddr, u32 size);
u32 dpp_dtb_dump_sdt_addr_clear(struct dpp_dev_t *dev, u32 queueId, u32 sdtNo);
DPP_STATUS dpp_dtb_hash_offline_delete(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no);
DPP_STATUS dpp_dtb_hash_online_delete(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no);
DPP_STATUS dpp_dtb_acl_index_request(struct dpp_dev_t *dev, u32 sdt_no, u32 vport, u32 *p_index);
DPP_STATUS dpp_dtb_acl_index_release(struct dpp_dev_t *dev, u32 sdt_no, u32 vport, u32 index);
DPP_STATUS dpp_dtb_acl_offline_delete(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u32 vport,
				      u32 counter_id, u32 rd_mode);
DPP_STATUS dpp_dtb_stat_ppu_cnt_clr(struct dpp_dev_t *dev, u32 queue_id,
				    enum stat_cnt_mode_e rd_mode, u32 start_count_id, u32 num);
DPP_STATUS dpp_dtb_acl_stat_clr_by_vport(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u32 vport,
					 enum stat_cnt_mode_e rd_mode, u32 start_counter_id);
u32 dpp_pcie_bar_msg_num_get(struct dpp_dev_t *dev, u32 *p_bar_msg_num);

#endif

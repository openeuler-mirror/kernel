/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_DTB_H_
#define _DPP_DTB_H_
#include "dpp_dtb_cfg.h"

#define DPP_DTB_QUEUE_ITEM_NUM_MAX (32)

#define DPP_DTB_ITEM_ACK_SIZE (16)
#define DPP_DTB_ITEM_BUFF_SIZE (16 * 1024)
#define DPP_DTB_ITEM_SIZE (16 + 16 * 1024)
#define DPP_DTB_TAB_UP_SIZE ((16 + 16 * 1024) * 32)
#define DPP_DTB_TAB_DOWN_SIZE ((16 + 16 * 1024) * 32)

#define DPP_DTB_TAB_UP_ACK_VLD_MASK (0x555555)
#define DPP_DTB_TAB_DOWN_ACK_VLD_MASK (0x5a5a5a)
#define DPP_DTB_TAB_ACK_IS_USING_MASK (0x11111100)
#define DPP_DTB_TAB_ACK_UNUSED_MASK (0x0)
#define DPP_DTB_TAB_ACK_SUCCESS_MASK (0xff)
#define DPP_DTB_TAB_ACK_FAILED_MASK (0x1)
#define DPP_DTB_TAB_ACK_CHECK_VALUE (0x12345678)

#define DPP_DTB_TAB_ACK_VLD_SHIFT (104)
#define DPP_DTB_TAB_ACK_STATUS_SHIFT (96)

#define DPP_DTB_TAB_UP_PHY_ADDR_GET(SLOT_ID, DEV_ID, QUEUE_ID, INDEX)                 \
	(p_dpp_dtb_mgr[SLOT_ID][DEV_ID]->queue_info[QUEUE_ID].tab_up.start_phy_addr + \
	 INDEX * p_dpp_dtb_mgr[SLOT_ID][DEV_ID]->queue_info[QUEUE_ID].tab_up.item_size)
#define DPP_DTB_TAB_UP_USER_PHY_ADDR_GET(SLOT_ID, DEV_ID, QUEUE_ID, INDEX) \
	(p_dpp_dtb_mgr[SLOT_ID][DEV_ID]->queue_info[QUEUE_ID].tab_up.user_addr[INDEX].phy_addr)
#define DPP_DTB_TAB_UP_USER_PHY_ADDR_FLAG_GET(SLOT_ID, DEV_ID, QUEUE_ID, INDEX) \
	(p_dpp_dtb_mgr[SLOT_ID][DEV_ID]->queue_info[QUEUE_ID].tab_up.user_addr[INDEX].user_flag)
#define DPP_DTB_TAB_DOWN_PHY_ADDR_GET(SLOT_ID, DEV_ID, QUEUE_ID, INDEX)                 \
	(p_dpp_dtb_mgr[SLOT_ID][DEV_ID]->queue_info[QUEUE_ID].tab_down.start_phy_addr + \
	 INDEX * p_dpp_dtb_mgr[SLOT_ID][DEV_ID]->queue_info[QUEUE_ID].tab_down.item_size)
#define DPP_DTB_TAB_UP_VIR_ADDR_GET(SLOT_ID, DEV_ID, QUEUE_ID, INDEX)                 \
	(p_dpp_dtb_mgr[SLOT_ID][DEV_ID]->queue_info[QUEUE_ID].tab_up.start_vir_addr + \
	 INDEX * p_dpp_dtb_mgr[SLOT_ID][DEV_ID]->queue_info[QUEUE_ID].tab_up.item_size)
#define DPP_DTB_TAB_UP_USER_VIR_ADDR_GET(SLOT_ID, DEV_ID, QUEUE_ID, INDEX) \
	(p_dpp_dtb_mgr[SLOT_ID][DEV_ID]->queue_info[QUEUE_ID].tab_up.user_addr[INDEX].vir_addr)
#define DPP_DTB_TAB_DOWN_VIR_ADDR_GET(SLOT_ID, DEV_ID, QUEUE_ID, INDEX)                 \
	(p_dpp_dtb_mgr[SLOT_ID][DEV_ID]->queue_info[QUEUE_ID].tab_down.start_vir_addr + \
	 INDEX * p_dpp_dtb_mgr[SLOT_ID][DEV_ID]->queue_info[QUEUE_ID].tab_down.item_size)
#define DPP_DTB_TAB_UP_WR_INDEX_GET(SLOT_ID, DEV_ID, QUEUE_ID) \
	(p_dpp_dtb_mgr[SLOT_ID][DEV_ID]->queue_info[QUEUE_ID].tab_up.wr_index)
#define DPP_DTB_TAB_UP_RD_INDEX_GET(SLOT_ID, DEV_ID, QUEUE_ID) \
	(p_dpp_dtb_mgr[SLOT_ID][DEV_ID]->queue_info[QUEUE_ID].tab_up.rd_index)
#define DPP_DTB_TAB_DOWN_WR_INDEX_GET(SLOT_ID, DEV_ID, QUEUE_ID) \
	(p_dpp_dtb_mgr[SLOT_ID][DEV_ID]->queue_info[QUEUE_ID].tab_down.wr_index)
#define DPP_DTB_TAB_DOWN_RD_INDEX_GET(SLOT_ID, DEV_ID, QUEUE_ID) \
	(p_dpp_dtb_mgr[SLOT_ID][DEV_ID]->queue_info[QUEUE_ID].tab_down.rd_index)
#define DPP_DTB_TAB_UP_DATA_LEN_GET(SLOT_ID, DEV_ID, QUEUE_ID, INDEX) \
	(p_dpp_dtb_mgr[SLOT_ID][DEV_ID]->queue_info[QUEUE_ID].tab_up.data_len[INDEX])
#define DPP_DTB_QUEUE_INIT_FLAG_GET(SLOT_ID, DEV_ID, QUEUE_ID) \
	(p_dpp_dtb_mgr[SLOT_ID][DEV_ID]->queue_info[QUEUE_ID].init_flag)
#define DPP_DTB_QUEUE_VPORT_GET(SLOT_ID, DEV_ID, QUEUE_ID) \
	(p_dpp_dtb_mgr[SLOT_ID][DEV_ID]->queue_info[QUEUE_ID].vport)

#define DPP_BDRING_ITEM_SIZE (16)

#define DPP_UP_MAC_BD_ITEM_NUM (0XFF)

#define DPP_BD_ITEM_NUM_MAX (0XFF)
#define DPP_UP_BD_BUFF_SIZE_MAX (4 * 1024)

#define DPP_UP_MAC_BD_ITEM_SIZE ((DPP_UP_MAC_BD_ITEM_NUM + 1) * DPP_BDRING_ITEM_SIZE)
#define DPP_UP_MAC_BUFF_SIZE (16 * 1024)
#define DPP_UP_MAC_BD_BUFF_SIZE (DPP_UP_MAC_BD_ITEM_NUM * DPP_UP_MAC_BUFF_SIZE)
#define DPP_UP_MAC_BD_TOTAL_SIZE (DPP_UP_MAC_BD_ITEM_SIZE + DPP_UP_MAC_BD_BUFF_SIZE)
#define DPP_DMA_BUFF_SIZE (4 * 1024 * 1024)

#define DPP_DMA_BD_VLD_MSK (0x80000000)
#define DPP_DMA_BD_DATA_LEN_MSK (0x7FF)

#define DPP_EP_ID_MAX (16)

#define DPP_DTB_LEN_MIN (1)
#define DPP_DTB_DOWN_LEN (0x3FF)

#define DPP_DMA_HASH_KEY_OFFSET (6)
#define DPP_DMA_HASH_ITEM_MAX (64)
#define DPP_DMA_HASH_KEY_RST (DPP_DMA_HASH_ITEM_MAX - DPP_DMA_HASH_KEY_OFFSET)

#define DPP_DMA_SENDTYPE_START_BIT (23)
#define DPP_DMA_SENDTYPE_BIT_NUM (2)
#define DPP_DMA_VALID_START_BIT (23)
#define DPP_DMA_VALID_BIT_NUM (1)
#define DPP_DMA_HASHID_START_BIT (21)
#define DPP_DMA_HASHID_BIT_NUM (2)
#define DPP_DMA_TBLID_START_BIT (16)
#define DPP_DMA_TBLID_BIT_NUM (2)

struct dpp_dtb_queue_cfg_t {
	ZXIC_ADDR_T up_start_phy_addr;
	ZXIC_ADDR_T up_start_vir_addr;
	ZXIC_ADDR_T down_start_phy_addr;
	ZXIC_ADDR_T down_start_vir_addr;

	u32 up_item_size;
	u32 down_item_size;
};

struct dpp_dtb_tab_up_user_addr_t {
	u32 user_flag;

	ZXIC_ADDR_T phy_addr;
	ZXIC_ADDR_T vir_addr;
};

struct dpp_dtb_tab_up_info_t {
	ZXIC_ADDR_T start_phy_addr;
	ZXIC_ADDR_T start_vir_addr;
	u32 item_size;

	u32 wr_index;
	u32 rd_index;

	u32 data_len[DPP_DTB_QUEUE_ITEM_NUM_MAX];
	struct dpp_dtb_tab_up_user_addr_t user_addr[DPP_DTB_QUEUE_ITEM_NUM_MAX];
};

struct dpp_dtb_tab_down_info_t {
	ZXIC_ADDR_T start_phy_addr;
	ZXIC_ADDR_T start_vir_addr;
	u32 item_size;

	u32 wr_index;
	u32 rd_index;
};

struct dpp_dtb_queue_info_t {
	u32 init_flag;
	u32 slot_id;
	u32 vport;
	u32 vector;

	struct dpp_dtb_tab_up_info_t tab_up;
	struct dpp_dtb_tab_down_info_t tab_down;
};

struct dpp_dtb_mgr_t {
	struct dpp_dtb_queue_info_t queue_info[DPP_DTB_QUEUE_NUM_MAX];
};

enum dpp_dtb_dir_type_e {
	DPP_DTB_DIR_DOWN_TYPE = 0,
	DPP_DTB_DIR_UP_TYPE = 1,
	DPP_DTB_DIR_TYPE_MAX,
};

enum dpp_dtb_tab_up_user_addr_type_e {
	DPP_DTB_TAB_UP_NOUSER_ADDR_TYPE = 0,
	DPP_DTB_TAB_UP_USER_ADDR_TYPE = 1,
	DPP_DTB_TAB_UP_USER_ADDR_TYPE_MAX,
};

enum dpp_dma_send_type_e {
	DMA_LEARN_HASH = 0,
	DMA_DEL_HASH = 1,
	DMA_UPDATE_HASH = 2,
	DMA_ADD_HASH = 3,
	DMA_SEND_TYPE_MAX
};

struct dpp_dma_bd_t {
	ZXIC_ADDR_T bd_phy_addr;
	ZXIC_ADDR_T bd_vir_addr;
	ZXIC_ADDR_T buff_phy_addr;
	ZXIC_ADDR_T buff_vir_addr;
	u32 bd_index;
};

struct dpp_dma_mgr_t {
	u32 init;
	u32 endian_flag;
	struct dpp_dma_bd_t up_mac;
};

u32 dtb_table_function_switch_get(void);

u32 dtb_table_function_switch_enable(void);

u32 dtb_table_function_switch_disable(void);

u32 dpp_dtb_debug_fun_enable(void);

u32 dpp_dtb_debug_fun_disable(void);

u32 dpp_dtb_debug_fun_get(void);

u32 dpp_dtb_prt_enable(void);

u32 dpp_dtb_prt_disable(void);

u32 dpp_dtb_prt_get(void);

u32 dpp_dtb_soft_perf_test_set(u32 value);

u32 dpp_dtb_soft_perf_test_get(void);

u32 dpp_dtb_hardware_perf_test_set(u32 value);

u32 dpp_dtb_hardware_perf_test_get(void);

u32 dpp_dtb_down_table_overtime_set(u32 times_s);
u32 dpp_dtb_down_table_overtime_get(void);

u32 dpp_dtb_dump_table_overtime_set(u32 times_s);
u32 dpp_dtb_dump_table_overtime_get(void);

#if ZXIC_REAL("MGR")
u32 dpp_dtb_mgr_create(u32 slot_id, u32 dev_id);
u32 dpp_dtb_mgr_destory_all(void);
u32 dpp_dtb_mgr_destory(u32 slot_id, u32 dev_id);
u32 dpp_dtb_mgr_reset(u32 slot_id, u32 dev_id);
struct dpp_dtb_mgr_t *dpp_dtb_mgr_get(u32 slot_id, u32 dev_id);
#endif

#if ZXIC_REAL("ACK_RW")
u32 dpp_dtb_item_ack_rd(struct dpp_dev_t *dev, u32 queue_id, u32 dir_flag, u32 index, u32 pos,
			u32 *p_data);
u32 dpp_dtb_item_ack_wr(struct dpp_dev_t *dev, u32 queue_id, u32 dir_flag, u32 index, u32 pos,
			u32 data);
#endif

#if ZXIC_REAL("BUFF_RW")
u32 dpp_dtb_item_buff_rd(struct dpp_dev_t *dev, u32 queue_id, u32 dir_flag, u32 index, u32 pos,
			 u32 len, u32 *p_data);
u32 dpp_dtb_item_buff_wr(struct dpp_dev_t *dev, u32 queue_id, u32 dir_flag, u32 index, u32 pos,
			 u32 len, u32 *p_data);
#endif

#if ZXIC_REAL("API")
u32 dpp_dtb_tab_down_info_set(struct dpp_dev_t *dev, u32 queue_id, u32 int_flag, u32 data_len,
			      u32 *p_data, u32 *p_item_index);
u32 dpp_dtb_tab_down_success_status_check(struct dpp_dev_t *dev, u32 queue_id, u32 element_id);
u32 dpp_dtb_tab_up_free_item_get(struct dpp_dev_t *dev, u32 queue_id, u32 *p_item_index);
u32 dpp_dtb_tab_up_item_addr_get(struct dpp_dev_t *dev, u32 queue_id, u32 item_index,
				 u32 *p_phy_haddr, u32 *p_phy_laddr);
u32 dpp_dtb_tab_up_item_offset_addr_get(struct dpp_dev_t *dev, u32 queue_id, u32 item_index,
					u32 addr_offset, u32 *p_phy_haddr, u32 *p_phy_laddr);
u32 dpp_dtb_tab_up_item_user_addr_set(struct dpp_dev_t *dev, u32 queue_id, u32 item_index,
				      ZXIC_ADDR_T phy_addr, ZXIC_ADDR_T vir_addr);
u32 dpp_dtb_tab_up_item_user_addr_clr(struct dpp_dev_t *dev, u32 queue_id, u32 item_index);
u32 dpp_dtb_tab_up_info_set(struct dpp_dev_t *dev, u32 queue_id, u32 item_index, u32 int_flag,
			    u32 data_len, u32 desc_len, u32 *p_desc_data);
u32 dpp_dtb_tab_up_success_status_check(struct dpp_dev_t *dev, u32 queue_id, u32 element_id);
u32 dpp_dtb_tab_up_data_get(struct dpp_dev_t *dev, u32 queue_id, u32 item_index, u32 data_len,
			    u32 *p_data);
u32 dpp_dtb_init(struct dpp_dev_t *dev);
u32 dpp_dtb_queue_down_init(struct dpp_dev_t *dev, u32 queue_id,
			    struct dpp_dtb_queue_cfg_t *p_queue_cfg);
u32 dpp_dtb_queue_dump_init(struct dpp_dev_t *dev, u32 queue_id,
			    struct dpp_dtb_queue_cfg_t *p_queue_cfg);
u32 dpp_dtb_down_channel_addr_set(struct dpp_dev_t *dev, u32 channelId, u64 phyAddr, u64 virAddr,
				  u32 size);
u32 dpp_dtb_dump_channel_addr_set(struct dpp_dev_t *dev, u32 channelId, u64 phyAddr, u64 virAddr,
				  u32 size);
u32 dpp_dtb_queue_id_free(struct dpp_dev_t *dev, u32 queue_id);
u32 dpp_dtb_queue_id_search_by_vport(struct dpp_dev_t *dev, u32 *p_queue_arr, u32 *p_num);
u32 dpp_dtb_queue_id_get(struct dpp_dev_t *dev, u32 *queue);
u32 dpp_dtb_queue_valid_flag_get(struct dpp_dev_t *dev, u32 queue, u32 *valid_flag);
u32 dpp_dtb_queue_init_flag_get(struct dpp_dev_t *dev, u32 queue, u32 *init_flag);

#endif

#if ZXIC_REAL("DMA")

#endif

#endif

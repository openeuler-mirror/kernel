/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_DTB_TABLE_H_
#define _DPP_DTB_TABLE_H_
#include "dpp_dev.h"
#include "dpp_hash.h"
#include "dpp_etcam.h"
#include "dpp_dtb_table_api.h"

#define DISABLE (0)
#define ENABLE (1)

#define DTB_DOWN_TABLE_CMD (0)
#define DTB_DUMP_TABLE_CMD (1)

#define DTB_QUEUE_MAX (128)
#define DTB_QUEUE_ELEMENT_MAX (32)
#define DTB_DATA_SIZE_BIT (16 * 1024 * 8)
#define DPP_DTB_TABLE_DATA_BUFF_SIZE (1024 * 16)
#define DPP_DTB_TABLE_DUMP_INFO_BUFF_SIZE (1024 * 4)
#define DTB_TABLE_CMD_SIZE_BIT (128)
#define DTB_TABLE_CMD_SIZE_BYTE (16)
#define DTB_ERAM_DATA_SIZE_1b (128)
#define DTB_ERAM_DATA_SIZE_64b (128)
#define DTB_ERAM_DATA_SIZE_128b (256)
#define DTB_ERAM_ENTRY_CNT_MAX_1b (DTB_DATA_SIZE_BIT / DTB_ERAM_DATA_SIZE_1b)
#define DTB_ERAM_ENTRY_CNT_MAX_64b (DTB_DATA_SIZE_BIT / DTB_ERAM_DATA_SIZE_64b)
#define DTB_ERAM_ENTRY_CNT_MAX_128b (DTB_DATA_SIZE_BIT / DTB_ERAM_DATA_SIZE_128b)
#define DTB_ZCAM_LEN_SIZE (5)
#define DTB_ETCAM_LEN_SIZE (6)
#define DTB_MC_HASH_LEN_SIZE (5)
#define DTB_ZCAM_DATA_SIZE ((u32)(64))
#define DTB_DMUP_DATA_MAX ((u32)(4 * 1024 * 1024))
#define DTB_DUMP_DDR_ITEMS_MAX (0x10000)

#define DTB_SDT_DUMP_SIZE (0x400000) //4MB

#define DTB_TABLE_VALID (1)
#define DTB_LEN_POS_SETP (16)

#define LPM_IPV4 (1)
#define LPM_IPV6 (0)
#define LPM_ENABLE (1)
#define LPM_DISABLE (0)

#define DTB_TABLE_MODE_ERAM (0)
#define DTB_TABLE_MODE_DDR (1)
#define DTB_TABLE_MODE_ZCAM (2)
#define DTB_TABLE_MODE_ETCAM (3)
#define DTB_TABLE_MODE_MC_HASH (4)

#define DTB_DUMP_MODE_ERAM (0)
#define DTB_DUMP_MODE_DDR (1)
#define DTB_DUMP_MODE_ZCAM (2)
#define DTB_DUMP_MODE_ETCAM (3)

#define DTB_ITEM_ADD_OR_UPDATE (0)
#define DTB_ITEM_DELETE (1)

extern u32 g_lpm_hw_dat_offset;

enum dpp_dtb_table_info_e {
	DTB_TABLE_DDR = 0,
	DTB_TABLE_ERAM_1 = 1,
	DTB_TABLE_ERAM_64 = 2,
	DTB_TABLE_ERAM_128 = 3,
	DTB_TABLE_ZCAM = 4,
	DTB_TABLE_ETCAM = 5,
	DTB_TABLE_MC_HASH = 6,
	DTB_TABLE_ENUM_MAX
};

enum dpp_dtb_dump_info_e {
	DTB_DUMP_ERAM = 0,
	DTB_DUMP_DDR = 1,
	DTB_DUMP_ZCAM = 2,
	DTB_DUMP_ETCAM = 3,
	DTB_DUMP_ENUM_MAX
};

enum dpp_dtb_dump_zcam_width_e {
	DTB_DUMP_ZCAM_128b = 0,
	DTB_DUMP_ZCAM_256b = 1,
	DTB_DUMP_ZCAM_512b = 2,
	DTB_DUMP_ZCAM_RSV = 3,
};

enum dpp_dtb_dump_etcam_width_e {
	DTB_DUMP_ETCAM_80b = 0,
	DTB_DUMP_ETCAM_160b = 1,
	DTB_DUMP_ETCAM_320b = 2,
	DTB_DUMP_ETCAM_640b = 3,
	DTB_DUMP_ETCAM_MAX
};

struct dpp_dtb_ddr_table_form_t {
	u32 valid;
	u32 type_mode; /* DDR：0x1 */
	u32 rw_len;
	u32 v46_flag; /*1：IPV4  0:IPV6*/
	u32 lpm_wr_vld;
	u32 baddr;
	u32 ecc_en;
	u32 rw_addr;
};

struct dpp_dtb_eram_table_form_t {
	u32 valid;
	u32 type_mode; /* ERAM：0x0 */
	u32 data_mode;
	u32 cpu_wr;
	u32 cpu_rd;
	u32 cpu_rd_mode;
	u32 addr;
	u32 data_h;
	u32 data_l;
};

struct dpp_dtb_zcam_table_form_t {
	u32 valid;
	u32 type_mode; /* zcam：0x2 */
	u32 ram_reg_flag;
	u32 zgroup_id; /* zgroup id */
	u32 zblock_id; /* zblock id */
	u32 zcell_id; /* zcell id */
	u32 mask;
	u32 sram_addr;
};

struct dpp_dtb_etcam_table_form_t {
	u32 valid;
	u32 type_mode; /* etcam：0x3 */
	u32 block_sel;
	u32 init_en;
	u32 row_or_col_msk; /* 1 write row mask reg  0:write col mask reg*/
	u32 vben; /* enable the valid bit addressed by addr*/
	u32 reg_tcam_flag;
	u32 uload;
	u32 rd_wr;
	u32 wr_mode;
	u32 data_or_mask;
	u32 addr;
	u32 vbit; /*valid bit input*/
};

struct dpp_dtb_mc_hash_table_form_t {
	u32 valid;
	u32 type_mode;
	u32 std_h;
	u32 std_l;
};

struct dpp_dtb_eram_dump_form_t {
	u32 valid;
	u32 up_type; /* 00:eram */
	u32 base_addr;
	u32 tb_depth;
	u32 tb_dst_addr_h;
	u32 tb_dst_addr_l;
};

struct dpp_dtb_ddr_dump_form_t {
	u32 valid;
	u32 up_type; /* 01:ddr */
	u32 base_addr;
	u32 tb_depth;
	u32 tb_dst_addr_h;
	u32 tb_dst_addr_l;
};

struct dpp_dtb_zcam_dump_form_t {
	u32 valid;
	u32 up_type; /* 10:zcam */
	u32 zgroup_id; /*  */
	u32 zblock_id; /*  */
	u32 ram_reg_flag;
	u32 z_reg_cell_id;
	u32 sram_addr;
	u32 tb_depth;
	u32 tb_width;
	u32 tb_dst_addr_h;
	u32 tb_dst_addr_l;
};
struct dpp_dtb_etcam_dump_form_t {
	u32 valid;
	u32 up_type; /* 11:etcam */
	u32 block_sel; /* block num */
	u32 addr;
	u32 rd_mode;
	u32 data_or_mask; /* data：1 mask：0*/
	u32 tb_depth;
	u32 tb_width;
	u32 tb_dst_addr_h;
	u32 tb_dst_addr_l;
};

struct etcam_dump_info_t {
	u32 block_sel; /* block index 0-7 */
	u32 addr;
	u32 rd_mode;
	u32 data_or_mask;
	u32 tb_depth;
	u32 tb_width;
};

struct dpp_dtb_field_t {
	char *p_name;
	u16 lsb_pos;
	u16 len;
};

struct dpp_dtb_table_t {
	char *table_type;
	u32 table_no;
	u32 field_num;
	struct dpp_dtb_field_t *p_fields;
};

struct dpp_dtb_entry_t {
	u8 *cmd;
	u8 *data;
	u32 data_in_cmd_flag;
	u32 data_size;
};

struct dpp_dtb_cmd_t {
	u32 queue_id;
	u32 dtb_phy_addr_hi32;
	u32 dtb_phy_addr_lo32;
	u32 cmd_type;
	u32 int_enable;
	u32 dtb_len;
};

struct dpp_dtb_mc_hash_key_t {
	u32 hash_key[16];
};

struct dpp_dtb_mixed_table_t {
	u32 down_cmd_len;
	u32 dump_cmd_len;
	u32 down_buff_offset;
	u32 dump_buff_offset;
	u8 *p_down_cmd_buff;
	u8 *p_dump_cmd_buff;
};

struct dpp_dtb_mc_hash_entry_info_t {
	u32 delete_en;
	u32 dma_en;
	u32 *p_data;
};
DPP_STATUS dpp_dtb_interrupt_status_set(u32 int_enable);
u32 dpp_dtb_interrupt_status_get(void);
DPP_STATUS dpp_dtb_cmd_endian_status_set(u32 endian);
DPP_STATUS dpp_dtb_cmd_endian_status_get(void);
DPP_STATUS dpp_dtb_smmu0_data_write(struct dpp_dev_t *dev, u32 queue_id, u32 smmu0_base_addr,
				    u32 smmu0_wr_mode, u32 entry_num,
				    struct dpp_dtb_eram_entry_info_t *p_entry_arr, u32 *element_id);
DPP_STATUS dpp_dtb_smmu0_flush(struct dpp_dev_t *dev, u32 queue_id, u32 smmu0_base_addr,
			       u32 smmu0_wr_mode, u32 start_index, u32 entry_num, u32 *element_id);
DPP_STATUS dpp_dtb_eram_dma_write(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u32 entry_num,
				  struct dpp_dtb_eram_entry_info_t *p_entry_arr, u32 *element_id);
DPP_STATUS dpp_dtb_hash_dma_insert(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u32 entry_num,
				   struct dpp_dtb_hash_entry_info_t *p_arr_hash_entry,
				   u32 *element_id);
DPP_STATUS dpp_dtb_hash_dma_delete(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u32 entry_num,
				   struct dpp_dtb_hash_entry_info_t *p_arr_hash_entry,
				   u32 *element_id);
DPP_STATUS
dpp_dtb_hash_dma_delete_cycle(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u32 entry_num,
			      struct dpp_dtb_hash_entry_info_t *p_arr_hash_entry, u32 *element_id);
DPP_STATUS dpp_dtb_acl_dma_insert(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u32 entry_num,
				  struct dpp_dtb_acl_entry_info_t *p_acl_entry_arr,
				  u32 *element_id);
DPP_STATUS dpp_dtb_eram_data_get(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no,
				 struct dpp_dtb_eram_entry_info_t *p_dump_eram_entry);
DPP_STATUS dpp_dtb_eram_stat_data_get(struct dpp_dev_t *dev, u32 queue_id, u32 base_addr,
				      u32 rd_mode, u32 index, u32 *p_data);
void dpp_dtb_srh_mode_set(u32 srh_mode);
u32 dpp_dtb_srh_mode_get(void);
u32 dpp_dtb_hash_data_get(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no,
			  struct dpp_dtb_hash_entry_info_t *p_dtb_hash_entry, u32 srh_mode);

u32 dpp_dtb_hash_zcam_get(struct dpp_dev_t *dev, u32 queue_id,
			  struct hash_entry_cfg *p_hash_entry_cfg,
			  struct dpp_hash_entry *p_hash_entry, u32 srh_mode, u8 *p_srh_succ);

DPP_STATUS dpp_dtb_hash_zcam_get_hardware(struct dpp_dev_t *dev, u32 queue_id,
					  struct hash_entry_cfg *p_hash_entry_cfg,
					  struct dpp_hash_entry *p_hash_entry, u8 *p_srh_succ);

DPP_STATUS dpp_dtb_hash_get_software(struct dpp_dev_t *dev, struct hash_entry_cfg *p_hash_entry_cfg,
				     struct dpp_hash_entry *p_hash_entry, u8 *p_srh_succ);
DPP_STATUS dpp_dtb_acl_data_get(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no,
				struct dpp_dtb_acl_entry_info_t *p_dump_acl_entry);
DPP_STATUS dpp_dtb_etcam_data_get(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no,
				  struct dpp_dtb_acl_entry_info_t *p_dump_acl_entry);
DPP_STATUS dpp_dtb_zcam_space_clr(struct dpp_dev_t *dev, struct dpp_se_cfg *p_se_cfg, u32 queue_id,
				  u32 fun_id);
DPP_STATUS dpp_dtb_eram_table_flush(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no);
DPP_STATUS dpp_dtb_hash_table_flush(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no);
DPP_STATUS dpp_dtb_hash_all_entry_delete(struct dpp_dev_t *dev, u32 queue_id, u32 hash_id);
DPP_STATUS dpp_dtb_etcam_table_flush(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no);
DPP_STATUS dpp_dtb_eram_table_dump(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no,
				   struct dpp_dtb_dump_index_t start_index,
				   struct dpp_dtb_eram_entry_info_t *p_dump_data_arr,
				   u32 *entry_num, struct dpp_dtb_dump_index_t *next_start_index,
				   u32 *finish_flag);
DPP_STATUS dpp_dtb_eram_dump(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u8 *pDumpData,
			     u32 *p_entry_num);
DPP_STATUS dpp_dtb_hash_table_only_zcam_dump(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no,
					     u8 *pDumpData, u32 *entryNum);
DPP_STATUS dpp_dtb_acl_table_dump(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no,
				  struct dpp_dtb_dump_index_t start_index,
				  struct dpp_dtb_acl_entry_info_t *p_dump_data_arr, u32 *entry_num,
				  struct dpp_dtb_dump_index_t *next_start_index, u32 *finish_flag);
DPP_STATUS dpp_dtb_acl_dump(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u8 *pDumpData,
			    u32 *p_entry_num);

void dpp_data_buff_print(u8 *buff, u32 size);
void dpp_acl_data_print(u8 *p_data, u8 *p_mask, u32 etcam_mode);
void dpp_dtb_data_print(u8 *p_data, u32 len);

u32 dpp_ddr_index_calc(u32 index, u32 width_mode, u32 key_type, u32 byte_offset);

DPP_STATUS
dpp_dtb_hash_dma_delete_hardware(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u32 entry_num,
				 struct dpp_dtb_hash_entry_info_t *p_arr_hash_entry,
				 u32 *element_id);

u32 dpp_dtb_hash_zcam_delete_hardware(struct dpp_dev_t *dev, u32 queue_id,
				      struct hash_entry_cfg *p_hash_entry_cfg,
				      struct dpp_hash_entry *p_hash_entry,
				      struct dpp_dtb_entry_t *p_entry, u8 *p_srh_succ);

DPP_STATUS dpp_dtb_se_zcam_dma_dump(struct dpp_dev_t *dev, u32 queue_id, u32 addr, u32 tb_width,
				    u32 depth, u32 *p_data, u32 *element_id);

DPP_STATUS dpp_dtb_hash_dump(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u8 *pDumpData,
			     u32 *p_entry_num);

u32 dpp_dtb_hash_data_parse(u32 item_type, u32 key_by_size, struct dpp_hash_entry *p_entry,
			    u8 *p_item_data, u8 *p_data_offset);
DPP_STATUS dpp_dtb_acl_index_release_by_vport(struct dpp_dev_t *dev, u32 sdt_no, u32 vport);
DPP_STATUS dpp_dtb_acl_index_parse(struct dpp_dev_t *dev, u32 queue_id, u32 eram_sdt_no, u32 vport,
				   u32 *index_num, u32 *p_index_array);
DPP_STATUS dpp_dtb_eram_data_clear(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u32 index_num,
				   u32 *p_index_array);
DPP_STATUS dpp_dtb_eram_stat_data_clear(struct dpp_dev_t *dev, u32 queue_id, u32 counter_id,
					enum stat_cnt_mode_e rd_mode, u32 index_num,
					u32 *p_index_array);
DPP_STATUS dpp_dtb_acl_data_clear(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u32 index_num,
				  u32 *p_index_array);
DPP_STATUS dpp_dtb_acl_stat_cnt_clr(struct dpp_dev_t *dev, u32 sdt_no, u32 vport,
				    enum stat_cnt_mode_e rd_mode, u32 start_counter_id);

#endif

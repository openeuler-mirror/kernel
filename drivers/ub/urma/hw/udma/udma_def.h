/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#ifndef __UDMA_DEF_H__
#define __UDMA_DEF_H__

#include <linux/types.h>
#include <linux/auxiliary_bus.h>
#include <linux/ummu_core.h>
#include <ub/urma/ubcore_types.h>
#include <ub/ubase/ubase_comm_mbx.h>

#define UDMA_AE_EVENT_TYPE 4
#define UDMA_CQE_NUM_PER_TYPE 2
#define NUM_JETTY_PER_GROUP 32

enum {
	UDMA_CAP_FEATURE_AR				= BIT(0),
	UDMA_CAP_FEATURE_JFC_INLINE			= BIT(4),
	UDMA_CAP_FEATURE_DIRECT_WQE			= BIT(11),
	UDMA_CAP_FEATURE_CONG_CTRL			= BIT(16),
	UDMA_CAP_FEATURE_REDUCE				= BIT(17),
	UDMA_CAP_FEATURE_UE_RX_CLOSE			= BIT(18),
	UDMA_CAP_FEATURE_RNR_RETRY			= BIT(19),
	UDMA_CAP_FEATURE_WRITE_ATOMIC_ADD	        = BIT(21),
	UDMA_CAP_FEATURE_RC_CTP_MULTIPLE_PATH_MODE	= BIT(26),
	UDMA_CAP_FEATURE_NOT_SHARE_JFC			= BIT(27),
	UDMA_CAP_FEATURE_PORT_CHANGE_AE			= BIT(29),
};

struct udma_res {
	uint32_t max_cnt;
	uint32_t start_idx;
	uint32_t next_idx;
	uint32_t depth;
};

struct udma_tbl {
	uint32_t max_cnt;
	uint32_t size;
};

struct udma_ucp_caps {
	struct udma_res ucp_jetty;
	struct udma_res ucp_jfc;
	struct udma_res ucp_jfr;
};

struct udma_udp_sport {
	spinlock_t lock;
	uint16_t ack_udp_srcport;
	uint16_t data_udp_srcport;
	uint8_t udp_srcport_range : 4;
	uint8_t spray_en	  : 1;
	uint8_t udp_global_en	  : 1;
};

struct udma_caps {
	struct udma_res jfs;
	struct udma_res jfr;
	struct udma_res jfc;
	struct udma_res jetty;
	struct udma_res jetty_grp;
	uint32_t jetty_in_grp;
	uint32_t jfs_sge;
	uint32_t jfr_sge;
	uint32_t jfs_rsge;
	uint32_t jfs_inline_sz;
	uint32_t comp_vector_cnt;
	uint16_t ue_cnt;
	uint8_t ue_id;
	uint32_t trans_mode;
	uint32_t max_msg_len;
	uint32_t feature;
	uint32_t rsvd_jetty_cnt;
	uint32_t max_read_size;
	uint32_t max_write_size;
	uint32_t max_cas_size;
	uint32_t max_fetch_and_add_size;
	uint32_t atomic_feat;
	struct udma_res ccu_jetty;
	struct udma_res hdc_jetty;
	struct udma_res stars_jetty;
	struct udma_res public_jetty;
	struct udma_res user_ctrl_normal_jetty;
	struct udma_res ccu_jfc;
	struct udma_res stars_jfc;
	struct udma_ucp_caps ucp_caps;
	uint8_t ack_queue_num;
	uint8_t port_num;
	uint8_t cqe_size;
	struct udma_tbl seid;
	struct udma_udp_sport udp;
	uint32_t rc_max_cnt;
	bool no_share_jfc_en;
	bool ctp_en;
	bool ipourma_en;
	bool sva_sep_mode_en;
	bool non_mirror_en;
	bool st64b_en;
	bool atomic_add_en;
};

struct udma_dfx_jetty {
	uint32_t		id;
	uint32_t		jfs_depth;
};

struct udma_dfx_jfs {
	uint32_t		id;
	uint32_t		depth;
};

struct udma_dfx_seg {
	uint32_t		id;
	struct ubcore_ubva	ubva;
	uint64_t		len;
	struct ubcore_token	token_value;
};

struct udma_dfx_entity {
	uint32_t		cnt;
	struct xarray		table;
	rwlock_t		rwlock;
};

struct udma_dfx_info {
	struct udma_dfx_entity	jetty;
	struct udma_dfx_entity	jetty_grp;
	struct udma_dfx_entity	jfs;
	struct udma_dfx_entity	jfr;
	struct udma_dfx_entity	jfc;
	struct udma_dfx_entity	seg;
};

struct udma_umem {
	struct ubcore_device *ub_dev;
	struct mm_struct *owning_mm;
	uint64_t length;
	uint64_t va;
	union ubcore_umem_flag flag;
	struct sg_append_table append;
	uint32_t nmap;
	bool is_writable;
};

struct udma_sw_db_page {
	struct list_head list;
	struct udma_umem *umem;
	uint64_t user_virt;
	refcount_t refcount;
};

struct udma_hugepage_priv {
	struct list_head list;
	uint32_t seq;
	struct page **pages;
	uint32_t page_num;
	uint32_t page_size;
	struct udma_umem *umem;
	void *va_base;
	uint32_t va_len;
	uint32_t left_va_offset;
	uint32_t left_va_len;
	refcount_t refcnt;
	struct sg_table sgt;
};

struct udma_page_priv {
	struct list_head list;
	struct page **pages;
	uint32_t page_num;
	void *va_base;
	uint32_t va_len;
	struct sg_table sgt;
	refcount_t refcnt;
};

struct udma_hugepage {
	void *va_start;
	uint32_t va_len;
	struct udma_hugepage_priv *priv;
};

struct udma_buf {
	dma_addr_t		addr;
	struct page *pages;
	union {
		void			*kva; /* used for kernel mode */
		struct iova_slot	*slot;
		void			*kva_or_slot;
	};
	struct udma_umem	*umem;
	uint32_t		entry_size;
	uint32_t		entry_cnt;
	uint32_t		cnt_per_page_shift;
	struct xarray		id_table_xa;
	struct mutex		id_table_mutex;
	bool			is_hugepage;
	bool			k_dtu_enable;
	struct udma_hugepage	*hugepage;
	uint64_t		len;
	struct udma_page_priv	*page_priv;
};

struct udma_k_sw_db_page {
	struct list_head list;
	uint32_t num_db;
	unsigned long *bitmap;
	struct udma_buf db_buf;
};

struct udma_sw_db {
	struct udma_sw_db_page *page;
	struct udma_k_sw_db_page *kpage;
	uint32_t index;
	uint32_t type;
	uint64_t db_addr;
	uint32_t *db_record;
	void *virt_addr;
	struct udma_page_priv *page_priv;
};

struct udma_entity_buf {
	uint32_t len;
	uint32_t seq_num;
	uint8_t data[0];
};

struct udma_entity_msg {
	uint8_t dst_ue_idx;
	uint8_t opcode;
	uint16_t rsv;
	struct udma_entity_buf buf;
};

struct udma_sq_reserved_info {
	uint64_t va_start;
	uint64_t va_size;
	uint64_t va_per_ue;
	uint64_t size_per_ue;
	uint64_t size_per_jetty;
	bool sq_reserved;
};

struct udma_ae_event_type {
	uint8_t event_type;
	uint8_t sub_type;
};

struct udma_rc_ctx {
	/* DW0 */
	uint32_t rsv0 : 5;
	uint32_t type : 3;
	uint32_t rce_shift : 4;
	uint32_t rsv1 : 4;
	uint32_t state : 3;
	uint32_t rsv2 : 1;
	uint32_t rce_token_id_l : 12;
	/* DW1 */
	uint32_t rce_token_id_h : 8;
	uint32_t rsv3 : 4;
	uint32_t rce_base_addr_l : 20;
	/* DW2 */
	uint32_t rce_base_addr_h;
	/* DW3~DW31 */
	uint32_t rsv4[28];
	uint32_t avail_sgmt_ost : 10;
	uint32_t rsv5 : 22;
	/* DW32~DW63 */
	uint32_t rsv6[32];
};

#endif /* __UDMA_DEF_H__ */

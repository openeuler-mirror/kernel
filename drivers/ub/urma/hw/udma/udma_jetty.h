/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#ifndef __UDMA_JETTY_H__
#define __UDMA_JETTY_H__

#include "udma_common.h"

#define SQE_TOKEN_ID_L_MASK GENMASK(11, 0)
#define SQE_TOKEN_ID_H_OFFSET 12U
#define SQE_TOKEN_ID_H_MASK GENMASK(7, 0)
#define SQE_VA_L_OFFSET 12U
#define SQE_VA_L_VALID_BIT GENMASK(19, 0)
#define SQE_VA_H_OFFSET 32U
#define SQE_VA_H_VALID_BIT GENMASK(31, 0)
#define JETTY_CTX_JFRN_H_OFFSET 12
#define AVAIL_SGMT_OST_INIT 512
#define UDMA_JFS_MASK_OFFSET 128

#define SQE_PLD_TOKEN_ID_MASK GENMASK(19, 0)

#define UDMA_TA_TIMEOUT_128MS 128
#define UDMA_TA_TIMEOUT_1000MS 1000
#define UDMA_TA_TIMEOUT_8000MS 8000
#define UDMA_TA_TIMEOUT_64000MS 64000

#define UDMA_MAX_PRIORITY 16

#define UDMA_SET_JETTY_OPT_MAX_NUM 4
#define UDMA_SET_JFS_OPT_MAX_NUM 10

/* stub UBCORE */
enum udma_set_get_jetty_opt_perm {
	PERM_R = 1,
	PERM_W = 1 << 1,
};

enum udma_set_get_jetty_opt_ignore_attr {
	USER_IGNORE = 1,
	KERNEL_IGNORE = 1 << 1,
};

enum udma_set_get_jetty_opt_mode {
	JFS_MODE = 1,
	JETTY_MODE = 1 << 1,
};

enum jetty_state {
	JETTY_RESET,
	JETTY_READY,
	JETTY_ERROR,
	JETTY_SUSPEND,
	STATE_NUM,
};

struct udma_jetty_opt_info {
	uint32_t buf_len;
	enum udma_set_get_jetty_opt_perm perm;
	enum udma_set_get_jetty_opt_ignore_attr ignore_attr;
	enum udma_set_get_jetty_opt_mode mode;
};

struct udma_jetty_opt_attr {
	uint64_t opt;
	void *buf;
	uint32_t len;
	enum udma_set_get_jetty_opt_mode mode;
	enum udma_set_get_jetty_opt_perm perm;
	bool is_user;
};

struct udma_jetty {
	struct ubcore_jetty ubcore_jetty;
	struct udma_jfr *jfr;
	struct udma_jetty_queue sq;
	uint64_t jetty_addr;
	refcount_t ae_refcount;
	struct completion ae_comp;
	bool ue_rx_closed;
};

struct udma_target_jetty {
	struct ubcore_tjetty ubcore_tjetty;
	union ubcore_eid le_eid;
	uint32_t token_value;
	bool token_value_valid;
};

enum jfsc_mode {
	JFS,
	JETTY,
};

enum jetty_type {
	JETTY_RAW_OR_NIC,
	JETTY_UM,
	JETTY_RC,
	JETTY_RM,
	JETTY_TYPE_RESERVED,
};

struct udma_jetty_ctx {
	/* DW0 */
	uint32_t ta_timeout : 2;
	uint32_t rnr_retry_num : 3;
	uint32_t type : 3;
	uint32_t sqe_bb_shift : 4;
	uint32_t sl : 4;
	uint32_t state : 3;
	uint32_t jfs_mode : 1;
	uint32_t sqe_token_id_l : 12;
	/* DW1 */
	uint32_t sqe_token_id_h : 8;
	uint32_t err_mode : 1;
	uint32_t ctp_rc_mul_path_mode : 1;
	uint32_t cmp_odr : 1;
	uint32_t rsv1 : 1;
	uint32_t sqe_base_addr_l : 20;
	/* DW2 */
	uint32_t sqe_base_addr_h;
	/* DW3 */
	uint32_t rsv2;
	/* DW4 */
	uint32_t tx_jfcn : 20;
	uint32_t jfrn_l : 12;
	/* DW5 */
	uint32_t jfrn_h : 8;
	uint32_t rsv3 : 4;
	uint32_t rx_jfcn : 20;
	/* DW6 */
	uint32_t seid_idx : 10;
	uint32_t pi_type : 1;
	uint32_t rsv4 : 21;
	/* DW7 */
	uint32_t user_data_l;
	/* DW8 */
	uint32_t user_data_h;
	/* DW9 */
	uint32_t sqe_position : 1;
	uint32_t sqe_pld_position : 1;
	uint32_t sqe_pld_tokenid : 20;
	uint32_t rsv5 : 10;
	/* DW10 */
	uint32_t tpn : 24;
	uint32_t rsv6 : 8;
	/* DW11 */
	uint32_t rmt_eid : 20;
	uint32_t rsv7 : 12;
	/* DW12 */
	uint32_t rmt_tokenid : 20;
	uint32_t rsv8 : 12;
	/* DW13 - DW15 */
	uint32_t rsv8_1[3];
	/* DW16 */
	uint32_t next_send_ssn : 16;
	uint32_t src_order_wqe : 16;
	/* DW17 */
	uint32_t src_order_ssn : 16;
	uint32_t src_order_sgme_cnt : 16;
	/* DW18 */
	uint32_t src_order_sgme_send_cnt : 16;
	uint32_t CI : 16;
	/* DW19 */
	uint32_t wqe_sgmt_send_cnt : 20;
	uint32_t src_order_wqebb_num : 4;
	uint32_t src_order_wqe_vld : 1;
	uint32_t no_wqe_send_cnt : 4;
	uint32_t so_lp_vld : 1;
	uint32_t fence_lp_vld : 1;
	uint32_t strong_fence_lp_vld : 1;
	/* DW20 */
	uint32_t PI : 16;
	uint32_t sq_db_doing : 1;
	uint32_t ost_rce_credit : 15;
	/* DW21 */
	uint32_t sq_db_retrying : 1;
	uint32_t wmtp_rsv0 : 31;
	/* DW22 */
	uint32_t wait_ack_timeout : 1;
	uint32_t wait_rnr_timeout : 1;
	uint32_t cqe_ie : 1;
	uint32_t cqe_sz : 1;
	uint32_t wml_rsv0 : 28;
	/* DW23 */
	uint32_t wml_rsv1 : 32;
	/* DW24 */
	uint32_t next_rcv_ssn : 16;
	uint32_t next_cpl_bb_idx : 16;
	/* DW25 */
	uint32_t next_cpl_sgmt_num : 20;
	uint32_t we_rsv0 : 12;
	/* DW26 */
	uint32_t next_cpl_bb_num : 4;
	uint32_t next_cpl_cqe_en : 1;
	uint32_t next_cpl_info_vld : 1;
	uint32_t rpting_cqe : 1;
	uint32_t not_rpt_cqe : 1;
	uint32_t flush_ssn : 16;
	uint32_t flush_ssn_vld : 1;
	uint32_t flush_vld : 1;
	uint32_t flush_cqe_done : 1;
	uint32_t we_rsv1 : 5;
	/* DW27 */
	uint32_t rcved_cont_ssn_num : 20;
	uint32_t we_rsv2 : 12;
	/* DW28 */
	uint32_t sq_timer;
	/* DW29 */
	uint32_t rnr_cnt : 3;
	uint32_t abt_ssn : 16;
	uint32_t abt_ssn_vld : 1;
	uint32_t taack_timeout_flag : 1;
	uint32_t we_rsv3 : 9;
	uint32_t err_type_l : 2;
	/* DW30 */
	uint32_t err_type_h : 7;
	uint32_t sq_flush_ssn : 16;
	uint32_t we_rsv4 : 9;
	/* DW31 */
	uint32_t avail_sgmt_ost : 10;
	uint32_t read_op_cnt : 10;
	uint32_t we_rsv5 : 12;
	/* DW32 - DW63 */
	uint32_t taack_nack_bm[32];
};

struct udma_jetty_grp_ctx {
	uint32_t start_jetty_id : 16;
	uint32_t rsv : 11;
	uint32_t jetty_number : 5;
	uint32_t valid;
};

static inline uint32_t to_udma_type(uint32_t trans_mode)
{
	switch (trans_mode) {
	case UBCORE_TP_RM:
		return JETTY_RM;
	case UBCORE_TP_RC:
		return JETTY_RC;
	case UBCORE_TP_UM:
		return JETTY_UM;
	default:
		return JETTY_TYPE_RESERVED;
	}
}

static inline struct udma_jetty *to_udma_jetty(struct ubcore_jetty *jetty)
{
	return container_of(jetty, struct udma_jetty, ubcore_jetty);
}

static inline struct udma_target_jetty *to_udma_tjetty(struct ubcore_tjetty *tjetty)
{
	return container_of(tjetty, struct udma_target_jetty, ubcore_tjetty);
}

static inline struct udma_jetty *to_udma_jetty_from_queue(struct udma_jetty_queue *queue)
{
	return container_of(queue, struct udma_jetty, sq);
}

static inline uint32_t udma_get_ta_timeout(uint8_t gear)
{
#define GEAR_0	0
#define GEAR_1	1
#define GEAR_2	2
#define GEAR_3	3

	switch (gear) {
	case GEAR_0: return UDMA_TA_TIMEOUT_128MS;
	case GEAR_1: return UDMA_TA_TIMEOUT_1000MS;
	case GEAR_2: return UDMA_TA_TIMEOUT_8000MS;
	case GEAR_3: return UDMA_TA_TIMEOUT_64000MS;
	default: return UDMA_TA_TIMEOUT_64000MS;
	}
}

static inline uint8_t udma_get_ta_timeout_gear(struct udma_dev *udev, uint32_t err_timeout)
{
#define TA_TIMEOUT_DIVISOR 8
#define UDMA_TA_TIMEOUT_MAX_INDEX 3

	uint8_t ta_timeout_gear = err_timeout / TA_TIMEOUT_DIVISOR;
	uint32_t hw_ver = ubase_get_hw_ver(udev->comdev.adev);

	if ((ta_timeout_gear >= UDMA_TA_TIMEOUT_MAX_INDEX) &&
	    ((hw_ver == UBASE_HW_VER_A_0) || (hw_ver == UBASE_HW_VER_K_0)))
		ta_timeout_gear = (UDMA_TA_TIMEOUT_MAX_INDEX - 1);

	return ta_timeout_gear;
}

static inline void udma_set_query_flush_time(struct udma_dev *udev, struct udma_jetty_queue *sq,
					     uint8_t err_timeout)
{
	uint8_t gear = udma_get_ta_timeout_gear(udev, err_timeout);

	sq->ta_timeout = udma_get_ta_timeout(gear);
}

void free_jetty_id(struct udma_dev *udma_dev,
			  struct udma_jetty *udma_jetty, bool is_grp);
enum jetty_state to_jetty_state(enum ubcore_jetty_state state);
const char *to_state_name(enum ubcore_jetty_state state);
bool verify_modify_jetty(enum ubcore_jetty_state jetty_state,
			 enum ubcore_jetty_state attr_state);
int alloc_jetty_id(struct udma_dev *udma_dev, struct udma_jetty_queue *sq,
		   uint32_t cfg_id, struct ubcore_jetty_group *jetty_grp);
struct ubcore_jetty *udma_create_jetty(struct ubcore_device *ub_dev,
				       struct ubcore_jetty_cfg *cfg,
				       struct ubcore_udata *udata);
int udma_destroy_jetty(struct ubcore_jetty *jetty);
int udma_destroy_jetty_batch(struct ubcore_jetty **jetty_arr, int jetty_num, int *bad_jetty_index);
int udma_unimport_jetty(struct ubcore_tjetty *tjetty);
int udma_modify_jetty(struct ubcore_jetty *jetty, struct ubcore_jetty_attr *attr,
		      struct ubcore_udata *udata);
int udma_flush_jetty(struct ubcore_jetty *jetty, int cr_cnt, struct ubcore_cr *cr);
int udma_set_jetty_state(struct udma_dev *dev, uint32_t jetty_id,
			 enum jetty_state state);
int udma_post_jetty_send_wr(struct ubcore_jetty *jetty, struct ubcore_jfs_wr *wr,
			    struct ubcore_jfs_wr **bad_wr);
int udma_post_jetty_recv_wr(struct ubcore_jetty *jetty, struct ubcore_jfr_wr *wr,
			    struct ubcore_jfr_wr **bad_wr);
int udma_unbind_jetty(struct ubcore_jetty *jetty);
void udma_reset_sw_k_jetty_queue(struct udma_jetty_queue *sq);
int udma_destroy_hw_jetty_ctx(struct udma_dev *dev, uint32_t jetty_id);
int udma_modify_and_destroy_jetty(struct udma_dev *dev,
				  struct udma_jetty_queue *sq);
int udma_alloc_jetty_id(struct udma_dev *udma_dev, uint32_t *idx,
			struct udma_res *jetty_res);
void udma_modify_jetty_precondition(struct udma_dev *dev, struct udma_jetty_queue *sq);

struct ubcore_tjetty *udma_import_jetty_ex(struct ubcore_device *ub_dev,
					    struct ubcore_tjetty_cfg *cfg,
					    struct ubcore_active_tp_cfg *active_tp_cfg,
					    struct ubcore_udata *udata);
int udma_bind_jetty_ex(struct ubcore_jetty *jetty,
			struct ubcore_tjetty *tjetty,
			struct ubcore_active_tp_cfg *active_tp_cfg,
			struct ubcore_udata *udata);
void udma_clean_cqe_for_jetty(struct udma_dev *dev, struct udma_jetty_queue *sq,
			      struct ubcore_jfc *send_jfc,
			      struct ubcore_jfc *recv_jfc);
int udma_batch_modify_and_destroy_jetty(struct udma_dev *dev,
					struct udma_jetty_queue **sq_list,
					uint32_t jetty_cnt, int *bad_jetty_index);
int udma_add_xa_and_create_hw_ctx(struct udma_dev *udma_dev, struct udma_jetty *udma_jetty,
				  struct ubcore_jetty_cfg *cfg);

int udma_verify_jetty_opt(struct udma_dev *udma_dev, struct udma_jetty_opt_attr attr);
int udma_set_jetty_field(struct udma_dev *udma_dev, struct udma_jetty_queue *sq,
			 uint64_t opt, void *buf);
int udma_get_jetty_field(struct udma_dev *udma_dev, struct udma_jetty_queue *sq,
			 uint64_t opt, void *buf);
int udma_free_jetty(struct ubcore_jetty *jetty, struct ubcore_udata *udata);
int udma_active_jetty(struct ubcore_jetty *jetty, struct ubcore_udata *udata);
int udma_alloc_jetty(struct ubcore_device *dev, struct ubcore_jetty_cfg *cfg,
		     struct ubcore_jetty **jetty, struct ubcore_udata *udata);
int udma_deactive_jetty(struct ubcore_jetty *jetty, struct ubcore_udata *udata);
int udma_get_jetty_opt(struct ubcore_jetty *jetty, uint64_t opt, void *buf,
		       uint32_t len, struct ubcore_udata *udata);
int udma_set_jetty_opt(struct ubcore_jetty *jetty, uint64_t opt,
		       void *buf, uint32_t len, struct ubcore_udata *udata);
void udma_get_jfs_cfg_field(struct ubcore_jfs_cfg *jfs_cfg, uint64_t opt, void *buf);
#endif /* __UDMA_JETTY_H__ */

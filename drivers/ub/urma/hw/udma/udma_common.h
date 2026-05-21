/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#ifndef __UDMA_COMM_H__
#define __UDMA_COMM_H__

#include <linux/jhash.h>
#include <linux/vmalloc.h>
#include <ub/urma/ubcore_api.h>
#include "udma_ctx.h"
#include "udma_dev.h"

#define TP_ACK_UDP_SPORT_H_OFFSET 8
#define UDMA_TPHANDLE_TPID_SHIFT 0xFFFFFF
#define UDMA_EID_GUID_INDEX_OFFSET 24
#define UDMA_MIN_SLEEP_TIME 100
#define UDMA_REMOVE_MAX_SLEEP_TIME 800
#define UDMA_OPEN_RX_MAX_SLEEP_TIME 3000
#define UDMA_TIME_SLEEP_RATE 2

struct udma_jetty_grp {
	struct ubcore_jetty_group ubcore_jetty_grp;
	uint32_t start_jetty_id;
	uint32_t next_jetty_id;
	uint32_t jetty_grp_id;
	uint32_t valid;
	struct mutex valid_lock;
	refcount_t ae_refcount;
	struct completion ae_comp;
};

struct udma_dtu_pg_info {
	struct page *pg;
	int order;
};

struct udma_jetty_queue {
	struct udma_buf buf;
	void *kva_curr;
	uint32_t id;
	void __iomem *db_addr;
	void __iomem *dwqe_addr;
	uint32_t pi;
	uint32_t ci;
	uintptr_t *wrid;
	spinlock_t lock;
	uint32_t max_inline_size;
	uint32_t max_sge_num;
	uint32_t tid;
	bool flush_flag;
	uint32_t old_entry_idx;
	enum ubcore_transport_mode trans_mode;
	struct ubcore_tjetty *rc_tjetty;
	bool is_jetty;
	uint32_t sqe_bb_cnt;
	uint32_t lock_free; /* Support kernel mode lock-free mode */
	uint32_t ta_timeout; /* ms */
	enum ubcore_jetty_state state;
	struct udma_context *udma_ctx;
	bool non_pin;
	struct udma_jetty_grp *jetty_grp;
	enum udma_jetty_type jetty_type;
	struct {
		struct page *pg;
		int order;
		uint32_t len;
	} reserved_info;
	struct sg_table *sgt;
	uint8_t db_status;
	bool need_ring_db;
	bool pi_type;
	bool activated;
	bool cstm;
	bool dtu_en;
	struct udma_dtu_pg_info dtu_pg_info;
};

enum tp_state {
	TP_INVALID = 0x0,
	TP_VALID = 0x1,
	TP_RTS = 0x3,
	TP_ERROR = 0x6,
};

struct udma_umem_param {
	struct ubcore_device *ub_dev;
	uint64_t va;
	uint64_t len;
	union ubcore_umem_flag flag;
	bool is_kernel;
};

struct udma_ue_index_cmd {
	uint16_t ue_idx;
	uint8_t rsv[2];
	uint8_t guid[16];
};

struct udma_tp_ctx {
	/* Byte4 */
	uint32_t version : 1;
	uint32_t tp_mode : 1;
	uint32_t trt : 1;
	uint32_t wqe_bb_shift : 4;
	uint32_t oor_en : 1;
	uint32_t tempid : 6;
	uint32_t portn : 6;
	uint32_t rsvd1 : 12;
	/* Byte8 */
	uint32_t wqe_ba_l;
	/* Byte12 */
	uint32_t wqe_ba_h : 20;
	uint32_t udp_srcport_range : 4;
	uint32_t cng_alg_sel : 3;
	uint32_t lbi : 1;
	uint32_t rsvd4 : 1;
	uint32_t vlan_en : 1;
	uint32_t mtu : 2;
	/* Byte16 */
	uint32_t route_addr_idx : 20;
	uint32_t rsvd6 : 12;
	/* Byte20 */
	uint32_t tpn_vtpn : 24;
	uint32_t rsvd7 : 8;
	/* Byte24 to Byte28 */
	uint32_t rsvd8[2];
	/* Byte 32 */
	uint32_t seid_idx : 16;
	uint32_t sjetty_l : 16;
	/* Byte 36 */
	uint32_t sjetty_h : 4;
	uint32_t tp_wqe_token_id : 20;
	uint32_t tp_wqe_position : 1;
	uint32_t rsv9_l : 7;
	/* Byte 40 */
	uint32_t rsvd9_h : 6;
	uint32_t taack_tpn : 24;
	uint32_t rsvd10 : 2;
	/* Byte 44 */
	uint32_t spray_en : 1;
	uint32_t sr_en : 1;
	uint32_t ack_freq_mode : 1;
	uint32_t route_type : 2;
	uint32_t vl : 4;
	uint32_t dscp : 6;
	uint32_t switch_mp_en : 1;
	uint32_t at_times : 5;
	uint32_t retry_num_init : 3;
	uint32_t at : 5;
	uint32_t rsvd13 : 3;
	/* Byte 48 */
	uint32_t on_flight_size : 16;
	uint32_t hpln : 8;
	uint32_t fl_l : 8;
	/* Byte 52 */
	uint32_t fl_h : 12;
	uint32_t dtpn : 20;
	/* Byte 56 */
	uint32_t rc_tpn : 24;
	uint32_t rc_vl : 4;
	uint32_t tpg_vld : 1;
	uint32_t reorder_cap : 3;
	/* Byte 60 */
	uint32_t reorder_q_shift : 4;
	uint32_t reorder_q_addr_l : 28;
	/* Byte 64 */
	uint32_t reorder_q_addr_h : 24;
	uint32_t tpg_l : 8;
	/* Byte 68 */
	uint32_t tpg_h : 12;
	uint32_t jettyn : 20;
	/* Byte 72 */
	uint32_t dyn_timeout_mode : 1;
	uint32_t base_time : 23;
	uint32_t rsvd15 : 8;
	/* Byte 76 */
	uint32_t tpack_psn : 24;
	uint32_t tpack_rspst : 3;
	uint32_t tpack_rspinfo : 5;
	/* Byte 80 */
	uint32_t tpack_msn : 24;
	uint32_t ack_udp_srcport_l : 8;
	/* Byte 84 */
	uint32_t ack_udp_srcport_h : 8;
	uint32_t max_rcv_psn : 24;
	/* Byte 88 */
	uint32_t scc_token : 19;
	uint32_t poll_db_wait_do : 1;
	uint32_t msg_rty_lp_flg : 1;
	uint32_t retry_cnt : 3;
	uint32_t sq_invld_flg : 1;
	uint32_t wait_ack_timeout : 1;
	uint32_t tx_rtt_caling : 1;
	uint32_t cnp_tx_flag : 1;
	uint32_t sq_db_doing : 1;
	uint32_t tpack_doing : 1;
	uint32_t sack_wait_do : 1;
	uint32_t tpack_wait_do : 1;
	/* Byte 92 */
	uint16_t post_max_idx;
	uint16_t wqe_max_bb_idx;
	/* Byte 96 */
	uint16_t wqe_bb_pi;
	uint16_t wqe_bb_ci;
	/* Byte 100 */
	uint16_t data_udp_srcport;
	uint16_t wqe_msn;
	/* Byte 104 */
	uint32_t cur_req_psn : 24;
	uint32_t tx_ack_psn_err : 1;
	uint32_t poll_db_type : 2;
	uint32_t tx_ack_flg : 1;
	uint32_t tx_sq_err_flg : 1;
	uint32_t scc_retry_type : 2;
	uint32_t flush_cqe_wait_do : 1;
	/* Byte 108 */
	uint32_t wqe_max_psn : 24;
	uint32_t ssc_token_l : 4;
	uint32_t rsvd16 : 4;
	/* Byte 112 */
	uint32_t tx_sq_timer;
	/* Byte 116 */
	uint32_t rtt_timestamp_psn : 24;
	uint32_t rsvd17 : 8;
	/* Byte 120 */
	uint32_t rtt_timestamp : 24;
	uint32_t cnp_timer_l : 8;
	/* Byte 124 */
	uint32_t cnp_timer_h : 16;
	uint32_t max_reorder_id : 16;
	/* Byte 128 */
	uint16_t cur_reorder_id;
	uint16_t wqe_max_msn;
	/* Byte 132 */
	uint16_t post_bb_pi;
	uint16_t post_bb_ci;
	/* Byte 136 */
	uint32_t lr_ae_ind : 1;
	uint32_t rx_cqe_cnt : 16;
	uint32_t reorder_q_si : 13;
	uint32_t rq_err_type_l : 2;
	/* Byte 140 */
	uint32_t rq_err_type_h : 3;
	uint32_t rsvd18 : 2;
	uint32_t rsvd19 : 27;
	/* Byte 144 */
	uint32_t req_seq;
	/* Byte 148 */
	uint32_t req_ce_seq;
	/* Byte 152 */
	uint32_t req_cmp_lrb_indx : 12;
	uint32_t req_lrb_indx : 12;
	uint32_t req_lrb_indx_vld : 1;
	uint32_t rx_req_psn_err : 1;
	uint32_t rx_req_last_optype : 3;
	uint32_t rx_req_fake_flg : 1;
	uint32_t rsvd20 : 2;
	/* Byte 156 */
	uint16_t jfr_wqe_idx;
	uint16_t rx_req_epsn_l;
	/* Byte 160 */
	uint32_t rx_req_epsn_h : 8;
	uint32_t rx_req_reduce_code : 8;
	uint32_t rx_req_msn_l : 16;
	/* Byte 164 */
	uint32_t rx_req_msn_h : 8;
	uint32_t jfr_wqe_rnr : 1;
	uint32_t jfr_wqe_rnr_timer : 5;
	uint32_t rsvd21 : 2;
	uint32_t jfr_wqe_cnt : 16;
	/* Byte 168 */
	uint32_t max_reorder_q_idx : 13;
	uint32_t rsvd22 : 3;
	uint32_t reorder_q_ei : 13;
	uint32_t rx_req_last_elr_flg : 1;
	uint32_t rx_req_last_elr_err_type_l : 2;
	/* Byte172 */
	uint32_t rx_req_last_elr_err_type_h : 3;
	uint32_t rx_req_last_op : 1;
	uint32_t jfrx_jetty : 1;
	uint32_t jfrx_jfcn_l : 16;
	uint32_t jfrx_jfcn_h : 4;
	uint32_t jfrx_jfrn_l : 7;
	/* Byte176 */
	uint32_t jfrx_jfrn_h1 : 9;
	uint32_t jfrx_jfrn_h2 : 4;
	uint32_t rq_timer_l : 19;
	/* Byte180 */
	uint32_t rq_timer_h : 13;
	uint32_t rq_at : 5;
	uint32_t wait_cqe_timeout : 1;
	uint32_t rsvd23 : 13;
	/* Byte184 */
	uint32_t rx_sq_timer;
	/* Byte188 */
	uint32_t tp_st : 3;
	uint32_t rsvd24 : 4;
	uint32_t ls_ae_ind : 1;
	uint32_t retry_msg_psn : 24;
	/* Byte192 */
	uint32_t retry_msg_fpsn : 24;
	uint32_t rsvd25 : 8;
	/* Byte196 */
	uint16_t retry_wqebb_idx;
	uint16_t retry_msg_msn;
	/* Byte200 */
	uint32_t ack_rcv_seq;
	/* Byte204 */
	uint32_t rtt : 24;
	uint32_t dup_sack_cnt : 8;
	/* Byte208 */
	uint32_t sack_max_rcv_psn : 24;
	uint32_t rsvd26 : 7;
	uint32_t rx_ack_flg : 1;
	/* Byte212 */
	uint32_t rx_ack_msn : 16;
	uint32_t sack_lrb_indx : 12;
	uint32_t rx_fake_flg : 1;
	uint32_t rx_rtt_caling : 1;
	uint32_t rx_ack_psn_err : 1;
	uint32_t sack_lrb_indx_vld : 1;
	/* Byte216 */
	uint32_t rx_ack_epsn : 24;
	uint32_t rsvd27 : 8;
	/* Byte220 */
	uint32_t max_retry_psn : 24;
	uint32_t retry_reorder_id_l : 8;
	/* Byte224 */
	uint32_t retry_reorder_id_h : 8;
	uint32_t rsvd28 : 8;
	uint32_t rsvd29 : 16;
	/* Byte228 to Byte256 */
	uint32_t scc_data[8];
};

int udma_ioummu_map(uint32_t l_tid, uint32_t r_tid, int prot, uint64_t addr,
		    struct sg_table *sgt);
void udma_ioummu_unmap(uint32_t l_tid, uint32_t r_tid, uint64_t addr, size_t size);
struct udma_umem *udma_umem_get(struct udma_umem_param *param);
void udma_umem_release(struct udma_umem *umem, bool is_kernel, bool dirty);
void udma_init_udma_table(struct udma_table *table, uint32_t max, uint32_t min, bool irq_lock);
void udma_init_udma_table_mutex(struct xarray *table, struct mutex *udma_mutex, bool irq_lock);
void udma_destroy_npu_cb_table(struct udma_dev *dev);
void udma_destroy_udma_table(struct udma_dev *dev, struct udma_table *table,
			     const char *table_name);
void udma_destroy_eid_table(struct udma_dev *udma_dev);
void udma_dfx_store_id(struct udma_dev *udma_dev, struct udma_dfx_entity *entity,
		       uint32_t id, const char *name);
void udma_dfx_delete_id(struct udma_dev *udma_dev, struct udma_dfx_entity *entity,
			uint32_t id);
void udma_iotlb_sync(struct udma_dev *dev, uint64_t va, uint64_t len);
int udma_alloc_normal_buf(struct udma_dev *udma_dev, size_t memory_size, struct udma_buf *buf);
void udma_free_normal_buf(struct udma_dev *udma_dev, size_t memory_size, struct udma_buf *buf);
int udma_k_alloc_buf(struct udma_dev *dev, struct udma_buf *buf, bool need_dtu);
void udma_k_free_buf(struct udma_dev *dev, struct udma_buf *buf, bool need_dtu);
bool remap_va_to_pfn(struct udma_dev *dev, uint64_t va, uint64_t *pfn);

static inline void udma_write64(struct udma_dev *udma_dev,
				uint64_t *val, void __iomem *dest)
{
	writeq(*val, dest);
}

static inline void udma_set_kernel_db_addr(struct udma_dev *dev,
					   struct udma_jetty_queue *queue)
{
	queue->dwqe_addr = dev->k_db_base + JETTY_DSQE_OFFSET +
			   UDMA_HW_PAGE_SIZE * queue->id;
	queue->db_addr = queue->dwqe_addr + UDMA_DOORBELL_OFFSET;
}

static inline void *get_buf_entry(struct udma_buf *buf, uint32_t n)
{
	uint32_t entry_index = n & (buf->entry_cnt - 1);

	return (char *)buf->kva + (entry_index * buf->entry_size);
}

static inline uint8_t to_ta_timeout(uint32_t err_timeout)
{
#define TA_TIMEOUT_DIVISOR 8
	return err_timeout / TA_TIMEOUT_DIVISOR;
}

static inline uint64_t udma_cal_npages(uint64_t va, uint64_t len)
{
	return (ALIGN(va + len, PAGE_SIZE) - ALIGN_DOWN(va, PAGE_SIZE)) / PAGE_SIZE;
}

static inline int
udma_remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
		     unsigned long pfn, unsigned long size, pgprot_t prot)
{
#ifdef CONFIG_ARCH_SUPPORTS_PMD_PFNMAP
	if (IS_ALIGNED(size, UDMA_HUGEPAGE_SIZE))
		return remap_pfn_range_try_pmd(vma, addr, pfn, size, prot);
#endif
	return remap_pfn_range(vma, addr, pfn, size, prot);
}

static inline struct page *udma_alloc_pages(int flag, uint32_t order)
{
	return order == 0 ? alloc_page(flag) : alloc_pages(flag, order);
}

static inline void udma_free_pages(struct page *pg, uint32_t order)
{
	order == 0 ? __free_page(pg) : __free_pages(pg, order);
}

int udma_query_ue_idx(struct ubcore_device *ub_dev, struct ubcore_devid *devid,
		      uint16_t *ue_idx);
void udma_dfx_ctx_print(struct udma_dev *udev, const char *name, uint32_t id, uint32_t len,
			uint32_t *ctx);
void udma_swap_endian(const uint8_t arr[], uint8_t res[], uint32_t res_size);

void udma_init_hugepage(struct udma_dev *dev);
void udma_destroy_hugepage(struct udma_dev *dev);
void udma_destroy_eid_guid_table(struct udma_dev *udma_dev);
void udma_dtu_uva_unremap(struct udma_dev *dev, struct udma_buf *buf,
			  struct udma_dtu_pg_info *dtu_pg_info);
int udma_dtu_uva_remap(struct udma_dev *dev, struct udma_buf *buf,
		       struct udma_dtu_pg_info *dtu_pg_info);

#endif /* __UDMA_COMM_H__ */

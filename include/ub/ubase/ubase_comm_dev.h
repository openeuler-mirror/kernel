/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef _UB_UBASE_COMM_DEV_H_
#define _UB_UBASE_COMM_DEV_H_

#include <linux/auxiliary_bus.h>
#include <linux/dcbnl.h>
#include <linux/list.h>

struct iova_slot;

#define UBASE_ADEV_NAME	"ubase"

#define UBASE_IOVA_COMM_PFN_CNT 1
#define UBASE_MAX_DSCP		(64)
#define UBASE_MAX_SL_NUM	(16U)
#define UBASE_MAX_VL_NUM	(16U)
#if UBASE_MAX_VL_NUM < IEEE_8021QAZ_MAX_TCS
#error "UBASE_MAX_VL_NUM can't less than IEEE_8021QAZ_MAX_TCS"
#endif

#define UBASE_NIC_MAX_VL_NUM	(2)

#define UBASE_SUP_UBL		BIT(0)
#define UBASE_SUP_ETH		BIT(1)
#define UBASE_SUP_UNIC		BIT(2)
#define UBASE_SUP_UDMA		BIT(3)
#define UBASE_SUP_CDMA		BIT(4)
#define UBASE_SUP_PMU		BIT(5)
#define UBASE_SUP_URMA		(UBASE_SUP_UNIC | UBASE_SUP_UDMA)
#define UBASE_SUP_UBL_ETH	(UBASE_SUP_UBL | UBASE_SUP_ETH)
#define UBASE_SUP_ALL		(UBASE_SUP_UNIC | UBASE_SUP_UDMA | \
				 UBASE_SUP_CDMA | UBASE_SUP_PMU)
#define UBASE_SUP_NO_PMU	(UBASE_SUP_ALL ^ UBASE_SUP_PMU)

#define UBASE_HW_VER_UNKNOWN	(0U)
#define UBASE_HW_VER_A_0	(1000U)
#define UBASE_HW_VER_K_0	(2000U)

enum ubase_reset_type {
	UBASE_NO_RESET,
	UBASE_ELR_RESET,
	UBASE_UE_RESET,
	UBASE_MAX_RESET,
};

enum ubase_reset_stage {
	UBASE_RESET_STAGE_NONE,
	UBASE_RESET_STAGE_DOWN,
	UBASE_RESET_STAGE_UNINIT,
	UBASE_RESET_STAGE_INIT,
	UBASE_RESET_STAGE_UP,
};

/**
 * struct ubase_caps - ubase capabilities
 * @num_ceq_vectors: completion event vectors number
 * @num_aeq_vectors: asynchronous event vectors umber
 * @num_misc_vectors: misc event vectors number
 * @aeqe_depth: the depth of asynchronous event vector queue
 * @ceqe_depth: the depth of completion event vector queue
 * @aeqe_size: the size of asynchronous event vector queue element
 * @ceqe_size: the size of completion event vector queue element
 * @total_ue_num: ue number
 * @public_jetty_cnt: public jetty count
 * @vl_num: vl number
 * @rsvd_jetty_cnt: reserved jetty count
 * @req_vl: requested vl
 * @resp_vl: response vl
 * @packet_pattern_mode: packet pattern mode
 * @ack_queue_num: ack queue number
 * @oor_en: out of order receive, 0: disable 1: enable
 * @reorder_queue_en: reorder queue enable, 0: disable 1: enable
 * @on_flight_size: on flight packets size
 * @reorder_cap: reorder capability
 * @reorder_queue_shift: reorder queue shift
 * @at_times: ack timeout
 * @ue_num: the total number of ue and mue
 * @mac_stats_num: mac stats number
 * @logic_port_bitmap: logic port bitmap
 * @ub_port_logic_id: ub port logic id
 * @io_port_logic_id: io port logic id
 * @io_port_id: io port id
 * @nl_port_id: nl port id
 * @chip_id: chip id
 * @die_id: die id
 * @ue_id: ub entity id
 * @nl_id: nl id
 * @tid: ub entity tid
 * @eid: ub entity eid
 * @upi: ub entity upi
 * @ctl_no: ub controller id
 * @fw_version: firmware version
 * @dtu_pa_base: dtu table's physical base address
 * @dtu_va_base: dtu table's virtual base address
 * @dtu_iova_base: dtu table's I/O virtual base address
 * @dtu_pa_size: dtu table's physical address size
 */
struct ubase_caps {
	u16	num_ceq_vectors;
	u16	num_aeq_vectors;
	u16	num_misc_vectors;

	u32	aeqe_depth;
	u32	ceqe_depth;
	u16	aeqe_size;
	u16	ceqe_size;

	u32	total_ue_num;
	u32	public_jetty_cnt;
	u8	vl_num;
	u16	rsvd_jetty_cnt;

	u8	req_vl[UBASE_MAX_VL_NUM];
	u8	resp_vl[UBASE_MAX_VL_NUM];

	u8	packet_pattern_mode;
	u8	ack_queue_num;
	u8	oor_en;
	u8	reorder_queue_en;
	u32	on_flight_size;
	u8	reorder_cap;
	u8	reorder_queue_shift;
	u8	at_times;
	u8	ue_num;
	u16	mac_stats_num;

	u32	logic_port_bitmap;
	u16	ub_port_logic_id;
	u16	io_port_logic_id;
	u16	io_port_id;
	u16	nl_port_id;
	u16	chip_id;
	u16	die_id;
	u16	ue_id;
	u16	nl_id;

	u32	tid;
	u32	eid;
	u16	upi;
	u32	ctl_no;

	u32	fw_version;

	u64	dtu_pa_base;
	u64	dtu_va_base;
	u64	dtu_iova_base;
	u64	dtu_pa_size;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
	KABI_RESERVE(5)
	KABI_RESERVE(6)
	KABI_RESERVE(7)
	KABI_RESERVE(8)
	KABI_RESERVE(9)
	KABI_RESERVE(10)
	KABI_RESERVE(11)
	KABI_RESERVE(12)
};

/**
 * struct ubase_res_caps - ubase resource capbilities
 * @max_cnt: the resource max count
 * @start_idx: start index
 * @depth: the queue depth of the resource
 */
struct ubase_res_caps {
	u32	max_cnt;
	u32	start_idx;
	u32	depth;
	KABI_RESERVE(1)
	KABI_RESERVE(2)
};

/**
 * struct ubase_pmem_caps - ubase physical memory capabilities
 * @dma_len: iova address sapce length
 * @dma_addr: iova address
 */
struct ubase_pmem_caps {
	u64		dma_len;
	dma_addr_t	dma_addr;
};

/**
 * struct ubase_rc_que_addr - ubase rc queue memory address
 * @iova: iova address
 * @va: va address
 */
struct ubase_rc_que_addr {
	dma_addr_t	iova;
	void		*va;
};

/**
 * struct ubase_rct_caps - ubase rc queue capabilities
 * @depth: depth of each rc queue
 * @max_cnt: max cnt of rc queue
 * @addrs: rc queues' memory address
 */
struct ubase_rct_caps {
	u32 depth;
	u32 max_cnt;
	struct ubase_rc_que_addr *addrs;
};

/**
 * struct ubase_adev_caps - ubase auxiliary device capabilities
 * @jfs: jfs resource capabilities
 * @jfr: jfr resource capabilities
 * @jfc: jfc resource capabilities
 * @tpg: tp group resource capabilities
 * @pmem: physical memory capabilities
 * @rc: rc queue resource capabilities
 * @jtg_max_cnt: jetty group max count
 * @rc_max_cnt: rc max count
 * @rc_que_depth: rc queue depth
 * @cqe_size: cqe size
 */
struct ubase_adev_caps {
	struct ubase_res_caps	jfs;
	struct ubase_res_caps	jfr;
	struct ubase_res_caps	jfc;
	struct ubase_res_caps	tpg;
	struct ubase_pmem_caps	pmem;
	struct ubase_rct_caps	rc;
	u32			jtg_max_cnt;
	u32			rc_max_cnt;
	u32			rc_que_depth;
	u16			cqe_size;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
	KABI_RESERVE(5)
	KABI_RESERVE(6)
	KABI_RESERVE(7)
	KABI_RESERVE(8)
	KABI_RESERVE(9)
	KABI_RESERVE(10)
	KABI_RESERVE(11)
	KABI_RESERVE(12)
};

/**
 * struct ubase_ctx_buf_cap - ubase context buffer capabilities
 * @dma_ctx_buf_ba: context buffer iova address
 * @page: dtu memory pages
 * @slot: iova slot
 * @entry_size: context entry size
 * @entry_cnt: context entry count
 * @cnt_per_page_shift: context entry count per page shift
 * @ctx_xa: context array
 * @ctx_mutex: context mutex
 */
struct ubase_ctx_buf_cap {
	dma_addr_t		dma_ctx_buf_ba; /* pass to hw */
	struct page		*page; /* dtu only */
	struct iova_slot	*slot;
	u32			entry_size;
	u32			entry_cnt;
	u32			cnt_per_page_shift;
	struct xarray		ctx_xa;
	struct mutex		ctx_mutex;
	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

struct net_device;

/**
 * struct ubase_adev_com - ubase auxiliary device common information
 * @adev: auxiliary device
 * @netdev: network device
 */
struct ubase_adev_com {
	struct auxiliary_device	*adev;
	struct net_device	*netdev;
	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

/**
 * struct ubase_resource_space - ubase resource space
 * @addr_unmapped: unmapped address
 * @addr: mapped address
 */
struct ubase_resource_space {
	resource_size_t addr_unmapped;
	void __iomem *addr;
	KABI_RESERVE(1)
	KABI_RESERVE(2)
};

/**
 * struct ubase_adev_qos - ubase auxiliary device qos information
 * @tp_sl_num: tp sl number
 * @tp_sl: tp sl
 * @ctp_sl_num: ctp sl number
 * @ctp_sl: ctp sl
 * @tp_vl_num: tp vl number
 *
 * @tp_resp_vl_offset: tp response vl offset,
 *			tp_resp_vl = tp_resp_vl + tp_resp_vl_offset
 * @tp_req_vl: tp request number
 * @ctp_vl_num: ctp vl number
 * @ctp_resp_vl_offset: ctp response vl offset,
 *			ctp_resp_vl = ctp_resp_vl + ctp_resp_vl_offset
 * @ctp_req_vl: ctp request vl
 * @dscp_vl: dscp to vl mapping
 * @nic_sl_num: nic sl number
 * @nic_sl: nic sl
 * @nic_vl_num: nic vl number
 * @nic_vl: nic vl
 * @ue_max_vl_id: ue max vl index
 * @ue_sl_vl: ue sl to vl mapping
 */
struct ubase_adev_qos {
	/* udma/cdma resource */
	u8	tp_sl_num;
	u8	tp_sl[UBASE_MAX_SL_NUM];
	u8	ctp_sl_num;
	u8	ctp_sl[UBASE_MAX_SL_NUM];

	u8	tp_vl_num;
	u8	tp_resp_vl_offset;
	u8	tp_req_vl[UBASE_MAX_VL_NUM];
	u8	ctp_vl_num;
	u8	ctp_resp_vl_offset;
	u8	ctp_req_vl[UBASE_MAX_VL_NUM];

	u8	dscp_vl[UBASE_MAX_DSCP];

	/* unic resource */
	u8	nic_sl_num;
	u8	nic_sl[UBASE_MAX_SL_NUM];

	u8	nic_vl_num;
	u8	nic_vl[UBASE_MAX_VL_NUM];

	/* common resource */
	u8	ue_max_vl_id;
	u8	ue_sl_vl[UBASE_MAX_SL_NUM];

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
	KABI_RESERVE(5)
	KABI_RESERVE(6)
};

#define UBASE_BUS_EID_LEN 4

/**
 * struct ubase_bus_eid - bus eid
 * @eid: bus eid
 */
struct ubase_bus_eid {
	u32 eid[UBASE_BUS_EID_LEN];
};

u32 ubase_get_hw_ver(struct auxiliary_device *adev);
bool ubase_adev_ubl_supported(struct auxiliary_device *adev);
bool ubase_adev_ctrlq_supported(struct auxiliary_device *adev);
bool ubase_adev_eth_mac_supported(struct auxiliary_device *adev);
bool ubase_adev_mac_stats_supported(struct auxiliary_device *aux_dev);
bool ubase_adev_prealloc_supported(struct auxiliary_device *aux_dev);
bool ubase_adev_ip_over_urma_supported(struct auxiliary_device *adev);
bool ubase_adev_ip_over_urma_utp_supported(struct auxiliary_device *adev);
bool ubase_adev_dtu_supported(struct auxiliary_device *aux_dev);
int ubase_adev_get_mem_node_id(struct auxiliary_device *aux_dev);
int ubase_dtu_tbl_init(struct auxiliary_device *aux_dev, u32 tid, u16 *dtu_win_num);
int ubase_dtu_tbl_uninit(struct auxiliary_device *aux_dev, u16 dtu_win_num);
bool ubase_adev_ucp_supported(struct auxiliary_device *adev);
bool ubase_adev_shutting_down(struct auxiliary_device *adev);

struct ubase_resource_space *ubase_get_io_base(struct auxiliary_device *adev);
struct ubase_resource_space *ubase_get_mem_base(struct auxiliary_device *adev);
struct ubase_caps *ubase_get_dev_caps(struct auxiliary_device *adev);
const struct ubase_adev_com *ubase_get_mdrv_data(struct auxiliary_device *adev);
struct ubase_adev_caps *ubase_get_unic_caps(struct auxiliary_device *adev);
struct ubase_adev_caps *ubase_get_udma_caps(struct auxiliary_device *adev);
struct ubase_adev_caps *ubase_get_cdma_caps(struct auxiliary_device *adev);
struct ubase_adev_qos *ubase_get_adev_qos(struct auxiliary_device *adev);
void ubase_reset_event(struct auxiliary_device *adev,
		       enum ubase_reset_type reset_type);
enum ubase_reset_stage ubase_get_reset_stage(struct auxiliary_device *adev);
void ubase_virt_register(struct auxiliary_device *adev,
			 void (*virt_handler)(struct auxiliary_device *adev,
					      u16 bus_ue_id, bool is_en));
void ubase_virt_unregister(struct auxiliary_device *adev);
void ubase_port_register(struct auxiliary_device *adev,
			 void (*port_handler)(struct auxiliary_device *adev,
					      bool link_up));
void ubase_port_unregister(struct auxiliary_device *adev);
void ubase_reset_register(struct auxiliary_device *adev,
			  void (*reset_handler)(struct auxiliary_device *adev,
						enum ubase_reset_stage stage));
void ubase_reset_unregister(struct auxiliary_device *adev);
void ubase_activate_register(struct auxiliary_device *adev,
			     void (*activate_handler)(struct auxiliary_device *adev,
						      bool activate));
void ubase_activate_unregister(struct auxiliary_device *adev);
int ubase_activate_dev(struct auxiliary_device *adev);
int ubase_deactivate_dev(struct auxiliary_device *adev);
int ubase_get_bus_eid(struct auxiliary_device *adev, struct ubase_bus_eid *eid);

int ubase_get_dev_mac(struct auxiliary_device *adev, u8 *dev_addr, u8 addr_len);
int ubase_set_dev_mac(struct auxiliary_device *adev, const u8 *dev_addr,
		      u8 addr_len);

void ubase_adev_fault_log(struct auxiliary_device *adev,
			  u32 event_id, void *data);

int ubase_adev_query_rc_ctx(struct auxiliary_device *adev, u32 rc_queue_idx,
			    void *ctx, u32 ctx_size);

int ubase_himac_reset(struct auxiliary_device *adev);

#endif /* _UBASE_COMM_DEV_H_ */

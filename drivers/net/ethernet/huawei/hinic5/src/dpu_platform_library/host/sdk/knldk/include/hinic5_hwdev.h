/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_hwdev.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_HWDEV_H
#define HINIC5_HWDEV_H

#include "hinic5_mt.h"
#include "hinic5_crm.h"
#include "hinic5_hw.h"
#include "hinic5_profile.h"
#include "hinic5_common.h"
#include "hinic5_chip_info.h"
#include "hinic5_vram_common.h"

#ifndef __UEFI__
#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#endif

#include <linux/device.h>

#define sdk_err(dev, format, ...) dev_err(dev, "[COMM]" format, ##__VA_ARGS__)
#define sdk_warn(dev, format, ...) dev_warn(dev, "[COMM]" format, ##__VA_ARGS__)
#define sdk_notice(dev, format, ...) dev_notice(dev, "[COMM]" format, ##__VA_ARGS__)
#define sdk_info(dev, format, ...) dev_info(dev, "[COMM]" format, ##__VA_ARGS__)

struct cfg_mgmt_info;

struct hinic5_hwif;
struct hinic5_aeqs;
struct hinic5_ceqs;
struct hinic5_mbox;
struct hinic5_msg_pf_to_mgmt;
struct hinic5_hwdev;
struct hinic5_wq;
struct sdk_cmdq_wqe_desc;

#define HINIC5_CHANNEL_DETECT_PERIOD    (5 * 1000)
#define HINIC5_CHANNEL_DETECT_MAX_BUSY  (3)

/**< System and chip time sync period unit in milliseconds */
#define HINIC5_NON_PTP_SYNC_FW_TIME_PERIOD (500)

/**
 * @brief Define a function pointer type for handling hinic5 events
 * @param handle Device handle
 * @param event Event information
 *
 * @return None
 */
typedef void (*hinic5_event_handler)(void *handle, struct hinic5_event_info *event);

struct hinic5_page_addr {
	void *virt_addr;
	u64 phys_addr;
};

struct mqm_addr_trans_tbl_info {
	u32 chunk_num;
	u32 search_gpa_num;
	u32 page_size;
	u32 page_num;
	struct hinic5_dma_addr_align *brm_srch_page_addr;
};

struct hinic5_devlink {
	struct hinic5_hwdev *hwdev;
	u8 activate_fw; /* 0 ~ 7 */
	u8 switch_cfg;  /* 0 ~ 7 */
};

enum hinic5_func_mode {
	/* single host */
	FUNC_MOD_NORMAL_HOST,
	/* multi host, bare-metal, sdi side */
	FUNC_MOD_MULTI_BM_MASTER,
	/* multi host, bare-metal, host side */
	FUNC_MOD_MULTI_BM_SLAVE,
	/* multi host, vm mode, sdi side */
	FUNC_MOD_MULTI_VM_MASTER,
	/* multi host, vm mode, host side */
	FUNC_MOD_MULTI_VM_SLAVE,
};

enum hinic5_pcie_nosnoop {
	HINIC5_PCIE_SNOOP = 0,
	HINIC5_PCIE_NO_SNOOP = 1,
};

enum hinic5_pcie_tph {
	HINIC5_PCIE_TPH_DISABLE = 0,
	HINIC5_PCIE_TPH_ENABLE = 1,
};

enum hinic5_perf_bitmap {
	HINIC5_CMDQ_PERF = 0,
	HINIC5_MAILBOX_PERF = 1,
};

#define IS_BMGW_MASTER_HOST(hwdev)	\
		((hwdev)->func_mode == FUNC_MOD_MULTI_BM_MASTER)
#define IS_BMGW_SLAVE_HOST(hwdev)	\
		((hwdev)->func_mode == FUNC_MOD_MULTI_BM_SLAVE)
#define IS_VM_MASTER_HOST(hwdev)	\
		((hwdev)->func_mode == FUNC_MOD_MULTI_VM_MASTER)
#define IS_VM_SLAVE_HOST(hwdev)		\
		((hwdev)->func_mode == FUNC_MOD_MULTI_VM_SLAVE)

#define IS_MASTER_HOST(hwdev)		\
		(IS_BMGW_MASTER_HOST(hwdev) || IS_VM_MASTER_HOST(hwdev))

#define IS_SLAVE_HOST(hwdev)		\
		(IS_BMGW_SLAVE_HOST(hwdev) || IS_VM_SLAVE_HOST(hwdev))

#define IS_MULTI_HOST(hwdev)		\
		(IS_BMGW_MASTER_HOST(hwdev) || IS_BMGW_SLAVE_HOST(hwdev) || \
		 IS_VM_MASTER_HOST(hwdev) || IS_VM_SLAVE_HOST(hwdev))

#define NEED_MBOX_FORWARD(hwdev)	IS_BMGW_SLAVE_HOST(hwdev)

enum hinic5_host_mode_e {
	HINIC5_MODE_NORMAL = 0,
	HINIC5_SDI_MODE_VM,
	HINIC5_SDI_MODE_BM,
	HINIC5_SDI_MODE_MAX,
};

struct mqm_eqm_hinic5_vram_name_s {
	char hinic5_vram_name[HINIC5_VRAM_NAME_MAX_LEN];
};

struct hinic5_sdk_timeout_info {
	enum hinic5_hw_type hw_type;    /**< Hardware type FPGA etc. */
	const char *hw_type_desc;    /**< Hardware type string representation. */
	u32 mbox_poll_timeout;    /* < Timeout for waiting cpi to write back mailbox status */
	u32 mbox_timeout;        /**< Timeout for waiting mailbox ack response */
	u32 cmdq_timeout;        /**< cmdq timeout */
};

struct hinic5_hwdev {
	void *adapter_hdl;  /* pointer to hinic5_adev or NDIS_Adapter */
#ifdef __UEFI__
	void *busdev_hdl;   /* pointer to pcidev or ub dev */
#endif
	void *dev_hdl; /* pointer to pcidev->dev or Handler, for
			* sdk_err() or dma_alloc()
			*/

	void *service_adapter[SERVICE_T_MAX];
	void *chip_node;
	void *ppf_hwdev;

	u32 wq_page_size;
	int chip_present_flag;
	bool poll;	   /* use polling mode or int mode */
	u32 rsvd1;

	struct hinic5_hwif *hwif; /* include void __iomem *bar */
	struct comm_global_attr glb_attr;
	u64 features[COMM_MAX_FEATURE_QWORD];

	struct cfg_mgmt_info *cfg_mgmt;

	struct hinic5_cmdqs *cmdqs;
	struct hinic5_stateless_aeqs *stateless_aeqs;
	struct hinic5_aeqs *aeqs;
	struct hinic5_ceqs *ceqs;
	struct hinic5_mbox *func_to_func;
	struct hinic5_msg_pf_to_mgmt *pf_to_mgmt;
	struct hinic5_clp_pf_to_mgmt *clp_pf_to_mgmt;

	void *fw_update_hdl;

	void *hinic5_cqm_hdl;
	struct mqm_addr_trans_tbl_info mqm_att;
	struct hinic5_page_addr page_pa0;
	struct hinic5_page_addr page_pa1;
	u32 stateful_ref_cnt;
	u32 rsvd2;

	struct mqm_eqm_hinic5_vram_name_s *mqm_eqm_hinic5_vram_name;

	struct mutex stateful_mutex; /* protect hinic5_cqm init and deinit */

	struct hinic5_hw_stats hw_stats;
	u8 *chip_fault_stats;

	hinic5_event_handler event_callback;
	void *event_pri_handle;

	struct hinic5_board_info board_info;

#if !defined(__UEFI__) && !defined(__VMWARE__) && !defined(__WIN__)
	struct delayed_work	sync_time_task;
	struct delayed_work	sync_kernel_time_task;
	struct delayed_work	channel_detect_task;
	void *non_ptp_cdev; // TODO: Structure definition reference to be resolved
#endif

	struct hinic5_prof_attr	         *prof_attr;
	const struct hinic5_prof_adapter *prof_adap;

	struct workqueue_struct *workq;

	u32 rd_bar_err_cnt;
	u32 linkdown_threshold;
	u32 heartbeat_period;
	atomic_t bus_link_down;
	atomic_t heartbeat_lost;
	struct timer_list heartbeat_timer;
	struct work_struct heartbeat_lost_work;
	atomic_t check_ob_flush_bypass_ref_cnt;

	ulong func_state;
	spinlock_t channel_lock; /* protect channel init and deinit */

	u16 probe_fault_level;

	struct hinic5_devlink *devlink_dev;

	enum hinic5_func_mode	func_mode;
	u32 rsvd3;

	u64 cur_recv_aeq_cnt;
	u64 last_recv_aeq_cnt;
	u32 aeq_busy_cnt;
	u32 max_aeq_busy_cnt;
	u8 rsvd4[52];

	u64 mbox_send_cnt;
	u64 mbox_ack_cnt;

	u8 cmdq_mode;
	u8 cmdq_cos_offset;
	u8 rsvd5[5];            // Reserved for hotpatch
	struct hisdk5_fast_msg_to_func *fast_msg_to_func;
	const struct hinic5_sdk_timeout_info *timeout_info;
};

#define HINIC5_DRV_FEATURE_QW0 \
	(COMM_F_API_CHAIN | COMM_F_CLP | COMM_F_MBOX_SEGMENT | \
	 COMM_F_CMDQ_NUM | COMM_F_VIRTIO_VQ_SIZE | COMM_F_EXTEND_CAP | \
	 COMM_F_SMF_CACHE_INVALID | COMM_F_ONLY_ENHANCE_CMDQ | \
	 COMM_F_USE_REAL_RX_BUF_SIZE | COMM_F_CMD_BUF_SIZE | \
	 COMM_F_HTN_CMD | COMM_F_MBOX_MSG_HEAD_SUPP_VER1 | COMM_F_FAST_MSG | \
	 COMM_F_UFHD | COMM_F_VIRTIO_FC_CACHE_MODE | COMM_F_NON_PTP_SYNC | \
	 COMM_F_HT_GPA | COMM_F_UFHD_FLEX_SEG)

#define HINIC5_MAX_HOST_NUM(hwdev)	((hwdev)->glb_attr.max_host_num)
#define HINIC5_MAX_PF_NUM(hwdev)	((hwdev)->glb_attr.max_pf_num)
#define HINIC5_MGMT_CPU_NODE_ID(hwdev)	((hwdev)->glb_attr.mgmt_host_node_id)

#define COMM_FEATURE_QW0(hwdev, feature)	(((hwdev)->features[0] & COMM_F_##feature) != 0)
#define COMM_SUPPORT_API_CHAIN(hwdev)		COMM_FEATURE_QW0(hwdev, API_CHAIN)
#define COMM_SUPPORT_CLP(hwdev)			COMM_FEATURE_QW0(hwdev, CLP)
#define COMM_SUPPORT_CHANNEL_DETECT(hwdev)	COMM_FEATURE_QW0(hwdev, CHANNEL_DETECT)
#define COMM_SUPPORT_CMDQ_NUM(hwdev)		COMM_FEATURE_QW0(hwdev, CMDQ_NUM)
#define COMM_SUPPORT_CMD_BUF_SIZE(hwdev)	COMM_FEATURE_QW0(hwdev, CMD_BUF_SIZE)
#define COMM_SUPPORT_VIRTIO_VQ_SIZE(hwdev)	COMM_FEATURE_QW0(hwdev, VIRTIO_VQ_SIZE)
#define COMM_IS_USE_REAL_RX_BUF_SIZE(hwdev)	COMM_FEATURE_QW0(hwdev, USE_REAL_RX_BUF_SIZE)
#define COMM_SUPPORT_EXTEND_CAPBILITY(hwdev)	COMM_FEATURE_QW0(hwdev, EXTEND_CAP)
#define COMM_SUPPORT_SMF_CACHE_INVALID(hwdev)	COMM_FEATURE_QW0(hwdev, SMF_CACHE_INVALID)
#define COMM_SUPPORT_ONLY_ENHANCE_CMDQ(hwdev)	COMM_FEATURE_QW0(hwdev, ONLY_ENHANCE_CMDQ)
#define COMM_SUPPORT_HTN_CMD(hwdev)		COMM_FEATURE_QW0(hwdev, HTN_CMD)
#define COMM_SUPPORT_FAST_MSG(hwdev)		COMM_FEATURE_QW0(hwdev, FAST_MSG)
#define COMM_SUPPORT_MBOX_HEAD_VER1(hwdev)	COMM_FEATURE_QW0(hwdev, MBOX_MSG_HEAD_SUPP_VER1)
#define COMM_SUPPORT_UFHD(hwdev)		COMM_FEATURE_QW0(hwdev, UFHD)
#define COMM_SUPPORT_VIRTIO_FC_CACHE(hwdev)	COMM_FEATURE_QW0(hwdev, VIRTIO_FC_CACHE_MODE)
#define COMM_SUPPORT_NON_PTP_SYNC(hwdev)	COMM_FEATURE_QW0(hwdev, NON_PTP_SYNC)
#define COMM_SUPPORT_HT_GPA(hwdev)		COMM_FEATURE_QW0(hwdev, HT_GPA)
#define COMM_SUPPORT_UFHD_FLEX_SEG(hwdev)	COMM_FEATURE_QW0(hwdev, UFHD_FLEX_SEG)

bool hinic5_get_perf_en(enum hinic5_perf_bitmap perf_bit);

#define HINIC5_CHIP_PRESENT	1
#define HINIC5_CHIP_ABSENT	0

/**
 * The chip will be absent when
 *  - link down
 *  - PCI shutdown
 *  - PCI reset done
 */
static inline bool hinic5_is_chip_present(const struct hinic5_hwdev *hwdev)
{
	return hwdev->chip_present_flag == HINIC5_CHIP_PRESENT;
}

/**
 * The chip will be error when
 *  - heartbeat lost
 *  - Level-2 or lower chip faults, see enum hinic5_fault_err_level
 */
static inline bool hinic5_is_chip_error(const struct hinic5_hwdev *hwdev)
{
	struct card_node *chip_info = (struct card_node *)hwdev->chip_node;

	return chip_info->exception_flag;
}

static inline bool hinic5_channel_detect_should_stop(const struct hinic5_hwdev *hwdev)
{
	struct card_node *chip_node = (struct card_node *)hwdev->chip_node;

	return atomic_read(&chip_node->channel_busy_cnt) >= HINIC5_CHANNEL_DETECT_MAX_BUSY;
}

/**
 * @brief hinic5_event_register - register hardware event
 * @param dev: device pointer to hwdev
 * @param pri_handle: private data will be used by the callback
 * @param callback: callback function
 *
 * @return 0: success, non-zero: error code
 */
int hinic5_event_register(void *dev, void *pri_handle, hinic5_event_handler callback);

/**
 * @brief hinic5_event_unregister - unregister hardware event
 * @param dev: device pointer to hwdev
 */
void hinic5_event_unregister(void *dev);

bool hinic5_check_htn_device_id(void *hwdev);

void *hinic5_get_ppf_dev(void);
bool hinic5_is_function_active(struct hinic5_hwdev *hwdev);

/**
 * @brief Dump CMDQ work queue wqebb
 * @param[in]  hwdev    Hardware device
 * @param[in]  cmdq_id  CMDQ id to query
 * @param[in]  wqe_idx  wqebb idx to query
 * @param[out] wqe_desc Queried wqebb information
 *
 * @return Success or not
 *		@retval zero: success
 *		@retval non-zero: failure
 */
int hinic5_dump_cmdq_wqebb(struct hinic5_hwdev *hwdev, u16 cmdq_id, u16 wqe_idx,
			   struct sdk_cmdq_wqe_desc *wqe_desc);

/**
 * @brief Dump CMDQ work queue information
 * @param[in]  hwdev    Hardware device
 * @param[in]  cmdq_id  CMDQ id to query
 * @param[out] wq       Queried CMDQ work queue information
 *
 * @return Success or not
 *		@retval zero: success
 *		@retval non-zero: failure
 */
int hinic5_dump_cmdq_wq(struct hinic5_hwdev *hwdev, u16 cmdq_id, struct hinic5_wq *wq);
#endif

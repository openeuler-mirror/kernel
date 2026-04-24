/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UBASE_DEV_H__
#define __UBASE_DEV_H__

#include <linux/atomic.h>
#include <linux/auxiliary_bus.h>
#include <linux/dma-mapping.h>
#include <linux/if_ether.h>
#include <ub/ubase/ubase_comm_cmd.h>
#include <ub/ubase/ubase_comm_ctrlq.h>
#include <ub/ubase/ubase_comm_debugfs.h>
#include <ub/ubase/ubase_comm_dev.h>
#include <ub/ubase/ubase_comm_eq.h>
#include <ub/ubase/ubase_comm_mbx.h>
#include <ub/ubase/ubase_comm_qos.h>
#include <ub/ubase/ubase_comm_stats.h>

#include "ubase.h"
#include "ubase_eq.h"
#include "ubase_ubus.h"

#define UBASE_MOD_VERSION		"1.0"

#define ubase_dbg(_udev, fmt, ...) do {	                                      \
	if (ubase_dbg_default())                                              \
		dev_info(_udev->dev, "(pid %d) " fmt,                         \
			 current->pid, ##__VA_ARGS__);                        \
	} while (0)

#define ubase_err(_udev, fmt, ...)                                            \
	dev_err(_udev->dev, "(pid %d) " fmt,                                  \
		current->pid, ##__VA_ARGS__)

#define ubase_info(_udev, fmt, ...)                                           \
	dev_info(_udev->dev, "(pid %d) " fmt,                                 \
		 current->pid, ##__VA_ARGS__)

#define ubase_warn(_udev, fmt, ...)                                           \
	dev_warn(_udev->dev, "(pid %d) " fmt,                                 \
		 current->pid, ##__VA_ARGS__)

#define ubase_err_rl(_udev, log_cnt, fmt, ...) do {                           \
	if (__ratelimit(&(_udev->log_rs.rs))) {                               \
		ubase_err(_udev, fmt, ##__VA_ARGS__);                         \
	} else {                                                              \
		(log_cnt)++;                                                  \
		ubase_dbg(_udev, fmt, ##__VA_ARGS__);                         \
	}                                                                     \
} while (0)

#define ubase_info_rl(_udev, log_cnt, fmt, ...) do {                          \
	if (__ratelimit(&(_udev->log_rs.rs))) {                               \
		ubase_info(_udev, fmt, ##__VA_ARGS__);                        \
	} else {                                                              \
		(log_cnt)++;                                                  \
		ubase_dbg(_udev, fmt, ##__VA_ARGS__);                         \
	}                                                                     \
} while (0)

#define ubase_warn_rl(_udev, log_cnt, fmt, ...) do {                          \
	if (__ratelimit(&(_udev->log_rs.rs))) {                               \
		ubase_warn(_udev, fmt, ##__VA_ARGS__);                        \
	} else {                                                              \
		(log_cnt)++;                                                  \
		ubase_dbg(_udev, fmt, ##__VA_ARGS__);                         \
	}                                                                     \
} while (0)

struct ubase_ctx_buf {
	struct ubase_ctx_buf_cap jfs;
	struct ubase_ctx_buf_cap jfr;
	struct ubase_ctx_buf_cap jfc;
	struct ubase_ctx_buf_cap jtg;
	struct ubase_ctx_buf_cap rc;
};

struct ubase_ue_node {
	struct list_head	list;
	u16			bus_ue_id;
};

struct ubase_cmdq_desc;
struct ubase_cmdq_ring {
	u32 ci;
	u32 pi;
	u32 desc_num;
	u32 tx_timeout;
	dma_addr_t desc_dma_addr;
	struct ubase_cmdq_desc *desc;
	spinlock_t lock;
};

struct ubase_cmdq {
	struct ubase_cmdq_ring csq;
	struct ubase_cmdq_ring crq;
	atomic_t csq_cnt;
};

struct ubase_hw {
	struct ubase_resource_space rs0_base;
	struct ubase_resource_space io_base;
	struct ubase_resource_space mem_base;
	struct ubase_cmdq cmdq;
	unsigned long state;
};

struct ubase_mbx_event_context {
	struct completion		done;
	int				result;
	u64				out_param;
	u16				seq_num;
	struct ubase_cmd_mailbox	*mbx_buff;
};

struct ubase_adev {
	struct auxiliary_device adev;
	struct ubase_dev *udev;
	struct atomic_notifier_head	comp_nh;
	struct notifier_block	comp_notifier;
	int idx;

	struct mutex	virt_lock;
	void (*virt_handler)(struct auxiliary_device *adev, u16 bus_ue_id,
			     bool is_en);
	struct mutex	port_lock;
	void (*port_handler)(struct auxiliary_device *adev, bool link_up);
	struct mutex	reset_lock;
	void (*reset_handler)(struct auxiliary_device *adev,
			      enum ubase_reset_stage stage);
	struct mutex	activate_lock;
	void (*activate_handler)(struct auxiliary_device *adev, bool activate);
};

struct ubase_priv {
	struct ubase_adev *uadev[UBASE_DRV_MAX];
	struct mutex uadev_lock; /* protect uadev[] */
};

struct ubase_dev_caps {
	struct ubase_adev_caps	udma_caps;
	struct ubase_adev_caps	unic_caps;
	struct ubase_caps	dev_caps;
};

struct ubase_mbox_cmd {
	struct dma_pool *pool;
	struct semaphore sem;
	struct ubase_mbx_event_context ctx;
	atomic_t mbx_cnt;
};

struct ubase_destroy_res_cmd {
	u8 destroy_done;
	u8 rsv[23];
};

struct ubase_dma_buf {
	void		*addr;
	dma_addr_t	dma_addr;
	size_t		size;
};

struct ubase_ctx_page {
	dma_addr_t		iova;
	u32			npage;
	refcount_t		refcount;
};

struct ubase_ta_layer_ctx {
	struct ubase_dma_buf	extdb_buf;
	struct ubase_dma_buf	timer_buf;
};

struct ubase_tp_layer_ctx {
	spinlock_t		tpg_lock;
	struct ubase_tpg	*tpg;
};

struct ubase_rc_queue {
	dma_addr_t	iova;
	void		*va;
	struct page	*page;
};

struct ubase_reset_stat {
	u32 reset_done_cnt;
	u32 hw_reset_done_cnt;
	u32 elr_reset_cnt;
	u32 reset_fail_cnt;
	u32 reset_retry_cnt;
	u32 port_reset_cnt;
	u32 himac_reset_cnt;
};

enum ubase_dev_state_bit {
	UBASE_STATE_INITED_B,
	UBASE_STATE_DISABLED_B,
	UBASE_STATE_RST_HANDLING_B,
	UBASE_STATE_IRQ_INVALID_B,
	UBASE_STATE_PORT_RESETTING_B,
	UBASE_STATE_CTX_READY_B,
	UBASE_STATE_PREALLOC_OK_B,
	UBASE_STATE_RST_WAIT_DEACTIVE_B,
	UBASE_STATE_SHUTDOWN,
};

struct ubase_crq_event_nbs {
	struct list_head list;
	struct ubase_crq_event_nb nb;
};

struct ubase_crq_table {
	struct mutex lock;
	unsigned long last_crq_scheduled;
	struct ubase_crq_event_nbs nbs;
};

#define UBASE_CTRLQ_DATA_NUM	5

#pragma pack(push, 1)
struct ubase_ctrlq_base_block {
	u8	service_ver;
	u8	service_type;
	u8	bb_num;
	u8	opcode;
	u8	ret;
	__le16	seq;
	u8	mbx_ue_id;
	__le16	bus_ue_id;
	__le16	rsv;
	__le32	data[UBASE_CTRLQ_DATA_NUM];
};
#pragma pack(pop)

struct ubase_ctrlq_ring {
	u16		ci;
	u16		pi;
	u16		depth;
	u32		tx_timeout;
	void __iomem	*base_addr;
	spinlock_t	lock;
};

struct ubase_ctrlq_msg_ctx {
	u8	valid : 1;
	u8	is_sync : 1;
	u8	rsv0 : 6;
	u8	mbx_ue_id;
	u8	result;
	u8	rsv1;
	u16	ue_seq;
	u16	bus_ue_id;
	u16	out_size;
	void	*out;
	unsigned long	dead_jiffies;
	struct completion	done;
};

struct ubase_ctrlq_crq_table {
	struct mutex	lock;
	unsigned long	last_crq_scheduled;
	u16				crq_nb_cnt;
	struct ubase_ctrlq_event_nb	*crq_nbs;
};

struct ubase_ctrlq_ue_req_event_nbs {
	struct list_head			list;
	struct ubase_ctrlq_ue_msg_nb		msg_nb;
};

struct ubase_ctrlq_ue_resp_event_nbs {
	struct list_head			list;
	struct ubase_ctrlq_ue_msg_nb		msg_nb;
};

struct ubase_ctrlq_ue_req_table {
	struct mutex				lock;
	struct ubase_ctrlq_ue_req_event_nbs	ue_req_nbs;
};

struct ubase_ctrlq_ue_resp_table {
	struct mutex				lock;
	struct ubase_ctrlq_ue_resp_event_nbs	ue_resp_nbs;
};

struct ubase_ctrlq {
	u16				csq_next_seq;
	unsigned long			state;
	atomic_t			req_cnt;
	struct ubase_ctrlq_ring		csq;
	struct ubase_ctrlq_ring		crq;
	struct ubase_ctrlq_msg_ctx	*msg_queue;
	struct ubase_ctrlq_crq_table	crq_table;
	struct ubase_ctrlq_ue_req_table		ue_req_table;
	struct ubase_ctrlq_ue_resp_table	ue_resp_table;
	struct semaphore			sem;
};

#define UBASE_ACT_STAT_MAX_NUM 10U
struct ubase_activate_dev_stats {
	u64	act_cnt;
	u64	deact_cnt;
	struct {
		bool		activate;
		int		result;
		time64_t	time;
	} stats[UBASE_ACT_STAT_MAX_NUM];
	struct mutex	lock;
};

struct ubase_stats {
	struct mutex			stats_lock;
	struct ubase_eth_mac_stats	eth_stats;
	struct ubase_activate_dev_stats	activate_record;
};

struct ubase_act_info {
	u16			wait_msn;
	u8			shutdown;
	int			result;
	struct completion	activate_done;
};

struct ubase_act_ctx {
	u16			msn;
	struct ubase_act_info	self;
	struct ubase_act_info	other;
	struct mutex		lock;
};

struct ubase_arq_msg {
	u16 opcode;
	void *data;
	u32 data_len;
};

#define MAX_ARQ_MSG_NUM 128
struct ubase_arq_msg_ring {
	u8 pi;
	u8 ci;
	atomic_t count;
	struct ubase_arq_msg msg[MAX_ARQ_MSG_NUM];
};

struct ubase_pmem_ctx {
	u16			page_cnt;
	struct page		**pgs;
	struct scatterlist	*sg;
	dma_addr_t		dma_addr;
};

struct ubase_prealloc_mem_info {
	struct ubase_pmem_ctx	comm;
	struct ubase_pmem_ctx	udma;
};

struct ubase_log_rs {
	struct ratelimit_state rs;
	u16 ctrlq_other_seq_invalid_log_cnt;
	u64 aeq_event_type_exceed_max_cnt;
	u32 ctrlq_wait_resp_timeout_cnt;
	u32 ctrlq_pi_invalid_cnt;
	u32 mbx_buff_not_empty_cnt;
};

enum ubase_node_type {
	UBASE_NODE_TYPE_UNKNOWN,
	UBASE_NODE_TYPE_INBAND_CTRL,
	UBASE_NODE_TYPE_INBAND_CTRLED,
	UBASE_NODE_TYPE_OUTBAND_CTRL,
	UBASE_NODE_TYPE_OUTBAND_CTRLED,
};

struct ubase_dev_qos {
	struct ubase_adev_qos		adev_qos;
	struct ubase_initial_qset_qos	initial_qos;
};

struct ubase_mm_ops {
	void *(*alloc_mem)(struct device *dev, dma_addr_t *dma_ctx_buf_ba,
			   size_t size, u32 ubase_mem_op);
	void (*free_mem)(struct device *dev, dma_addr_t *dma_ctx_buf_ba,
			 size_t size, u32 ubase_mem_op);
};

struct ubase_mem_init_ops {
	int (*mem_init)(struct device *dev, struct ubase_mm_ops *mm_ops);
	void (*mem_uninit)(struct device *dev, struct ubase_mm_ops *mm_ops);
};

struct ubase_dev {
	struct device		*dev;
	int			dev_id;
	struct ubase_priv	priv;
	struct ubase_hw		hw;

	bool			use_fixed_rc_num;
	enum ubase_node_type	node_type;
	struct ubase_dev_caps	caps;
	struct ubase_dev_qos	qos;
	struct ubase_dbgfs	dbgfs;
	struct ubase_ctx_buf	ctx_buf;
	struct ubase_ta_layer_ctx	ta_ctx;
	struct ubase_tp_layer_ctx	tp_ctx;
	struct ubase_rc_queue	*rc_entry;
	u32			cap_bits[UBASE_CAP_LEN];
	struct ubase_irq_table	irq_table;
	struct ubase_mbox_cmd	mb_cmd;
	struct workqueue_struct	*ubase_wq;
	struct workqueue_struct	*ubase_ctrlq_wq;
	struct workqueue_struct	*ubase_async_wq;
	struct workqueue_struct	*ubase_reset_wq;
	struct workqueue_struct	*ubase_period_wq;
	struct workqueue_struct	*ubase_arq_wq;
	unsigned long		serv_proc_cnt;
	struct ubase_delay_work	service_task;
	struct ubase_delay_work	ctrlq_service_task;
	struct ubase_delay_work	reset_service_task;
	struct ubase_delay_work	period_service_task;
	struct ubase_delay_work	arq_service_task;
	struct ubase_crq_table	crq_table;
	struct ubase_ctrlq	ctrlq;
	unsigned long		state_bits;
	struct list_head	ue_list;
	struct mutex		ue_list_lock;

	struct ubase_reset_stat	reset_stat;
	enum ubase_reset_type	reset_type;
	unsigned long		last_reset_scheduled;
	enum ubase_reset_stage	reset_stage;
	struct ubase_stats	stats;
	struct ubase_act_ctx	act_ctx;
	struct ubase_arq_msg_ring	arq;
	struct ubase_prealloc_mem_info	pmem_info;
	u8			dev_mac[ETH_ALEN];
	struct ubase_log_rs	log_rs;
	struct ubase_mem_init_ops	mem_init_ops;
	struct ubase_mm_ops	mm_ops;
};

#define UBASE_ERR_MSG_LEN	128
struct ubase_init_function {
	char err_msg[UBASE_ERR_MSG_LEN];
	u32 support_devs;
	u8 need_reset;
	int (*init_func)(struct ubase_dev *udev);
	void (*uninit_func)(struct ubase_dev *udev);
};

bool ubase_dbg_default(void);
bool ubase_dev_urma_supported(struct ubase_dev *udev);
bool ubase_dev_unic_supported(struct ubase_dev *udev);
bool ubase_dev_cdma_supported(struct ubase_dev *udev);
bool ubase_dev_pmu_supported(struct ubase_dev *udev);
bool ubase_dev_fwctl_supported(struct ubase_dev *udev);

static inline
struct ubase_dev *__ubase_get_udev_by_adev(struct auxiliary_device *adev)
{
	struct ubase_adev *uadev = container_of(adev, struct ubase_adev, adev);
	return uadev->udev;
}

static inline bool ubase_dev_uvb_supported(struct ubase_dev *udev)
{
	return ubase_get_cap_bit(udev, UBASE_SUPPORT_UVB_B);
}

static inline bool ubase_ip_over_urma_supported(struct ubase_dev *udev)
{
	return ubase_get_cap_bit(udev, UBASE_SUPPORT_IP_OVER_URMA_B);
}

static inline bool ubase_ip_over_urma_utp_supported(struct ubase_dev *udev)
{
	return ubase_get_cap_bit(udev, UBASE_SUPPORT_IP_OVER_URMA_UTP_B);
}

static inline bool ubase_pmu_irq_supported(struct ubase_dev *udev)
{
	return ubase_get_cap_bit(udev, UBASE_SUPPORT_PMU_IRQ_B);
}

static inline
struct ubase_dev *ubase_get_udev_by_adev(struct auxiliary_device *adev)
{
	if (!adev)
		return NULL;

	return __ubase_get_udev_by_adev(adev);
}

static inline bool ubase_dev_udma_supported(struct ubase_dev *udev)
{
	return ubase_dev_urma_supported(udev) &&
	       !ubase_get_cap_bit(udev, UBASE_SUPPORT_UDMA_DISABLE_B);
}

static inline bool ubase_dev_ubl_supported(struct ubase_dev *udev)
{
	return ubase_get_cap_bit(udev, UBASE_SUPPORT_UBL_B);
}

static inline bool ubase_dev_ta_extdb_buf_supported(struct ubase_dev *udev)
{
	return ubase_get_cap_bit(udev, UBASE_SUPPORT_TA_EXTDB_BUF_B);
}

static inline bool ubase_dev_ta_timer_buf_supported(struct ubase_dev *udev)
{
	return ubase_get_cap_bit(udev, UBASE_SUPPORT_TA_TIMER_BUF_B);
}

static inline bool ubase_dev_err_handle_supported(struct ubase_dev *udev)
{
	return ubase_get_cap_bit(udev, UBASE_SUPPORT_ERR_HANDLE_B);
}

static inline bool ubase_dev_ctrlq_supported(struct ubase_dev *udev)
{
	return ubase_get_cap_bit(udev, UBASE_SUPPORT_CTRLQ_B);
}

static inline bool ubase_dev_eth_mac_supported(struct ubase_dev *udev)
{
	return ubase_get_cap_bit(udev, UBASE_SUPPORT_ETH_MAC_B);
}

static inline bool ubase_dev_mac_stats_supported(struct ubase_dev *udev)
{
	return ubase_get_cap_bit(udev, UBASE_SUPPORT_MAC_STATS_B);
}

static inline bool __ubase_dev_prealloc_supported(struct ubase_dev *udev)
{
	return ubase_get_cap_bit(udev, UBASE_SUPPORT_PRE_ALLOC_B);
}

static inline bool ubase_activate_proxy_supported(struct ubase_dev *udev)
{
	return ubase_get_cap_bit(udev, UBASE_SUPPORT_ACTIVATE_PROXY_B);
}

static inline bool ubase_utp_supported(struct ubase_dev *udev)
{
	return ubase_get_cap_bit(udev, UBASE_SUPPORT_UTP_B);
}

static inline bool ubase_ucp_supported(struct ubase_dev *udev)
{
	return ubase_get_cap_bit(udev, UBASE_SUPPORT_UCP_B);
}

static inline bool ubase_dev_prealloc_supported(struct ubase_dev *udev)
{
	return __ubase_dev_prealloc_supported(udev) &&
	       PAGE_SIZE != UBASE_PMEM_PAGE_SIZE;
}

static inline bool ubase_dev_usc_supported(struct ubase_dev *udev)
{
	return ubase_get_cap_bit(udev, UBASE_SUPPORT_USC_B);
}

static inline u32 ubase_jfs_num(struct ubase_dev *udev)
{
	struct ubase_adev_caps *unic_caps = &udev->caps.unic_caps;
	struct ubase_adev_caps *udma_caps = &udev->caps.udma_caps;
	struct ubase_caps *dev_caps = &udev->caps.dev_caps;

	return unic_caps->jfs.max_cnt + udma_caps->jfs.max_cnt +
	       dev_caps->public_jetty_cnt + dev_caps->rsvd_jetty_cnt;
}

static inline u32 ubase_jfs_ctx_align_size(struct ubase_dev *udev)
{
	return ALIGN(ubase_jfs_num(udev) * UBASE_JFS_CTX_SIZE, PAGE_SIZE);
}

static inline u32 ubase_ta_timer_align_size(struct ubase_dev *udev)
{
	return ALIGN(udev->ta_ctx.timer_buf.size, PAGE_SIZE);
}

static inline bool ubase_mbx_ue_id_is_valid(u16 mbx_ue_id,
					    struct ubase_dev *udev)
{
	if (!mbx_ue_id || (mbx_ue_id >= udev->caps.dev_caps.ue_num))
		return false;

	return true;
}

static inline bool ubase_shutting_down(struct ubase_dev *udev)
{
	return test_bit(UBASE_STATE_SHUTDOWN, &udev->state_bits);
}

static inline bool ubase_is_ctrl_node(struct ubase_dev *udev)
{
	return udev->node_type == UBASE_NODE_TYPE_INBAND_CTRL;
}

int ubase_adev_idx_alloc(void);
void ubase_adev_idx_free(int id);

void ubase_port_down(struct ubase_dev *udev);
void ubase_port_up(struct ubase_dev *udev);

int ubase_dev_init(struct ubase_dev *udev);
void ubase_dev_uninit(struct ubase_dev *udev);

int ubase_dev_reset_init(struct ubase_dev *udev);
void ubase_dev_reset_uninit(struct ubase_dev *udev);

void ubase_suspend_aux_devices(struct ubase_dev *udev);
void ubase_resume_aux_devices(struct ubase_dev *udev);

void ubase_virt_handler(struct ubase_dev *udev, u16 bus_ue_id, bool is_en);

void __ubase_deactivate_dev(struct ubase_dev *udev);

int ubase_activate_handler(struct ubase_dev *udev, u32 bus_ue_id);
int ubase_deactivate_handler(struct ubase_dev *udev, u32 bus_ue_id);

void ubase_flush_workqueue(struct ubase_dev *udev);

#endif

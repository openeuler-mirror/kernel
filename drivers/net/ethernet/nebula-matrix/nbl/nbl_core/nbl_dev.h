/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_DEV_H_
#define _NBL_DEV_H_

#include "nbl_core.h"
#include "nbl_dev_user.h"
#include "nbl_sysfs.h"

#define NBL_DEV_MGT_TO_COMMON(dev_mgt)		((dev_mgt)->common)
#define NBL_DEV_MGT_TO_DEV(dev_mgt)		NBL_COMMON_TO_DEV(NBL_DEV_MGT_TO_COMMON(dev_mgt))
#define NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt)	((dev_mgt)->common_dev)
#define NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt)	((dev_mgt)->ctrl_dev)
#define NBL_DEV_MGT_TO_NET_DEV(dev_mgt)		((dev_mgt)->net_dev)
#define NBL_DEV_MGT_TO_RDMA_DEV(dev_mgt)	((dev_mgt)->rdma_dev)
#define NBL_DEV_MGT_TO_USER_DEV(dev_mgt)	((dev_mgt)->user_dev)
#define NBL_DEV_MGT_TO_REP_DEV(dev_mgt)		((dev_mgt)->rep_dev)
#define NBL_DEV_MGT_TO_LAG_DEV(dev_mgt)		((dev_mgt)->lag_dev)
#define NBL_DEV_MGT_TO_ST_DEV(dev_mgt)		((dev_mgt)->st_dev)
#define NBL_DEV_COMMON_TO_MSIX_INFO(dev_common)	(&(dev_common)->msix_info)
#define NBL_DEV_CTRL_TO_TASK_INFO(dev_ctrl)	(&(dev_ctrl)->task_info)
#define NBL_DEV_MGT_TO_EMP_CONSOLE(dev_mgt)	((dev_mgt)->emp_console)
#define NBL_DEV_MGT_TO_NETDEV_OPS(dev_mgt)	((dev_mgt)->net_dev->ops)

#define NBL_DEV_MGT_TO_SERV_OPS_TBL(dev_mgt)	((dev_mgt)->serv_ops_tbl)
#define NBL_DEV_MGT_TO_SERV_OPS(dev_mgt)	(NBL_DEV_MGT_TO_SERV_OPS_TBL(dev_mgt)->ops)
#define NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt)	(NBL_DEV_MGT_TO_SERV_OPS_TBL(dev_mgt)->priv)
#define NBL_DEV_MGT_TO_RES_PT_OPS(adapter) (&(NBL_DEV_MGT_TO_SERV_OPS_TBL(dev_mgt)->pt_tbl.pt_ops))
#define NBL_DEV_MGT_TO_CHAN_OPS_TBL(dev_mgt)	((dev_mgt)->chan_ops_tbl)
#define NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt)	(NBL_DEV_MGT_TO_CHAN_OPS_TBL(dev_mgt)->ops)
#define NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt)	(NBL_DEV_MGT_TO_CHAN_OPS_TBL(dev_mgt)->priv)
#define NBL_DEV_MGT_TO_DISP_OPS_TBL(dev_mgt)	((dev_mgt)->disp_ops_tbl)
#define NBL_DEV_MGT_TO_DISP_OPS(dev_mgt)	(NBL_DEV_MGT_TO_DISP_OPS_TBL(dev_mgt)->ops)
#define NBL_DEV_MGT_TO_DISP_PRIV(dev_mgt)	(NBL_DEV_MGT_TO_DISP_OPS_TBL(dev_mgt)->priv)

#define DEFAULT_MSG_ENABLE (NETIF_MSG_DRV | NETIF_MSG_PROBE | NETIF_MSG_LINK | \
			    NETIF_MSG_IFDOWN | NETIF_MSG_IFUP)

#define NBL_STRING_NAME_LEN			(32)
#define NBL_DEFAULT_MTU				(1500)

#define NBL_MAX_CARDS				16

#define NBL_DEV_BATCH_RESET_FUNC_NUM		(32)
#define NBL_DEV_BATCH_RESET_USEC		(1000000)

#define NBL_TIME_LEN				(32)
#define NBL_SAVED_TRACES_NUM			(16)

#define NBL_DEV_FW_RESET_WAIT_TIME		(3500)

#define NBL_DEV_WAIT_CTRL_TRY_NUM		30
#define NBL_DEV_WAIT_CTRL_SLEEP_MIN_TIME1	500000
#define NBL_DEV_WAIT_CTRL_SLEEP_MAX_TIME1	600000
#define NBL_DEV_WAIT_CTRL_SLEEP_MIN_TIME2	3000000
#define NBL_DEV_WAIT_CTRL_SLEEP_MAX_TIME2	4000000

/* CTRL wait 1s to insure emp finish resource clear */
#define NBL_DEV_RESUME_DELAY_CTRL_TIME		1500
#define NBL_DEV_RESUME_DELAY_PF_TIME		3500
#define NBL_DEV_RESUME_DELAY_VF_TIME		6500

enum nbl_reset_status {
	NBL_RESET_INIT,
	NBL_RESET_SEND,
	NBL_RESET_DONE,
	NBL_RESET_STATUS_MAX
};

struct nbl_task_info {
	struct nbl_adapter *adapter;
	struct nbl_dev_mgt *dev_mgt;
	struct work_struct offload_network_task;
	struct work_struct fw_hb_task;
	struct delayed_work fw_reset_task;
	struct work_struct clean_adminq_task;
	struct work_struct ipsec_task;
	struct work_struct port_link_task;
	struct work_struct sfp_plug_task;
	struct work_struct adapt_desc_gother_task;
	struct work_struct clean_abnormal_irq_task;
	struct work_struct report_temp_task;
	struct work_struct report_reboot_task;
	struct work_struct reset_task;
	enum nbl_reset_event reset_event;
	enum nbl_reset_status reset_status[NBL_MAX_FUNC];
	struct timer_list serv_timer;
	unsigned long serv_timer_period;

	bool fw_resetting;
	bool timer_setup; /* need setup timer */
	bool timer_working; /* timer has init */
};

struct nbl_reset_task_info {
	struct work_struct task;
	enum nbl_reset_event event;
};

/* resume task's finite state machaine */
enum nbl_resume_fsm {
	NBL_RESUME_INIT_FSM,
	NBL_RESUME_WAIT_CHAN_RDY_FSM,
	NBL_RESUME_RECOVERING_FSM,
	NBL_RESUME_SUCCESS_FSM,
	NBL_RESUME_FINISH_FSM,
	NBL_RESUME_ERR_FSM,
	NBL_RESUME_MAX_FSM,
};

struct nbl_resume_task_info {
	struct delayed_work task;
	int my_ctrl_rsm_done;
	int ctrl_ack_rsm_tmp;
	enum nbl_resume_fsm fsm;
};

enum nbl_msix_serv_type {
	/* virtio_dev has a config vector_id, and the vector_id need is 0 */
	NBL_MSIX_VIRTIO_TYPE = 0,
	NBL_MSIX_NET_TYPE,
	NBL_MSIX_MAILBOX_TYPE,
	NBL_MSIX_ABNORMAL_TYPE,
	NBL_MSIX_ADMINDQ_TYPE,
	NBL_MSIX_RDMA_TYPE,
	NBL_MSIX_SFP_PLUG_TYPE,
	NBL_MSIX_TYPE_MAX

};

struct nbl_msix_serv_info {
	char irq_name[NBL_STRING_NAME_LEN];
	u16 num;
	u16 base_vector_id;
	/* true: hw report msix, hw need to mask actively */
	bool hw_self_mask_en;
	bool enable;
};

struct nbl_msix_info {
	struct nbl_msix_serv_info serv_info[NBL_MSIX_TYPE_MAX];
	struct msix_entry *msix_entries;
};

struct nbl_dev_common {
	struct nbl_dev_mgt *dev_mgt;
	struct device *hwmon_dev;
	struct nbl_msix_info msix_info;
	char mailbox_name[NBL_STRING_NAME_LEN];
	// for ctrl-dev/net-dev mailbox recv msg
	struct work_struct clean_mbx_task;

	struct devlink_ops *devlink_ops;
	struct devlink *devlink;
	struct nbl_reset_task_info reset_task;
	struct nbl_resume_task_info resume_task;
};

enum nbl_dev_temp_status {
	NBL_TEMP_STATUS_NORMAL = 0,
	NBL_TEMP_STATUS_WARNING,
	NBL_TEMP_STATUS_CRIT,
	NBL_TEMP_STATUS_EMERG,
	NBL_TEMP_STATUS_MAX
};

enum nbl_emp_log_level {
	NBL_EMP_ALERT_LOG_FATAL = 0,
	NBL_EMP_ALERT_LOG_ERROR = 1,
	NBL_EMP_ALERT_LOG_WARNING = 2,
	NBL_EMP_ALERT_LOG_INFO = 3,
};

struct nbl_fw_reporter_ctx {
	u64 timestamp;
	u32 temp_num;
	char reboot_report_time[NBL_TIME_LEN];
};

struct nbl_fw_temp_trace_data {
	u64 timestamp;
	u32 temp_num;
};

struct nbl_fw_reboot_trace_data {
	char local_time[NBL_TIME_LEN];
};

struct nbl_health_reporters {
	struct {
		struct nbl_fw_temp_trace_data trace_data[NBL_SAVED_TRACES_NUM];
		u8 saved_traces_index;
		struct mutex lock; /* protect reading data of temp_trace_data*/
	} temp_st_arr;

	struct {
		struct nbl_fw_reboot_trace_data trace_data[NBL_SAVED_TRACES_NUM];
		u8 saved_traces_index;
		struct mutex lock; /* protect reading data of reboot_trace_data*/
	} reboot_st_arr;

	struct nbl_fw_reporter_ctx reporter_ctx;
	struct devlink_health_reporter *fw_temp_reporter;
	struct devlink_health_reporter *fw_reboot_reporter;
};

struct nbl_dev_ctrl {
	struct nbl_task_info task_info;
	enum nbl_dev_temp_status temp_status;
	struct nbl_health_reporters health_reporters;
	struct workqueue_struct *ctrl_dev_wq1;
};

enum nbl_dev_emp_alert_event {
	NBL_EMP_EVENT_TEMP_ALERT = 1,
	NBL_EMP_EVENT_LOG_ALERT = 2,
	NBL_EMP_EVENT_MODULE_TEMP_ALERT = 3,
	NBL_EMP_EVENT_MAX
};

enum nbl_dev_temp_threshold {
	NBL_TEMP_NOMAL_THRESHOLD = 85,
	NBL_TEMP_WARNING_THRESHOLD = 105,
	NBL_TEMP_CRIT_THRESHOLD = 115,
	NBL_TEMP_EMERG_THRESHOLD = 120,
};

struct nbl_dev_temp_alarm_info {
	int logvel;
#define NBL_TEMP_ALARM_STR_LEN		128
	char alarm_info[NBL_TEMP_ALARM_STR_LEN];
};

struct nbl_dev_vsi_controller {
	u16 queue_num;
	u16 queue_free_offset;
	void *vsi_list[NBL_VSI_MAX];
};

struct nbl_dev_net_ops {
	int (*setup_netdev_ops)(void *priv, struct net_device *netdev,
				struct nbl_init_param *param);
	int (*setup_ethtool_ops)(void *priv, struct net_device *netdev,
				 struct nbl_init_param *param);
#ifdef CONFIG_DCB
	int (*setup_dcbnl_ops)(void *priv, struct net_device *netdev,
			       struct nbl_init_param *param);
#endif
};

struct nbl_dev_attr_info {
	struct nbl_netdev_name_attr dev_name_attr;
};

struct nbl_dev_net {
	struct net_device *netdev;
	struct nbl_dev_attr_info dev_attr;
	struct nbl_dev_net_ops *ops;
	u8 lag_inited;
	u8 eth_id;
	struct nbl_dev_vsi_controller vsi_ctrl;
	u16 total_queue_num;
	u16 kernel_queue_num;
	u16 user_queue_num;
	u16 total_vfs;
	struct nbl_net_qos qos_config;
	struct nbl_net_mirror mirror_config;
	struct nbl_st_name st_name;
};

enum {
	NBL_DISABLE_ADEV = 1 << 0,
	NBL_DISABLE_GRC_ADEV = 1 << 1,
};

enum nbl_asyn_evt {
	NBL_RDMA_BOND_CFG,
	NBL_RDMA_MTU_CFG,
	NBL_RDMA_OVS_OFFLOAD,
	NBL_RDMA_ASYNC_EVT_MAX,
};

union nbl_async_evt_data {
	bool bond_shp_dis;
	bool ovs_offld;
	int mtu;
};

struct nbl_dev_rdma {
	struct mutex adev_lock; /* protect adev add/remove multi path  */
	struct nbl_dev_mgt *dev_mgt;
	struct auxiliary_device *adev;
	struct auxiliary_device *grc_adev;
	struct auxiliary_device *bond_adev;
	struct work_struct abnormal_event_task;
	int adev_index;
	int grc_adev_index;
	u32 mem_type;
	bool has_rdma;
	bool has_grc;
	bool bond_shp_dis;
	bool bond_registered;
	bool bond_shaping_configed;
	bool mirror_enable;
	bool has_abnormal_event_task;
	u32 internal_cfg;
	/**
	 * Asynchronously process OS notification events to avoid a scenario
	 * where the protocol stack holds the `rtnl_lock` while `nbl_core` holds
	 * the `nbl_lag_devcomm_lock`, whereas `nbl_do_bond_work`—which holds
	 * the`nbl_lag_devcomm_lock` while adding or removing RDMA adevs—would
	 * attempt to acquire the `rtnl_lock`, resulting in a deadlock.
	 */
	struct work_struct asyn_evt_task;
	spinlock_t async_evt_lock; /* protect aync_evt_change */
	union nbl_async_evt_data aync_evt_data[NBL_RDMA_ASYNC_EVT_MAX];
	bool aync_evt_change[NBL_RDMA_ASYNC_EVT_MAX];
};

struct nbl_dev_emp_console {
	struct nbl_dev_mgt *dev_mgt;
	unsigned int id;
	atomic_t opened;
	wait_queue_head_t wait;
	struct cdev cdev;
	struct kfifo rx_fifo;
	struct ktermios termios;
};

#if (IS_ENABLED(CONFIG_VFIO) && IS_ENABLED(CONFIG_VFIO_MDEV))
struct nbl_dev_user_iommu_group {
	struct mutex dma_tree_lock; /* lock dma tree */
	struct list_head group_next;
	struct kref     kref;
	struct rb_root dma_tree;
	struct iommu_group *iommu_group;
	struct device *dev;
	struct device *mdev;
	struct vfio_device *vdev;
};

#endif

struct nbl_dev_user {
#if (IS_ENABLED(CONFIG_VFIO) && IS_ENABLED(CONFIG_VFIO_MDEV))
	struct vfio_device *vdev;
	struct device mdev;
#endif
	struct notifier_block iommu_notifier;
	struct device *dev;
	struct nbl_adapter *adapter;
	struct nbl_dev_user_iommu_group *group;
	void *shm_msg_ring;
	u64 dma_limit;
	atomic_t open_cnt;
	int minor;
	int network_type;
	bool iommu_status;
	bool remap_status;
	bool user_promisc_mode;
	bool user_mcast_mode;
	bool dsch_status;
	u16 user_vsi;
};

#if (IS_ENABLED(CONFIG_VFIO) && IS_ENABLED(CONFIG_VFIO_MDEV))
struct nbl_vfio_device {
	struct vfio_device vdev;
	struct nbl_dev_user *user;
};

#define NBL_USERDEV_TO_VFIO_DEV(user)	((user)->vdev)
#define NBL_VFIO_DEV_TO_USERDEV(vdev)	(*(struct nbl_dev_user **)((vdev) + 1))
#endif

struct nbl_dev_rep {
	struct nbl_rep_data *rep;
	int num_vfs;
};

/* Unify leonis/draco/rnic resource tool. All pf has st char dev. For leonis, only pf0 has adminq,
 * so other pf's resoure tool use pf0's char dev actually.
 */
struct nbl_dev_st_dev {
	char st_name[NBL_RESTOOL_NAME_LEN];
	char real_st_name[NBL_RESTOOL_NAME_LEN];
};

struct nbl_lag_dev;

struct nbl_dev_mgt {
	struct nbl_common_info *common;
	struct nbl_service_ops_tbl *serv_ops_tbl;
	struct nbl_channel_ops_tbl *chan_ops_tbl;
	struct nbl_dispatch_ops_tbl *disp_ops_tbl;
	struct nbl_dev_common *common_dev;
	struct nbl_dev_ctrl *ctrl_dev;
	struct nbl_dev_net *net_dev;
	struct nbl_dev_rdma *rdma_dev;
	struct nbl_dev_emp_console *emp_console;
	struct nbl_dev_rep *rep_dev;
	struct nbl_dev_st_dev *st_dev;
	struct nbl_lag_dev *lag_dev;
	struct nbl_devcomm_comp_dev *pf_comp_dev;
	struct nbl_dev_user *user_dev;
	struct nbl_adapter *adapter;
	u32 adev_flag;
};

struct nbl_dev_vsi_ops {
	int (*register_vsi)(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param,
			    void *vsi_data);
	int (*setup)(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param,
		     void *vsi_data);
	void (*remove)(struct nbl_dev_mgt *dev_mgt, void *vsi_data);
	int (*start)(void *dev_priv, struct net_device *netdev, void *vsi_data);
	void (*stop)(void *dev_priv, void *vsi_data);
};

struct nbl_dev_vsi {
	struct nbl_dev_vsi_ops *ops;
	struct net_device *netdev;
	struct net_device *napi_netdev;
	struct nbl_register_net_result register_result;
	u16 vsi_id;
	u16 queue_offset;
	u16 queue_num;
	u16 queue_size;
	u16 in_kernel;
	u8 index;
	bool enable;
	bool use_independ_irq;
	bool static_queue;
};

struct nbl_dev_vsi_tbl {
	struct nbl_dev_vsi_ops vsi_ops;
	bool vf_support;
	bool only_nic_support;
	bool userdev_support;
	u16 in_kernel;
	bool use_independ_irq;
	bool static_queue;
};

#define NBL_DEV_BOARD_ID_MAX			NBL_DRIVER_DEV_MAX
struct nbl_dev_board_id_entry {
	u32 board_key; /* domain << 16 | bus_id */
	u8 refcount;
	bool valid;
};

struct nbl_dev_board_id_table {
	struct nbl_dev_board_id_entry entry[NBL_DEV_BOARD_ID_MAX];
};

struct nbl_dev_resume_fsm_info {
	enum nbl_resume_fsm success_next_fsm;
	int (*act_cb)(struct nbl_dev_mgt *dev_mgt);
};

int nbl_dev_setup_rdma_dev(struct nbl_adapter *adapter, struct nbl_init_param *param);
void nbl_dev_remove_rdma_dev(struct nbl_adapter *adapter);
int nbl_dev_setup_lag_dev(struct nbl_adapter *adapter, struct nbl_init_param *param);
void nbl_dev_remove_lag_dev(struct nbl_adapter *adapter);
int nbl_dev_start_rdma_dev(struct nbl_adapter *adapter);
void nbl_dev_stop_rdma_dev(struct nbl_adapter *adapter);
int nbl_dev_resume_rdma_dev(struct nbl_adapter *adapter);
int nbl_dev_suspend_rdma_dev(struct nbl_adapter *adapter);
void nbl_dev_rdma_process_abnormal_event(struct nbl_dev_rdma *rdma_dev);
void nbl_dev_rdma_process_flr_event(struct nbl_dev_rdma *rdma_dev, u16 vsi_id);
size_t nbl_dev_rdma_qos_cfg_store(struct nbl_dev_mgt *dev_mgt, int offset,
				  const char *buf, size_t count);
size_t nbl_dev_rdma_qos_cfg_show(struct nbl_dev_mgt *dev_mgt, int offset, char *buf);

int nbl_dev_init_emp_console(struct nbl_adapter *adapter);
void nbl_dev_destroy_emp_console(struct nbl_adapter *adapter);
int nbl_dev_setup_hwmon(struct nbl_adapter *adapter);
void nbl_dev_remove_hwmon(struct nbl_adapter *adapter);
struct nbl_dev_vsi *nbl_dev_vsi_select(struct nbl_dev_mgt *dev_mgt, u8 vsi_index);
int nbl_netdev_add_sysfs(struct nbl_dev_net *net_dev);
void nbl_netdev_remove_sysfs(struct nbl_dev_net *net_dev);
void nbl_net_init_netname_attr(struct nbl_netdev_name_attr *dev_name_attr, char *rep_name);
void nbl_ldev_add_netdev(struct nbl_dev_mgt *dev_mgt, struct net_device *netdev);
void nbl_ldev_remove_netdev(struct nbl_dev_mgt *dev_mgt, struct net_device *netdev);
int nbl_dev_create_rdma_aux_dev(struct nbl_dev_mgt *dev_mgt, u8 type);
void nbl_dev_destroy_rdma_aux_dev(struct nbl_dev_rdma *rdma_dev,
				  struct auxiliary_device **adev);
void nbl_dev_rdma_notify_bond_member(struct nbl_dev_mgt *dev_mgt);
#endif

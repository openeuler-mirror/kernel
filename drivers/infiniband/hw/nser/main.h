/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2015 - 2021 WangXun Corporation */
#ifndef NSER_MAIN_H
#define NSER_MAIN_H

#include <linux/if_vlan.h>
#include <net/netevent.h>
#ifndef CONFIG_64BIT
#include <linux/io-64-nonatomic-lo-hi.h>
#endif
#include <rdma/rdma_cm.h>
#include "osdep.h"
#include "defs.h"
#include "hmc.h"
#include "type.h"
#include "ws.h"
#include "protos.h"
#include "pble.h"
#include "iidc.h"
#include "nser_kcompat.h"
#include <rdma/nser-abi.h>
#include "verbs.h"
#include "user.h"

extern struct list_head nser_handlers;
extern spinlock_t nser_handler_lock;
extern bool nser_upload_context;
extern bool nser_hmc_on_chip;
extern bool nser_mirror_ena;

#define NSER_FW_VER_DEFAULT	2
#define NSER_HW_VER	        2

#define NSER_ARP_ADD		1
#define NSER_ARP_DELETE	2
#define NSER_ARP_RESOLVE	3

#define NSER_MACIP_ADD		1
#define NSER_MACIP_DELETE	2

#define IW_CCQ_SIZE	(NSER_CQP_SW_SQSIZE_2048 + 1)
#define IW_CEQ_SIZE	2048
#define IW_AEQ_SIZE	2048

#define RX_BUF_SIZE	(1536 + 8)
#define IW_REG0_SIZE	(4 * 1024)
#define IW_TX_TIMEOUT	(6 * HZ)
#define IW_FIRST_QPN	1

#define IW_SW_CONTEXT_ALIGN	1024

#define MAX_DPC_ITERATIONS	128

#define NSER_EVENT_TIMEOUT_MS		5000
#define NSER_VCHNL_EVENT_TIMEOUT_MS	10000
#define NSER_RST_TIMEOUT_HZ		4

#define	NSER_NO_QSET	0xffff

#define IW_CFG_FPM_QP_COUNT		32768
#define NSER_MAX_PAGES_PER_FMR		262144
#define NSER_MIN_PAGES_PER_FMR		1
#define NSER_CQP_COMPL_RQ_WQE_FLUSHED	2
#define NSER_CQP_COMPL_SQ_WQE_FLUSHED	3

#define NSER_Q_TYPE_PE_AEQ	0x80
#define NSER_Q_INVALID_IDX	0xffff
#define NSER_REM_ENDPOINT_TRK_QPID	3

#define NSER_DRV_OPT_ENA_MPA_VER_0		0x00000001
#define NSER_DRV_OPT_DISABLE_MPA_CRC		0x00000002
#define NSER_DRV_OPT_DISABLE_FIRST_WRITE	0x00000004
#define NSER_DRV_OPT_DISABLE_INTF		0x00000008
#define NSER_DRV_OPT_ENA_MSI			0x00000010
#define NSER_DRV_OPT_DUAL_LOGICAL_PORT		0x00000020
#define NSER_DRV_OPT_NO_INLINE_DATA		0x00000080
#define NSER_DRV_OPT_DISABLE_INT_MOD		0x00000100
#define NSER_DRV_OPT_DISABLE_VIRT_WQ		0x00000200
#define NSER_DRV_OPT_ENA_PAU			0x00000400
#define NSER_DRV_OPT_MCAST_LOGPORT_MAP		0x00000800

#define IW_HMC_OBJ_TYPE_NUM	ARRAY_SIZE(iw_hmc_obj_types)
#define NSER_ROCE_CWND_DEFAULT			0x400
#define NSER_ROCE_RTOMIN_DEFAULT		0x5
#define NSER_ROCE_ACKCREDS_DEFAULT		0x1E
#if IS_ENABLED(CONFIG_CONFIGFS_FS)
#define NSER_DEFAULT_UP_UP_MAP			0x0706050403020100l
#endif

#define NSER_FLUSH_SQ		BIT(0)
#define NSER_FLUSH_RQ		BIT(1)
#define NSER_REFLUSH		BIT(2)
#define NSER_FLUSH_WAIT	BIT(3)

#define NSER_IRQ_NAME_STR_LEN 64
#define NSER_MAX_QP_ID_GROUP 256
#define NSER_QP_ID_GROUP_SIZE 512U

enum init_completion_state {
	INVALID_STATE = 0,
	INITIAL_STATE,
	CQP_CREATED,
	HMC_OBJS_CREATED,
	HW_RSRC_INITIALIZED,
	CCQ_CREATED,
	CEQ0_CREATED, /* Last state of probe */
	ILQ_CREATED,
	IEQ_CREATED,
	REM_ENDPOINT_TRK_CREATED,
	CEQS_CREATED,
	PBLE_CHUNK_MEM,
	AEQ_CREATED,
	IP_ADDR_REGISTERED,  /* Last state of open */
};

struct nser_cqp_err_info {
	u16 maj;
	u16 min;
	const char *desc;
};

struct nser_cqp_compl_info {
	u32 op_ret_val;
	u16 maj_err_code;
	u16 min_err_code;
	bool error;
	u8 op_code;
};

struct nser_cqp_request {
	struct cqp_cmds_info info;
	wait_queue_head_t waitq;
	struct list_head list;
	refcount_t refcnt;
	void (*callback_fcn)(struct nser_cqp_request *cqp_request);
	void *param;
	struct nser_cqp_compl_info compl_info;
	bool waiting:1;
	bool request_done:1;
	bool dynamic:1;
};

struct nser_cqp {
	struct nser_sc_cqp sc_cqp;
	spinlock_t req_lock; /* protect CQP request list */
	spinlock_t compl_lock; /* protect CQP completion processing */
	wait_queue_head_t waitq;
	wait_queue_head_t remove_wq;
	struct nser_dma_mem sq;
	struct nser_dma_mem host_ctx;
	u64 *scratch_array;
	struct nser_cqp_request *cqp_requests;
	struct list_head cqp_avail_reqs;
	struct list_head cqp_pending_reqs;
};

struct nser_ccq {
	struct nser_sc_cq sc_cq;
	struct nser_dma_mem mem_cq;
	struct nser_dma_mem shadow_area;
};

struct nser_ceq {
	struct nser_sc_ceq sc_ceq;
	struct nser_dma_mem mem;
	u32 irq;
	u32 msix_idx;
	struct nser_pci_f *rf;
	struct tasklet_struct dpc_tasklet;
	spinlock_t ce_lock; /* sync cq destroy with cq completion event notification */
};

struct nser_aeq {
	struct nser_sc_aeq sc_aeq;
	struct nser_dma_mem mem;
	struct nser_pble_alloc palloc;
	bool virtual_map;
};

struct nser_arp_entry {
	u32 ip_addr[4];
	u8 mac_addr[ETH_ALEN];
};

struct nser_msix_vector {
	u32 idx;
	u32 irq;
	u32 cpu_affinity;
	u32 ceq_id;
	cpumask_t mask;
	char name[NSER_IRQ_NAME_STR_LEN];
};

struct nser_mc_table_info {
	u32 mgn;
	u32 dest_ip[4];
	bool lan_fwd:1;
	bool ipv4_valid:1;
};

struct mc_table_list {
	struct list_head list;
	struct nser_mc_table_info mc_info;
	struct nser_mcast_grp_info mc_grp_ctx;
};

struct nser_qv_info {
	u32 v_idx; /* msix_vector */
	u16 ceq_idx;
	u16 aeq_idx;
	u8 itr_idx;
};

struct nser_qvlist_info {
	u32 num_vectors;
	struct nser_qv_info qv_info[];
};

struct nser_gen_ops {
	void (*request_reset)(struct nser_pci_f *rf);
	int (*register_qset)(struct nser_sc_vsi *vsi,
			     struct nser_ws_node *tc_node);
	void (*unregister_qset)(struct nser_sc_vsi *vsi,
				struct nser_ws_node *tc_node);
};

struct nser_pci_f {
	bool reset:1;
	bool rsrc_created:1;
	bool msix_shared:1;
	bool ftype:1;
	u8 rsrc_profile;
	u8 max_rdma_vfs;
	u8 *hmc_info_mem;
	u8 *mem_rsrc;
	u8 rst_to;
	/* Not used in SRIOV VF mode */
	u8 pf_id;
	u8 fragcnt_limit;
	bool dcqcn_ena:1;
	bool timely_ena:1;
	u32 sd_type;
	u32 msix_count;
	u32 max_mr;
	u32 max_qp;
	u32 max_cq;
	u32 max_ah;
	u32 next_ah;
	u32 max_mcg;
	u32 next_mcg;
	u32 max_pd;
	u32 next_qp;
	u32 next_cq;
	u32 next_pd;
	u32 max_mr_size;
	u32 max_cqe;
	u32 mr_stagmask;
	u32 used_pds;
	u32 used_cqs;
	u32 used_mrs;
	u32 used_qps;
	u32 arp_table_size;
	u32 next_arp_index;
	u32 ceqs_count;
	u32 next_ws_node_id;
	u32 max_ws_node_id;
	unsigned long *allocated_ws_nodes;
	unsigned long *allocated_qps;
	unsigned long *allocated_cqs;
	unsigned long *allocated_mrs;
	unsigned long *allocated_pds;
	unsigned long *allocated_mcgs;
	unsigned long *allocated_ahs;
	unsigned long *allocated_arps;
	enum init_completion_state init_state;
	struct nser_sc_dev sc_dev;
	struct nser_handler *hdl;
	struct pci_dev *pcidev;
	void *cdev;
	struct nser_hw hw;
	struct nser_cqp cqp;
	struct nser_ccq ccq;
	struct nser_aeq aeq;
	struct nser_ceq *ceqlist;
	struct nser_hmc_pble_rsrc *pble_rsrc;
	struct nser_arp_entry *arp_table;
	spinlock_t arp_lock; /*protect ARP table access*/
	spinlock_t rsrc_lock; /* protect HW resource array access */
	spinlock_t qptable_lock; /*protect QP table access*/
	spinlock_t cqtable_lock; /*protect CQ table access*/
	struct nser_qp **qp_table;
	struct nser_cq **cq_table;
	spinlock_t qh_list_lock; /* protect mc_qht_list */
	struct mc_table_list mc_qht_list;
	struct nser_msix_vector *iw_msixtbl;
	struct nser_qvlist_info *iw_qvlist;
	struct tasklet_struct dpc_tasklet;
	struct msix_entry *msix_entries;
	struct nser_dma_mem obj_mem;
	struct nser_dma_mem obj_next;
	atomic_t vchnl_msgs;
	wait_queue_head_t vchnl_waitq;
	struct workqueue_struct *cqp_cmpl_wq;
	struct work_struct cqp_cmpl_work;
	struct workqueue_struct *vchnl_wq;
	struct nser_sc_vsi default_vsi;
	void *back_fcn;
	struct nser_gen_ops gen_ops;
	void (*check_fc)(struct nser_sc_vsi *vsi, struct nser_sc_qp *sc_qp);
	struct nser_cc_params cc_params;
	struct nser_device *iwdev;
	u8 vlan_parse_en;
	u32 used_qp_id_num[NSER_MAX_QP_ID_GROUP];
	u32 qp_id_group_num;
	u8 __iomem *hmc_va;
	u8 port_num;
	u64 *allocated_qps_ts;
	u64 *allocated_cqs_ts;
	u64 *allocated_mrs_ts;
};

struct nser_device {
	struct ib_device ibdev;
	struct nser_pci_f *rf;
	struct net_device *netdev;
	struct notifier_block nb_netdevice_event;
	struct notifier_block nb_net_event;
	struct notifier_block nb_inet6addr_event;
	struct notifier_block nb_inetaddr_event;
	struct nser_handler *hdl;
	struct workqueue_struct *cleanup_wq;
	struct nser_sc_vsi vsi;
	DECLARE_HASHTABLE(ah_hash_tbl, 8);
	struct mutex ah_list_lock;
#ifdef CONFIG_DEBUG_FS
	u64 ah_reused;
#endif
	u32 ah_list_cnt;
	u32 ah_list_hwm;
	u32 roce_cwnd;
	u32 roce_ackcreds;
	u32 vendor_id;
	u32 vendor_part_id;
	u32 device_cap_flags;
	u32 rcv_wnd;
	u16 mac_ip_table_idx;
	u16 vsi_num;
	u8 rcv_wscale;
	u8 iw_status;
	u8 rd_fence_rate;
#if IS_ENABLED(CONFIG_CONFIGFS_FS)
	u64 up_up_map;
	u8 cnp_up_override;
	u32 ceq_intrl; /* Interrupt rate limit per second: 0-disabled, 4237 - 250,000 */
	bool up_map_en:1;
	bool override_rcv_wnd:1;
	bool override_cwnd:1;
	bool override_ackcreds:1;
	bool override_ooo:1;
	bool override_rtomin:1;
	bool override_rd_fence_rate:1;
	bool roce_ecn_en:1;
	bool roce_no_icrc_en:1;
	u8 cnp_dscp;
	u8 cnp_802p_prio;
	bool cnp_en:1;
#endif /* CONFIG_CONFIGFS_FS */
	bool roce_timely_en:1;
	bool roce_dcqcn_en:1;
	bool dcb_vlan_mode:1;
	bool is_lag:1;
	enum init_completion_state init_state;
	wait_queue_head_t suspend_wq;
	char ib_devname[IB_DEVICE_NAME_MAX];
};

struct nser_handler {
	struct list_head list;
	struct nser_device *iwdev;
#ifdef CONFIG_DEBUG_FS
	struct dentry *nser_dbg_dentry;
	struct list_head ucontext_list;
	spinlock_t uctx_list_lock; /*sync access to ucontext list*/
#endif /* DEBUG_SUPPORT */
	bool shared_res_created;
};

static inline struct nser_device *to_iwdev(struct ib_device *ibdev)
{
	return container_of(ibdev, struct nser_device, ibdev);
}

static inline struct nser_ucontext *to_ucontext(struct ib_ucontext *ibucontext)
{
	return container_of(ibucontext, struct nser_ucontext, ibucontext);
}

static inline struct nser_user_mmap_entry *
to_nser_mmap_entry(struct rdma_user_mmap_entry *rdma_entry)
{
	return container_of(rdma_entry, struct nser_user_mmap_entry,
			    rdma_entry);
}

static inline struct nser_pd *to_iwpd(struct ib_pd *ibpd)
{
	return container_of(ibpd, struct nser_pd, ibpd);
}

static inline struct nser_ah *to_iwah(struct ib_ah *ibah)
{
	return container_of(ibah, struct nser_ah, ibah);
}

static inline struct nser_mr *to_iwmr(struct ib_mr *ibmr)
{
	return container_of(ibmr, struct nser_mr, ibmr);
}

static inline struct nser_mr *to_iwmw(struct ib_mw *ibmw)
{
	return container_of(ibmw, struct nser_mr, ibmw);
}

static inline struct nser_cq *to_iwcq(struct ib_cq *ibcq)
{
	return container_of(ibcq, struct nser_cq, ibcq);
}

static inline struct nser_qp *to_iwqp(struct ib_qp *ibqp)
{
	return container_of(ibqp, struct nser_qp, ibqp);
}

static inline struct nser_pci_f *dev_to_rf(struct nser_sc_dev *dev)
{
	return container_of(dev, struct nser_pci_f, sc_dev);
}

/**
 * nser_alloc_resource - allocate a resource
 * @iwdev: device pointer
 * @resource_array: resource bit array:
 * @max_resources: maximum resource number
 * @req_resources_num: Allocated resource number
 * @next: next free id
 **/
static inline int nser_alloc_rsrc(struct nser_pci_f *rf,
				   unsigned long *rsrc_array, u32 max_rsrc,
				   u32 *req_rsrc_num, u32 *next)
{
	u32 rsrc_num;
	unsigned long flags;

	spin_lock_irqsave(&rf->rsrc_lock, flags);
	rsrc_num = find_next_zero_bit(rsrc_array, max_rsrc, *next);
	if (rsrc_num >= max_rsrc) {
		rsrc_num = find_first_zero_bit(rsrc_array, max_rsrc);
		if (rsrc_num >= max_rsrc) {
			spin_unlock_irqrestore(&rf->rsrc_lock, flags);
			nser_dbg(&rf->sc_dev,
				  "ERR: resource [%d] allocation failed\n",
				  rsrc_num);
			return -EOVERFLOW;
		}
	}
	__set_bit(rsrc_num, rsrc_array);
	*next = rsrc_num + 1;
	if (*next == max_rsrc)
		*next = 0;
	*req_rsrc_num = rsrc_num;
	spin_unlock_irqrestore(&rf->rsrc_lock, flags);

	return 0;
}

/**
 * nser_free_resource - free a resource
 * @iwdev: device pointer
 * @resource_array: resource array for the resource_num
 * @resource_num: resource number to free
 **/
static inline void nser_free_rsrc(struct nser_pci_f *rf,
				   unsigned long *rsrc_array, u32 rsrc_num)
{
	unsigned long flags;

	spin_lock_irqsave(&rf->rsrc_lock, flags);
	__clear_bit(rsrc_num, rsrc_array);
	spin_unlock_irqrestore(&rf->rsrc_lock, flags);
}

#define MAX_RSRC_DESTROY_TIME (4*HZ)

/**
 * get_qp_id_group - find the optimal qp_id group with the fewest assigned qp_ids
 * @iwdev: device pointer
 * @qp_id: start qp_id of the optimal group
 * @qp_id_cnt: count of qp_id til the optimal group
 **/
static inline int get_qp_id_group(struct nser_pci_f *rf, u32 *qp_id, u32 *qp_id_cnt)
{
	u32 index;
	u32 optimal_index = 0;
	unsigned long flags;

	spin_lock_irqsave(&rf->rsrc_lock, flags);
	for (index = 0; index < rf->qp_id_group_num; ++index) {
		if (rf->used_qp_id_num[index] < rf->used_qp_id_num[optimal_index])
			optimal_index = index;
	}
	*qp_id_cnt = min(NSER_QP_ID_GROUP_SIZE, rf->max_qp - optimal_index * NSER_QP_ID_GROUP_SIZE);
	*qp_id = optimal_index * NSER_QP_ID_GROUP_SIZE;
	if (rf->used_qp_id_num[optimal_index] < *qp_id_cnt) {
		*qp_id_cnt += *qp_id;
		rf->used_qp_id_num[optimal_index] += 1;
		spin_unlock_irqrestore(&rf->rsrc_lock, flags);
		return 0;
	}
	spin_unlock_irqrestore(&rf->rsrc_lock, flags);

	return -EOVERFLOW;
}

/**
 * put_qp_id_group - decrement the count in the qp_id group
 * @iwdev: device pointer
 * @qp_id: the free qp_id
 **/
static inline void put_qp_id_group(struct nser_pci_f *rf, u32 qp_id)
{
	u32 group_index;
	unsigned long flags;

	spin_lock_irqsave(&rf->rsrc_lock, flags);
	group_index = qp_id / NSER_QP_ID_GROUP_SIZE;
	rf->used_qp_id_num[group_index] -= 1;
	spin_unlock_irqrestore(&rf->rsrc_lock, flags);
}

/**
 * nser_alloc_resource_with_ts - allocate a resource
 * @iwdev: device pointer
 * @resource_array: resource bit array:
 * @max_resources: maximum resource number
 * @req_resources_num: Allocated resource number
 * @next: next free id
 * @rsrc_array_ts: rsrc_array with rsrc deletion timestamp
 **/
static inline int nser_alloc_rsrc_with_ts(struct nser_pci_f *rf,
				   unsigned long *rsrc_array, u32 max_rsrc,
				   u32 *req_rsrc_num, u32 *next, u64 *rsrc_array_ts)
{
	u32 rsrc_num;
	u32 search_len;
	unsigned long flags;

	spin_lock_irqsave(&rf->rsrc_lock, flags);
	rsrc_num = find_next_zero_bit(rsrc_array, max_rsrc, *next);
	if (rsrc_num >= max_rsrc) {
		spin_unlock_irqrestore(&rf->rsrc_lock, flags);
		nser_dbg(&rf->sc_dev,
				"ERR: resource [%d] allocation failed\n",
				rsrc_num);
		return -EOVERFLOW;
	}

	while (!time_after64(get_jiffies_64(), rsrc_array_ts[rsrc_num] + MAX_RSRC_DESTROY_TIME)) {
		search_len = max_rsrc - (rsrc_num - *next + 1);
		rsrc_num = find_next_zero_bit(rsrc_array, search_len, rsrc_num + 1);
		if (rsrc_num >= search_len) {
			spin_unlock_irqrestore(&rf->rsrc_lock, flags);
			nser_dbg(&rf->sc_dev,
				"ERR: resource [%d] allocation failed, sleep 1s for next allocation\n",
				rsrc_num);
			schedule_timeout(HZ);
			spin_lock_irqsave(&rf->rsrc_lock, flags);
			rsrc_num = find_next_zero_bit(rsrc_array, max_rsrc, *next);
			if (rsrc_num >= max_rsrc) {
				spin_unlock_irqrestore(&rf->rsrc_lock, flags);
				nser_dbg(&rf->sc_dev,
					"ERR: resource [%d] allocation failed\n",
					rsrc_num);
				return -EOVERFLOW;
			}
		}
	}
	__set_bit(rsrc_num, rsrc_array);

	*req_rsrc_num = rsrc_num;
	spin_unlock_irqrestore(&rf->rsrc_lock, flags);

	return 0;
}

/**
 * nser_free_resource_with_ts - free a resource
 * @iwdev: device pointer
 * @resource_array: resource array for the resource_num
 * @resource_num: resource number to free
 * @rsrc_array_ts: rsrc_array with rsrc deletion timestamp
 **/
static inline void nser_free_rsrc_with_ts(struct nser_pci_f *rf,
				   unsigned long *rsrc_array, u32 rsrc_num, u64 *rsrc_array_ts)
{
	unsigned long flags;

	spin_lock_irqsave(&rf->rsrc_lock, flags);
	__clear_bit(rsrc_num, rsrc_array);
	rsrc_array_ts[rsrc_num] = get_jiffies_64();
	spin_unlock_irqrestore(&rf->rsrc_lock, flags);
}

int nser_ctrl_init_hw(struct nser_pci_f *rf);
void nser_ctrl_deinit_hw(struct nser_pci_f *rf);
int nser_rt_init_hw(struct nser_device *iwdev,
		     struct nser_l2params *l2params);
void nser_rt_deinit_hw(struct nser_device *iwdev);
void nser_qp_add_ref(struct ib_qp *ibqp);
void nser_qp_rem_ref(struct ib_qp *ibqp);

struct ib_qp *nser_get_qp(struct ib_device *ibdev, int qpn);
void nser_flush_wqes(struct nser_qp *iwqp, u32 flush_mask);

void nser_manage_arp_cache(struct nser_pci_f *rf, const unsigned char *mac_addr,
			    u32 *ip_addr, u32 action);
struct nser_cqp_request *nser_alloc_and_get_cqp_request(struct nser_cqp *cqp,
							  bool wait);
void nser_free_cqp_request(struct nser_cqp *cqp,
			    struct nser_cqp_request *cqp_request);
void nser_put_cqp_request(struct nser_cqp *cqp,
			   struct nser_cqp_request *cqp_request);

u32 nser_initialize_hw_rsrc(struct nser_pci_f *rf);
bool nser_cqp_crit_err(struct nser_sc_dev *dev, u8 cqp_cmd,
			u16 maj_err_code, u16 min_err_code);
int nser_handle_cqp_op(struct nser_pci_f *rf,
			struct nser_cqp_request *cqp_request);

int nser_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr, int attr_mask,
		    struct ib_udata *udata);
int nser_modify_qp_roce(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			 int attr_mask, struct ib_udata *udata);
void nser_cq_add_ref(struct ib_cq *ibcq);
void nser_cq_rem_ref(struct ib_cq *ibcq);
void nser_cq_wq_destroy(struct nser_pci_f *rf, struct nser_sc_cq *cq);

void nser_cleanup_pending_cqp_op(struct nser_pci_f *rf);
int nser_hw_modify_qp(struct nser_device *iwdev, struct nser_qp *iwqp,
		       struct nser_modify_qp_info *info, bool wait);
int nser_qp_suspend_resume(struct nser_sc_qp *qp, bool suspend);

void nser_free_sqbuf(struct nser_sc_vsi *vsi, void *bufp);
//void nser_free_qp_rsrc(struct nser_qp *iwqp);
int nser_hw_flush_wqes(struct nser_pci_f *rf, struct nser_sc_qp *qp,
			struct nser_qp_flush_info *info, bool wait);

void nser_copy_ip_ntohl(u32 *dst, __be32 *src);
void nser_copy_ip_htonl(__be32 *dst, u32 *src);
u16 nser_get_vlan_ipv4(u32 *addr);
struct net_device *nser_netdev_vlan_ipv6(u32 *addr, u16 *vlan_id, u8 *mac);
struct ib_mr *nser_reg_phys_mr(struct ib_pd *ib_pd, u64 addr, u64 size,
				int acc, u64 *iova_start);
int nser_upload_qp_context(struct nser_qp *iwqp, bool freeze, bool raw);
void nser_del_hmc_objects(struct nser_sc_dev *dev,
			   struct nser_hmc_info *hmc_info, bool privileged,
			   bool reset);
int nser_obj_aligned_mem(struct nser_pci_f *rf, struct nser_dma_mem *memptr,
			  u32 size, u32 mask);
void nser_cqp_ce_handler(struct nser_pci_f *rf, struct nser_sc_cq *cq);
int nser_ah_cqp_op(struct nser_pci_f *rf, struct nser_sc_ah *sc_ah, u8 cmd,
		    bool wait,
		    void (*callback_fcn)(struct nser_cqp_request *cqp_request),
		    void *cb_param);
void nser_gsi_ud_qp_ah_cb(struct nser_cqp_request *cqp_request);
bool nser_cq_empty(struct nser_cq *iwcq);
#if IS_ENABLED(CONFIG_CONFIGFS_FS)
struct nser_device *nser_get_device_by_name(const char *name);
#endif
#ifdef CONFIG_DEBUG_FS
struct nser_handler;
void nser_dbg_pf_init(struct nser_handler *hdl);
void nser_dbg_pf_exit(struct nser_handler *hdl);
void nser_dbg_init(void);
void nser_dbg_exit(void);
void nser_dbg_save_ucontext(struct nser_device *iwdev,
			     struct nser_ucontext *ucontext);
void nser_dbg_free_ucontext(struct nser_ucontext *ucontext);
#endif /* DEBUG_SUPPORT */
struct nser_handler *nser_find_handler(struct pci_dev *pcidev);
int nser_inetaddr_event(struct notifier_block *notifier, unsigned long event,
			 void *ptr);
int nser_inet6addr_event(struct notifier_block *notifier, unsigned long event,
			  void *ptr);
int nser_net_event(struct notifier_block *notifier, unsigned long event,
		    void *ptr);
int nser_netdevice_event(struct notifier_block *notifier, unsigned long event,
			  void *ptr);
void nser_port_ibevent(struct nser_device *iwdev);
#if IS_ENABLED(CONFIG_CONFIGFS_FS)
int nser_configfs_init(void);
void nser_configfs_exit(void);
#endif
void nser_set_rf_user_cfg_params(struct nser_pci_f *rf);
void nser_add_ip(struct nser_device *iwdev);
void nser_add_handler(struct nser_handler *hdl);
void nser_del_handler(struct nser_handler *hdl);
void cqp_compl_worker(struct work_struct *work);
void nser_cleanup_dead_qps(struct nser_sc_vsi *vsi);

bool nser_ipv4_is_lpb(u32 loc_addr, u32 rem_addr);
bool nser_ipv6_is_lpb(u32 *loc_addr, u32 *rem_addr);

int nser_add_arp(struct nser_pci_f *rf, u32 *ip, const u8 *mac);
int nser_arp_table(struct nser_pci_f *rf, u32 *ip_addr,
		    const u8 *mac_addr, u32 action);

int nser_cqp_qp_create_cmd(struct nser_sc_dev *dev, struct nser_sc_qp *qp);
int nser_cqp_cq_create_cmd(struct nser_sc_dev *dev, struct nser_sc_cq *cq);
int nser_cqp_qp_destroy_cmd(struct nser_sc_dev *dev, struct nser_sc_qp *qp);
void nser_cqp_cq_destroy_cmd(struct nser_sc_dev *dev, struct nser_sc_cq *cq);
void nser_disconn(struct nser_qp *iwqp);

static inline u8 nser_tos2dscp(u8 tos)
{
#define NSER_DSCP_S 2
#define NSER_DSCP GENMASK(7, 2)
	return FIELD_GET(NSER_DSCP, tos);
}







#endif /* NSER_MAIN_H */

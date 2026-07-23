/* SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB) */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef ZXDH_MAIN_H
#define ZXDH_MAIN_H
#define Z_DH_DEBUG
#define MSIX_SUPPORT

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_vlan.h>
#include <net/addrconf.h>
#include <net/netevent.h>
#include <net/tcp.h>
#include <net/ip6_route.h>
#include <net/flow.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/spinlock.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/crc32c.h>
#include <linux/kthread.h>
#include "dpp_tbl_api.h"
#ifndef CONFIG_64BIT
#include <linux/io-64-nonatomic-lo-hi.h>
#endif
#include "zxdh_auxiliary_bus.h"
#include <linux/configfs.h>
#include <crypto/hash.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_pack.h>
#include <rdma/rdma_cm.h>
#include <rdma/iw_cm.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_cache.h>
#include "status.h"
#include "osdep.h"
#include "defs.h"
#include "hmc.h"
#include "type.h"
#include "ws.h"
#include "protos.h"
#include "pble.h"
#include "cm.h"
#include "iidc.h"
#include "zrdma_kcompat.h"
#include "zrdma-abi.h"
#include "verbs.h"
#include "user.h"
#include "puda.h"
#include "srq.h"
#include "manager.h"
#include "dbgfs.h"
#include <linux/inet.h>

extern struct list_head zxdh_handlers;
extern spinlock_t zxdh_handler_lock;

struct zxdh_fw_compat {
	u8 module_id;
	u8 major;
	u8 fw_minor;
	u8 drv_minor;
	u16 patch;
	u16 rsv;
} __packed;

struct zxdh_vport_t {
	u32 tpid /* : 16; */;
	u32 vhca /* : 10; */;
	u32 uplink_port /* : 6; */;

	u32 rss_hash_factor /* : 8; */;
	u32 hash_alg /* : 4; */;
	u32 panel_id /* : 4; */;

	u32 lag_id /* : 3; */;
	u32 pf_vqm_vfid /* : 11; */;
	u32 ingress_tm_enable /* : 2; */;
	u32 egress_tm_enable /* : 1; */;

	u32 mtu /* : 16; */;

	u32 port_base_qid /* : 12; */;
	u32 hash_search_index /* : 3; */;
	u32 rsv1 /* : 1; */;

	u32 tm_enable /* : 1; */;
	u32 ingress_meter_enable /* : 1; */;
	u32 egress_meter_enable /* : 1; */;
	u32 ingress_meter_mode /* : 1; */;
	u32 egress_meter_mode /* : 1; */;
	u32 fd_enable /* : 1; */;
	u32 vepa_enable /* : 1; */;
	u32 spoof_check_enable /* : 1; */;

	u32 inline_sec_offload /* : 1; */;
	u32 ovs_enable /* : 1; */;
	u32 lag_enable /* : 1; */;
	u32 is_passthrough /* : 1; */;
	u32 is_vf /* : 1; */;
	u32 virtion_version /* : 2; */;
	u32 virtio_enable /* : 1; */;

	u32 accelerator_offload_flag /* : 1; */;
	u32 lro_offload /* : 1; */;
	u32 ip_fragment_offload /* : 1; */;
	u32 tcp_udp_checksum_offload /* : 1; */;
	u32 ip_checksum_offload /* : 1; */;
	u32 outer_ip_checksum_offload /* : 1; */;
	u32 is_up /* : 1; */;
	u32 allmulticast_enable /* : 1; */;

	u32 hw_bond_enable /* : 1; */;
	u32 rdma_offload_enable /* : 1; */;
	u32 vlan_filter_enable /* : 1; */;
	u32 vlan_strip_offload /* : 1; */;
	u32 qinq_vlan_strip_offload /* : 1; */;
	u32 rss_enable /* : 1; */;
	u32 mtu_offload_enable /* : 1; */;
	u32 hit_flag /*: 1; */;
};

#define ZXDH_PF_NAME "dinghai10e"
#define ZXDH_RDMA_DEV_NAME "rdma_aux"

#define EGR_FLAG_VHCA ((u32)(offsetof(struct zxdh_vport_t, vhca) / sizeof(u32)))
#define EGR_FLAG_RDMA_OFFLOAD_EN_OFF \
	((u32)(offsetof(struct zxdh_vport_t, rdma_offload_enable) / sizeof(u32)))

#define EGR_RDMA_OFFLOAD_EN 0x1
u32 dpp_vport_vhca_id_add(struct dpp_pf_info_t *pf_info, u32 vhca_id);
u32 dpp_vport_attr_set(struct dpp_pf_info_t *pf_info, u32 mode, u32 value);
u32 dpp_add_rdma_trans_item(struct dpp_pf_info_t *pf_info, const void *mac, u16 vhca_id);
u32 dpp_del_rdma_trans_item(struct dpp_pf_info_t *pf_info, const void *mac);
u32 dpp_glb_cfg_get_1(struct dpp_pf_info_t *pf_info, u32 *glb_cfg_data_1);
u32 dpp_pktrx_mcode_glb_cfg_write(struct dpp_pf_info_t *pf_info, u32 start_bit_no, u32 end_bit_no,
				  u32 glb_cfg_data_1);
void zxdh_rdma_events_unregister(void);
typedef int32_t (*zxdh_rdma_event_func)(struct net_device *netdev, u8 event_type, void *data);
void zxdh_rdma_events_register(zxdh_rdma_event_func callback);

enum {
	ZXDH_RDMA_HEALTH_EVENT = 1,
	ZXDH_RDMA_SRIOV_EVENT = 2,
};

#define ZXDH_RDMA_VER_LEN 60
#define ZXDH_RDMA_QP_BUF_LEN 100
#define ZXDH_RDMA_QP_NOT_EXIST 0
#define ZXDH_RDMA_QP_EXIST 1

#define ZXDH_MAX_IRQ_COUNT 4
#define ZXDH_CEQ_IRQ_COUNT 3

#define ZXDH_FW_VER_DEFAULT 2
#define ZXDH_HW_VER 2

#define ZXDH_ARP_ADD 1
#define ZXDH_ARP_DELETE 2
#define ZXDH_ARP_RESOLVE 3

#define ZXDH_MACIP_ADD 1
#define ZXDH_MACIP_DELETE 2

#define IW_CCQ_SIZE ZXDH_CQP_SW_SQSIZE_2048
#define IW_CEQ_SIZE 2048
#define IW_AEQ_SIZE 2048

#define RX_BUF_SIZE (1536 + 8)
#define IW_REG0_SIZE (4 * 1024)
#define IW_TX_TIMEOUT (6 * HZ)
#define IW_FIRST_QPN 1

#define IW_SW_CONTEXT_ALIGN 1024

#define MAX_DPC_ITERATIONS 128

#define ZXDH_EVENT_TIMEOUT_MS 5000
#define ZXDH_VCHNL_EVENT_TIMEOUT_MS 10000
#define ZXDH_RST_TIMEOUT_HZ 4

#define ZXDH_NO_QSET 0xffff

#define IW_CFG_FPM_QP_COUNT 32768
#define ZXDH_MAX_PAGES_PER_FMR 512
#define ZXDH_MIN_PAGES_PER_FMR 1
#define ZXDH_CQP_COMPL_RQ_WQE_FLUSHED 2
#define ZXDH_CQP_COMPL_SQ_WQE_FLUSHED 3

#define ZXDH_Q_TYPE_PE_AEQ 0x80
#define ZXDH_Q_INVALID_IDX 0xffff
#define ZXDH_REM_ENDPOINT_TRK_QPID 3

#define ZXDH_DRV_OPT_ENA_MPA_VER_0 0x00000001
#define ZXDH_DRV_OPT_DISABLE_MPA_CRC 0x00000002
#define ZXDH_DRV_OPT_DISABLE_FIRST_WRITE 0x00000004
#define ZXDH_DRV_OPT_DISABLE_INTF 0x00000008
#define ZXDH_DRV_OPT_ENA_MSI 0x00000010
#define ZXDH_DRV_OPT_DUAL_LOGICAL_PORT 0x00000020
#define ZXDH_DRV_OPT_NO_INLINE_DATA 0x00000080
#define ZXDH_DRV_OPT_DISABLE_INT_MOD 0x00000100
#define ZXDH_DRV_OPT_DISABLE_VIRT_WQ 0x00000200
#define ZXDH_DRV_OPT_ENA_PAU 0x00000400
#define ZXDH_DRV_OPT_MCAST_LOGPORT_MAP 0x00000800

#define IW_HMC_OBJ_TYPE_NUM ARRAY_SIZE(iw_hmc_obj_types)
#define ZXDH_ROCE_CWND_DEFAULT 0x400
#define ZXDH_ROCE_RTOMIN_DEFAULT 0x5
#define ZXDH_ROCE_ACKCREDS_DEFAULT 0x1E
#if IS_ENABLED(CONFIG_CONFIGFS_FS)
#define ZXDH_DEFAULT_UP_UP_MAP 0x0706050403020100l
#endif

#define ZXDH_FLUSH_SQ BIT(0)
#define ZXDH_FLUSH_RQ BIT(1)
#define ZXDH_REFLUSH BIT(2)
#define ZXDH_FLUSH_WAIT BIT(3)

#define SINGLE_EP0 1
#define MULTI_EP_NO_ZF 0
#define MULTI_EP_WITH_ZF 0

#define ETH_INFO_HASH_COUNT 256

#define ZXDH_DUAL_TOR_SWITCH_OFFSET 0x5780
#define ZXDH_DUAL_TOR_SWITCH_OPEN 0xaaaaaaaa

#define ZXDH_HW_SCHEDULE_OFF 0
#define ZXDH_HW_SCHEDULE_ON 1

#define FW_TIME_WAIT_1S 1000
#define FW_TIME_WAIT_CNT 20

#define HOST_RDMA_MAX_PF 256

struct dev_log_trace {
	refcount_t t_switch;
};

enum init_completion_state {
	INVALID_STATE = 0,
	INITIAL_STATE,
	CQP_CREATED,
	SMMU_PAGETABLE_INITIALIZED,
	DATA_CAP_CREATED,
	HMC_OBJS_CREATED,
	HW_RSRC_INITIALIZED,
	CQP_QP_CREATED,
	AEQ_CREATED,
	CCQ_CREATED,
	CEQ0_CREATED, /* Last state of probe */
	ILQ_CREATED,
	IEQ_CREATED,
	REM_ENDPOINT_TRK_CREATED,
	CEQS_CREATED,
	PBLE_CHUNK_MEM,
	IP_ADDR_REGISTERED, /* Last state of open */
};

enum {
	MCODE_TYPE_DCQCN = 1,
	MCODE_TYPE_RTT = 2,
	MCODE_TYPE_WUMENG = 6,
};

struct zxdh_cqp_err_info {
	u16 maj;
	u16 min;
	const char *desc;
};

struct zxdh_cqp_compl_info {
	u64 op_ret_val;
	u16 maj_err_code;
	u16 min_err_code;
	bool error;
	u8 op_code;
	__le64 addrbuf[5];
};

struct zxdh_cqp_request {
	struct cqp_cmds_info info;
	wait_queue_head_t waitq;
	struct list_head list;
	refcount_t refcnt;
	void (*callback_fcn)(struct zxdh_cqp_request *cqp_request);
	void *param;
	struct zxdh_cqp_compl_info compl_info;
	u8 waiting : 1;
	u8 request_done : 1;
	u8 dynamic : 1;
};

struct zxdh_cqp {
	struct zxdh_sc_cqp sc_cqp;
	spinlock_t req_lock; /* protect CQP request list */
	spinlock_t compl_lock; /* protect CQP completion processing */
	wait_queue_head_t waitq;
	wait_queue_head_t remove_wq;
	struct zxdh_dma_mem sq;
	struct zxdh_dma_mem host_ctx;
	u64 *scratch_array;
	struct zxdh_cqp_request *cqp_requests;
	struct list_head cqp_avail_reqs;
	struct list_head cqp_pending_reqs;
};

struct zxdh_ccq {
	struct zxdh_sc_cq sc_cq;
	struct zxdh_dma_mem mem_cq;
	struct zxdh_dma_mem shadow_area;
};

struct zxdh_ceq {
	struct zxdh_sc_ceq sc_ceq;
	struct zxdh_dma_mem mem;
	u32 irq;
	u32 msix_idx;
	bool irq_sta;
	struct zxdh_pci_f *rf;
	struct tasklet_struct dpc_tasklet;

	spinlock_t ce_lock; /* sync cq destroy with cq completion event notification */
};

struct zxdh_aeq {
	struct zxdh_sc_aeq sc_aeq;
	struct zxdh_dma_mem mem;
	struct zxdh_pble_alloc palloc;
	bool virtual_map;
	u32 irq;
	u32 msix_idx;
	bool irq_sta;
};

struct zxdh_arp_entry {
	u32 ip_addr[4];
	u8 mac_addr[ETH_ALEN];
};

struct zxdh_msix_vector {
	u32 idx;
	u32 irq;
	u32 cpu_affinity;
	u32 ceq_id;
	cpumask_t mask;
};

struct zxdh_mc_table_info {
	u32 mgn;
	u32 dest_ip[4];
	u8 lan_fwd : 1;
	u8 ipv4_valid : 1;
};

struct mc_table_list {
	struct list_head list;
	struct zxdh_mc_table_info mc_info;
	struct zxdh_mcast_grp_info mc_grp_ctx;
};

struct zxdh_qv_info {
	u32 v_idx; /* msix_vector */
	u16 ceq_idx;
	u16 aeq_idx;
	u8 itr_idx;
};

struct zxdh_qvlist_info {
	u32 num_vectors;
	struct zxdh_qv_info qv_info[];
};

struct zxdh_gen_ops {
	void (*request_reset)(struct zxdh_pci_f *rf);
	int (*register_qset)(struct zxdh_sc_vsi *vsi, struct zxdh_ws_node *tc_node);
	void (*unregister_qset)(struct zxdh_sc_vsi *vsi, struct zxdh_ws_node *tc_node);
};

struct zxdh_pci_f {
	u8 reset : 1;
	u8 rsrc_created : 1;
	u8 ftype : 1;
	u8 rsrc_profile;
	u8 max_rdma_vfs;
	u8 *hmc_info_mem;
	u8 *mem_rsrc;
	u8 rdma_ver;
	u8 rst_to;
	/* Not used in SRIOV VF mode */
	u8 pf_id;
	u8 vf_id;
	u8 ep_id;
	u8 fragcnt_limit;
	enum zxdh_protocol_used protocol_used;
	u8 en_rem_endpoint_trk : 1;
	u8 dcqcn_ena : 1;
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
	u32 next_mr;
	u32 max_mr_size;
	u32 max_cqe;
	u32 mr_stagmask;
	u32 used_pds;
	u32 used_cqs;
	u32 used_mrs;
	u32 used_qps;
	u32 max_srq;
	u32 next_srq;
	u32 used_srqs;
#ifdef Z_CONFIG_RDMA_ARP
	u32 arp_table_size;
	u32 next_arp_index;
	unsigned long *allocated_arps;
	struct zxdh_arp_entry *arp_table;
	spinlock_t arp_lock; /*protect ARP table access*/
#endif
	u32 ceqs_count;
	u32 limits_sel;
	u64 base_bar_offset;

	unsigned long *allocated_qps;
	unsigned long *allocated_cqs;
	unsigned long *allocated_mrs;
	unsigned long *allocated_pds;
	unsigned long *allocated_mcgs;
	unsigned long *allocated_ahs;
	unsigned long *allocated_srqs;

	enum init_completion_state init_state;
	struct zxdh_sc_dev sc_dev;
	struct zxdh_handler *hdl;
	struct pci_dev *pcidev;
	void *cdev;
	struct zxdh_hw hw;
	struct zxdh_cqp cqp;
	struct zxdh_ccq ccq;
	struct zxdh_aeq aeq;
	struct zxdh_ceq *ceqlist;
	struct zxdh_hmc_pble_rsrc *pble_rsrc;
	struct zxdh_hmc_pble_rsrc *pble_mr_rsrc;
	struct zxdh_dma_mem cqp_host_ctx;

	spinlock_t rsrc_lock; /* protect HW resource array access */
	spinlock_t qptable_lock; /*protect QP table access*/
	spinlock_t cqtable_lock; /*protect CQ table access*/
	struct zxdh_qp **qp_table;
	struct zxdh_cq **cq_table;
	struct zxdh_msix_vector *iw_msixtbl;
	struct zxdh_qvlist_info *iw_qvlist;
	spinlock_t srqtable_lock; /*protect SRQ table access*/
	struct zxdh_srq **srq_table;
	struct tasklet_struct dpc_tasklet;
	struct msix_entry *msix_entries;
	struct workqueue_struct *cqp_cmpl_wq;
	struct work_struct cqp_cmpl_work;
	struct zxdh_gen_ops gen_ops;
	void (*check_fc)(struct zxdh_sc_vsi *vsi, struct zxdh_sc_qp *sc_qp);
	struct zxdh_dcqcn_cc_params dcqcn_params;
	struct zxdh_device *iwdev;
	struct zrdma_debugfs_entries debugfs_entry;
	u8 vlan_parse_en;
	u8 mcode_type;
	u16 pcie_id;
	u8 ver_buf[ZXDH_RDMA_VER_LEN];
	u32 qp_buf[ZXDH_RDMA_QP_BUF_LEN];
	u16 qp_index;
	u8 rdma_srq_mem_type;
	u32 rdma_ext_bar_offset;
	u32 srq_l2d_size;
	u64 srq_l2d_base_paddr;
};

struct zxdh_cap_entry_info {
	struct rdma_user_mmap_entry *cap_mmap_entry;
};

struct zxdh_dma_addr {
	dma_addr_t cap_dma_addr;
	void *cap_cpu_addr;
};

struct zxdh_cap_addr_info {
	union {
		u64 cap_iova_addr;
		struct zxdh_dma_addr cap_direct_dma_addr;
	} addr_info;
	struct zxdh_cap_entry_info entry_info;
};

struct zxdh_hw_data_cap_info {
	struct zxdh_cap_addr_info cap_txrx_use_iova[CAP_NODE_NUM];
	struct zxdh_cap_addr_info cap_tx_use_direct_dma[CAP_NODE_NUM];
	struct zxdh_cap_addr_info cap_rx_use_direct_dma[CAP_NODE_NUM];
	struct zxdh_cap_addr_info mp_cap;
	struct zxdh_cap_addr_info hw_object_mmap;
	u64 mp_cap_media_addr_base;
	u32 object_buffer_size;
};

struct zxdh_eth_info {
	struct zxdh_rdma_to_eth_ip_para rdma_to_eth_ip_para;
	struct net_device *netdev;
	struct hlist_node list;
	u32 ip_cfg_ref_cnt;
};

struct aeq_stop_cap_work {
	struct work_struct work;
	struct zxdh_pci_f *rf;
};

struct zxdh_device {
	struct ib_device ibdev;
#ifndef ZXDH_UAPI_DEF
	const struct uverbs_object_tree_def *driver_trees[6];
#endif
	struct zxdh_pci_f *rf;
	struct net_device *netdev;
	struct net_device *source_netdev;
	struct zxdh_handler *hdl;
	struct workqueue_struct *cleanup_wq;
	struct zxdh_sc_vsi vsi;
	struct zxdh_cm_core cm_core;
	struct list_head ah_list;
	struct mutex ah_list_lock;
	struct dev_log_trace trace_switch;
	struct zxdh_qp *qp1;
	u32 ah_list_cnt;
	u32 ah_list_hwm;
	u32 roce_cwnd;
	u32 roce_ackcreds;
	u32 vendor_id;
	u32 vendor_part_id;
	u32 device_cap_flags;
	u32 push_mode;
	u32 rcv_wnd;
	u16 mac_ip_table_idx;
	u16 vsi_num;
	u8 mac_addr[ETH_ALEN];
	u8 rcv_wscale;
	u8 iw_status;
	u8 rd_fence_rate;
#if IS_ENABLED(CONFIG_CONFIGFS_FS)
	u64 up_up_map;
	u8 cnp_up_override;
	u8 iwarp_rtomin;
	u32 ceq_intrl; /* Interrupt rate limit per second: 0-disabled, 4237 - 250,000 */
	u8 up_map_en : 1;
	u8 iwarp_dctcp_en : 1;
	u8 iwarp_timely_en : 1;
	u8 iwarp_bolt_en : 1;
	u8 iwarp_ecn_en : 1;
	u8 override_rcv_wnd : 1;
	u8 override_cwnd : 1;
	u8 override_ackcreds : 1;
	u8 override_ooo : 1;
	u8 override_rtomin : 1;
	u8 override_rd_fence_rate : 1;
	u8 roce_rtomin;
	u8 roce_ecn_en : 1;
	u8 roce_timely_en : 1;
	u8 roce_no_icrc_en : 1;
	u8 roce_dctcp_en : 1;
#endif /* CONFIG_CONFIGFS_FS */
	u8 roce_mode : 1;
	u8 roce_dcqcn_en : 1;
	u8 dcb_vlan_mode : 1;
	u8 iw_ooo : 1;
	enum init_completion_state init_state;
	struct zxdh_hw_data_cap_info hw_data_cap;
	wait_queue_head_t suspend_wq;
	struct hlist_head *eth_info_hlist;
	struct mutex eth_info_list_mtx_lock;
};

struct zxdh_handler {
	struct list_head list;
	struct zxdh_device *iwdev;
	bool shared_res_created;
};

struct rdma_sriov_glb_info {
	struct pci_dev *pdev;
	struct zxdh_pci_f *rf;
	u16 rdma_pf_enable;
};

static inline struct zxdh_device *to_iwdev(struct ib_device *ibdev)
{
	return container_of(ibdev, struct zxdh_device, ibdev);
}

static inline struct zxdh_ucontext *to_ucontext(struct ib_ucontext *ibucontext)
{
	return container_of(ibucontext, struct zxdh_ucontext, ibucontext);
}

static inline struct zxdh_user_mmap_entry *
to_zxdh_mmap_entry(struct rdma_user_mmap_entry *rdma_entry)
{
	return container_of(rdma_entry, struct zxdh_user_mmap_entry, rdma_entry);
}

static inline struct zxdh_pd *to_iwpd(struct ib_pd *ibpd)
{
	return container_of(ibpd, struct zxdh_pd, ibpd);
}

static inline struct zxdh_ah *to_iwah(struct ib_ah *ibah)
{
	return container_of(ibah, struct zxdh_ah, ibah);
}

static inline struct zxdh_mr *to_iwmr(struct ib_mr *ibmr)
{
	return container_of(ibmr, struct zxdh_mr, ibmr);
}

static inline struct zxdh_mr *to_iwmw(struct ib_mw *ibmw)
{
	return container_of(ibmw, struct zxdh_mr, ibmw);
}

static inline struct zxdh_cq *to_iwcq(struct ib_cq *ibcq)
{
	return container_of(ibcq, struct zxdh_cq, ibcq);
}

static inline struct zxdh_qp *to_iwqp(struct ib_qp *ibqp)
{
	return container_of(ibqp, struct zxdh_qp, ibqp);
}

static inline struct zxdh_pci_f *dev_to_rf(struct zxdh_sc_dev *dev)
{
	return container_of(dev, struct zxdh_pci_f, sc_dev);
}

/**
 * zxdh_alloc_resource_qp - allocate a qp resource
 * @iwdev: device pointer
 * @resource_array: resource bit array:
 * @max_resources: maximum resource number
 * @req_resources_num: Allocated resource number
 * @next: next free id
 * @ret: qp sta value
 */
static inline int zxdh_alloc_rsrc_qp(struct zxdh_pci_f *rf, unsigned long *rsrc_array, u32 max_rsrc,
				     u32 *req_rsrc_num, u32 *next, u8 *ret)
{
	u32 rsrc_num;
	u16 i;
	unsigned long flags;

	*ret = ZXDH_RDMA_QP_NOT_EXIST;
	spin_lock_irqsave(&rf->rsrc_lock, flags);
	rsrc_num = find_next_zero_bit(rsrc_array, max_rsrc, *next);
	if (rsrc_num >= max_rsrc) {
		rsrc_num = find_first_zero_bit(rsrc_array, max_rsrc);
		if (rsrc_num >= max_rsrc) {
			spin_unlock_irqrestore(&rf->rsrc_lock, flags);
			pr_err("ERR: resource [%d] allocation failed\n", rsrc_num);
			return -EOVERFLOW;
		}
	}
	__set_bit(rsrc_num, rsrc_array);
	*next = rsrc_num + 1;
	if (*next == max_rsrc)
		*next = 0;
	*req_rsrc_num = rsrc_num;
	for (i = 0; i < ZXDH_RDMA_QP_BUF_LEN; i++) {
		if (rf->qp_buf[i] == rsrc_num) {
			*ret = ZXDH_RDMA_QP_EXIST;
			break;
		}
	}
	spin_unlock_irqrestore(&rf->rsrc_lock, flags);

	return 0;
}

/**
 * zxdh_alloc_resource - allocate a resource
 * @iwdev: device pointer
 * @resource_array: resource bit array:
 * @max_resources: maximum resource number
 * @req_resources_num: Allocated resource number
 * @next: next free id
 */
static inline int zxdh_alloc_rsrc(struct zxdh_pci_f *rf, unsigned long *rsrc_array, u32 max_rsrc,
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
			pr_err("ERR: resource [%d] allocation failed\n", rsrc_num);
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
 * zxdh_free_resource - free a resource
 * @iwdev: device pointer
 * @resource_array: resource array for the resource_num
 * @resource_num: resource number to free
 */
static inline void zxdh_free_rsrc(struct zxdh_pci_f *rf, unsigned long *rsrc_array, u32 rsrc_num)
{
	unsigned long flags;

	spin_lock_irqsave(&rf->rsrc_lock, flags);
	__clear_bit(rsrc_num, rsrc_array);
	spin_unlock_irqrestore(&rf->rsrc_lock, flags);
}

int zxdh_ctrl_init_hw(struct zxdh_pci_f *rf);
void zxdh_ctrl_deinit_hw(struct zxdh_pci_f *rf);
int zxdh_rt_init_hw(struct zxdh_device *iwdev);
void zxdh_rt_deinit_hw(struct zxdh_device *iwdev);
void zxdh_qp_add_ref(struct ib_qp *ibqp);
void zxdh_qp_rem_ref(struct ib_qp *ibqp);
void zxdh_flush_wqes(struct zxdh_qp *iwqp, u32 flush_mask);
struct zxdh_cqp_request *zxdh_alloc_and_get_cqp_request(struct zxdh_cqp *cqp, bool wait);
void zxdh_free_cqp_request(struct zxdh_cqp *cqp, struct zxdh_cqp_request *cqp_request);
void zxdh_put_cqp_request(struct zxdh_cqp *cqp, struct zxdh_cqp_request *cqp_request);
u32 zxdh_initialize_hw_rsrc(struct zxdh_pci_f *rf);
void zxdh_port_ibevent(struct zxdh_device *iwdev);
void zxdh_aeq_qp_disconn(struct zxdh_qp *qp);
void zxdh_aeq_process_retry_err(struct zxdh_qp *iwqp);
void zxdh_aeq_process_entry_err(struct zxdh_qp *iwqp);

bool zxdh_cqp_crit_err(struct zxdh_sc_dev *dev, u8 cqp_cmd, u16 maj_err_code, u16 min_err_code);
int zxdh_check_cqp_cmd(struct cqp_cmds_info *info);
int zxdh_handle_cqp_op(struct zxdh_pci_f *rf, struct zxdh_cqp_request *cqp_request);
int zxdh_modify_qp_roce(struct ib_qp *ibqp, struct ib_qp_attr *attr, int attr_mask,
			struct ib_udata *udata);
void zxdh_cq_add_ref(struct ib_cq *ibcq);
void zxdh_cq_rem_ref(struct ib_cq *ibcq);
void zxdh_cq_wq_destroy(struct zxdh_pci_f *rf, struct zxdh_sc_cq *cq);

void zxdh_cleanup_pending_cqp_op(struct zxdh_pci_f *rf);
int zxdh_hw_modify_qp(struct zxdh_device *iwdev, struct zxdh_qp *iwqp,
		      struct zxdh_modify_qp_info *info, bool wait);
int zxdh_qp_suspend_resume(struct zxdh_sc_qp *qp, bool suspend);
void zxdh_free_qp_rsrc(struct zxdh_qp *iwqp);
int zxdh_hw_flush_wqes(struct zxdh_pci_f *rf, struct zxdh_sc_qp *qp,
		       struct zxdh_qp_flush_info *info, bool wait);
void zxdh_copy_ip_ntohl(u32 *dst, __be32 *src);
void zxdh_copy_ip_htonl(__be32 *dst, u32 *src);
u16 zxdh_get_vlan_ipv4(u32 *addr);
struct net_device *zxdh_netdev_vlan_ipv6(u32 *addr, u16 *vlan_id, u8 *mac);
struct ib_mr *zxdh_reg_phys_mr(struct ib_pd *ib_pd, u64 addr, u64 size, int acc, u64 *iova_start);
int zxdh_upload_qp_context(struct zxdh_qp *iwqp, bool freeze, bool raw);
void zxdh_del_hmc_objects(struct zxdh_sc_dev *dev, struct zxdh_hmc_info *hmc_info);
void zxdh_del_data_cap_objects(struct zxdh_sc_dev *dev);
void zxdh_cqp_ce_handler(struct zxdh_pci_f *rf, struct zxdh_sc_cq *cq);
int zxdh_ah_cqp_op(struct zxdh_pci_f *rf, struct zxdh_sc_ah *sc_ah, u8 cmd, bool wait,
		   void (*callback_fcn)(struct zxdh_cqp_request *cqp_request), void *cb_param);
void zxdh_gsi_ud_qp_ah_cb(struct zxdh_cqp_request *cqp_request);
bool zxdh_cq_empty(struct zxdh_cq *iwcq);
#if IS_ENABLED(CONFIG_CONFIGFS_FS)
struct zxdh_device *zxdh_get_device_by_name(const char *name);
#endif

void zxdh_set_rf_user_cfg_params(struct zxdh_pci_f *rf);
void zxdh_handle_internal_error(struct zxdh_pci_f *rf);
void zxdh_add_handler(struct zxdh_handler *hdl);
void zxdh_del_handler(struct zxdh_handler *hdl);
void cqp_compl_worker(struct work_struct *work);
void zxdh_stop_cap_worker(struct work_struct *work);
void zxdh_aeq_process_stop_cap(struct zxdh_pci_f *rf);
void zrdma_cleanup_rdma_tools_cfg(struct zxdh_pci_f *rf);
void free_cap_addr(struct zxdh_device *iwdev, struct zxdh_cap_addr_info *cap_addr_info);
int zxdh_manager_init(struct zxdh_pci_f *rf, struct iidc_core_dev_info *cdev_info);
void zxdh_update_dpp_mac_tbl(struct zxdh_device *iwdev, struct iidc_core_dev_info *cdev_info);
int zxdh_eth_info_hlist_add(struct zxdh_device *iwdev, struct zxdh_rdma_to_eth_ip_para *ip_para);
int zxdh_eth_info_hlist_delete(struct zxdh_device *iwdev, struct zxdh_rdma_to_eth_ip_para *ip_para);
void zxdh_eth_info_hlist_display(struct zxdh_device *iwdev);

struct zxdh_rdma_hb_if {
	int32_t (*cfg_rdma_hb_master)(struct net_device *primary_netdev,
				      struct net_device *linux_bond_netdev, bool hb_enable);
	int32_t (*cfg_rdma_hb_speed)(struct net_device *netdev, u32 bps);
};

extern void zxdh_hwbond_register_rdma_ops(struct zxdh_rdma_hb_if *ops);
extern void zxdh_hwbond_unregister_rdma_ops(void);

int zxdh_set_smmu_invalid(struct zxdh_pci_f *rf);

#endif /* ZRDMA_MAIN_H */

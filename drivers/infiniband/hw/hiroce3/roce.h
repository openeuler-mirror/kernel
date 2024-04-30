/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_H
#define ROCE_H

#include <linux/types.h>
#include <linux/io-mapping.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/version.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_umem.h>
#include <rdma/uverbs_ioctl.h>

#include "hinic3_hw.h"
#include "hinic3_crm.h"
#include "hinic3_hw_cfg.h"
#include "hinic3_lld.h"
#include "hinic3_cqm.h"
#include "hinic3_rdma.h"

#include "hinic3_mgmt_interface.h"

#include "roce_db.h"
#include "roce_sysfs.h"

#include "roce_verbs_cmd.h"
#include "roce_verbs_format.h"
#include "roce_verbs_ulp_format.h"

#define HIROCE3_DRV_NAME "roce3_drv"
#define HIROCE3_DRV_AUTHOR "Huawei Technologies CO., Ltd"
#define HIROCE3_DRV_DESC "Huawei(R) Intelligent Network Interface Card, RoCE Driver"
#define HIROCE3_DRV_VERSION ""

#define ROCE_IB_UVERBS_ABI_VERSION 1
#define ROCE_ULD_DEV_NAME_LEN 16

#define MAX_CEQ_NEED 256
#define MS_DELAY 5
#define US_PERF_DELAY 100

#define DEV_ADDR_FIRST_BYTE_VAL_MASK 2

#define ROCE_NODE_DESC_LEN 5

#define ROCE_SQ_WQEBB_SIZE 64

#define ROCE_GID_LEN 16

#define ROCE_PCI_CFG_REGS_BAR0 0
#define ROCE_PCI_CFG_REGS_BAR3 3

#define DEFAULT_ROCE_DEV_NODE_PRI 0640

#define ALPHA_THREADHOLD_UNIT_SHIFT 3

#define PAGE_4K_SHIFT 12

#define ROCE_MAX_PORT_NUM 8

#ifndef BIG_ENDIAN
#define BIG_ENDIAN 0x4321
#endif

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 0x1234
#endif

#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif

#define MAX_ROCE_DEV (28 * 4)

enum {
	ROCE3_2_PORT_NUM = 2,
	ROCE3_4_PORT_NUM = 4
};

enum {
	ROCE3_25G_PORT_SPEED = 25,
	ROCE3_100G_PORT_SPEED = 100
};

enum {
	ROCE3_INVALID_HCA = -1,
	ROCE3_2_100G_HCA = 0,
	ROCE3_4_25G_HCA = 1,
	ROCE3_2_25G_HCA = 2
};

enum ROCE3_100G_BW_PARAM_E {
	ROCE3_100G_CIR = 46500000,
	ROCE3_100G_PIR = 52500000,
	ROCE3_100G_CNP = 100
};

enum ROCE3_25G_BW_PARAM_E {
	ROCE3_25G_CIR = 23200000,
	ROCE3_25G_PIR = 25500000,
	ROCE3_25G_CNP = 3
};

enum roce_bitshift_e {
	BYTES_TO_2B_SHIFT = 1,
	BYTES_TO_4B_SHIFT,
	BYTES_TO_8B_SHIFT,
	BYTES_TO_16B_SHIFT,
	BYTES_TO_32B_SHIFT
};

#define roce3_pr_err_once pr_err_once

/* BIG/LITTLE ENGIAN switch */
#ifdef HW_CONVERT_ENDIAN
#define roce3_convert_be32(val) (val)
#define roce3_convert_cpu32(val) (val)
#define roce3_more_be32(val) cpu_to_be32(val)
#else
#define roce3_convert_be32(val) cpu_to_be32(val)
#define roce3_convert_cpu32(val) be32_to_cpu(val)
#define roce3_more_be32(val) (val)
#endif

enum roce3_aeq_type {
	/* ofed err */
	OFED_ET_PATH_MIG = 0,
	OFED_ET_COMM_EST,
	OFED_ET_SQ_DRAINED,
	OFED_ET_SRQ_QP_LAST_WQE,
	OFED_ET_WQ_CATAS_ERR,

	OFED_ET_PATH_MIG_FAILED = 5,
	OFED_ET_WQ_INVAL_REQ_ERR,
	OFED_ET_WQ_ACCESS_ERR,
	OFED_ET_CQ_ERR,
	OFED_ET_SRQ_LIMIT,
	OFED_ET_SRQ_CATAS_ERR,

	/* non ofed err */
	NON_OFED_ET_QPC_LOOKUP_ERR = 11,
	NON_OFED_ET_OTHER_TYPE_ERR,

	/* NOF AA err */
	OFED_NOF_AA_QP_DISCONNECT = 64,
	OFED_NOF_AA_MASTER_CHANGE,

	INVAL_ET_ERR
};

enum {
	ROCE_CMD_TIME_CLASS_A = 3000,
	ROCE_CMD_TIME_CLASS_B = 4000,
	ROCE_CMD_TIME_CLASS_C = 5000
};

enum roce3_sgl_mode {
	ROCE_DOUBLE_SGL = 0,
	ROCE_SINGLE_SGL
};

enum roce3_qpc_mtucode {
	ROCE_MTU_CODE_256 = 0x0,
	ROCE_MTU_CODE_512 = 0x1,
	ROCE_MTU_CODE_1K = 0x3,
	ROCE_MTU_CODE_2K = 0x7,
	ROCE_MTU_CODE_4K = 0xf
};

enum roce3_ctrl_status {
	ROCE3_PORT_EVENT = BIT(0)
};

#define ROCE_DEFAULT_PORT_NUM 1

#if defined(ROCE_VBS_EN) || defined(ROCE_CHIP_TEST)
#define ROCE_UVERBS_CMD_MASK \
	((1ULL << IB_USER_VERBS_CMD_GET_CONTEXT) | \
	(1ULL << IB_USER_VERBS_CMD_QUERY_DEVICE) | \
	(1ULL << IB_USER_VERBS_CMD_QUERY_PORT) | \
	(1ULL << IB_USER_VERBS_CMD_ALLOC_PD) | \
	(1ULL << IB_USER_VERBS_CMD_DEALLOC_PD) | \
	(1ULL << IB_USER_VERBS_CMD_CREATE_AH) | \
	(1ULL << IB_USER_VERBS_CMD_DESTROY_AH) | \
	(1ULL << IB_USER_VERBS_CMD_REG_MR) | \
	(1ULL << IB_USER_VERBS_CMD_DEREG_MR) | \
	(1ULL << IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL) | \
	(1ULL << IB_USER_VERBS_CMD_CREATE_CQ) | \
	(1ULL << IB_USER_VERBS_CMD_RESIZE_CQ) | \
	(1ULL << IB_USER_VERBS_CMD_DESTROY_CQ) | \
	(1ULL << IB_USER_VERBS_CMD_CREATE_QP) | \
	(1ULL << IB_USER_VERBS_CMD_MODIFY_QP) | \
	(1ULL << IB_USER_VERBS_CMD_QUERY_QP) | \
	(1ULL << IB_USER_VERBS_CMD_DESTROY_QP) | \
	(1ULL << IB_USER_VERBS_CMD_CREATE_SRQ) | \
	(1ULL << IB_USER_VERBS_CMD_MODIFY_SRQ) | \
	(1ULL << IB_USER_VERBS_CMD_QUERY_SRQ) | \
	(1ULL << IB_USER_VERBS_CMD_DESTROY_SRQ) | \
	(1ULL << IB_USER_VERBS_CMD_CREATE_XSRQ) | \
	(1ULL << IB_USER_VERBS_CMD_CREATE_DCT) | \
	(1ULL << IB_USER_VERBS_CMD_QUERY_DCT) | \
	(1ULL << IB_USER_VERBS_CMD_ARM_DCT) | \
	(1ULL << IB_USER_VERBS_CMD_DESTROY_DCT) | \
	(1ULL << IB_USER_VERBS_CMD_CREATE_MR) | \
	(1ULL << IB_USER_VERBS_CMD_REG_FAST_MR) | \
	(1ULL << IB_USER_VERBS_CMD_DEREG_FAST_MR) | \
	(1ULL << IB_USER_VERBS_CMD_MAP_FRMR_SG) | \
	(1ULL << IB_USER_VERBS_CMD_OPEN_QP))
#else
#define ROCE_UVERBS_CMD_MASK \
	((1ULL << IB_USER_VERBS_CMD_GET_CONTEXT) | \
	(1ULL << IB_USER_VERBS_CMD_QUERY_DEVICE) | \
	(1ULL << IB_USER_VERBS_CMD_QUERY_PORT) | \
	(1ULL << IB_USER_VERBS_CMD_ALLOC_PD) | \
	(1ULL << IB_USER_VERBS_CMD_DEALLOC_PD) | \
	(1ULL << IB_USER_VERBS_CMD_CREATE_AH) | \
	(1ULL << IB_USER_VERBS_CMD_DESTROY_AH) | \
	(1ULL << IB_USER_VERBS_CMD_REG_MR) | \
	(1ULL << IB_USER_VERBS_CMD_REREG_MR) | \
	(1ULL << IB_USER_VERBS_CMD_DEREG_MR) | \
	(1ULL << IB_USER_VERBS_CMD_ALLOC_MW) | \
	(1ULL << IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL) | \
	(1ULL << IB_USER_VERBS_CMD_DEALLOC_MW) | \
	(1ULL << IB_USER_VERBS_CMD_CREATE_CQ) | \
	(1ULL << IB_USER_VERBS_CMD_RESIZE_CQ) | \
	(1ULL << IB_USER_VERBS_CMD_DESTROY_CQ) | \
	(1ULL << IB_USER_VERBS_CMD_CREATE_QP) | \
	(1ULL << IB_USER_VERBS_CMD_MODIFY_QP) | \
	(1ULL << IB_USER_VERBS_CMD_QUERY_QP) | \
	(1ULL << IB_USER_VERBS_CMD_DESTROY_QP) | \
	(1ULL << IB_USER_VERBS_CMD_ATTACH_MCAST) | \
	(1ULL << IB_USER_VERBS_CMD_DETACH_MCAST) | \
	(1ULL << IB_USER_VERBS_CMD_CREATE_SRQ) | \
	(1ULL << IB_USER_VERBS_CMD_MODIFY_SRQ) | \
	(1ULL << IB_USER_VERBS_CMD_QUERY_SRQ) | \
	(1ULL << IB_USER_VERBS_CMD_DESTROY_SRQ) | \
	(1ULL << IB_USER_VERBS_CMD_OPEN_XRCD) | \
	(1ULL << IB_USER_VERBS_CMD_CLOSE_XRCD) | \
	(1ULL << IB_USER_VERBS_CMD_CREATE_XSRQ) | \
	(1ULL << IB_USER_VERBS_CMD_OPEN_QP))
#endif

#define ROCE_UVERBS_EXT_CMD_MASK (1ULL << IB_USER_VERBS_EX_CMD_MODIFY_CQ)

enum roce3_load_balance_mode_e {
	ROCE_LB_MODE_0 = 0,
	ROCE_LB_MODE_1,
	ROCE_LB_MODE_2,
	ROCE_LB_MODE_N,
};

enum push_ofed_device_status {
	ROCE_DEV_STATUS_NORMAL = 0,
	ROCE_DEV_STATUS_CMDQ_TIMEOUT
};

enum roce3_func_state {
	ROCE_FUNC_DISABLE = 0,
	ROCE_FUNC_ENABLE
};

enum {
	ROCE_Cl_TYPE_QPC = 0x0,	/* cl_start: 0x0, cl_end: 0x7f, cl_size: 0 */
	ROCE_CL_TYPE_MPT = 0x1,	/* cl_start: 0x150, cl_end: 0x15f, cl_size: 0 */
	ROCE_CL_TYPE_SQ_WQE = 0x2,	/* cl_start: 0x80, cl_end: 0xff, cl_size: 0 */
	ROCE_CL_TYPE_RQ_WQE = 0x3,	/* cl_start: 0x80, cl_end: 0xff, cl_size: 0 */
	ROCE_CL_TYPE_CQC_SRQC = 0x4,	/* cl_start: 0x120, cl_end: 0x13f, cl_size: 0 */
	ROCE_CL_TYPE_RDMARC = 0x5,	/* cl_start: 0x120, cl_end: 0x13f, cl_size: 0 */
	ROCE_CL_TYPE_CMTT = 0x6,	/* cl_start: 0x100, cl_end: 0x11f, cl_size: 0 */
	ROCE_CL_TYPE_DMTT = 0x7	/* cl_start: 0x100, cl_end: 0x11f, cl_size: 0 */
};

#define XRC_CONTAINER_FLAG ((int)(1L << 20))

struct roce3_notifier {
	struct notifier_block nb;
	struct notifier_block nb_inet;
	struct notifier_block nb_inet6;
};

struct roce3_buf_list {
	void *buf;
	dma_addr_t map;
};

struct roce3_buf {
	struct roce3_buf_list direct;
	struct roce3_buf_list *page_list;
	int nbufs;

	int npages;
	int page_shift;
};

struct roce3_ucontext {
	struct ib_ucontext ibucontext;
	void __iomem *db_map;
	void __iomem *dwqe_map;
	u64 db_dma_addr;
	u64 dwqe_dma_addr;
	struct list_head db_page_list;
	struct mutex db_page_mutex;
};

struct roce3_qp_cnt {
	struct mutex cur_qps_mutex;
	u32 alloc_qp_cnt;
	u32 del_qp_cnt;
};

struct roce3_cdev_file {
	struct roce3_cdev *cdev;
};

struct roce3_cdev {
	struct cdev cdev;
	/*lint -e104 -e808*/
	struct class *cdev_class;
	/*lint +e104 +e808*/
	struct device *dev;
	int dev_num;
	dev_t dev_major;
};

struct roce3_netlink {
	int dev_num;
};

struct roce3_dev_hw_info {
	int config_num_ports; /* Number of ports from configuration file */
	int hca_type;		 /* HCA version: 4x25G or 2x100G */
	u8 phy_port;
	u8 ep_id; /* EP ID */
	u8 cpu_endian;
	u8 rsvd;

	bool is_vf;
};

bool roce3_is_roceaa(u8 scence_id);

struct roce3_dev_cfg_info {
	u8 scence_id; /* load scenes ID as aa_en */
	u8 lb_en;	 /* load balance enable */
	u8 lb_mode;   /* load balance mode */
	u8 rsvd;

	u8 srq_container_en;
	u8 srq_container_mode;
	u8 xrc_srq_container_mode;
	u8 warn_th;

	u8 fake_en;
	u8 page_bit;
	u8 pf_start_bit;
	u8 pf_end_bit;

	u8 port_num;	/* cfg data port num */
	u8 host_num;	/* cfg data host num */
	u8 master_func; /* nofaa master func */
	u8 rsvd1;
};

struct roce3_device {
	struct ib_device ib_dev;
	struct hinic3_lld_dev *lld_dev;
	struct net_device *ndev;
	struct pci_dev *pdev;
	void *hwdev;
	void *hwdev_hdl;
	// struct dev_version_info dev_ver;  /*version info */
	struct hinic3_board_info board_info;
	struct roce3_cdev cdev;
	struct roce3_netlink netlink_dev;

	struct roce3_notifier notifier;
	void __iomem *kernel_db_map;
	void __iomem *kernel_dwqe_map;
	spinlock_t node_desc_lock;
	struct mutex cap_mask_mutex;
	struct rdma_service_cap rdma_cap;

	u8 mac[6]; /* Mac addr. */
	u16 glb_func_id;
	unsigned long status;
	int ceq_num;
	int ceqn[MAX_CEQ_NEED];
	int try_times;
	bool ib_active;

	u8 group_rc_cos;
	u8 group_ud_cos;
	u8 group_xrc_cos;

	struct roce3_dev_hw_info hw_info;   /* Hw info read from nic/pcie */
	struct roce3_dev_cfg_info cfg_info; /* Cfg data info read from MPU */

#ifdef ROCE_BONDING_EN
	int want_bond_slave_cnt;
	int want_bond_slave_bits[2]; /* The maximum number of bonds supported is 2 */
	enum ib_port_state port_state;
	struct hinic3_dcb_state dcb_info;
	char *sdi_bond_name;
	struct roce3_bond_device *bond_dev;
#endif

	struct mutex mac_vlan_mutex;
	struct list_head mac_vlan_list_head;
	struct net_device **gid_dev;

	struct roce3_ecn_ctx ecn_ctx;
	struct roce3_dfx_ctx dfx_ctx;

	struct roce3_qp_cnt qp_cnt;

	struct srcu_struct mr_srcu;
	atomic_t num_prefetch;
	struct completion comp_prefetch;
	enum push_ofed_device_status dev_status_to_ofed;

	spinlock_t reset_flow_resource_lock;
	struct list_head qp_list;

	void *fake_data_buf;
	dma_addr_t fake_data_page_addr;
	// mailbox, ppf store all pf's roce device, to improve the effiency.
	void *pri_roce_dev[ROCE_MAX_PORT_NUM];
	bool is_vroce;
};

static inline struct roce3_device *to_roce3_dev(const struct ib_device *ibdev)
{
	return container_of(ibdev, struct roce3_device, ib_dev);
}

static inline struct roce3_ucontext *to_roce3_ucontext(const struct ib_ucontext *ibucontext)
{
	return container_of(ibucontext, struct roce3_ucontext, ibucontext);
}

int roce3_db_map_user(struct roce3_ucontext *context, unsigned long virt, struct roce3_db *db);
void roce3_db_unmap_user(struct roce3_ucontext *context, struct roce3_db *db);

int roce3_buf_write_mtt(struct roce3_device *rdev, struct rdma_mtt *mtt, struct tag_cqm_buf *buf);
int roce3_umem_write_mtt(struct roce3_device *rdev, struct rdma_mtt *mtt, struct ib_umem *umem);

int roce3_query_device(struct ib_device *ibdev, struct ib_device_attr *props, struct ib_udata *uhw);

int roce3_modify_device(struct ib_device *ibdev, int mask, struct ib_device_modify *props);

int roce3_mmap(struct ib_ucontext *ibcontext, struct vm_area_struct *vma);

int roce3_create_cq(struct ib_cq *cq, const struct ib_cq_init_attr *attr, struct ib_udata *udata);

int roce3_destroy_cq(struct ib_cq *ibcq, struct ib_udata *udata);

int roce3_destroy_qp(struct ib_qp *ibqp, struct ib_udata *udata);

int roce3_create_srq(struct ib_srq *ibsrq, struct ib_srq_init_attr *init_attr,
	struct ib_udata *udata);

int roce3_destroy_srq(struct ib_srq *ibsrq, struct ib_udata *udata);

int roce3_dereg_mr(struct ib_mr *ibmr, struct ib_udata *udata);

int roce3_alloc_ucontext(struct ib_ucontext *ibucontext, struct ib_udata *udata);

void roce3_dealloc_ucontext(struct ib_ucontext *ibcontext);

int roce3_alloc_pd(struct ib_pd *ibpd, struct ib_udata *udata);

int roce3_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata);

int roce3_create_ah(struct ib_ah *ibah, struct rdma_ah_init_attr *init_attr,
	struct ib_udata *udata);

int roce3_destroy_ah(struct ib_ah *ibah, u32 flags);

int roce3_alloc_xrcd(struct ib_xrcd *ibxrcd, struct ib_udata *udata);

int roce3_dealloc_xrcd(struct ib_xrcd *ibxrcd, struct ib_udata *udata);

int roce3_alloc_mw(struct ib_mw *ibmw, struct ib_udata *udata);

int roce3_query_ah(struct ib_ah *ibah, struct rdma_ah_attr *ah_attr);


int roce3_query_port(struct ib_device *device, u8 port_num, struct ib_port_attr *port_attr);

int roce3_query_gid(struct ib_device *ibdev, u8 port, int index, union ib_gid *gid);

int roce3_modify_port(struct ib_device *ibdev, u8 port, int mask, struct ib_port_modify *props);

int roce3_port_immutable(struct ib_device *ibdev, u8 port_num,
	struct ib_port_immutable *immutable);

struct net_device *roce3_ib_get_netdev(struct ib_device *ibdev, u8 port_num);

enum rdma_link_layer roce3_port_link_layer(struct ib_device *ibdev, u8 port_num);

int roce3_query_pkey(struct ib_device *ibdev, u8 port, u16 index, u16 *pkey);

struct ib_qp *roce3_create_qp(struct ib_pd *pd, struct ib_qp_init_attr *qp_init_attr,
	struct ib_udata *udata);


int roce3_modify_cq(struct ib_cq *ibcq, u16 cq_count, u16 cq_period);

int roce3_resize_cq(struct ib_cq *ibcq, int entries, struct ib_udata *udata);

int roce3_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc);

int roce3_arm_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags);


int roce3_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr, int attr_mask,
	struct ib_udata *udata);

int roce3_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *qp_attr, int qp_attr_mask,
	struct ib_qp_init_attr *qp_init_attr);

int roce3_post_recv(struct ib_qp *ibqp, const struct ib_recv_wr *wr,
	const struct ib_recv_wr **bad_wr);
int roce3_post_srq_recv(struct ib_srq *ibsrq, const struct ib_recv_wr *wr,
	const struct ib_recv_wr **bad_wr);

void roce3_drain_rq(struct ib_qp *ibqp);

int roce3_modify_srq(struct ib_srq *ibsrq, struct ib_srq_attr *attr,
	enum ib_srq_attr_mask attr_mask, struct ib_udata *udata);

int roce3_query_srq(struct ib_srq *ibsrq, struct ib_srq_attr *srq_attr);

struct ib_mr *roce3_get_dma_mr(struct ib_pd *ibpd, int access);
struct ib_mr *roce3_alloc_mr(struct ib_pd *ibpd, enum ib_mr_type mr_type, u32 max_num_sg);
struct ib_mr *roce3_reg_user_mr(struct ib_pd *ibpd, u64 start, u64 length,
	u64 virt_addr, int access, struct ib_udata *udata);

int roce3_map_kernel_frmr_sg(struct ib_mr *ibmr, struct scatterlist *sg,
	int sg_nents, unsigned int *sg_offset);

int roce3_dealloc_mw(struct ib_mw *ibmw);

int roce3_query_device_status(struct ib_device *ibdev, int *dev_status);
int roce3_init_cdev(struct roce3_device *rdev);
void roce3_remove_cdev(struct roce3_device *rdev);
int roce3_bond_get_dcb_info(struct roce3_device *rdev);

int roce3_init_sysfs(struct roce3_device *rdev);
void roce3_remove_sysfs(struct roce3_device *rdev);

int roce3_is_eth_port_of_netdev(struct net_device *rdma_ndev, struct net_device *cookie);

void roce3_async_event(void *svc_hd, u8 event_type, u8 *val);
u8 roce3_async_event_level(void *svc_hd, u8 event_type, u8 *val);
void roce3_cq_completion(void *svc_hd, u32 cqn, void *cq_handler);
void roce3_unregister_netdev_event(struct roce3_device *rdev);
int roce3_ifconfig_up_down_event_report(struct roce3_device *rdev, u8 net_event);
int roce3_register_netdev_event(struct roce3_device *rdev);
void roce3_clean_vlan_device_mac(struct roce3_device *rdev);
void roce3_clean_real_device_mac(struct roce3_device *rdev);

int roce3_ib_add_gid(const struct ib_gid_attr *attr, __always_unused void **context);

int roce3_ib_del_gid(const struct ib_gid_attr *attr, __always_unused void **context);

void roce3_remove_dev_file(struct roce3_device *rdev);
int roce3_init_dev_file(struct roce3_device *rdev);

#endif // ROCE_H

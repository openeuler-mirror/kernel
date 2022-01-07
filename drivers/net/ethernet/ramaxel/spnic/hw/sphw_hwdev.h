/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPHW_HWDEV_H
#define SPHW_HWDEV_H

#include "sphw_mt.h"
#include "sphw_crm.h"
#include "sphw_hw.h"

struct cfg_mgmt_info;

struct sphw_hwif;
struct sphw_aeqs;
struct sphw_ceqs;
struct sphw_mbox;
struct sphw_msg_pf_to_mgmt;

struct sphw_page_addr {
	void *virt_addr;
	u64 phys_addr;
};

struct mqm_addr_trans_tbl_info {
	u32 chunk_num;
	u32 search_gpa_num;
	u32 page_size;
	u32 page_num;
	struct sphw_page_addr *brm_srch_page_addr;
};

struct sphw_hwdev {
	void *adapter_hdl;  /* pointer to spnic_pcidev or NDIS_Adapter */
	void *pcidev_hdl;   /* pointer to pcidev or Handler */
	void *dev_hdl;      /* pointer to pcidev->dev or Handler, for
			     * sdk_err() or dma_alloc()
			     */

	void *service_adapter[SERVICE_T_MAX];
	void *chip_node;
	void *ppf_hwdev;

	u32 wq_page_size;
	int chip_present_flag;
	bool poll;	   /*use polling mode or int mode*/

	struct sphw_hwif *hwif; /* include void __iomem *bar */
	struct comm_global_attr glb_attr;
	u64 features[COMM_MAX_FEATURE_QWORD];

	struct cfg_mgmt_info *cfg_mgmt;

	struct sphw_cmdqs *cmdqs;
	struct sphw_aeqs *aeqs;
	struct sphw_ceqs *ceqs;
	struct sphw_mbox *func_to_func;
	struct sphw_msg_pf_to_mgmt *pf_to_mgmt;
	struct sphw_clp_pf_to_mgmt *clp_pf_to_mgmt;

	void *cqm_hdl;
	struct mqm_addr_trans_tbl_info mqm_att;
	struct sphw_page_addr page_pa0;
	struct sphw_page_addr page_pa1;
	u32 statufull_ref_cnt;

	struct sphw_hw_stats hw_stats;
	u8 *chip_fault_stats;

	sphw_event_handler event_callback;
	void *event_pri_handle;

	struct sphw_board_info board_info;

	int			prof_adap_type;
	struct sphw_prof_attr	*prof_attr;

	struct workqueue_struct *workq;

	u32 rd_bar_err_cnt;
	bool pcie_link_down;
	bool heartbeat_lost;
	struct timer_list heartbeat_timer;
	struct work_struct heartbeat_lost_work;
};

#define SPHW_MAX_HOST_NUM(hwdev)	((hwdev)->glb_attr.max_host_num)
#define SPHW_MAX_PF_NUM(hwdev)		((hwdev)->glb_attr.max_pf_num)
#define SPHW_MGMT_CPU_NODE_ID(hwdev)	((hwdev)->glb_attr.mgmt_host_node_id)

#define COMM_FEATURE_QW0(hwdev, feature)	((hwdev)->features[0] & COMM_F_##feature)
#define COMM_SUPPORT_API_CHAIN(hwdev)	COMM_FEATURE_QW0(hwdev, API_CHAIN)

#define SPHW_DRV_FEATURE_QW0		COMM_F_API_CHAIN

#endif

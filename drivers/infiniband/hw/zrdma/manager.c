// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/pci.h>
#include "iidc.h"
#include "main.h"
#include "manager.h"
#include "icrdma_hw.h"

u64 zxdh_hw_bar_pages[C_RDMA_HW_BAR_PAGE_NUM] = { 0 };

struct zxdh_rdma_hb_if hwbond_ops = {
	.cfg_rdma_hb_master = switch_bound_master_netdev,
	.cfg_rdma_hb_speed = set_rdma_firmware_speed,
};

int dh_rdma_pf_pcie_id_get(struct zxdh_mgr *mgr)
{
	u32 pos = 0;
	u8 type = 0;
	u16 padding = 0;
	struct pci_dev *pdev = mgr->pdev;

	for (pos = pci_find_capability(pdev, PCI_CAP_ID_VNDR); pos > 0;
	     pos = pci_find_next_capability(pdev, pos, PCI_CAP_ID_VNDR)) {
		pci_read_config_byte(pdev, pos + offsetof(struct zxdh_pf_pci_cap, cfg_type), &type);

		if (type == ZXDH_PCI_CAP_PCI_CFG) {
			pci_read_config_word(
				pdev, pos + offsetof(struct zxdh_pf_pci_cap, padding[0]), &padding);
			mgr->pcie_id = padding;
			return 0;
		}
	}
	return -1;
}

int zxdh_chan_sync_send(struct zxdh_mgr *pmgr, struct zxdh_chan_msg *pmsg, u32 *pdata, u32 rep_len)
{
	u16 buffer_len = 0;
	void *recv_buffer = NULL;
	int ret = 0;
	u8 *reply_ptr = NULL;
	u16 reply_msg_len = 0;
	u32 cnt = 0;

	struct zxdh_pci_bar_msg in = { 0 };
	struct zxdh_msg_recviver_mem result = { 0 };

	if (!pmgr || !pmsg || !pdata)
		return -1;

	buffer_len = rep_len + ZXDH_CHAN_REPS_LEN;
	recv_buffer = kmalloc(buffer_len, GFP_KERNEL);
	if (!recv_buffer)
		return -1;

	in.virt_addr = (u64)pmgr->pci_hw_addr + ZXDH_BAR_CHAN_OFFSET;
	in.payload_addr = pmsg->msg;
	in.payload_len = pmsg->msg_len;

	if (!pmgr->ftype)
		in.src = MSG_CHAN_END_PF;
	else
		in.src = MSG_CHAN_END_VF;

	in.dst = MSG_CHAN_END_RISC;
	in.event_id = MODULE_RDMA;

	if (dh_rdma_pf_pcie_id_get(pmgr) == 0)
		in.src_pcieid = pmgr->pcie_id;
	else {
		kfree(recv_buffer);
		return -1;
	}

	result.buffer_len = buffer_len;
	result.recv_buffer = recv_buffer;

	do {
		ret = zxdh_bar_chan_sync_msg_send(&in, &result);
		if ((ret != ZXDH_BAR_ERR_TIME_OUT) && (ret != ZXDH_BAR_ERR_LOCK_FAILED))
			break;
		cnt++;
	} while (cnt < ZXDH_BAR_MSG_RETRY_NUM);

	if (ret != 0) {
		pr_err("zxdh_bar_chan_sync_msg_send faile, ret=%d cnt=%d\n", ret, cnt);
		kfree(recv_buffer);
		return -1;
	}

	reply_ptr = (u8 *)result.recv_buffer;
	if (*reply_ptr == MSG_REP_VALID) {
		reply_msg_len = *(u16 *)(reply_ptr + MSG_REP_LEN_OFFSET);
		memcpy(pdata, reply_ptr + ZXDH_CHAN_REPS_LEN,
		       ((reply_msg_len > rep_len) ? rep_len : reply_msg_len));
		kfree(recv_buffer);
		return 0;
	}

	kfree(recv_buffer);
	return 0;
}

int zxdh_mgr_par_get(struct zxdh_mgr *dh_mgr)
{
	int ret = 0;

	struct zxdh_mgr_msg *cmd = kzalloc(sizeof(struct zxdh_mgr_msg), GFP_KERNEL);
	struct zxdh_chan_msg *pmsg = kzalloc(sizeof(struct zxdh_chan_msg), GFP_KERNEL);
	struct zxdh_mgr_par param;

	if (!pmsg) {
		kfree(cmd);
		return -ENOMEM;
	}

	if (!cmd) {
		kfree(pmsg);
		return -ENOMEM;
	}

	cmd->op_code = 0;
	cmd->pf_id = dh_mgr->pf_id;
	cmd->vport_vf_id = dh_mgr->vport_vf_id;
	cmd->ftype = dh_mgr->ftype;
	cmd->ep_id = dh_mgr->ep_id;

	pmsg->msg_len = sizeof(struct zxdh_mgr_msg);
	pmsg->msg = (void *)cmd;

	ret = zxdh_chan_sync_send(dh_mgr, pmsg, (void *)&dh_mgr->param,
				  sizeof(struct zxdh_mgr_par));
	param = dh_mgr->param;
	pr_info("mgr cfg param:");
	pr_info("ftype=%d, ep_id=%d, pf_id=%d, max_vf_num=%d, vhca_id=%d, bar_offset=0x%x.\n",
		param.ftype, param.ep_id, param.pf_id, param.max_vf_num, param.vhca_id,
		param.bar_offset);
	pr_info("l2d_smmu_addr=0x%llx, vf_id=%d, vhca_id_pf=%d, l2d_smmu_l2_offset=%d.\n",
		param.l2d_smmu_addr, param.vf_id, param.vhca_id_pf, param.l2d_smmu_l2_offset);
	pr_info("qp_cnt=%d,cq_cnt=%d,srq_cnt=%d,ceq_cnt=%d,ah_cnt=%d\n", param.qp_cnt, param.cq_cnt,
		param.srq_cnt, param.ceq_cnt, param.ah_cnt);
	pr_info("mr_cnt=%d, pbleq_cnt=%d,pblem_cnt=%d\n", param.mr_cnt, param.pbleq_cnt,
		param.pblem_cnt);
	pr_info("base_qpn=%d, base_cqn=%d, base_srqn=%d, base_ceqn=%d.\n", param.base_qpn,
		param.base_cqn, param.base_srqn, param.base_ceqn);
	pr_info("qp_hmc_base=0x%llx,cq_hmc_base=0x%llx,srq_hmc_base=0x%llx,txwindow_hmc_base=0x%llx\n",
		param.qp_hmc_base, param.cq_hmc_base, param.srq_hmc_base, param.txwindow_hmc_base);
	pr_info("ird_base=0x%llx,ah_base=0x%llx,mr_base=0x%llx,pbleq_base=0x%llx,pblem_base=0x%llx\n",
		param.ird_hmc_base, param.ah_hmc_base, param.mr_hmc_base, param.pbleq_hmc_base,
		param.pblem_hmc_base);
	pr_info("mcode_type=%d,chip_version=%d,max_hw_wq_frags=%d,max_hw_read_sges=%d\n",
		param.mcode_type, param.chip_version, param.max_hw_wq_frags,
		param.max_hw_read_sges);

	if (ret != 0) {
		pr_info("get pf param faile, ret=%d.\n", ret);
		kfree(cmd);
		kfree(pmsg);
		return -EPIPE;
	}

	if (param.ftype != dh_mgr->ftype || param.ep_id != dh_mgr->ep_id ||
	    param.pf_id != dh_mgr->pf_id) {
		kfree(cmd);
		kfree(pmsg);
		return -EPIPE;
	}

	kfree(cmd);
	kfree(pmsg);

	return 0;
}

static int zxdh_sc_init_hmccnt(struct zxdh_pci_f *rf, struct zxdh_mgr_par *param)
{
	struct zxdh_sc_dev *dev = &rf->sc_dev;
	u32 hmc_info_mem_size;

	hmc_info_mem_size = sizeof(struct zxdh_hmc_pble_rsrc) * 2 + sizeof(struct zxdh_hmc_info) +
			    (sizeof(struct zxdh_hmc_obj_info) * ZXDH_HMC_IW_MAX);

	rf->hmc_info_mem = kzalloc(hmc_info_mem_size, GFP_KERNEL);
	if (!rf->hmc_info_mem)
		return -ENOMEM;

	rf->pble_mr_rsrc = (struct zxdh_hmc_pble_rsrc *)rf->hmc_info_mem;
	rf->pble_rsrc = (struct zxdh_hmc_pble_rsrc *)(rf->pble_mr_rsrc + 1);
	dev->hmc_info = &rf->hw.hmc;
	dev->hmc_info->hmc_obj = (struct zxdh_hmc_obj_info *)(rf->pble_rsrc + 1);

	rf->max_rdma_vfs = param->max_vf_num;
	dev->hmc_use_dpu_ddr = param->hmc_use_dpu_ddr;
	dev->l2d_smmu_addr = param->l2d_smmu_addr;
	dev->l2d_smmu_l2_offset = param->l2d_smmu_l2_offset;

	dev->hmc_pf_manager_info.hmc_base = param->qp_hmc_base;
	dev->hmc_pf_manager_info.hmc_size = param->pf_hmc_size;

	rf->max_qp = param->qp_cnt;
	rf->max_cq = param->cq_cnt;
	rf->max_srq = param->srq_cnt;
	rf->max_ah = param->ah_cnt;
	rf->max_mr = param->mr_cnt;

	if (rf->srq_l2d_base_paddr != 0 && rf->srq_l2d_size != 0) {
		if (rf->ftype == FUNCTION_TYPE_PF)
			rf->max_srq = ZXDH_PF_MAX_SRQ_NUM_USE_L2D;
		else
			rf->max_srq = ZXDH_VF_MAX_SRQ_NUM_USE_L2D;

	} else {
		rf->max_srq = 0;
		pr_warn("%s[%d]: warning SRQ can not use DDR memory! ep_id=%d pf_id=%d vf_id=%d ftype=%d\n",
			__func__, __LINE__, rf->ep_id, rf->pf_id, rf->vf_id, rf->ftype);
	}

	dev->max_qp = rf->max_qp;
	dev->max_cq = rf->max_cq;
	dev->max_srq = rf->max_srq;
	dev->base_qpn = param->base_qpn;
	dev->base_cqn = param->base_cqn;
	dev->base_srqn = param->base_srqn;

	dev->hmc_info->hmc_obj[ZXDH_HMC_IW_QP].max_cnt = rf->max_qp;
	dev->hmc_info->hmc_obj[ZXDH_HMC_IW_CQ].max_cnt = rf->max_cq;
	dev->hmc_info->hmc_obj[ZXDH_HMC_IW_SRQ].max_cnt = rf->max_srq;
	dev->hmc_info->hmc_obj[ZXDH_HMC_IW_TXWINDOW].max_cnt = rf->max_qp;
	dev->hmc_info->hmc_obj[ZXDH_HMC_IW_IRD].max_cnt = rf->max_qp;
	dev->hmc_info->hmc_obj[ZXDH_HMC_IW_AH].max_cnt = rf->max_ah;
	dev->hmc_info->hmc_obj[ZXDH_HMC_IW_MR].max_cnt = param->mr_cnt;
	dev->hmc_info->hmc_obj[ZXDH_HMC_IW_PBLE].max_cnt = param->pbleq_cnt;
	dev->hmc_info->hmc_obj[ZXDH_HMC_IW_PBLE_MR].max_cnt = param->pblem_cnt;

	dev->hmc_info->hmc_obj[ZXDH_HMC_IW_QP].base = param->qp_hmc_base;
	dev->hmc_info->hmc_obj[ZXDH_HMC_IW_CQ].base = param->cq_hmc_base;
	dev->hmc_info->hmc_obj[ZXDH_HMC_IW_SRQ].base = param->srq_hmc_base;
	dev->hmc_info->hmc_obj[ZXDH_HMC_IW_TXWINDOW].base = param->txwindow_hmc_base;
	dev->hmc_info->hmc_obj[ZXDH_HMC_IW_IRD].base = param->ird_hmc_base;
	dev->hmc_info->hmc_obj[ZXDH_HMC_IW_AH].base = param->ah_hmc_base;
	dev->hmc_info->hmc_obj[ZXDH_HMC_IW_MR].base = param->mr_hmc_base;
	dev->hmc_info->hmc_obj[ZXDH_HMC_IW_PBLE].base = param->pbleq_hmc_base;
	dev->hmc_info->hmc_obj[ZXDH_HMC_IW_PBLE_MR].base = param->pblem_hmc_base;

	dev->hmc_info->hmc_obj[ZXDH_HMC_IW_QP].cnt = param->qp_cnt;
	dev->hmc_info->hmc_obj[ZXDH_HMC_IW_CQ].cnt = param->cq_cnt;
	dev->hmc_info->hmc_obj[ZXDH_HMC_IW_SRQ].cnt = param->srq_cnt;
	dev->hmc_info->hmc_obj[ZXDH_HMC_IW_AH].cnt = param->ah_cnt;
	dev->hmc_info->hmc_obj[ZXDH_HMC_IW_MR].cnt = param->mr_cnt;
	if (rf->sc_dev.ep_id != ZXDH_ZF_EPID || dev->hmc_use_dpu_ddr) {
		dev->data_cap_sd.data_cap_base = C_HMC_DATA_CAP_IOVA_BASE;
		dev->data_cap_sd.data_len = C_HMC_DATA_CAP_IOVA_LEN;
	}

	if (!rf->ftype) {
		dev->hmc_pf_manager_info.total_qp_cnt =
			param->qp_cnt + param->max_vf_num * param->vf_qp_cnt;
		dev->hmc_pf_manager_info.total_cq_cnt =
			param->cq_cnt + param->max_vf_num * param->vf_cq_cnt;
		dev->hmc_pf_manager_info.total_srq_cnt =
			param->srq_cnt + param->max_vf_num * param->vf_srq_cnt;
		dev->hmc_pf_manager_info.total_ah_cnt =
			param->ah_cnt + param->max_vf_num * param->vf_ah_cnt;
		dev->hmc_pf_manager_info.total_mrte_cnt =
			param->mr_cnt + param->max_vf_num * param->vf_mr_cnt;

		dev->hmc_pf_manager_info.pf_pblemr_cnt = param->pblem_cnt;
		dev->hmc_pf_manager_info.pf_pblequeue_cnt = param->pbleq_cnt;

		dev->hmc_pf_manager_info.vf_qp_cnt = param->vf_qp_cnt;
		dev->hmc_pf_manager_info.vf_pblemr_cnt = param->vf_pblem_cnt;
		dev->hmc_pf_manager_info.vf_pblequeue_cnt = param->vf_pbleq_cnt;
	}
	return 0;
}

static void zxdh_init_hw_bar_pages(u8 ep_id, u64 *base_bar_offset)
{
	int i;
	u64 page_bar_offset;
	u64 bar_offset_low;
	u64 bar_offset_high;

	if (ep_id == ZXDH_ZF_EPID) {
		page_bar_offset = *base_bar_offset;
		bar_offset_low = page_bar_offset & 0xFFFF;
		bar_offset_high = page_bar_offset & 0xF0000;
		*base_bar_offset = bar_offset_low + (bar_offset_high << 4);
	} else
		page_bar_offset = 0;

	for (i = 0; i < C_RDMA_HW_BAR_PAGE_NUM; i++) {
		if (ep_id == ZXDH_ZF_EPID) {
			bar_offset_low = page_bar_offset & 0xFFFF;
			bar_offset_high = page_bar_offset & 0xF0000;
			zxdh_hw_bar_pages[i] = bar_offset_low + (bar_offset_high << 4);
			zxdh_hw_bar_pages[i] -= *base_bar_offset;
		} else
			zxdh_hw_bar_pages[i] = page_bar_offset;

		page_bar_offset += C_RDMA_HW_BAR_PAGE_SIZE;
	}
}

static int zxdh_pf_dev_exist_for_vf(struct zxdh_pci_f *rf)
{
	u64 cqp_status_phy_addr = 0;
	u32 cqp_status = 0xFFFF;
	int ret = 0;

	if (rf->ftype == 1) {
		cqp_status_phy_addr = C_RDMA_CQP_STATUS_PHY_ADDR + rf->sc_dev.vhca_id_pf * 0x1000;
		ret = zxdh_rdma_reg_read(rf, cqp_status_phy_addr, &cqp_status);
		if (ret) {
			pr_err("%s[%d]: rdma reg read failed!\n", __func__, __LINE__);
			return ret;
		}

		pr_info("vf rdma probe: ep_id=%d, pf_id=%d, vf_id=%d, vhca_id=%d, vhca_id_pf=%d, cqp_status=%d\n",
			rf->ep_id, rf->pf_id, rf->vf_id, rf->sc_dev.vhca_id, rf->sc_dev.vhca_id_pf,
			cqp_status);
		if (cqp_status != 1) {
			pr_err("vf rdma probe: The RDMA device for EP%d PF%d corresponding to VF%d does not exist!\n",
			       rf->ep_id, rf->pf_id, rf->vf_id);
			return -ENODEV;
		}
	}

	return 0;
}

int zxdh_manager_init(struct zxdh_pci_f *rf, struct iidc_core_dev_info *cdev_info)
{
	int ret = 0;
	struct zxdh_mgr *dh_mgr = kzalloc(sizeof(struct zxdh_mgr), GFP_KERNEL);

	if (!dh_mgr)
		return -ENOMEM;

	dh_mgr->pdev = cdev_info->pdev;
	dh_mgr->pf_id = rf->pf_id;
	dh_mgr->vport_vf_id = (cdev_info->vport_id) & 0xFF;
	dh_mgr->ftype = rf->ftype;
	dh_mgr->ep_id = rf->sc_dev.ep_id;

	dh_mgr->device_id = cdev_info->pdev->subsystem_device;
	dh_mgr->pci_hw_addr = cdev_info->hw_addr;

	ret = zxdh_mgr_par_get(dh_mgr);
	if (ret != 0) {
		kfree(dh_mgr);
		pr_info("dh_rdma_mgr_par_get faile.\n");
		return ret;
	}

	pr_info("manager pcie_id=0x%x, device_id=0x%x, slot_id=0x%x\n", dh_mgr->pcie_id,
		dh_mgr->device_id, cdev_info->slot_id);
	rf->pcie_id = dh_mgr->pcie_id;
	rf->vf_id = dh_mgr->param.vf_id;
	rf->sc_dev.vf_id = dh_mgr->param.vf_id;
	rf->sc_dev.vhca_id = dh_mgr->param.vhca_id;
	rf->sc_dev.vhca_id_pf = dh_mgr->param.vhca_id_pf;
	if (rf->sc_dev.vhca_id == 1023) {
		kfree(dh_mgr);
		pr_info("vhca_id:1023 invalid\n");
		return -1;
	}

	ret = zxdh_pf_dev_exist_for_vf(rf);
	if (ret != 0) {
		kfree(dh_mgr);
		return -1;
	}

	rf->sc_dev.hmc_fn_id = dh_mgr->param.hmc_sid;
	rf->sc_dev.total_vhca = dh_mgr->param.dh_total_vhca;
	rf->sc_dev.np_mode_low_lat = dh_mgr->param.np_mode_low_lat;
	rf->sc_dev.chip_version = dh_mgr->param.chip_version;

	rf->sc_dev.nof_ioq_ddr_addr = dh_mgr->param.nof_ioq_ddr_addr;
	rf->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags = dh_mgr->param.max_hw_wq_frags;
	rf->sc_dev.hw_attrs.uk_attrs.max_hw_read_sges = dh_mgr->param.max_hw_read_sges;
	//VHCA_RC_UD_GQP_MAX_CNT
	rf->sc_dev.vhca_gqp_start = dh_mgr->param.vhca_gqp_start;
	rf->sc_dev.vhca_gqp_cnt = dh_mgr->param.vhca_gqp_cnt;
	rf->sc_dev.vhca_8k_index_start = dh_mgr->param.vhca_8k_index_start;
	//VHCA_RC_UD_8K_MAX_CNT
	rf->sc_dev.vhca_8k_index_cnt = dh_mgr->param.vhca_8k_index_cnt;
	rf->sc_dev.vhca_ud_gqp = dh_mgr->param.vhca_ud_gqp;
	rf->sc_dev.vhca_ud_8k_index = dh_mgr->param.vhca_ud_8k_index;

	pr_info("vhca_gqp_start:0x%x\n", rf->sc_dev.vhca_gqp_start);
	pr_info("vhca_gqp_cnt:0x%x\n", rf->sc_dev.vhca_gqp_cnt);
	pr_info("vhca_8k_index_start:0x%x\n", rf->sc_dev.vhca_8k_index_start);
	pr_info("vhca_8k_index_cnt:0x%x\n", rf->sc_dev.vhca_8k_index_cnt);
	pr_info("vhca_ud_gqp:0x%x\n", rf->sc_dev.vhca_ud_gqp);
	pr_info("vhca_ud_8k_index:0x%x\n", rf->sc_dev.vhca_ud_8k_index);

	rf->base_bar_offset = dh_mgr->param.bar_offset;
	zxdh_init_hw_bar_pages(rf->sc_dev.ep_id, &rf->base_bar_offset);
	rf->hw.hw_addr = cdev_info->hw_addr + rf->base_bar_offset;
	pr_info("rf->hw.hw_addr=0x%llx, cdev_info->hw_addr=0x%llx, rf->base_bar_offset=0x%llx\n",
		(u64)(uintptr_t)rf->hw.hw_addr, (u64)(uintptr_t)cdev_info->hw_addr,
		rf->base_bar_offset);

	ret = zxdh_sc_init_hmccnt(rf, &dh_mgr->param);
	if (ret != 0) {
		kfree(dh_mgr);
		pr_info("init_hmccnt faile.\n");
		return ret;
	}

	rf->sc_dev.max_ceqs = dh_mgr->param.ceq_cnt;
	rf->sc_dev.base_ceqn = dh_mgr->param.base_ceqn;

	rf->msix_count = min(rf->msix_count, (rf->sc_dev.max_ceqs + 1));
	if (rf->msix_count > 1)
		rf->sc_dev.max_ceqs = (rf->msix_count - 1);
	else
		rf->sc_dev.max_ceqs = rf->msix_count;
	if (rf->msix_count == 0) {
		kfree(dh_mgr);
		pr_info("misx_count is 0\n");
		return -EINVAL;
	}
	rf->mcode_type = dh_mgr->param.mcode_type;
	kfree(dh_mgr);

	return 0;
}

/***
 * @brief send general rdma message to firmware
 *
 * @param rf
 * @param para includes infos of buffers to send and receive
 * @return int
 * @retval 0 on success
 * @retval -EINVAL when input arguments are invalid
 * @retval -ENOMEM when alloc buffer fails
 * @retval -EPROTO when bar message send/recv fails
 */
int rdma_chan_msg_send(struct zxdh_pci_f *rf, struct rdma_chan_msg_para *para)
{
	int ret = 0;
	u8 *rep_ptr;
	u16 rep_len = 0;
	u8 rep_valid = 0;
	size_t recv_len = 0;
	void *recv_buffer = NULL;

	struct zxdh_mgr mgr = { 0 };
	struct zxdh_pci_bar_msg in = { 0 };
	struct zxdh_msg_recviver_mem result = { 0 };
	struct iidc_core_dev_info *cdev_info = NULL;
	u32 cnt = 0;
	u32 cnt_num = ZXDH_BAR_MSG_RETRY_NUM;

	if (!para || !rf)
		return -EINVAL;
	if (rf->sc_dev.driver_load == false)
		cnt_num = ZXDH_BAR_MSG_DEFAULT_NUM;

	if (!(para->in_buf) || !(para->out_buf))
		return -EINVAL;

	cdev_info = (struct iidc_core_dev_info *)rf->cdev;

	// query pcie id
	mgr.pdev = cdev_info->pdev;
	ret = dh_rdma_pf_pcie_id_get(&mgr);
	if (ret) {
		pr_err("[%s] get pf pcie_id failed, ret=%d\n", __func__, ret);
		return -EINVAL;
	}

	// malloc recv buffer with extra ZXDH_CHAN_REPS_LEN size
	recv_len = ZXDH_CHAN_REPS_LEN + para->out_size;
	recv_buffer = kzalloc(recv_len, GFP_KERNEL);
	if (!recv_buffer)
		return -ENOMEM;

	// get message preparation
	in.payload_addr = (void *)para->in_buf;
	in.payload_len = para->in_size;

	in.src = rf->ftype == 0 ? MSG_CHAN_END_PF : MSG_CHAN_END_VF;
	in.dst = MSG_CHAN_END_RISC;
	in.event_id = MODULE_RDMA;
	in.virt_addr = (u64)(cdev_info->hw_addr) + ZXDH_BAR_CHAN_OFFSET;
	in.src_pcieid = mgr.pcie_id;

	// resv buffer preparation
	result.recv_buffer = recv_buffer;
	result.buffer_len = recv_len;

	do {
		ret = zxdh_bar_chan_sync_msg_send(&in, &result);
		if ((ret != ZXDH_BAR_ERR_TIME_OUT) && (ret != ZXDH_BAR_ERR_LOCK_FAILED))
			break;

		cnt++;
	} while (cnt < cnt_num);

	if (ret) {
		pr_err("[%s] message send failed, ret=%d cnt=%d\n", __func__, ret, cnt);
		kfree(recv_buffer);
		return -EPROTO;
	}

	rep_ptr = (u8 *)recv_buffer;
	rep_valid = *rep_ptr;
	if (rep_valid != MSG_REP_VALID) {
		pr_err("[%s] response message invalid, rep_valid=0x%x\n", __func__, rep_valid);
		kfree(recv_buffer);
		return -EPROTO;
	}

	rep_len = *(u16 *)(rep_ptr + MSG_REP_LEN_OFFSET);
	if (rep_len != para->out_size) {
		pr_err("[%s] response length invalid, rep_len=0x%x\n", __func__, rep_len);
		kfree(recv_buffer);
		return -EPROTO;
	}

	memcpy(para->out_buf, rep_ptr + ZXDH_CHAN_REPS_LEN, rep_len);
	kfree(recv_buffer);
	return 0;
}

/***
 * @brief read register value from rdma
 *
 * @param rf for accessing hardware info
 * @param phy_addr physical address on rdma. registuer width is u32
 * @param outdata
 * @return int
 *      - 0: ok
 *      - -1: failed
 */
int zxdh_rdma_reg_read(struct zxdh_pci_f *rf, u64 phy_addr, u32 *outdata)
{
	int ret = 0;
	u8 rep_valid = 0;
	u16 rep_len = 0;
	u8 *rep_ptr;
	struct zxdh_pci_bar_msg in = { 0 };
	struct zxdh_msg_recviver_mem result = { 0 };
	struct zxdh_mgr mgr = { 0 };
	struct iidc_core_dev_info *cdev_info;
	struct zxdh_reg_read_cmd *read_cmd;
	size_t recv_len;
	void *recv_buffer;
	struct dh_rdma_reg_read_resp *read_resp;
	u32 cnt = 0;
	u32 cnt_num = ZXDH_BAR_MSG_RETRY_NUM;

	if (!rf || !outdata)
		return -EINVAL;
	if (rf->sc_dev.driver_load == false)
		cnt_num = ZXDH_BAR_MSG_DEFAULT_NUM;

	cdev_info = (struct iidc_core_dev_info *)rf->cdev;
	// query pcie id
	mgr.pdev = cdev_info->pdev;
	ret = dh_rdma_pf_pcie_id_get(&mgr);
	if (ret) {
		pr_err("[%s] get pf pcie_id failed, ret=%d\n", __func__, ret);
		return -EINVAL;
	}

	read_cmd = kzalloc(sizeof(struct zxdh_reg_read_cmd), GFP_KERNEL);
	if (!read_cmd)
		return -ENOMEM;

	recv_len =
		ZXDH_CHAN_REPS_LEN + sizeof(struct dh_rdma_reg_read_resp) + 1 * sizeof(u32); // data
	recv_buffer = kzalloc(recv_len, GFP_KERNEL);
	if (!recv_buffer) {
		kfree(read_cmd);
		return -ENOMEM;
	}

	// commnad preparation
	read_cmd->op_code = RDMA_REG_READ;
	read_cmd->req.phy_addr = phy_addr;
	read_cmd->req.reg_num = 1;

	// send message preparation
	in.payload_addr = (void *)read_cmd;
	in.payload_len = sizeof(struct zxdh_reg_read_cmd);
	in.src = rf->ftype == 0 ? MSG_CHAN_END_PF : MSG_CHAN_END_VF;
	in.dst = MSG_CHAN_END_RISC;
	in.event_id = MODULE_RDMA;
	in.virt_addr = (u64)(uintptr_t)cdev_info->hw_addr + ZXDH_BAR_CHAN_OFFSET;
	in.src_pcieid = mgr.pcie_id;

	// resv buffer preparation
	result.recv_buffer = recv_buffer;
	result.buffer_len = recv_len;

	do {
		ret = zxdh_bar_chan_sync_msg_send(&in, &result);
		if ((ret != ZXDH_BAR_ERR_TIME_OUT) && (ret != ZXDH_BAR_ERR_LOCK_FAILED))
			break;

		cnt++;
	} while (cnt < cnt_num);

	kfree(read_cmd);

	if (ret) {
		pr_err("[%s] message send failed, ret=%d\n", __func__, ret);
		kfree(recv_buffer);
		return -EPROTO;
	}

	rep_ptr = (u8 *)recv_buffer;
	rep_valid = *rep_ptr;
	if (rep_valid != MSG_REP_VALID) {
		pr_err("[%s] response message invalid, rep_valid=0x%x\n", __func__, rep_valid);
		kfree(recv_buffer);
		return -EPROTO;
	}

	rep_len = *(u16 *)(rep_ptr + MSG_REP_LEN_OFFSET);
	if (rep_len != recv_len - ZXDH_CHAN_REPS_LEN) {
		pr_err("[%s] response length invalid, rep_len=0x%x\n", __func__, rep_len);
		kfree(recv_buffer);
		return -EPROTO;
	}

	read_resp = (struct dh_rdma_reg_read_resp *)(rep_ptr + ZXDH_CHAN_REPS_LEN);
	if (read_resp->status_code != 200) {
		pr_err("[%s] response status invalid, statuc_code=0x%x\n", __func__,
		       read_resp->status_code);
		kfree(recv_buffer);
		return -EPROTO;
	}

	*outdata = read_resp->data[0];

	kfree(recv_buffer);
	return 0;
}

int zxdh_rdma_regs_read(struct zxdh_pci_f *rf, u64 phy_addr, u32 *outdata, u32 num)
{
	int ret = 0;
	u8 rep_valid = 0;
	u16 rep_len = 0;
	u8 *rep_ptr;
	struct zxdh_pci_bar_msg in = { 0 };
	struct zxdh_msg_recviver_mem result = { 0 };
	struct zxdh_mgr mgr = { 0 };
	struct iidc_core_dev_info *cdev_info;
	struct zxdh_reg_read_cmd *read_cmd;
	size_t recv_len;
	void *recv_buffer;
	struct dh_rdma_reg_read_resp *read_resp;
	u32 cnt = 0;
	u32 cnt_num = ZXDH_BAR_MSG_RETRY_NUM;

	if (!rf || !outdata)
		return -EINVAL;
	if (rf->sc_dev.driver_load == false)
		cnt_num = ZXDH_BAR_MSG_DEFAULT_NUM;

	cdev_info = (struct iidc_core_dev_info *)rf->cdev;
	// query pcie id
	mgr.pdev = cdev_info->pdev;
	ret = dh_rdma_pf_pcie_id_get(&mgr);
	if (ret) {
		pr_err("[%s] get pf pcie_id failed, ret=%d\n", __func__, ret);
		return -EINVAL;
	}

	read_cmd = kzalloc(sizeof(struct zxdh_reg_read_cmd), GFP_KERNEL);
	if (!read_cmd)
		return -ENOMEM;

	recv_len = ZXDH_CHAN_REPS_LEN + sizeof(struct dh_rdma_reg_read_resp) +
		   num * sizeof(u32); // data
	recv_buffer = kzalloc(recv_len, GFP_KERNEL);
	if (!recv_buffer) {
		kfree(read_cmd);
		return -ENOMEM;
	}

	// commnad preparation
	read_cmd->op_code = RDMA_REG_READ;
	read_cmd->req.phy_addr = phy_addr;
	read_cmd->req.reg_num = num;

	// send message preparation
	in.payload_addr = (void *)read_cmd;
	in.payload_len = sizeof(struct zxdh_reg_read_cmd);
	in.src = rf->ftype == 0 ? MSG_CHAN_END_PF : MSG_CHAN_END_VF;
	in.dst = MSG_CHAN_END_RISC;
	in.event_id = MODULE_RDMA;
	in.virt_addr = (u64)(uintptr_t)cdev_info->hw_addr + ZXDH_BAR_CHAN_OFFSET;
	in.src_pcieid = mgr.pcie_id;

	// resv buffer preparation
	result.recv_buffer = recv_buffer;
	result.buffer_len = recv_len;

	do {
		ret = zxdh_bar_chan_sync_msg_send(&in, &result);
		if ((ret != ZXDH_BAR_ERR_TIME_OUT) && (ret != ZXDH_BAR_ERR_LOCK_FAILED))
			break;

		cnt++;
	} while (cnt < cnt_num);

	kfree(read_cmd);

	if (ret) {
		pr_err("[%s] message send failed, ret=%d cnt=%d\n", __func__, ret, cnt);
		kfree(recv_buffer);
		return -EPROTO;
	}

	rep_ptr = (u8 *)recv_buffer;
	rep_valid = *rep_ptr;
	if (rep_valid != MSG_REP_VALID) {
		pr_err("[%s] response message invalid, rep_valid=0x%x\n", __func__, rep_valid);
		kfree(recv_buffer);
		return -EPROTO;
	}

	rep_len = *(u16 *)(rep_ptr + MSG_REP_LEN_OFFSET);
	if (rep_len != recv_len - ZXDH_CHAN_REPS_LEN) {
		pr_err("[%s] response length invalid, rep_len=0x%x\n", __func__, rep_len);
		kfree(recv_buffer);
		return -EPROTO;
	}

	read_resp = (struct dh_rdma_reg_read_resp *)(rep_ptr + ZXDH_CHAN_REPS_LEN);
	if (read_resp->status_code != 200) {
		pr_err("[%s] response status invalid, statuc_code=0x%x\n", __func__,
		       read_resp->status_code);
		kfree(recv_buffer);
		return -EPROTO;
	}

	memcpy(outdata, read_resp->data, num * sizeof(u32));

	kfree(recv_buffer);
	return 0;
}

int zxdh_rdma_reg_write(struct zxdh_pci_f *rf, u64 phy_addr, u32 val)
{
	int ret = 0;
	u8 rep_valid = 0;
	u16 rep_len = 0;
	u8 *rep_ptr;
	struct zxdh_pci_bar_msg in = { 0 };
	struct zxdh_msg_recviver_mem result = { 0 };
	struct zxdh_mgr mgr = { 0 };
	struct iidc_core_dev_info *cdev_info;
	size_t write_cmd_len;
	size_t recv_len;
	void *recv_buffer;
	struct zxdh_reg_write_cmd *write_cmd;
	struct dh_rdma_reg_write_resp *write_resp;
	u32 cnt = 0;
	u32 cnt_num = ZXDH_BAR_MSG_RETRY_NUM;

	if (!rf)
		return -EINVAL;
	if (rf->sc_dev.driver_load == false)
		cnt_num = ZXDH_BAR_MSG_DEFAULT_NUM;

	cdev_info = (struct iidc_core_dev_info *)rf->cdev;
	// query pcie id
	mgr.pdev = cdev_info->pdev;
	ret = dh_rdma_pf_pcie_id_get(&mgr);
	if (ret) {
		pr_err("[%s] get pf pcie_id failed, ret=%d\n", __func__, ret);
		return -EINVAL;
	}

	write_cmd_len = sizeof(struct zxdh_reg_write_cmd) + 1 * sizeof(u32);
	write_cmd = kzalloc(write_cmd_len, GFP_KERNEL);
	if (!write_cmd)
		return -ENOMEM;

	recv_len = ZXDH_CHAN_REPS_LEN + sizeof(struct dh_rdma_reg_write_resp);
	recv_buffer = kzalloc(recv_len, GFP_KERNEL);
	if (!recv_buffer) {
		kfree(write_cmd);
		return -ENOMEM;
	}

	// commnad preparation
	write_cmd->op_code = RDMA_REG_WRITE;
	write_cmd->req.phy_addr = phy_addr;
	write_cmd->req.reg_num = 1;
	write_cmd->req.data[0] = val;

	// send message preparation
	in.payload_addr = (void *)write_cmd;
	in.payload_len = write_cmd_len;
	in.src = rf->ftype == 0 ? MSG_CHAN_END_PF : MSG_CHAN_END_VF;
	in.dst = MSG_CHAN_END_RISC;
	in.event_id = MODULE_RDMA;
	in.virt_addr = (u64)(uintptr_t)cdev_info->hw_addr + ZXDH_BAR_CHAN_OFFSET;
	in.src_pcieid = mgr.pcie_id;

	// resv buffer preparation
	result.recv_buffer = recv_buffer;
	result.buffer_len = recv_len;

	do {
		ret = zxdh_bar_chan_sync_msg_send(&in, &result);
		if ((ret != ZXDH_BAR_ERR_TIME_OUT) && (ret != ZXDH_BAR_ERR_LOCK_FAILED))
			break;

		cnt++;
		pr_info("[%s] cnt:%d ret:%d\n", __func__, cnt, ret);
	} while (cnt < cnt_num);

	kfree(write_cmd);

	if (ret) {
		pr_err("[%s] message send failed, ret=%d cnt=%d\n", __func__, ret, cnt);
		kfree(recv_buffer);
		return -EPROTO;
	}

	rep_ptr = (u8 *)recv_buffer;
	rep_valid = *rep_ptr;
	if (rep_valid != MSG_REP_VALID) {
		pr_err("[%s] response message invalid, rep_valid=0x%x\n", __func__, rep_valid);
		kfree(recv_buffer);
		return -EPROTO;
	}

	rep_len = *(u16 *)(rep_ptr + MSG_REP_LEN_OFFSET);
	if (rep_len != recv_len - ZXDH_CHAN_REPS_LEN) {
		pr_err("[%s] response length invalid, rep_len=0x%x\n", __func__, rep_len);
		kfree(recv_buffer);
		return -EPROTO;
	}

	write_resp = (struct dh_rdma_reg_write_resp *)(rep_ptr + ZXDH_CHAN_REPS_LEN);
	if (write_resp->status_code != 200) {
		pr_err("[%s] response status invalid, statuc_code=0x%x\n", __func__,
		       write_resp->status_code);
		kfree(recv_buffer);
		return -EPROTO;
	}

	kfree(recv_buffer);
	return 0;
}

int zxdh_mp_dtcm_para_get(struct zxdh_pci_f *rf, u16 mcode_type, u16 para_id, u32 *outdata)
{
	int ret = 0;
	u8 rep_valid = 0;
	u16 rep_len = 0;
	u8 *rep_ptr;
	struct zxdh_mgr mgr = { 0 };
	struct zxdh_pci_bar_msg in = { 0 };
	struct zxdh_msg_recviver_mem result = { 0 };
	struct zxdh_mp_dtcm_para_get_cmd get_cmd = { 0 };
	struct iidc_core_dev_info *cdev_info;
	size_t recv_len;
	void *recv_buffer;
	struct dh_mp_dtcm_para_get_resp *get_resp;
	u32 cnt = 0;
	u32 cnt_num = ZXDH_BAR_MSG_RETRY_NUM;

	if (!rf || !outdata)
		return -EINVAL;
	if (rf->sc_dev.driver_load == false)
		cnt_num = ZXDH_BAR_MSG_DEFAULT_NUM;

	cdev_info = (struct iidc_core_dev_info *)rf->cdev;
	// query pcie id
	mgr.pdev = cdev_info->pdev;
	ret = dh_rdma_pf_pcie_id_get(&mgr);
	if (ret) {
		pr_err("[%s] get pf pcie_id failed, ret=%d\n", __func__, ret);
		return -EINVAL;
	}

	recv_len = ZXDH_CHAN_REPS_LEN + sizeof(struct dh_mp_dtcm_para_get_resp);
	recv_buffer = kzalloc(recv_len, GFP_KERNEL);
	if (!recv_buffer)
		return -ENOMEM;

	// commnad preparation
	get_cmd.op_code = RDMA_MP_DTCM_PARA_GET;
	get_cmd.req.mcode_type = mcode_type;
	get_cmd.req.para_id = para_id;

	// get message preparation
	in.payload_addr = (void *)&get_cmd;
	in.payload_len = sizeof(struct zxdh_mp_dtcm_para_get_cmd);
	in.src = rf->ftype == 0 ? MSG_CHAN_END_PF : MSG_CHAN_END_VF;
	in.dst = MSG_CHAN_END_RISC;
	in.event_id = MODULE_RDMA;
	in.virt_addr = (u64)(uintptr_t)cdev_info->hw_addr + ZXDH_BAR_CHAN_OFFSET;
	in.src_pcieid = mgr.pcie_id;

	// resv buffer preparation
	result.recv_buffer = recv_buffer;
	result.buffer_len = recv_len;

	do {
		ret = zxdh_bar_chan_sync_msg_send(&in, &result);
		if ((ret != ZXDH_BAR_ERR_TIME_OUT) && (ret != ZXDH_BAR_ERR_LOCK_FAILED))
			break;

		cnt++;
	} while (cnt < cnt_num);

	if (ret) {
		pr_err("[%s] message send failed, ret=%d cnt=%d\n", __func__, ret, cnt);
		kfree(recv_buffer);
		return -EPROTO;
	}

	rep_ptr = (u8 *)recv_buffer;
	rep_valid = *rep_ptr;
	if (rep_valid != MSG_REP_VALID) {
		pr_err("[%s] response message invalid, rep_valid=0x%x\n", __func__, rep_valid);
		kfree(recv_buffer);
		return -EPROTO;
	}

	rep_len = *(u16 *)(rep_ptr + MSG_REP_LEN_OFFSET);
	if (rep_len != recv_len - ZXDH_CHAN_REPS_LEN) {
		pr_err("[%s] response length invalid, rep_len=0x%x\n", __func__, rep_len);
		kfree(recv_buffer);
		return -EPROTO;
	}

	get_resp = (struct dh_mp_dtcm_para_get_resp *)(rep_ptr + ZXDH_CHAN_REPS_LEN);
	if (get_resp->status_code != 200) {
		pr_err("[%s] response status invalid, statuc_code=0x%x\n", __func__,
		       get_resp->status_code);
		kfree(recv_buffer);
		return -EPROTO;
	}

	pr_info("resp: para_id=%d val=%d\n", get_resp->para_id, get_resp->val);

	*outdata = get_resp->val;
	kfree(recv_buffer);
	return 0;
}

int zxdh_mp_dtcm_para_set(struct zxdh_pci_f *rf, u16 mcode_type, u16 para_id, u32 val)
{
	int ret = 0;
	u8 rep_valid = 0;
	u16 rep_len = 0;
	u8 *rep_ptr;
	struct zxdh_mgr mgr = { 0 };
	struct zxdh_pci_bar_msg in = { 0 };
	struct zxdh_msg_recviver_mem result = { 0 };
	struct zxdh_mp_dtcm_para_set_cmd set_cmd = { 0 };
	struct iidc_core_dev_info *cdev_info;
	size_t recv_len;
	void *recv_buffer;
	struct dh_mp_dtcm_para_set_resp *set_resp;
	u32 cnt = 0;
	u32 cnt_num = ZXDH_BAR_MSG_RETRY_NUM;

	if (!rf)
		return -EINVAL;
	if (rf->sc_dev.driver_load == false)
		cnt_num = ZXDH_BAR_MSG_DEFAULT_NUM;

	cdev_info = (struct iidc_core_dev_info *)rf->cdev;
	// query pcie id
	mgr.pdev = cdev_info->pdev;
	ret = dh_rdma_pf_pcie_id_get(&mgr);
	if (ret) {
		pr_err("[%s] get pf pcie_id failed, ret=%d\n", __func__, ret);
		return -EINVAL;
	}

	recv_len = ZXDH_CHAN_REPS_LEN + sizeof(struct dh_mp_dtcm_para_set_resp);
	recv_buffer = kzalloc(recv_len, GFP_KERNEL);
	if (!recv_buffer)
		return -ENOMEM;

	// commnad preparation
	set_cmd.op_code = RDMA_MP_DTCM_PARA_SET;
	set_cmd.req.mcode_type = mcode_type;
	set_cmd.req.para_id = para_id;
	set_cmd.req.val = val;

	// get message preparation
	in.payload_addr = (void *)&set_cmd;
	in.payload_len = sizeof(struct zxdh_mp_dtcm_para_set_cmd);
	in.src = rf->ftype == 0 ? MSG_CHAN_END_PF : MSG_CHAN_END_VF;
	in.dst = MSG_CHAN_END_RISC;
	in.event_id = MODULE_RDMA;
	in.virt_addr = (u64)(uintptr_t)cdev_info->hw_addr + ZXDH_BAR_CHAN_OFFSET;
	in.src_pcieid = mgr.pcie_id;

	// resv buffer preparation
	result.recv_buffer = recv_buffer;
	result.buffer_len = recv_len;

	do {
		ret = zxdh_bar_chan_sync_msg_send(&in, &result);
		if ((ret != ZXDH_BAR_ERR_TIME_OUT) && (ret != ZXDH_BAR_ERR_LOCK_FAILED))
			break;

		cnt++;
	} while (cnt < cnt_num);
	if (ret) {
		pr_err("[%s] message send failed, ret=%d cnt=%d\n", __func__, ret, cnt);
		kfree(recv_buffer);
		return -EPROTO;
	}

	rep_ptr = (u8 *)recv_buffer;
	rep_valid = *rep_ptr;
	if (rep_valid != MSG_REP_VALID) {
		pr_err("[%s] response message invalid, rep_valid=0x%x\n", __func__, rep_valid);
		kfree(recv_buffer);
		return -EPROTO;
	}

	rep_len = *(u16 *)(rep_ptr + MSG_REP_LEN_OFFSET);
	if (rep_len != recv_len - ZXDH_CHAN_REPS_LEN) {
		pr_err("[%s] response length invalid, rep_len=0x%x\n", __func__, rep_len);
		kfree(recv_buffer);
		return -EPROTO;
	}

	set_resp = (struct dh_mp_dtcm_para_set_resp *)(rep_ptr + ZXDH_CHAN_REPS_LEN);
	if (set_resp->status_code != 200) {
		pr_err("[%s] response status invalid, statuc_code=0x%x\n", __func__,
		       set_resp->status_code);
		kfree(recv_buffer);
		return -EPROTO;
	}

	pr_info("resp: para_id=%d\n", para_id);
	kfree(recv_buffer);

	return 0;
}

static void clean_bond_old_gid(struct ib_device *ibdev, struct net_device *primary_netdev)
{
	struct ib_port_attr attr;
	const struct ib_gid_attr *gid_attr;
	struct net_device *ndev;
	int err;
	int i;

	err = ib_query_port(ibdev, 1, &attr);
	if (err)
		return;

	for (i = 0; i < attr.gid_tbl_len; i++) {
		gid_attr = rdma_get_gid_attr(ibdev, 1, i);
		if (IS_ERR(gid_attr))
			continue;
#ifndef IB_READ_GID_ATTRIBUTE_NETDEVICE_NOT_DEFINE
		rcu_read_lock();
		ndev = rdma_read_gid_attr_ndev_rcu(gid_attr);
		if (IS_ERR(ndev)) {
			rcu_read_unlock();
			continue;
		}
		rcu_read_unlock();
#else
		ndev = gid_attr->ndev;
#endif

		if (ndev != NULL && ndev == primary_netdev) {
			pr_info("%s clean ndev=%s primary_netdev=%s i=%d subnet_prefix=0x%llx gids:\n",
				__func__, ndev->name, primary_netdev->name, i,
				gid_attr->gid.global.subnet_prefix);
			pr_info("%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x\n",
				gid_attr->gid.raw[0], gid_attr->gid.raw[1], gid_attr->gid.raw[2],
				gid_attr->gid.raw[3], gid_attr->gid.raw[4], gid_attr->gid.raw[5],
				gid_attr->gid.raw[6], gid_attr->gid.raw[7], gid_attr->gid.raw[8],
				gid_attr->gid.raw[9], gid_attr->gid.raw[10], gid_attr->gid.raw[11],
				gid_attr->gid.raw[12], gid_attr->gid.raw[13], gid_attr->gid.raw[14],
				gid_attr->gid.raw[15]);
			rdma_put_gid_attr(gid_attr);
		} else if (ndev != NULL && primary_netdev != NULL) {
			pr_info("[%s] ndev name=%s primary_netdev name=%s i=%d", __func__,
				ndev->name, primary_netdev->name, i);
		}
		rdma_put_gid_attr(gid_attr);
	}
}

int32_t switch_bound_master_netdev(struct net_device *primary_netdev,
				   struct net_device *linux_bond_netdev, bool hb_enable)
{
	struct zxdh_device *iwdev = NULL;
	struct ib_device *ibdev;
	struct zxdh_pci_f *rf;
	struct net_device *old_netdev;
	struct net_device *new_netdev;
	int ret;

	if (!primary_netdev || !linux_bond_netdev) {
		pr_err("[rdma_bond] primary_netdev or linux_bond_netdev is NULL.\n");
		return -1;
	}

	pr_info("[rdma_bond] primary:%s bond:%s hb_enable:%d\n", primary_netdev->name,
		linux_bond_netdev->name, hb_enable);

	if (hb_enable) {
		old_netdev = primary_netdev;
		new_netdev = linux_bond_netdev;
	} else {
		old_netdev = linux_bond_netdev;
		new_netdev = primary_netdev;
	}

	ibdev = ib_device_get_by_netdev(old_netdev, RDMA_DRIVER_ZXDH);
	if (!ibdev) {
		pr_err("[rdma_bond] get ib device by netdev failed.\n");
		return -1;
	}
	iwdev = to_iwdev(ibdev);
	if (!iwdev) {
		pr_err("[rdma_bond] ibdev to iwdev failed.\n");
		ib_device_put(ibdev);
		return -1;
	}
	clean_bond_old_gid(ibdev, old_netdev);

	rf = iwdev->rf;
	if (!rf) {
		pr_err("[rdma_bond] rf is NULL\n");
		ib_device_put(ibdev);
		return -1;
	}

	if (rf->sc_dev.hw_attrs.self_health == true) {
		pr_err("[rdma_bond] self_health is true\n");
		ib_device_put(ibdev);
		return -1;
	}

	pr_info("[rdma_bond] %s ==> %s\n", old_netdev->name, new_netdev->name);
	pr_info("[rdma_bond] NETDEV_TO_IBDEV_SUPPORT is defined\n");
	ret = ib_device_set_netdev(ibdev, new_netdev, 1);
	if (ret) {
		pr_err("[rdma_bond] ib device set netdev error, ret=%d\n", ret);
		ib_device_put(ibdev);
		return -1;
	}
	iwdev->netdev = new_netdev;
	rdma_roce_rescan_device(ibdev);

	zxdh_update_dpp_mac_tbl(iwdev, iwdev->rf->cdev);
	pr_info("[rdma_bond] update dpp mac tbl\n");
	create_debugfs_default_entry(rf, ZRDMA_DEBUGFS_MODE_BOND);
	ib_device_put(ibdev);
	return 0;
}

/***
 * @brief Set the rdma speed to firmware, triggering speed reconfiguration.
 *
 * @param netdev zxdh_net device
 * @param bps for speed
 * @param speed_valid boolean
 * @return int32_t
 */
int32_t set_rdma_firmware_speed(struct net_device *netdev, u32 bps)
{
	int ret = 0;
	u32 status_code = 0;
	struct zxdh_device *iwdev;
	struct ib_device *ibdev;
	struct zxdh_pci_f *rf;
	struct zxdh_hwbond_speed_set_cmd cmd = { 0 };
	struct rdma_chan_msg_para para = { 0 };

	pr_info("[rdma_bond] new speed: %d\n", bps);
	ibdev = ib_device_get_by_netdev(netdev, RDMA_DRIVER_ZXDH);
	if (!ibdev)
		return -1;
	iwdev = to_iwdev(ibdev);
	if (!iwdev) {
		ib_device_put(ibdev);
		return -1;
	}
	rf = iwdev->rf;
	if (!rf) {
		ib_device_put(ibdev);
		return -1;
	}

	if (rf->sc_dev.hw_attrs.self_health == true) {
		ib_device_put(ibdev);
		return -1;
	}

	cmd.op_code = RDMA_HWBOND_SPEED_SET;
	cmd.req.speed = bps;
	cmd.req.speed_valid = TRUE;

	para.in_buf = (u8 *)&cmd;
	para.in_size = sizeof(cmd);
	para.out_buf = (u8 *)&status_code;
	para.out_size = sizeof(status_code);

	ret = rdma_chan_msg_send(rf, &para);
	if (ret) {
		pr_info("[%s] send msg failed, ret:%d", __func__, ret);
		ib_device_put(ibdev);
		return -1;
	}

	if (status_code != 200) {
		pr_info("[%s] status code not ok, status:%d", __func__, status_code);
		ib_device_put(ibdev);
		return -1;
	}

	ib_device_put(ibdev);
	return 0;
}

int set_rdma_vf_num(struct zxdh_rdma_sriov_event_info *sriov_info, u64 *vf_pblem_cnt)
{
	int ret = 0;
	u8 *rep_ptr;
	u16 rep_len = 0;
	u8 rep_valid = 0;
	size_t recv_len = 0;
	void *recv_buffer = NULL;

	struct zxdh_rdma_vf_num_set_cmd cmd = { 0 };
	struct zxdh_mgr mgr = { 0 };
	struct zxdh_pci_bar_msg in = { 0 };
	struct zxdh_msg_recviver_mem result = { 0 };
	struct dh_rdma_vf_num_set_resp *resp;
	u32 cnt = 0;
	u32 cnt_num = ZXDH_BAR_MSG_RETRY_NUM;

	mgr.pdev = sriov_info->pdev;
	ret = dh_rdma_pf_pcie_id_get(&mgr);
	if (ret) {
		pr_err("[%s] get pf pcie_id failed, ret=%d\n", __func__, ret);
		return -EINVAL;
	}

	recv_len = ZXDH_CHAN_REPS_LEN + sizeof(struct dh_rdma_vf_num_set_resp);
	recv_buffer = kzalloc(recv_len, GFP_KERNEL);
	if (!recv_buffer)
		return -ENOMEM;

	cmd.op_code = RDMA_VFS_NUM_SET;
	cmd.req.ep_id = (sriov_info->vport_id >> 12) & 0x7;
	cmd.req.pf_id = (sriov_info->vport_id >> 8) & 0x7;
	cmd.req.num_vfs = sriov_info->num_vfs;

	in.payload_addr = (void *)&cmd;
	in.payload_len = sizeof(cmd);

	in.src = MSG_CHAN_END_PF;
	in.dst = MSG_CHAN_END_RISC;
	in.event_id = MODULE_RDMA;
	in.virt_addr = sriov_info->bar0_virt_addr + ZXDH_BAR_CHAN_OFFSET;
	in.src_pcieid = mgr.pcie_id;

	// resv buffer preparation
	result.recv_buffer = recv_buffer;
	result.buffer_len = recv_len;

	do {
		ret = zxdh_bar_chan_sync_msg_send(&in, &result);
		if ((ret != ZXDH_BAR_ERR_TIME_OUT) && (ret != ZXDH_BAR_ERR_LOCK_FAILED))
			break;

		cnt++;
	} while (cnt < cnt_num);

	if (ret) {
		pr_err("[%s] message send failed, ret=%d cnt=%d\n", __func__, ret, cnt);
		kfree(recv_buffer);
		return -EPROTO;
	}

	rep_ptr = (u8 *)recv_buffer;
	rep_valid = *rep_ptr;
	if (rep_valid != MSG_REP_VALID) {
		pr_err("[%s] response message invalid, rep_valid=0x%x\n", __func__, rep_valid);
		kfree(recv_buffer);
		return -EPROTO;
	}

	rep_len = *(u16 *)(rep_ptr + MSG_REP_LEN_OFFSET);
	if (rep_len != recv_len - ZXDH_CHAN_REPS_LEN) {
		pr_err("[%s] response length invalid, rep_len=0x%x\n", __func__, rep_len);
		kfree(recv_buffer);
		return -EPROTO;
	}

	resp = (struct dh_rdma_vf_num_set_resp *)(rep_ptr + ZXDH_CHAN_REPS_LEN);
	if (resp->status_code != 200) {
		pr_info("[%s] status code not ok, status:%d", __func__, resp->status_code);
		return -EPROTO;
	}

	*vf_pblem_cnt = resp->vf_pblem_cnt;
	kfree(recv_buffer);
	return 0;
}

static int zxdh_data_check_sum(u8 *buf, u8 check_sum, u32 buf_len)
{
	u8 sum = 0;
	u32 i;

	if (!buf)
		return -ENOMEM;
	for (i = 0; i < buf_len; i++)
		sum += buf[i];

	if (sum != check_sum)
		return -EINVAL;

	return 0;
}

static int zxdh_resp_msg_check(u8 *buf, u32 buf_len)
{
	u32 len;

	if (!buf)
		return -ENOMEM;
	if ((buf_len > ZXDH_RESP_MSG_LEN) || (buf_len < ZXDH_MSG_MIN_LEN))
		return -ERANGE;
	if (buf[0] != ZXDH_VER_HEADER_H)
		return -EINVAL;
	if (buf[1] != ZXDH_VER_HEADER_L)
		return -EINVAL;

	len = buf[2] + 3;
	return zxdh_data_check_sum(&buf[3], buf[len], buf[2]);
}

int zxdh_req_cmd_ver(struct zxdh_pci_f *rf)
{
	int ret = 0;
	u8 rep_valid = 0;
	u16 rep_len = 0;
	u32 msg_len = 0;
	u8 *rep_ptr;
	struct zxdh_mgr mgr = { 0 };
	struct zxdh_pci_bar_msg in = { 0 };
	struct zxdh_msg_recviver_mem result = { 0 };
	struct iidc_core_dev_info *cdev_info;
	struct zxdh_req_msg req_msg = { 0 };
	struct zxdh_resp_msg *resp_msg;
	size_t recv_len;
	void *recv_buffer;
	u32 cnt = 0;
	u32 cnt_num = ZXDH_BAR_MSG_RETRY_NUM;

	if (!rf)
		return -ENOMEM;
	if (rf->sc_dev.driver_load == false)
		cnt_num = ZXDH_BAR_MSG_DEFAULT_NUM;
	rf->sc_dev.flr_query = 0;
	memset(rf->ver_buf, 0, ZXDH_RDMA_VER_LEN * sizeof(u8));
	cdev_info = (struct iidc_core_dev_info *)rf->cdev;

	// query pcie id
	mgr.pdev = cdev_info->pdev;
	ret = dh_rdma_pf_pcie_id_get(&mgr);
	if (ret) {
		pr_err("[%s] get pf pcie_id failed, ret=%d\n", __func__, ret);
		return -EINVAL;
	}

	recv_len = ZXDH_CHAN_REPS_LEN + sizeof(struct zxdh_resp_msg);
	recv_buffer = kzalloc(recv_len, GFP_KERNEL);
	if (!recv_buffer)
		return -ENOMEM;

	// commnad preparation
	req_msg.op_code = RDMA_REQ_VER;
	req_msg.buf[0] = ZXDH_VER_HEADER_H;
	req_msg.buf[1] = ZXDH_VER_HEADER_L;
	req_msg.buf[2] = 1;
	req_msg.buf[3] = 1;
	req_msg.buf[4] = 1;

	// get message preparation
	in.payload_addr = (void *)&req_msg;
	in.payload_len = sizeof(struct zxdh_req_msg);
	in.src = rf->ftype == 0 ? MSG_CHAN_END_PF : MSG_CHAN_END_VF;
	in.dst = MSG_CHAN_END_RISC;
	in.event_id = MODULE_RDMA;
	in.virt_addr = (u64)cdev_info->hw_addr + ZXDH_BAR_CHAN_OFFSET;
	in.src_pcieid = mgr.pcie_id;

	// resv buffer preparation
	result.recv_buffer = recv_buffer;
	result.buffer_len = recv_len;

	do {
		ret = zxdh_bar_chan_sync_msg_send(&in, &result);
		if ((ret != ZXDH_BAR_ERR_TIME_OUT) && (ret != ZXDH_BAR_ERR_LOCK_FAILED))
			break;

		cnt++;
	} while (cnt < cnt_num);

	if (ret) {
		pr_err("[%s] message send failed, ret=%d cnt=%d\n", __func__, ret, cnt);
		kfree(recv_buffer);
		return -EPROTO;
	}

	rep_ptr = (u8 *)recv_buffer;
	rep_valid = *rep_ptr;
	if (rep_valid != MSG_REP_VALID) {
		pr_err("[%s] response message invalid, rep_valid=0x%x\n", __func__, rep_valid);
		kfree(recv_buffer);
		return -EPROTO;
	}

	rep_len = *(u16 *)(rep_ptr + MSG_REP_LEN_OFFSET);
	if (rep_len != recv_len - ZXDH_CHAN_REPS_LEN) {
		pr_err("[%s] response length invalid, rep_len=0x%x\n", __func__, rep_len);
		kfree(recv_buffer);
		return -ERANGE;
	}

	resp_msg = (struct zxdh_resp_msg *)(rep_ptr + ZXDH_CHAN_REPS_LEN);
	if (resp_msg->op_code != RDMA_RESP_VER) {
		pr_err("[%s] response op code invalid, op_code=0x%x\n", __func__,
		       resp_msg->op_code);
		kfree(recv_buffer);
		return -EPROTO;
	}

	msg_len = resp_msg->buf[2] + 4;
	ret = zxdh_resp_msg_check(resp_msg->buf, msg_len);
	if (ret == 0) {
		pr_info("[%s] rdma get ver cfg success!\n", __func__);
		if (resp_msg->buf[2] > ZXDH_RDMA_VER_LEN)
			memcpy(rf->ver_buf, &resp_msg->buf[3], ZXDH_RDMA_VER_LEN * sizeof(u8));
		else
			memcpy(rf->ver_buf, &resp_msg->buf[3], resp_msg->buf[2] * sizeof(u8));
		rf->sc_dev.flr_query = rf->ver_buf[0];
	}
	kfree(recv_buffer);

	return ret;
}

notify_remote_ip_update remote_ip_update_hook = NULL;
int register_remote_ip_event_handler(notify_remote_ip_update handler)
{
	if (!handler) {
		pr_err("Failed to register: handler is NULL.\n");
		return -EINVAL;
	}

	remote_ip_update_hook = handler;
	pr_info("Event handler registered successfully.\n");
	return 0;
}
EXPORT_SYMBOL(register_remote_ip_event_handler);

void unregister_remote_ip_event_handler(void)
{
	pr_info("double plane: %s\n", __func__);
	remote_ip_update_hook = NULL;
}
EXPORT_SYMBOL(unregister_remote_ip_event_handler);

void rdma_update_remote_ip(struct zxdh_rdma_to_eth_ip_para *info)
{
	char s_straddr[INET6_ADDRSTRLEN + 20];
	char d_straddr[INET6_ADDRSTRLEN + 20];

	if (info->ipv4 == true) {
		scnprintf(s_straddr, sizeof(s_straddr), "%pI4", &info->src_ip[3]);
		scnprintf(d_straddr, sizeof(d_straddr), "%pI4", &info->dst_ip[3]);
	} else {
		scnprintf(s_straddr, sizeof(s_straddr), "%pI6", info->src_ip);
		scnprintf(d_straddr, sizeof(d_straddr), "%pI6", info->dst_ip);
	}
	pr_info("%s[%d]: ipv4=%d, name=%s, smac=0x%llx, dmac=0x%llx s_straddr=%s, d_straddr=%s\n",
		__func__, __LINE__, info->ipv4, info->ifname, info->src_mac, info->dst_mac,
		s_straddr, d_straddr);

	pr_info("%s[%d]: src_ip=0x%x-0x%x-0x%x-0x%x, dst_ip=0x%x-0x%x-0x%x-0x%x\n", __func__,
		__LINE__, info->src_ip[0], info->src_ip[1], info->src_ip[2], info->src_ip[3],
		info->dst_ip[0], info->dst_ip[1], info->dst_ip[2], info->dst_ip[3]);
	if (remote_ip_update_hook)
		remote_ip_update_hook(info);
}

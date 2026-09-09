// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include <linux/bitfield.h>
#include <linux/bitops.h>
#include <linux/vmalloc.h>
#include "main.h"
#include "hw.h"
#include "aeq.h"
#include "ceq.h"
#include "debug.h"
#include "ctrl.h"
#include "pble.h"
#include "cqp.h"
#include "hmc.h"
#include "grc.h"
#include "qp.h"
#include "counters.h"
#include "dump_fields.h"

static u32 nbl_regs[NBL_MAX_REGS] = {
	NBL_REG_CQP_PI,
	NBL_REG_SQ_DB,
	NBL_REG_ARM_CQ,
	NBL_REG_CEQ0_CI,
	NBL_REG_CEQ1_CI,
	NBL_REG_AEQ_CI,
	NBL_REG_RQ_DB,
	NBL_REG_NOTIFY_OFFSET,
	NBL_REG_DWQE_OFFSET
};

static void nbl_get_snic_global_msix_idx(struct nbl_pci_f *rf, u16 global_msix_idx[], u16 msix_cnt)
{
	int i;
	struct nbl_core_dev_info *cdev_info = (struct nbl_core_dev_info *)rf->cdev;

	memcpy(global_msix_idx, cdev_info->global_vector_id, sizeof(u16) * msix_cnt);

	for (i = 0; i < msix_cnt; i++)
		nbl_dev_dbg(&rf->pcidev->dev, "RoCE get_global_msix_idx[%d]=%u",
			    i, global_msix_idx[i]);
}

static void nbl_get_dpu_global_msix_idx(struct nbl_pci_f *rf, u16 global_msix_idx[], u16 msix_cnt)
{
	int i;
	int ret_val;
	u8 in[NBL_GRC_INPUT_SIZE];
	u8 out[NBL_GRC_OUTPUT_SIZE];
	int data_len = 0;
	struct grc_cache_msg_header *head;
	struct get_dpu_global_msix_idx_req req = {0};

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_GET_GLO_MSIX_IDX;
	head->payload_len = sizeof(struct get_dpu_global_msix_idx_req);
	data_len += sizeof(struct grc_cache_msg_header);

	nbl_dev_info(&rf->pcidev->dev, "RoCE get_dpu_global_msix_idx function_id=%u",
		     rf->sc_dev.function_id);

	req.function_id = rf->sc_dev.function_id;
	memcpy(in + data_len, &req, sizeof(req));
	data_len += sizeof(req);

	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val) {
		nbl_pr_err("get_dpu_global_msix_idx cmd err=%d", ret_val);
		return;
	}

	memcpy(global_msix_idx, out + 1, sizeof(u16) * msix_cnt);

	for (i = 0; i < msix_cnt; i++)
		nbl_dev_dbg(&rf->pcidev->dev, "RoCE get_dpu_global_msix_idx[%d]=%u",
			    i, global_msix_idx[i]);
}

/**
 * nbl_save_msix_info - copy msix vector information to rdma device
 * @rf: RDMA PCI function
 * Allocate dev msix table and copy the msix info to the table
 * Return 0 if successful, otherwise return error
 */
static enum nbl_status_code nbl_save_msix_info(struct nbl_pci_f *rf)
{
	struct msix_entry *pmsix;
	u16 global_msix_idx[NBL_RDMA_MSIX] = {0};
	u32 i;
	size_t size;

	/*
	 * May be only one interrupt vector shared by aeq and ceq,
	 * to be considerred later,   TODO..
	 */
	if (rf->msix_count < NBL_MSIX_COUNT_MIN) /* 0:aeq, others:ceq*/
		return NBL_ERR_NO_INTR;

	size = sizeof(struct nbl_msix_vector) * rf->msix_count;
	rf->nbl_msixtbl = kzalloc(size, GFP_KERNEL);
	if (!rf->nbl_msixtbl)
		return NBL_ERR_NO_MEMORY;

	if (product_type == PRODUCT_TYPE_SNIC)
		nbl_get_snic_global_msix_idx(rf, global_msix_idx, NBL_RDMA_MSIX);

	if (product_type == PRODUCT_TYPE_DPU && host_id == HOST_ID_TYPE_HOST)
		nbl_get_dpu_global_msix_idx(rf, global_msix_idx, NBL_RDMA_MSIX);

	pmsix = rf->msix_entries;
	for (i = 0; i < rf->msix_count; i++) {
		if (product_type == PRODUCT_TYPE_SNIC ||
			(product_type == PRODUCT_TYPE_DPU && host_id == HOST_ID_TYPE_HOST))
			rf->nbl_msixtbl[i].idx = global_msix_idx[i];
		else
			rf->nbl_msixtbl[i].idx = pmsix->entry;
		rf->nbl_msixtbl[i].irq = pmsix->vector;
		rf->nbl_msixtbl[i].cpu_affinity =
			cpumask_local_spread(i, rf->pcidev->dev.numa_node);
		nbl_pr_dbg("save msix[%d] idx:%d irq:%d affinity:%d\n",
			i, global_msix_idx[i], pmsix->vector,
			rf->nbl_msixtbl[i].cpu_affinity);
		pmsix++;
	}

	return 0;
}

static enum nbl_status_code nbl_initialize_dev(struct nbl_pci_f *rf)
{
	u32 size;
	enum nbl_status_code status;
	struct nbl_sc_dev *dev = &rf->sc_dev;
	struct nbl_device_init_info info = {};

	size = sizeof(struct nbl_hmc_pble_rsrc) +
	       sizeof(struct nbl_hmc_obj_info) * NBL_HMC_MAX;
	rf->hmc_info_mem = kzalloc(size, GFP_KERNEL);
	if (!rf->hmc_info_mem)
		return NBL_ERR_NO_MEMORY;

	rf->pble_rsrc = (struct nbl_hmc_pble_rsrc *)rf->hmc_info_mem;
	dev->hmc_info = &rf->hw.hmc;
	dev->hmc_info->hmc_obj = (struct nbl_hmc_obj_info *)(rf->pble_rsrc + 1);

	info.bar0 = rf->hw.hw_addr;
	info.hw = &rf->hw;
	info.ost_rd_atom = rf->nbl_actual_rd_atom;
	/* to do add other dev attr */
	status = nbl_sc_dev_init(&rf->sc_dev, &info);
	if (status) {
		nbl_ib_err(dev, "sc_dev init err=%d", status);
		/* Free here: init_state is still INVALID_STATE at this point,
		 * so nbl_ctrl_deinit_hw takes the default path and will not
		 * free this memory for us.
		 */
		kfree(rf->hmc_info_mem);
		rf->hmc_info_mem = NULL;
	}

	return status;
}

static enum nbl_status_code nbl_setup_init_state(struct nbl_pci_f *rf)
{
	enum nbl_status_code status;
	struct nbl_core_dev_info *cdev_info = (struct nbl_core_dev_info *)rf->cdev;

	status = nbl_save_msix_info(rf);
	if (status)
		return status;

	rf->hw.device = cdev_info->dma_dev;
	/* other process TODO */
	status = nbl_initialize_dev(rf);
	if (status)
		goto clean_msixtbl;

	return 0;
clean_msixtbl:
	kfree(rf->nbl_msixtbl);
	rf->nbl_msixtbl = NULL;
	return status;
}

static enum nbl_status_code nbl_notify_set(struct nbl_pci_f *rf, bool valid)
{
	u8 in[NBL_GRC_INPUT_SIZE];
	u8 out[NBL_GRC_OUTPUT_SIZE];
	int data_len = 0;
	struct notify_info_req req = {0};
	int ret_val;
	struct grc_cache_msg_header *head;
	struct nbl_core_dev_info *cdev_info = (struct nbl_core_dev_info *)rf->cdev;

	head = (struct grc_cache_msg_header *)in;

	if (sizeof(req) > NBL_GRC_INPUT_PAYLOAD_SIZE) {
		nbl_pr_err("hw init notify payload size invalid\n");
		return -EINVAL;
	}

	req.function_id = rf->sc_dev.function_id;
	req.host_id = host_id;
	req.product_type = product_type;
	req.valid = valid ? 1 : 0;
	if (rf->sc_dev.pcie_func_id == 0)
		req.bar0_phy_addr = cdev_info->real_hw_addr +
				    NBL_HOST_SNIC_AF_NOTIFY_OFFSET;
	else
		req.bar0_phy_addr = cdev_info->real_hw_addr;
	nbl_pr_dbg("hw init notify req: fun id %u,bar0_phy_addr 0x%llx valid(%d)\n",
		req.function_id, req.bar0_phy_addr, (valid ? 1 : 0));

	head->op_code = GRC_MSG_OP_SET_NOTIFY_INFO;
	head->payload_len = sizeof(struct notify_info_req);
	data_len += sizeof(struct grc_cache_msg_header);

	memcpy(in + data_len, &req, sizeof(req));
	data_len += sizeof(req);

	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val) {
		nbl_pr_err("hw notify init cmd err=%d", ret_val);
		return ret_val;
	}

	return 0;
}

static void nbl_notify_cleanup(struct nbl_pci_f *rf)
{
	nbl_notify_set(rf, false);
}

static enum nbl_status_code nbl_notify_init(struct nbl_pci_f *rf)
{
	return nbl_notify_set(rf, true);
}

/**
 * nbl_del_init_mem - deallocate memory resources
 * @rf: RDMA PCI function
 */
static void nbl_del_init_mem(struct nbl_pci_f *rf)
{
	kfree(rf->nbl_msixtbl);
	rf->nbl_msixtbl = NULL;
	kfree(rf->hmc_info_mem);
	rf->hmc_info_mem = NULL;
	iounmap(rf->hw.notify_addr);
	rf->hw.notify_addr = NULL;
}

static void nbl_del_hw_rsrc(struct nbl_pci_f *rf)
{
	vfree(rf->mem_rsrc);
	rf->mem_rsrc = NULL;
}

void nbl_ctrl_deinit_hw(struct nbl_pci_f *rf)
{
	enum init_completion_state state = rf->init_state;

	rf->init_state = INVALID_STATE;

	switch (state) {
	case QP_INITED:
		nbl_deinit_qps(rf);
		fallthrough;
	case HW_RSRC_INITIALIZED:
		nbl_del_hw_rsrc(rf);
		fallthrough;
	case HMC_OBJS_CREATED:
		nbl_hmc_destroy(rf);
		fallthrough;
	case CQP_CREATED:
		nbl_cmd_cleanup(rf);
		fallthrough;
	case NOTIFY_INITIALIZED:
		nbl_notify_cleanup(rf);
		fallthrough;
	case INITIAL_STATE:
		nbl_del_init_mem(rf);
		break;
	default:
		break;
	}
}

/**
 * nbl_ctrl_init_hw - Initializes control portion of HW
 * @rf: RDMA PCI function
 *
 * Create admin queues, HMC obejcts and RF resource objects
 */
enum nbl_status_code nbl_ctrl_init_hw(struct nbl_pci_f *rf)
{
	enum nbl_status_code status;

	do {
		status = nbl_setup_init_state(rf);
		if (status)
			break;
		rf->init_state = INITIAL_STATE;

		status = nbl_notify_init(rf);
		if (status)
			break;
		rf->init_state = NOTIFY_INITIALIZED;

		status = nbl_cmd_init(rf);
		if (status)
			break;
		rf->init_state = CQP_CREATED;

		status = nbl_hmc_setup(rf);
		if (status)
			break;
		rf->init_state = HMC_OBJS_CREATED;

		status = nbl_initialize_hw_rsrc(rf);
		if (status)
			break;
		rf->init_state = HW_RSRC_INITIALIZED;

		status = nbl_init_qps(rf);
		if (status)
			break;
		rf->init_state = QP_INITED;

		/*other process TODO */

		return 0;
	} while (0);

	dev_info(&rf->pcidev->dev,
		"NBL hardware initialization FAILED init_state=%d status=%d\n",
		rf->init_state, status);

	nbl_ctrl_deinit_hw(rf);

	return status;
}

/**
 * nbl_get_used_rsrc - determine resources used internally
 * @nbl_dev: nbl device
 *
 * Called at the end of open to get all internal allocations
 */
static void nbl_get_used_rsrc(struct nbl_device *nbl_dev)
{
	nbl_dev->rf->used_pds = find_next_zero_bit(nbl_dev->rf->allocated_pds,
						   nbl_dev->rf->max_pd, 0);
	nbl_dev->rf->used_qps = find_next_zero_bit(nbl_dev->rf->allocated_qps,
						   nbl_dev->rf->max_qp, 0);
	nbl_dev->rf->used_cqs = find_next_zero_bit(nbl_dev->rf->allocated_cqs,
						   nbl_dev->rf->max_cq, 0);
	atomic_set(&nbl_dev->rf->used_mrs_a,
		find_next_zero_bit(nbl_dev->rf->allocated_mrs, nbl_dev->rf->max_mr, 0));
}

/**
 * nbl_rt_deinit_hw - clean up the nbl device resources
 * @nbl_dev: nbl device
 *
 */
void nbl_rt_deinit_hw(struct nbl_device *nbl_dev)
{

	enum init_completion_state state = nbl_dev->init_state;

	nbl_dev->init_state = INVALID_STATE;

	switch (state) {
	case PBLE_CHUNK_MEM:
		nbl_hmc_deinit_pble(nbl_dev->rf);
		fallthrough;
	case AEQ_CREATED:
		nbl_destroy_aeq(nbl_dev->rf);
		fallthrough;
	case CEQS_CREATED:
		nbl_del_ceqs(nbl_dev->rf);
		break;
	default:
		break;
	}
}

/**
 * nbl_rt_init_hw - Initializes runtime portion of HW
 * @nbl_dev: nbl device
 *
 * Create device queues AEQS/CEQs. Setup nbl device resource objects.
 */
enum nbl_status_code nbl_rt_init_hw(struct nbl_device *nbl_dev)
{
	struct nbl_pci_f *rf = nbl_dev->rf;
	enum nbl_status_code status;

	do {
		status = nbl_setup_ceqs(rf);
		if (status)
			break;
		nbl_dev->init_state = CEQS_CREATED;

		status = nbl_setup_aeq(rf);
		if (status)
			break;
		nbl_dev->init_state = AEQ_CREATED;

		status = nbl_hmc_init_pble(rf);
		if (status)
			break;
		nbl_dev->init_state = PBLE_CHUNK_MEM;

		nbl_get_used_rsrc(nbl_dev);

		nbl_dev->device_cap_flags = IB_DEVICE_MEM_WINDOW | IB_DEVICE_MEM_MGT_EXTENSIONS |
									IB_DEVICE_RC_RNR_NAK_GEN;
		return 0;
	} while (0);

	dev_err(&rf->pcidev->dev,
		"HW runtime init FAIL status = %d last cmpl = %d\n", status,
		nbl_dev->init_state);
	nbl_rt_deinit_hw(nbl_dev);

	return status;
}

static void nbl_enable_rdma_intrl(struct nbl_pci_f *rf, u32 idx, u8 ena_flag)
{
	int ret_val;
	uint8_t in[NBL_GRC_INPUT_SIZE];
	uint8_t out[NBL_GRC_OUTPUT_SIZE];
	int data_len = 0;
	struct grc_cache_msg_header *head;
	struct nbl_ena_rdma_intrl_req req = {0};
	struct nbl_core_dev_info *cdev_info =
		(struct nbl_core_dev_info *)rf->cdev;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_ENA_RDMA_INTRL;
	head->payload_len = sizeof(struct nbl_ena_rdma_intrl_req);
	data_len += sizeof(struct grc_cache_msg_header);

	req.msix_global_idx = idx;
	req.devfn = PCI_DEVFN(cdev_info->real_dev, cdev_info->real_function);
	req.bus = cdev_info->real_bus;
	req.valid = ena_flag;
	memcpy(in + data_len, &req, sizeof(req));
	data_len += sizeof(req);

	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val)
		nbl_pr_err("enable_rdma_intrl cmd err=%d", ret_val);

	nbl_dev_dbg(&rf->pcidev->dev, "RoCE enable_rdma_intrl end");
}

static void nbl_ena_rdma_vector_ctrl(struct nbl_pci_f *rf, u32 idx, bool flag)
{
	u32 regval;

	if (host_id != HOST_ID_TYPE_ECPU)
		return;

	regval = readl(rf->hw.hw_addr + IRQ_KERNEL_CTL(host_id, idx));
	if (flag)
		regval = regval & (~IRQ_KERNEL_CTL_MASK_M);
	else
		regval = regval | IRQ_KERNEL_CTL_MASK_M;

	writel(regval, rf->hw.hw_addr + IRQ_KERNEL_CTL(host_id, idx));
	nbl_ib_dbg(&rf->sc_dev, "enable msix_table reg_idx:%d, address:%#x val:%#x flag:%d\n",
		idx, IRQ_KERNEL_CTL(host_id, idx), regval, flag);

}

static void nbl_ena_rdma_vector_intrl(struct nbl_pci_f *rf, u32 idx, bool flag)
{
	u64 reg_addr;
	union padapt_ecpu_msix_info msix_info_tbl = {0};
	u8 devfn = rf->pcidev->devfn;
	u8 bus = rf->pcidev->bus->number;

	if (host_id != HOST_ID_TYPE_ECPU)
		return;

	msix_info_tbl.intrl_pnum = 0;
	msix_info_tbl.intrl_rate = 0;
	msix_info_tbl.function_id = devfn & 0x7;
	msix_info_tbl.device_id = devfn >> 3;
	msix_info_tbl.bus_id = bus;
	msix_info_tbl.valid = flag ? 1 : 0;

	reg_addr = ECPU_MSIX_INFO_TBL(idx);
	wr32_for_each(&rf->hw, reg_addr,
		      msix_info_tbl.data, sizeof(msix_info_tbl.data));

	nbl_ib_warn(&rf->sc_dev, "enable msix_info_table,reg_idx:%u address:0x%llx\n",
		idx, reg_addr);
	nbl_ib_warn(&rf->sc_dev, "val_low32:%#x,val_high32:%#x flag:%d\n",
		msix_info_tbl.data[0], msix_info_tbl.data[1], flag);
}

/**
 * nbl_disable_irq - Disable interrupt
 * @rf: pointer to the nbl_pci_f structure
 * @idx: vector index
 */
static void nbl_disable_irq(struct nbl_pci_f *rf, u32 idx)
{
	if (product_type == PRODUCT_TYPE_SNIC) {
		nbl_enable_rdma_intrl(rf, idx, 0);
		return;
	}

	if (product_type == PRODUCT_TYPE_DPU && host_id == HOST_ID_TYPE_ECPU) {
		nbl_ena_rdma_vector_intrl(rf, idx, false);
		nbl_ena_rdma_vector_ctrl(rf, idx, false);
	}
}

/**
 * nbl_enable_irq - Enable interrupt
 * @rf: pointer to the nbl_pci_f structure
 * @idx: vector index
 */
static void nbl_enable_irq(struct nbl_pci_f *rf, u32 idx)
{
	if (product_type == PRODUCT_TYPE_SNIC) {
		nbl_enable_rdma_intrl(rf, idx, 1);
		return;
	}

	if (product_type == PRODUCT_TYPE_DPU && host_id == HOST_ID_TYPE_ECPU) {
		nbl_ena_rdma_vector_intrl(rf, idx, true);
		nbl_ena_rdma_vector_ctrl(rf, idx, true);
	}
}

static const struct nbl_irq_ops nbl_irq_ops = {
	.nbl_dis_irq = nbl_disable_irq,
	.nbl_en_irq = nbl_enable_irq,
};

static u32 nbl_get_notify_offset(struct nbl_sc_dev *sc_dev)
{
	if (host_id >= HOST_ID_TYPE_MAX || product_type >= PRODUCT_TYPE_MAX) {
		nbl_ib_err(sc_dev, "invalid params,host_id=%u,product_type=%u",
			   host_id, product_type);
		return NBL_INVALID_OFFSET;
	}

	if (host_id == HOST_ID_TYPE_ECPU)
		return NBL_ECPU_NOTIFY_OFFSET;

	if (host_id == HOST_ID_TYPE_HOST) {
		if (product_type == PRODUCT_TYPE_SNIC) {
			if (sc_dev->pcie_func_id == 0)
				return NBL_HOST_SNIC_AF_RDMA_NOTIFY_OFFSET;
			else
				return NBL_HOST_SNIC_RDMA_NOTIFY_OFFSET;
		}
		if (product_type == PRODUCT_TYPE_DPU)
			return NBL_HOST_NOTIFY_OFFSET;
	}

	return NBL_INVALID_OFFSET;
}

static u32 nbl_get_bar0_offset(struct nbl_sc_dev *sc_dev)
{
	if (host_id >= HOST_ID_TYPE_MAX || product_type >= PRODUCT_TYPE_MAX) {
		nbl_ib_err(sc_dev, "invalid params,host_id=%u,product_type=%u",
			   host_id, product_type);
		return NBL_INVALID_OFFSET;
	}

	if (host_id == HOST_ID_TYPE_ECPU)
		return NBL_ECPU_BAR0_HWADDR_OFFSET;

	if (host_id == HOST_ID_TYPE_HOST) {
		if (product_type == PRODUCT_TYPE_SNIC)
			return NBL_HOST_SNIC_BAR0_OFFSET;
		if (product_type == PRODUCT_TYPE_DPU)
			return NBL_HOST_BAR0_HWADDR_OFFSET;
	}

	return NBL_INVALID_OFFSET;
}

int nbl_init_hw(struct nbl_sc_dev *sc_dev)
{
	int i;
	u32 offset0;
	u32 offset1;
	u8 __iomem *hw_addr;
	struct nbl_pci_f *rf = container_of(sc_dev, struct nbl_pci_f, sc_dev);
	u32 bdf_num = PCI_DEVID(rf->pcidev->bus->number, rf->pcidev->devfn);

	/* offset0: from bar0 to hw addr */
	offset0 = nbl_get_bar0_offset(sc_dev);
	/* offset1: from hw addr to notify */
	offset1 = nbl_get_notify_offset(sc_dev);
	if (offset0 == NBL_INVALID_OFFSET || offset1 == NBL_INVALID_OFFSET)
		return -EINVAL;

	nbl_pr_dbg(
		"set notify regs for pcie_func_id %u, function_id=%u,bdf_num=0x%x,sc_dev->hw->hw_addr=%p",
		sc_dev->pcie_func_id, sc_dev->function_id, bdf_num,
		sc_dev->hw->hw_addr);

	sc_dev->hw->notify_addr = ioremap(pci_resource_start(rf->pcidev, 0) + offset0 + offset1,
		NBL_ADAPTER_PAGE_SIZE);
	if (!sc_dev->hw->notify_addr) {
		nbl_pr_err("ioremap notify area err\n");
		return NBL_ERR_NO_MEMORY;
	}

	for (i = 0; i < NBL_MAX_REGS; i++) {
		if (i == NBL_NOTIFY_OFFSET) {
			/* calc addr from bar0 to notify, so base + offset0 + offset1 */
			hw_addr = 0;
			sc_dev->hw_regs[i] =
				(void __iomem *)(hw_addr + offset0 + offset1);
		} else if (i == NBL_DWQE_OFFSET) {
			/* calc addr from bar0 to dwqe, so base + offset0 + offset1 + 4K */
			hw_addr = 0;
			sc_dev->hw_regs[i] =
				(void __iomem *)(hw_addr + offset0 + offset1 +
					NBL_ADAPTER_PAGE_SIZE);
		} else {
			/* calc addr from hw addr to notify, so base + offset1 + nbl_regs[] */
			sc_dev->hw_regs[i] =
				(void __iomem *)(sc_dev->hw->notify_addr + nbl_regs[i]);
		}
	}

	/* to do setup other regs and attrs */
	sc_dev->irq_ops = &nbl_irq_ops;

	return NBL_SUCCESS;
}

static void nbl_set_hw_rsrc(struct nbl_pci_f *rf)
{
	rf->allocated_qps = (void *)rf->mem_rsrc;
	rf->allocated_cqs = &rf->allocated_qps[BITS_TO_LONGS(rf->max_qp)];
	rf->allocated_mrs = &rf->allocated_cqs[BITS_TO_LONGS(rf->max_cq)];
	rf->allocated_pds = &rf->allocated_mrs[BITS_TO_LONGS(rf->max_mr)];
	rf->allocated_ahs = &rf->allocated_pds[BITS_TO_LONGS(rf->max_pd)];
	rf->qp_table =
		(struct nbl_qp **)(&rf->allocated_ahs[BITS_TO_LONGS(rf->max_ah)]);
	rf->qp_seq_table = (int *)(&rf->qp_table[rf->max_qp]);
	rf->cq_table = (struct nbl_cq **)(&rf->qp_seq_table[rf->max_qp]);
	rf->qp_return_ts = (u64 *)(&rf->cq_table[rf->max_cq]);
	rf->mr_table = (struct nbl_mr **)(&rf->qp_return_ts[rf->max_qp]);

	spin_lock_init(&rf->rsrc_lock);
	spin_lock_init(&rf->qptable_lock);
	spin_lock_init(&rf->cqtable_lock);
	spin_lock_init(&rf->mrtable_lock);
	spin_lock_init(&rf->cq_arm_lock);
}

static u32 nbl_calc_mem_rsrc_size(struct nbl_pci_f *rf)
{
	u32 rsrc_size = 0;

	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_qp);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_cq);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_mr);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_pd);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_ah);
	rsrc_size += sizeof(struct nbl_qp **) * rf->max_qp;
	rsrc_size += sizeof(struct nbl_cq **) * rf->max_cq;
	rsrc_size += sizeof(struct nbl_mr **) * rf->max_mr;
	rsrc_size += sizeof(int) * rf->max_qp;
	rsrc_size += sizeof(u64) * rf->max_qp;
	nbl_ib_dbg(&rf->sc_dev, "the rsrc_size is %u.\n", rsrc_size);

	return rsrc_size;
}

/**
 * nbl_initialize_hw_rsrc - initialize hw resource tracking array
 * @rf: RDMA PCI function
 */
enum nbl_status_code nbl_initialize_hw_rsrc(struct nbl_pci_f *rf)
{
	u32 rsrc_size;

	rf->max_cqe = rf->sc_dev.hw_attrs.uk_attrs.max_hw_cq_size;
	rf->max_qp = rf->sc_dev.hmc_info->hmc_obj[NBL_HMC_QP].cnt;
	rf->max_cq = rf->sc_dev.hmc_info->hmc_obj[NBL_HMC_CQ].cnt;
	rf->max_mr = rf->sc_dev.hmc_info->hmc_obj[NBL_HMC_MR].cnt;
	rf->max_pd = rf->sc_dev.hw_attrs.max_hw_pds;
	rf->max_ah = rf->sc_dev.hw_attrs.max_hw_ahs;

	rsrc_size = nbl_calc_mem_rsrc_size(rf);
	rf->mem_rsrc = vzalloc(rsrc_size);
	if (!rf->mem_rsrc) {
		nbl_ib_err(&rf->sc_dev, "failed vzalloc mem for rsrc");
		return NBL_ERR_ALLOCMEM_FAILED;
	}

	nbl_set_hw_rsrc(rf);
	set_bit(NBL_QP_NUM_FOR_RSV, rf->allocated_qps); /* qp num 0 is reserve */
	set_bit(NBL_QP_NUM_FOR_CM, rf->allocated_qps); /* qp num 1 is cm use */
	set_bit(0, rf->allocated_mrs);
	set_bit(0, rf->allocated_pds);
	set_bit(0, rf->allocated_ahs);
	memset(rf->qp_seq_table, 0, sizeof(int) * rf->max_qp);

	nbl_ib_dbg(&rf->sc_dev, "[rsrc]: max_qp(%u), mac_cq(%u), max_mr(%u), max_pd(%u), max_ah(%u), max_cqe(%u)",
		rf->max_qp, rf->max_cq, rf->max_mr, rf->max_pd, rf->max_ah,
		rf->max_cqe);

	return NBL_SUCCESS;
}

enum nbl_status_code nbl_init_qps(struct nbl_pci_f *rf)
{
	sema_init(&rf->qp_flush_sem, NBL_HW_FLUSH_CNT);

	rf->flush_wq = alloc_workqueue("nbl_flush_wq", WQ_UNBOUND,
					    WQ_UNBOUND_MAX_ACTIVE);
	if (!rf->flush_wq) {
		nbl_ib_err(&rf->sc_dev, "alloc flush work queue failed\n");
		return NBL_ERR_NO_MEMORY;
	}

	rf->query_qpc_wq = alloc_workqueue("nbl_debug_query_qpc_wq", WQ_UNBOUND,
					   WQ_UNBOUND_MAX_ACTIVE);
	if (!rf->query_qpc_wq) {
		nbl_ib_err(&rf->sc_dev, "alloc query_qpc work queue failed\n");
		destroy_workqueue(rf->flush_wq);
		return NBL_ERR_NO_MEMORY;
	}

	return NBL_SUCCESS;
}

void nbl_deinit_qps(struct nbl_pci_f *rf)
{
	destroy_workqueue(rf->flush_wq);
	destroy_workqueue(rf->query_qpc_wq);
}

/**
 * nbl_get_hw_msix_id - get hw msix id
 * @rf: roce pci function struct, input
 * @host_vector: the OS msix vector, input
 * @hw_msix_id: the hardware msix id got, output
 * Return: return 0 is success, other value if fail
 */
int nbl_get_hw_msix_id(struct nbl_pci_f *rf, u32 host_vector, u16 *hw_msix_id)
{
	u8 in[NBL_GRC_INPUT_SIZE];
	u8 out[NBL_GRC_OUTPUT_SIZE];
	int data_len = 0;
	struct hw_msix_id_req req = {0};
	int ret_val;
	u16 hw_msix_id_get;
	struct grc_cache_msg_header *head;

	if (host_id == HOST_ID_TYPE_ECPU) {
		*hw_msix_id = host_vector + NBL_ECPU_HW_MSIX_ID_OFFSET;
		return 0;
	}

	head = (struct grc_cache_msg_header *)in;

	if (sizeof(req) > NBL_GRC_INPUT_PAYLOAD_SIZE) {
		nbl_pr_err("hw get msix id para invalid\n");
		return -EINVAL;
	}

	req.function_id = rf->sc_dev.function_id;
	req.host_vector = host_vector;

	nbl_pr_info("hw msix id req: fun id %u, host vector %u\n",
		req.function_id, req.host_vector);

	head->op_code = GRC_MSG_OP_HW_MISX_ID_REQ;
	head->payload_len = sizeof(struct hw_msix_id_req);
	data_len += sizeof(struct grc_cache_msg_header);

	memcpy(in + data_len, &req, sizeof(req));
	data_len += sizeof(req);

	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val) {
		nbl_pr_err("hw msix id req cmd err=%d", ret_val);
		return ret_val;
	}
	memcpy(&hw_msix_id_get, out + 1, sizeof(hw_msix_id_get));
	*hw_msix_id = hw_msix_id_get;

	return 0;
}

void nbl_dump_hex(struct nbl_pci_f *rf, u8 *buf, int len)
{
	const u8 *ptr = buf;
	int i, linelen, remaining = len;
	unsigned char linebuf[NBL_HEX_DUMP_BUF_MAX];
	int rowsize = NBL_HEX_DUMP_ROW;

	for (i = 0; i < len; i += rowsize) {
		linelen = min(remaining, rowsize);
		remaining -= rowsize;

		hex_dump_to_buffer(ptr + i, linelen, rowsize, NBL_HEX_DUMP_GRP,
				   linebuf, sizeof(linebuf), false);

		nbl_pr_info("[%d-%d] %s\n", i, (i + linelen - 1), linebuf);
	}
}

static void nbl_dump_cc_qpc_fields(u8 *qpc_data)
{
	u32 cc_recreq_sendtx_blk_cnt;
	u32 cc_winm_busy;
	u32 cc_ta_sn_phase_chg;
	u32 cc_ta_sn;
	u32 cc_recack_lastwinm_blk_cnt;
	u32 cc_recack_epsn;

	u32 cc_time_lastta;
	u32 ccqcn_reqcarry_sendcnp_time;

	u32 qcn_rececn_flag;
	u32 cc_more_rttminth_flag;
	u32 cc_less_rttminth_flag;
	u32 cc_recack_rttflag;
	u32 cc_sendack_mid_blk_cnt;
	u32 cc_recreq_blk_cnt;
	u32 cc_recreq_mid_blk_cnt;
	u32 cc_recreq_epsn;

	u32 cc_rttmin;
	u32 cc_rtt;
	u32 cc_oamack_next_psn;

	u32 rttm_busy;
	u32 recack_rectx_blk_cnt;
	u32 targetwin;
	u32 targetwin_min;

	u32 rttm_psnts;
	u32 txp_sendpld_blk_cnt;
	u32 cc_mode;
	u32 oamack_blk_th;

	u64 temp;

	if (qpc_data == NULL)
		return;

	get_64bit_val((__be64 *)qpc_data, 0x138, &temp);
	cc_recreq_sendtx_blk_cnt = (u32)FIELD_GET(NBL_QPC_CC_RECREQ_SENDTX_BLK_CNT, temp);
	cc_winm_busy = (u32)FIELD_GET(NBL_QPC_CC_WINM_BUSY, temp);
	cc_ta_sn_phase_chg = (u32)FIELD_GET(NBL_QPC_CC_TA_SN_PHASE_CHG, temp);
	cc_ta_sn = (u32)FIELD_GET(NBL_QPC_CC_TA_SN, temp);
	cc_recack_lastwinm_blk_cnt = (u32)FIELD_GET(NBL_QPC_CC_RECACK_LASTWINM_BLK_CNT, temp);
	cc_recack_epsn = (u32)FIELD_GET(NBL_QPC_CC_RECACK_EPSN, temp);

	pr_info("0x138 cc_recreq_sendtx_blk_cnt:%d cc_winm_busy:%d cc_ta_sn_phase_chg:%d cc_ta_sn:%d cc_recack_lastwinm_blk_cnt:%d cc_recack_epsn:%d\n",
		cc_recreq_sendtx_blk_cnt, cc_winm_busy, cc_ta_sn_phase_chg,
		cc_ta_sn, cc_recack_lastwinm_blk_cnt, cc_recack_epsn);

	get_64bit_val((__be64 *)qpc_data, 0x130, &temp);
	cc_time_lastta = (u32)FIELD_GET(NBL_QPC_CC_TIME_LASTTA, temp);
	ccqcn_reqcarry_sendcnp_time = (u32)FIELD_GET(NBL_QPC_CCQCN_REQCARRY_SENDCNP_TIME, temp);
	pr_info("0x130 cc_time_lastta:%u ccqcn_reqcarry_sendcnp_time:%u\n",
		cc_time_lastta, ccqcn_reqcarry_sendcnp_time);

	get_64bit_val((__be64 *)qpc_data, 0x128, &temp);
	qcn_rececn_flag = (u32)FIELD_GET(NBL_QPC_QCN_RECECN_FLAG, temp);
	cc_more_rttminth_flag = (u32)FIELD_GET(NBL_QPC_CC_MORE_RTTMINTH_FLAG, temp);
	cc_less_rttminth_flag = (u32)FIELD_GET(NBL_QPC_CC_LESS_RTTMINTH_FLAG, temp);
	cc_recack_rttflag = (u32)FIELD_GET(NBL_QPC_CC_RECACK_RTTFLAG, temp);
	cc_sendack_mid_blk_cnt = (u32)FIELD_GET(NBL_QPC_CC_SENDACK_MID_BLK_CNT, temp);
	cc_recreq_blk_cnt = (u32)FIELD_GET(NBL_QPC_CC_RECREQ_BLK_CNT, temp);
	cc_recreq_mid_blk_cnt = (u32)FIELD_GET(NBL_QPC_CC_RECREQ_MID_BLK_CNT, temp);
	cc_recreq_epsn = (u32)FIELD_GET(NBL_QPC_CC_RECREQ_EPSN, temp);

	pr_info("0x128 qcn_rececn_flag:%d cc_more_rttminth_flag:%d cc_less_rttminth_flag:%d cc_recack_rttflag:%d cc_sendack_mid_blk_cnt:%d cc_recreq_blk_cnt:%d cc_recreq_mid_blk_cnt:%d cc_recreq_epsn:%d\n",
		qcn_rececn_flag, cc_more_rttminth_flag, cc_less_rttminth_flag,
		cc_recack_rttflag, cc_sendack_mid_blk_cnt, cc_recreq_blk_cnt,
		cc_recreq_mid_blk_cnt, cc_recreq_epsn);

	get_64bit_val((__be64 *)qpc_data, 0x120, &temp);
	cc_rttmin = (u32)FIELD_GET(NBL_QPC_CC_RTTMIN, temp);
	cc_rtt = (u32)FIELD_GET(NBL_QPC_CC_RTT_MEASURE, temp);
	cc_oamack_next_psn = (u32)FIELD_GET(NBL_QPC_CC_OAMACK_NEXT_PSN, temp);

	get_64bit_val((__be64 *)qpc_data, 0x198, &temp);
	rttm_busy = (u32)FIELD_GET(NBL_QPC_CC_RTTM_BUSY, temp);
	recack_rectx_blk_cnt = (u32)FIELD_GET(NBL_QPC_CC_RECACK_RECTX_BLK_CNT, temp);
	targetwin = (u32)FIELD_GET(NBL_QPC_CC_TARGETWIN, temp);

	get_64bit_val((__be64 *)qpc_data, 0x28, &temp);
	targetwin_min = (u32)FIELD_GET(NBL_QPC_CC_TARGETWIN_MIN, temp);

	get_64bit_val((__be64 *)qpc_data, 0x190, &temp);
	rttm_psnts = (u32)FIELD_GET(NBL_QPC_CC_RTTM_PSNTS, temp);
	txp_sendpld_blk_cnt = (u32)FIELD_GET(NBL_QPC_CC_TXP_SENDPLD_BLK_CNT, temp);

	get_64bit_val((__be64 *)qpc_data, 0x18, &temp);
	cc_mode = (u32)FIELD_GET(NBL_QPC_CC_MODE, temp);

	get_64bit_val((__be64 *)qpc_data, 48, &temp);
	oamack_blk_th = (u32)FIELD_GET(NBL_QPC_CC_SENDACK_BLK_CNT_TH, temp);

	pr_info("0x120 rtt:%d (%d ns) cc_rttmin:%d (%d ns) cc_oamack_next_psn:%d\n",
		cc_rtt, cc_rtt*640, cc_rttmin, cc_rttmin*40, cc_oamack_next_psn);

	pr_info("0x190 rttm_psnts:%d txp_sendpld_blk_cnt:%d\n",
		rttm_psnts, txp_sendpld_blk_cnt);

	pr_info("0x198 rttm_busy:%d recack_rectx_blk_cnt:%d cc_mode:%d oamack_blk_th:%d targetwin_min:%d targetwin:%d\n",
		rttm_busy, recack_rectx_blk_cnt, cc_mode, oamack_blk_th, targetwin_min, targetwin);

}

static void nbl_dump_cc_debug_info(struct nbl_pci_f *rf, u32 mask, u8 *key, u8 *data)
{
	u32 qpn = be32_to_cpu(*(u32 *)key);

	qpn = (qpn >> 8) & 0x3FFFF;
	if (qpn == (mask & 0x3FFFF) || (mask & 0x3FFFF) == 0) {

		if ((mask & 0x1000000) || rf->qp_table[qpn]) {
			pr_info("qpn[%d] CC's debug qpc info:\n", qpn);
			nbl_dump_cc_qpc_fields(data);
			if (qpn == (mask & 0x3FFFF))
				nbl_dump_hex(rf, data, NBL_CACHE_QPCC_SIZE);
		}
	}
}

/**
 * Dump QPC information based on given criteria.
 *
 * @nbl_dev: Pointer to the NBL device structure.
 * @mask: The mask to decide which fields of the key to compare.
 * @key: The key data (containing vfid and qpn).
 * @data: The QPC data.
 *
 * Note:
 * - The highest nibble of the mask is 2.
 *   -- Hex digits 6-5 represent the vfid, FF dump all vfids.
 *   -- Hex digits 4-0 represent the QPN, FFFFF dump all QPs.
 */
static void nbl_dump_qpc_info(struct nbl_func_file *func_file, u32 mask, u8 *key, u8 *data)
{
	u32 key32 = be32_to_cpu(*(u32 *)key);
	u32 qpn;
	u8 vfid;
	u32 mask_qpn;
	u8 mask_vfid;

	qpn = (key32 >> 8) & 0x3FFFF;
	vfid = key32 >> 26;

	mask_qpn = mask & NBL_CACHE_QPCC_FIELDS_QPN_MASK;
	mask_vfid = (mask >> 20) & NBL_CACHE_QPCC_FIELDS_VFID_MASK;

	/* Check if the 6-5 hex digits are FF (dump all vfids)
	 * Check if the 4-0 hex digits are FFFFF (dump all QPs)
	 * or match based on vfid and qpn
	 */
	if (((mask & 0x0FF00000) == 0x0FF00000 && qpn == mask_qpn) ||
			((mask & 0x000FFFFF) == 0x000FFFFF && vfid == mask_vfid) ||
			(vfid == mask_vfid && qpn == mask_qpn) ||
			((mask & 0x0FFFFFFF) == 0x0FFFFFFF)) {
		pr_info("QPC INFO WRITE TO BUFFER: vfid[%d] qpn[%d]", vfid, qpn);
		write_to_file_buffer(func_file,
			"================vfid[%d] qpn[%d] qpc info================\n", vfid, qpn);
		nbl_dump_fields(func_file, data, NBL_DBG_DUMP_QPC);
	}
}

static void nbl_dump_mrtc_debug_info(struct nbl_device *nbl_dev, u32 mask, u8 *key, u8 *data)
{
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_func_file *func_file = &nbl_dev->func_dump_info->dump_func_file;
	u32 mkey = be32_to_cpu(*(u32 *)key);
	u8 vfid = mkey >> 26;

	mkey = (mkey >> 2) & 0xFFFFFF;
	if (mkey == (mask & 0xFFFFFF) || (mask & 0xFFFFFF) == 0) {
		pr_info("mrte cache key: 0x%x\n", mkey);
		nbl_dump_hex(rf, key, NBL_CACHE_KEY_BASE_SIZE);
		write_to_file_buffer(func_file,
			"================vfid[%d] mkey[%d] mrt info================\n", vfid, mkey);
		pr_info("mrte cache data:");
		nbl_dump_hex(rf, data, NBL_CACHE_MRTE_SIZE);
		nbl_dump_fields(func_file, data, NBL_DBG_DUMP_MRT);
	}
}

static void nbl_dump_mrt_key(struct nbl_func_file *func_file, u8 *key)
{
	u32 key32 = be32_to_cpu(*(u32 *)key);
	u8 vfid = key32 >> 26;
	u32 mkey = (key32 >> 2) & 0xFFFFFF;

	write_to_file_buffer(func_file,
		"================vfid[%d] mkey[%d] mrt info================\n", vfid, mkey);
}

static int nbl_hw_cache_handle(struct nbl_device *nbl_dev, int type, u32 mask,
	u8 *key, int key_len, u8 *data, int data_len)
{
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_func_file *dump_func_file = &nbl_dev->func_dump_info->dump_func_file;

	int ix, jx, kx;

	ix = 0;
	jx = 0;
	kx = 0;
	if (type == NBL_CACHE_QPCC) {
		while (ix < key_len) {
			if (key[ix + NBL_CACHE_QPCC_KEY_VLD_IX] & NBL_CACHE_QPCC_KEY_VLD_MSK) {

				if (mask & NBL_CACHE_QPCC_CC_DATA_MASK)
					nbl_dump_cc_debug_info(rf, mask, &key[ix], &data[jx]);
				else if (mask & NBL_CACHE_QPCC_FIELDS_MASK) {
					nbl_dump_qpc_info(
						dump_func_file, mask, &key[ix], &data[jx]);
				} else {
					nbl_dev_info(&rf->pcidev->dev, "qpc cache key:");
					nbl_dump_hex(rf, &key[ix], NBL_CACHE_KEY_BASE_SIZE);
					if (mask & NBL_CACHE_QPCC_DATA_MASK) {
						nbl_dev_info(&rf->pcidev->dev, "qpc cache data:");
						nbl_dump_hex(rf, &data[jx], NBL_CACHE_QPCC_SIZE);
						/* Write to cache_qpc */
						nbl_dump_fields(
							dump_func_file,
							&data[jx],
							NBL_DBG_DUMP_QPC
						);
					}
				}

				kx++;
			}
			ix += NBL_CACHE_KEY_BASE_SIZE;
			jx += NBL_CACHE_QPCC_SIZE;
		}
	} else if (type == NBL_CACHE_CQCC) {
		while (ix < key_len) {
			if (key[ix + NBL_CACHE_CQCC_KEY_VLD_IX] & NBL_CACHE_CQCC_KEY_VLD_MSK) {
				nbl_dev_info(&rf->pcidev->dev, "cqc cache key:");
				nbl_dump_hex(rf, &key[ix], NBL_CACHE_KEY_BASE_SIZE);
				if (mask & NBL_CACHE_CQCC_DATA_MASK) {
					nbl_dev_info(&rf->pcidev->dev, "cqc cache data:");
					nbl_dump_hex(rf, &data[jx], NBL_CACHE_CQCC_SIZE);
				}
				kx++;
			}
			ix += NBL_CACHE_KEY_BASE_SIZE;
			jx += NBL_CACHE_CQCC_SIZE;
		}
	} else if (type == NBL_CACHE_MRTC) {
		while (ix < key_len) {
			if (key[ix + NBL_CACHE_MRTE_KEY_VLD_IX] & NBL_CACHE_MRTE_KEY_VLD_MSK) {

				if (mask & NBL_CACHE_MRTE_MKEY_DUMP_MASK) {
					nbl_dump_mrtc_debug_info(
						nbl_dev, mask, &key[ix], &data[jx]);
				} else {
					nbl_dev_info(&rf->pcidev->dev, "mrte cache key:");
					nbl_dump_hex(rf, &key[ix], NBL_CACHE_KEY_BASE_SIZE);
					nbl_dump_mrt_key(dump_func_file, &key[ix]);
					if (mask & NBL_CACHE_MRTE_DATA_MASK) {
						nbl_dev_info(&rf->pcidev->dev, "mrte cache data:");
						nbl_dump_hex(rf, &data[jx], NBL_CACHE_MRTE_SIZE);
						nbl_dump_fields(
							dump_func_file,
							&data[jx],
							NBL_DBG_DUMP_MRT
						);
					}
				}

				kx++;
			}
			ix += NBL_CACHE_KEY_BASE_SIZE;
			jx += NBL_CACHE_MRTE_SIZE;
		}
	} else if (type == NBL_CACHE_PBLC) {
		while (ix < key_len) {
			if (key[ix + NBL_CACHE_PBLE_KEY_VLD_IX] & NBL_CACHE_PBLE_KEY_VLD_MSK) {
				nbl_dev_info(&rf->pcidev->dev, "pble cache key:");
				nbl_dump_hex(rf, &key[ix], NBL_CACHE_KEY_BASE_SIZE);
				if (mask & NBL_CACHE_PBLE_DATA_MASK) {
					nbl_dev_info(&rf->pcidev->dev, "pble cache data:");
					nbl_dump_hex(rf, &data[jx], NBL_CACHE_PBLE_SIZE);
				}
				kx++;
			}
			ix += NBL_CACHE_KEY_BASE_SIZE;
			jx += NBL_CACHE_PBLE_SIZE;
		}
	} else if (type == NBL_CACHE_SQRQEC) {
		while (ix < key_len) {
			if (key[ix + NBL_CACHE_SQRQE_KEY_VLD_IX] & NBL_CACHE_SQRQE_KEY_VLD_MSK) {
				nbl_dev_info(&rf->pcidev->dev, "sqrqe cache key:");
				nbl_dump_hex(rf, &key[ix], NBL_CACHE_KEY_BASE_SIZE);
				if (mask & NBL_CACHE_SQRQE_DATA_MASK) {
					nbl_dev_info(&rf->pcidev->dev, "sqrqe cache data:");
					nbl_dump_hex(rf, &data[jx], NBL_CACHE_SQRQE_SIZE);
				}
				kx++;
			}
			ix += NBL_CACHE_KEY_BASE_SIZE;
			jx += NBL_CACHE_SQRQE_SIZE;
		}
	} else if (type == NBL_CACHE_IRQEC) {
		while (ix < key_len) {
			if (key[ix + NBL_CACHE_IRQE_KEY_VLD_IX] & NBL_CACHE_IRQE_KEY_VLD_MSK) {
				nbl_dev_info(&rf->pcidev->dev, "irqe cache key:");
				nbl_dump_hex(rf, &key[ix], NBL_CACHE_KEY_BASE_SIZE);
				if (mask & NBL_CACHE_IRQE_DATA_MASK) {
					nbl_dev_info(&rf->pcidev->dev, "irqe cache data:");
					nbl_dump_hex(rf, &data[jx], NBL_CACHE_IRQE_SIZE);
				}
				kx++;
			}
			ix += NBL_CACHE_KEY_BASE_SIZE;
			jx += NBL_CACHE_IRQE_SIZE;
		}
	} else if (type == NBL_CACHE_RAQEC) {
		while (ix < key_len) {
			if (key[ix + NBL_CACHE_RAQE_KEY_VLD_IX] & NBL_CACHE_RAQE_KEY_VLD_MSK) {
				nbl_dev_info(&rf->pcidev->dev, "raqe cache key:");
				nbl_dump_hex(rf, &key[ix], NBL_CACHE_KEY_BASE_SIZE);
				if (mask & NBL_CACHE_RAQE_DATA_MASK) {
					nbl_dev_info(&rf->pcidev->dev, "raqe cache data:");
					nbl_dump_hex(rf, &data[jx], NBL_CACHE_RAQE_SIZE);
				}
				kx++;
			}
			ix += NBL_CACHE_KEY_BASE_SIZE;
			jx += NBL_CACHE_RAQE_SIZE;
		}
	}
	return kx;
}

int nbl_dump_hw_cache(struct nbl_device *nbl_dev, u32 dump_mask, enum nbl_cqp_cache_type type)
{
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	int err_code, ret;
	int ix, count;
	int query_once_num;
	int cache_type;
	int cache_data_size;
	int cache_deep;
	__be64 *in;
	u8 *ptr;
	u32 in_size = NBL_CMD_INPUT_SIZE;
	struct nbl_dma_mem key_buf;
	struct nbl_dma_mem data_buf;

	if (type == NBL_CACHE_QPCC) {
		query_once_num = NBL_CACHE_QPCC_NUM_ONCE;
		cache_type = NBL_CACHE_QPCC;
		cache_data_size = NBL_CACHE_QPCC_SIZE;
		cache_deep = NBL_CACHE_QPCC_DEEP;
	} else if (type == NBL_CACHE_CQCC) {
		query_once_num = NBL_CACHE_CQCC_NUM_ONCE;
		cache_type = NBL_CACHE_CQCC;
		cache_data_size = NBL_CACHE_CQCC_SIZE;
		cache_deep = NBL_CACHE_CQCC_DEEP;
	} else if (type == NBL_CACHE_MRTC) {
		query_once_num = NBL_CACHE_MRTE_NUM_ONCE;
		cache_type = type;
		cache_data_size = NBL_CACHE_MRTE_SIZE;
		cache_deep = NBL_CACHE_MRTE_DEEP;
	} else if (type == NBL_CACHE_PBLC) {
		query_once_num = NBL_CACHE_PBLE_NUM_ONCE;
		cache_type = type;
		cache_data_size = NBL_CACHE_PBLE_SIZE;
		cache_deep = NBL_CACHE_PBLE_DEEP;
	} else if (type == NBL_CACHE_SQRQEC) {
		query_once_num = NBL_CACHE_SQRQE_NUM_ONCE;
		cache_type = type;
		cache_data_size = NBL_CACHE_SQRQE_SIZE;
		cache_deep = NBL_CACHE_SQRQE_DEEP;
	} else if (type == NBL_CACHE_IRQEC) {
		query_once_num = NBL_CACHE_IRQE_NUM_ONCE;
		cache_type = type;
		cache_data_size = NBL_CACHE_IRQE_SIZE;
		cache_deep = NBL_CACHE_IRQE_DEEP;
	} else if (type == NBL_CACHE_RAQEC) {
		query_once_num = NBL_CACHE_RAQE_NUM_ONCE;
		cache_type = type;
		cache_data_size = NBL_CACHE_RAQE_SIZE;
		cache_deep = NBL_CACHE_RAQE_DEEP;
	} else {
		nbl_ib_err(sc_dev, "[cache] dump unknown hw cache\n");
		return 0;
	}
	nbl_dev_info(&rf->pcidev->dev, "[cache] dump hw cache with mask(0x%x)\n", dump_mask);

	data_buf.size = SZ_4K;
	data_buf.va =
		nbl_dma_alloc_coherent(sc_dev->hw->device, data_buf.size,
				       &data_buf.pa, GFP_KERNEL | __GFP_ZERO);
	if (!data_buf.va) {
		nbl_ib_err(sc_dev, "Error, dump cache allocate data buf no mem\n");
		return -ENOMEM;
	}

	key_buf.size = SZ_4K;
	key_buf.va =
		nbl_dma_alloc_coherent(sc_dev->hw->device, key_buf.size,
				       &key_buf.pa, GFP_KERNEL | __GFP_ZERO);
	if (!key_buf.va) {
		nbl_ib_err(sc_dev, "Error, dump cache allocate key buf no mem\n");
		return -ENOMEM;
	}

	in = kzalloc(in_size, GFP_KERNEL);
	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;

	ix = 0;
	count = 0;
	while (ix < cache_deep) {
		memset(key_buf.va, 0xff, key_buf.size);
		memset(data_buf.va, 0xff, data_buf.size);

		if (dump_mask & NBL_CACHE_DUMP_CQP_MASK)
			nbl_dev_info(&rf->pcidev->dev, "key pa[0x%llx], data pa[0x%llx], from %d to %d\n",
				key_buf.pa, data_buf.pa, ix, ix + query_once_num - 1);

		set_64bit_val(
			in, 0,
			FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_QUERY_CACHE) |
			FIELD_PREP(NBL_CQP_CACHE_TYPE, cache_type) |
			FIELD_PREP(NBL_CQP_START_INDEX, ix) |
			FIELD_PREP(NBL_CQP_KEY_NUM, query_once_num) |
			FIELD_PREP(NBL_CQP_UNIT_BNUM, cache_data_size));
		set_64bit_val(in, 8, key_buf.pa);
		set_64bit_val(in, 16, data_buf.pa);

		if (dump_mask & NBL_CACHE_DUMP_CQP_MASK) {
			ptr = (u8 *)in;
			nbl_dev_info(&rf->pcidev->dev,
				"[CQP  8-15]: %02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x\n",
				ptr[8], ptr[9], ptr[10], ptr[11], ptr[12],
				ptr[13], ptr[14], ptr[15]);
			nbl_dev_info(&rf->pcidev->dev,
				"[CQP 16-23]: %02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x\n",
				ptr[16], ptr[17], ptr[18], ptr[19], ptr[20],
				ptr[21], ptr[22], ptr[23]);
		}

		err_code = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);
		if (err_code) {
			nbl_ib_err(&rf->sc_dev, "%s cqp cmd failed,err=%d\n", __func__, err_code);
			break;
		}

		ret = nbl_hw_cache_handle(nbl_dev, cache_type, dump_mask,
					(u8 *)key_buf.va,
					(NBL_CACHE_KEY_BASE_SIZE * query_once_num),
					(u8 *)data_buf.va,
					(cache_data_size * query_once_num));
		count += ret;

		ix += query_once_num;
	}

	nbl_dev_info(&rf->pcidev->dev, "[cache] dump hw cache total valid num(%d)\n", count);

	dma_free_coherent(sc_dev->hw->device, key_buf.size, key_buf.va, key_buf.pa);
	dma_free_coherent(sc_dev->hw->device, data_buf.size, data_buf.va, data_buf.pa);
	kfree(in);

	return 0;
}

void nbl_clear_hw_cache(struct nbl_pci_f *rf, enum nbl_cqp_cache_type cache_type)
{
	int ret_val;
	u8 in[NBL_GRC_INPUT_SIZE] = {0};
	u8 out[NBL_GRC_OUTPUT_SIZE] = {0};
	u8 data_len = 0;
	struct grc_cache_msg_header *head;
	struct clear_cache_req req = {0};

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_CLEAR_CACHE;
	head->payload_len = sizeof(req);
	data_len += sizeof(struct grc_cache_msg_header);
	req.cache_type = cache_type;

	memcpy(in + data_len, &req, sizeof(req));
	data_len += sizeof(req);

	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val)
		nbl_pr_err("clear cache %d cmd err=%d", cache_type, ret_val);
}

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
#include "pble.h"
#include "cqp.h"
#include "hmc.h"
#include "grc.h"
#include "qp.h"
#include "counters.h"
#include "dump_fields.h"
#include "srq.h"
#include "nbl_rdma_module.h"

static u32 nbl_regs[NBL_MAX_REGS] = {
	NBL_REG_CQP_PI,
	NBL_REG_SQ_DB,
	NBL_REG_ARM_CQ,
	NBL_REG_CEQ0_CI,
	NBL_REG_AEQ_CI,
	NBL_REG_RQ_DB,
	NBL_REG_SRQ_DB0,
	NBL_REG_SRQ_DB1,
	NBL_REG_NOTIFY_OFFSET,
	NBL_REG_DWQE_OFFSET
};

static int nbl_init_hw(struct nbl_sc_dev *sc_dev);

static void nbl_get_global_msix_idx(struct nbl_pci_f *rf,
				    u16 global_msix_idx[], u16 msix_cnt)
{
	int i;
	struct nbl_core_export *core_info = (struct nbl_core_export *)rf->cdev;

	memcpy(global_msix_idx, core_info->global_vector_id, sizeof(u16) * msix_cnt);

	for (i = 0; i < msix_cnt; i++)
		nbl_dev_dbg(&rf->pcidev->dev, "RoCE get_global_msix_idx[%d]=%u",
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
	const struct nbl_product_desc *product = rf->product;
	struct msix_entry *pmsix;
	u16 *global_msix_idx;
	u32 i;
	size_t size;

	if (rf->msix_count < NBL_MSIX_COUNT_MIN) /* 0:aeq, others:ceq*/
		return NBL_ERR_NO_INTR;

	rf->msix_ceq_base_id = NBL_MSIX_ID_CEQ_BASE;
	if (rf->msix_count > num_online_cpus() + 1)
		rf->msix_count = num_online_cpus() + 1;

	global_msix_idx = kcalloc(rf->msix_count, sizeof(u16), GFP_KERNEL);
	if (!global_msix_idx)
		return NBL_ERR_NO_MEMORY;

	size = sizeof(struct nbl_msix_vector) * rf->msix_count;
	rf->nbl_msixtbl = kzalloc(size, GFP_KERNEL);
	if (!rf->nbl_msixtbl) {
		kfree(global_msix_idx);
		return NBL_ERR_NO_MEMORY;
	}

	product->irq_ops->get_global_msix_idx(rf, global_msix_idx,
					     rf->msix_count);

	pmsix = rf->msix_entries;
	for (i = 0; i < rf->msix_count; i++) {
		rf->nbl_msixtbl[i].idx = global_msix_idx[i];

		rf->nbl_msixtbl[i].irq = pmsix->vector;
		rf->nbl_msixtbl[i].cpu_affinity =
			cpumask_local_spread(i, dev_to_node(&rf->pcidev->dev));
		nbl_pr_dbg("save msix[%d] idx:%d irq:%d affinity:%d\n", i,
			   rf->nbl_msixtbl[i].idx, pmsix->vector,
			   rf->nbl_msixtbl[i].cpu_affinity);
		pmsix++;
	}
	kfree(global_msix_idx);
	return 0;
}

static enum nbl_status_code nbl_sc_dev_init(struct nbl_sc_dev *sc_dev,
				     struct nbl_device_init_info *info)
{
	sc_dev->hw = info->hw;
	sc_dev->hw->hw_addr = info->bar0;
	/* to do set other dev attr */
	sc_dev->hw_attrs.max_hw_outbound_msg_size = NBL_MAX_OUTBOUND_MSG_SIZE;
	sc_dev->hw_attrs.max_hw_inbound_msg_size = NBL_MAX_INBOUND_MSG_SIZE;

	return nbl_init_hw(sc_dev);
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
	} else {
		rf->product->lifecycle_ops->detect_caps(rf);
	}

	return status;
}

static enum nbl_status_code nbl_setup_init_state(struct nbl_pci_f *rf)
{
	enum nbl_status_code status;
	struct nbl_core_export *core_info = (struct nbl_core_export *)rf->cdev;

	status = nbl_save_msix_info(rf);
	if (status)
		return status;

	rf->hw.device = core_info->dma_dev;

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

u64 nbl_read_real_bar_base_addr(struct pci_dev *pdev)
{
	u32 val;
	u64 addr;

	pci_read_config_dword(pdev, PCI_BASE_ADDRESS_0, &val);
	addr = (u64)(val & PCI_BASE_ADDRESS_MEM_MASK);

	pci_read_config_dword(pdev, PCI_BASE_ADDRESS_0 + 4, &val);
	addr |= ((u64)val << 32);

	return addr;
}

struct df200_rdma_host_notify *df200_hn;

int nbl_df200_host_notify_init(void)
{
	df200_hn = kcalloc(1, sizeof(struct df200_rdma_host_notify), GFP_KERNEL);
	if (!df200_hn)
		return -ENOMEM;

	df200_hn->pfid_map_tbl_sel = 1;
	df200_hn->pfid_map_tbl_entries = 0;

	return 0;
}

void nbl_df200_host_notify_deinit(void)
{
	kfree(df200_hn);
	df200_hn = NULL;
}

static int rdma_pfid_map_entry_exist_idx(u64 target)
{
	u64 key;
	int ix;
	struct df200_rdma_host_notify *hn = df200_hn;

	if (hn->pfid_map_tbl_entries == 0)
		return -1;

	ix = 0;
	while (ix < hn->pfid_map_tbl_entries) {
		key = hn->pfid_map_tbl[ix].ddata & 0xFFFFFFFFFFFF;
		if (key == target)
			return ix;
		ix++;
	}

	return -1;
}

static void nbl_set_df200_host_notify(struct nbl_hw *hw, u16 idx,
				      union df200_host_rdma_pfid_map_tbl_reg *pfid_map_tbl)
{
	u64 reg_addr = DF200_HOST_RDMA_PFID_MAP_TABLE(idx);

	wr32_for_each(hw, reg_addr, pfid_map_tbl->data, sizeof(*pfid_map_tbl));
}

static void nbl_set_rdma_tbl_sel(struct nbl_hw *hw, u16 sel)
{
	u32 *value;
	union df200_rdma_tbl_sel_reg rdma_sel = {};

	rdma_sel.rdma_tbl_sel = sel;
	value = (u32 *)&rdma_sel;
	wr32(hw, DF200_HOST_RDMA_TBL_SEL, *value);
}

static void nbl_set_rdma_tbl_ready(struct nbl_hw *hw, u16 ready)
{
	u32 *value;
	union df200_rdma_tbl_ready_reg rdma_ready = {};

	rdma_ready.rdma_tbl_ready = ready;
	value = (u32 *)&rdma_ready;
	wr32(hw, DF200_HOST_RDMA_TBL_READY, *value);
}

static void df200_set_host_notify(struct nbl_hw *hw, u64 bar0_addr, u16 function_id, bool valid)
{
	union df200_host_rdma_pfid_map_tbl_reg invalid_entry;
	u64 notify_addr, key, op_key;
	int entry_hit;
	int entry;
	int next_pfid_base;
	struct df200_rdma_host_notify *hn = df200_hn;

	memset(&invalid_entry, 0xFF, sizeof(union df200_host_rdma_pfid_map_tbl_reg));
	notify_addr = bar0_addr + NBL_HOST_BAR0_HWADDR_OFFSET;
	op_key = (notify_addr & DF200_HOST_BAR_ADDR_MASK);

	entry_hit = rdma_pfid_map_entry_exist_idx(op_key);
	if (valid) {
		if (hn->pfid_map_tbl_entries == (DF200_HOST_PFID_MAX_TBL_ENTRY / 2)) {
			nbl_pr_err("No enough pfid map entries left for df200\n");
			return;
		}

		if (entry_hit >= 0) {
			if (hn->pfid_map_tbl[entry_hit].key.vfid != function_id) {
				hn->pfid_map_tbl[entry_hit].ddata = 0;
				hn->pfid_map_tbl[entry_hit].key.bar_addr = (op_key >> 19);
				hn->pfid_map_tbl[entry_hit].key.vfid = function_id;
				goto update;
			} else
				return;
		}

		/* Move the bigger entries to the end to make room for the entries of dev */
		for (entry = hn->pfid_map_tbl_entries - 1; entry >= 0; entry--) {
			key = hn->pfid_map_tbl[entry].ddata & 0xFFFFFFFFFFFF;
			if (key > op_key)
				memcpy(&hn->pfid_map_tbl[entry + 1], &hn->pfid_map_tbl[entry],
				       sizeof(hn->pfid_map_tbl[0]));
			else
				break;
		}

		/* Fill the pfid map entry into the whole */
		hn->pfid_map_tbl[entry + 1].ddata = 0;
		hn->pfid_map_tbl[entry + 1].key.bar_addr = (op_key >> 19);
		hn->pfid_map_tbl[entry + 1].key.vfid = function_id;

		/* update total number */
		hn->pfid_map_tbl_entries++;
	} else {
		if (entry_hit < 0) {
			nbl_pr_warn("No pfid map entries matched!\n");
			return;
		}

		/* Move the bigger entries to the beginning to occupy the room of dev's entries */
		for (entry = 0; entry < hn->pfid_map_tbl_entries; entry++) {
			key = hn->pfid_map_tbl[entry].ddata & 0xFFFFFFFFFFFF;
			if (key > op_key)
				memcpy(&hn->pfid_map_tbl[entry - 1], &hn->pfid_map_tbl[entry],
				       sizeof(hn->pfid_map_tbl[0]));
		}
		/* update total number */
		hn->pfid_map_tbl_entries--;
	}

update:
	/* 3. Retrieve the next map table to be used */
	next_pfid_base = hn->pfid_map_tbl_sel ? DF200_HOST_PFID_MASTER_TBL_BASE :
			 DF200_HOST_PFID_SLAVE_TBL_BASE;

	/* 4. Write the updated qid_map_tbl into HW */
	for (entry = 0; entry < (DF200_HOST_PFID_MAX_TBL_ENTRY / 2); entry++) {
		if (entry < hn->pfid_map_tbl_entries) {
			nbl_set_df200_host_notify(hw, entry + next_pfid_base,
						  &hn->pfid_map_tbl[entry]);
			nbl_pr_dbg("set rdma pfid table entry %d, val 0x%x, 0x%x\n",
				   next_pfid_base + entry,
				   hn->pfid_map_tbl[entry].data[0],
				   hn->pfid_map_tbl[entry].data[1]);
		} else {
			/* Invalid the rest of map tbl entries */
			nbl_set_df200_host_notify(hw, entry + next_pfid_base,
						  &invalid_entry);
			nbl_pr_dbg("set rdma pfid table entry %d, val 0x%x, 0x%x\n",
				   next_pfid_base + entry,
				   invalid_entry.data[0], invalid_entry.data[1]);
		}
	}

	/* 5. Write tbl select and ready into HW */
	hn->pfid_map_tbl_sel ^= 1;
	nbl_set_rdma_tbl_sel(hw, hn->pfid_map_tbl_sel);
	nbl_set_rdma_tbl_ready(hw, 1);
}

int nbl_notify_set_direct(struct nbl_pci_f *rf, bool valid)
{
	const struct nbl_product_desc *product = rf->product;
	u64 bar0_addr;
	struct nbl_core_export *core_info = (struct nbl_core_export *)rf->cdev;

	bar0_addr = nbl_read_real_bar_base_addr(rf->pcidev);
	if (product->host_id == HOST_ID_TYPE_ECPU)
		rf->hw.hw_ops->set_hw_ecpu_notify(&rf->hw, rf->sc_dev.function_id,
						  bar0_addr, valid);
	if (product->host_id == HOST_ID_TYPE_HOST &&
	    product->product_type == PRODUCT_TYPE_DPU) {
		bar0_addr = core_info->real_hw_addr;
		df200_set_host_notify(&rf->hw, bar0_addr, rf->sc_dev.function_id, valid);
	}

	return 0;
}

int nbl_set_notify_bar_addr(struct nbl_pci_f *rf, bool valid)
{
	void *reg_addr;
	u32 regval;
	u32 notify_bar_offset[] = {
		NBL_RDMA_PF0_BAR_ADDR_REG,
		NBL_RDMA_PF1_BAR_ADDR_REG,
		NBL_RDMA_PF2_BAR_ADDR_REG,
		NBL_RDMA_PF3_BAR_ADDR_REG
	};

	if (rf->sc_dev.function_id >= rf->sc_dev.pf_count) {
		nbl_ib_warn(&rf->sc_dev, "invalid rdma function_id=%u", rf->sc_dev.function_id);
		return -EINVAL;
	}

	if (rf->sc_dev.pf_count == 1) {
		/* RNIC 1 * 400 use old method, and change to valid when
		 * we got hw change 1*400 notify version.
		 */
		if (valid)
			wr32(&rf->hw, NBL_RDMA_PF0_BAR_ADDR_REG, NBL_RDMA_BAR_ADDR_VALUE);
		else
			wr32(&rf->hw, NBL_RDMA_PF0_BAR_ADDR_REG, NBL_RDMA_BAR_ADDR_INVALID_VALUE);
	} else {
		/* RNIC 2 * 200 use valid control notify */
		reg_addr = rf->hw.hw_addr + notify_bar_offset[rf->sc_dev.function_id];
		regval = readl(reg_addr);
		if (valid)
			regval |= BIT(31);
		else
			regval &= ~BIT(31);
		writel(regval, reg_addr);
	}

	return 0;
}

int nbl_notify_set_via_channel(struct nbl_pci_f *rf, bool valid)
{
	u8 in[NBL_GRC_INPUT_SIZE];
	u8 out[NBL_GRC_OUTPUT_SIZE];
	int data_len = 0;
	struct notify_info_req req = {};
	int ret_val;
	struct grc_cache_msg_header *head;
	struct nbl_core_export *core_info = (struct nbl_core_export *)rf->cdev;

	head = (struct grc_cache_msg_header *)in;

	if (sizeof(req) > NBL_GRC_INPUT_PAYLOAD_SIZE) {
		nbl_pr_err("hw init notify payload size invalid\n");
		return -EINVAL;
	}

	req.function_id = rf->sc_dev.function_id;
	req.host_id = rf->product->host_id;
	req.product_type = rf->product->product_type;
	req.valid = valid ? 1 : 0;
	req.pcie_fn_id = rf->sc_dev.pcie_fn_id;

	req.bar0_phy_addr = core_info->real_hw_addr;

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

int nbl_notify_set(struct nbl_pci_f *rf, bool valid)
{
	if (WARN_ON(!rf->product))
		return -EINVAL;

	return rf->product->lifecycle_ops->set_notify(rf, valid);
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
 * allocated in nbl_setup_init_state (INITIAL_STATE stage)
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

/* free memory allocated in nbl_initialize_hw_rsrc (HW_RSRC_INITIALIZED stage) */
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
	case GLOBAL_Q_INITED:
		nbl_global_q_deinit(rf);
		fallthrough;
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

		nbl_cqp_v2_flush_s1_cache_cmd(0, rf->sc_dev.function_id, rf, true);
		status = nbl_initialize_hw_rsrc(rf);
		if (status)
			break;
		rf->init_state = HW_RSRC_INITIALIZED;

		status = nbl_init_qps(rf);
		if (status)
			break;
		rf->init_state = QP_INITED;

		status = nbl_global_q_init(rf);
		if (status)
			break;
		rf->init_state = GLOBAL_Q_INITED;
		nbl_set_vf_pf_map(rf);

		return 0;
	} while (0);

	dev_err(&rf->pcidev->dev,
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
	case CLEANUP_WQ_CREAT:
		destroy_workqueue(nbl_dev->rf->cleanup_wq);
		fallthrough;
	case PBLE_CHUNK_MEM:
		nbl_hmc_deinit_pble(nbl_dev->rf);
		fallthrough;
	case AEQ_CREATED:
		nbl_deinit_aeq(nbl_dev->rf);
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

		rf->cleanup_wq = alloc_workqueue("nbl_cleanup_wq",
			WQ_UNBOUND, WQ_UNBOUND_MAX_ACTIVE);
		if (!rf->cleanup_wq) {
			status = NBL_ERR_NO_MEMORY;
			break;
		}
		nbl_dev->init_state = CLEANUP_WQ_CREAT;

		nbl_get_used_rsrc(nbl_dev);

		nbl_dev->device_cap_flags = IB_DEVICE_MEM_WINDOW |
					    IB_DEVICE_MEM_MGT_EXTENSIONS |
					    IB_DEVICE_RC_RNR_NAK_GEN |
					    IB_DEVICE_XRC;

		return 0;
	} while (0);

	dev_err(&rf->pcidev->dev,
		"HW runtime init FAIL status = %d last cmpl = %d\n", status,
		nbl_dev->init_state);
	nbl_rt_deinit_hw(nbl_dev);

	return status;
}

static void nbl_ena_rdma_vector_ctrl(struct nbl_pci_f *rf, u32 idx, bool flag)
{
	u32 regval;

	regval = readl(rf->hw.hw_addr +
		       IRQ_KERNEL_CTL(HOST_ID_TYPE_ECPU, idx));
	if (flag)
		regval = regval & (~NBL_PADAPT_IRQ_KERNEL_CTL_MASK);
	else
		regval = regval | NBL_PADAPT_IRQ_KERNEL_CTL_MASK;

	writel(regval, rf->hw.hw_addr +
		IRQ_KERNEL_CTL(HOST_ID_TYPE_ECPU, idx));
	nbl_pr_dbg(
		"enable msix_table reg_idx:%d, address:%#x val:%#x flag:%d\n",
		idx, IRQ_KERNEL_CTL(HOST_ID_TYPE_ECPU, idx), regval, flag);
}

static void nbl_ena_ecpu_vector_intrl(struct nbl_pci_f *rf, u32 idx, bool flag)
{
	u64 reg_addr;
	union nbl_padapt_msix_info_reg tbl = {};
	u8 devfn = rf->pcidev->devfn;
	u8 bus = rf->pcidev->bus->number;

	tbl.vh.intrl_pnum = 0;
	tbl.vh.intrl_rate = 0;
	tbl.vh.function_id = devfn & 0x7;
	tbl.vh.device_id = devfn >> 3;
	tbl.vh.bus_id = bus;
	tbl.vh.valid = flag ? 1 : 0;

	reg_addr = PADPT_MSIX_INFO_TBL(idx, NBL_VER_3);
	wr32_for_each(&rf->hw, reg_addr,
		      tbl.data, sizeof(tbl.data));

	nbl_ib_dbg(&rf->sc_dev,
		   "enable msix_info_table,reg_idx:%u address:0x%llx\n", idx,
		   reg_addr);
	nbl_ib_dbg(&rf->sc_dev, "val_low32:%#x,val_high32:%#x flag:%d\n",
		   tbl.data[0], tbl.data[1], flag);
}

static void nbl_ena_rnic400_vector_intrl(struct nbl_pci_f *rf, u32 idx,
					 bool flag)
{
	union nbl_padapt_msix_info_reg tbl = {};
	u8 devfn = rf->pcidev->devfn;
	u8 bus = rf->pcidev->bus->number;
	u64 reg_addr;

	tbl.vr.intrl_pnum = 0;
	tbl.vr.intrl_rate = 0;
	tbl.vr.function_id = devfn & 0x7;
	tbl.vr.device_id = devfn >> 3;
	tbl.vr.bus_id = bus;
	tbl.vr.mask_en = 0;
	tbl.vr.valid = flag ? 1 : 0;

	reg_addr = PADPT_MSIX_INFO_TBL(idx, NBL_VER_4);
	wr32_for_each(&rf->hw, reg_addr, tbl.data, sizeof(tbl.data));

	nbl_ib_dbg(&rf->sc_dev,
		   "enable msix_info_table,reg_idx:%u address:0x%llx\n", idx,
		   reg_addr);
	nbl_ib_dbg(&rf->sc_dev, "val_low32:%#x,val_high32:%#x flag:%d\n",
		   tbl.data[0], tbl.data[1], flag);
}

/**
 * nbl_df200_ecpu_disable_irq - Disable DF200 ECPU interrupt
 * @rf: pointer to the nbl_pci_f structure
 * @idx: vector index
 */
static void nbl_df200_ecpu_disable_irq(struct nbl_pci_f *rf, u32 idx)
{
	nbl_ena_ecpu_vector_intrl(rf, idx, false);
	nbl_ena_rdma_vector_ctrl(rf, idx, false);
}

static void nbl_unmask_irq(struct nbl_pci_f *rf, u32 idx)
{
	union nbl_padapt_msix_ctrl_reg msix_ctrl;

	memset(&msix_ctrl, 0, sizeof(msix_ctrl));

	writel(*((u32 *)&msix_ctrl.data[NBL_PADAPT_MSIX_CTRL_MASK_OFF]),
		rf->hw.hw_addr + NBL_MSIX_CTRL_TBL(idx) +
		NBL_PADAPT_MSIX_CTRL_MASK_OFF);
}

/**
 * nbl_df200_ecpu_enable_irq - Enable DF200 ECPU interrupt
 * @rf: pointer to the nbl_pci_f structure
 * @idx: vector index
 */
static void nbl_df200_ecpu_enable_irq(struct nbl_pci_f *rf, u32 idx)
{
	nbl_ena_ecpu_vector_intrl(rf, idx, true);
	nbl_ena_rdma_vector_ctrl(rf, idx, true);
}

static void nbl_host_irq_noop(struct nbl_pci_f *rf, u32 idx)
{
	(void)rf;
	(void)idx;
}

static void nbl_rnic400_disable_irq(struct nbl_pci_f *rf, u32 idx)
{
	nbl_ena_rnic400_vector_intrl(rf, idx, false);
}

static void nbl_rnic400_enable_irq(struct nbl_pci_f *rf, u32 idx)
{
	nbl_ena_rnic400_vector_intrl(rf, idx, true);
}

static bool nbl_legacy_aeq_qp_event_valid(u8 event_seq, int qp_seq)
{
	(void)event_seq;
	(void)qp_seq;

	return true;
}

static bool nbl_rnic400_aeq_qp_event_valid(u8 event_seq, int qp_seq)
{
	return event_seq == (qp_seq & NBL_AEQE_QP_SEQ_MASK);
}

const struct nbl_irq_ops nbl_df200_ecpu_irq_ops = {
	.get_global_msix_idx = nbl_get_global_msix_idx,
	.aeq_qp_event_valid = nbl_legacy_aeq_qp_event_valid,
	.nbl_dis_irq = nbl_df200_ecpu_disable_irq,
	.nbl_en_irq = nbl_df200_ecpu_enable_irq,
	.nbl_umask_irq = NULL,
};

const struct nbl_irq_ops nbl_host_irq_ops = {
	.get_global_msix_idx = nbl_get_global_msix_idx,
	.aeq_qp_event_valid = nbl_legacy_aeq_qp_event_valid,
	.nbl_dis_irq = nbl_host_irq_noop,
	.nbl_en_irq = nbl_host_irq_noop,
	.nbl_umask_irq = NULL,
};

const struct nbl_irq_ops nbl_rnic400_irq_ops = {
	.get_global_msix_idx = nbl_get_global_msix_idx,
	.aeq_qp_event_valid = nbl_rnic400_aeq_qp_event_valid,
	.nbl_dis_irq = nbl_rnic400_disable_irq,
	.nbl_en_irq = nbl_rnic400_enable_irq,
	.nbl_umask_irq = nbl_unmask_irq,
};

static u32 nbl_get_notify_offset(struct nbl_pci_f *rf)
{
	const struct nbl_product_desc *product = rf->product;
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	struct nbl_uk_attrs *uk_attrs = &sc_dev->hw_attrs.uk_attrs;

	if (product->host_id >= HOST_ID_TYPE_MAX ||
	    product->product_type >= PRODUCT_TYPE_MAX) {
		nbl_ib_err(sc_dev, "invalid params,host_id=%u,product_type=%u",
			   product->host_id, product->product_type);
		return NBL_INVALID_OFFSET;
	}

	if (product->host_id == HOST_ID_TYPE_ECPU)
		return NBL_ECPU_NOTIFY_OFFSET_v3;

	if (product->host_id == HOST_ID_TYPE_HOST) {
		if (product->product_type == PRODUCT_TYPE_SNIC) {
			if (nbl_product_cap_enabled(rf,
						    NBL_PRODUCT_CAP_PF_NOTIFY))
				return NBL_HOST_SNIC_RDMA_PF_NOTIFY;
			else if (uk_attrs->hw_rev == NBL_VER_4)
				return NBL_HOST_RNIC_RDMA_NOFITY_OFFSET;
			else
				return NBL_HOST_SNIC_RDMA_NOTIFY_OFFSET;
		}
		if (product->product_type == PRODUCT_TYPE_DPU)
			return NBL_HOST_NOTIFY_OFFSET;
	}

	return NBL_INVALID_OFFSET;
}

static u32 nbl_get_bar0_offset(struct nbl_pci_f *rf)
{
	const struct nbl_product_desc *product = rf->product;
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;

	if (product->host_id >= HOST_ID_TYPE_MAX ||
	    product->product_type >= PRODUCT_TYPE_MAX) {
		nbl_ib_err(sc_dev, "invalid params,host_id=%u,product_type=%u",
			   product->host_id, product->product_type);
		return NBL_INVALID_OFFSET;
	}

	if (product->host_id == HOST_ID_TYPE_ECPU)
		return NBL_ECPU_BAR0_HWADDR_OFFSET;

	if (product->host_id == HOST_ID_TYPE_HOST) {
		if (product->product_type == PRODUCT_TYPE_SNIC)
			return NBL_HOST_SNIC_BAR0_OFFSET;
		if (product->product_type == PRODUCT_TYPE_DPU)
			return NBL_HOST_BAR0_HWADDR_OFFSET;
	}

	return NBL_INVALID_OFFSET;
}

static int nbl_init_hw(struct nbl_sc_dev *sc_dev)
{
	int i;
	u32 offset0;
	u32 offset1;
	u32 dwqe_from_ntf;
	u8 __iomem *hw_addr;
	struct nbl_pci_f *rf = container_of(sc_dev, struct nbl_pci_f, sc_dev);
	u32 bdf_num = PCI_DEVID(rf->pcidev->bus->number, rf->pcidev->devfn);

	/* offset0: from bar0 to hw addr */
	offset0 = nbl_get_bar0_offset(rf);
	/* offset1: from hw addr to notify */
	offset1 = nbl_get_notify_offset(rf);
	if (offset0 == NBL_INVALID_OFFSET || offset1 == NBL_INVALID_OFFSET)
		return -EINVAL;

	/* only rnic400 dwqe from 0xff8000 + 256k */
	dwqe_from_ntf = (NBL_RF_TO_HW_VER(rf) == NBL_VER_4) ?
		NBL_RDMA_NORMAL_NOTF_WIDTH : NBL_ADAPTER_PAGE_SIZE;

	nbl_pr_dbg(
		"set notify regs for pcie_func_id %u, function_id=%u,bdf_num=0x%x,sc_dev->hw->hw_addr=%p",
		sc_dev->pcie_fn_id, sc_dev->function_id, bdf_num,
		sc_dev->hw->hw_addr);

	sc_dev->hw->notify_addr = ioremap(pci_resource_start(rf->pcidev, 0) +
					ALIGN_DOWN(offset0 + offset1, PAGE_SIZE), PAGE_SIZE);
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
				(void __iomem *)ALIGN((unsigned long)(hw_addr + offset0 + offset1 +
					dwqe_from_ntf), PAGE_SIZE);
		} else {
			/* calc addr from hw addr to notify, so base + offset1 + nbl_regs[] */
			if (!nbl_product_flag_enabled(rf, NBL_PRODUCT_F_CTRL_DEV) &&
			    PAGE_SIZE == SZ_64K)
				sc_dev->hw_regs[i] =
					(void __iomem *)(sc_dev->hw->notify_addr +
					VF_RDMA_START_OFFSET + nbl_regs[i]);
			else
				sc_dev->hw_regs[i] =
					(void __iomem *)(sc_dev->hw->notify_addr + nbl_regs[i]);
		}
	}

	sc_dev->irq_ops = rf->product->irq_ops;

	return NBL_SUCCESS;
}

static void nbl_set_hw_rsrc(struct nbl_pci_f *rf)
{
	struct nbl_res_table *cq_table = &rf->cq_table;

	rf->allocated_qps = (void *)rf->mem_rsrc;
	rf->allocated_cqs = &rf->allocated_qps[BITS_TO_LONGS(rf->max_qp)];
	rf->allocated_mrs = &rf->allocated_cqs[BITS_TO_LONGS(rf->max_cq)];
	rf->allocated_pds = &rf->allocated_mrs[BITS_TO_LONGS(rf->max_mr)];
	rf->allocated_ahs = &rf->allocated_pds[BITS_TO_LONGS(rf->max_pd)];
	rf->allocated_srq = &rf->allocated_ahs[BITS_TO_LONGS(rf->max_ah)];
	rf->allocated_xrcd = &rf->allocated_srq[BITS_TO_LONGS(rf->max_srq)];
	rf->allocated_dpage = &rf->allocated_xrcd[BITS_TO_LONGS(rf->max_xrcd)];
	rf->allocated_devx_umem = &rf->allocated_dpage[BITS_TO_LONGS(rf->max_dpage)];
	rf->qp_table =
		(struct nbl_qp **)(&rf->allocated_devx_umem[BITS_TO_LONGS(rf->max_devx_umem)]);
	rf->qp_seq_table = (int *)(&rf->qp_table[rf->max_qp]);
	rf->srq_table =
		(struct nbl_srq **)(&rf->qp_seq_table[rf->max_qp]);
	rf->srq_seq_table = (u8 *)(&rf->srq_table[rf->max_srq]);
	rf->devx_umem_table = (struct devx_umem **)(&rf->srq_seq_table[rf->max_srq]);
	rf->qp_return_ts = (u64 *)(&rf->devx_umem_table[rf->max_devx_umem]);

	memset(cq_table, 0, sizeof(*cq_table));
	spin_lock_init(&cq_table->lock);
	INIT_RADIX_TREE(&cq_table->tree, GFP_ATOMIC);

	spin_lock_init(&rf->rsrc_lock);
	spin_lock_init(&rf->qptable_lock);
	spin_lock_init(&rf->srqtable_lock);
	spin_lock_init(&rf->cq_arm_lock);
	spin_lock_init(&rf->devx_umem_table_lock);
}

static u32 nbl_calc_mem_rsrc_size(struct nbl_pci_f *rf)
{
	u32 rsrc_size = 0;

	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_qp);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_cq);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_mr);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_pd);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_ah);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_srq);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_xrcd);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_dpage);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_devx_umem);
	rsrc_size += sizeof(struct nbl_qp **) * rf->max_qp;
	rsrc_size += sizeof(struct nbl_srq **) * rf->max_srq;
	rsrc_size += sizeof(struct devx_umem **) * rf->max_devx_umem;
	rsrc_size += sizeof(int) * rf->max_qp;
	rsrc_size += sizeof(u64) * rf->max_qp;
	rsrc_size += sizeof(u8) * rf->max_srq;
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
	u32 max_function_id;

	rf->max_cqe = rf->sc_dev.hw_attrs.uk_attrs.max_hw_cq_size;
	rf->max_qp = rf->sc_dev.hmc_info->hmc_obj[NBL_HMC_QP].cnt;
	rf->max_cq = rf->sc_dev.hmc_info->hmc_obj[NBL_HMC_CQ].cnt;
	rf->max_mr = rf->sc_dev.hmc_info->hmc_obj[NBL_HMC_MR].cnt;
	rf->max_pd = rf->sc_dev.hw_attrs.max_hw_pds;
	rf->max_ah = rf->sc_dev.hw_attrs.max_hw_ahs;
	rf->max_srq = rf->sc_dev.hmc_info->hmc_obj[NBL_HMC_SRQ].cnt;
	/* max xrc domain number is equal to srq number, because one
	 * srq is bond to one xrc domain, in the max case, need xrc
	 * domain number equal to srq number.
	 */
	rf->max_xrcd = rf->sc_dev.hmc_info->hmc_obj[NBL_HMC_SRQ].cnt;
	rf->max_devx_umem = rf->init_params.devx_umem_num;

	/* rnic400 dwqe from 0xff8000 + 256K, so always 64k align */
	if (NBL_RF_TO_HW_VER(rf) != NBL_VER_4 && PAGE_SIZE == SZ_64K) {
		if (nbl_product_flag_enabled(rf, NBL_PRODUCT_F_CTRL_DEV)) {
			rf->max_dpage = NBL_MAX_DPAGE;
			rf->start_dpage = (PAGE_SIZE - RDMA_NORMAL_NOTIFY_SIZE) / NBL_DPAGE_SIZE;
		} else {
			rf->max_dpage = (VF_RDMA_BAR_SIZE - RDMA_NORMAL_NOTIFY_SIZE) /
					NBL_DPAGE_SIZE;
			rf->start_dpage =
				(u32)(PAGE_SIZE - RDMA_NORMAL_NOTIFY_SIZE - VF_RDMA_START_OFFSET) /
				NBL_DPAGE_SIZE;
		}
		rf->next_dpage = rf->start_dpage;
	} else {
		rf->max_dpage = NBL_MAX_DPAGE;
		rf->start_dpage = 0;
		rf->next_dpage = 0;
	}

	rsrc_size = nbl_calc_mem_rsrc_size(rf);
	rf->mem_rsrc = vzalloc(rsrc_size);
	if (!rf->mem_rsrc) {
		nbl_ib_err(&rf->sc_dev, "failed vzalloc mem for rsrc");
		return NBL_ERR_ALLOCMEM_FAILED;
	}

	nbl_set_hw_rsrc(rf);
	set_bit(NBL_QP_NUM_FOR_RSV, rf->allocated_qps); /* qp num 0 is reserve */
	set_bit(NBL_QP_NUM_FOR_CM, rf->allocated_qps); /* qp num 1 is cm use */
	set_bit(NBL_QP_NUM_FOR_DUMP, rf->allocated_qps);
	set_bit(0, rf->allocated_mrs);
	set_bit(0, rf->allocated_pds);
	set_bit(0, rf->allocated_ahs);
	set_bit(0, rf->allocated_srq);
	if (NBL_RF_TO_HW_VER(rf) == NBL_VER_2 && rf->sc_dev.function_id == 0) {
		max_function_id = NBL_RDMA_MAX_FUNCTION_ID(NBL_RF_TO_HW_VER(rf));
		bitmap_set(rf->allocated_qps, NBL_QP_NUM_FOR_RSV, max_function_id + 1);
		bitmap_set(rf->allocated_cqs, 0, max_function_id + 1);
		bitmap_set(rf->allocated_mrs, 0, max_function_id + 1);
		bitmap_set(rf->allocated_srq, 0, max_function_id + 1);
	}
	memset(rf->qp_seq_table, 0, sizeof(int) * rf->max_qp);
	memset(rf->srq_seq_table, 0, sizeof(u8) * rf->max_srq);

	nbl_ib_dbg(&rf->sc_dev, "[rsrc]: max_qp(%u), max_cq(%u), max_mr(%u), max_pd(%u)\n",
		rf->max_qp, rf->max_cq, rf->max_mr, rf->max_pd);
	nbl_ib_dbg(&rf->sc_dev, "max_ah(%u), max_cqe(%u), max_srq(%u), max_xrcd(%u)\n",
		rf->max_ah, rf->max_cqe, rf->max_srq, rf->max_xrcd);

	return NBL_SUCCESS;
}

enum nbl_status_code nbl_init_qps(struct nbl_pci_f *rf)
{
	sema_init(&rf->qp_flush_sem, NBL_HW_FLUSH_CNT);

	rf->flush_wq = alloc_workqueue("nbl_flush_wq",
						WQ_UNBOUND | WQ_MEM_RECLAIM,
						WQ_UNBOUND_MAX_ACTIVE);
	if (!rf->flush_wq) {
		nbl_ib_err(&rf->sc_dev, "alloc flush work queue failed\n");
		return NBL_ERR_NO_MEMORY;
	}

	return NBL_SUCCESS;
}

void nbl_deinit_qps(struct nbl_pci_f *rf)
{
	destroy_workqueue(rf->flush_wq);
}

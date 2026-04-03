// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt)	"ubus resource: " fmt

#include <linux/io.h>
#include <linux/mm.h>
#include <linux/resource_ext.h>

#include "ubus.h"
#include "msg.h"
#include "decoder.h"
#include "resource.h"

struct query_token_msg_pld_req {
	u32 token_enable : 1;
	u32 reserved : 31;
};
#define QUERY_TOKEN_MSG_REQ_PLD_SIZE 4
#define QUERY_TOKEN_MSG_REQ_SIZE 36

struct query_token_msg_pld_rsp {
	u32 token_id : 20;
	u32 reserved : 12;
	u32 token_value;
};
#define QUERY_TOKEN_MSG_RSP_SIZE 40

struct query_token_msg_pld {
	union {
		struct query_token_msg_pld_req req;
		struct query_token_msg_pld_rsp rsp;
	};
};

struct query_token_msg_pkt {
	struct msg_pkt_header header;
	struct query_token_msg_pld pld;
};

static const struct vm_operations_struct ub_phys_vm_ops = {
	.access = generic_access_phys,
};

int ub_mmap_resource_range(struct ub_entity *uent, unsigned long idx,
			   struct vm_area_struct *vma, int write_combine)
{
	resource_size_t size;

	size = ((ub_resource_len(uent, idx) - 1) >> PAGE_SHIFT) + 1;
	if (vma->vm_pgoff + vma_pages(vma) > size)
		return -EINVAL;

	if (write_combine)
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
	else
		vma->vm_page_prot = pgprot_device(vma->vm_page_prot);

	vma->vm_pgoff += (ub_resource_start(uent, idx) >> PAGE_SHIFT);
	vma->vm_ops = &ub_phys_vm_ops;

	return io_remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
				  vma->vm_end - vma->vm_start,
				  vma->vm_page_prot);
}

static int _ub_assign_resource(struct ub_entity *uent, int idx,
			       resource_size_t size, resource_size_t align)
{
	struct resource *res;
	struct resource_entry *entry, *tmp;
	struct resource *uent_res = &uent->zone[idx].res;
	struct ub_bus_controller *ubc = uent->ubc;
	int ret = -EINVAL;

	if (ubc == NULL) {
		ub_err(uent, "ub assign resource failed, ubc is NULL.\n");
		return -EINVAL;
	}

	resource_list_for_each_entry_safe(entry, tmp, &ubc->resources) {
		res = entry->res;

		if (!(res->flags & IORESOURCE_MEM) ||
		    !strstr(res->name, "UB_BUS_CTL"))
			continue;
		ret = allocate_resource(res, uent_res, size, 0, ~0, align, NULL,
					NULL);
		if (ret == 0)
			return 0;
	}
	ub_err(uent, "ub assign resource failed, no res available, ret = %d\n", ret);

	return -ENOMEM;
}

static int ub_assign_resource(struct ub_entity *uent, int idx)
{
	struct resource *res = &uent->zone[idx].res;
	resource_size_t size;
	resource_size_t page_size = PAGE_SIZE;
	/* decoder mapped address unit 1M */
	resource_size_t align = page_size > SZ_1M ? page_size : SZ_1M;
	int ret;

	res->name = ub_name(uent);
	res->flags |= IORESOURCE_UNSET | IORESOURCE_SIZEALIGN;
	size = uent->zone[idx].region.size;
	ret = _ub_assign_resource(uent, idx, size, align);
	if (ret < 0) {
		ub_err(uent, "RESOURCE %d: failed to assign, size=%#llx\n",
		       idx, size);
		return ret;
	}

	res->flags &= ~IORESOURCE_UNSET;
	res->flags &= ~IORESOURCE_STARTALIGN;
	ub_info(uent, "RESOURCE %d: assigned %pR\n", idx, res);

	return 0;
}

static void ub_release_resource(struct ub_entity *uent, int idx)
{
	int ret;

	if (uent->zone[idx].res.parent) {
		ret = release_resource(&uent->zone[idx].res);
		if (ret)
			ub_err(uent, "resource release failed, ret=%d.\n", ret);
	}
}

static void __iomem *ub_iomap_range(struct ub_entity *uent, int res_id,
				    unsigned long offset, unsigned long maxlen,
				    bool is_wc)
{
	resource_size_t start = ub_resource_start(uent, res_id);
	resource_size_t len = ub_resource_len(uent, res_id);
	unsigned long flags = ub_resource_flags(uent, res_id);

	if (len <= offset || !start)
		return NULL;
	len -= offset;
	start += offset;
	if (maxlen && len > maxlen)
		len = maxlen;
	if (!(flags & IORESOURCE_MEM))
		return NULL;

	if (is_wc)
		return ioremap_wc(start, len);
	else
		return ioremap(start, len);
}

void __iomem *ub_iomap(struct ub_entity *uent, int res_id, unsigned long maxlen)
{
	if (res_id >= MAX_UB_RES_NUM || !uent)
		return NULL;

	return ub_iomap_range(uent, res_id, 0, maxlen, false);
}
EXPORT_SYMBOL_GPL(ub_iomap);

void __iomem *ub_iomap_wc(struct ub_entity *uent, int res_id, unsigned long maxlen)
{
	if (res_id >= MAX_UB_RES_NUM || !uent)
		return NULL;

	return ub_iomap_range(uent, res_id, 0, maxlen, true);
}
EXPORT_SYMBOL_GPL(ub_iomap_wc);

void ub_iounmap(void __iomem *addr)
{
	iounmap(addr);
}
EXPORT_SYMBOL_GPL(ub_iounmap);

static int ub_read_ubba_reg(struct ub_entity *uent, size_t pg_size, int idx)
{
	u32 addr_l_reg[MAX_UB_RES_NUM] = { UB_ERS0_UBBA_L, UB_ERS1_UBBA_L,
					   UB_ERS2_UBBA_L };
	u32 addr_h_reg[MAX_UB_RES_NUM] = { UB_ERS0_UBBA_H, UB_ERS1_UBBA_H,
					   UB_ERS2_UBBA_H };
	u32 ss_reg[MAX_UB_RES_NUM] = { UB_ERS0_SS, UB_ERS1_SS, UB_ERS2_SS };
	u32 hpa_l = 0, hpa_h = 0, size = 0;
	int ret;

	ret = ub_cfg_read_dword(uent, addr_l_reg[idx], &hpa_l);
	ret |= ub_cfg_read_dword(uent, addr_h_reg[idx], &hpa_h);
	ret |= ub_cfg_read_dword(uent, ss_reg[idx], &size);
	if (ret) {
		ub_err(uent, "read reg failed when request HPA resource\n");
		return -EINVAL;
	} else if (size == 0) {
		ub_err(uent, "size is 0 when request HPA resource\n");
		return -EINVAL;
	}

	uent->zone[idx].res.start = ubba_gen(hpa_h, hpa_l);
	uent->zone[idx].res.end =
		uent->zone[idx].res.start + ((u64)size * pg_size - 1);

	uent->zone[idx].res.flags = IORESOURCE_MEM;
	uent->zone[idx].res.name = ub_name(uent);
	uent->zone[idx].ubba_used = 1;

	ub_info(uent, "mmio idx %d, %pR\n", idx, &uent->zone[idx].res);
	return 0;
}

static int ub_read_sa_reg(struct ub_entity *uent, size_t pg_size, int idx)
{
	u32 sa_l_reg[MAX_UB_RES_NUM] = { UB_ERS0_SA_L, UB_ERS1_SA_L,
					 UB_ERS2_SA_L };
	u32 sa_h_reg[MAX_UB_RES_NUM] = { UB_ERS0_SA_H, UB_ERS1_SA_H,
					 UB_ERS2_SA_H };
	u32 ss_reg[MAX_UB_RES_NUM] = { UB_ERS0_SS, UB_ERS1_SS, UB_ERS2_SS };
	u32 sa_l = 0, sa_h = 0, size = 0;
	int ret;

	ret = ub_cfg_read_dword(uent, sa_l_reg[idx], &sa_l);
	ret |= ub_cfg_read_dword(uent, sa_h_reg[idx], &sa_h);
	ret |= ub_cfg_read_dword(uent, ss_reg[idx], &size);
	if (ret) {
		ub_err(uent, "read reg failed when request SA resource\n");
		return -EINVAL;
	} else if (size == 0) {
		ub_err(uent, "size is 0 when request SA resource\n");
		return -EINVAL;
	}

	/* Shift left 32 bits to get upper-bit address */
	uent->zone[idx].region.start = ((u64)sa_h << 32) | sa_l;
	uent->zone[idx].region.size = size * pg_size;
	uent->zone[idx].res.flags = IORESOURCE_MEM;
	uent->zone[idx].sa_used = 1;

	return 0;
}

static int ub_entity_read_mmio_idx(struct ub_entity *uent, int idx)
{
	struct ub_entity *pue;
	size_t pg_size = 0;

	/* ue to its mue, mue to Entity0, Entity0 use itself */
	pue = uent->pue;
	if (pue->entity_idx) /* to ensure Entity0 uent */
		pue = pue->pue;

	(void)ub_cfg_read_byte(uent, UB_SYS_PGS, (u8 *)&pg_size);
	if ((u8)pg_size & UB_SYS_PGS_SIZE)
		pg_size = SZ_64K;
	else
		pg_size = SZ_4K;

	if (pue->zone[idx].ubba_used)
		return ub_read_ubba_reg(uent, pg_size, idx);

	if (pue->zone[idx].sa_used)
		return ub_read_sa_reg(uent, pg_size, idx);

	return -EPERM;
}

int ub_insert_resource(struct ub_entity *dev, int idx)
{
	struct resource *res, *root = NULL;
	int ret;

	if (idx >= MAX_UB_RES_NUM)
		return -EINVAL;

	res = &dev->zone[idx].res;
	if (!(res->flags & IORESOURCE_MEM))
		return -EINVAL;

	root = &iomem_resource;

	ret = insert_resource(root, res);
	if (ret) {
		ub_warn(dev, "failed to claim uent resource %pR\n", res);
		return -ENOMEM;
	}

	return 0;
}

static int ub_entity_alloc_mmio_idx(struct ub_entity *dev, int idx)
{
	if (is_ibus_controller(dev) || is_idev(dev))
		return ub_insert_resource(dev, idx);
	return ub_assign_resource(dev, idx);
}

void ub_entity_free_mmio_idx(struct ub_entity *dev, int idx)
{
	ub_release_resource(dev, idx);
	dev->zone[idx].init_succ = 0;
	dev->zone[idx].ubba_used = 0;
	dev->zone[idx].sa_used = 0;
}

static void fill_decoder_map_info(struct ub_entity *uent, int idx,
				  struct decoder_map_info *info)
{
	info->pa = uent->zone[idx].res.start;
	info->uba = uent->zone[idx].region.start;
	info->size = uent->zone[idx].region.size;
	info->eid_low = uent->eid;
	info->eid_high = 0;
	info->tpg_num = is_primary(uent) ? uent->cna : uent->pue->cna;
	info->order_id = 0;
	info->order_type = 0;
	info->token_id = uent->token_id;
	info->token_value = uent->token_value;
	info->upi = uent->bi ? uent->bi->info.upi : 0;
	info->src_eid = uent->bi ? uent->bi->info.eid : 0;
}

static int ub_entity_decoder_map_mmio_idx(struct ub_entity *uent, int idx)
{
	struct decoder_map_info info = {};
	struct ub_decoder *decoder;
	int ret;

	fill_decoder_map_info(uent, idx, &info);
	decoder = is_primary(uent) ? uent->ubc->decoder :
				     uent->pue->ubc->decoder;

	ret = ub_decoder_map(decoder, &info);
	if (ret)
		ub_err(uent, "resource%d decoder map failed.\n", idx);

	info.token_value = 0;
	return ret;
}

static void ub_entity_decoder_unmap_mmio_idx(struct ub_entity *uent, int idx)
{
	struct ub_decoder *decoder;

	if (!uent->zone[idx].sa_used)
		return;

	decoder = is_primary(uent) ? uent->ubc->decoder :
				     uent->pue->ubc->decoder;
	if (ub_decoder_unmap(decoder, uent->zone[idx].res.start,
			     uent->zone[idx].region.size))
		ub_warn(uent, "resource%d decoder unmap failed.\n", idx);
}

static bool map_by_ubus(struct ub_entity *ent)
{
	struct ub_bus_controller *ubc = ent->ubc;
	u32 feature;
	int ret;

	ret = ub_cfg_read_dword(ubc->uent, UB_CFG1_SUPPORT_FEATURE_L, &feature);
	if (ret) {
		ub_err(ubc->uent, "read ub cfg1 support feature failed, ret=%d\n",
		       ret);
		return false;
	}
	return !(feature & UB_DECODER_JURIS);
}

void ub_entity_decoder_unmap_mmio(struct ub_entity *dev)
{
	int i;

	for (i = 0; i < MAX_UB_RES_NUM; i++)
		if (dev->zone[i].sa_used && dev->zone[i].init_succ &&
		    dev->zone[i].decoder_mapped) {
			ub_entity_decoder_unmap_mmio_idx(dev, i);
			dev->zone[i].decoder_mapped = 0;
		}
}

void ub_entity_decoder_map_mmio(struct ub_entity *dev)
{
	int i, ret;

	if (is_ibus_controller(dev))
		return;

	if (!map_by_ubus(dev))
		return;

	for (i = 0; i < MAX_UB_RES_NUM; i++) {
		if (!dev->zone[i].sa_used || !dev->zone[i].init_succ)
			continue;
		if (dev->zone[i].decoder_mapped) {
			ub_err(dev, "mmio idx[%d] has been mapped\n", i);
			continue;
		}
		ret = ub_entity_decoder_map_mmio_idx(dev, i);
		if (ret) {
			ub_err(dev, "failed to establish ommu map, mmio_idx=%d, size=%#lx, error_code=%d\n",
			       i, dev->zone[i].region.size, ret);
			goto fail;
		}
		dev->zone[i].decoder_mapped = 1;
	}

	return;
fail:
	for (i -= 1; i >= 0; i--) {
		ub_entity_decoder_unmap_mmio_idx(dev, i);
		dev->zone[i].decoder_mapped = 0;
	}
}

static int ub_query_token_rsp_handle(struct ub_entity *uent,
				     struct query_token_msg_pkt *pkt)
{
	struct query_token_msg_pld_rsp *rsp = &pkt->pld.rsp;

	if (pkt->header.msgetah.rsp_status != UB_MSG_RSP_SUCCESS) {
		ub_err(uent, "query token rsp, status=%#02x\n",
		       pkt->header.msgetah.rsp_status);
		return -EINVAL;
	}

	uent->token_id = rsp->token_id;
	uent->token_value = rsp->token_value;

	return 0;
}

static int ub_query_token_info(struct ub_entity *uent)
{
	struct message_device *mdev = uent->message->mdev;
	struct query_token_msg_pkt req_pkt = {};
	struct query_token_msg_pkt rsp_pkt = {};
	struct msg_info info = {};
	int ret;

	ub_msg_pkt_header_init(&req_pkt.header, uent,
			       QUERY_TOKEN_MSG_REQ_PLD_SIZE,
			       code_gen(UB_MSG_CODE_SEC, UB_TOKEN_CHECK_CFG,
					MSG_REQ), false);

	req_pkt.pld.req.token_enable = 1;
	message_info_init(&info, uent, &req_pkt, &rsp_pkt,
			  (QUERY_TOKEN_MSG_REQ_SIZE << MSG_REQ_SIZE_OFFSET) |
			   QUERY_TOKEN_MSG_RSP_SIZE);

	ret = message_sync_request(mdev, &info, req_pkt.header.msgetah.code);
	if (ret)
		return ret;

	return ub_query_token_rsp_handle(uent, &rsp_pkt);
}

static int ub_entity_writeback_addr(struct ub_entity *uent, int idx)
{
	u32 addr_l_reg[MAX_UB_RES_NUM] = { UB_ERS0_UBBA_L, UB_ERS1_UBBA_L,
					   UB_ERS2_UBBA_L };
	u32 addr_h_reg[MAX_UB_RES_NUM] = { UB_ERS0_UBBA_H, UB_ERS1_UBBA_H,
					   UB_ERS2_UBBA_H };
	u32 support_feature, ubba_l, ubba_h;
	int ret;

	if (!uent->zone[idx].sa_used)
		return 0;

	ret = ub_cfg_read_dword(uent, UB_CFG1_SUPPORT_FEATURE_L,
				&support_feature);
	if (ret) {
		ub_err(uent,
		       "read reg failed when request sup feature, ret=%d\n",
		       ret);
		return -EINVAL;
	}
	if (support_feature & UB_UBBAS_SUPPORT) {
		ubba_l = (u32)(uent->zone[idx].res.start);
		/* Shift right 32 bits to get upper-bit address */
		ubba_h = (u32)((uent->zone[idx].res.start) >> 32);
		ub_cfg_write_dword(uent, addr_l_reg[idx], ubba_l);
		ub_cfg_write_dword(uent, addr_h_reg[idx], ubba_h);
	}

	return 0;
}

int _ub_entity_setup_mmio(struct ub_entity *dev)
{
	int ret;
	int i;

	if (is_ibus_controller(dev)) {
		ub_info(dev, "now doesn't support ub bus controller mmio\n");
		return 0;
	}

	if (is_device(dev) && !is_p_device(dev)) {
		ret = ub_query_token_info(dev);
		if (ret) {
			ub_err(dev, "Token query failed\n");
			return ret;
		}
		ub_info(dev, "Token ID=%#x\n", dev->token_id);
	}

	for (i = 0; i < MAX_UB_RES_NUM; i++) {
		ret = ub_entity_read_mmio_idx(dev, i);
		if (ret)
			continue;

		ret = ub_entity_alloc_mmio_idx(dev, i);
		if (ret) {
			ub_err(dev,
			       "failed to alloc resource for mmio idx %d\n", i);
			goto fail;
		}

		/* Write back the address reg for the VM scenario capture. */
		ret = ub_entity_writeback_addr(dev, i);
		if (ret) {
			ub_err(dev,
			       "failed to write back address for mmio idx %d\n",
			       i);
			ub_entity_free_mmio_idx(dev, i);
			goto fail;
		}

		ub_info(dev, "MMIO[%d]: ubba=%#lx, size=%#llx, hpa=%#llx, wr attr=0, prefetchable=0, order type=0,\n",
			i, dev->zone[i].region.start, ub_resource_len(dev, i),
			dev->zone[i].res.start);
		dev->zone[i].init_succ = 1;
	}

	return 0;

fail:
	for (i -= 1; i >= 0; i--)
		if (dev->zone[i].init_succ)
			ub_entity_free_mmio_idx(dev, i);

	return ret;
}

int ub_entity_setup_mmio(struct ub_entity *uent)
{
	int i;

	for (i = 0; i < MAX_UB_RES_NUM; i++)
		if (!uent->zone[i].init_succ)
			break;

	if (i == MAX_UB_RES_NUM)
		return 0;

	return _ub_entity_setup_mmio(uent);
}

void ub_entity_unset_mmio(struct ub_entity *dev)
{
	int i;

	for (i = 0; i < MAX_UB_RES_NUM; i++)
		if (dev->zone[i].init_succ)
			ub_entity_free_mmio_idx(dev, i);
}

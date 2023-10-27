// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <common/driver.h>

enum {
	XSC_PAGES_CANT_GIVE	= 0,
	XSC_PAGES_GIVE		= 1,
	XSC_PAGES_TAKE		= 2
};

struct xsc_pages_req {
	struct xsc_core_device *xdev;
	u32	func_id;
	s16	npages;
	struct work_struct work;
};

struct fw_page {
	struct rb_node	rb_node;
	u64		addr;
	struct page	*page;
	u16		func_id;
};

struct xsc_query_pages_inbox {
	struct xsc_inbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_query_pages_outbox {
	struct xsc_outbox_hdr	hdr;
	u8			reserved[2];
	__be16			func_id;
	__be16			init_pages;
	__be16			num_pages;
};

struct xsc_manage_pages_inbox {
	struct xsc_inbox_hdr	hdr;
	__be16			rsvd0;
	__be16			func_id;
	__be16			rsvd1;
	__be16			num_entries;
	u8			rsvd2[16];
	__be64			pas[0];
};

struct xsc_manage_pages_outbox {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd0[2];
	__be16			num_entries;
	u8			rsvd1[20];
	__be64			pas[0];
};

static int insert_page(struct xsc_core_device *xdev, u64 addr, struct page *page, u16 func_id)
{
	struct rb_root *root = &xdev->dev_res->page_root;
	struct rb_node **new = &root->rb_node;
	struct rb_node *parent = NULL;
	struct fw_page *nfp;
	struct fw_page *tfp;

	while (*new) {
		parent = *new;
		tfp = rb_entry(parent, struct fw_page, rb_node);
		if (tfp->addr < addr)
			new = &parent->rb_left;
		else if (tfp->addr > addr)
			new = &parent->rb_right;
		else
			return -EEXIST;
	}

	nfp = kmalloc(sizeof(*nfp), GFP_KERNEL);
	if (!nfp)
		return -ENOMEM;

	nfp->addr = addr;
	nfp->page = page;
	nfp->func_id = func_id;

	rb_link_node(&nfp->rb_node, parent, new);
	rb_insert_color(&nfp->rb_node, root);

	return 0;
}

static struct page *remove_page(struct xsc_core_device *xdev, u64 addr)
{
	struct rb_root *root = &xdev->dev_res->page_root;
	struct rb_node *tmp = root->rb_node;
	struct page *result = NULL;
	struct fw_page *tfp;

	while (tmp) {
		tfp = rb_entry(tmp, struct fw_page, rb_node);
		if (tfp->addr < addr) {
			tmp = tmp->rb_left;
		} else if (tfp->addr > addr) {
			tmp = tmp->rb_right;
		} else {
			rb_erase(&tfp->rb_node, root);
			result = tfp->page;
			kfree(tfp);
			break;
		}
	}

	return result;
}

static int xsc_cmd_query_pages(struct xsc_core_device *xdev, u16 *func_id,
				s16 *pages, s16 *init_pages)
{
	struct xsc_query_pages_inbox	in;
	struct xsc_query_pages_outbox	out;
	int err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_PAGES);
	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err)
		return err;

	if (out.hdr.status)
		//return xsc_cmd_status_to_err(&out.hdr);
		return -EIO;

	if (pages)
		*pages = be16_to_cpu(out.num_pages);
	if (init_pages)
		*init_pages = be16_to_cpu(out.init_pages);
	*func_id = be16_to_cpu(out.func_id);

	return err;
}

static int give_pages(struct xsc_core_device *xdev, u16 func_id, int npages,
		      int notify_fail)
{
	struct xsc_manage_pages_inbox *in;
	struct xsc_manage_pages_outbox out;
	struct page *page;
	int inlen;
	u64 addr;
	int err;
	int i;

	inlen = sizeof(*in) + npages * sizeof(in->pas[0]);
	in = xsc_vzalloc(inlen);
	if (!in) {
		xsc_core_warn(xdev, "vzalloc failed %d\n", inlen);
		return -ENOMEM;
	}
	memset(&out, 0, sizeof(out));

	for (i = 0; i < npages; i++) {
		page = alloc_page(GFP_HIGHUSER);
		if (!page) {
			err = -ENOMEM;
			xsc_core_warn(xdev, "failed to allocate page\n");
			goto out_alloc;
		}
		addr = dma_map_page(&xdev->pdev->dev, page, 0,
				    PAGE_SIZE, DMA_BIDIRECTIONAL);
		if (dma_mapping_error(&xdev->pdev->dev, addr)) {
			xsc_core_warn(xdev, "failed dma mapping page\n");
			__free_page(page);
			err = -ENOMEM;
			goto out_alloc;
		}
		err = insert_page(xdev, addr, page, func_id);
		if (err) {
			xsc_core_err(xdev, "failed to track allocated page\n");
			dma_unmap_page(&xdev->pdev->dev, addr, PAGE_SIZE, DMA_BIDIRECTIONAL);
			__free_page(page);
			err = -ENOMEM;
			goto out_alloc;
		}
		in->pas[i] = cpu_to_be64(addr);
	}

	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_MANAGE_PAGES);
	in->hdr.opmod = cpu_to_be16(XSC_PAGES_GIVE);
	in->func_id = cpu_to_be16(func_id);
	in->num_entries = cpu_to_be16(npages);
	err = xsc_cmd_exec(xdev, in, inlen, &out, sizeof(out));
	xsc_core_dbg(xdev, "err %d\n", err);
	if (err) {
		xsc_core_warn(xdev, "func_id 0x%x, npages %d, err %d\n", func_id, npages, err);
		goto out_alloc;
	}
	xdev->dev_res->fw_pages += npages;

	if (out.hdr.status) {
		//err = xsc_cmd_status_to_err(&out.hdr);
		err = -EIO;
		if (err) {
			xsc_core_warn(xdev,
				"func_id 0x%x, npages %d, status %d\n",
				func_id, npages, out.hdr.status);
			goto out_alloc;
		}
	}

	xsc_core_dbg(xdev, "err %d\n", err);

	goto out_free;

out_alloc:
	if (notify_fail) {
		memset(in, 0, inlen);
		memset(&out, 0, sizeof(out));
		in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_MANAGE_PAGES);
		in->hdr.opmod = cpu_to_be16(XSC_PAGES_CANT_GIVE);
		if (xsc_cmd_exec(xdev, in, sizeof(*in), &out, sizeof(out)))
			xsc_core_warn(xdev, "\n");
	}
	for (i--; i >= 0; i--) {
		addr = be64_to_cpu(in->pas[i]);
		page = remove_page(xdev, addr);
		if (!page) {
			xsc_core_err(xdev, "BUG: can't remove page at addr 0x%llx\n",
				      addr);
			continue;
		}
		dma_unmap_page(&xdev->pdev->dev, addr, PAGE_SIZE, DMA_BIDIRECTIONAL);
		__free_page(page);
	}

out_free:
	xsc_vfree(in);
	return err;
}

static int reclaim_pages(struct xsc_core_device *xdev, u32 func_id, int npages,
			 int *nclaimed)
{
	struct xsc_manage_pages_inbox   in;
	struct xsc_manage_pages_outbox *out;
	struct page *page;
	int num_claimed;
	int outlen;
	u64 addr;
	int err;
	int i;

	memset(&in, 0, sizeof(in));
	outlen = sizeof(*out) + npages * sizeof(out->pas[0]);
	out = xsc_vzalloc(outlen);
	if (!out)
		return -ENOMEM;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_MANAGE_PAGES);
	in.hdr.opmod = cpu_to_be16(XSC_PAGES_TAKE);
	in.func_id = cpu_to_be16(func_id);
	in.num_entries = cpu_to_be16(npages);
	xsc_core_dbg(xdev, "npages %d, outlen %d\n", npages, outlen);
	err = xsc_cmd_exec(xdev, &in, sizeof(in), out, outlen);
	if (err) {
		xsc_core_err(xdev, "failed recliaming pages\n");
		goto out_free;
	}
	xdev->dev_res->fw_pages -= npages;

	if (out->hdr.status) {
		//err = xsc_cmd_status_to_err(&out->hdr);
		err = -EIO;
		goto out_free;
	}

	num_claimed = be16_to_cpu(out->num_entries);
	if (nclaimed)
		*nclaimed = num_claimed;

	for (i = 0; i < num_claimed; i++) {
		addr = be64_to_cpu(out->pas[i]);
		page = remove_page(xdev, addr);
		if (!page) {
			xsc_core_warn(xdev, "FW reported unknown DMA address 0x%llx\n", addr);
		} else {
			dma_unmap_page(&xdev->pdev->dev, addr, PAGE_SIZE, DMA_BIDIRECTIONAL);
			__free_page(page);
		}
	}

out_free:
	xsc_vfree(out);
	return err;
}

static void pages_work_handler(struct work_struct *work)
{
	struct xsc_pages_req *req = container_of(work, struct xsc_pages_req, work);
	struct xsc_core_device *xdev = req->xdev;
	int err = 0;

	if (req->npages < 0)
		err = reclaim_pages(xdev, req->func_id, -1 * req->npages, NULL);
	else if (req->npages > 0)
		err = give_pages(xdev, req->func_id, req->npages, 1);

	if (err)
		xsc_core_warn(xdev, "%s fail %d\n", req->npages < 0 ?
			       "reclaim" : "give", err);

	kfree(req);
}

void xsc_core_req_pages_handler(struct xsc_core_device *xdev, u16 func_id,
				 s16 npages)
{
	struct xsc_pages_req *req;

	req = kzalloc(sizeof(*req), GFP_ATOMIC);
	if (!req)
		return;

	req->xdev = xdev;
	req->func_id = func_id;
	req->npages = npages;
	INIT_WORK(&req->work, pages_work_handler);
	queue_work(xdev->dev_res->pg_wq, &req->work);
}

int xsc_satisfy_startup_pages(struct xsc_core_device *xdev)
{
	s16 init_pages;
	u16 func_id;
	int err;

	err = xsc_cmd_query_pages(xdev, &func_id, NULL, &init_pages);
	if (err)
		return err;

	xsc_core_dbg(xdev, "requested %d init pages for func_id 0x%x\n", init_pages, func_id);

	return give_pages(xdev, func_id, init_pages, 0);
}

static int optimal_reclaimed_pages(void)
{
	struct xsc_cmd_prot_block *block;
	struct xsc_cmd_layout *lay;
	int ret;

	ret = (sizeof(lay->in) + sizeof(block->data) -
	       sizeof(struct xsc_manage_pages_outbox)) / 8;

	return ret;
}

int xsc_reclaim_startup_pages(struct xsc_core_device *xdev)
{
	unsigned long end = jiffies + msecs_to_jiffies(5000);
	struct fw_page *fwp;
	struct rb_node *p;
	int err;

	do {
		p = rb_first(&xdev->dev_res->page_root);
		if (p) {
			fwp = rb_entry(p, struct fw_page, rb_node);
			err = reclaim_pages(xdev, fwp->func_id, optimal_reclaimed_pages(), NULL);
			if (err) {
				xsc_core_warn(xdev, "failed reclaiming pages (%d)\n", err);
				return err;
			}
		}
		if (time_after(jiffies, end)) {
			xsc_core_warn(xdev, "FW did not return all pages. giving up...\n");
			break;
		}
	} while (p);

	return 0;
}

int xsc_pagealloc_init(struct xsc_core_device *xdev)
{
	xdev->dev_res->page_root = RB_ROOT;
	xdev->dev_res->pg_wq = create_singlethread_workqueue("xsc_page_allocator");
	if (!xdev->dev_res->pg_wq)
		return -ENOMEM;

	return 0;
}

void xsc_pagealloc_cleanup(struct xsc_core_device *xdev)
{
	destroy_workqueue(xdev->dev_res->pg_wq);
}

int xsc_pagealloc_start(struct xsc_core_device *xdev)
{
	return 0;
}

void xsc_pagealloc_stop(struct xsc_core_device *xdev)
{
	flush_workqueue(xdev->dev_res->pg_wq);
}

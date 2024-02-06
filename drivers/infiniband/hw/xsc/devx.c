// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_verbs.h>
#include <rdma/uverbs_types.h>
#include <rdma/uverbs_ioctl.h>
#include <rdma/ib_umem.h>
#include "common/driver.h"
#include "xsc_ib.h"
#define UVERBS_MODULE_NAME xsc_ib
#include <rdma/uverbs_named_ioctl.h>
#include "user.h"

static struct xsc_ib_ucontext *devx_uattrs2uctx(struct uverbs_attr_bundle *attrs)
{
	return to_xucontext(ib_uverbs_get_ucontext(attrs));
}

static bool devx_is_general_cmd(void *in)
{
	struct xsc_inbox_hdr *hdr =
		(struct xsc_inbox_hdr *)in;
	u16 opcode = be16_to_cpu(hdr->opcode);

	switch (opcode) {
	case XSC_CMD_OP_QUERY_HCA_CAP:
		return true;
	default:
		return false;
	}
}

static int UVERBS_HANDLER(XSC_IB_METHOD_DEVX_OTHER)(struct uverbs_attr_bundle *attrs)
{
	struct xsc_ib_ucontext *c;
	struct xsc_ib_dev *dev;
	void *cmd_in = uverbs_attr_get_alloced_ptr(attrs, XSC_IB_ATTR_DEVX_OTHER_CMD_IN);
	int cmd_out_len = uverbs_attr_get_len(attrs, XSC_IB_ATTR_DEVX_OTHER_CMD_OUT);
	void *cmd_out;
	int err;

	c = devx_uattrs2uctx(attrs);
	if (IS_ERR(c))
		return PTR_ERR(c);
	dev = to_mdev(c->ibucontext.device);

	if (!devx_is_general_cmd(cmd_in))
		return -EINVAL;

	cmd_out = uverbs_zalloc(attrs, cmd_out_len);
	if (IS_ERR(cmd_out))
		return PTR_ERR(cmd_out);

	err = xsc_cmd_exec(dev->xdev, cmd_in,
			   uverbs_attr_get_len(attrs, XSC_IB_ATTR_DEVX_OTHER_CMD_IN),
			   cmd_out, cmd_out_len);
	if (err)
		return err;

	return uverbs_copy_to(attrs, XSC_IB_ATTR_DEVX_OTHER_CMD_OUT, cmd_out, cmd_out_len);
}

DECLARE_UVERBS_NAMED_METHOD(XSC_IB_METHOD_DEVX_OTHER,
			    UVERBS_ATTR_PTR_IN(XSC_IB_ATTR_DEVX_OTHER_CMD_IN,
					       UVERBS_ATTR_MIN_SIZE(sizeof(struct xsc_inbox_hdr)),
					       UA_MANDATORY,
					       UA_ALLOC_AND_COPY),
			    UVERBS_ATTR_PTR_OUT(XSC_IB_ATTR_DEVX_OTHER_CMD_OUT,
						UVERBS_ATTR_MIN_SIZE(sizeof(struct xsc_outbox_hdr)),
						UA_MANDATORY));

DECLARE_UVERBS_GLOBAL_METHODS(XSC_IB_OBJECT_DEVX,
			      &UVERBS_METHOD(XSC_IB_METHOD_DEVX_OTHER));

const struct uverbs_object_tree_def *xsc_ib_get_devx_tree(void)
{
	return NULL;
}

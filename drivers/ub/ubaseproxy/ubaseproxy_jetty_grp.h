/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#ifndef __UBASEPROXY_JETTY_GRP_H__
#define __UBASEPROXY_JETTY_GRP_H__

#include "ubaseproxy_dev.h"

struct ubaseproxy_jtg_key_words {
	u16 start_jetty_id;
	u8 jetty_number;
	u32 valid;
};

struct ubaseproxy_jetty_grp_ctx {
	u32 start_jetty_id : 16;
	u32 rsv : 11;
	u32 jetty_number : 5;
	u32 valid;
};

struct ubaseproxy_jtg_modify_info {
	u32 to_bind;
	u32 to_unbind;
	u32 old_valid;
	u32 new_valid;
	u8 old_jetty_num;
	u8 new_jetty_num;
};

int ubaseproxy_handle_create_jetty_grp_ctx_req(struct ubaseproxy_dev *udev,
					       struct ubase_proxy_req_msg *req);
int ubaseproxy_handle_destroy_jetty_grp_ctx_req(struct ubaseproxy_dev *udev,
						struct ubase_proxy_req_msg *req);
int ubaseproxy_handle_query_jetty_grp_ctx_req(struct ubaseproxy_dev *udev,
					      struct ubase_proxy_req_msg *req);
int ubaseproxy_handle_modify_jetty_grp_ctx_req(struct ubaseproxy_dev *udev,
					       struct ubase_proxy_req_msg *req);
#endif /* __UBASEPROXY_JETTY_GRP_H__ */

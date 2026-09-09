/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/*
 * Copyright (c) 2021 nebula-matrix Limited.
 */

#ifndef NBL_UDS_CLIENT_H
#define NBL_UDS_CLIENT_H

#include <linux/socket.h>
#include <linux/un.h>
#include "main.h"

#define NBL_RDMA_ECPU_UDS "rdma_ecpu_uds"
#define NBL_GRC_WQ_TIMEOUT_MSEC 60000 /* wait time work is being schduled */
#define NBL_GRC_TIMEOUT_MSEC 20 /* time for grc to finish a request */
#define NBL_GRC_GET_RESP_AGAIN (5 * NBL_GRC_TIMEOUT_MSEC) /* time for grc to get a resp again */
#define UDS_GET_RESP_MAX_TRY 1

int nbl_uds_send_msg_to_grc(struct nbl_grc *grc, void *buf, u16 buf_len);
int nbl_uds_get_resp_from_grc(struct nbl_grc *grc, void *buf, u16 buf_len);
int nbl_uds_client_init(struct nbl_grc *grc);
void nbl_uds_client_exit(struct nbl_grc *grc);

#endif /* NBL_UDS_CLIENT_H */

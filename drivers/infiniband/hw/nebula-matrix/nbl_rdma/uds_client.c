// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include "uds_client.h"
#include "grc.h"

static inline int is_grc_seq_same(u8 send_seq, u8 recv_seq)
{
	return (send_seq - 1 == recv_seq ||
		(send_seq == 0 && recv_seq == 0xFF)) ? 1 : 0;
}

int nbl_uds_send_msg_to_grc(struct nbl_grc *grc, void *buf, u16 buf_len)
{
	int ret;
	struct kvec iv;
	struct msghdr msg_hdr = {};

	iv.iov_base = buf;
	iv.iov_len = buf_len;

	ret = kernel_sendmsg(grc->client.sock, &msg_hdr, &iv, 1, buf_len);
	if (ret < 0) {
		nbl_pr_err("kernel_sendmsg to grc err=%d", ret);
		return ret;
	} else if (ret != buf_len) {
		nbl_pr_err("kernel_sendmsg to grc buf_len:%d, err=%d", buf_len, ret);
		return ret;
	}

	nbl_pr_dbg("send uds msg to grc len=%d", ret);
	return 0;
}

int nbl_uds_get_resp_from_grc(struct nbl_grc *grc, void *buf, u16 buf_len)
{
	int ret;
	struct kvec iv;
	struct msghdr msg_hdr = {};
	u8 buf_tmp[64] = {0};
	u8 seq_num;
	int i = 0;

	iv.iov_base = buf;
	iv.iov_len = buf_len;
	ret = kernel_recvmsg(grc->client.sock, &msg_hdr, &iv, 1, buf_len, MSG_DONTWAIT);
	while (1) {
		seq_num = ((u8 *)buf)[0];
		if (ret == NBL_GRC_OUTPUT_SIZE && is_grc_seq_same(grc->seq_num, seq_num))
			break;

		if ((ret == NBL_GRC_OUTPUT_SIZE && !is_grc_seq_same(grc->seq_num, seq_num)) ||
			ret == -EAGAIN){
			i++;
			if (i > UDS_GET_RESP_MAX_TRY) {
				nbl_pr_err("Err! the number of retries you want[%d] exceeds the MAX value(%d).",
					i, UDS_GET_RESP_MAX_TRY);
				return ret;
			}
			nbl_pr_notice("try again! uds resp msg. send_seq=%u recv_seq=%u ret=%d",
				grc->seq_num, seq_num, ret);
			msleep(NBL_GRC_GET_RESP_AGAIN);
			memset(iv.iov_base, 0, iv.iov_len);
			memset(&msg_hdr, 0, sizeof(msg_hdr));
			ret = kernel_recvmsg(grc->client.sock, &msg_hdr, &iv, 1, buf_len,
				MSG_DONTWAIT);
			continue;
		} else {
			nbl_pr_err("Err! uds resp msg. seq_num=%u ret=%d", grc->seq_num, ret);
			return ret;
		}
	}

	nbl_pr_dbg("OK! recv uds resp msg. send_seq:%u, recv_seq:%u", grc->seq_num, seq_num);
	memcpy(buf_tmp, (u8 *)buf + 1, buf_len - 1);
	memcpy(buf, buf_tmp, buf_len - 1);

	return 0;
}

int nbl_uds_client_init(struct nbl_grc *grc)
{
	int ret;
	struct sockaddr_un un;

	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	strscpy(un.sun_path + 1, NBL_RDMA_ECPU_UDS, sizeof(un.sun_path) - 1);

	ret = sock_create_kern(&init_net, AF_UNIX, SOCK_STREAM, 0, &grc->client.sock);
	if (ret) {
		pr_err("request socket failed,ret=%d", ret);
		return ret;
	}

	ret = kernel_connect(grc->client.sock, (struct sockaddr *)&un, sizeof(un), 0);
	if (ret) {
		pr_err("connect socket failed=%d", ret);
		return ret;
	}

	return 0;
}

#define NBL_GRC_DISCONN_STR "disconnect"
void nbl_uds_client_exit(struct nbl_grc *grc)
{
	u8 disconn_str[64] = {0};

	sprintf(disconn_str, "%s", NBL_GRC_DISCONN_STR);
	nbl_uds_send_msg_to_grc(grc, disconn_str, sizeof(disconn_str));

	sock_release(grc->client.sock);
}

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */
#include <linux/string.h>
#include <linux/overflow.h>
#include <linux/sunrpc/clnt.h>
#include <linux/nfs.h>
#include <linux/nfs_fs.h>
#include <linux/nfs_xdr.h>

#include "enfs_log.h"
#include "exten_call.h"
#include "enfs_config.h"
#include "enfs.h"

#define MAX_IPV6_ADDR_LEN (64)
#define ENFS_DNS_MAX_NAME_LEN 256
#define NUM0 0
#define NUM1 1
#define ENFS_SHARD_V1_XDR_SIZE 12
#define ENFS_SHARD_XDR_SIZE 8
#define ENFS_LIF_V1_XDR_SIZE 32
#define ENFS_LIF_XDR_SIZE 28
#define ENFS_LS_XDR_SIZE 12

typedef int (*ENfsDecodeFunc)(struct enfs_extend3_rsp **extend3ResOut, __be32 *p,
			      struct xdr_stream *xdrStream);
typedef int (*ENfsExtendOpDecode)(struct enfs_extend3_rsp **extend3ResOut, uint32_t version,
				  __be32 *p, struct xdr_stream *xdrStream);

struct enfs_extend_decode_proc {
	ENfsExtendOpDecode decodeFunc;
};

struct enfs_extend_version_func {
	ENfsDecodeFunc fsShardInfoFunc;
	ENfsDecodeFunc lifInfoFunc;
	ENfsDecodeFunc dnsInfoFunc;
	ENfsDecodeFunc lsVersionFunc;
};

static struct enfs_extend_decode_proc g_decodeFuncByOpCode[] = {
	[NFS3_GET_FSINFO_OP] = { .decodeFunc = EnfsGetFsInfoDecode },
	[NFS3_GET_LIF_VIEW_OP] = { .decodeFunc = EnfsGetLifInfoDecode },
	[NFS_ENFS_QUERY_DNS_OP] = { .decodeFunc = EnfsQueryDnsInfoDecode },
	[NFS3_GET_LS_VERSION_OP] = { .decodeFunc = EnfsGetLsIdDecode }
};

static struct enfs_extend_version_func g_decodeFuncByVersion[] = {
	[NUM0] = {
		  .fsShardInfoFunc = NfsExtendDecodeFsShardV1,
		  .lifInfoFunc = NfsExtendDecodeLifInfoV1,
		  .dnsInfoFunc = NfsExtendDecodeDnsInfoV1,
		   },
	[NUM1] = {
		  .fsShardInfoFunc = NfsExtendDecodeFsShardV1,
		  .lifInfoFunc = NfsExtendDecodeLifInfoV1,
		  .dnsInfoFunc = NfsExtendDecodeDnsInfoV1,
		  .lsVersionFunc = NfsExtendDecodeLsId,
		   },
};

static int
NfsExtendProcInfoExtendEncode(
	char *pbuf,
	int buflen,
	struct enfs_extend3_args *pObj)
{
	__be32 *start;
	struct xdr_buf xdrBuf;
	struct xdr_stream xdrStream;
	uint32_t opcode = 0;
	unsigned int quadlen;
	unsigned int padding;
	uint32_t len;

	xdr_buf_init(&xdrBuf, pbuf, buflen);
	xdrBuf.head[0].iov_len = 0;
	xdr_init_encode(&xdrStream, &xdrBuf, NULL, NULL);

	start = xdr_reserve_space(&xdrStream, 8);
	if (unlikely(!start))
		return -EINVAL;
	*start++ = cpu_to_be32(pObj->opcode);
	*start++ = cpu_to_be32(pObj->version);

	opcode = pObj->opcode;

	if (opcode == NFS3_GET_FSINFO_OP) {
		start = xdr_reserve_space(&xdrStream, sizeof(struct enfs_file_uuid));
		if (unlikely(!start))
			return -EMSGSIZE;
		len = sizeof(struct enfs_file_uuid) - sizeof(uint32_t);
		quadlen = XDR_QUADLEN(len);
		padding = (quadlen << 2) - len;
		memcpy(start, pObj->extend_args_u.Uuid.data, len);
		if (padding != 0)
			memset((char *)start + len, 0, padding);
		start += quadlen;
		*start++ = cpu_to_be32(pObj->extend_args_u.Uuid.dataLen);
		enfs_print_uuid(&pObj->extend_args_u.Uuid);
	}

	if (opcode == NFS3_GET_LIF_VIEW_OP) {
		start = xdr_reserve_space(
			&xdrStream, 8 + pObj->extend_args_u.lifArgs.ipNumber *
						    MAX_IPV6_ADDR_LEN);
		if (unlikely(!start))
			return -EMSGSIZE;
		*start++ = cpu_to_be32(pObj->extend_args_u.lifArgs.tenantId);
		*start++ = cpu_to_be32(pObj->extend_args_u.lifArgs.ipNumber);
		len = pObj->extend_args_u.lifArgs.ipNumber * MAX_IPV6_ADDR_LEN;
		quadlen = XDR_QUADLEN(len);
		padding = (quadlen << 2) - len;
		memcpy(start, pObj->extend_args_u.lifArgs.ipAddr, len);
		if (padding != 0)
			memset((char *)start + len, 0, padding);
		start += quadlen;
	}

	if (opcode == NFS_ENFS_QUERY_DNS_OP) {
		// 8 means dnsargs's type and count
		start = xdr_reserve_space(
			&xdrStream,
			8 + pObj->extend_args_u.dnsArgs.dnsNameCount *
					ENFS_DNS_MAX_NAME_LEN);
		if (unlikely(!start))
			return -EMSGSIZE;
		*start++ = cpu_to_be32(pObj->extend_args_u.dnsArgs.ipType);
		*start++ =
			cpu_to_be32(pObj->extend_args_u.dnsArgs.dnsNameCount);
		len = pObj->extend_args_u.dnsArgs.dnsNameCount *
		      ENFS_DNS_MAX_NAME_LEN;
		quadlen = XDR_QUADLEN(len);
		// 2 means Move two places to the left
		padding = (quadlen << 2) - len;
		memcpy(start, pObj->extend_args_u.dnsArgs.dnsName, len);
		if (padding != 0)
			memset((char *)start + len, 0, padding);
		start += quadlen;
	}

	return 0;
}

int NfsExtendDecodeFsShardV1(struct enfs_extend3_rsp **extend3ResOut, __be32 *p,
			     struct xdr_stream *xdrStream)
{
	uint32_t i;
	size_t extend3ResLen;
	uint64_t clusterId;
	uint32_t storagePoolId;
	uint32_t fsId;
	uint32_t tenantId;
	uint32_t shardNumber;
	struct enfs_extend3_rsp *extend3Res = NULL;

	p = xdr_inline_decode(xdrStream, 24);
	if (unlikely(p == NULL))
		return true;
	p = xdr_decode_hyper(p, &clusterId);
	storagePoolId = be32_to_cpup(p++);
	fsId = be32_to_cpup(p++);
	tenantId = be32_to_cpup(p++);
	shardNumber = be32_to_cpup(p++);
	if (shardNumber > MAX_SHARD_NUMBER_IN_CLUSTER_4FS)
		return -E2BIG;

	p = xdr_inline_decode(xdrStream,
			      size_mul(shardNumber, ENFS_SHARD_V1_XDR_SIZE));
	if (unlikely(p == NULL))
		return true;
	extend3ResLen = size_add(sizeof(*extend3Res),
				 size_mul(sizeof(struct enfs_shard_view_single),
					  shardNumber));
	extend3Res = kmalloc(extend3ResLen, GFP_KERNEL);
	if (extend3Res == NULL)
		return -ENOMEM;
	extend3Res->extend_res_u.fsInfo.clusterId = clusterId;
	extend3Res->extend_res_u.fsInfo.storagePoolId = storagePoolId;
	extend3Res->extend_res_u.fsInfo.fsId = fsId;
	extend3Res->extend_res_u.fsInfo.tenantId = tenantId;
	extend3Res->extend_res_u.fsInfo.num = shardNumber;
	for (i = 0; i < extend3Res->extend_res_u.fsInfo.num; i++) {
		p = xdr_decode_hyper(
			p, &extend3Res->extend_res_u.fsInfo.shardView[i].lsid);
		extend3Res->extend_res_u.fsInfo.shardView[i].cpuId =
			be32_to_cpup(p++);
	}
	*extend3ResOut = extend3Res;
	return 0;
}

int NfsExtendDecodeFsShard(struct enfs_extend3_rsp **extend3ResOut, __be32 *p,
			   struct xdr_stream *xdrStream)
{
	uint32_t i;
	size_t extend3ResLen;
	uint64_t clusterId;
	uint32_t storagePoolId;
	uint32_t fsId;
	uint32_t tenantId;
	uint32_t shardNumber;
	struct enfs_extend3_rsp *extend3Res = NULL;

	p = xdr_inline_decode(xdrStream, 24);
	if (unlikely(p == NULL))
		return true;
	p = xdr_decode_hyper(p, &clusterId);
	storagePoolId = be32_to_cpup(p++);
	fsId = be32_to_cpup(p++);
	tenantId = be32_to_cpup(p++);
	shardNumber = be32_to_cpup(p++);
	if (shardNumber > MAX_SHARD_NUMBER_IN_CLUSTER_4FS)
		return -E2BIG;

	p = xdr_inline_decode(xdrStream,
			      size_mul(shardNumber, ENFS_SHARD_XDR_SIZE));
	if (unlikely(p == NULL))
		return true;
	extend3ResLen = size_add(sizeof(*extend3Res),
				 size_mul(sizeof(struct enfs_shard_view_single),
					  shardNumber));
	extend3Res = kmalloc(extend3ResLen, GFP_KERNEL);
	if (extend3Res == NULL)
		return -ENOMEM;
	extend3Res->extend_res_u.fsInfo.clusterId = clusterId;
	extend3Res->extend_res_u.fsInfo.storagePoolId = storagePoolId;
	extend3Res->extend_res_u.fsInfo.fsId = fsId;
	extend3Res->extend_res_u.fsInfo.tenantId = tenantId;
	extend3Res->extend_res_u.fsInfo.num = shardNumber;
	for (i = 0; i < extend3Res->extend_res_u.fsInfo.num; i++) {
		p = xdr_decode_hyper(
			p, &extend3Res->extend_res_u.fsInfo.shardView[i].lsid);
		extend3Res->extend_res_u.fsInfo.shardView[i].cpuId =
			INVALID_CPU_ID;
	}
	*extend3ResOut = extend3Res;
	return 0;
}

int NfsExtendDecodeLifInfoV1(struct enfs_extend3_rsp **extend3ResOut, __be32 *p,
			     struct xdr_stream *xdrStream)
{
	uint32_t i;
	size_t extend3ResLen;
	uint32_t lifNum;
	struct enfs_extend3_rsp *extend3Res = NULL;

	p = xdr_inline_decode(xdrStream, 4);
	if (unlikely(p == NULL))
		return true;
	lifNum = be32_to_cpup(p++);
	if (lifNum > MAX_SUPPORTED_REMOTE_IP_COUNT)
		return -E2BIG;

	p = xdr_inline_decode(xdrStream,
			      size_mul(lifNum, ENFS_LIF_V1_XDR_SIZE));
	if (unlikely(p == NULL))
		return true;
	extend3ResLen = size_add(sizeof(*extend3Res),
				 size_mul(sizeof(struct enfs_lif_port_info_single),
					  lifNum));
	extend3Res = kmalloc(extend3ResLen, GFP_KERNEL);
	if (extend3Res == NULL)
		return -ENOMEM;
	extend3Res->extend_res_u.lifInfo.lifNumber = lifNum;
	for (i = 0; i < extend3Res->extend_res_u.lifInfo.lifNumber; i++) {
		extend3Res->extend_res_u.lifInfo.lifport[i].isfound =
			be32_to_cpup(p++);
		extend3Res->extend_res_u.lifInfo.lifport[i].workStatus =
			be32_to_cpup(p++);
		p = xdr_decode_hyper(
			p, &extend3Res->extend_res_u.lifInfo.lifport[i].lsId);
		extend3Res->extend_res_u.lifInfo.lifport[i].tenantId =
			be32_to_cpup(p++);
		p = xdr_decode_hyper(p, &extend3Res->extend_res_u.lifInfo
						 .lifport[i]
						 .homeSiteWwn);
		extend3Res->extend_res_u.lifInfo.lifport[i].cpuId =
			be32_to_cpup(p++);
	}
	*extend3ResOut = extend3Res;
	return 0;
}

int NfsExtendDecodeLifInfo(struct enfs_extend3_rsp **extend3ResOut, __be32 *p,
			   struct xdr_stream *xdrStream)
{
	uint32_t i;
	size_t extend3ResLen;
	uint32_t lifNum;
	struct enfs_extend3_rsp *extend3Res = NULL;

	p = xdr_inline_decode(xdrStream, 4);
	if (unlikely(p == NULL))
		return true;
	lifNum = be32_to_cpup(p++);
	if (lifNum > MAX_SUPPORTED_REMOTE_IP_COUNT)
		return -E2BIG;

	p = xdr_inline_decode(xdrStream,
			      size_mul(lifNum, ENFS_LIF_XDR_SIZE));
	if (unlikely(p == NULL))
		return true;
	extend3ResLen = size_add(sizeof(*extend3Res),
				 size_mul(sizeof(struct enfs_lif_port_info_single),
					  lifNum));
	extend3Res = kmalloc(extend3ResLen, GFP_KERNEL);
	if (extend3Res == NULL)
		return -ENOMEM;
	extend3Res->extend_res_u.lifInfo.lifNumber = lifNum;
	for (i = 0; i < extend3Res->extend_res_u.lifInfo.lifNumber; i++) {
		extend3Res->extend_res_u.lifInfo.lifport[i].isfound =
			be32_to_cpup(p++);
		extend3Res->extend_res_u.lifInfo.lifport[i].workStatus =
			be32_to_cpup(p++);
		p = xdr_decode_hyper(
			p, &extend3Res->extend_res_u.lifInfo.lifport[i].lsId);
		extend3Res->extend_res_u.lifInfo.lifport[i].tenantId =
			be32_to_cpup(p++);
		p = xdr_decode_hyper(p, &extend3Res->extend_res_u.lifInfo
						 .lifport[i]
						 .homeSiteWwn);
		extend3Res->extend_res_u.lifInfo.lifport[i].cpuId =
			INVALID_CPU_ID;
	}
	*extend3ResOut = extend3Res;
	return 0;
}

int NfsExtendDecodeDnsInfoV1(struct enfs_extend3_rsp **extend3ResOut, __be32 *p,
			     struct xdr_stream *xdrStream)
{
	uint32_t i;
	size_t extend3ResLen;
	uint32_t ipNumber;
	struct enfs_extend3_rsp *extend3Res = NULL;
	// 4 means dnsres's ipNumber
	p = xdr_inline_decode(xdrStream, 4);
	if (unlikely(p == NULL))
		return true;
	ipNumber = be32_to_cpup(p++);
	if (ipNumber == 0 || ipNumber > MAX_SUPPORTED_REMOTE_IP_COUNT)
		return -E2BIG;

	extend3ResLen = size_add(sizeof(*extend3Res),
				 size_mul(sizeof(struct enfs_dns_query_ip_info_single),
					  ipNumber));
	extend3Res = kmalloc(extend3ResLen, GFP_KERNEL);
	if (extend3Res == NULL)
		return -ENOMEM;

	extend3Res->extend_res_u.dnsQueryIpInfo.ipNumber = ipNumber;
	for (i = 0; i < extend3Res->extend_res_u.dnsQueryIpInfo.ipNumber; i++) {
		// 4 means dnsres's cpuid
		p = xdr_inline_decode(xdrStream, 4);
		if (unlikely(p == NULL)) {
			kfree(extend3Res);
			return true;
		}
		extend3Res->extend_res_u.dnsQueryIpInfo.ipInfo[i].cpuId =
			be32_to_cpup(p++);

		// 8 means dnsres's lsid
		p = xdr_inline_decode(xdrStream, 8);
		if (unlikely(p == NULL)) {
			kfree(extend3Res);
			return true;
		}
		p = xdr_decode_hyper(
			p,
			&extend3Res->extend_res_u.dnsQueryIpInfo.ipInfo[i].lsId);

		p = xdr_inline_decode(xdrStream, MAX_IPV6_ADDR_LEN);
		if (unlikely(p == NULL)) {
			kfree(extend3Res);
			return true;
		}
		memcpy(extend3Res->extend_res_u.dnsQueryIpInfo.ipInfo[i].ipAddr,
		       p, MAX_IPV6_ADDR_LEN);
		extend3Res->extend_res_u.dnsQueryIpInfo.ipInfo[i]
			.ipAddr[MAX_IPV6_ADDR_LEN - 1] = '\0';
	}
	*extend3ResOut = extend3Res;
	return 0;
}

int NfsExtendDecodeLsId(struct enfs_extend3_rsp **extend3ResOut, __be32 *p,
			struct xdr_stream *xdrStream)
{
	uint32_t i;
	size_t extend3ResLen;
	uint32_t lsNum;
	uint64_t clusterId;
	struct enfs_extend3_rsp *extend3Res = NULL;

	p = xdr_inline_decode(xdrStream, sizeof(uint32_t));
	if (unlikely(p == NULL))
		return -ENOMEM;
	lsNum = be32_to_cpup(p++);
	if (lsNum > MAX_GLOBAL_CTRL_NODE_NUM)
		return -E2BIG;

	p = xdr_inline_decode(xdrStream, 8);
	if (unlikely(p == NULL))
		return -ENOMEM;
	p = xdr_decode_hyper(p, &clusterId);

	p = xdr_inline_decode(xdrStream,
			      size_mul(lsNum, ENFS_LS_XDR_SIZE));
	if (unlikely(p == NULL))
		return -EBADMSG;
	extend3ResLen = size_add(sizeof(*extend3Res),
				 size_mul(sizeof(struct enfs_get_ls_version_single),
					  lsNum));
	extend3Res = kmalloc(extend3ResLen, GFP_KERNEL);
	if (extend3Res == NULL)
		return -ENOMEM;
	extend3Res->extend_res_u.lsView.num = lsNum;
	extend3Res->extend_res_u.lsView.clusterId = clusterId;
	for (i = 0; i < extend3Res->extend_res_u.lsView.num; i++) {
		extend3Res->extend_res_u.lsView.lsInfo[i].lsId =
			be32_to_cpup(p++);
		p = xdr_decode_hyper(
			p,
			&extend3Res->extend_res_u.lsView.lsInfo[i].lsVersion);
	}
	*extend3ResOut = extend3Res;
	return 0;
}

int EnfsGetFsInfoDecode(struct enfs_extend3_rsp **extend3ResOut, uint32_t version, __be32 *p,
			struct xdr_stream *xdrStream)
{
	int ret = 0;
	int decode_version = 0;
	ENfsDecodeFunc func = NULL;

	if (version < ENFS_SERVER_VERSION_BASE)
		ret = NfsExtendDecodeFsShard(extend3ResOut, p, xdrStream);
	else {
		decode_version = ((version > ENFS_SERVER_VERSION_BASE) &&
			  ((version - ENFS_SERVER_VERSION_BASE) >=
			   sizeof(g_decodeFuncByVersion) /
				   sizeof(struct enfs_extend_version_func))) ?
				 (sizeof(g_decodeFuncByVersion) /
					  sizeof(struct enfs_extend_version_func) -
				  1) :
				 version - ENFS_SERVER_VERSION_BASE;
		func = g_decodeFuncByVersion[decode_version].fsShardInfoFunc;
		if (!func) {
			enfs_log_error(
				"Enfs getFsShard deocde func is null, resp version:%u",
				version);
			return true;
		}
		ret = func(extend3ResOut, p, xdrStream);
	}
	return ret;
}

int EnfsGetLifInfoDecode(struct enfs_extend3_rsp **extend3ResOut, uint32_t version,
			 __be32 *p, struct xdr_stream *xdrStream)
{
	int ret = 0;
	int decode_version = 0;
	ENfsDecodeFunc func = NULL;

	if (version < ENFS_SERVER_VERSION_BASE)
		ret = NfsExtendDecodeLifInfo(extend3ResOut, p, xdrStream);
	else {
		decode_version = ((version > ENFS_SERVER_VERSION_BASE) &&
			  ((version - ENFS_SERVER_VERSION_BASE) >=
			   sizeof(g_decodeFuncByVersion) /
				   sizeof(struct enfs_extend_version_func))) ?
				 (sizeof(g_decodeFuncByVersion) /
					  sizeof(struct enfs_extend_version_func) -
				  1) :
				 version - ENFS_SERVER_VERSION_BASE;
		func = g_decodeFuncByVersion[decode_version].lifInfoFunc;
		if (!func) {
			enfs_log_error(
				"Enfs getLifInfo deocde func is null, resp version:%u",
				version);
			return true;
		}
		ret = func(extend3ResOut, p, xdrStream);
	}
	return ret;
}

int EnfsQueryDnsInfoDecode(struct enfs_extend3_rsp **extend3ResOut, uint32_t version,
			   __be32 *p, struct xdr_stream *xdrStream)
{
	int ret = 0;
	int decode_version = 0;
	ENfsDecodeFunc func = NULL;

	if (version < ENFS_SERVER_VERSION_BASE) {
		ret = true;
		enfs_log_error(
			"Enfs decode dnsInfo failed, server version(%u) unspported",
			version);
	} else {
		decode_version =
			((version > ENFS_SERVER_VERSION_BASE) &&
			 ((version - ENFS_SERVER_VERSION_BASE) >=
			  sizeof(g_decodeFuncByVersion) /
				  sizeof(struct enfs_extend_version_func))) ?
				(sizeof(g_decodeFuncByVersion) /
					 sizeof(struct enfs_extend_version_func) -
				 1) :
				version - ENFS_SERVER_VERSION_BASE;
		func = g_decodeFuncByVersion[decode_version].dnsInfoFunc;
		if (!func) {
			enfs_log_error(
				"Enfs getDnsInfo deocde func is null, resp version:%u",
				version);
			return true;
		}
		ret = func(extend3ResOut, p, xdrStream);
	}
	return ret;
}

int EnfsGetLsIdDecode(struct enfs_extend3_rsp **extend3ResOut, uint32_t version, __be32 *p,
		      struct xdr_stream *xdrStream)
{
	int ret = 0;
	int decode_version = 0;
	ENfsDecodeFunc func = NULL;

	if (version < ENFS_SERVER_VERSION_BASE) {
		ret = true;
		enfs_log_error(
			"Enfs decode dnsInfo failed, server version(%u) unspported",
			version);
	} else {
		decode_version =
			((version > ENFS_SERVER_VERSION_BASE) &&
			 ((version - ENFS_SERVER_VERSION_BASE) >=
			  sizeof(g_decodeFuncByVersion) /
				  sizeof(struct enfs_extend_version_func))) ?
				(sizeof(g_decodeFuncByVersion) /
					 sizeof(struct enfs_extend_version_func) -
				 1) :
				version - ENFS_SERVER_VERSION_BASE;
		func = g_decodeFuncByVersion[decode_version].lsVersionFunc;
		if (!func) {
			enfs_log_error(
				"Enfs getDnsInfo deocde func is null, resp version:%u",
				version);
			return true;
		}
		ret = func(extend3ResOut, p, xdrStream);
	}

	return ret;
}

int EnfsExtendDecodePreCheck(uint32_t version, uint32_t opCode)
{
	if ((opCode < 0) || (opCode >= (sizeof(g_decodeFuncByOpCode) /
					sizeof(struct enfs_extend_decode_proc)))) {
		enfs_log_error("Extend op decode pre check opcode(%u) failed.",
			       opCode);
		return -ENFS_NOT_SUPPORT;
	}
	return 0;
}

static int
NfsExtendProcInfoExtendDecode(
	char *buf, uint32_t bufLen,
	struct enfs_extend3_rsp **extend3ResOut)
{
	int ret = 0;
	__be32 *p;
	uint32_t opCode = 0;
	uint32_t version = 0;
	struct xdr_buf xdrBuf;
	struct xdr_stream xdrStream;
	ENfsExtendOpDecode func = NULL;

	xdr_buf_init(&xdrBuf, buf, bufLen);
	xdrBuf.len = bufLen;
	xdr_init_decode(&xdrStream, &xdrBuf, NULL, NULL);
	p = xdr_inline_decode(&xdrStream, 8);
	if (unlikely(p == NULL))
		return -EINVAL;
	opCode = be32_to_cpup(p++);
	version = be32_to_cpup(p++);

	ret = EnfsExtendDecodePreCheck(version, opCode);
	if (ret) {
		enfs_log_error("Enfs extend op decode pre check failed");
		return ret;
	}

	func = g_decodeFuncByOpCode[opCode].decodeFunc;
	if (!func) {
		enfs_log_error("Enfs deocde op(%u) func is null", opCode);
		return -EINVAL;
	}
	ret = func(extend3ResOut, version, p, &xdrStream);
	if (ret) {
		enfs_log_error(
			"enfs decode failed, opCode:%u, version:%u, ret:%d",
			opCode, version, ret);
		return ret;
	}

	return 0;
}

#define EXTEND_CMD_MAX_BUF_LEN 819200 /* 800K */

static void rpc_default_callback(struct rpc_task *task, void *data)
{
}

static const struct rpc_call_ops rpc_default_ops = {
	.rpc_call_done = rpc_default_callback,
};

/*
 * Send extend request by specified xprt.
 */
int dorado_extend_route(struct rpc_clnt *clnt, struct rpc_xprt *xprt, char *buf,
			int *buflen)
{
	int status;
	struct rpc_task *task;
	struct nfs_extend_xdr_arg xdr_arg = { 0 };

	struct rpc_message msg = {
		.rpc_proc = &nfs3_procedures[NFS3PROC_EXTEND],
		.rpc_argp = &xdr_arg,
		.rpc_resp = &xdr_arg,
	};

	struct rpc_task_setup task_setup_data = {
		.rpc_client = clnt,
		.rpc_xprt = xprt,
		.rpc_message = &msg,
		.callback_ops = &rpc_default_ops,
		.callback_data = NULL,
		.flags = RPC_TASK_SOFT | RPC_TASK_TIMEOUT | RPC_TASK_SOFTCONN,
	};

	xdr_arg.buflen = *buflen;
	xdr_arg.pBuf = buf;
	xdr_arg.maxsize = EXTEND_CMD_MAX_BUF_LEN;

	task = rpc_run_task(&task_setup_data);
	if (IS_ERR(task))
		return PTR_ERR(task);
	status = task->tk_status;
	if (status) {
		enfs_log_debug("NFS reply status:%d resp_len:%d\n", status,
			      xdr_arg.buflen);
	}
	*buflen = xdr_arg.buflen;
	rpc_put_task(task);
	return status;
}

int dorado_extend_op(struct rpc_clnt *clnt, char *buf, int *buflen)
{
	int status;
	struct nfs_extend_xdr_arg xdr_arg = { 0 };

	struct rpc_message msg = {
		.rpc_proc = &nfs3_procedures[NFS3PROC_EXTEND],
		.rpc_argp = &xdr_arg,
		.rpc_resp = &xdr_arg,
	};

	xdr_arg.buflen = *buflen;
	xdr_arg.pBuf = buf;
	xdr_arg.maxsize = EXTEND_CMD_MAX_BUF_LEN;

	status = rpc_call_sync(clnt, &msg,
			       RPC_TASK_SOFT | RPC_TASK_TIMEOUT |
				       RPC_TASK_SOFTCONN);
	*buflen = xdr_arg.buflen;
	return status;
}

void nego_enfs_version(struct rpc_clnt *clnt, struct enfs_extend3_args *args)
{
	struct enfs_xprt_context *ctx = NULL;

	xprt_get(clnt->cl_xprt);
	ctx = (struct enfs_xprt_context *)xprt_get_reserve_context(
		clnt->cl_xprt);
	if (ctx == NULL) {
		enfs_log_error("The xprt multipath ctx is not valid.\n");
		xprt_put(clnt->cl_xprt);
		return;
	}
	if (ctx->version == ENFS_SERVER_VERSION_BASE)
		args->version = ENFS_V3;
	xprt_put(clnt->cl_xprt);
}

int dorado_query_fs_shard(struct rpc_clnt *clnt, struct enfs_file_uuid *file_uuid,
			  struct enfs_shard_view **resDataOut)
{
	int ret;
	char *buf = NULL;
	struct enfs_extend3_rsp *extend3Res = NULL;
	struct enfs_shard_view *resData = NULL;
	struct enfs_extend3_args *args = NULL;
	int bufLen = sizeof(struct enfs_extend3_args);

	args = kmalloc(bufLen, GFP_KERNEL);
	if (args == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	buf = kmalloc(EXTEND_CMD_MAX_BUF_LEN, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto out;
	}

	args->opcode = NFS3_GET_FSINFO_OP;
	args->version = ENFS_VERSION_BUTT - 1;
	args->extend_args_u.Uuid = *file_uuid;

	nego_enfs_version(clnt, args);
	ret = NfsExtendProcInfoExtendEncode(buf, bufLen, args);
	if (ret)
		goto out;

	ret = dorado_extend_op(clnt, buf, &bufLen);
	if (ret) {
		enfs_log_debug("get extent failed %d.\n", ret);
		goto out;
	}

	// decode
	ret = NfsExtendProcInfoExtendDecode(buf, bufLen, &extend3Res);
	if (ret)
		goto out;

	resData = kmalloc(sizeof(struct enfs_shard_view) + sizeof(struct enfs_shard_view_single) *
				(extend3Res->extend_res_u.fsInfo.num), GFP_KERNEL);
	if (!resData) {
		ret = -ENOMEM;
		goto out;
	}
	resData->clusterId = extend3Res->extend_res_u.fsInfo.clusterId;
	resData->storagePoolId = extend3Res->extend_res_u.fsInfo.storagePoolId;
	resData->fsId = extend3Res->extend_res_u.fsInfo.fsId;
	resData->tenantId = extend3Res->extend_res_u.fsInfo.tenantId;
	resData->num = extend3Res->extend_res_u.fsInfo.num;
	memcpy(resData->shardView, extend3Res->extend_res_u.fsInfo.shardView,
	       sizeof(struct enfs_shard_view_single) *
		       extend3Res->extend_res_u.fsInfo.num);
	*resDataOut = resData;

out:
	kfree(args);
	kfree(extend3Res);
	kfree(buf);
	return ret;
}

int dorado_query_lsId(struct rpc_clnt *clnt, struct enfs_get_ls_version_rsp **resDataOut)
{
	int ret;
	char *buf = NULL;
	struct enfs_extend3_rsp *extend3Res = NULL;
	struct enfs_get_ls_version_rsp *resData = NULL;
	struct enfs_extend3_args *args = NULL;
	int bufLen = sizeof(uint32_t) * 2;

	args = kmalloc(bufLen, GFP_KERNEL);
	if (args == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	buf = kmalloc(EXTEND_CMD_MAX_BUF_LEN, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto out;
	}

	args->opcode = NFS3_GET_LS_VERSION_OP;
	args->version = ENFS_VERSION_BUTT - 1;
	ret = NfsExtendProcInfoExtendEncode(buf, bufLen, args);
	if (ret)
		goto out;

	ret = dorado_extend_op(clnt, buf, &bufLen);
	if (ret) {
		enfs_log_debug("get extent failed %d.\n", ret);
		goto out;
	}

	// decode
	ret = NfsExtendProcInfoExtendDecode(buf, bufLen, &extend3Res);
	if (ret)
		goto out;

	resData = kmalloc(sizeof(struct enfs_get_ls_version_rsp) +
				  sizeof(struct enfs_get_ls_version_single) *
					  (extend3Res->extend_res_u.lsView.num),
			  GFP_KERNEL);
	if (!resData) {
		ret = -ENOMEM;
		goto out;
	}
	resData->num = extend3Res->extend_res_u.lsView.num;
	resData->clusterId = extend3Res->extend_res_u.lsView.clusterId;
	memcpy(resData->lsInfo, extend3Res->extend_res_u.lsView.lsInfo,
	       sizeof(struct enfs_get_ls_version_single) *
		       extend3Res->extend_res_u.lsView.num);
	*resDataOut = resData;

out:
	kfree(args);
	kfree(extend3Res);
	kfree(buf);
	return ret;
}

int dorado_query_lifview(struct rpc_clnt *clnt, struct rpc_xprt *xprt,
			 char *ipAddr, uint32_t ipNumber,
			 struct enfs_lif_port_info *lifInfo)
{
	int ret;
	int i;
	char *buf = NULL;
	struct enfs_extend3_args *args = NULL;
	struct enfs_extend3_rsp *extend3Res = NULL;
	char *curIP;
	int bufLen;

	if (!ipNumber || ipNumber > MAX_SUPPORTED_REMOTE_IP_COUNT)
		return -EINVAL;
	bufLen = sizeof(uint32_t) * 4 + ipNumber * MAX_IPV6_ADDR_LEN;

	buf = kmalloc(EXTEND_CMD_MAX_BUF_LEN, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto out;
	}

	args = kmalloc(bufLen, GFP_KERNEL);
	if (args == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	args->version = ENFS_VERSION_BUTT - 1;
	args->opcode = NFS3_GET_LIF_VIEW_OP;
	memcpy((void *)args->extend_args_u.lifArgs.ipAddr, (void *)ipAddr,
	       IP_ADDRESS_LEN_MAX * ipNumber);
	args->extend_args_u.lifArgs.ipNumber = ipNumber;
	args->extend_args_u.lifArgs.tenantId = 0; /* tenantId reserved */

	nego_enfs_version(clnt, args);
	ret = NfsExtendProcInfoExtendEncode(buf, bufLen, args);
	if (ret)
		goto out;

	ret = dorado_extend_route(clnt, xprt, buf, &bufLen);
	if (ret) {
		enfs_log_debug("ENFS: NfsExtendOp get lif view failed %d.\n",
			ret);
		goto out;
	}

	// decode
	ret = NfsExtendProcInfoExtendDecode(buf, bufLen, &extend3Res);
	if (ret)
		goto out;
	if (extend3Res->extend_res_u.lifInfo.lifNumber != ipNumber) {
		ret = -EBADMSG;
		goto out;
	}

	curIP = ipAddr;
	for (i = 0; i < extend3Res->extend_res_u.lifInfo.lifNumber; i++) {
		curIP = &ipAddr[i * MAX_IPV6_ADDR_LEN];
		strscpy(lifInfo[i].ipAddr, curIP, MAX_IPV6_ADDR_LEN);
		lifInfo[i].lsId =
			extend3Res->extend_res_u.lifInfo.lifport[i].lsId;
		lifInfo[i].workStatus =
			extend3Res->extend_res_u.lifInfo.lifport[i].workStatus;
		lifInfo[i].wwn =
			extend3Res->extend_res_u.lifInfo.lifport[i].homeSiteWwn;
		lifInfo[i].cpuId =
			extend3Res->extend_res_u.lifInfo.lifport[i].cpuId;
		enfs_log_debug(
			"enfs: query lif number: %u, ipaddr(%s):isfound(%u) workStatus(%u) lsId(%llu) tenantId(%u) homeSiteWwn(%llu) cpuId(%u)",
			extend3Res->extend_res_u.lifInfo.lifNumber,
			lifInfo[i].ipAddr,
			extend3Res->extend_res_u.lifInfo.lifport[i].isfound,
			extend3Res->extend_res_u.lifInfo.lifport[i].workStatus,
			extend3Res->extend_res_u.lifInfo.lifport[i].lsId,
			extend3Res->extend_res_u.lifInfo.lifport[i].tenantId,
			extend3Res->extend_res_u.lifInfo.lifport[i].homeSiteWwn,
			extend3Res->extend_res_u.lifInfo.lifport[i].cpuId);
	}

out:
	kfree(args);
	kfree(extend3Res);
	kfree(buf);
	return ret;
}

int enfs_query_lifview(struct rpc_clnt *clnt, struct rpc_xprt *xprt,
		       char *ipaddr, uint64_t *lsid, uint64_t *wwn,
		       uint32_t *cpuId)
{
	int ret;
	struct enfs_lif_port_info lif_info = { 0 };

	ret = dorado_query_lifview(clnt, xprt, ipaddr, 1, &lif_info);
	if (ret || lif_info.workStatus == 0) {
		enfs_log_debug("err:%d status:%d\n", ret, lif_info.workStatus);
		return ret;
	}
	*lsid = lif_info.lsId;
	*wwn = lif_info.wwn;
	*cpuId = lif_info.cpuId;
	return 0;
}

int scan_uuid(const char *str, uint8_t *arr, int arrlen)
{
	int ret;
	int i;
	uint32_t num;
	char tmpbuf[3];
	int str_len;

	if (str == NULL || arr == NULL || arrlen <= 0)
		return -1;

	str_len = strlen(str);

	if (str_len % 2 != 0 || arrlen < str_len / 2)
		return -1;

	for (i = 0; i < str_len; i += 2) {
		tmpbuf[0] = str[i];
		tmpbuf[1] = str[i + 1];
		tmpbuf[2] = '\0';

		ret = kstrtouint(tmpbuf, 16, &num);
		if (ret != 0)
			return -1;

		arr[i / 2] = (uint8_t)num;
	}
	return 0;
}

int sprint_uuid(char *buf, int buflen, struct enfs_file_uuid *file_uuid)
{
	int i;
	int n;
	char *head = buf;

	if (buflen < FILE_UUID_BUFF_LEN)
		return -1;

	for (i = 0; i < FILE_UUID_BUFF_LEN; i++) {
		n = sprintf(head, "%.2X", file_uuid->data[i]);
		head += n;
	}
	return 0;
}

void NfsExtendDnsQuerySetArgs(struct enfs_extend3_args *args, uint32_t ip_type,
			      uint32_t dnsNamecount, char *dnsName)
{
	args->version = ENFS_VERSION_BUTT - 1;
	args->opcode = NFS_ENFS_QUERY_DNS_OP;
	args->extend_args_u.dnsArgs.ipType = ip_type;
	args->extend_args_u.dnsArgs.dnsNameCount = dnsNamecount;
	memcpy((void *)args->extend_args_u.dnsArgs.dnsName, (void *)dnsName,
	       ENFS_DNS_MAX_NAME_LEN * dnsNamecount);
}

void NfsExtendDnsQuerySetRes(struct enfs_extend3_rsp *extend3Res,
			     struct enfs_dns_query_ip_info_single *resData)
{
	int i;

	for (i = 0; i < extend3Res->extend_res_u.dnsQueryIpInfo.ipNumber; i++) {
		resData[i].cpuId =
			extend3Res->extend_res_u.dnsQueryIpInfo.ipInfo[i].cpuId;
		resData[i].lsId =
			extend3Res->extend_res_u.dnsQueryIpInfo.ipInfo[i].lsId;
		memcpy(resData[i].ipAddr,
		       extend3Res->extend_res_u.dnsQueryIpInfo.ipInfo[i].ipAddr,
		       MAX_IPV6_ADDR_LEN);
	}
}

int dorado_query_dns(struct rpc_clnt *clnt,
		     struct enfs_dns_query_ip_info_single **dnsQueryIpInfo,
		     uint32_t ip_type, uint32_t dnsNamecount, char *dnsName,
		     int *ipNumber)
{
	int ret;
	char *buf = NULL;
	struct enfs_extend3_args *args = NULL;
	struct enfs_extend3_rsp *extend3Res = NULL;
	struct enfs_dns_query_ip_info_single *resData = NULL;
	// union don't use sizeof,4 means args's op and vers and dnsargs's type and count
	int bufLen =
		sizeof(uint32_t) * 4 + dnsNamecount * ENFS_DNS_MAX_NAME_LEN;
	buf = kmalloc(EXTEND_CMD_MAX_BUF_LEN, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto out;
	}

	args = kmalloc(bufLen, GFP_KERNEL);
	if (args == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	NfsExtendDnsQuerySetArgs(args, ip_type, dnsNamecount, dnsName);
	nego_enfs_version(clnt, args);

	ret = NfsExtendProcInfoExtendEncode(buf, bufLen, args);
	if (ret)
		goto out;

	ret = dorado_extend_op(clnt, buf, &bufLen);

	if (ret) {
		enfs_log_debug("NfsExtendOp query dns failed %d.\n", ret);
		goto out;
	}

	// decode
	ret = NfsExtendProcInfoExtendDecode(buf, bufLen, &extend3Res);
	if (ret)
		goto out;

	*ipNumber = extend3Res->extend_res_u.dnsQueryIpInfo.ipNumber;
	resData = kmalloc(extend3Res->extend_res_u.dnsQueryIpInfo.ipNumber *
			(sizeof(struct enfs_dns_query_ip_info_single)), GFP_KERNEL);
	if (resData == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	NfsExtendDnsQuerySetRes(extend3Res, resData);
	*dnsQueryIpInfo = resData;

out:
	kfree(extend3Res);
	kfree(args);
	kfree(buf);
	return ret;
}

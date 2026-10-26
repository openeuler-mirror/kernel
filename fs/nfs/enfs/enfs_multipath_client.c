// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */
#include <linux/types.h>
#include <linux/nfs.h>
#include <linux/nfs4.h>
#include <linux/nfs_fs.h>
#include <linux/nfs_fs_sb.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sunrpc/clnt.h>
#include <linux/sunrpc/addr.h>
#include "enfs_multipath_client.h"
#include "enfs_multipath_parse.h"
#include "enfs_log.h"

int enfs_alloc_nfsclient_info(struct multipath_client_info **client_info)
{
	struct multipath_client_info *info;

	info = kzalloc(sizeof(struct multipath_client_info), GFP_KERNEL);
	if (!info) {
		enfs_log_error("Memory allocation failed");
		return -ENOMEM;
	}

	info->local_ip_list = kzalloc(sizeof(struct nfs_ip_list), GFP_KERNEL);
	if (!info->local_ip_list) {
		enfs_log_error("Memory allocation failed");
		goto local_exit;
	}

	info->remote_ip_list = kzalloc(sizeof(struct nfs_ip_list), GFP_KERNEL);
	if (!info->remote_ip_list) {
		enfs_log_error("Memory allocation failed");
		goto remote_exit;
	}

	info->pRemoteDnsInfo =
		kzalloc(sizeof(struct enfs_route_dns_info), GFP_KERNEL);
	if (!info->pRemoteDnsInfo) {
		enfs_log_error("Memory allocation failed");
		goto dns_exit;
	}
	*client_info = info;
	return 0;

dns_exit:
	kfree(info->remote_ip_list);
remote_exit:
	kfree(info->local_ip_list);
local_exit:
	kfree(info);
	return -ENOMEM;
}

void enfs_free_nfsclient_info(struct multipath_client_info *client_info)
{
	if (!client_info)
		return;

	kfree(client_info->local_ip_list);
	kfree(client_info->remote_ip_list);
	kfree(client_info->pRemoteDnsInfo);
	kfree(client_info);
}

static int
nfs_multipath_client_mount_info_init(
	struct multipath_client_info *client_info,
	const struct nfs_client_initdata *cl_init)
{
	struct multipath_mount_options *opt =
		(struct multipath_mount_options *)(cl_init->enfs_option);

	if (opt->local_ip_list) {
		client_info->local_ip_list =
			kzalloc(sizeof(struct nfs_ip_list), GFP_KERNEL);
		if (!client_info->local_ip_list)
			return -ENOMEM;

		memcpy(client_info->local_ip_list, opt->local_ip_list,
		       sizeof(struct nfs_ip_list));
	}

	if (opt->remote_ip_list) {
		client_info->remote_ip_list =
			kzalloc(sizeof(struct nfs_ip_list), GFP_KERNEL);
		if (!client_info->remote_ip_list) {
			kfree(client_info->local_ip_list);
			client_info->local_ip_list = NULL;
			return -ENOMEM;
		}
		memcpy(client_info->remote_ip_list, opt->remote_ip_list,
		       sizeof(struct nfs_ip_list));
	}

	if (opt->pRemoteDnsInfo) {
		client_info->pRemoteDnsInfo =
			kzalloc(sizeof(struct enfs_route_dns_info), GFP_KERNEL);
		if (!client_info->pRemoteDnsInfo) {
			kfree(client_info->local_ip_list);
			client_info->local_ip_list = NULL;
			kfree(client_info->remote_ip_list);
			client_info->remote_ip_list = NULL;
			return -ENOMEM;
		}
		memcpy(client_info->pRemoteDnsInfo, opt->pRemoteDnsInfo,
		       sizeof(struct enfs_route_dns_info));
	}

	client_info->fill_local = opt->fill_local;

	return 0;
}

static void enfs_free_client_info(struct multipath_client_info *clp_info)
{
	if (!clp_info)
		return;

	if (clp_info->local_ip_list != NULL)
		kfree(clp_info->local_ip_list);
	if (clp_info->remote_ip_list != NULL)
		kfree(clp_info->remote_ip_list);

	if (clp_info->pRemoteDnsInfo != NULL)
		kfree(clp_info->pRemoteDnsInfo);
	kfree(clp_info);
}

void nfs_multipath_client_info_free(void *data)
{
	struct multipath_client_info *clp_info =
		(struct multipath_client_info *)data;

	if (clp_info == NULL)
		return;
	enfs_log_info("free client info %p.\n", clp_info);
	enfs_free_client_info(clp_info);
}

int nfs_multipath_client_info_init(void **data,
				   const struct nfs_client_initdata *cl_init)
{
	int rc;
	struct multipath_client_info **enfs_info;

	enfs_info = (struct multipath_client_info **)data;
	if (enfs_info == NULL)
		return -EINVAL;

	if (*enfs_info == NULL)
		*enfs_info = kzalloc(sizeof(struct multipath_client_info),
				     GFP_KERNEL);

	if (*enfs_info == NULL)
		return -ENOMEM;

	enfs_log_info("init client info %p.\n", *enfs_info);
	rc = nfs_multipath_client_mount_info_init(*enfs_info, cl_init);
	if (rc) {
		nfs_multipath_client_info_free(*enfs_info);
		*enfs_info = NULL;
		return rc;
	}
	return rc;
}

static bool
nfs_multipath_ip_list_info_match(
	const struct nfs_ip_list *ip_list_src,
	const struct nfs_ip_list *ip_list_dst)
{
	int i;
	int j;
	bool is_find;
	/* if both are equal or NULL, then return true. */
	if (ip_list_src == ip_list_dst)
		return true;

	if ((ip_list_src == NULL || ip_list_dst == NULL))
		return false;

	if (ip_list_src->count != ip_list_dst->count)
		return false;

	for (i = 0; i < ip_list_src->count; i++) {
		is_find = false;
		for (j = 0; j < ip_list_src->count; j++) {
			if (rpc_cmp_addr_port(
				    (const struct sockaddr *)&ip_list_src
					    ->address[i],
				    (const struct sockaddr *)&ip_list_dst
					    ->address[j])) {
				is_find = true;
				break;
			}
		}
		if (is_find == false)
			return false;
	}
	return true;
}

int nfs_multipath_dns_list_info_match(const struct enfs_route_dns_info *dns_src,
				      const struct enfs_route_dns_info *dns_dst)
{
	int i;
	int j;
	bool find;

	/* if both are equal or NULL, then return true. */
	if (dns_src == dns_dst)
		return true;

	if ((dns_src == NULL || dns_dst == NULL))
		return false;

	if (dns_src->dnsNameCount != dns_dst->dnsNameCount)
		return false;

	for (i = 0; i < dns_src->dnsNameCount; i++) {
		find = false;
		for (j = 0; j < dns_dst->dnsNameCount; j++) {
			if (strcmp(dns_src->routeRemoteDnsList[i].dnsname,
				   dns_dst->routeRemoteDnsList[j].dnsname) ==
			    0) {
				find = true;
				break;
			}
		}
		if (find == false)
			return false;
	}
	return true;
}

int nfs_multipath_client_info_match(void *src, void *dst)
{
	int ret = true;

	struct multipath_client_info *src_info;
	struct multipath_mount_options *dst_info;

	src_info = (struct multipath_client_info *)src;
	dst_info = (struct multipath_mount_options *)dst;

	ret = nfs_multipath_ip_list_info_match(src_info->local_ip_list,
					       dst_info->local_ip_list);
	if (ret == false) {
		enfs_log_error("local_ip not match.\n");
		return ret;
	}

	if (src_info->pRemoteDnsInfo->dnsNameCount == 0 &&
	    dst_info->pRemoteDnsInfo->dnsNameCount == 0) {
		ret = nfs_multipath_ip_list_info_match(
			src_info->remote_ip_list, dst_info->remote_ip_list);
		if (ret == false) {
			enfs_log_error("remote_ip not match.\n");
			return ret;
		}
	} else {
		ret = nfs_multipath_dns_list_info_match(
			src_info->pRemoteDnsInfo, dst_info->pRemoteDnsInfo);
		if (ret == false) {
			enfs_log_error("dns not match.\n");
			return ret;
		}
	}

	return ret;
}

int nfs4_multipath_client_info_match(void *src, void *dst)
{
	int ret = true;
	struct multipath_client_info *srcinfo = src;
	struct multipath_client_info *dstinfo = dst;

	if (src == NULL || dst == NULL)
		return false;

	ret = nfs_multipath_ip_list_info_match(srcinfo->local_ip_list,
					       dstinfo->local_ip_list);
	if (ret == false) {
		enfs_log_info("nfs4 local_ip not match.\n");
		return ret;
	}

	ret = nfs_multipath_ip_list_info_match(srcinfo->remote_ip_list,
					       dstinfo->remote_ip_list);
	if (ret == false) {
		enfs_log_info("nfs4 remote_ip not match.\n");
		return ret;
	}

	ret = nfs_multipath_dns_list_info_match(srcinfo->pRemoteDnsInfo,
						dstinfo->pRemoteDnsInfo);
	if (ret == false) {
		enfs_log_info("nfs4 dns not match.\n");
		return ret;
	}
	enfs_log_info("nfs4 try match client ret %d.\n", ret);
	return ret;
}

static void
print_ip_info(
	struct seq_file *seq,
	struct nfs_ip_list *ip_list,
	const char *type)
{
	char buf[IP_ADDRESS_LEN_MAX + 1];
	int len = 0;
	int i = 0;

	if (seq)
		seq_printf(seq, ",%s=", type);
	enfs_log_debug("%s ip list:\n", type);

	for (i = 0; i < ip_list->count; i++) {
		len = rpc_ntop((struct sockaddr *)&ip_list->address[i], buf,
			       IP_ADDRESS_LEN_MAX);
		if (len > 0 && len < IP_ADDRESS_LEN_MAX)
			buf[len] = '\0';

		if (i != 0 && seq)
			seq_printf(seq, "~");
		if (seq)
			seq_printf(seq, "%s", buf);

		enfs_log_debug("\t%s\n", buf);
	}
}

static void
print_dns_info(
	struct seq_file *seq,
	struct enfs_route_dns_info *pRemoteDnsInfo,
	const char *type)
{
	int i = 0;
	char *name;

	if (seq)
		seq_printf(seq, ",%s=", type);
	enfs_log_debug("%s dns list:\n", type);
	for (i = 0; i < pRemoteDnsInfo->dnsNameCount; i++) {
		name = pRemoteDnsInfo->routeRemoteDnsList[i].dnsname;
		if (i != 0 && seq)
			seq_printf(seq, "~");
		if (seq)
			seq_printf(seq, "%s", name);
		enfs_log_debug("\t%s\n", name);
	}
}

static void multipath_print_sockaddr(struct seq_file *seq,
				     struct sockaddr *addr)
{
	switch (addr->sa_family) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *)addr;

		seq_printf(seq, "%pI4", &sin->sin_addr);
		return;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;

		seq_printf(seq, "%pI6", &sin6->sin6_addr);
		return;
	}
	default:
		break;
	}
	enfs_log_error("unsupport family:%d\n", addr->sa_family);
}

static void
convert_lookup_cache_str(
	struct nfs_server *server,
	char **server_lookup,
	char **actual_lookup)
{
	if ((server->enfs_flags & NFS_MOUNT_LOOKUP_CACHE_NONEG) &&
	    (server->enfs_flags & NFS_MOUNT_LOOKUP_CACHE_NONE)) {
		*server_lookup = "none";
	} else if ((server->enfs_flags & NFS_MOUNT_LOOKUP_CACHE_NONEG) ||
		   (server->enfs_flags & NFS_MOUNT_LOOKUP_CACHE_NONE)) {
		*server_lookup = "positive";
	} else {
		*server_lookup = "all";
	}

	if ((server->flags & NFS_MOUNT_LOOKUP_CACHE_NONEG) &&
	    (server->flags & NFS_MOUNT_LOOKUP_CACHE_NONE)) {
		*actual_lookup = "none";
	} else if ((server->flags & NFS_MOUNT_LOOKUP_CACHE_NONEG) ||
		   (server->flags & NFS_MOUNT_LOOKUP_CACHE_NONE)) {
		*actual_lookup = "positive";
	} else {
		*actual_lookup = *server_lookup;
	}
}

static void multipath_print_enfs_info(struct seq_file *seq,
				      struct nfs_server *server)
{
	struct sockaddr_storage peeraddr;
	struct rpc_clnt *next = server->client;
	char *server_lookup_cache = NULL;
	char *actual_lookup_cache = NULL;

	convert_lookup_cache_str(server, &server_lookup_cache,
				 &actual_lookup_cache);

	rpc_peeraddr(server->client, (struct sockaddr *)&peeraddr,
		     sizeof(peeraddr));
	seq_printf(seq, ",slookupcache=%s", server_lookup_cache);
	seq_printf(seq, ",alookupcache=%s", actual_lookup_cache);
	seq_puts(seq, ",enfs_info=");
	multipath_print_sockaddr(seq, (struct sockaddr *)&peeraddr);

	while (next->cl_parent) {
		if (next == next->cl_parent)
			break;
		next = next->cl_parent;
	}
	seq_printf(seq, "_%u", next->cl_clid);
}

void nfs_multipath_client_info_show(struct seq_file *seq, void *data)
{
	struct nfs_server *server = data;
	struct multipath_client_info *client_info =
		server->nfs_client->cl_multipath_data;

	enfs_log_debug("show nfs mount option\n");
	if ((client_info->local_ip_list) &&
	    (client_info->local_ip_list->count > 0))
		print_ip_info(seq, client_info->local_ip_list, "localaddrs");

	if ((client_info->pRemoteDnsInfo) &&
	    (client_info->pRemoteDnsInfo->dnsNameCount > 0)) {
		print_dns_info(seq, client_info->pRemoteDnsInfo, "remoteaddrs");
	} else {
		if ((client_info->remote_ip_list) &&
		    (client_info->remote_ip_list->count > 0))
			print_ip_info(seq, client_info->remote_ip_list,
				      "remoteaddrs");
	}

	multipath_print_enfs_info(seq, server);
}

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */
#include "enfs_remount.h"

#include <linux/string.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/sunrpc/clnt.h>
#include <linux/spinlock.h>
#include <linux/sunrpc/addr.h>
#include <linux/sunrpc/metrics.h>
#include <linux/sunrpc/xprtmultipath.h>
#include <linux/sunrpc/xprtsock.h>
#include <linux/sunrpc/xprt.h>
#include <linux/smp.h>
#include <linux/delay.h>

#include "enfs.h"
#include "enfs_log.h"
#include "enfs_multipath.h"
#include "enfs_multipath_parse.h"
#include "enfs_path.h"
#include "enfs_proc.h"
#include "enfs_multipath_client.h"
#include "enfs_config.h"

static bool enfs_rpc_xprt_switch_need_delete_addr(
	struct multipath_mount_options *enfs_option, struct sockaddr *dstaddr,
	struct sockaddr *srcaddr, u32 protocol)
{
	int i;
	bool find_same_ip = false;
	int32_t local_total;
	int32_t remote_total;

	local_total = enfs_option->local_ip_list->count;
	remote_total = enfs_option->remote_ip_list->count;
	if (remote_total == 0) {
		enfs_log_debug("no ip list is present.\n");
		return false;
	}

	find_same_ip = local_total == 0 || protocol == XPRT_TRANSPORT_RDMA;
	for (i = 0; i < local_total && !find_same_ip; i++)
		find_same_ip = rpc_cmp_addr((struct sockaddr *)&enfs_option
						    ->local_ip_list->address[i],
					    srcaddr);

	if (find_same_ip == false)
		return true;

	find_same_ip = false;
	for (i = 0; i < remote_total; i++) {
		find_same_ip =
			rpc_cmp_addr((struct sockaddr *)&enfs_option
					     ->remote_ip_list->address[i],
				     dstaddr);
		if (find_same_ip)
			break;
	}

	if (find_same_ip == false)
		return true;
	return false;
}

// Used in rcu_lock
static bool enfs_delete_xprt_from_switch(struct rpc_xprt *xprt,
					 void *enfs_option,
					 struct rpc_xprt_switch *xps)
{
	struct enfs_xprt_context *ctx = NULL;
	struct multipath_mount_options *mopt =
		(struct multipath_mount_options *)enfs_option;

	if (enfs_is_main_xprt(xprt))
		return true;

	ctx = (struct enfs_xprt_context *)xprt_get_reserve_context(xprt);
	if (enfs_rpc_xprt_switch_need_delete_addr(
		    mopt, (struct sockaddr *)&xprt->addr,
		    (struct sockaddr *)&ctx->srcaddr, ctx->protocol)) {
		print_enfs_multipath_addr((struct sockaddr *)&ctx->srcaddr,
					  (struct sockaddr *)&xprt->addr);
		rpc_xprt_switch_remove_xprt(xps, xprt, false);
		enfs_link_count_add(-1);
		return true;
	}

	return false;
}

void enfs_clnt_delete_obsolete_xprts(struct nfs_client *nfs_client,
				     void *enfs_option)
{
	int xprt_count = 0;
	struct rpc_xprt *pos = NULL;
	struct rpc_xprt_switch *xps = NULL;

	rcu_read_lock();
	xps = xprt_switch_get(
		rcu_dereference(nfs_client->cl_rpcclient->cl_xpi.xpi_xpswitch));
	if (xps == NULL) {
		rcu_read_unlock();
		xprt_switch_put(xps);
		return;
	}
	list_for_each_entry_rcu(pos, &xps->xps_xprt_list, xprt_switch) {
		/* Keep the main transport even when the new limit is one. */
		if (enfs_is_main_xprt(pos))
			continue;
		if (xprt_count < (enfs_get_config_link_count_per_mount() - 1)) {
			if (enfs_delete_xprt_from_switch(pos, enfs_option,
							 xps) == false) {
				xprt_count++;
			}
		} else {
			rpc_xprt_switch_remove_xprt(xps, pos, false);
			enfs_link_count_add(-1);
		}
	}
	rcu_read_unlock();
	xprt_switch_put(xps);
}

int enfs_remount(struct nfs_client *nfs_client, void *enfs_option)
{
	int ret;
	struct sockaddr_storage ss;
	struct multipath_mount_options *remount_opt = enfs_option;
	struct multipath_client_info *client_info =
		nfs_client->cl_multipath_data;

	/* mount is not use multipath */
	if (client_info == NULL || enfs_option == NULL) {
		enfs_log_error(
			"mount information or remount information is empty.\n");
		return -EINVAL;
	}

	/*
	 * Do not need remount if not choose multitpath when auto fill local addr.
	 */
	if (remount_opt->local_ip_list->count == 0 &&
	    remount_opt->remote_ip_list->count == 0 &&
	    nfs_multipath_dns_list_info_match(remount_opt->pRemoteDnsInfo,
					      client_info->pRemoteDnsInfo) &&
	    client_info->fill_local == 1) {
		return 0;
	}
	client_info->fill_local = 0;

	if (remount_opt->pRemoteDnsInfo->dnsNameCount != 0) {
		rpc_peeraddr(nfs_client->cl_rpcclient, (struct sockaddr *)&ss,
			     sizeof(ss));
		ret = multipath_query_dns(remount_opt, ss.ss_family, false,
					  nfs_client->cl_rpcclient);
		if (ret != 0) {
			enfs_log_error(
				"remount err:%d, waiting for the next dns update.\n",
				ret);
			return 0;
		}
	}

	return enfs_remount_iplist(nfs_client, enfs_option);
}

int enfs_remount_iplist(struct nfs_client *nfs_client, void *enfs_option)
{
	int errno = 0;
	char servername[48];
	struct multipath_mount_options *remount_opt = enfs_option;
	struct multipath_client_info *client_info =
		nfs_client->cl_multipath_data;
	struct xprt_create xprtargs;
	struct rpc_create_args args = {
		.protocol = nfs_client->cl_proto,
		.net = nfs_client->cl_net,
		.addrsize = nfs_client->cl_addrlen,
		.servername = nfs_client->cl_hostname,
	};
	memset(&xprtargs, 0, sizeof(struct xprt_create));

	//mount is not use multipath
	if (client_info == NULL || enfs_option == NULL) {
		enfs_log_error(
			"mount information or remount information is empty.\n");
		return -EINVAL;
	}
	//remount : localaddrs and remoteaddrs are empty
	if (remount_opt->local_ip_list->count == 0 &&
	    remount_opt->remote_ip_list->count == 0) {
		enfs_log_info(
			"remount local_ip_list and remote_ip_list are NULL\n");
		return 0;
	}

	errno = enfs_config_xprt_create_args(&xprtargs, &args, servername,
					     sizeof(servername));
	if (errno) {
		enfs_log_error("config_xprt_create failed! errno:%d\n", errno);
		return errno;
	}

	if (remount_opt->local_ip_list->count == 0 &&
	    client_info->local_ip_list->count != 0) {
		memcpy(remount_opt->local_ip_list, client_info->local_ip_list,
		       sizeof(struct nfs_ip_list));
	}

	if (remount_opt->remote_ip_list->count == 0) {
		if (client_info->remote_ip_list->count == 0) {
			errno = rpc_peeraddr(
				nfs_client->cl_rpcclient,
				(struct sockaddr *)&remount_opt->remote_ip_list
					->address[0],
				sizeof(struct sockaddr_storage));
			if (errno == 0) {
				enfs_log_error("get clnt dstaddr errno:%d\n",
					       errno);
				return errno;
			}
			remount_opt->remote_ip_list->count = 1;
		} else {
			memcpy(remount_opt->remote_ip_list,
			       client_info->remote_ip_list,
			       sizeof(struct nfs_ip_list));
		}
	}

	enfs_log_debug("Remount creating new links...\n");
	enfs_xprt_ippair_create(&xprtargs, nfs_client->cl_rpcclient,
				remount_opt);

	enfs_clnt_delete_obsolete_xprts(nfs_client, remount_opt);

	memcpy(client_info->local_ip_list, remount_opt->local_ip_list,
	       sizeof(struct nfs_ip_list));
	memcpy(client_info->remote_ip_list, remount_opt->remote_ip_list,
	       sizeof(struct nfs_ip_list));
	memcpy(client_info->pRemoteDnsInfo, remount_opt->pRemoteDnsInfo,
	       sizeof(struct enfs_route_dns_info));

	return 0;
}

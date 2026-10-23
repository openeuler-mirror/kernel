// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */
#include "enfs_multipath.h"
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/atomic.h>
#include <linux/sunrpc/addr.h>
#include <linux/sunrpc/bc_xprt.h>
#include <linux/sunrpc/clnt.h>
#include <linux/sunrpc/metrics.h>
#include <linux/sunrpc/rpc_pipe_fs.h>
#include <linux/sunrpc/xprt.h>
#include <linux/sunrpc/xprtsock.h>
#include <linux/sunrpc/xprtmultipath.h>
#include <linux/types.h>
#include <linux/un.h>
#include <linux/utsname.h>
#include <linux/workqueue.h>
#include <trace/events/sunrpc.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <net/addrconf.h>

#include "enfs_config.h"
#include "enfs_log.h"
#include "enfs_multipath_parse.h"
#include "enfs_path.h"
#include "enfs_proc.h"
#include "enfs_remount.h"
#include "enfs_roundrobin.h"
#include "failover_path.h"
#include "failover_time.h"
#include "pm_ping.h"
#include "pm_state.h"
#include "enfs_multipath.h"
#include "shard.h"
#include "exten_call.h"
#include "enfs_rpc_proc.h"
#include "dns_internal.h"

struct xprt_attach_callback_data {
	atomic_t *condition;
	wait_queue_head_t *waitq;
};

struct xprt_attach_info {
	struct sockaddr_storage *localAddress;
	struct sockaddr_storage *remoteAddress;
	struct rpc_xprt *xprt;
	struct xprt_attach_callback_data *data;
	int protocol;
};

static DECLARE_WAIT_QUEUE_HEAD(path_attach_wait_queue);
static spinlock_t link_count_lock;
static int link_count;
static spinlock_t mount_count_lock;
static int mount_count;

bool enfs_link_count_add(int num)
{
	bool ret = false;

	spin_lock(&link_count_lock);
	if (num < 0) {
		link_count += num;
		ret = true;
		spin_unlock(&link_count_lock);
		return ret;
	}
	if (link_count <= enfs_get_config_link_count_total() - num) {
		link_count += num;
		ret = true;
	}
	spin_unlock(&link_count_lock);

	return ret;
}

int enfs_link_count_num(void)
{
	int num;

	spin_lock(&link_count_lock);
	num = link_count;
	spin_unlock(&link_count_lock);
	return num;
}

void enfs_clnt_get_linkcap(struct rpc_clnt *clnt)
{
	unsigned int nxprts = 0;
	struct rpc_xprt_switch *xps;

	rcu_read_lock();
	xps = rcu_dereference(clnt->cl_xpi.xpi_xpswitch);
	if (xps)
		nxprts = xps->xps_nxprts;
	rcu_read_unlock();
	enfs_link_count_add(nxprts);
	enfs_mount_count_add(1);
}

void enfs_clnt_release_linkcap(struct rpc_clnt *clnt)
{
	unsigned int nxprts = 0;
	struct rpc_xprt_switch *xps;

	rcu_read_lock();
	xps = rcu_dereference(clnt->cl_xpi.xpi_xpswitch);
	if (xps)
		nxprts = xps->xps_nxprts;
	rcu_read_unlock();
	enfs_link_count_add(-nxprts);
	enfs_mount_count_add(-1);
}

bool enfs_mount_count_add(int num)
{
	bool ret = false;

	spin_lock(&mount_count_lock);
	if (mount_count <= ENFS_MAX_MOUNT_COUNT - num) {
		mount_count += num;
		ret = true;
	}
	spin_unlock(&mount_count_lock);

	return ret;
}

int enfs_mount_count(void)
{
	int num;

	spin_lock(&mount_count_lock);
	num = mount_count;
	spin_unlock(&mount_count_lock);
	return num;
}

void enfs_destroy_rpcclnt_list(struct list_head *head)
{
	struct rpcclnt_release_item *item;

	while (!list_empty(head)) {
		item = list_entry(head->next, struct rpcclnt_release_item,
				  node);
		rpc_release_client(item->clnt);
		list_del(&item->node);
		kfree(item);
	}
}

void enfs_destroy_clnt_list(struct list_head *head)
{
	struct clnt_release_item *item;

	while (!list_empty(head)) {
		item = list_entry(head->next, struct clnt_release_item, node);
		rpc_release_client(item->clnt);
		nfs_put_client(item->client);
		list_del(&item->node);
		kfree(item);
	}
}

/**
 * set socket port.
 * @ns: need transform to network byte order
 */
static void sockaddr_set_port(struct sockaddr *addr, __be16 port, bool ns)
{
	switch (addr->sa_family) {
	case AF_INET:
		((struct sockaddr_in *)addr)->sin_port = ns ? htons(port) :
							      port;
		break;
	case AF_INET6:
		((struct sockaddr_in6 *)addr)->sin6_port = ns ? htons(port) :
								port;
		break;
	}
}

static __be16 get_rpc_clnt_port(struct rpc_clnt *clnt)
{
	struct sockaddr_storage ss;
	struct sockaddr *addr = (struct sockaddr *)&ss;

	rpc_peeraddr(clnt, (struct sockaddr *)&ss, sizeof(ss));
	switch (addr->sa_family) {
	case AF_INET:
		return ((struct sockaddr_in *)addr)->sin_port;

	case AF_INET6:
		return ((struct sockaddr_in6 *)addr)->sin6_port;

	default:
		enfs_log_error("not support family:%d.\n", addr->sa_family);
		return -1;
	}
}

static int sockaddr_ip_to_str(struct sockaddr *addr, char *buf, int len)
{
	if (addr == NULL) {
		snprintf(buf, len, "*");
		return 0;
	}
	switch (addr->sa_family) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *)addr;

		snprintf(buf, len, "%pI4", &sin->sin_addr);
		return 0;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;

		snprintf(buf, len, "%pI6", &sin6->sin6_addr);
		return 0;
	}
	default:
		break;
	}
	return 1;
}

void print_enfs_multipath_addr(struct sockaddr *local, struct sockaddr *remote)
{
	char buf1[128];
	char buf2[128];

	sockaddr_ip_to_str(local, buf1, sizeof(buf1));
	sockaddr_ip_to_str(remote, buf2, sizeof(buf2));

	enfs_log_info("local:%s remote:%s\n", buf1, buf2);
}

static int enfs_servername(char *servername, unsigned long long len,
			   struct rpc_create_args *args)
{
	struct sockaddr_un *sun = (struct sockaddr_un *)args->address;
	struct sockaddr_in *sin = (struct sockaddr_in *)args->address;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)args->address;

	servername[0] = '\0';
	switch (args->address->sa_family) {
	case AF_LOCAL:
		snprintf(servername, len, "%s", sun->sun_path);
		break;
	case AF_INET:
		snprintf(servername, len, "%pI4", &sin->sin_addr.s_addr);
		break;
	case AF_INET6:
		snprintf(servername, len, "%pI6", &sin6->sin6_addr);
		break;
	default:
		enfs_log_info("invalid family:%d\n", args->address->sa_family);
		return -EINVAL;
	}
	return 0;
}

static void pm_xprt_ping_callback(void *data)
{
	struct xprt_attach_callback_data *attach_callback_data =
		(struct xprt_attach_callback_data *)data;
	atomic_dec(attach_callback_data->condition);
	wake_up(attach_callback_data->waitq);
}

static int enfs_add_xprt_setup(struct rpc_clnt *clnt,
			       struct rpc_xprt_switch *xps,
			       struct rpc_xprt *xprt, void *data)
{
	int ret;
	struct enfs_xprt_context *ctx;
	struct xprt_attach_info *attach_info = data;
	struct sockaddr_storage *srcaddr = attach_info->localAddress;

	ctx = (struct enfs_xprt_context *)xprt_get_reserve_context(xprt);
	memset(ctx, 0, sizeof(struct enfs_xprt_context));
	ctx->stats = rpc_alloc_iostats(clnt);
	ctx->main = false;
	ctx->protocol = attach_info->protocol;
	if (srcaddr != NULL)
		ctx->srcaddr = *srcaddr;
	pm_set_path_state(xprt, PM_STATE_INIT);
	pm_ping_set_path_check_state(xprt, PM_CHECK_INIT);

	attach_info->xprt = xprt;
	xprt_get(xprt);

	ret = pm_ping_rpc_test_xprt_with_callback(
		clnt, xprt, pm_xprt_ping_callback, attach_info->data);
	if (ret != 1)
		enfs_log_error("Failed to add ping task.\n");

	ret = 1;

	return ret; // so that rpc_clnt_add_xprt does not call rpc_xprt_switch_add_xprt
}

int enfs_configure_xprt_to_clnt(struct xprt_create *xprtargs,
				struct rpc_clnt *clnt,
				struct xprt_attach_info *attach_info)
{
	int err = 0;
	__be16 port;

	xprtargs->srcaddr = (struct sockaddr *)attach_info->localAddress;
	xprtargs->dstaddr = (struct sockaddr *)attach_info->remoteAddress;

	port = get_rpc_clnt_port(clnt);
	sockaddr_set_port((struct sockaddr *)attach_info->remoteAddress, port,
			  false);
	print_enfs_multipath_addr(
		(struct sockaddr *)attach_info->localAddress,
		(struct sockaddr *)attach_info->remoteAddress);

	err = rpc_clnt_add_xprt(clnt, xprtargs, enfs_add_xprt_setup,
				attach_info);
	if (err != 1) {
		enfs_log_error("clnt add xprt err:%d\n", err);
		return err;
	}
	return 0;
}

// Calculate the greatest common divisor of two numbers
static int enfs_cal_gcd(int num1, int num2)
{
	if (num2 == 0)
		return num1;
	return enfs_cal_gcd(num2, num1 % num2);
}

bool enfs_cmp_addrs(struct sockaddr_storage *srcaddr,
		    struct sockaddr_storage *dstaddr,
		    struct sockaddr_storage *localAddress,
		    struct sockaddr_storage *remoteAddress)
{
	if (localAddress == NULL ||
	    rpc_cmp_addr((struct sockaddr *)srcaddr,
			 (struct sockaddr *)localAddress)) {
		if (rpc_cmp_addr((struct sockaddr *)dstaddr,
				 (struct sockaddr *)remoteAddress)) {
			return true;
		}
	}

	return false;
}

bool enfs_xprt_addrs_is_same(struct rpc_xprt *xprt,
			     struct sockaddr_storage *localAddress,
			     struct sockaddr_storage *remoteAddress)
{
	struct enfs_xprt_context *xprt_local_info = NULL;
	struct sockaddr_storage *srcaddr = NULL;
	struct sockaddr_storage *dstaddr = NULL;

	if (xprt == NULL)
		return true;
	xprt_local_info =
		(struct enfs_xprt_context *)xprt_get_reserve_context(xprt);

	srcaddr = &xprt_local_info->srcaddr;
	dstaddr = &xprt->addr;

	return enfs_cmp_addrs(srcaddr, dstaddr, localAddress, remoteAddress);
}

bool enfs_already_have_xprt(struct rpc_clnt *clnt,
			    struct sockaddr_storage *localAddress,
			    struct sockaddr_storage *remoteAddress)
{
	struct rpc_xprt *pos = NULL;
	struct rpc_xprt_switch *xps = NULL;

	rcu_read_lock();
	xps = xprt_switch_get(rcu_dereference(clnt->cl_xpi.xpi_xpswitch));
	if (xps == NULL) {
		rcu_read_unlock();
		return false;
	}
	list_for_each_entry_rcu(pos, &xps->xps_xprt_list, xprt_switch) {
		if (enfs_xprt_addrs_is_same(pos, localAddress, remoteAddress)) {
			xprt_switch_put(xps);
			rcu_read_unlock();
			return true;
		}
	}
	xprt_switch_put(xps);
	rcu_read_unlock();
	return false;
}

static void enfs_xprt_switch_add_xprt(struct rpc_clnt *clnt,
				      struct rpc_xprt *xprt)
{
	struct rpc_xprt_switch *xps;

	rcu_read_lock();
	xps = rcu_dereference(clnt->cl_xpi.xpi_xpswitch);
	spin_lock(&xps->xps_lock);
	if (xps->xps_net == xprt->xprt_net || xps->xps_net == NULL)
		xprt_switch_add_xprt_locked(xps, xprt);
	spin_unlock(&xps->xps_lock);
	rcu_read_unlock();
}

/* Maximum number of localaddrs in the scenario where IP addresses are
 * automatically obtained.
 */
static bool limit_local_addr(struct nfs_ip_list *ip_list, struct rpc_xprt *xprt)
{
	struct enfs_xprt_context *ctx = xprt_get_reserve_context(xprt);

	// if protocol is rdma, the number of localaddrs does not need to be verified
	if (ctx->protocol == XPRT_TRANSPORT_RDMA)
		return true;

	return enfs_insert_ip_list(ip_list, MAX_IP_PAIR_PER_MOUNT,
				   &ctx->srcaddr) ||
	       enfs_ip_list_contain(ip_list, &ctx->srcaddr);
}

static void enfs_add_xprts_to_clnt(struct rpc_clnt *clnt,
				   struct xprt_attach_info *attach_infos,
				   int total_combinations, int remoteTotal,
				   int localTotal)
{
	struct rpc_xprt *xprt;
	enum enfs_path_state state;
	int i;
	int link_count = 0;
	struct nfs_ip_list *ip_list;
	int count = GetEnfsConfigIpFiltersCount();
	int maxCountPerMount = enfs_get_config_link_count_per_mount() - 1;

	if (count == 0 && localTotal == 0) {
		maxCountPerMount =
			remoteTotal < enfs_get_config_link_count_per_mount() -
						1 ?
				remoteTotal :
				enfs_get_config_link_count_per_mount() - 1;
	}

	ip_list = kzalloc(sizeof(struct nfs_ip_list), GFP_KERNEL);
	if (!ip_list) {
		enfs_log_error("alloc memery failed.\n");
		return;
	}

	for (i = 0; i < total_combinations; i++) {
		xprt = attach_infos[i].xprt;

		if (xprt == NULL)
			continue;

		state = pm_get_path_state(xprt);

		if (link_count < maxCountPerMount &&
		    (enfs_is_path_connected(state) ||
		     enfs_get_create_path_no_route()) &&
		    limit_local_addr(ip_list, xprt) && enfs_link_count_add(1)) {
			enfs_xprt_switch_add_xprt(clnt, xprt);
			enfs_query_xprt_shard(clnt, xprt);
			link_count++;
		} else {
			enfs_log_error(
				"Add xprt to clnt ERR! path state = %d, link_count = %d\n",
				state, link_count);
		}

		xprt_put(xprt);
	}
	kfree(ip_list);
}

static void enfs_combine_addr(struct xprt_create *xprtargs,
			      struct rpc_clnt *clnt, struct nfs_ip_list *local,
			      struct nfs_ip_list *remote)
{
	int i;
	int err;
	int local_index;
	int remote_index;
	int link_count = 0;
	int local_total = local->count;
	int remote_total = remote->count;
	int local_remote_total_lcm;
	int total_combinations = local_total * remote_total;
	struct xprt_attach_info *attach_infos;
	atomic_t wait_queue_condition;
	struct xprt_attach_callback_data attach_callback_data = {
		&wait_queue_condition, &path_attach_wait_queue
	};

	atomic_set(&wait_queue_condition, total_combinations);

	enfs_log_debug("local count:%d remote count:%d\n",
		       local_total, remote_total);
	if (local_total == 0 || remote_total == 0) {
		enfs_log_debug("no ip list is present.\n");
		return;
	}

	attach_infos = kzalloc((total_combinations) * sizeof(struct xprt_attach_info),
		GFP_KERNEL);
	if (attach_infos == NULL) {
		enfs_log_error("Failed to kzalloc memory\n");
		return;
	}
	// Calculate the least common multiple of local_total and remote_total
	local_remote_total_lcm =
		total_combinations / enfs_cal_gcd(local_total, remote_total);

	// It needs to be offset one for lcm times of cycle so that
	// all possible link setup method would be traversed
	for (i = 0; i < total_combinations; i++) {
		local_index = i % local_total;
		remote_index = (i + link_count / local_remote_total_lcm) %
			       remote_total;

		if (local->address[local_index].ss_family !=
		    remote->address[remote_index].ss_family) {
			atomic_dec(&wait_queue_condition);
			link_count++;
			continue;
		}

		if (enfs_already_have_xprt(clnt, &local->address[local_index],
					   &remote->address[remote_index])) {
			atomic_dec(&wait_queue_condition);
			link_count++;
			continue;
		}

		attach_infos[i].localAddress = &local->address[local_index];
		attach_infos[i].remoteAddress = &remote->address[remote_index];
		attach_infos[i].data = &attach_callback_data;
		attach_infos[i].protocol = xprtargs->ident;

		err = enfs_configure_xprt_to_clnt(xprtargs, clnt,
						  &attach_infos[i]);
		if (err) {
			enfs_log_error("add xprt ippair err:%d\n", err);
			atomic_dec(&wait_queue_condition);
		}
		link_count++;
	}

	wait_event(path_attach_wait_queue,
		   atomic_read(&wait_queue_condition) == 0);

	enfs_add_xprts_to_clnt(clnt, attach_infos, total_combinations,
			       remote_total, local_total);

	kfree(attach_infos);
}

static void enfs_combine_addr_with_no_local(struct xprt_create *xprtargs,
					    struct rpc_clnt *clnt,
					    struct nfs_ip_list *local,
					    struct nfs_ip_list *remote)
{
	int i;
	int err;
	int link_count = 0;
	int local_total = local->count;
	int remote_total = remote->count;
	int total_combinations = remote_total;
	struct xprt_attach_info *attach_infos;
	atomic_t wait_queue_condition;
	struct xprt_attach_callback_data attach_callback_data = {
		&wait_queue_condition, &path_attach_wait_queue
	};

	atomic_set(&wait_queue_condition, total_combinations);

	enfs_log_debug("local count:%d remote count:%d\n",
		       local_total, remote_total);
	if (remote_total == 0) {
		enfs_log_debug("no ip list is present.\n");
		return;
	}

	attach_infos = kzalloc((total_combinations) * sizeof(struct xprt_attach_info),
		GFP_KERNEL);
	if (attach_infos == NULL) {
		enfs_log_error("Failed to kzalloc memory\n");
		return;
	}

	for (i = 0; i < total_combinations; i++) {
		if (enfs_already_have_xprt(clnt, NULL, &remote->address[i])) {
			atomic_dec(&wait_queue_condition);
			link_count++;
			continue;
		}

		attach_infos[i].localAddress = NULL;
		attach_infos[i].remoteAddress = &remote->address[i];
		attach_infos[i].data = &attach_callback_data;
		attach_infos[i].protocol = xprtargs->ident;

		err = enfs_configure_xprt_to_clnt(xprtargs, clnt,
						  &attach_infos[i]);
		if (err) {
			enfs_log_error("add xprt ippair err:%d\n", err);
			atomic_dec(&wait_queue_condition);
		}
		link_count++;
	}

	wait_event(path_attach_wait_queue,
		   atomic_read(&wait_queue_condition) == 0);

	enfs_add_xprts_to_clnt(clnt, attach_infos, total_combinations,
			       remote_total, local_total);

	kfree(attach_infos);
}

void enfs_xprt_ippair_create(struct xprt_create *xprtargs,
			     struct rpc_clnt *clnt, void *data)
{
	struct multipath_mount_options *mopt =
		(struct multipath_mount_options *)data;
	if (mopt == NULL) {
		enfs_log_error("ip list is NULL.\n");
		return;
	}
	if (xprtargs->ident == XPRT_TRANSPORT_RDMA ||
	    mopt->local_ip_list->count == 0) {
		enfs_combine_addr_with_no_local(xprtargs, clnt,
						mopt->local_ip_list,
						mopt->remote_ip_list);
	} else {
		enfs_combine_addr(xprtargs, clnt, mopt->local_ip_list,
				  mopt->remote_ip_list);
	}
	enfs_lb_set_policy(clnt, NULL);
}

struct xprts_options_and_clnt {
	struct rpc_create_args *args;
	struct rpc_clnt *clnt;
	void *data;
};

int enfs_config_xprt_create_args(struct xprt_create *xprtargs,
				 struct rpc_create_args *args, char *servername,
				 size_t length)
{
	int errno = 0;

	xprtargs->ident = args->protocol;
	xprtargs->net = args->net;
	xprtargs->addrlen = args->addrsize;
	xprtargs->servername = args->servername;

	if (args->flags & RPC_CLNT_CREATE_INFINITE_SLOTS)
		xprtargs->flags |= XPRT_CREATE_INFINITE_SLOTS;
	if (args->flags & RPC_CLNT_CREATE_NO_IDLE_TIMEOUT)
		xprtargs->flags |= XPRT_CREATE_NO_IDLE_TIMEOUT;

	if (xprtargs->servername == NULL) {
		errno = enfs_servername(servername, length, args);
		if (errno)
			return errno;
		xprtargs->servername = servername;
	}

	return 0;
}

static void set_in_addr(struct sockaddr_storage *ss, __be32 ifa_address)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)ss;

	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = ifa_address;
}

static void set_in6_addr(struct sockaddr_storage *ss,
			 const struct inet6_ifaddr *in6)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;

	memset(ss, 0, sizeof(*ss));
	ss->ss_family = AF_INET6;
	memcpy(&sin6->sin6_addr, &in6->addr, sizeof(struct in6_addr));
}

static void enfs_auto_fill_local_inet(struct nfs_ip_list *list,
				      struct in_device *dvice)
{
	char buf[INET6_ADDRSTRLEN];
	const struct in_ifaddr *ifa;

	if (!dvice)
		return;
	in_dev_for_each_ifa_rcu(ifa, dvice) {
		if (list->count >= enfs_get_config_link_count_per_mount())
			break;

		snprintf(buf, INET6_ADDRSTRLEN, "%pI4", &ifa->ifa_address);
		if (!enfs_whitelist_filte(buf))
			continue;

		set_in_addr(&list->address[list->count], ifa->ifa_address);
		list->count++;
		enfs_log_debug("IPv4: %s\n", buf);
	}
}

static void enfs_auto_fill_local_inet6(struct nfs_ip_list *list,
				       struct inet6_dev *idev)
{
	struct inet6_ifaddr *ifp;
	char buf[INET6_ADDRSTRLEN];
	char buf_c[INET6_ADDRSTRLEN]; /* Abbreviations */

	if (!idev)
		return;

	list_for_each_entry(ifp, &idev->addr_list, if_list) {
		if (list->count >= enfs_get_config_link_count_per_mount())
			break;

		snprintf(buf, INET6_ADDRSTRLEN, "%pI6", &ifp->addr);
		snprintf(buf_c, INET6_ADDRSTRLEN, "%pI6c", &ifp->addr);
		if (!enfs_whitelist_filte(buf) && !enfs_whitelist_filte(buf_c))
			continue;

		set_in6_addr(&list->address[list->count], ifp);
		list->count++;
		enfs_log_debug("IPv6: %s/%d\n", buf_c, ifp->prefix_len);
	}
}

// IPv4,IPv6
static void find_fill_local_addr(struct nfs_ip_list *list,
				 unsigned short family)
{
	struct net_device *dev;

	rtnl_lock();
	for_each_netdev(&init_net, dev) {
		if (list->count >= enfs_get_config_link_count_per_mount())
			break;
		enfs_log_debug("device: %s\n", dev->name);

		// IPv4
		enfs_auto_fill_local_inet(list, dev->ip_ptr);
		// IPv6
		if (family == AF_INET6)
			enfs_auto_fill_local_inet6(list, dev->ip6_ptr);
	}
	rtnl_unlock();
}

static int fill_local_iplist(struct xprts_options_and_clnt *args,
			     struct multipath_mount_options *options,
			     struct nfs_ip_list *local)
{
	struct sockaddr_storage ss;
	int count = GetEnfsConfigIpFiltersCount();

	rpc_peeraddr(args->clnt, (struct sockaddr *)&ss, sizeof(ss));
	if (options->fill_local && count != 0) {
		/* Do not need to fill in the IP address again, if not found */
		find_fill_local_addr(local, ss.ss_family);
		return 0;
	}

	return 0;
}

static int enfs_fill_empty_iplist(struct xprts_options_and_clnt *args,
				  struct multipath_mount_options *options)
{
	int ret;
	struct nfs_ip_list *local = options->local_ip_list;
	struct nfs_ip_list *remote = options->remote_ip_list;

	if (local->count == 0)
		options->fill_local = 1;

	ret = fill_local_iplist(args, options, local);
	if (ret)
		return ret;
	// If a domain name is configured but the query fails, do not handle.
	if (remote->count == 0 && options->pRemoteDnsInfo->dnsNameCount == 0) {
		ret = rpc_peeraddr(args->clnt,
				   (struct sockaddr *)&remote->address[0],
				   sizeof(struct sockaddr_storage));
		if (ret == 0) {
			enfs_log_error("enfs: get clnt dstaddr errno:%d\n",
				       ret);
			return ret;
		}
		remote->count = 1;
	}

	return 0;
}

int enfs_multipath_create_thread(void *data)
{
	int errno;
	struct sockaddr_storage ss;
	char servername[48];
	struct xprts_options_and_clnt *create_args = data;
	struct multipath_mount_options *mount_options =
		create_args->args->multipath_option;
	struct xprt_create xprtargs;

	memset(&xprtargs, 0, sizeof(struct xprt_create));

	if (mount_options == NULL) {
		enfs_log_error(
			"enfs: mount localaddrs and remoteaddrs are empty !\n");
		return -EINVAL;
	}

	if (mount_options->pRemoteDnsInfo->dnsNameCount != 0) {
		enfs_add_domain_name(mount_options);
		rpc_peeraddr(create_args->clnt, (struct sockaddr *)&ss,
			     sizeof(ss));
		errno = multipath_query_dns(mount_options, ss.ss_family, true,
					    create_args->clnt);
		if (errno != 0) {
			enfs_log_error(
				"dns query failed,waiting for the next update.\n");
		}
	}

	errno = enfs_config_xprt_create_args(&xprtargs, create_args->args,
					     servername, sizeof(servername));
	if (errno) {
		enfs_log_error("enfs: config_xprt_create failed! errno:%d\n",
			       errno);
		return errno;
	}

	errno = enfs_fill_empty_iplist(create_args, mount_options);
	if (errno) {
		enfs_log_error("fill empty ip list err:%d\n", errno);
		return errno;
	}

	errno = enfs_proc_create_clnt(create_args->clnt);
	if (errno != 0)
		enfs_log_error("create clnt proc failed.\n");

	create_args->clnt->cl_enfs = 1;
	enfs_xprt_ippair_create(&xprtargs, create_args->clnt, mount_options);

	kfree(create_args->args);
	kfree(data);
	return 0;
}

static int set_main_xprt_ctx(struct rpc_clnt *clnt, struct rpc_xprt *xprt,
			     struct sockaddr_storage *srcaddr, int protocol)
{
	struct enfs_xprt_context *ctx = xprt_get_reserve_context(xprt);
	int err;

	if (!ctx) {
		enfs_log_error("main xprt not multipath ctx.\n");
		return -1;
	}
	if (protocol != XPRT_TRANSPORT_RDMA) {
		err = xs_xprt_set_srcaddr(xprt, (struct sockaddr *)srcaddr);
		if (err) {
			enfs_log_error("set main xprt source address failed: %d.\n",
				       err);
			return err;
		}
	}

	ctx->main = true;
	ctx->stats = rpc_alloc_iostats(clnt);
	ctx->srcaddr = *srcaddr;
	ctx->protocol = protocol;
	pm_set_path_state(xprt, PM_STATE_NORMAL);
	pm_ping_set_path_check_state(xprt, PM_CHECK_INIT);

	return 0;
}

static int alloc_main_xprt_multicontext(struct rpc_create_args *args,
					struct rpc_clnt *clnt)
{
	int err;
	struct sockaddr_storage srcaddr;

	// avoid main xprt multicontex local addr is empty.
	err = rpc_localaddr(clnt, (struct sockaddr *)&srcaddr, sizeof(srcaddr));
	if (err) {
		enfs_log_error("get clnt localaddr err:%d\n", err);
		return err;
	}

	err = set_main_xprt_ctx(clnt, clnt->cl_xprt, &srcaddr, args->protocol);
	if (err)
		enfs_log_error("alloc main xprt failed.\n");

	return err;
}

void enfs_create_multi_xprt(struct rpc_create_args *args, struct rpc_clnt *clnt)
{
	struct xprts_options_and_clnt *thargs = NULL;
	struct rpc_create_args *cargs = NULL;
	int err = 0;

	if (args->version == 4)
		return;

	enfs_log_info("%p\n", clnt);
	if (!enfs_mount_count_add(1)) {
		enfs_log_error("number of mount exceeds the limit.\n");
		return;
	}

	if (!enfs_link_count_add(1)) {
		enfs_log_error("number of link count exceeds the limit.\n");
		goto cleanup_mount;
	}

	cargs = kmalloc(sizeof(struct rpc_create_args), GFP_KERNEL);
	if (cargs == NULL)
		goto cleanup_link;

	*cargs = *args;

	thargs = kmalloc(sizeof(struct xprts_options_and_clnt), GFP_KERNEL);
	if (thargs == NULL)
		goto cleanup_cargs;

	alloc_main_xprt_multicontext(args, clnt);

	thargs->args = cargs;
	thargs->clnt = clnt;
	thargs->data = args->multipath_option;

	err = enfs_multipath_create_thread(thargs);
	if (err != 0)
		goto cleanup_thargs;

	return;

cleanup_thargs:
	kfree(thargs);
cleanup_cargs:
	kfree(cargs);
cleanup_link:
	enfs_link_count_add(-1);
cleanup_mount:
	enfs_mount_count_add(-1);
}

void enfs_release_rpc_clnt(struct rpc_clnt *clnt)
{
	enfs_proc_delete_clnt(clnt);
	// The sending client is inserted, not the main client.
	enfs_delete_clnt_shard_cache(clnt);
}

static void enfs_create_xprt_ctx(struct rpc_xprt *xprt)
{
	int err;

	err = enfs_alloc_xprt_ctx(xprt);
	if (err)
		enfs_log_error("alloc xprt failed.\n");
}

static void enfs_set_transport(struct rpc_task *task, struct rpc_clnt *clnt)
{
	if (clnt->cl_vers == 4)
		return;

	if (enfs_is_rr_route(clnt))
		shard_set_transport(task, clnt);
}

static void enfs_inc_queuelen(struct rpc_xprt *xprt)
{
	struct enfs_xprt_context *context;

	if (!xprt)
		return;
	context = xprt_get_reserve_context(xprt);
	if (!context)
		return;
	atomic_long_inc(&context->queuelen);
}

static void enfs_dec_queuelen(struct rpc_xprt *xprt)
{
	long value;
	struct enfs_xprt_context *context;

	if (!xprt)
		return;
	context = xprt_get_reserve_context(xprt);
	if (!context)
		return;
	value = atomic_long_dec_return(&context->queuelen);
	if (value < 0) {
		/* Prevent the reduction to negative */
		enfs_log_error(
			"the value of queue length is negative, value(%ld).\n",
			value);
		atomic_long_inc(&context->queuelen);
	}
}

static void enfs_get_rpc_program(struct rpc_task *task, u32 *program,
				 u32 *version)
{
	*program = ENFS_RPC_PROG_NUM;
	*version = ENFS_RPC_PROG_VERSION;
}

static struct rpc_multipath_ops ops = {
	.owner = THIS_MODULE,
	.create_clnt = enfs_create_multi_xprt,
	.releas_clnt = enfs_release_rpc_clnt,
	.create_xprt = enfs_create_xprt_ctx,
	.destroy_xprt = enfs_free_xprt_ctx,
	.xprt_iostat = enfs_count_iostat,
	.failover_handle = failover_handle,
	.adjust_task_timeout = failover_adjust_task_timeout,
	.init_task_req = failover_init_task_req,
	.prepare_transmit = failover_prepare_transmit,
	.set_transport = enfs_set_transport,
	.inc_queuelen = enfs_inc_queuelen,
	.dec_queuelen = enfs_dec_queuelen,
	.get_rpc_program = enfs_get_rpc_program,
	.task_need_call_start_again = failover_task_need_call_start_again,
};

int enfs_multipath_init(void)
{
	int err;

	enfs_log_info("multipath init.\n");

	spin_lock_init(&link_count_lock);
	spin_lock_init(&mount_count_lock);

	err = enfs_lb_init();
	if (err != 0) {
		enfs_log_error("enfs loadbalance init err:%d\n", err);
		return err;
	}

	err = pm_ping_init();
	if (err != 0) {
		enfs_log_error("pm ping init err:%d\n", err);
		enfs_lb_exit();
		return err;
	}

	err = enfs_proc_init();
	if (err != 0) {
		enfs_log_error("enfs proc init err:%d\n", err);
		pm_ping_fini();
		enfs_lb_exit();
		return err;
	}

	rpc_multipath_ops_register(&ops);

	return 0;
}

void enfs_multipath_exit(void)
{
	enfs_log_info("multipath exit.\n");
	rpc_multipath_ops_unregister(&ops);
	enfs_proc_exit();
	pm_ping_fini();
	enfs_lb_exit();
}

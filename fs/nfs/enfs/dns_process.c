// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */
#include <linux/kthread.h>
#include <linux/nfs_fs.h>
#include <linux/sunrpc/addr.h>
#include <linux/sunrpc/clnt.h>
#include <net/netns/generic.h>
#include <linux/dns_resolver.h>
#include "../../../fs/nfs/nfs4_fs.h"
#include "../../../fs/nfs/netns.h"
#include "dns_internal.h"
#include "enfs_log.h"
#include "enfs_multipath.h"
#include "enfs_multipath_client.h"
#include "enfs_remount.h"
#include "enfs_config.h"
#include "exten_call.h"

static struct task_struct *dns_thread;
static struct workqueue_struct *dns_workq; // timer for test xprt workqueue

static LIST_HEAD(dns_cache_list);
static spinlock_t dns_cache_lock;

static char dns_sort_ip
	[IP_ADDRESS_LEN_MAX]; // Temporary character string used for sorting.

struct name_list {
	struct list_head next;
	char name[MAX_DNS_NAME_LEN];
	struct nfs_ip_list inet;
	struct nfs_ip_list inet6;

	/* Add to background list on update. */
	struct nfs_ip_list inet_bc;
	struct nfs_ip_list inet6_bc;
	int ref;
};

static int sockaddr_ip_to_str(struct sockaddr *addr, char *buf, int len)
{
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

void enfs_debug_print_name_list(void)
{
	int i;
	struct name_list *list;
	char buf[128];

	spin_lock(&dns_cache_lock);
	list_for_each_entry(list, &dns_cache_list, next) {
		enfs_log_info("domain name:%s\n", list->name);
		for (i = 0; i < list->inet.count; i++) {
			sockaddr_ip_to_str((struct sockaddr *)&list->inet.address[i],
					   buf, 128);
			enfs_log_info("%s\n", buf);
		}
		for (i = 0; i < list->inet6.count; i++) {
			sockaddr_ip_to_str((struct sockaddr *)&list->inet6.address[i],
					   buf, 128);
			enfs_log_info("%s\n", buf);
		}
	}
	spin_unlock(&dns_cache_lock);
}

void enfs_update_domain_name(char *name, struct nfs_ip_list *ip_list)
{
	struct name_list *name_list;
	struct sockaddr *addr;
	int i;

	spin_lock(&dns_cache_lock);
	list_for_each_entry(name_list, &dns_cache_list, next) {
		if (strcmp(name, name_list->name) != 0)
			continue;

		for (i = 0; i < ip_list->count; i++) {
			addr = (struct sockaddr *)&ip_list->address[i];
			switch (addr->sa_family) {
			case AF_INET:
				enfs_insert_ip_list(&name_list->inet,
						    enfs_get_config_link_count_per_mount(),
						    &ip_list->address[i]);
				break;
			case AF_INET6:
				enfs_insert_ip_list(&name_list->inet6,
						    enfs_get_config_link_count_per_mount(),
						    &ip_list->address[i]);
				break;
			}
		}
		break;
	}

	spin_unlock(&dns_cache_lock);
}

/**
 * Exchange the IP address of the back end to the front end.
 */
void enfs_swap_name_cache(void)
{
	struct name_list *name_list;

	spin_lock(&dns_cache_lock);
	list_for_each_entry(name_list, &dns_cache_list, next) {
		if (name_list->inet_bc.count != 0) {
			name_list->inet = name_list->inet_bc;
			name_list->inet_bc.count = 0;
		}

		if (name_list->inet6_bc.count != 0) {
			name_list->inet6 = name_list->inet6_bc;
			name_list->inet6_bc.count = 0;
		}
	}
	spin_unlock(&dns_cache_lock);
}

void enfs_domain_inc(char *name)
{
	struct name_list *name_list;

	spin_lock(&dns_cache_lock);
	list_for_each_entry(name_list, &dns_cache_list, next) {
		if (strcmp(name, name_list->name) == 0) {
			name_list->ref++;
			break;
		}
	}

	if (&name_list->next == &dns_cache_list) { /* is head */
		name_list = kzalloc(sizeof(*name_list), GFP_KERNEL);
		if (!name_list) {
			spin_unlock(&dns_cache_lock);
			enfs_log_error("alloc failed.\n");
			return;
		}
		/*
		 * The length must be verified in the mount|remount phase
		 * (enfs_valid_dns) .
		 */
		strscpy(name_list->name, name, MAX_DNS_NAME_LEN);
		name_list->ref = 1;
		list_add_tail(&name_list->next, &dns_cache_list);
	}

	spin_unlock(&dns_cache_lock);
}

bool enfs_ip_list_contain(struct nfs_ip_list *ip_list,
			  struct sockaddr_storage *addr)
{
	int i;

	for (i = 0; i < ip_list->count; i++) {
		if (rpc_cmp_addr((struct sockaddr *)&ip_list->address[i],
				 (struct sockaddr *)addr)) {
			return true;
		}
	}

	return false;
}

bool enfs_insert_ip_list(struct nfs_ip_list *ip_list, int max,
			 struct sockaddr_storage *addr)
{
	int i;

	if (!ip_list || ip_list->count >= max)
		return false;

	for (i = 0; i < ip_list->count; i++) {
		if (rpc_cmp_addr((struct sockaddr *)&ip_list->address[i],
				 (struct sockaddr *)addr)) {
			return false;
		}
	}

	if (i < max) {
		ip_list->address[i] = *addr;
		ip_list->count++;
		return true;
	}
	return false;
}

void ip_list_append(struct nfs_ip_list *dst, struct nfs_ip_list *src,
		    int *tmp_slot)
{
	int i;
	struct sockaddr_storage *addr;

	for (i = 0; i < src->count && *tmp_slot != 0; i++) {
		addr = &src->address[i];
		if (enfs_insert_ip_list(dst,
					enfs_get_config_link_count_per_mount(),
					addr)) {
			(*tmp_slot)--;
		}
	}
}

static int dns_resolver_name_list(char *dns_result, int *tmp_slot,
				  struct nfs_ip_list *ip_list)
{
	int error = 0;
	ssize_t ip_len;
	char *ip_str;
	struct sockaddr_storage sa;

	enfs_log_debug("	resolver name list\n");
	ip_str = strsep(&dns_result, ",");
	while (ip_str) {
		if (ip_list->count == enfs_get_config_link_count_per_mount() ||
		    *tmp_slot == 0) {
			error = 0;
			break;
		}

		ip_len = rpc_pton(NULL, ip_str, strlen(ip_str),
				  (struct sockaddr *)&sa, sizeof(sa));
		if (ip_len <= 0) {
			enfs_log_error("pton name:%s failed.\n", ip_str);
			error = -ESRCH;
			break;
		}

		if (enfs_insert_ip_list(ip_list,
					enfs_get_config_link_count_per_mount(),
					&sa)) {
			(*tmp_slot)--;
		}

		ip_str = strsep(&dns_result, ",");
	}

	return error;
}

/** DNS server maybe return 1 ip everytime,need get multi times,to sure get
 * different ip.
 * @slot: distributed when multiple domain names.
 * @optsions: ipv4 or ipv6
 */
static int multi_query_dns(struct nfs_ip_list *ip_list, char *name, int slot,
			   int *tmp_slot, const char *options)
{
	int error;
	char *ip_addr = NULL;
	int ip_len;

	struct net *net;

	net = current->nsproxy->net_ns;
	enfs_log_debug("domain_name:%s option:%s\n", name, options);
	ip_len = dns_query(net, NULL, name, strlen(name), options,
			   &ip_addr, NULL, true);
	if (ip_len <= 0) {
		enfs_log_debug("dns query:%s error.\n", ip_addr);
		return -ESRCH;
	}

	/*
	 * Note:
	 * Query domain name list, query only once.
	 * Now,the executable program in user space must return the IP list.
	 */
	error = dns_resolver_name_list(ip_addr, tmp_slot, ip_list);
	kfree(ip_addr);
	return error;
}

// Only process ipv4 when remotetarget family is ipv4.
// Both ipv4 and ipv6 when remotetarget family is ipv6.
static int query_dns_cross_protocol(struct nfs_ip_list *ip_list, char *name,
				    int slot, unsigned short family)
{
	int ret;
	int tmp_slot = slot;

	// allow ipv6 query failed.
	if (family == AF_INET6) {
		ret = multi_query_dns(ip_list, name, slot, &tmp_slot,
				      "ipv6 list");
		if (ret) {
			enfs_log_debug("dns query name:%s type:ipv6 err:%d.\n",
				       name, ret);
		}

		ret = multi_query_dns(ip_list, name, slot, &tmp_slot,
				      "ipv4 list");
		if (ret) {
			enfs_log_debug("dns query name:%s type:ipv4 err:%d.\n",
				       name, ret);
		}
		return 0;
	}

	ret = multi_query_dns(ip_list, name, slot, &tmp_slot, "ipv4 list");
	if (ret)
		enfs_log_debug("dns query name:%s type:A err:%d.\n", name, ret);
	return ret;
}

static bool query_domain_name_in_cache(struct nfs_ip_list *ip_list, char *name,
				       int slot, unsigned short family)
{
	struct name_list *name_list;
	int tmp_solt = slot;
	bool ret = false;

	// 两个域名16,一个域名32
	// v4仅v4,v6优先v6
	spin_lock(&dns_cache_lock);
	list_for_each_entry(name_list, &dns_cache_list, next) {
		if (strcmp(name_list->name, name) != 0)
			continue;

		if (family == AF_INET6)
			ip_list_append(ip_list, &name_list->inet6, &tmp_solt);
		ip_list_append(ip_list, &name_list->inet, &tmp_solt);

		if (tmp_solt != slot)
			ret = true;
		break;
	}
	spin_unlock(&dns_cache_lock);
	return ret;
}

int enfs_quick_sort(int low, int high, struct enfs_dns_query_ip_info_single *dns_query_ip_info)
{
	int i = low;
	int j = high;
	u64 key = dns_query_ip_info[i].lsId;

	strscpy(dns_sort_ip, dns_query_ip_info[i].ipAddr, IP_ADDRESS_LEN_MAX);

	while (i < j) {
		while (i < j && dns_query_ip_info[j].lsId >= key)
			j--;

		dns_query_ip_info[i].lsId = dns_query_ip_info[j].lsId;
		strscpy(dns_query_ip_info[i].ipAddr,
			dns_query_ip_info[j].ipAddr, IP_ADDRESS_LEN_MAX);

		while (i < j && dns_query_ip_info[i].lsId <= key)
			i++;

		dns_query_ip_info[j].lsId = dns_query_ip_info[i].lsId;
		strscpy(dns_query_ip_info[j].ipAddr,
			dns_query_ip_info[i].ipAddr, IP_ADDRESS_LEN_MAX);
	}
	dns_query_ip_info[i].lsId = key;
	strscpy(dns_query_ip_info[i].ipAddr, dns_sort_ip, IP_ADDRESS_LEN_MAX);
	if (i - 1 > low)
		enfs_quick_sort(low, i - 1, dns_query_ip_info);

	if (i + 1 < high)
		enfs_quick_sort(i + 1, high, dns_query_ip_info);
	memset(dns_sort_ip, 0, sizeof(dns_sort_ip));

	return 0;
}

int enfs_dns_process_ip(struct enfs_dns_query_ip_info_single *dns_query_ip_info,
			struct enfs_dns_query_lsid_rsp **dns_query_lsid_info, int *lsid_count,
			int ipNumber)
{
	int i;
	int index = 0;
	int count = 1;
	struct enfs_dns_query_lsid_rsp *ls_id_info = NULL;

	// sort all ip by lsid
	enfs_quick_sort(0, ipNumber - 1, dns_query_ip_info);
	for (i = 1; i < ipNumber; i++) {
		if (dns_query_ip_info[i - 1].lsId != dns_query_ip_info[i].lsId)
			count++;
	}

	*lsid_count = count;
	// combine ip by lsis,while ip's lsid is same,all of them combined to one structure
	ls_id_info = kmalloc_array(count, sizeof(struct enfs_dns_query_lsid_rsp), GFP_KERNEL);
	if (!ls_id_info)
		return -ENOMEM;

	for (i = 0; i < ipNumber; i++) {
		if (i != 0 &&
		    dns_query_ip_info[i - 1].lsId == dns_query_ip_info[i].lsId) {
			ls_id_info[index].count++;
			continue;
		}
		if (i != 0)
			index++;
		ls_id_info[index].lsId = dns_query_ip_info[i].lsId;
		ls_id_info[index].offset = 0;
		ls_id_info[index].count = 0;
		ls_id_info[index].count++;
	}

	*dns_query_lsid_info = ls_id_info;
	return 0;
}

int enfs_server_query_dns(struct rpc_clnt *clnt, struct enfs_route_dns_info *dns_info,
			  struct nfs_ip_list *ip_list, int slot,
			  u32 ip_type, u32 dns_namecount,
			  char *dns_name)
{
	int ret;
	int i = 0;
	int offset = 0;
	int tmp_slot = slot;
	struct enfs_dns_query_lsid_rsp *dns_query_lsid_info = NULL;
	struct enfs_dns_query_ip_info_single *dns_query_ip_info = NULL;
	// malloc max node 256
	int ipNumber;
	int lsid_count;

	ret = dorado_query_dns(clnt, &dns_query_ip_info, ip_type, dns_namecount,
			       dns_name, &ipNumber);
	if (ret)
		return ret;

	if (!dns_query_ip_info)
		return ret;

	ret = enfs_dns_process_ip(dns_query_ip_info, &dns_query_lsid_info, &lsid_count,
				  ipNumber);
	if (ret)
		return ret;

	i = 0;
	while (ip_list->count <
	       (enfs_get_config_link_count_per_mount() < ipNumber ?
			enfs_get_config_link_count_per_mount() :
			ipNumber)) {
		if (dns_query_lsid_info[i].offset < dns_query_lsid_info[i].count) {
			if (i != 0)
				offset += dns_query_lsid_info[i - 1].count;
			ret = dns_resolver_name_list(
				dns_query_ip_info[offset +
						 dns_query_lsid_info[i].offset].ipAddr,
				&tmp_slot, ip_list);
			if (ret)
				goto out;
			dns_query_lsid_info[i].offset++;
			i++;
		} else {
			i++;
		}
		if (i == lsid_count) {
			offset = 0;
			i = 0;
		}
	}

out:
	kfree(dns_query_ip_info);
	kfree(dns_query_lsid_info);
	return ret;
}

void query_dns_each_name(struct enfs_route_dns_info *dns_info, int slot,
			 struct nfs_ip_list *ip_list, unsigned short family,
			 bool use_cache)
{
	int ret;
	int i;
	char *dns_name = NULL;

	for (i = 0; i < dns_info->dnsNameCount; i++) {
		dns_name = dns_info->routeRemoteDnsList[i].dnsname;
		enfs_log_debug("query DNS:%s\n", dns_name);

		if (use_cache &&
		    query_domain_name_in_cache(ip_list, dns_name, slot, family)) {
			enfs_log_debug("cache name:%s.\n", dns_name);
			continue;
		}
		ret = query_dns_cross_protocol(ip_list, dns_name, slot, family);
		if (ret != 0)
			enfs_log_debug("dns multi query dns failed.\n");
		else
			enfs_update_domain_name(dns_name, ip_list);
	}
}

int multipath_query_dns(struct multipath_mount_options *opt,
			unsigned short family, bool use_cache,
			struct rpc_clnt *clnt)
{
	int ret;
	int i;
	int slot = 0;
	struct enfs_route_dns_info *dns_info;
	char *dns_name = NULL;
	struct nfs_ip_list *ip_list;
	u32 ip_type = 0;

	if (!opt->pRemoteDnsInfo || opt->pRemoteDnsInfo->dnsNameCount <= 0 ||
	    opt->pRemoteDnsInfo->dnsNameCount > MAX_DNS_SUPPORTED) {
		return -EINVAL;
	}

	ip_list = kmalloc(sizeof(*ip_list), GFP_KERNEL);
	if (!ip_list)
		return -ENOMEM;
	ip_list->count = 0;
	dns_info = opt->pRemoteDnsInfo;
	dns_name = kmalloc(dns_info->dnsNameCount * EXTEND_MAX_DNS_NAME_LEN, GFP_KERNEL);
	if (!dns_name) {
		kfree(ip_list);
		return -ENOMEM;
	}

	if (clnt) {
		if (family == AF_INET6)
			ip_type = IP_TYPE_BOTH;
		for (i = 0; i < dns_info->dnsNameCount; i++) {
			sprintf(dns_name + i * EXTEND_MAX_DNS_NAME_LEN, "%s",
				dns_info->routeRemoteDnsList[i].dnsname);
		}

		slot = enfs_get_config_link_count_per_mount() /
		       dns_info->dnsNameCount;
		ret = enfs_server_query_dns(clnt, dns_info, ip_list,
					    enfs_get_config_link_count_per_mount(), ip_type,
					    dns_info->dnsNameCount, dns_name);
		if (ret != 0) {
			query_dns_each_name(dns_info, slot, ip_list, family,
					    use_cache);
		}
	} else {
		query_dns_each_name(dns_info, slot, ip_list, family, use_cache);
	}

	kfree(dns_name);
	if (ip_list->count == 0) {
		enfs_log_debug("query dns failed, no IP is found.\n");
		kfree(ip_list);
		return -ESRCH;
	}

	memcpy(opt->remote_ip_list, ip_list, sizeof(struct nfs_ip_list));
	kfree(ip_list);
	return 0;
}

typedef int (*enfs_iter_clnt)(struct nfs_client *clp, void *data);
int enfs_iter_nfs_clnt(enfs_iter_clnt fn, void *data)
{
	struct net *net;
	struct nfs_net *nn;
	struct nfs_client *clp;
	int ret = 0;

	rcu_read_lock();
	for_each_net_rcu(net) {
		nn = net_generic(net, nfs_net_id);
		if (!nn)
			continue;

		if (list_empty(&nn->nfs_client_list))
			continue;
		spin_lock(&nn->nfs_client_lock);
		list_for_each_entry(clp, &nn->nfs_client_list, cl_share_link) {
			if (!clp->cl_multipath_data)
				continue;

			ret = fn(clp, data);
			if (ret != 0)
				break;
		}
		spin_unlock(&nn->nfs_client_lock);
		break;
	}
	rcu_read_unlock();
	return ret;
}

void enfs_add_domain_name(struct multipath_mount_options *opt)
{
	int i;

	if (!opt->pRemoteDnsInfo || opt->pRemoteDnsInfo->dnsNameCount == 0)
		return;

	for (i = 0;
	     i < MAX_DNS_SUPPORTED && i < opt->pRemoteDnsInfo->dnsNameCount;
	     i++) {
		enfs_domain_inc(opt->pRemoteDnsInfo->routeRemoteDnsList[i].dnsname);
	}
}

static int collect_clnt_name(struct nfs_client *clp, void *data)
{
	int i;
	struct multipath_client_info *clp_info = clp->cl_multipath_data;

	for (i = 0; i < MAX_DNS_SUPPORTED &&
		    i < clp_info->pRemoteDnsInfo->dnsNameCount;
	     i++) {
		enfs_domain_inc(clp_info->pRemoteDnsInfo->routeRemoteDnsList[i].dnsname);
	}
	return 0;
}

static int enfs_collect_all_domain_name(void)
{
	struct name_list *ls;
	struct name_list *ls_next;

	/* 1. clear domain name ref */
	spin_lock(&dns_cache_lock);
	list_for_each_entry(ls, &dns_cache_list, next) {
		ls->ref = 0;
	}
	spin_unlock(&dns_cache_lock);

	/* 2. add reference */
	enfs_iter_nfs_clnt(collect_clnt_name, NULL);

	/* 3. release 0 reference name */
	spin_lock(&dns_cache_lock);
	list_for_each_entry_safe(ls, ls_next, &dns_cache_list, next) {
		if (ls->ref == 0) {
			list_del(&ls->next);
			kfree(ls);
		}
	}
	spin_unlock(&dns_cache_lock);
	return 0;
}

void enfs_domain_for_each(int (*func)(struct name_list *, void *), void *data)
{
	struct name_list *name_list;
	struct name_list *next_list;
	int ret;

	spin_lock(&dns_cache_lock);
	list_for_each_entry_safe(name_list, next_list, &dns_cache_list, next) {
		ret = func(name_list, data);
		if (ret)
			break;
	}
	spin_unlock(&dns_cache_lock);
}

struct query_name_work {
	struct work_struct work;
	char name[MAX_DNS_NAME_LEN];
	struct nfs_ip_list ip_list;
};

static void do_dns_update_new(struct work_struct *work)
{
	int error;
	struct multipath_mount_options opt;
	struct enfs_route_dns_info dns_info;
	struct query_name_work *query_work =
		container_of(work, struct query_name_work, work);

	dns_info.dnsNameCount = 1;
	strscpy(dns_info.routeRemoteDnsList[0].dnsname, query_work->name, MAX_DNS_NAME_LEN);
	opt.remote_ip_list = &query_work->ip_list;
	opt.pRemoteDnsInfo = &dns_info;

	error = multipath_query_dns(&opt, AF_INET, false, NULL);
	if (error != 0)
		enfs_log_debug("Scheduled update dns err:%d.\n", error);
	else
		enfs_update_domain_name(query_work->name, &query_work->ip_list);

	error = multipath_query_dns(&opt, AF_INET6, false, NULL);
	if (error != 0)
		enfs_log_debug("Scheduled update dns err:%d.\n", error);
	else
		enfs_update_domain_name(query_work->name, &query_work->ip_list);

	kfree(query_work);
}

static int domain_name_update(struct name_list *name_list, void *data)
{
	bool ok;
	struct query_name_work *query_work;

	query_work = kmalloc(sizeof(*query_work), GFP_KERNEL);
	if (!query_work) {
		enfs_log_error("alloc failed.\n");
		return 0;
	}

	INIT_WORK(&query_work->work, do_dns_update_new);
	strscpy(query_work->name, name_list->name, MAX_DNS_NAME_LEN);
	memset(&query_work->ip_list, 0, sizeof(struct nfs_ip_list));

	ok = queue_work(dns_workq, &query_work->work);
	if (!ok) {
		kfree(query_work);
		enfs_log_info("queue work failed\n");
	}
	return 0;
}

struct dns_work {
	struct work_struct wk_work;
	struct nfs_client *clp;
	struct multipath_client_info *clp_info;
	struct rpc_clnt *clRpcclient;
	struct sockaddr_storage ss;
	bool query_ok;
};

static int find_and_remount(struct nfs_client *clp, void *data)
{
	int error;
	struct dns_work *work = data;
	struct multipath_mount_options opt;
	struct multipath_client_info *clp_info = work->clp_info;
	struct multipath_client_info *info = clp->cl_multipath_data;

	if (clp != work->clp)
		return 0;

	if (!work->query_ok)
		goto do_err;

	opt.remote_ip_list = clp_info->remote_ip_list;
	opt.local_ip_list = clp_info->local_ip_list;
	opt.pRemoteDnsInfo = clp_info->pRemoteDnsInfo;
	error = enfs_remount_iplist(clp, &opt);
	if (error != 0)
		enfs_log_info("Scheduled remount err:%d.\n", error);

do_err:
	/* set domain name update flag in nfs client list spin_lock */
	info->updating_domain = 0;
	return 1;
}

static void do_dns_update(struct work_struct *work)
{
	int error;
	struct multipath_mount_options opt;
	struct dns_work *wk = container_of(work, struct dns_work, wk_work);
	struct multipath_client_info *clp_info = wk->clp_info;

	opt.remote_ip_list = clp_info->remote_ip_list;
	opt.local_ip_list = clp_info->local_ip_list;
	opt.pRemoteDnsInfo = clp_info->pRemoteDnsInfo;
	error = multipath_query_dns(&opt, wk->ss.ss_family, true,
				    wk->clRpcclient);
	if (error != 0) {
		enfs_log_info("Scheduled update dns err:%d.\n", error);
		wk->query_ok = false;
	}

	find_and_remount(wk->clp, wk);

	enfs_free_nfsclient_info(wk->clp_info);
	nfs_put_client(wk->clp);
	//rpc_release_client(wk->clRpcclient);
	kfree(wk);
	wk = NULL;
}

static int dns_update_work(struct nfs_client *clp, void *data)
{
	bool ok;
	int error;
	struct dns_work *wk;
	struct multipath_client_info *clp_info = clp->cl_multipath_data;
	struct list_head *list = (struct list_head *)data;
	struct clnt_release_item *item;

	wk = kzalloc(sizeof(*wk), GFP_KERNEL);
	if (!wk)
		return -ENOMEM;

	error = enfs_alloc_nfsclient_info(&wk->clp_info);
	if (error) {
		kfree(wk);
		return -ENOMEM;
	}

	item = kzalloc(sizeof(*item), GFP_KERNEL);
	if (!item) {
		enfs_free_nfsclient_info(wk->clp_info);
		kfree(wk);
		return -ENOMEM;
	}
	/* set domain name update flag */
	clp_info->updating_domain = 1;

	*wk->clp_info->remote_ip_list = *clp_info->remote_ip_list;
	*wk->clp_info->local_ip_list = *clp_info->local_ip_list;
	*wk->clp_info->pRemoteDnsInfo = *clp_info->pRemoteDnsInfo;

	if (!refcount_inc_not_zero(&clp->cl_rpcclient->cl_count)) {
		enfs_free_nfsclient_info(wk->clp_info);
		kfree(wk);
		kfree(item);
	}
	nfsclient_refinc(&clp->cl_count);
	wk->clp = clp;
	wk->clRpcclient = clp->cl_rpcclient;
	INIT_WORK(&wk->wk_work, do_dns_update);
	rpc_peeraddr(clp->cl_rpcclient, (struct sockaddr *)&wk->ss,
		     sizeof(struct sockaddr_storage));
	wk->query_ok = true;

	ok = queue_work(dns_workq, &wk->wk_work);
	if (!ok) {
		clp_info->updating_domain = 0;
		enfs_free_nfsclient_info(wk->clp_info);
		item->clnt = wk->clRpcclient;
		item->client = wk->clp;
		list_add_tail(&item->node, list);
		kfree(wk);
		return -1;
	}
	kfree(item);
	return 0;
}

static int requery_clnt_dns(struct nfs_client *clp, void *data)
{
	int error;
	struct multipath_client_info *clp_info = clp->cl_multipath_data;

	if (kthread_should_stop())
		return 1;

	if (!clp_info || !clp->cl_rpcclient || clp_info->fill_local ||
	    clp_info->updating_domain) {
		return 0;
	}

	if (clp->cl_cons_state > NFS_CS_READY) {
		enfs_log_info("client not ready.\n");
		return 0;
	}

	if (!clp_info->pRemoteDnsInfo ||
	    clp_info->pRemoteDnsInfo->dnsNameCount == 0) {
		return 0;
	}

	error = dns_update_work(clp, data);
	if (error)
		enfs_log_info("dns update queue err:%d\n", error);
	return 0;
}

static int dns_update_loop(void *data)
{
	int32_t interval_ms;
	ktime_t start = ktime_get();
	const int query_times = 5; /* Update after multiple queries */
	int times = 0;
	LIST_HEAD(free_list);

	while (!kthread_should_stop()) {
		/*
		 * Ensure the domain name is queried more
		 * than 5 times before being remount.
		 */
		interval_ms =
			enfs_get_config_dns_update_interval() * 60 * 1000 / 5;
		if (interval_ms != 0 && enfs_timeout_ms(&start, interval_ms) &&
		    enfs_get_config_multipath_state() ==
			    ENFS_MULTIPATH_ENABLE) {
			start = ktime_get();
			enfs_collect_all_domain_name();
			enfs_domain_for_each(domain_name_update, NULL);

			if (times == query_times) {
				enfs_swap_name_cache();
				enfs_iter_nfs_clnt(requery_clnt_dns,
						       &free_list);
				enfs_destroy_clnt_list(&free_list);
				enfs_log_debug("update DNS.");
				times = 0;
			}
			times++;
		}
		enfs_msleep(1000);
	}
	return 0;
}

int enfs_dns_init(void)
{
	spin_lock_init(&dns_cache_lock);

	dns_workq = create_workqueue("enfs_dns_workqueue");
	if (!dns_workq) {
		enfs_log_error("create workqueue failed.\n");
		return -ENOMEM;
	}

	dns_thread = kthread_run(dns_update_loop, NULL, "enfs_dns_update");
	if (IS_ERR(dns_thread)) {
		enfs_log_error("Failed to create thread enfs_dns_update.\n");
		return PTR_ERR(dns_thread);
	}
	return 0;
}

void enfs_dns_exit(void)
{
	if (dns_thread)
		kthread_stop(dns_thread);

	if (dns_workq)
		destroy_workqueue(dns_workq);
}

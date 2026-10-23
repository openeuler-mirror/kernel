// SPDX-License-Identifier: GPL-2.0
/*
 *  Client-side ENFS adapt header.
 *
 *  Copyright (c) 2023. Huawei Technologies Co., Ltd. All rights reserved.
 */
#include "enfs_rpc_proc.h"
#include "enfs_lookup_cache.h"
#include "enfs_multipath_client.h"
#include "enfs_log.h"
#include "enfs_config.h"
#include "../../../fs/nfs/netns.h"
#include "enfs.h"

#define ENFS_LOOKUPCACHE_ACTIVE \
	(1 << 30) /* Indicates that the file system is currently active */

#define ENFS_LOOKUP_ACTIVE \
	SB_ACTIVE /* Indicates that the file system is currently active */

static struct task_struct *lookupcache_thread;
static struct workqueue_struct *lookupcache_workq;
static spinlock_t g_lookupcache_switch_lock;
static int g_lookupcache_switch = ENFS_LOOKUPCACHE_ENABLE;
static ktime_t start_query_lookup = { 0 };

static bool start_query_lookup_init;

const struct rpc_procinfo enfs_lookup_cahce = { PROC(LOOKUPCACHE, lookupcache,
						     lookupcache, 1) };

static void encode_uint32(struct xdr_stream *xdr, u32 value)
{
	__be32 *p = xdr_reserve_space(xdr, 4);
	*p = cpu_to_be32(value);
}

static void encode_nfs_fh(struct xdr_stream *xdr, const struct nfs_fh *fh)
{
	__be32 *p;

	WARN_ON_ONCE(fh->size > ENFS_fhandle_sz);
	p = xdr_reserve_space(xdr, 4 + fh->size);
	xdr_encode_opaque(p, fh->data, fh->size);
}

static int decode_uint32(struct xdr_stream *xdr, u32 *value)
{
	__be32 *p;

	p = xdr_inline_decode(xdr, 4);
	if (unlikely(p == NULL))
		goto out_overflow;
	*value = be32_to_cpup(p);
	return 0;
out_overflow:
	return -EIO;
}

void enfs_xdr_enc_lookupcacheargs(struct rpc_rqst *rqstp,
				  struct xdr_stream *xdr, const void *data)
{
	const struct enfs_get_onfig_args *args = data;

	encode_uint32(xdr, args->version);
	encode_uint32(xdr, args->mask);
	encode_uint32(xdr, args->reserve);
	encode_nfs_fh(xdr, &args->fh);
	encode_uint32(xdr, args->vers);
}

int enfs_xdr_dec_lookupcacheres(struct rpc_rqst *req, struct xdr_stream *xdr,
				void *data)
{
	int error;
	struct enfs_get_onfig_res *enfsRes = data;

	error = decode_uint32(xdr, &enfsRes->version);
	if (unlikely(error))
		goto out;
	error = decode_uint32(xdr, &enfsRes->mask);
	if (unlikely(error))
		goto out;
	error = decode_uint32(xdr, &enfsRes->lookupCache);
	if (unlikely(error))
		goto out;
	error = decode_uint32(xdr, &enfsRes->reserve);
	if (unlikely(error))
		goto out;
	error = decode_uint32(xdr, &enfsRes->status);
	if (unlikely(error))
		goto out;
out:
	return error;
}

void enfs_clean_server_lookup_cache_flag(void)
{
	struct nfs_net *nn = net_generic(current->nsproxy->net_ns, nfs_net_id);
	struct nfs_server *pos;

	spin_lock(&nn->nfs_client_lock);
	list_for_each_entry(pos, &nn->nfs_volume_list, master_link) {
		pos->enfs_flags &= ~(ENFS_SERVER_FLAG_LOOKUP_CACHE_NOREG |
				     ENFS_SERVER_FLAG_LOOKUP_CACHE_NONE |
				     ENFS_SERVER_FLAG_GET_CAP_RUNNING);
	}
	spin_unlock(&nn->nfs_client_lock);
}

void enfs_update_lookup_cache_flag_to_server(u32 result,
					     struct nfs_server *server)
{
	spin_lock(&g_lookupcache_switch_lock);
	/* If not use multipath mount option, don't set enfs flag.
	 * this process is mutually exclusive with the cleanup process
	 * when change the switch to disable.
	 */
	if (g_lookupcache_switch == ENFS_LOOKUPCACHE_ENABLE &&
	    server->nfs_client && server->nfs_client->cl_multipath_data) {
		switch (result) {
		case ENFS_LOOKUPCACHE_ALL:
			server->enfs_flags &=
				~(ENFS_SERVER_FLAG_LOOKUP_CACHE_NOREG |
				  ENFS_SERVER_FLAG_LOOKUP_CACHE_NONE);
			break;
		case ENFS_LOOKUPCACHE_NONEG:
			server->enfs_flags &=
				~ENFS_SERVER_FLAG_LOOKUP_CACHE_NONE;
			server->enfs_flags |=
				ENFS_SERVER_FLAG_LOOKUP_CACHE_NOREG;
			break;
		case ENFS_LOOKUPCACHE_NONE:
			server->enfs_flags |=
				(ENFS_SERVER_FLAG_LOOKUP_CACHE_NOREG |
				 ENFS_SERVER_FLAG_LOOKUP_CACHE_NONE);
			break;
		default:
			enfs_log_info("Get invalid lookupCache:%u.\n", result);
		}
	}
	spin_unlock(&g_lookupcache_switch_lock);
}

int enfs_query_lookup_cache(struct lookupcache_work *work_info)
{
	int ret;
	struct enfs_get_onfig_res enfsRes = { 0 };
	struct enfs_get_onfig_args args = { 0 };
	struct nfs_server *pos = NULL;
	struct net *net;
	struct nfs_net *nn = NULL;
	struct inode *inode = NULL;
	struct nfs_fh *fh = NULL;
	struct dentry *s_root;
	struct super_block *super;
	int32_t interval_ms = 5 * 60 * 1000;
	struct enfs_xprt_context *ctx = NULL;

	args.mask = BIT(ENFS_LOOKUP_CACHE_LEVEL);
	args.fh = work_info->fh;
	args.version = ENFS_VERSION_BUTT - 1;
	args.vers = work_info->cl_rpcclient->cl_vers;

	ret = enfs_rpc_send(work_info->cl_rpcclient, ENFSPROC_LOOKUPCACHE,
			    &args, &enfsRes);

	/* every 5 minutes prints the error log */
	if (ret) {
		if (!start_query_lookup_init) {
			start_query_lookup_init = true;
			start_query_lookup = ktime_get();
		} else if (enfs_timeout_ms(&start_query_lookup, interval_ms)) {
			enfs_log_error("get lookupcache failed %d.\n", ret);
			start_query_lookup = ktime_get();
		}
		return ret;
	}

	rcu_read_lock();
	for_each_net_rcu(net) {
		nn = net_generic(net, nfs_net_id);
		if (nn == NULL)
			continue;

		spin_lock(&nn->nfs_client_lock);
		list_for_each_entry(pos, &nn->nfs_volume_list, master_link) {
			if (pos != work_info->server)
				continue;

			super = pos->super;
			if (!super)
				break;

			s_root = super->s_root;
			if (!s_root)
				break;

			if (!(pos->super->s_flags & ENFS_LOOKUP_ACTIVE))
				break;

			if (atomic_read(&super->s_active) == 0)
				break;

			inode = d_inode(s_root);
			if (!inode)
				break;

			fh = NFS_FH(inode);
			if (memcmp(fh, &work_info->fh, sizeof(struct nfs_fh)) ==
			    0) {
				if (!ret) {
					enfs_update_lookup_cache_flag_to_server(
						enfsRes.lookupCache, pos);
				}
				pos->enfs_flags &=
					~ENFS_SERVER_FLAG_GET_CAP_RUNNING;
				xprt_get(pos->client->cl_xprt);
				ctx = (struct enfs_xprt_context *)
					xprt_get_reserve_context(
						pos->client->cl_xprt);
				if (ctx == NULL) {
					enfs_log_error(
						"The xprt multipath ctx is not valid.\n");
					xprt_put(pos->client->cl_xprt);
					spin_unlock(&nn->nfs_client_lock);
					rcu_read_unlock();
					return ret;
				}
				if (enfsRes.version ==
				    ENFS_SERVER_VERSION_BASE) {
					ctx->version = ENFS_SERVER_VERSION_BASE;
				} else {
					ctx->version = 0;
				}
				xprt_put(pos->client->cl_xprt);
			}
		}
		spin_unlock(&nn->nfs_client_lock);
		break;
	}
	rcu_read_unlock();

	return ret;
}

bool enfs_query_lookup_cache_pre_check(struct nfs_server *server)
{
	struct multipath_client_info *client_info = NULL;

	if (server->enfs_flags & ENFS_SERVER_FLAG_GET_CAP_RUNNING)
		return false;

	if (server->nfs_client)
		client_info = server->nfs_client->cl_multipath_data;

	if (client_info && server->super &&
	    (server->super->s_flags & ENFS_LOOKUP_ACTIVE) &&
	    server->super->s_root) {
		return true;
	}
	return false;
}

void lookupcache_execute_work(struct work_struct *work)
{
	int ret = 0;

	// get the work information
	struct lookupcache_work *work_info =
		container_of(work, struct lookupcache_work, work_lookup);

	if (!work_info->server) {
		enfs_log_error("work_info->nfs_client null .\n");
		goto stop;
	}
	ret = enfs_query_lookup_cache(work_info);
	if (ret) {
		enfs_log_debug("lookupcache execute failed ,ret %d", ret);
		goto stop;
	}
stop:
	rpc_release_client(work_info->cl_rpcclient);
	kfree(work_info);
	work_info = NULL;
}

int lookupcache_add_work(struct nfs_fh *fh, struct nfs_server *server,
			 struct list_head *head)
{
	struct lookupcache_work *work_info;
	struct rpcclnt_release_item *item;
	bool ret = false;

	if (IS_ERR(fh) || fh == NULL) {
		enfs_log_error("The fh ptr is not exist.\n");
		return -EINVAL;
	}

	if (IS_ERR(server) || server == NULL) {
		enfs_log_error("The clnt ptr is not exist.\n");
		return -EINVAL;
	}

	work_info = kzalloc(sizeof(struct lookupcache_work), GFP_ATOMIC);
	if (work_info == NULL)
		return -ENOMEM;

	item = kzalloc(sizeof(*item), GFP_KERNEL);
	if (!item) {
		enfs_log_error("alloc item failed.\n");
		kfree(work_info);
		return -ENOMEM;
	}

	if (!refcount_inc_not_zero(
		    &server->nfs_client->cl_rpcclient->cl_count)) {
		kfree(work_info);
		kfree(item);
		return -EINVAL;
	}
	work_info->fh = *fh;
	work_info->server = server;
	work_info->cl_rpcclient = server->nfs_client->cl_rpcclient;

	INIT_WORK(&work_info->work_lookup, lookupcache_execute_work);

	ret = queue_work(lookupcache_workq, &work_info->work_lookup);
	if (!ret) {
		item->clnt = work_info->cl_rpcclient;
		list_add_tail(&item->node, head);
		kfree(work_info);
		work_info = NULL;
		return -EINVAL;
	}

	kfree(item);
	server->enfs_flags |= ENFS_SERVER_FLAG_GET_CAP_RUNNING;
	return 0;
}

void enfs_trigger_get_capability(struct nfs_server *server)
{
	struct nfs_fh *fh = NULL;
	LIST_HEAD(free_list);

	if (enfs_query_lookup_cache_pre_check(server)) {
		struct inode *inode = d_inode(server->super->s_root);

		if (!inode)
			return;
		fh = NFS_FH(inode);
		lookupcache_add_work(fh, server, &free_list);
	}
	enfs_destroy_rpcclnt_list(&free_list);
}

void lookupcache_loop_rpclnt(void)
{
	struct net *net;
	struct nfs_net *nn;
	struct nfs_server *pos;
	struct nfs_fh *fh = NULL;
	struct dentry *s_root;
	struct super_block *super;
	struct inode *inode = NULL;
	LIST_HEAD(free_list);

	rcu_read_lock();
	for_each_net_rcu(net) {
		nn = net_generic(net, nfs_net_id);
		if (nn == NULL)
			continue;

		if (list_empty(&nn->nfs_volume_list))
			continue;

		spin_lock(&nn->nfs_client_lock);
		list_for_each_entry(pos, &nn->nfs_volume_list, master_link) {
			if (enfs_query_lookup_cache_pre_check(pos)) {
				super = pos->super;
				if (!super)
					continue;

				s_root = super->s_root;
				if (!s_root)
					continue;

				if (atomic_read(&super->s_active) == 0)
					continue;

				inode = d_inode(s_root);
				if (!inode)
					continue;

				fh = NFS_FH(inode);
				lookupcache_add_work(fh, pos, &free_list);
			}
		}
		spin_unlock(&nn->nfs_client_lock);
		break;
	}
	rcu_read_unlock();
	enfs_destroy_rpcclnt_list(&free_list);
}

void enfs_lookupcache_update_switch(void)
{
	int old_value = g_lookupcache_switch;
	int new_value = enfs_get_config_lookupcache_state();

	spin_lock(&g_lookupcache_switch_lock);
	if (old_value != new_value)
		g_lookupcache_switch = new_value;

	spin_unlock(&g_lookupcache_switch_lock);

	if ((old_value != new_value) &&
	    (new_value == ENFS_LOOKUPCACHE_DISABLE)) {
		enfs_clean_server_lookup_cache_flag();
	}
}

int lookupcache_routine(void *data)
{
	ktime_t start = ktime_get();
	int32_t interval_ms;

	while (!kthread_should_stop()) {
		enfs_lookupcache_update_switch();
		interval_ms = enfs_get_config_lookupcache_interval() * 1000;
		if ((g_lookupcache_switch == ENFS_LOOKUPCACHE_ENABLE) &&
		    enfs_timeout_ms(&start, interval_ms) &&
		    (enfs_get_config_multipath_state() ==
		     ENFS_MULTIPATH_ENABLE)) {
			start = ktime_get();
			lookupcache_loop_rpclnt();
		}
		enfs_msleep(1000);
	}
	return 0;
}

int lookupcache_start(void)
{
	lookupcache_thread =
		kthread_run(lookupcache_routine, NULL, "enfs_lookupcache");
	if (IS_ERR(lookupcache_thread)) {
		enfs_log_error("Failed to create thread lookupcache get.\n");
		return PTR_ERR(lookupcache_thread);
	}
	return 0;
}

int enfs_lookupcache_workqueue_init(void)
{
	lookupcache_workq = create_workqueue("enfs_lookupcache_workqueue");
	if (!lookupcache_workq) {
		enfs_log_error("create enfs_lookupcache workqueue failed.\n");
		return -ENOMEM;
	}

	return 0;
}

void lookupcache_workqueue_fini(void)
{
	enfs_log_debug("delete work queue\n");

	if (lookupcache_workq)
		destroy_workqueue(lookupcache_workq);
}

int enfs_lookupcache_timer_init(void)
{
	int ret;

	ret = enfs_lookupcache_workqueue_init();
	if (ret != 0) {
		enfs_log_error(
			"enfs: lookupcache timer init workqueue init failed.\n");
		return ret;
	}
	ret = lookupcache_start();
	if (ret != 0) {
		enfs_log_error(
			"enfs: lookupcache timer init work start failed.\n");
		lookupcache_workqueue_fini();
		return ret;
	}

	return ret;
}

void enfs_lookupcache_fini(void)
{
	if (lookupcache_thread)
		kthread_stop(lookupcache_thread);

	lookupcache_workqueue_fini();
}

int enfs_lookupcache_init(void)
{
	spin_lock_init(&g_lookupcache_switch_lock);
	enfs_proc_reg(ENFSPROC_LOOKUPCACHE, &enfs_lookup_cahce);
	return enfs_lookupcache_timer_init();
}

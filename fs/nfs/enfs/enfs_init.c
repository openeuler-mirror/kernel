// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */
#include <linux/module.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/limits.h>
#include <linux/ratelimit.h>
#include <linux/slab.h>
#include <linux/sunrpc/svc_xprt.h>
#include <linux/sunrpc/sched.h>
#include <linux/sunrpc/clnt.h>
#include <linux/tracepoint.h>
#include <linux/nfs.h>
#include <linux/nfs4.h>
#include <linux/nfs3.h>
#include <linux/nfs_fs.h>
#include <linux/nfs_fs_sb.h>
#include "enfs.h"
#include "enfs_multipath_parse.h"
#include "enfs_multipath_client.h"
#include "enfs_remount.h"
#include "enfs_lookup_cache.h"
#include "enfs_rpc_init.h"
#include "enfs_log.h"
#include "enfs_multipath.h"
#include "mgmt_init.h"
#include "dns_internal.h"
#include "shard.h"
#include "enfs_config.h"

#if IS_ENABLED(CONFIG_NFSD) && defined(CONFIG_TRACEPOINTS)
#include "../../nfsd/export.h"
#include "../../nfsd/nfsfh.h"
#endif

#ifdef CONFIG_TRACEPOINTS
static bool nfsd_link_debug = true;
module_param(nfsd_link_debug, bool, 0644);
MODULE_PARM_DESC(nfsd_link_debug,
		 "Log NFSD TCP/RDMA connection events (default: on)");

static struct tracepoint *enfs_nfsd_accept_tp;
static struct tracepoint *enfs_nfsd_detach_tp;
#if IS_ENABLED(CONFIG_NFSD)
static bool nfsd_export_debug;
module_param(nfsd_export_debug, bool, 0644);
MODULE_PARM_DESC(nfsd_export_debug,
		 "Log observed NFSD client/export requests (default: off)");

static struct tracepoint *enfs_nfsd_fh_verify_tp;
static DEFINE_RATELIMIT_STATE(enfs_nfsd_export_rs, 5 * HZ, 10);
#endif

static bool enfs_nfsd_addr_valid(const struct sockaddr_storage *addr,
				 size_t len)
{
	if (addr->ss_family == AF_INET)
		return len >= sizeof(struct sockaddr_in);
	if (addr->ss_family == AF_INET6)
		return len >= sizeof(struct sockaddr_in6);
	return false;
}

static void enfs_nfsd_link_log(const struct svc_xprt *xprt,
			       const char *state)
{
	const char *proto = xprt->xpt_class->xcl_name;

	if (!READ_ONCE(nfsd_link_debug) || !xprt->xpt_server ||
	    strcmp(xprt->xpt_server->sv_name, "nfsd"))
		return;
	if (strcmp(proto, "tcp") && strcmp(proto, "rdma"))
		return;
	if (!enfs_nfsd_addr_valid(&xprt->xpt_remote, xprt->xpt_remotelen) ||
	    !enfs_nfsd_addr_valid(&xprt->xpt_local, xprt->xpt_locallen))
		return;

	enfs_log_info("nfsd %pISpc -> %pISpc %s %s\n",
		      (struct sockaddr *)&xprt->xpt_remote,
		      (struct sockaddr *)&xprt->xpt_local,
		      !strcmp(proto, "tcp") ? "TCP" : "RDMA", state);
}

static void enfs_nfsd_link_accept(void *data, const struct svc_xprt *xprt,
				  const char *service)
{
	if (!strcmp(service, "nfsd"))
		enfs_nfsd_link_log(xprt, "CONNECTED");
}

static void enfs_nfsd_link_detach(void *data, const struct svc_xprt *xprt)
{
	enfs_nfsd_link_log(xprt, "CLOSED");
}

#if IS_ENABLED(CONFIG_NFSD)
static void enfs_nfsd_export_access(void *data, const struct svc_rqst *rqstp,
				    const struct svc_fh *fhp, umode_t type,
				    int access)
{
	const struct svc_xprt *xprt = rqstp->rq_xprt;
	char *buf, *path;

	if (!READ_ONCE(nfsd_export_debug) || !xprt || !fhp->fh_export ||
	    !enfs_nfsd_addr_valid(&xprt->xpt_remote, xprt->xpt_remotelen) ||
	    !enfs_nfsd_addr_valid(&xprt->xpt_local, xprt->xpt_locallen) ||
	    !__ratelimit(&enfs_nfsd_export_rs))
		return;

	buf = kmalloc(PATH_MAX, GFP_ATOMIC);
	if (!buf)
		return;
	path = d_path(&fhp->fh_export->ex_path, buf, PATH_MAX);
	if (!IS_ERR(path))
		enfs_log_info("nfsd client=%pISpc server=%pISpc export=%s\n",
			      (struct sockaddr *)&xprt->xpt_remote,
			      (struct sockaddr *)&xprt->xpt_local, path);
	kfree(buf);
}

static void enfs_nfsd_export_unbind(void)
{
	if (enfs_nfsd_fh_verify_tp) {
		tracepoint_probe_unregister(enfs_nfsd_fh_verify_tp,
					    enfs_nfsd_export_access, NULL);
		enfs_nfsd_fh_verify_tp = NULL;
	}
}
#else
static inline void enfs_nfsd_export_unbind(void) { }
#endif

static void enfs_nfsd_link_unbind(void)
{
	if (enfs_nfsd_accept_tp) {
		tracepoint_probe_unregister(enfs_nfsd_accept_tp,
					    enfs_nfsd_link_accept, NULL);
		enfs_nfsd_accept_tp = NULL;
	}
	if (enfs_nfsd_detach_tp) {
		tracepoint_probe_unregister(enfs_nfsd_detach_tp,
					    enfs_nfsd_link_detach, NULL);
		enfs_nfsd_detach_tp = NULL;
	}
}

static void enfs_nfsd_link_bind(struct tracepoint *tp, void *data)
{
	if (!enfs_nfsd_accept_tp && !strcmp(tp->name, "svc_xprt_accept")) {
		if (!tracepoint_probe_register(tp, enfs_nfsd_link_accept, NULL))
			enfs_nfsd_accept_tp = tp;
	} else if (!enfs_nfsd_detach_tp &&
		   !strcmp(tp->name, "svc_xprt_detach")) {
		if (!tracepoint_probe_register(tp, enfs_nfsd_link_detach, NULL))
			enfs_nfsd_detach_tp = tp;
	}
#if IS_ENABLED(CONFIG_NFSD)
	if (!enfs_nfsd_fh_verify_tp &&
	    !strcmp(tp->name, "nfsd_fh_verify")) {
		if (!tracepoint_probe_register(tp, enfs_nfsd_export_access,
					       NULL))
			enfs_nfsd_fh_verify_tp = tp;
	}
#endif
}

#ifdef CONFIG_MODULES
static bool enfs_nfsd_notifier_registered;

static int enfs_nfsd_tracepoint_notify(struct notifier_block *nb,
				       unsigned long action, void *data)
{
	struct module *mod = ((struct tp_module *)data)->mod;
	unsigned int i;

	if (strcmp(mod->name, "sunrpc") && strcmp(mod->name, "nfsd"))
		return NOTIFY_DONE;
	if (action == MODULE_STATE_COMING) {
		for (i = 0; i < mod->num_tracepoints; i++)
			enfs_nfsd_link_bind(
				tracepoint_ptr_deref(&mod->tracepoints_ptrs[i]), NULL);
	} else if (action == MODULE_STATE_GOING) {
		if (!strcmp(mod->name, "sunrpc"))
			enfs_nfsd_link_unbind();
		else
			enfs_nfsd_export_unbind();
	}
	return NOTIFY_OK;
}

static struct notifier_block enfs_nfsd_tracepoint_notifier = {
	.notifier_call = enfs_nfsd_tracepoint_notify,
};
#endif

static void enfs_nfsd_link_debug_init(void)
{
	for_each_kernel_tracepoint(enfs_nfsd_link_bind, NULL);
#ifdef CONFIG_MODULES
	if (!register_tracepoint_module_notifier(
			&enfs_nfsd_tracepoint_notifier))
		enfs_nfsd_notifier_registered = true;
#endif
	if (!enfs_nfsd_accept_tp || !enfs_nfsd_detach_tp)
		enfs_log_error("NFSD link tracepoints unavailable\n");
}

static void enfs_nfsd_link_debug_exit(void)
{
#ifdef CONFIG_MODULES
	if (enfs_nfsd_notifier_registered)
		unregister_tracepoint_module_notifier(
			&enfs_nfsd_tracepoint_notifier);
#endif
	enfs_nfsd_link_unbind();
	enfs_nfsd_export_unbind();
	tracepoint_synchronize_unregister();
}
#else
static inline void enfs_nfsd_link_debug_init(void) { }
static inline void enfs_nfsd_link_debug_exit(void) { }
#endif

static struct enfs_adapter_ops enfs_adapter = {
	.name = "enfs",
	.owner = THIS_MODULE,
	.parse_mount_options = nfs_multipath_parse_options,
	.free_mount_options = nfs_multipath_free_options,
	.client_info_init = nfs_multipath_client_info_init,
	.client_info_free = nfs_multipath_client_info_free,
	.client_info_match = nfs_multipath_client_info_match,
	.nfs4_client_info_match = nfs4_multipath_client_info_match,
	.client_info_show = nfs_multipath_client_info_show,
	.remount_ip_list = enfs_remount,
	.set_mount_data = enfs_set_mount_data,
	.trigger_get_capability = enfs_trigger_get_capability,
};

struct enfs_init_entry {
	char *name;
	int (*init)(void);
	void (*final)(void);
};

static inline void init_helper_finalize(struct enfs_init_entry *job, int idx)
{
	struct enfs_init_entry *entry = NULL;

	while (idx > 0) {
		idx = idx - 1;
		entry = &job[idx];
		if (entry->final != NULL) {
			entry->final();
			enfs_log_error("final %s.\n", entry->name);
		}
	}
}

static inline int init_helper_init(struct enfs_init_entry *job, int size)
{
	int ret;
	int i;
	struct enfs_init_entry *entry = NULL;

	for (i = 0; i < size; i++) {
		entry = &job[i];
		ret = entry->init();
		if (ret) {
			enfs_log_error("init step(%d) init(%s) fail.\n", i,
				       entry->name);
			goto init_err;
		}
	}

	return 0;

init_err:
	init_helper_finalize(job, i);
	return -1;
}

static struct enfs_init_entry init_entry[] = {
	{ "multipath", enfs_multipath_init, enfs_multipath_exit },
	{ "shard", enfs_shard_init, enfs_shard_exit },
	{ "mgmt", mgmt_init, mgmt_fini },
	{ "dns", enfs_dns_init, enfs_dns_exit },
};

static int __init init_enfs(void)
{
	int ret;

	enfs_config_load();

	ret = enfs_adapter_register(&enfs_adapter);
	if (ret) {
		enfs_log_error("regist enfs_adapter fail. ret %d\n", ret);
		return -1;
	}

	ret = init_helper_init(init_entry, ARRAY_SIZE(init_entry));
	if (ret) {
		enfs_adapter_unregister(&enfs_adapter);
		return -1;
	}

	ret = enfs_rpc_init();
	if (ret) {
		enfs_adapter_unregister(&enfs_adapter);
		return -1;
	}

	enfs_nfsd_link_debug_init();
	return 0;
}

static void __exit exit_enfs(void)
{
	enfs_nfsd_link_debug_exit();
	enfs_lookupcache_fini();
	init_helper_finalize(init_entry, ARRAY_SIZE(init_entry));
	enfs_adapter_unregister(&enfs_adapter);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Huawei Tech. Co., Ltd.");
MODULE_DESCRIPTION("Nfs client multipath");
MODULE_VERSION("1.0");

module_init(init_enfs);
module_exit(exit_enfs);

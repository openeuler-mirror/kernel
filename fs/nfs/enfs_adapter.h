/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Client-side ENFS adapt header.
 *
 *  Copyright (c) 2023. Huawei Technologies Co., Ltd. All rights reserved.
 */

#ifndef _NFS_ADAPTER_H_
#define _NFS_ADAPTER_H_

#include <linux/parser.h>
#include "internal.h"

#if IS_ENABLED(CONFIG_ENFS)
enum nfsmultipathoptions {
	REMOTEADDR,
	LOCALADDR,
	REMOTEDNSNAME,
	REMOUNTREMOTEADDR,
	REMOUNTLOCALADDR,
	INVALID_OPTION
};

/* enfs_flag in struct nfs_server bitmap define */
#define ENFS_SERVER_FLAG_GET_CAP_RUNNING \
	0x1 /* enfs get capability rpc task is running or pendding */
#define ENFS_SERVER_FLAG_LOOKUP_CACHE_NOREG \
	0x10000 /* NFS_MOUNT_LOOKUP_CACHE_NONEG, don't change value */
#define ENFS_SERVER_FLAG_LOOKUP_CACHE_NONE \
	0x20000 /* NFS_MOUNT_LOOKUP_CACHE_NONE, don't change value */

struct enfs_adapter_ops {
	const char *name;
	struct module *owner;
	int (*parse_mount_options)(enum nfsmultipathoptions option, char *str,
				   void **enfs_option, struct net *net_ns);
	void (*free_mount_options)(void **data);
	int (*client_info_init)(void **data,
				const struct nfs_client_initdata *cl_init);
	void (*client_info_free)(void *data);
	int (*client_info_match)(void *src, void *dst);
	int (*nfs4_client_info_match)(void *src, void *dst);
	void (*client_info_show)(struct seq_file *mount_option, void *data);
	int (*remount_ip_list)(struct nfs_client *nfs_client,
			       void *enfs_option);
	void (*set_mount_data)(void **opt, const char *hostname);
	void (*trigger_get_capability)(struct nfs_server *server);
};

int enfs_parse_mount_options(enum nfsmultipathoptions option, char *str,
			     struct nfs_fs_context *mnt, struct fs_context *fc);
void enfs_free_mount_options(struct nfs_fs_context *data);
int nfs_create_multi_path_client(struct nfs_client *client,
				 const struct nfs_client_initdata *cl_init);
void nfs_multipath_set_mount_data(void **opt, const char *hostname);
void nfs_free_multi_path_client(struct nfs_client *clp);
int nfs_multipath_client_match(void *src, void *dst);
int nfs4_multipath_client_match(void *src, void *dst);
void nfs_multipath_show_client_info(struct seq_file *mount_option,
				    struct nfs_server *server);
int enfs_adapter_register(struct enfs_adapter_ops *ops);
int enfs_adapter_unregister(struct enfs_adapter_ops *ops);
int nfs_remount_iplist(struct nfs_client *nfs_client, void *enfs_option);
bool enfs_check_have_lookup_cache_flag(struct nfs_server *server, int flag);
void enfs_trigger_get_server_capability(struct nfs_server *server);
bool nfs_has_created_multipath(struct nfs_client *nfs_client);

#else
static inline
void nfs_free_multi_path_client(struct nfs_client *clp)
{

}

static inline
int nfs_multipath_client_match(struct nfs_client *clp,
			const struct nfs_client_initdata *sap)
{
	return 1;
}

static inline
int nfs_create_multi_path_client(struct nfs_client *client,
			const struct nfs_client_initdata *cl_init)
{
	return 0;
}

static inline
void nfs_multipath_show_client_info(struct seq_file *mount_option,
			struct nfs_server *server)
{

}

static inline
int nfs4_multipath_client_match(struct nfs_client *src,
			struct nfs_client *dst)
{
	return 1;
}

static inline
void enfs_free_mount_options(struct nfs_fs_context *data)
{

}

static inline int nfs_remount_iplist(struct nfs_client *nfs_client, void *data)
{
	return 1;
}

static inline bool nfs_has_created_multipath(struct nfs_client *nfs_client)
{
	return false;
}

static inline void nfs_multipath_set_mount_data(void **opt, const char *hostname)
{
}

static inline bool enfs_check_have_lookup_cache_flag(struct nfs_server *server, int flag)
{
	return (server->flags & NFS_MOUNT_LOOKUP_CACHE_NONE);
}

#endif // CONFIG_ENFS
#endif

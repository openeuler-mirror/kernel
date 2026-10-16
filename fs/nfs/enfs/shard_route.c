// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */
#include <linux/kthread.h>
#include <linux/lockd/lockd.h>
#include <linux/nfs3.h>
#include <linux/nfs_fs.h>
#include <linux/nfs_xdr.h>
#include <linux/sunrpc/clnt.h>
#include <linux/sunrpc/svc.h>
#include <linux/sunrpc/types.h>
#include <linux/sunrpc/xprt.h>
#include <linux/moduleparam.h>
#include "../../../net/sunrpc/netns.h"
#include "../../../fs/nfs/nfs4_fs.h"
#include "../../../fs/nfs/netns.h"
#include "dns_internal.h"
#include "enfs.h"
#include "enfs_config.h"
#include "enfs_log.h"
#include "enfs_roundrobin.h"
#include "exten_call.h"
#include "pm_state.h"
#include "shard.h"

#define MAX_SHARD_COUNT_TIME 5	// 5 second
#define FAULT_DETECTED 1

#define SHARD_VIEW_UPDATE_INTERVAL_UNDER_LOCK 10
#define SECOND_TO_MILLISECOND 1000

// TODO: replace the rwlock with RCU
struct shard_view_ctrl {
	rwlock_t view_lock;
	struct list_head view_list;

	rwlock_t clnt_info_lock;
	struct list_head clnt_info_list;
};

struct enfs_shard_info {
	struct work_struct work;
	struct nfs_server *server;
};

static struct shard_view_ctrl *shard_ctrl;
static struct task_struct *shard_thread;
static struct workqueue_struct *shard_workq;
static struct workqueue_struct *shard_check_wq;

struct clnt_debug_cmd {
	const char *name;
	void (*fn)(int argc, char *argv[]);
};

struct view_table {
	struct list_head next;
	rwlock_t lock;
	struct list_head fs_head;
	struct list_head shard_head;
	struct list_head ls_head;
	uint64_t devId;
};

struct fs_info {
	struct list_head next;
	uint64_t clusterId;
	uint32_t storagePoolId;
	uint32_t fsId;
	uint32_t tenantId;
};

struct shard_entry {
	uint64_t lsid;
	uint32_t vnodeid;
	uint32_t pnodeid;
	uint32_t cpuid;
	uint64_t version;
};

struct shard_view {
	struct list_head next;
	uint64_t clusterId;
	uint32_t storagePoolId;
	uint32_t num;
	struct shard_entry entry[MAX_SHARD_NUMBER_IN_CLUSTER_4FS];
};

struct lif_info {
	struct list_head next;
	char ipAddr[IP_ADDRESS_LEN_MAX];
	uint32_t workStatus;
	uint64_t lsId;
	uint32_t tenantId;
	uint64_t homeSiteWwn;
};

struct ls_entry {
	uint64_t lsVersion;
	uint32_t lsId;
};

struct ls_info {
	struct list_head next;
	uint32_t num;
	uint64_t clusterId;
	struct ls_entry entry[MAX_GLOBAL_CTRL_NODE_NUM];
};

struct clnt_uuid_info {
	struct list_head next;
	struct rpc_clnt *clnt;
	struct enfs_file_uuid root_uuid;
	bool updating;
};

static bool delete_view_table(uint64_t devId);

static int enfs_find_clnt_root(struct rpc_clnt *clnt, struct enfs_file_uuid *root_uuid)
{
	int ret = 0;
	struct clnt_uuid_info *info;

	read_lock(&shard_ctrl->clnt_info_lock);
	list_for_each_entry(info, &shard_ctrl->clnt_info_list, next) {
		if (info->clnt == clnt &&
		    !memcmp(root_uuid, &info->root_uuid, sizeof(*root_uuid)))
			goto out;
	}
	ret = -1;

out:
	read_unlock(&shard_ctrl->clnt_info_lock);
	return ret;
}

static int enfs_insert_clnt_root(struct rpc_clnt *clnt, struct enfs_file_uuid *root_uuid)
{
	int ret = 0;
	struct clnt_uuid_info *info;

	write_lock(&shard_ctrl->clnt_info_lock);
	list_for_each_entry(info, &shard_ctrl->clnt_info_list, next) {
		if (info->clnt == clnt) {
			info->root_uuid = *root_uuid;
			goto out;
		}
	}

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		ret = -1;
		goto out;
	}

	info->clnt = clnt;
	info->root_uuid = *root_uuid;
	list_add_tail(&info->next, &shard_ctrl->clnt_info_list);
	info->updating = false;

out:
	write_unlock(&shard_ctrl->clnt_info_lock);
	return ret;
}

int enfs_delete_clnt_shard_cache(struct rpc_clnt *clnt)
{
	int ret = 0;
	struct clnt_uuid_info *info;
	uint64_t devId = 0;

	write_lock(&shard_ctrl->clnt_info_lock);
	list_for_each_entry(info, &shard_ctrl->clnt_info_list, next) {
		if (info->clnt == clnt) {
			devId = GET_DEVID_FROM_UUID(&info->root_uuid);
			list_del(&info->next);
			kfree(info);
			break;
		}
	}
	if (devId == 0)
		goto out;

	list_for_each_entry(info, &shard_ctrl->clnt_info_list, next) {
		if (devId == GET_DEVID_FROM_UUID(&info->root_uuid)) {
			devId = 0;
			break;
		}
	}

	if (devId != 0) {
		write_lock(&shard_ctrl->view_lock);
		delete_view_table(devId);
		write_unlock(&shard_ctrl->view_lock);
	}

out:
	write_unlock(&shard_ctrl->clnt_info_lock);
	return ret;
}

static struct view_table *create_view_table(uint64_t devId)
{
	struct view_table *table;

	list_for_each_entry(table, &shard_ctrl->view_list, next) {
		if (table->devId == devId)
			return table;
	}

	table = kmalloc(sizeof(*table), GFP_KERNEL);
	if (!table)
		return NULL;

	rwlock_init(&table->lock);
	INIT_LIST_HEAD(&table->fs_head);
	INIT_LIST_HEAD(&table->shard_head);
	INIT_LIST_HEAD(&table->ls_head);
	table->devId = devId;
	list_add_tail(&table->next, &shard_ctrl->view_list);

	return table;
}

static struct view_table *get_view_table(uint64_t devId, bool create)
{
	struct view_table *table;

	list_for_each_entry(table, &shard_ctrl->view_list, next) {
		if (table->devId == devId)
			return table;
	}

	// Note use write_lock when creating a view tabel.
	if (create)
		return create_view_table(devId);
	return NULL;
}

/**
 * enfs_clear_ ## __struct_name() - delete and free all __struct_name from view_table
 * @table: view table
 *
 * Context: protected by view_table write lock
 * Return: None
 */
#define DEFINE_CLEAR_LIST_FUNC(__struct_name, __list_name)		\
static void enfs_clear_ ## __struct_name(struct view_table *table)	\
{									\
	struct __struct_name *item, *tmp;				\
									\
	list_for_each_entry_safe(item, tmp, &table->__list_name, next) {\
		list_del(&item->next);					\
		kfree(item);						\
	}								\
}

DEFINE_CLEAR_LIST_FUNC(fs_info, fs_head);
DEFINE_CLEAR_LIST_FUNC(shard_view, shard_head);
DEFINE_CLEAR_LIST_FUNC(ls_info, ls_head);

static void enfs_free_view_table(struct view_table *table)
{
	enfs_clear_fs_info(table);
	enfs_clear_shard_view(table);
	enfs_clear_ls_info(table);
	list_del(&table->next);
	kfree(table);
}

/*
 * view_lock need write_lock
 */
static bool delete_view_table(uint64_t devId)
{
	struct view_table *table, *tmp;

	list_for_each_entry_safe(table, tmp, &shard_ctrl->view_list, next) {
		if (table->devId == devId) {
			enfs_free_view_table(table);
			return true;
		}
	}

	return false;

}

static struct fs_info *get_fsinfo(struct view_table *table, uint32_t fsId)
{
	struct fs_info *info;

	list_for_each_entry(info, &table->fs_head, next) {
		if (info->fsId == fsId)
			return info;
	}

	return NULL;
}

static int get_ls_and_cpu_id(struct view_table *table, uint64_t clusterId,
				 uint32_t storagePoolId, uint32_t shardId,
				 uint64_t *lsid, uint32_t *cpuId)
{
	struct shard_view *view;
	bool matched;

	list_for_each_entry(view, &table->shard_head, next) {
		matched = (view->clusterId == clusterId &&
			   view->storagePoolId == storagePoolId);
		if (matched)
			break;
	}

	if (!matched)
		return -1;

	if (shardId >= view->num) {
		enfs_log_error
			("shard id is more than buff size, view(0x%llx:%llu:%u:%u), id:%u.\n",
			 table->devId, view->clusterId, view->storagePoolId,
			 view->num, shardId);
		return -1;
	}
	*lsid = view->entry[shardId].lsid;
	*cpuId = view->entry[shardId].cpuid;

	return 0;
}

/**
 * @return:0 for success,otherwise for failed
 */
static int enfs_query_lif_info(struct rpc_clnt *clnt, struct enfs_file_uuid *file_uuid,
			uint64_t *lsid, uint32_t *cpuId)
{
	int ret = 0;
	struct view_table *table;
	struct fs_info *info;
	uint32_t shardId;

	read_lock(&shard_ctrl->view_lock);
	table = get_view_table(GET_DEVID_FROM_UUID(file_uuid), false);
	if (!table) {
		ret = -1;
		goto out;
	}

	info = get_fsinfo(table, GET_FSID_FROM_UUID(file_uuid));
	if (!info) {
		ret = -1;
		goto out;
	}

	shardId = get_shardid_from_uuid(file_uuid);
	ret = get_ls_and_cpu_id(table, info->clusterId, info->storagePoolId,
				shardId, lsid, cpuId);
	if (ret) {
		enfs_log_error("get lsid failed.\n");
		goto out;
	}

out:
	read_unlock(&shard_ctrl->view_lock);
	return ret;
}

static int update_fs_info(struct view_table *table,
			  struct enfs_shard_view *fs_shard_view)
{
	struct fs_info *info;

	list_for_each_entry(info, &table->fs_head, next) {
		if (info->fsId == fs_shard_view->fsId) {
			info->clusterId = fs_shard_view->clusterId;
			info->storagePoolId = fs_shard_view->storagePoolId;
			return 0;
		}
	}

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	info->fsId = fs_shard_view->fsId;
	info->clusterId = fs_shard_view->clusterId;
	info->storagePoolId = fs_shard_view->storagePoolId;
	list_add_tail(&info->next, &table->fs_head);
	return 0;
}

static void copy_shard_entry(struct shard_view *view,
				 struct enfs_shard_view *fs_shard_view, int *flag)
{
	int i;

	for (i = 0; i < fs_shard_view->num; i++) {
		if (view->entry[i].lsid != fs_shard_view->shardView[i].lsid)
			*flag = FAULT_DETECTED;
		view->entry[i].lsid = fs_shard_view->shardView[i].lsid;
		view->entry[i].cpuid = fs_shard_view->shardView[i].cpuId;
	}
}

static int update_shard_view(struct view_table *table,
				 struct enfs_shard_view *fs_shard_view, int *flag)
{
	int i;
	struct shard_view *view;

	list_for_each_entry(view, &table->shard_head, next) {
		if (view->clusterId == fs_shard_view->clusterId &&
		    view->storagePoolId == fs_shard_view->storagePoolId) {
			copy_shard_entry(view, fs_shard_view, flag);
			return 0;
		}
	}

	view = kmalloc(sizeof(*view), GFP_KERNEL);
	if (!view)
		return -ENOMEM;

	view->clusterId = fs_shard_view->clusterId;
	view->storagePoolId = fs_shard_view->storagePoolId;
	view->num = fs_shard_view->num;
	for (i = 0; i < fs_shard_view->num; i++) {
		view->entry[i].lsid = fs_shard_view->shardView[i].lsid;
		view->entry[i].cpuid = fs_shard_view->shardView[i].cpuId;
	}
	list_add_tail(&view->next, &table->shard_head);
	return 0;
}

static int enfs_update_fsshard(uint64_t devId, struct enfs_shard_view *fs_shard_view, int *flag)
{
	int ret = 0;
	struct view_table *table;

	write_lock(&shard_ctrl->view_lock);
	table = get_view_table(devId, true);
	if (!table) {
		enfs_log_error("get view table failed.\n");
		ret = -ENOMEM;
		goto out;
	}

	ret = update_fs_info(table, fs_shard_view);
	if (ret) {
		enfs_log_error("update fs info err:%d\n", ret);
		goto out;
	}

	ret = update_shard_view(table, fs_shard_view, flag);
	if (ret) {
		enfs_log_error("update shard view err:%d\n", ret);
		goto out;
	}

out:
	write_unlock(&shard_ctrl->view_lock);
	return ret;
}

static int find_same_lsid(struct ls_info *info, int size, int target_lsId)
{
	int left = 0;
	int right = size - 1;

	while (left <= right) {
		int mid = left + (right - left) / 2;

		if (info->entry[mid].lsId == target_lsId)
			return mid;
		else if (info->entry[mid].lsId < target_lsId)
			left = mid + 1;
		else
			right = mid - 1;
	}
	return -1;
}

static void copy_ls_entry(struct ls_info *info,
			  struct enfs_get_ls_version_rsp *ls_view, int *flag)
{
	int i;
	int target;

	if (ls_view->num > MAX_GLOBAL_CTRL_NODE_NUM) {
		*flag = FAULT_DETECTED;
		return;
	}

	if (info->num != ls_view->num)
		*flag = FAULT_DETECTED;

	for (i = 0; i < ls_view->num; i++) {
		target = find_same_lsid(info, info->num,
					ls_view->lsInfo[i].lsId);
		if (target < 0) {
			*flag = FAULT_DETECTED;
			continue;
		}
		if (info->entry[target].lsVersion !=
			ls_view->lsInfo[i].lsVersion) {
			*flag = FAULT_DETECTED;
		}
	}

	info->num = ls_view->num;
	for (i = 0; i < ls_view->num; i++) {
		info->entry[i].lsId = ls_view->lsInfo[i].lsId;
		info->entry[i].lsVersion = ls_view->lsInfo[i].lsVersion;
	}
}

static int update_ls_info(struct view_table *table,
			  struct enfs_get_ls_version_rsp *ls_view, int *flag)
{
	int i;
	struct ls_info *info;

	list_for_each_entry(info, &table->ls_head, next) {
		if (info->clusterId == ls_view->clusterId) {
			copy_ls_entry(info, ls_view, flag);
			return 0;
		}
	}

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	info->clusterId = ls_view->clusterId;
	info->num = ls_view->num;
	for (i = 0; i < ls_view->num; i++) {
		info->entry[i].lsVersion = ls_view->lsInfo[i].lsVersion;
		info->entry[i].lsId = ls_view->lsInfo[i].lsId;
	}
	list_add_tail(&info->next, &table->ls_head);
	return 0;
}

static int enfs_update_lsinfo(uint64_t devId, struct enfs_get_ls_version_rsp *ls_view,
			   int *flag)
{
	int ret = 0;
	struct view_table *table;

	write_lock(&shard_ctrl->view_lock);
	table = get_view_table(devId, true);
	if (!table) {
		enfs_log_error("get view table failed.\n");
		ret = -ENOMEM;
		goto out;
	}

	ret = update_ls_info(table, ls_view, flag);
	if (ret) {
		enfs_log_error("update ls info err:%d\n", ret);
		goto out;
	}

out:
	write_unlock(&shard_ctrl->view_lock);
	return ret;
}

// getattr,fsstat,fsinfo,pathconf
static const struct nfs_fh *parse_msg_fh(struct rpc_message *msg)
{
	struct nfs_fh *fh = msg->rpc_argp;
	return fh;
}

#define DEFINE_PARSE_FH_FUNC(__name, __struct_name, __return_member)	\
static const struct nfs_fh *						\
parse_ ## __name ## _fh(struct rpc_message *msg)			\
{									\
	struct __struct_name *args = msg->rpc_argp;			\
	return args->__return_member;					\
}

DEFINE_PARSE_FH_FUNC(sattr, nfs3_sattrargs, fh);
DEFINE_PARSE_FH_FUNC(dirop, nfs3_diropargs, fh);
DEFINE_PARSE_FH_FUNC(access, nfs3_accessargs, fh);
DEFINE_PARSE_FH_FUNC(readlink, nfs3_readlinkargs, fh);
DEFINE_PARSE_FH_FUNC(pgio, nfs_pgio_args, fh);
DEFINE_PARSE_FH_FUNC(create, nfs3_createargs, fh);
DEFINE_PARSE_FH_FUNC(mkdir, nfs3_mkdirargs, fh);
DEFINE_PARSE_FH_FUNC(symlink, nfs3_symlinkargs, fromfh);
DEFINE_PARSE_FH_FUNC(mknod, nfs3_mknodargs, fh);
DEFINE_PARSE_FH_FUNC(remove, nfs_removeargs, fh);
DEFINE_PARSE_FH_FUNC(rename, nfs_renameargs, old_dir);
DEFINE_PARSE_FH_FUNC(link, nfs3_linkargs, fromfh);
DEFINE_PARSE_FH_FUNC(readdir, nfs3_readdirargs, fh);
DEFINE_PARSE_FH_FUNC(commit, nfs_commitargs, fh);

struct nfs3_cmd_ops {
	int cmd;
	const struct nfs_fh *(*parse_fh)(struct rpc_message *msg);
	const char *name;
};

struct nfs3_cmd_ops nfs3_parse_ops[] = {
	{ NFS3PROC_NULL, NULL, "NFS3PROC_NULL" },
	{ NFS3PROC_GETATTR, parse_msg_fh, "NFS3PROC_GETATTR" },
	{ NFS3PROC_SETATTR, parse_sattr_fh, "NFS3PROC_SETATTR" },
	{ NFS3PROC_LOOKUP, parse_dirop_fh, "NFS3PROC_LOOKUP" },
	{ NFS3PROC_ACCESS, parse_access_fh, "NFS3PROC_ACCESS" },
	{ NFS3PROC_READLINK, parse_readlink_fh, "NFS3PROC_READLINK" },
	{ NFS3PROC_READ, parse_pgio_fh, "NFS3PROC_READ" },
	{ NFS3PROC_WRITE, parse_pgio_fh, "NFS3PROC_WRITE" },
	{ NFS3PROC_CREATE, parse_create_fh, "NFS3PROC_CREATE" },
	{ NFS3PROC_MKDIR, parse_mkdir_fh, "NFS3PROC_MKDIR" },
	{ NFS3PROC_SYMLINK, parse_symlink_fh, "NFS3PROC_SYMLINK" },
	{ NFS3PROC_MKNOD, parse_mknod_fh, "NFS3PROC_MKNOD" },
	{ NFS3PROC_REMOVE, parse_remove_fh, "NFS3PROC_REMOVE" },
	{ NFS3PROC_RMDIR, parse_dirop_fh, "NFS3PROC_RMDIR" },
	{ NFS3PROC_RENAME, parse_rename_fh, "NFS3PROC_RENAME" },
	{ NFS3PROC_LINK, parse_link_fh, "NFS3PROC_LINK" },
	{ NFS3PROC_READDIR, parse_readdir_fh, "NFS3PROC_READDIR" },
	{ NFS3PROC_READDIRPLUS, parse_readdir_fh, "NFS3PROC_READDIRPLUS" },
	{ NFS3PROC_FSSTAT, parse_msg_fh, "NFS3PROC_FSSTAT" },
	{ NFS3PROC_FSINFO, parse_msg_fh, "NFS3PROC_FSINFO" },
	{ NFS3PROC_PATHCONF, parse_msg_fh, "NFS3PROC_PATHCONF" },
	{ NFS3PROC_COMMIT, parse_commit_fh, "NFS3PROC_COMMIT" },
};

int nfs3_parse_ops_size = sizeof(nfs3_parse_ops) / sizeof(struct nfs3_cmd_ops);

struct shard_work {
	struct work_struct work;
	struct clnt_uuid_info info;
	struct rpc_xprt_switch *xps;
	int isupdate;
};

static int sockaddr_ip_to_str(struct sockaddr *addr, char *buf, int len)
{
	switch (addr->sa_family) {
	case AF_INET:{
			struct sockaddr_in *sin = (struct sockaddr_in *)addr;

			snprintf(buf, len, "%pI4", &sin->sin_addr);
			return 0;
		}
	case AF_INET6:{
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;

			snprintf(buf, len, "%pI6c", &sin6->sin6_addr);
			return 0;
		}
	default:
		break;
	}
	return 1;
}

static int query_and_update_shard(struct rpc_clnt *clnt, struct enfs_file_uuid *file_uuid,
				  struct shard_work *work)
{
	int ret;
	int flag = 0;
	struct enfs_shard_view *fsshard_view = NULL;
	struct enfs_get_ls_version_rsp *ls_view = NULL;

	ret = dorado_query_fs_shard(clnt, file_uuid, &fsshard_view);
	if (ret) {
		enfs_log_debug("query fs shard err:%d.\n", ret);
		return ret;
	}

	enfs_update_fsshard(GET_DEVID_FROM_UUID(file_uuid), fsshard_view,
				&flag);
	kfree(fsshard_view);

	ret = dorado_query_lsId(clnt, &ls_view);
	if (ret) {
		enfs_log_debug("query lsId err:%d.\n", ret);
		return ret;
	}

	enfs_update_lsinfo(GET_DEVID_FROM_UUID(file_uuid), ls_view, &flag);
	kfree(ls_view);

	if (flag && work)
		work->isupdate = true;
	return 0;
}

static void insert_and_update_shard(struct rpc_clnt *clnt, struct enfs_file_uuid *file_uuid)
{
	if (enfs_find_clnt_root(clnt, file_uuid) != 0) {
		enfs_insert_clnt_root(clnt, file_uuid);
		query_and_update_shard(clnt, file_uuid, NULL);
	}
}

void enfs_print_uuid(struct enfs_file_uuid *file_uuid)
{
	char buf[80];		/* 80 uuid buf */
	uint8_t *uuid = file_uuid->data;

	if (!is_enfs_debug())
		return;

	enfs_log_debug("dev:%llu fs:%u dtree:%u snap:%u pfid:%llu fid:%llu\n",
		      *(uint64_t *) (uuid + UUID_DEVID_OFFSET),
		      *(uint32_t *) (uuid + UUID_FSID_OFFSET),
		      *(uint32_t *) (uuid + UUID_DTREEID_OFFSET),
		      *(uint32_t *) (uuid + UUID_SNAPID_OFFSET),
		      *(uint64_t *) (uuid + UUID_PFID_OFFSET),
		      *(uint64_t *) (uuid + UUID_FID_OFFSET));

	sprint_uuid(buf, 80, file_uuid);
	enfs_log_debug("UUID:%s\n", buf);
}

static void enfs_debug_fh(const struct nfs_fh *fh)
{
	int i;
	char str[NFS_MAXFHSIZE * 2];

	for (i = 0; i < fh->size; i++)
		sprintf(str + 2 * i, "%02X", fh->data[i]);
	str[2 * i] = '\0';
	enfs_log_debug("fh: %s\n", str);
}

static int get_uuid_from_task(struct rpc_clnt *clnt, struct rpc_task *task,
				  struct enfs_file_uuid *file_uuid)
{
	struct rpc_message *msg = &task->tk_msg;
	int cmd = msg->rpc_proc->p_proc;
	const struct nfs_fh *fh;

	if (cmd >= nfs3_parse_ops_size || nfs3_parse_ops[cmd].parse_fh == NULL)
		return -1;

	fh = nfs3_parse_ops[cmd].parse_fh(msg);
	fh_file_uuid(fh, file_uuid);

	/* debug print uuid */
	enfs_print_uuid(file_uuid);

	if (cmd == NFS3PROC_FSINFO)
		insert_and_update_shard(clnt, file_uuid);

	return 0;
}

static struct rpc_xprt *
enfs_choose_better_xprt(
	struct rpc_xprt *xport1,
	struct rpc_xprt *xport2)
{
	struct enfs_xprt_context *context1;
	struct enfs_xprt_context *context2;
	bool is_xprt1_normal, is_xprt2_normal;

	if (xport1 == NULL)
		return xport2;
	if (xport2 == NULL)
		return xport1;

	context1 = (struct enfs_xprt_context *)xprt_get_reserve_context(xport1);
	context2 = (struct enfs_xprt_context *)xprt_get_reserve_context(xport2);

	is_xprt1_normal = atomic_read(&context1->path_state) == PM_STATE_NORMAL;
	is_xprt2_normal = atomic_read(&context2->path_state) == PM_STATE_NORMAL;
	if (is_xprt1_normal && !is_xprt2_normal)
		return xport1;
	if (!is_xprt1_normal && is_xprt2_normal)
		return xport2;

	if (atomic_long_read(&(context1->queuelen)) >
	    atomic_long_read(&(context2->queuelen))) {
		return xport2;
	}
	return xport1;
}

static uint64_t get_wwn_from_xps(struct rpc_xprt_switch *xps, uint64_t lsid)
{
	struct rpc_xprt *pos;
	struct enfs_xprt_context *context;

	list_for_each_entry_rcu(pos, &xps->xps_xprt_list, xprt_switch) {
		context =
			(struct enfs_xprt_context *)xprt_get_reserve_context(pos);
		if (context->lsid == lsid)
			return context->wwn;
	}
	return 0;
}

struct route_rule {
	struct rpc_xprt *xprt;
	struct rpc_xprt *optimal_xprt;
	bool (*match)(uint64_t wwn, uint64_t lsid, uint32_t cpuId,
			  struct enfs_xprt_context *context);
};

static bool check_cpuid_invalid(uint32_t cpuId)
{
	return cpuId == INVALID_CPU_ID;
}

static bool match_wwn_cpuId_lsId(uint64_t wwn, uint64_t lsid, uint32_t cpuId,
				 struct enfs_xprt_context *context)
{
	if (check_cpuid_invalid(cpuId) || check_cpuid_invalid(context->cpuId))
		return false;
	if (enfs_check_config_wwn(context->wwn) &&
		lsid == context->lsid && cpuId == context->cpuId) {
		return true;
	}
	return false;
}

static bool match_cpuId_lsId(uint64_t wwn, uint64_t lsid, uint32_t cpuId,
				 struct enfs_xprt_context *context)
{
	if (check_cpuid_invalid(cpuId) || check_cpuid_invalid(context->cpuId))
		return false;
	if (lsid == context->lsid && cpuId == context->cpuId)
		return true;
	return false;
}

static bool match_wwn_lsid(uint64_t wwn, uint64_t lsid, uint32_t cpuId,
			   struct enfs_xprt_context *context)
{
	if (enfs_check_config_wwn(context->wwn) && lsid == context->lsid)
		return true;
	return false;
}

/*
 * In the hypermetro scenario,select the xport of the preferred array.
 */
static bool match_wwn(uint64_t wwn, uint64_t lsid, uint32_t cpuId,
			  struct enfs_xprt_context *context)
{
	return enfs_check_config_wwn(context->wwn);
}

/*
 * Select the xport with the same lsid
 */
static bool match_lsid(uint64_t wwn, uint64_t lsid, uint32_t cpuId,
			   struct enfs_xprt_context *context)
{
	if (lsid == context->lsid)
		return true;
	return false;
}

/*
 * In the hypermetro scenario,select the xport of the array with
 * the same lif port.
 */
static bool match_same_wwn(uint64_t wwn, uint64_t lsid, uint32_t cpuId,
			   struct enfs_xprt_context *context)
{
	if (wwn != 0 && context->wwn == wwn)
		return true;
	return false;
}

static bool match_default(uint64_t wwn, uint64_t lsid, uint32_t cpuId,
			  struct enfs_xprt_context *context)
{
	return true;
}

static struct rpc_xprt *enfs_choose_shard_xport(struct rpc_xprt_switch *xps,
					 const struct rpc_xprt *cur,
					 uint64_t lsid, struct rpc_clnt *clnt,
					 uint32_t cpuId)
{
	uint64_t wwn = 0;
	struct rpc_xprt *pos = NULL;
	bool found = false;
	struct rpc_xprt *prev = NULL;
	struct enfs_xprt_context *context = NULL;
	struct rpc_xprt *choose_xprt = NULL;
	int i;
	int nativeLinkStatus = enfs_get_native_link_io_status();
	struct route_rule rule[] = {
		{ NULL, NULL, match_wwn_cpuId_lsId },	// optimal site && cpu && shard view
		{ NULL, NULL, match_wwn_lsid },	// optimal site && shard view
		{ NULL, NULL, match_wwn },	// optimal site
		{ NULL, NULL, match_cpuId_lsId },	// cpu and shard route
		{ NULL, NULL, match_lsid },	// shard route
		{ NULL, NULL, match_same_wwn },	// select ports at the same site
		{ NULL, NULL, match_default },	// RR
	};
	int len = ARRAY_SIZE(rule);

	wwn = get_wwn_from_xps(xps, lsid);
	list_for_each_entry_rcu(pos, &xps->xps_xprt_list, xprt_switch) {
		context =
			(struct enfs_xprt_context *)xprt_get_reserve_context(pos);
		if (context == NULL
			|| !enfs_is_path_connected(atomic_read(&context->path_state))) {
			prev = pos;
			continue;
		}

		if (!nativeLinkStatus && context->main)
			continue;

		if (cur == prev)
			found = true;

		for (i = 0; i < len; i++) {
			if (rule[i].match(wwn, lsid, cpuId, context)) {
				rule[i].xprt = enfs_choose_better_xprt(rule[i].xprt, pos);
				break;
			}
		}

		if (found == false) {
			prev = pos;
			continue;
		}

		for (i = 0; i < len; i++) {
			if (rule[i].match(wwn, lsid, cpuId, context)) {
				rule[i].optimal_xprt = enfs_choose_better_xprt(rule[i].optimal_xprt,
									       pos);
				break;
			}
		}
		prev = pos;
	}

	for (i = 0; i < len; i++) {
		if (rule[i].xprt == NULL)
			continue;

		if (rule[i].optimal_xprt != NULL)
			choose_xprt = rule[i].optimal_xprt;
		else
			choose_xprt = rule[i].xprt;

		break;
	}

	return choose_xprt;
}

static struct rpc_xprt *enfs_get_shard_xport(struct rpc_clnt *clnt,
					  struct rpc_task *task, uint64_t lsid,
					  uint32_t cpuId)
{
	struct rpc_xprt *old;
	struct rpc_xprt *xprt = NULL;
	struct rpc_xprt_switch *xps;
	struct rpc_xprt_iter *xpi = &clnt->cl_xpi;
	struct enfs_xprt_context *context;

	rcu_read_lock();
	xps = rcu_dereference(xpi->xpi_xpswitch);
	if (xps == NULL)
		goto out;
	old = smp_load_acquire(&xpi->xpi_cursor); // multi thread access
	xprt = enfs_choose_shard_xport(xps, old, lsid, clnt, cpuId);
	smp_store_release(&xpi->xpi_cursor, xprt); // multi thread access

	if (task->tk_xprt) {
		xprt_release(task);
		rpc_init_task_retry_counters(task);
		rpc_task_release_transport(task);
	}

	if (xprt == NULL)
		goto out;

	xprt = xprt_get(xprt);
	context = xprt_get_reserve_context(xprt);
	if (context)
		atomic_long_inc(&context->queuelen);

out:
	rcu_read_unlock();
	return xprt;
}

void shard_set_transport(struct rpc_task *task, struct rpc_clnt *clnt)
{
	uint64_t lsid = 0;
	uint32_t cpuId = 0;
	int ret;
	struct enfs_file_uuid file_uuid;
	struct rpc_xprt_switch *xps;

	rcu_read_lock();
	xps = rcu_dereference(clnt->cl_xpi.xpi_xpswitch);
	rcu_read_unlock();

	if (clnt->cl_vers != 3 || xps->xps_iter_ops != enfs_xprt_rr_ops())
		return;
	memset(&file_uuid, 0, sizeof(struct enfs_file_uuid));
	ret = get_uuid_from_task(clnt, task, &file_uuid);
	if (ret != 0) {
		enfs_log_debug("get uuid from task failed.\n");
		return;
	}

	if (enfs_get_config_multipath_state() != ENFS_MULTIPATH_ENABLE ||
		enfs_get_config_loadbalance_mode() != ENFS_LOADBALANCE_SHARDVIEW) {
		return;
	}

	ret = get_uuid_from_task(clnt, task, &file_uuid);
	if (ret != 0) {
		enfs_log_debug("get uuid failed.\n");
		return;
	}

	ret = enfs_query_lif_info(clnt, &file_uuid, &lsid, &cpuId);
	if (ret != 0 || lsid == 0) {
		// trigger query shard from storage
		return;
	}

	task->tk_xprt = enfs_get_shard_xport(clnt, task, lsid, cpuId);

}

static void debug_show_uuidinfo(int argc, char *argv[])
{
	int ret;
	struct view_table *table;
	struct fs_info *info;
	struct shard_view *view;
	struct enfs_file_uuid file_uuid;
	uint64_t clusterId = 0xffff;
	uint32_t storagePoolId = 0xffff;
	uint32_t shardId;

	file_uuid.dataLen = FILE_UUID_BUFF_LEN;

	if (argc != 1) {
		enfs_log_info("argc number is wrong.\n");
		return;
	}

	ret = scan_uuid(argv[0], file_uuid.data, FILE_UUID_BUFF_LEN);
	if (ret) {
		enfs_log_info("uuid str is wrong, str:%s.\n", argv[1]);
		return;
	}

	enfs_log_info("fsidinfo devId:%llu",
		      GET_DEVID_FROM_UUID(&file_uuid));
	read_lock(&shard_ctrl->view_lock);
	list_for_each_entry(table, &shard_ctrl->view_list, next) {
		if (table->devId != GET_DEVID_FROM_UUID(&file_uuid))
			continue;

		list_for_each_entry(info, &table->fs_head, next) {
			if (info->fsId != GET_FSID_FROM_UUID(&file_uuid))
				continue;
			clusterId = info->clusterId;
			storagePoolId = info->storagePoolId;
			enfs_log_info("fsidinfo fsid:%u clusterId:%llu storagePoolId:%u tenantId:%u.\n",
				      GET_FSID_FROM_UUID(&file_uuid), info->clusterId,
				      info->storagePoolId, info->tenantId);
			break;
		}

		shardId = get_shardid_from_uuid(&file_uuid);
		list_for_each_entry(view, &table->shard_head, next) {
			if (view->clusterId != clusterId ||
				view->storagePoolId != storagePoolId) {
				continue;
			}
			if (shardId >= view->num) {
				enfs_log_error("shardNum:%u shardId:%u",
						   view->num, shardId);
			}
			enfs_log_info("fsidinfo clusterId:%llu storagePoolId:%u shardNum:%u shard:%u lsid:%llu cpuId:%u.\n",
				      view->clusterId, view->storagePoolId, view->num,
				      shardId, view->entry[shardId].lsid,
				      view->entry[shardId].cpuid);
			break;
		}
		break;
	}
	read_unlock(&shard_ctrl->view_lock);

}

static void debug_show_fsinfo(int argc, char *argv[])
{
	uint32_t fsid;
	struct view_table *table;
	struct fs_info *info;

	if (argc != 1) {
		enfs_log_info("argc number is wrong.\n");
		return;
	}
	if (kstrtouint(argv[0], 10, &fsid) != 0) {
		enfs_log_info("parse cluster id wrong.\n");
		return;
	}

	read_lock(&shard_ctrl->view_lock);
	list_for_each_entry(table, &shard_ctrl->view_list, next) {
		list_for_each_entry(info, &table->fs_head, next) {
			if (fsid != info->fsId)
				continue;
			enfs_log_info("fsid(%u) clusterId(%llu) storagePoolId(%u) tenantId(%u).\n",
				      fsid, info->clusterId,
				      info->storagePoolId, info->tenantId);
		}
	}
	read_unlock(&shard_ctrl->view_lock);
}

static void debug_show_shardinfo(int argc, char *argv[])
{
	struct view_table *table;
	struct shard_view *view;
	uint64_t clusterId;
	uint32_t storagePoolId;
	uint32_t startIndex;
	uint32_t count;
	bool matched;

	if (argc != 3) {
		enfs_log_info("argc number is wrong.\n");
		return;
	}

	if (kstrtoull(argv[0], 10, &clusterId) != 0) {
		enfs_log_info("parse cluster id wrong, %s.\n", argv[0]);
		return;
	}
	if (kstrtouint(argv[1], 10, &storagePoolId) != 0) {
		enfs_log_info("parse storage pool id wrong, %s.\n", argv[1]);
		return;
	}
	if (kstrtouint(argv[2], 10, &startIndex) != 0) {
		enfs_log_info("parse shard start id wrong, %s.\n", argv[2]);
		return;
	}

	enfs_log_info("clusterId(%llu) storagePoolId(%u) startIndex(%u).\n",
		      clusterId, storagePoolId, startIndex);

	read_lock(&shard_ctrl->view_lock);
	list_for_each_entry(table, &shard_ctrl->view_list, next) {
		list_for_each_entry(view, &table->shard_head, next) {
			matched = (view->clusterId == clusterId &&
				   view->storagePoolId == storagePoolId);
			if (!matched)
				continue;
			for (count = 0; count < 100; count++) {
				if (count + startIndex >= view->num)
					continue;
				enfs_log_info("shardid(%d) lsid(0x%llx) vnodeid(%u) cpuId(%u).\n",
					      count + startIndex,
					      view->entry[count + startIndex].lsid,
					      view->entry[count + startIndex].vnodeid,
					      view->entry[count + startIndex].cpuid);
			}
		}
	}
	read_unlock(&shard_ctrl->view_lock);
}

static int get_ip_to_str(struct sockaddr *addr, char *buf, int len)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	switch (addr->sa_family) {
	case AF_INET:
		sin = (struct sockaddr_in *)addr;
		snprintf(buf, len, "%pI4", &sin->sin_addr);
		return 0;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)addr;
		snprintf(buf, len, "%pI6c", &sin6->sin6_addr);
		return 0;
	default:
		break;
	}
	return 1;
}

static void debug_show_lifinfo(int argc, char *argv[])
{
	struct clnt_uuid_info *info;
	struct rpc_clnt *clnt;
	struct rpc_xprt_switch *xps;
	struct rpc_xprt *pos;
	struct enfs_xprt_context *context;
	char buf[128];
	bool matched;

	if (argc > 1) {
		enfs_log_info("argc number is wrong.\n");
		return;
	}

	read_lock(&shard_ctrl->clnt_info_lock);
	list_for_each_entry(info, &shard_ctrl->clnt_info_list, next) {
		clnt = info->clnt;
		rcu_read_lock();
		xps = rcu_dereference(clnt->cl_xpi.xpi_xpswitch);
		list_for_each_entry_rcu(pos, &xps->xps_xprt_list, xprt_switch) {
			get_ip_to_str((struct sockaddr *)&(pos->addr), buf,
					  sizeof(buf));
			matched = (argc == 0 || strcmp(buf, argv[0]) == 0);
			if (!matched)
				continue;
			context =
				(struct enfs_xprt_context *)
				xprt_get_reserve_context(pos);
			enfs_log_info("ipaddr(%s) lsId(0x%llx) wwn(0x%llx) cpuId(%u).\n",
				      buf, context->lsid, context->wwn,
				      context->cpuId);
		}
		rcu_read_unlock();
	}
	read_unlock(&shard_ctrl->clnt_info_lock);

}

static void debug_show_shardview(int argc, char *argv[])
{
	struct view_table *table;
	struct fs_info *info;
	struct shard_view *view;

	read_lock(&shard_ctrl->view_lock);
	list_for_each_entry(table, &shard_ctrl->view_list, next) {
		enfs_log_info("shardivew  devid:%llu.\n", table->devId);

		list_for_each_entry(info, &table->fs_head, next) {
			enfs_log_info("shardview  fsid:%u clusterId:%llu storagePoolId:%u tenantId:%u.\n",
				      info->fsId, info->clusterId, info->storagePoolId,
				      info->tenantId);
		}

		list_for_each_entry(view, &table->shard_head, next) {
			enfs_log_info("shardview  clusterId:%llu storagePoolId:%u shardNum:%u.\n",
				      view->clusterId, view->storagePoolId, view->num);
		}
	}
	read_unlock(&shard_ctrl->view_lock);

}

static void debug_show_dns_cache(int argc, char *argv[])
{
	enfs_debug_print_name_list();
}

static char *parse_cmd_args(char *str, int *argc, char *argv[10])
{
	char *token;
	int i = 0;
	char *copy = kstrdup(str, GFP_KERNEL);
	char *tmp = copy;

	if (!copy) {
		*argc = 0;
		return NULL;
	}

	while ((token = strsep(&tmp, " ")) != NULL) {
		if (i == 10)
			break;
		argv[i] = token;
		i++;
	}
	*argc = i;

	return copy;
}

static void debug_show_linkcount(int argc, char *argv[])
{
	enfs_log_info("enfs link count:%d mount count:%d\n",
		      enfs_link_count_num(), enfs_mount_count());
}

int enfs_debug_match_cmd(char *str, size_t len)
{
	int i;
	int argc;
	char *argv[10];
	const struct clnt_debug_cmd cmds[] = {
		{ "uuidinfo", debug_show_uuidinfo },
		{ "fsinfo", debug_show_fsinfo },
		{ "shardinfo", debug_show_shardinfo },
		{ "lifinfo", debug_show_lifinfo },
		{ "shardview", debug_show_shardview },
		{ "linkcount", debug_show_linkcount },
		{ "dnscache", debug_show_dns_cache },
	};

	char *buf = parse_cmd_args(str, &argc, argv);

	if (!buf || argc == 0) {
		enfs_log_info("parse failed.\n");
		return 0;
	}

	for (i = 0; i < ARRAY_SIZE(cmds); i++) {
		if (strcmp(argv[0], cmds[i].name) == 0) {
			cmds[i].fn(argc - 1, &(argv[1]));
			break;
		}
	}
	if (i == ARRAY_SIZE(cmds))
		enfs_log_info("not found cmd:%s\n", argv[0]);

	kfree(buf);
	return 0;
}

void enfs_query_xprt_shard(struct rpc_clnt *clnt, struct rpc_xprt *xprt)
{
	int ret;
	uint64_t lsid = 0;
	uint64_t wwn = 0;
	uint32_t cpuId = 0;
	char buf[64];
	struct enfs_xprt_context *ctx =
		(struct enfs_xprt_context *)xprt_get_reserve_context(xprt);

	if (clnt->cl_vers != 3)
		return;

	ret = sockaddr_ip_to_str((struct sockaddr *)&xprt->addr, buf, 64);
	if (ret != 0) {
		enfs_log_error("ip to str err:%d.\n", ret);
		return;
	}

	ret = enfs_query_lifview(clnt, xprt, buf, &lsid, &wwn, &cpuId);
	if (ret)
		return;

	ctx->lsid = lsid;
	ctx->wwn = wwn;
	ctx->cpuId = cpuId;

}

static bool is_valid_ip_address(const char *ip_str)
{
	struct in_addr addr4;
	struct in6_addr addr6;

	if (in4_pton(ip_str, -1, (u8 *) &addr4, '\0', NULL) == 1)
		return true;

	if (in6_pton(ip_str, -1, (u8 *) &addr6, '\0', NULL) == 1)
		return true;

	return false;
}

static int EnfsChooseNewNlmXprt(struct rpc_clnt *clnt, struct rpc_xprt *xprt,
				void *data)
{
	int ret = 0;
	char remoteip[64] = { "*" };
	char localip[64] = { "*" };
	struct enfs_xprt_context *ctx = NULL;
	struct enfs_xprt_context *nlm_ctx = NULL;
	char local_name[INET6_ADDRSTRLEN];
	const char *local = local_name;
	struct sockaddr_storage srcaddr;
	struct rpc_xprt *nlm_xprt = (struct rpc_xprt *)data;
	enum enfs_path_state state = pm_get_path_state(xprt);

	if (!enfs_is_path_connected(state))
		return 0;

	sockaddr_ip_to_str((struct sockaddr *)&xprt->addr, remoteip,
			   sizeof(remoteip));
	memcpy((struct sockaddr *)&nlm_xprt->addr,
		   (struct sockaddr *)&xprt->addr, sizeof(xprt->addr));

	ctx = (struct enfs_xprt_context *)xprt_get_reserve_context(xprt);
	if (ctx == NULL) {
		enfs_log_error("The xprt multipath ctx is not valid.\n");
		return 0;
	}

	nlm_ctx =
		(struct enfs_xprt_context *)xprt_get_reserve_context(nlm_xprt);
	if (nlm_ctx == NULL) {
		enfs_log_error("The nlm xprt ctx is not valid.\n");
		return 0;
	}

	sockaddr_ip_to_str((struct sockaddr *)&ctx->srcaddr, local_name,
			   sizeof(local_name));
	if (!is_valid_ip_address(local)) {
		ret =
			rpc_localalladdr(xprt, (struct sockaddr *)&srcaddr,
					 sizeof(srcaddr));
		if (ret != 0) {
			enfs_log_error("rpc_localalladdr localip err:%d.\n",
					   ret);
			return 0;
		}
		memcpy((struct sockaddr *)&nlm_ctx->srcaddr,
			   (struct sockaddr *)&srcaddr, sizeof(srcaddr));
		sockaddr_ip_to_str((struct sockaddr *)&srcaddr, localip,
				   sizeof(localip));
	} else {
		memcpy((struct sockaddr *)&nlm_ctx->srcaddr,
			   (struct sockaddr *)&ctx->srcaddr, sizeof(ctx->srcaddr));
		sockaddr_ip_to_str((struct sockaddr *)&ctx->srcaddr, localip,
				   sizeof(localip));
	}

	return -1;
}

static int enfs_traverse_nlm_xprt(struct nfs_server *server)
{
	char remoteip[IP_ADDRESS_LEN_MAX] = { "*" };
	struct rpc_xprt *xprt = server->nlm_host->h_rpcclnt->cl_xprt;
	struct enfs_xprt_context *ctx = NULL;

	server->nlm_host->enfs_flag |= ENFS_NEED_REBUILD_NLM_XPRT;
	rpc_clnt_iterate_for_each_xprt(server->nfs_client->cl_rpcclient,
						EnfsChooseNewNlmXprt,
						(void *)xprt);

	sockaddr_ip_to_str((struct sockaddr *)&xprt->addr, remoteip,
				sizeof(remoteip));
	strscpy(server->nlm_host->h_name, remoteip, IP_ADDRESS_LEN_MAX);
	strscpy(server->nlm_host->h_addrbuf, remoteip, NSM_ADDRBUF);

	ctx =
		(struct enfs_xprt_context *)xprt_get_reserve_context(xprt);
	if (ctx == NULL) {
		enfs_log_error
			("The xprt multipath ctx is not valid.\n");
		return 0;
	}
	memcpy((struct sockaddr *)&server->nlm_host->h_addr,
			(struct sockaddr *)&xprt->addr, sizeof(xprt->addr));
	memcpy((struct sockaddr *)&server->nlm_host->h_srcaddr,
			(struct sockaddr *)&ctx->srcaddr, sizeof(ctx->srcaddr));

	return 0;
}

static int enfs_recovery_nlm_lock(struct rpc_clnt *clnt)
{
	int ret = 0;
	struct nfs_net *nn = NULL;
	struct net *net;
	struct nfs_server *pos = NULL;
	char remoteip[64] = { "*" };
	char serverip[64] = { "*" };

	rcu_read_lock();
	for_each_net_rcu(net) {
		nn = net_generic(net, nfs_net_id);
		if (nn == NULL)
			continue;

		spin_lock(&nn->nfs_client_lock);
		list_for_each_entry(pos, &nn->nfs_volume_list, master_link) {
			if (!pos->nlm_host)
				continue;

			if (!pos->client)
				continue;

			if (pos->nlm_host == NULL)
				continue;

			ret = sockaddr_ip_to_str(
				(struct sockaddr *)&clnt->cl_xprt->addr,
				remoteip, sizeof(remoteip));
			if (ret != 0) {
				enfs_log_error("remoteip to str err:%d.\n",
						   ret);
				continue;
			}

			ret = sockaddr_ip_to_str(
				(struct sockaddr *)&pos->client->cl_xprt->addr,
				serverip, sizeof(serverip));
			if (ret != 0) {
				enfs_log_error("remoteip to str err:%d.\n",
						   ret);
				continue;
			}

			if (!strcmp(remoteip, serverip)) {
				enfs_traverse_nlm_xprt(pos);
				if (!list_empty(&pos->nlm_host->h_lockowners)) {
					if (pos->nlm_host->h_last_reclaim_time != 0 &&
					    (ktime_to_ms(ktime_get()) -
						     pos->nlm_host
							     ->h_last_reclaim_time <
					     (SHARD_VIEW_UPDATE_INTERVAL_UNDER_LOCK *
					      SECOND_TO_MILLISECOND)))
						continue;

					enfs_log_info("reclaiming lock:%s.\n",
						      serverip);
					nlmclnt_recovery(pos->nlm_host);
				}
			}
		}
		spin_unlock(&nn->nfs_client_lock);
		break;
	}
	rcu_read_unlock();
	return 0;
}

static int each_xprt_update_shard(struct rpc_clnt *clnt, struct rpc_xprt *xprt,
				  void *data)
{
	enum enfs_path_state state = pm_get_path_state(xprt);
	if (enfs_is_path_connected(state))
		enfs_query_xprt_shard(clnt, xprt);
	return 0;
}

static void shard_update_done(struct rpc_clnt *clnt)
{
	struct clnt_uuid_info *info;

	write_lock(&shard_ctrl->clnt_info_lock);
	list_for_each_entry(info, &shard_ctrl->clnt_info_list, next) {
		if (info->clnt == clnt) {
			info->updating = false;
			break;
		}
	}
	write_unlock(&shard_ctrl->clnt_info_lock);
}

static void do_shard_update(struct work_struct *work)
{
	int error;
	struct shard_work *shard_work =
		container_of(work, struct shard_work, work);
	struct clnt_uuid_info *info = &shard_work->info;

	error =
		query_and_update_shard(info->clnt, &info->root_uuid, shard_work);
	if (error)
		enfs_log_debug("update shard err:%d.\n", error);

	rpc_clnt_iterate_for_each_xprt(info->clnt, each_xprt_update_shard,
					   NULL);

	if (shard_work->isupdate) {
		// Actively reassert the nlm lock
		enfs_recovery_nlm_lock(info->clnt);
	}

	rpc_release_client(shard_work->info.clnt);
	xprt_switch_put(shard_work->xps);
	shard_update_done(info->clnt);
	kfree(shard_work);
}

static int shard_update_work(struct clnt_uuid_info *info,
				 struct list_head *head)
{
	struct rpcclnt_release_item *item;
	struct shard_work *shard_work;
	bool ok;

	shard_work = kzalloc(sizeof(*shard_work), GFP_KERNEL);
	if (!shard_work)
		return -ENOMEM;

	item = kzalloc(sizeof(*item), GFP_KERNEL);
	if (!item) {
		enfs_log_error("alloc item failed.\n");
		kfree(shard_work);
		return -ENOMEM;
	}

	rcu_read_lock();
	shard_work->xps =
		xprt_switch_get(rcu_dereference(info->clnt->cl_xpi.xpi_xpswitch));
	rcu_read_unlock();
	if (!shard_work->xps) {
		kfree(item);
		kfree(shard_work);
		return -EAGAIN;
	}

	INIT_WORK(&shard_work->work, do_shard_update);
	shard_work->info = *info;
	if (!refcount_inc_not_zero(&shard_work->info.clnt->cl_count)) {
		xprt_switch_put(shard_work->xps);
		kfree(item);
		kfree(shard_work);
		return 0;
	}

	ok = queue_work(shard_workq, &shard_work->work);
	if (!ok) {
		item->clnt = shard_work->info.clnt;
		list_add_tail(&item->node, head);
		xprt_switch_put(shard_work->xps);
		kfree(shard_work);
		return -1;
	}

	kfree(item);
	return 0;
}

static void query_update_all_clnt(void)
{
	int ret;
	struct clnt_uuid_info *info;
	LIST_HEAD(free_list);

	write_lock(&shard_ctrl->clnt_info_lock);
	list_for_each_entry(info, &shard_ctrl->clnt_info_list, next) {
		if (info->updating)
			continue;

		info->updating = true;
		ret = shard_update_work(info, &free_list);
		if (ret) {
			enfs_log_error("update all err:%d.\n", ret);
			info->updating = false;
		}
	}
	write_unlock(&shard_ctrl->clnt_info_lock);

	enfs_destroy_rpcclnt_list(&free_list);
}

static bool enfs_need_quick_update_shard(void)
{
	bool ret = false;
	struct nfs_net *nn = NULL;
	struct net *net;
	struct nfs_server *pos = NULL;

	rcu_read_lock();
	for_each_net_rcu(net) {
		nn = net_generic(net, nfs_net_id);
		if (nn == NULL)
			continue;

		spin_lock(&nn->nfs_client_lock);
		list_for_each_entry(pos, &nn->nfs_volume_list, master_link) {
			if (!pos->nlm_host)
				continue;
			if (!list_empty(&pos->nlm_host->h_lockowners)) {
				ret = true;
				break;
			}
		}
		spin_unlock(&nn->nfs_client_lock);
		break;
	}
	rcu_read_unlock();

	return ret;
}

static int shard_update_loop(void *data)
{
	int32_t interval_ms;
	ktime_t start = ktime_get();

	while (!kthread_should_stop()) {
		interval_ms =
			enfs_need_quick_update_shard() ?
				(SHARD_VIEW_UPDATE_INTERVAL_UNDER_LOCK *
				 SECOND_TO_MILLISECOND) :
				(enfs_get_config_shardview_update_interval() *
				 SECOND_TO_MILLISECOND);
		if (enfs_timeout_ms(&start, interval_ms)
			&& enfs_get_config_multipath_state() ==
			ENFS_MULTIPATH_ENABLE) {
			start = ktime_get();
			query_update_all_clnt();
			enfs_log_debug("update shard.\n");
		}
		enfs_msleep(1000);	// 1000 ms.
	}
	return 0;
}

static void enfs_shard_ctrl_clear(void)
{
	struct clnt_uuid_info *info, *tmp_info;
	struct view_table *table, *tmp_table;

	write_lock(&shard_ctrl->clnt_info_lock);
	list_for_each_entry_safe(info, tmp_info, &shard_ctrl->clnt_info_list, next) {
		list_del(&info->next);
		kfree(info);
	}
	write_unlock(&shard_ctrl->clnt_info_lock);

	write_lock(&shard_ctrl->view_lock);
	list_for_each_entry_safe(table, tmp_table, &shard_ctrl->view_list, next) {
		enfs_free_view_table(table);
	}
	write_unlock(&shard_ctrl->view_lock);

	kfree(shard_ctrl);
	shard_ctrl = NULL;
}

static struct shard_view_ctrl *enfs_shard_ctrl_init(void)
{
	struct shard_view_ctrl *ctrl;

	ctrl = kmalloc(sizeof(*ctrl), GFP_KERNEL);
	if (!ctrl) {
		enfs_log_error("shard view ctrl alloc failed.\n");
		return NULL;
	}

	INIT_LIST_HEAD(&ctrl->view_list);
	rwlock_init(&ctrl->view_lock);
	INIT_LIST_HEAD(&ctrl->clnt_info_list);
	rwlock_init(&ctrl->clnt_info_lock);
	return ctrl;
}

static void enfs_shard_workfn(struct work_struct *work)
{
	struct enfs_shard_info *info =
		container_of(work, struct enfs_shard_info, work);
	struct nfs_server *server = info->server;
	struct super_block *super = server->super;
	struct inode *inode;
	struct nfs_fh *fh;
	struct dentry *dentry;
	struct enfs_file_uuid root_uuid;

	dentry = super->s_root;
	if (!dentry)
		goto out;

	inode = d_inode(dentry);
	if (!inode)
		goto out;

	fh = NFS_FH(inode);
	if (is_enfs_debug())
		enfs_debug_fh(fh);
	memset(&root_uuid, 0, sizeof(struct enfs_file_uuid));
	fh_file_uuid(fh, &root_uuid);

	insert_and_update_shard(server->client, &root_uuid);
out:
	nfs_sb_deactive(super);
	kfree(info);
}

static int enfs_check_shard(void)
{
	int ret = 0;
	struct nfs_net *nn;
	struct net *net;
	struct nfs_server *server;
	struct super_block *super;
	struct enfs_shard_info *info;

	shard_check_wq = create_workqueue("shard_check_wq");
	if (!shard_check_wq) {
		ret = -ENOMEM;
		goto out;
	}

	rcu_read_lock();
	for_each_net_rcu(net) {
		nn = net_generic(net, nfs_net_id);
		if (nn == NULL)
			continue;

		spin_lock(&nn->nfs_client_lock);
		list_for_each_entry(server, &nn->nfs_volume_list, master_link) {
			super = server->super;
			if (!super)
				continue;
			if (atomic_read(&super->s_active) == 0)
				continue;
			if (!nfs_sb_active(super))
				continue;
			info = kmalloc(sizeof(*info), GFP_ATOMIC);
			if (!info) {
				nfs_sb_deactive(super);
				ret = -ENOMEM;
				goto out;
			}
			INIT_WORK(&info->work, enfs_shard_workfn);
			info->server = server;
			queue_work(shard_check_wq, &info->work);
		}
		spin_unlock(&nn->nfs_client_lock);
		break;
	}
	rcu_read_unlock();

out:
	// free shard_check_wq in enfs_shard_exit() if an error occurs
	return ret;
}

int enfs_shard_init(void)
{
	int rc;

	shard_ctrl = enfs_shard_ctrl_init();
	if (!shard_ctrl) {
		enfs_log_error("create shard view ctrl failed.\n");
		return -ENOMEM;
	}

	rc = enfs_check_shard();
	if (rc) {
		enfs_log_error("check shard failed!");
		return rc;
	}

	shard_workq = create_workqueue("enfs_shard_workqueue");
	if (!shard_workq) {
		enfs_log_error("create workqueue failed.\n");
		return -ENOMEM;
	}

	shard_thread =
		kthread_run(shard_update_loop, NULL, "enfs_shard_update");
	if (IS_ERR(shard_thread)) {
		enfs_log_error("Failed to create thread shard update.\n");
		return PTR_ERR(shard_thread);
	}
	return 0;
}

void enfs_shard_exit(void)
{
	if (shard_thread)
		kthread_stop(shard_thread);

	if (shard_workq)
		destroy_workqueue(shard_workq);

	if (shard_ctrl)
		enfs_shard_ctrl_clear();

	if (shard_check_wq)
		destroy_workqueue(shard_check_wq);
}

// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_rdma_inject_debugfs.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)

#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/uaccess.h>
#include <linux/bitmap.h>
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_rdma_inject.h"
#include "sxe2_drv_rdma_inject_debugfs.h"
#include "sxe2_drv_rdma_common.h"

#define SXE2_INJECT_DEBUG_FILE_READ_AND_WRITE (0600)
#define SXE2_INJECT_DEBUG_FILE_READ_ONLY      (0400)
#define SXE2_INJECT_DEBUG_FILE_WRITE_ONLY     (0200)
#define INJECT_ARGV_COUNT_MAX		      (32)
#define INJECT_CMD_PARA_CONT1		      (1)
#define INJECT_CMD_PARA_CONT2		      (2)
#define INJECT_CMD_PARA_CONT3		      (3)
#define INJECT_CMD_PARA_CONT4		      (4)
#define INJECT_SHOW_ATTR		      (4)

struct dentry *sxe2_drv_debugfs_get_dev_root(struct sxe2_rdma_device *dev)
{
	return dev->hdl->sxe2_rdma_dbg_dentry;
}
static struct dentry *sxe2_debugfs_create_dir(const char *name,
					      struct dentry *parent)
{
	if (IS_ERR_OR_NULL(parent) && strncmp(name, DEBUGFS_ROOT_DIR, 4))
		return ERR_PTR(-ENOMEM);
	else
		return debugfs_create_dir(name, parent);
}

static struct dentry *
sxe2_debugfs_create_file(const char *name, umode_t mode, struct dentry *parent,
			 void *data, const struct file_operations *fops)
{
	if (IS_ERR_OR_NULL(parent))
		return ERR_PTR(-ENOMEM);
	else
		return debugfs_create_file(name, mode, parent, data, fops);
}

static bool inject_filter_mid(struct sxe2_injection *injection, const char *val)
{
	s32 mid	 = 0;
	bool ret = false;
	int count = 0;

	count = kstrtol(val, 0, (long *)&mid);
	if (mid < 0)
		goto end;

	ret = (bool)(mid == injection->mid);

end:
	return ret;
}

static bool inject_filter_name(struct sxe2_injection *injection, const char *val)
{
	return (bool)(!strncmp(val, injection->inject_name.name, strlen(val)));
}

static bool inject_filter_status(struct sxe2_injection *injection, const char *val)
{
	bool ret = false;

	if (!strncmp(val, "active", strlen(val)) && (injection->alive != 0)) {
		ret = true;
		goto end;
	}
	if (!strncmp(val, "inactive", strlen(val)) && (injection->alive == 0))
		ret = true;

end:
	return ret;
}

static void inject_fmt_item(struct sxe2_injection *injection,
			    struct inject_custom_show_rsp *rsp)
{
	rsp->mid = (u32)injection->mid;
	memcpy(rsp->name, injection->inject_name.name,
	       strlen(injection->inject_name.name));
	rsp->alive = injection->alive;
	rsp->type  = injection->type;
	if (rsp->alive == 0 || injection->user_data[0] == '\0') {
		rsp->usr_data[0] = '\0';
	} else {
		memcpy(rsp->usr_data, injection->user_data,
		       strlen(injection->user_data));
	}
}

static s32 split_command(char *cmd, s32 *argc, char *argv[])
{
	s32 ret	    = 0;
	char *token = NULL;

	cmd[strlen(cmd) - 1] = '\0';
	token		     = strsep(&cmd, " ");
	while (token != NULL) {
		if (*argc >= INJECT_ARGV_COUNT_MAX) {
			ret = -EINVAL;
			DRV_RDMA_LOG_WARN("too many arguments: '%s'\n", token);
			goto end;
		}

		argv[*argc] = token;

		token = strsep(&cmd, " ");
		(*argc)++;
	}

end:
	return ret;
}

static char *inject_type_n2p(enum inject_type type)
{
	s32 ret				   = false;
	static char *str[INJECT_TYPE_BUTT] = { "callback", "pause", "abort",
					       "reset" };
	if (type >= INJECT_TYPE_BUTT)
		ret = true;

	return ret ? "-" : str[type];
}

static enum inject_type inject_type_p2n(char *type)
{
	char *str[INJECT_TYPE_BUTT] = { "callback", "pause", "abort", "reset" };
	enum inject_type e		    = INJECT_TYPE_CALLBACK;

	for (; e < INJECT_TYPE_BUTT; e++) {
		if (!strcasecmp(str[e], type))
			break;
	}
	return e;
}

static ssize_t sxe2_drv_inject_deactive_write(struct file *filp,
					      const char __user *buf,
					      size_t count, loff_t *off)
{
	ssize_t ret			  = 0;
	char cmd[INJECT_CMD_MAX_LEN]	  = { 0 };
	s32 argc			  = 0;
	char *argv[INJECT_ARGV_COUNT_MAX] = { 0 };
	struct sxe2_rdma_pci_f *dev;
	struct sxe2_injection *injection;
	size_t field_len = 0;
	unsigned long flags = 0;
	unsigned long flags_inject = 0;

	if (*off != 0)
		goto end;

	if (count > INJECT_CMD_MAX_LEN) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_ERROR("Cmd exceeded length limit\n");
		goto end;
	}

	dev = filp->private_data;
	if (!dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("dev find fail\n");
		goto end;
	}
	spin_lock_irqsave(&dev->inject_dbg.dbg_lock, flags);

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_ERROR("Cmd copy from user fail\n");
		goto end_unlock;
	}
	DRV_RDMA_LOG_INFO("Request command :%s\n", cmd);

	argc = 0;
	memset(argv, 0, sizeof(*argv) * INJECT_ARGV_COUNT_MAX);
	ret = split_command(cmd, &argc, argv);
	if (ret)
		goto end_unlock;

	if (argc != INJECT_CMD_PARA_CONT1) {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR("Inject Inactive invalid param nums\n");
		goto end_unlock;
	}

	field_len = strlen(argv[0]);
	if (field_len > INJECT_NAME_MAX_LEN - 1) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_ERROR("InjectActive name exceed max len:%u\n",
				   INJECT_NAME_MAX_LEN - 1);
		goto end_unlock;
	}

	injection = inject_find(dev, argv[0]);
	if (injection == NULL) {
		ret = -ENOENT;
		DRV_RDMA_LOG_ERROR("Find inject fail\n");
		goto end_unlock;
	}

	inject_lock(injection, &flags_inject);
	injection->alive = 0;
	inject_unlock(injection, &flags_inject);

end_unlock:
	spin_unlock_irqrestore(&dev->inject_dbg.dbg_lock, flags);

end:
	ret = ret ? ret : (ssize_t)count;
	return ret;
}

static const struct file_operations inject_deactive_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = sxe2_drv_inject_deactive_write,
};

static ssize_t sxe2_drv_inject_active_write(struct file *filp,
					    const char __user *buf,
					    size_t count, loff_t *off)
{
	ssize_t ret			  = 0;
	char cmd[INJECT_CMD_MAX_LEN]	  = { 0 };
	s32 argc			  = 0;
	char *argv[INJECT_ARGV_COUNT_MAX] = { 0 };
	struct sxe2_rdma_pci_f *dev;
	char *attr = NULL;
	struct sxe2_injection *injection;
	struct sxe2_injection tmp;
	size_t field_len			 = 0;
	s32 i					 = 0;
	char *inject_active_in[INJECT_SHOW_ATTR] = { "type=", "alive=",
						     "userData=" };
	int str_count = 0;
	unsigned  long flags = 0;

	if (*off != 0)
		goto end;

	if (count > INJECT_CMD_MAX_LEN) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_ERROR("Cmd exceeded length limit\n");
		goto end;
	}
	dev = filp->private_data;
	if (!dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("dev find fail\n");
		goto end;
	}
	spin_lock_irqsave(&dev->inject_dbg.dbg_lock, flags);
	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_ERROR("Cmd copy from user fail\n");
		goto end_unlock;
	}
	DRV_RDMA_LOG_INFO("Request command :%s\n", cmd);

	argc = 0;
	memset(argv, 0, sizeof(*argv) * INJECT_ARGV_COUNT_MAX);
	ret = split_command(cmd, &argc, argv);
	if (ret)
		goto end_unlock;

	if (argc < INJECT_CMD_PARA_CONT1 || argc > INJECT_CMD_PARA_CONT4) {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR("InjectActive invalid param nums\n");
		goto end_unlock;
	}
	field_len = strlen(argv[0]);
	if (field_len > INJECT_NAME_MAX_LEN - 1) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_ERROR("InjectActive name exceed max len:%u\n",
				   INJECT_NAME_MAX_LEN - 1);
		goto end_unlock;
	}
	memset(&tmp, 0, sizeof(tmp));

	injection = inject_find(dev, argv[0]);
	if (injection == NULL) {
		ret = -ENOENT;
		DRV_RDMA_LOG_ERROR("Find inject fail\n");
		goto end_unlock;
	}
	tmp.inject_name.name = injection->inject_name.name;

	for (i = 0; i < argc; i++) {
		if (!strncmp(argv[i], inject_active_in[0],
			     strlen(inject_active_in[0]))) {
			attr = strstr(argv[i], inject_active_in[0]) +
			       strlen(inject_active_in[0]);
			tmp.type = inject_type_p2n(attr);
		} else if (!strncmp(argv[i], inject_active_in[1],
				    strlen(inject_active_in[1]))) {
			attr = strstr(argv[i], inject_active_in[1]) +
			       strlen(inject_active_in[1]);
			str_count = (s32)kstrtol(attr, 0, (long *)&tmp.alive);
		} else if (!strncmp(argv[i], inject_active_in[2],
				    strlen(inject_active_in[2]))) {
			attr = strstr(argv[i], inject_active_in[2]) +
			       strlen(inject_active_in[2]);
			field_len = strlen(attr);
			if (field_len > INJECT_USR_DATA_LEN - 1) {
				ret = -ENOMEM;
				DRV_RDMA_LOG_ERROR(
					"InjectActive User data exceed max len:%u\n",
					INJECT_USR_DATA_LEN - 1);
				goto end_unlock;
			}
			memcpy(tmp.user_data, attr, field_len);
		}
	}
	inject_fill(&tmp, injection);

end_unlock:
	spin_unlock_irqrestore(&dev->inject_dbg.dbg_lock, flags);
end:
	ret = ret ? ret : (ssize_t)count;
	return ret;
}

static const struct file_operations inject_active_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = sxe2_drv_inject_active_write,
};

static ssize_t sxe2_drv_inject_count_read(struct file *filp, char __user *buf,
					  size_t count, loff_t *off)
{
	ssize_t ret   = 0;
	u32 len_total = 0;
	char *rsp     = NULL;
	char *rsp_end;
	struct sxe2_rdma_pci_f *dev;
	unsigned  long flags = 0;

	if (*off != 0)
		goto end;

	dev = filp->private_data;
	if (!dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("dev find fail\n");
		goto end;
	}
	spin_lock_irqsave(&dev->inject_dbg.dbg_lock, flags);

	rsp = kzalloc(sizeof(char) * INJECT_SNPRINTF_LEN_MAX,
			      GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_ERROR("Inject rsp kmalloc fail\n");
		goto end_unlock;
	}
	rsp_end = rsp;

	INJECT_DEBUG_SNPRINTF(rsp_end, len_total, "Inject Count: %d\n",
			      inject_count(dev));

	ret = simple_read_from_buffer(buf, count, off, rsp, (ssize_t)len_total);
	if (ret < 0)
		DRV_RDMA_LOG_ERROR("simple read error %zu\n", ret);

	kfree(rsp);
	rsp = NULL;

end_unlock:
	spin_unlock_irqrestore(&dev->inject_dbg.dbg_lock, flags);

end:
	return ret;
}

static const struct file_operations inject_count_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = sxe2_drv_inject_count_read,
};
int sxe2_drv_inject_show_read_parse_args(char *cmd, char *rsp,
					 inject_filter_func *filter,
					 char **attr, u32 *len)
{
	s32 argc			       = 0;
	char *argv[INJECT_ARGV_COUNT_MAX]      = { 0 };
	u32 len_total			       = 0;
	int ret				       = 0;
	char *inject_show_in[INJECT_SHOW_ATTR] = { "all",
						   "mid=", "name=", "status=" };

	argc = 0;
	memset(argv, 0, sizeof(*argv) * INJECT_ARGV_COUNT_MAX);
	ret = split_command(cmd, &argc, argv);
	if (ret) {
		ret = -EINVAL;
		goto end;
	}

	if (argc != INJECT_CMD_PARA_CONT1) {
		INJECT_DEBUG_SNPRINTF(rsp, len_total,
				      "InjectShow invalid param nums\n");
		*len = len_total;
		ret  = -EINVAL;
		goto end;
	}

	if (!strncmp(argv[0], inject_show_in[1], strlen(inject_show_in[1]))) {
		*filter = inject_filter_mid;
		*attr	= strstr(argv[0], inject_show_in[1]) +
			strlen(inject_show_in[1]);
	} else if (!strncmp(argv[0], inject_show_in[2],
			    strlen(inject_show_in[2]))) {
		*filter = inject_filter_name;
		*attr	= strstr(argv[0], inject_show_in[2]) +
			strlen(inject_show_in[2]);
	} else if (!strncmp(argv[0], inject_show_in[3],
			    strlen(inject_show_in[3]))) {
		*filter = inject_filter_status;
		*attr	= strstr(argv[0], inject_show_in[3]) +
			strlen(inject_show_in[3]);
	} else if (strncmp(argv[0], inject_show_in[0],
			   strlen(inject_show_in[0]))) {
		INJECT_DEBUG_SNPRINTF(rsp, len_total,
				      "InjectShow invalid param str %s\n",
				      argv[0]);
		*len = len_total;
		ret  = -EINVAL;
		goto end;
	}
end:
	return ret;
}
static ssize_t sxe2_drv_inject_show_read(struct file *filp, char __user *buf,
					 size_t count, loff_t *off)
{
	ssize_t ret   = 0;
	u32 len_total = 0;

	char *cmd;
	char *rsp = NULL;
	char *rsp_end;
	struct sxe2_rdma_pci_f *dev;
	u32 inject_count	  = 0;
	char *attr		  = NULL;
	inject_filter_func filter = NULL;
	struct inject_custom_show_rsp inject_rsp;
	struct list_head *pos = NULL;
	struct sxe2_injection *injection;
	unsigned long flags	  = 0;

	char *inject_info_format[INJECT_MAX_ATTR] = { "MID",	"Name",
						      "Status", "Alive",
						      "Type",	"UserData" };

	if (*off != 0)
		goto end;

	dev = filp->private_data;
	if (!dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("dev find fail\n");
		goto end;
	}
	spin_lock_irqsave(&dev->inject_dbg.dbg_lock, flags);

	cmd = dev->inject_dbg.inject_cmd;
	DRV_RDMA_LOG_INFO("Request command :%s\n", cmd);

	rsp = kzalloc(sizeof(char) * INJECT_SNPRINTF_LEN_MAX,
			      GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_ERROR("Inject rsp kmalloc fail\n");
		goto end_unlock;
	}
	rsp_end = rsp;

	ret = sxe2_drv_inject_show_read_parse_args(cmd, rsp_end, &filter, &attr,
						   &len_total);
	if (ret)
		goto end_kfree;

	spin_lock_irqsave(&dev->inject_mem.list_lock, flags);
	list_for_each(pos, &dev->inject_mem.g_inject_list) {
		injection = list_entry(pos, struct sxe2_injection, list_node);
		if (filter == NULL || filter(injection, attr)) {
			memset(&inject_rsp, 0, sizeof(inject_rsp));
			inject_fmt_item(injection, &inject_rsp);
			INJECT_DEBUG_SNPRINTF(rsp_end, len_total,
					      "<inject %d>:\n", inject_count);
			INJECT_DEBUG_SNPRINTF(rsp_end, len_total, "%s:\t\t%u\n",
					      inject_info_format[0],
					      inject_rsp.mid);
			INJECT_DEBUG_SNPRINTF(rsp_end, len_total, "%s:\t\t%s\n",
					      inject_info_format[1],
					      inject_rsp.name);
			INJECT_DEBUG_SNPRINTF(rsp_end, len_total, "%s:\t\t%s\n",
					      inject_info_format[2],
					      inject_rsp.alive ? "Active" :
								 "Inactive");
			INJECT_DEBUG_SNPRINTF(rsp_end, len_total, "%s:\t\t%d\n",
					      inject_info_format[3],
					      inject_rsp.alive);
			INJECT_DEBUG_SNPRINTF(
				rsp_end, len_total, "%s:\t\t%s\n",
				inject_info_format[4],
				inject_rsp.alive ?
					inject_type_n2p(inject_rsp.type) :
					"-");
			INJECT_DEBUG_SNPRINTF(rsp_end, len_total, "%s:\t%s\n",
					      inject_info_format[5],
					      inject_rsp.usr_data);
			inject_count++;
		}
	}
	INJECT_DEBUG_SNPRINTF(rsp_end, len_total, "InjectCounts %u\n",
			      inject_count);
	spin_unlock_irqrestore(&dev->inject_mem.list_lock, flags);

end_kfree:
	ret = simple_read_from_buffer(buf, count, off, rsp, (ssize_t)len_total);
	if (ret < 0)
		DRV_RDMA_LOG_WARN("simple read error %zu\n", ret);

	kfree(rsp);
	rsp = NULL;
end_unlock:
	spin_unlock_irqrestore(&dev->inject_dbg.dbg_lock, flags);
end:
	return ret;
}

static ssize_t sxe2_drv_inject_show_write(struct file *filp,
					  const char __user *buf, size_t count,
					  loff_t *off)
{
	ssize_t ret		    = 0;
	char *show_cmd		    = NULL;
	struct sxe2_rdma_pci_f *dev = NULL;
	unsigned long flags	  = 0;

	if (*off != 0)
		goto end;

	dev = filp->private_data;
	if (!dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("dev find fail\n");
		goto end;
	}
	spin_lock_irqsave(&dev->inject_dbg.dbg_lock, flags);

	show_cmd = dev->inject_dbg.inject_cmd;
	memset(show_cmd, 0, sizeof(char) * INJECT_CMD_MAX_LEN);

	if (count > INJECT_CMD_MAX_LEN) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_ERROR("Cmd exceeded length limit\n");
		goto end_unlock;
	}

	if (copy_from_user(show_cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_ERROR("Cmd copy from user fail\n");
		goto end_unlock;
	}
	DRV_RDMA_LOG_INFO("Request command :%s\n", show_cmd);

end_unlock:
	spin_unlock_irqrestore(&dev->inject_dbg.dbg_lock, flags);
	ret = ret ? ret : (ssize_t)count;

end:
	return ret;
}

static const struct file_operations inject_show_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = sxe2_drv_inject_show_read,
	.write = sxe2_drv_inject_show_write,
};

void sxe2_drv_inject_clean_debug_files(struct sxe2_rdma_device *dev)
{
	struct sxe2_inject_debug *dbg_node = NULL;

	dbg_node = &dev->rdma_func->inject_dbg;
	debugfs_remove_recursive(dbg_node->dbg_root);
	dbg_node->dbg_root = NULL;
}
EXPORT_SYMBOL(sxe2_drv_inject_clean_debug_files);

void sxe2_drv_inject_create_debugfs_files(struct sxe2_rdma_device *dev)
{
	struct sxe2_inject_debug *dbg_node = NULL;

	dbg_node	   = &dev->rdma_func->inject_dbg;
	dbg_node->dbg_root = sxe2_debugfs_create_dir(
		"inject", sxe2_drv_debugfs_get_dev_root(dev));
	if (IS_ERR_OR_NULL(dbg_node->dbg_root)) {
		DRV_RDMA_LOG_ERROR("Create debugfs dir fail.\n");
		goto end;
	}

	sxe2_debugfs_create_file("inject_show",
				 SXE2_INJECT_DEBUG_FILE_READ_AND_WRITE,
				 dbg_node->dbg_root, dev->rdma_func,
				 &inject_show_fops);
	sxe2_debugfs_create_file("inject_count",
				 SXE2_INJECT_DEBUG_FILE_READ_ONLY,
				 dbg_node->dbg_root, dev->rdma_func,
				 &inject_count_fops);
	sxe2_debugfs_create_file("inject_active",
				 SXE2_INJECT_DEBUG_FILE_WRITE_ONLY,
				 dbg_node->dbg_root, dev->rdma_func,
				 &inject_active_fops);
	sxe2_debugfs_create_file("inject_deactive",
				 SXE2_INJECT_DEBUG_FILE_WRITE_ONLY,
				 dbg_node->dbg_root, dev->rdma_func,
				 &inject_deactive_fops);

	spin_lock_init(&dbg_node->dbg_lock);

end:
	return;
}
EXPORT_SYMBOL(sxe2_drv_inject_create_debugfs_files);

#endif

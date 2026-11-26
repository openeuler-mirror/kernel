// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/namei.h>
#include "enfs.h"
#include "enfs_errcode.h"
#include "enfs_log.h"
#include "enfs_config.h"

#define MAX_FILE_SIZE 8192
#define STRING_BUF_SIZE 128
#define CONFIG_FILE_PATH "/etc/enfs/config.ini"
#define ENFS_NOTIFY_FILE_PERIOD 1000UL

#define MAX_PATH_DETECT_INTERVAL 300
#define MIN_PATH_DETECT_INTERVAL 5
#define MAX_PATH_DETECT_TIMEOUT 60
#define MIN_PATH_DETECT_TIMEOUT 1
#define MAX_MULTIPATH_TIMEOUT 60
#define MIN_MULTIPATH_TIMEOUT 0
#define MAX_MULTIPATH_STATE ENFS_MULTIPATH_DISABLE
#define MIN_MULTIPATH_STATE ENFS_MULTIPATH_ENABLE
#define MIN_SHARDVIEW_UPDATE_INTERVAL 30 // 30 second
#define MAX_SHARDVIEW_UPDATE_INTERVAL 300 // 300 second
#define MIN_LOOKUPCACHE_INTERVAL 30 // 30 second
#define MAX_LOOKUPCACHE_STATE ENFS_LOOKUPCACHE_ENABLE
#define MIN_LOOKUPCACHE_STATE ENFS_LOOKUPCACHE_DISABLE

#define DEFAULT_PATH_DETECT_INTERVAL 10
#define DEFAULT_PATH_DETECT_TIMEOUT 5
#define DEFAULT_MULTIPATH_TIMEOUT 0 // 0 means use mount cmd para
#define DEFAULT_MULTIPATH_STATE ENFS_MULTIPATH_ENABLE
#define DEFAULT_LOADBALANCE_MODE ENFS_LOADBALANCE_RR
#define DEFAULT_DNS_UPDATE_INTERVAL 5 // 5 minute
#define DEFAULT_DNS_AUTO_MULTIPATH_RESOLUTION 0 // default is disable
#define DEFAULT_SHARDVIEW_UPDATE_INTERVAL 60 // 60 second
#define MAX_PRIOPITY_ARRAY_WWNS 6
#define MAX_IP_PREFIX 8
#define DEFAULT_LOOKUPCACHE_INTERVAL 60 // 60 second
#define DEFAULT_LOOKUPCACHE_STATE ENFS_LOOKUPCACHE_ENABLE

typedef int (*check_and_assign_func)(char *, char *, int, int);

struct enfs_config_info {
	int32_t path_detect_interval;
	int32_t path_detect_timeout;
	int32_t multipath_timeout;
	int32_t loadbalance_mode;
	int32_t multipath_state;
	int32_t dns_update_interval;
	int32_t dns_auto_multipath_resolution;
	int32_t shardview_update_interval;
	int32_t priopity_wwn_count;
	uint64_t priopity_array_wwns[MAX_PRIOPITY_ARRAY_WWNS];
	int32_t ip_filters_count;
	char local_ip_filters[MAX_IP_PREFIX][INET6_ADDRSTRLEN];
	int32_t lookupcache_interval;
	int32_t lookupcache_enable;
	int32_t link_count_per_mount;
	int32_t link_count_total;
	int32_t native_link_io_enable;
	int32_t create_path_no_route;
};

struct enfs_config_value_info {
	char *field_name;
	check_and_assign_func func;
	int min_value;
	int max_value;
};

static struct enfs_config_info g_enfs_config_info;
static struct timespec64 modify_time;
static struct task_struct *thread;

static int enfs_check_config_value(char *value, int min_value, int max_value)
{
	unsigned long num_value;
	int ret;

	ret = kstrtol(value, 10, &num_value);
	if (ret != 0) {
		enfs_log_error("Failed to convert string to int\n");
		return -EINVAL;
	}

	if (num_value < min_value || num_value > max_value)
		return -EINVAL;

	return num_value;
}

static int32_t enfs_check_and_assign_int_value(char *field_name, char *value,
					       int min_value, int max_value)
{
	int i;
	int int_value;
	static struct config_entry_t {
		const char *name;
		int32_t *val;
	} config[] = {
		{ "path_detect_interval",
		  &g_enfs_config_info.path_detect_interval },
		{ "path_detect_timeout",
		  &g_enfs_config_info.path_detect_timeout },
		{ "multipath_timeout", &g_enfs_config_info.multipath_timeout },
		{ "multipath_disable", &g_enfs_config_info.multipath_state },
		{ "dns_update_interval",
		  &g_enfs_config_info.dns_update_interval },
		{ "dns_auto_multipath_resolution",
		  &g_enfs_config_info.dns_auto_multipath_resolution },
		{ "shardview_update_interval",
		  &g_enfs_config_info.shardview_update_interval },
		{ "lookupcache_interval",
		  &g_enfs_config_info.lookupcache_interval },
		{ "lookupcache_enable",
		  &g_enfs_config_info.lookupcache_enable },
		{ "link_count_per_mount",
		  &g_enfs_config_info.link_count_per_mount },
		{ "link_count_total", &g_enfs_config_info.link_count_total },
		{ "native_link_io_enable",
		  &g_enfs_config_info.native_link_io_enable },
		{ "create_path_no_route",
		  &g_enfs_config_info.create_path_no_route },
	};

	int_value = enfs_check_config_value(value, min_value, max_value);
	if (int_value < 0)
		return -EINVAL;

	for (i = 0; i < ARRAY_SIZE(config); i++) {
		if (strcmp(field_name, config[i].name) == 0) {
			*config[i].val = int_value;
			return ENFS_RET_OK;
		}
	}
	return -EINVAL;
}

static int32_t enfs_check_and_assign_loadbalance_mode(char *field_name,
						      char *value,
						      int min_value,
						      int max_value)
{
	if (value == NULL)
		return -EINVAL;

	if (strcmp(field_name, "multipath_select_policy") == 0) {
		if (strcmp(value, "roundrobin") == 0) {
			g_enfs_config_info.loadbalance_mode =
				ENFS_LOADBALANCE_RR;
			return ENFS_RET_OK;
		}
		if (strcmp(value, "shardview") == 0) {
			g_enfs_config_info.loadbalance_mode =
				ENFS_LOADBALANCE_SHARDVIEW;
			return ENFS_RET_OK;
		}
	}
	return -EINVAL;
}

static int32_t enfs_check_and_assign_ip_filters(char *field_name, char *value,
						int min_value, int max_value)
{
	int count = 0;
	char *token;
	char *copy;
	char *tmp;

	if (strcmp(field_name, "local_ip_filters") != 0)
		return -EINVAL;
	copy = kstrdup(value, GFP_KERNEL);
	tmp = copy;
	if (!copy)
		return -EINVAL;

	if (strlen(tmp) == 0) {
		g_enfs_config_info.ip_filters_count = count;
		kfree(copy);
		return ENFS_RET_OK;
	}
	while ((token = strsep(&tmp, ",")) != NULL) {
		if (count >= MAX_IP_PREFIX) {
			kfree(copy);
			return -EINVAL;
		}

		if (strlen(token) >= INET6_ADDRSTRLEN) { // 48 byte
			kfree(copy);
			return -EINVAL;
		}

		strscpy(g_enfs_config_info.local_ip_filters[count], token, INET6_ADDRSTRLEN);
		count++;
	}

	g_enfs_config_info.ip_filters_count = count;
	kfree(copy);
	return ENFS_RET_OK;
}

static int32_t enfs_check_and_assign_wwns(char *field_name, char *value,
					  int min_value, int max_value)
{
	int count = 0;
	char *token;
	char *copy;
	char *tmp;

	if (value == NULL)
		return -EINVAL;

	if (strcmp(field_name, "priopity_array_wwns") != 0)
		return -EINVAL;
	copy = kstrdup(value, GFP_KERNEL);
	tmp = copy;
	if (!copy)
		return -EINVAL;

	while ((token = strsep(&tmp, ",")) != NULL) {
		unsigned long long value;
		int ret;

		if (count >= MAX_PRIOPITY_ARRAY_WWNS) {
			kfree(copy);
			return -EINVAL;
		}
		if (strlen(token) != 16) { // 8 bytes = 16 chars
			kfree(copy);
			return -EINVAL;
		}

		ret = kstrtoull(token, 16, &value);
		if (ret != 0) {
			kfree(copy);
			return -EINVAL;
		}

		g_enfs_config_info.priopity_array_wwns[count] = value;
		count++;
	}

	g_enfs_config_info.priopity_wwn_count = count;
	kfree(copy);
	return ENFS_RET_OK;
}

static const struct enfs_config_value_info g_check_and_assign_value[] = {
	{ "path_detect_interval", enfs_check_and_assign_int_value,
	  MIN_PATH_DETECT_INTERVAL, MAX_PATH_DETECT_INTERVAL },
	{ "path_detect_timeout", enfs_check_and_assign_int_value,
	  MIN_PATH_DETECT_TIMEOUT, MAX_PATH_DETECT_TIMEOUT },
	{ "multipath_timeout", enfs_check_and_assign_int_value,
	  MIN_MULTIPATH_TIMEOUT, MAX_MULTIPATH_TIMEOUT },
	{ "multipath_disable", enfs_check_and_assign_int_value,
	  MIN_MULTIPATH_STATE, MAX_MULTIPATH_STATE },
	{ "multipath_select_policy", enfs_check_and_assign_loadbalance_mode, 0,
	  0 },
	{ "dns_update_interval", enfs_check_and_assign_int_value, 0, INT_MAX },
	{ "dns_auto_multipath_resolution", enfs_check_and_assign_int_value, 0,
	  1 },
	{ "shardview_update_interval", enfs_check_and_assign_int_value,
	  MIN_SHARDVIEW_UPDATE_INTERVAL, MAX_SHARDVIEW_UPDATE_INTERVAL },
	{ "priopity_array_wwns", enfs_check_and_assign_wwns, 0, 0 },
	{ "local_ip_filters", enfs_check_and_assign_ip_filters, 0, 0 },
	{ "lookupcache_interval", enfs_check_and_assign_int_value,
	  MIN_LOOKUPCACHE_INTERVAL, INT_MAX },
	{ "lookupcache_enable", enfs_check_and_assign_int_value,
	  MIN_LOOKUPCACHE_STATE, MAX_LOOKUPCACHE_STATE },
	{ "link_count_per_mount", enfs_check_and_assign_int_value,
	  MIN_SUPPORTED_REMOTE_IP_COUNT, MAX_SUPPORTED_REMOTE_IP_COUNT },
	{ "link_count_total", enfs_check_and_assign_int_value,
	  MIN_ENFS_MAX_LINK_COUNT, ENFS_MAX_LINK_COUNT },
	{ "native_link_io_enable", enfs_check_and_assign_int_value, 0, 1 },
	{ "create_path_no_route", enfs_check_and_assign_int_value, 0, 1 },
};

static int32_t enfs_read_config_file_in_openeuler(char *buffer, char *file_path)
{
	int ret;
	ssize_t len;
	struct file *filp;
	loff_t f_pos = 0;

	filp = filp_open(file_path, O_RDONLY, 0);
	if (IS_ERR(filp)) {
		enfs_log_error("Failed to open file %s\n", file_path);
		return PTR_ERR(filp);
	}

	len = kernel_read(filp, buffer, MAX_FILE_SIZE, &f_pos);
	ret = filp_close(filp, NULL);
	if (len < 0)
		return len;
	if (ret)
		return ret;
	buffer[len] = '\0';
	return ENFS_RET_OK;
}

static int32_t enfs_deal_with_comment_line(char *buffer)
{
	int ret;
	char *pos = strchr(buffer, '\n');

	if (pos != NULL)
		ret = strlen(buffer) - strlen(pos);
	else
		ret = strlen(buffer);
	return ret;
}

static int32_t enfs_parse_key_value_from_config(char *buffer, char *key,
						char *value, int keyLen,
						int valueLen)
{
	char *line;
	char *tokenPtr;
	int len;
	char *tem;
	char *pos = strchr(buffer, '\n');

	if (pos != NULL)
		len = strlen(buffer) - strlen(pos);
	else
		len = strlen(buffer);
	line = kmalloc(len + 1, GFP_KERNEL);
	if (!line) {
		enfs_log_error("Failed to allocate memory.\n");
		return -ENOMEM;
	}
	line[len] = '\0';
	strscpy(line, buffer, len + 1);

	tem = line;
	tokenPtr = strsep(&tem, "=");
	if (tokenPtr == NULL || tem == NULL) {
		kfree(line);
		return len;
	}
	strscpy(key, strim(tokenPtr), keyLen);
	strscpy(value, strim(tem), valueLen);

	kfree(line);
	return len;
}

static int32_t enfs_get_value_from_config_file(char *buffer, char *field_name,
					       char *value, int valueLen)
{
	int ret;
	char key[STRING_BUF_SIZE + 1] = { 0 };
	char val[STRING_BUF_SIZE + 1] = { 0 };

	while (buffer[0] != '\0') {
		// parse one line
		if (buffer[0] == '\n') {
			// handle space line
			buffer++;
		} else if (buffer[0] == '#') {
			// handle comment
			ret = enfs_deal_with_comment_line(buffer);
			if (ret > 0)
				buffer += ret;
		} else {
			// normal config line
			ret = enfs_parse_key_value_from_config(buffer, key, val,
							       STRING_BUF_SIZE,
							       STRING_BUF_SIZE);
			if (ret < 0) {
				enfs_log_error(
					"failed to parse key value,ret = %d.\n",
					ret);
				return ret;
			}
			key[STRING_BUF_SIZE] = '\0';
			val[STRING_BUF_SIZE] = '\0';

			buffer += ret;

			if (strcmp(field_name, key) == 0) {
				strscpy(value, val, valueLen);
				return ENFS_RET_OK;
			}
		}
	}
	enfs_log_debug("can not find value which matched field_name: %s.\n",
		       field_name);
	return -EINVAL;
}

int32_t enfs_config_load(void)
{
	char value[STRING_BUF_SIZE + 1];
	int ret;
	int table_len;
	int min;
	int max;
	int i;
	char *buffer;

	buffer = kmalloc(MAX_FILE_SIZE + 1, GFP_KERNEL);
	if (!buffer) {
		enfs_log_error("Failed to allocate memory.\n");
		return -ENOMEM;
	}

	// default value
	g_enfs_config_info.path_detect_interval = DEFAULT_PATH_DETECT_INTERVAL;
	g_enfs_config_info.path_detect_timeout = DEFAULT_PATH_DETECT_TIMEOUT;
	g_enfs_config_info.multipath_timeout = DEFAULT_MULTIPATH_TIMEOUT;
	g_enfs_config_info.multipath_state = DEFAULT_MULTIPATH_STATE;
	g_enfs_config_info.loadbalance_mode = DEFAULT_LOADBALANCE_MODE;
	g_enfs_config_info.dns_update_interval = DEFAULT_DNS_UPDATE_INTERVAL;
	g_enfs_config_info.dns_auto_multipath_resolution = 0;
	g_enfs_config_info.shardview_update_interval =
		DEFAULT_SHARDVIEW_UPDATE_INTERVAL;
	g_enfs_config_info.priopity_wwn_count = 0;
	g_enfs_config_info.ip_filters_count = 0;
	memset(g_enfs_config_info.local_ip_filters, 0,
	       sizeof(g_enfs_config_info.local_ip_filters));
	g_enfs_config_info.lookupcache_interval = DEFAULT_LOOKUPCACHE_INTERVAL;
	g_enfs_config_info.lookupcache_enable = DEFAULT_LOOKUPCACHE_STATE;
	g_enfs_config_info.link_count_per_mount =
		DEFAULT_SUPPORTED_REMOTE_IP_COUNT;
	g_enfs_config_info.link_count_total = DEFAULT_ENFS_MAX_LINK_COUNT;
	g_enfs_config_info.native_link_io_enable = 1;
	g_enfs_config_info.create_path_no_route = 0;

	table_len = sizeof(g_check_and_assign_value) /
		    sizeof(g_check_and_assign_value[0]);

	ret = enfs_read_config_file_in_openeuler(buffer, CONFIG_FILE_PATH);
	if (ret != 0) {
		kfree(buffer);
		return ret;
	}
	for (i = 0; i < table_len; i++) {
		ret = enfs_get_value_from_config_file(
			buffer, g_check_and_assign_value[i].field_name, value,
			STRING_BUF_SIZE);
		if (ret < 0)
			continue;
		value[STRING_BUF_SIZE] = '\0';
		min = g_check_and_assign_value[i].min_value;
		max = g_check_and_assign_value[i].max_value;
		if (g_check_and_assign_value[i].func != NULL) {
			(*g_check_and_assign_value[i].func)(
				g_check_and_assign_value[i].field_name, value,
				min, max);
		}
	}

	kfree(buffer);
	return ENFS_RET_OK;
}

int32_t enfs_get_config_path_detect_interval(void)
{
	return g_enfs_config_info.path_detect_interval;
}

int32_t enfs_get_config_path_detect_timeout(void)
{
	return g_enfs_config_info.path_detect_timeout;
}

int32_t enfs_get_config_multipath_timeout(void)
{
	return g_enfs_config_info.multipath_timeout;
}

int32_t enfs_get_config_multipath_state(void)
{
	return g_enfs_config_info.multipath_state;
}

int32_t enfs_get_config_loadbalance_mode(void)
{
	return g_enfs_config_info.loadbalance_mode;
}

int32_t enfs_get_config_dns_update_interval(void)
{
	return g_enfs_config_info.dns_update_interval;
}

int32_t enfs_get_config_dns_auto_multipath_resolution(void)
{
	return g_enfs_config_info.dns_auto_multipath_resolution;
}

int32_t enfs_get_config_shardview_update_interval(void)
{
	return g_enfs_config_info.shardview_update_interval;
}

int32_t enfs_get_config_lookupcache_interval(void)
{
	return g_enfs_config_info.lookupcache_interval;
}

int32_t enfs_get_config_lookupcache_state(void)
{
	return g_enfs_config_info.lookupcache_enable;
}

int32_t enfs_get_config_link_count_per_mount(void)
{
	return g_enfs_config_info.link_count_per_mount;
}

int32_t enfs_get_config_link_count_total(void)
{
	return g_enfs_config_info.link_count_total;
}

int32_t enfs_get_native_link_io_status(void)
{
	return g_enfs_config_info.native_link_io_enable;
}

int32_t enfs_get_create_path_no_route(void)
{
	return g_enfs_config_info.create_path_no_route;
}

bool enfs_check_config_wwn(uint64_t wwn)
{
	int count;

	for (count = 0; count < g_enfs_config_info.priopity_wwn_count;
	     count++) {
		if (g_enfs_config_info.priopity_array_wwns[count] == wwn)
			return true;
	}
	return false;
}

bool enfs_glob_match(char const *pat, char const *str)
{
	unsigned char c;
	unsigned char d;
	char const *back_pat = NULL;
	char const *back_str = str;
	bool match = false;
	bool inverted = (*pat == '!');
	char const *class = pat + inverted;
	unsigned char a = *class++;
	unsigned char b = a;

	for (;;) {
		c = *str++;
		d = *pat++;

		switch (d) {
		case '?':
			if (c == '\0')
				return false;
			break;
		case '*':
			if (*pat == '\0')
				return true;
			back_pat = pat;
			back_str = --str;
			break;
		case '[': {
			match = false;
			inverted = (*pat == '!');
			class = pat + inverted;
			a = *class++;

			do {
				b = a;
				if (a == '\0')
					goto literal;

				if (class[0] == '-' && class[1] != ']') {
					b = class[1];

					if (b == '\0')
						goto literal;

					class += 2;
				}
				match |= (a <= c && c <= b);
			} while ((a = *class++) != ']');

			if (match == inverted)
				goto backtrack;
			pat = class;
			}
			break;

		case '\\':
			d = *pat++;
			break;
		default:
literal:
			if (c == d) {
				if (d == '\0')
					return true;
				break;
			}
backtrack:
			if (c == '\0' || !back_pat)
				return false;
			pat = back_pat;
			str = ++back_str;
			break;
		}
	}
}

bool enfs_whitelist_filte(char *ip_addr)
{
	int i;
	int count = g_enfs_config_info.ip_filters_count;

	if (count == 0)
		return true;

	for (i = 0; i < count; i++) {
		if (enfs_glob_match(g_enfs_config_info.local_ip_filters[i],
				    ip_addr)) {
			return true;
		}
	}
	return false;
}

static bool enfs_file_changed(const char *filename)
{
	int err;
	struct kstat file_stat;

	struct path fpath;

	err = kern_path(filename, LOOKUP_FOLLOW, &fpath);
	if (err)
		return false;
	err = vfs_getattr(&fpath, &file_stat, STATX_BASIC_STATS, 0);
	path_put(&fpath);

	if (err) {
		enfs_log_debug("failed to open file:%s err:%d\n", filename,
			       err);
		return false;
	}

	if (timespec64_compare(&modify_time, &file_stat.mtime) == -1) {
		modify_time = file_stat.mtime;
		enfs_log_debug("file change: %lld %lld\n",
			       (long long)(modify_time.tv_sec),
			       (long long)(file_stat.mtime.tv_sec));
		return true;
	}

	return false;
}

static int enfs_thread_func(void *data)
{
	while (!kthread_should_stop()) {
		if (enfs_file_changed(CONFIG_FILE_PATH))
			enfs_config_load();
		enfs_msleep(ENFS_NOTIFY_FILE_PERIOD);
	}
	return 0;
}

int enfs_config_timer_init(void)
{
	thread = kthread_run(enfs_thread_func, NULL, "enfs_notiy_file_thread");
	if (IS_ERR(thread)) {
		enfs_log_error("Failed to create kernel thread\n");
		return PTR_ERR(thread);
	}
	return 0;
}

void enfs_config_timer_exit(void)
{
	enfs_log_info("enfs_notify_file_exit\n");
	if (thread)
		kthread_stop(thread);
}

int GetEnfsConfigIpFiltersCount(void)
{
	return g_enfs_config_info.ip_filters_count;
}

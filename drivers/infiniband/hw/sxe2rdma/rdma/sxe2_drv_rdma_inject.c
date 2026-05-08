// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_rdma_inject.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)

#include <linux/delay.h>
#include <linux/bug.h>
#include <linux/vmalloc.h>
#include <linux/bitmap.h>
#include <linux/mutex.h>

#include "sxe2_drv_rdma_inject.h"
#include "sxe2_drv_rdma_common.h"
#include "sxe2_drv_rdma_log.h"

#define INJECT_MAX_ARGC	       16
#define INJECT_CMD_LEN	       200
#define INJECT_HASH_TABLE_SIZE 512
#define INJECT_PARTITION_SIZE  (2 * 1024 * 1024)
#define INJECT_HASH_CODE       (1315423911)

struct inject_type_proc {
	char *string;
	enum inject_type value;
};

struct inject_cmd_param_proc {
	const char *opt;
	s32 (*proc)(const char *data, struct sxe2_injection *param);
};

void inject_lock(struct sxe2_injection *injection, unsigned long *flags)
{
	spin_lock_irqsave(&injection->lock, *flags);
}

void inject_unlock(struct sxe2_injection *injection, unsigned long *flags)
{
	spin_unlock_irqrestore(&injection->lock, *flags);
}

static s32 inject_init_mem(struct sxe2_rdma_pci_f *dev)
{
	s32 ret = 0;

	struct sxe2_inject_mem_mgr *mm = &dev->inject_mem.inject_mem_mgr;

	mm->base_addr = vzalloc(INJECT_PARTITION_SIZE);
	if (mm->base_addr == NULL) {
		ret = -EFAULT;
	} else {
		mm->end_addr = mm->base_addr + INJECT_PARTITION_SIZE;
		mm->cursor   = mm->base_addr;
	}

	return ret;
}

static void *inject_get_sub_mem(struct sxe2_rdma_pci_f *dev, u32 size)
{
	void *ptr		       = NULL;
	struct sxe2_inject_mem_mgr *mm = &dev->inject_mem.inject_mem_mgr;

	if (mm->cursor + size < mm->end_addr) {
		ptr = mm->cursor;
		mm->cursor += size;
	}
	return ptr;
}

s32 inject_init(struct sxe2_rdma_pci_f *dev)
{
	u32 i	= 0;
	s32 ret = 0;
	struct list_head *g_inject_hash_table;
	struct sxe2_inject_mem_mgr *mm;
	u64 *usable_mm;
	u32 inject_mm_cnt = 0;

	WARN_ON(dev == NULL);
	if (dev == NULL) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("dev find fail, ret %d\n", ret);
		goto end;
	}

	ret = inject_init_mem(dev);
	WARN_ON(ret != 0);
	if (ret != 0) {
		DRV_RDMA_LOG_ERROR("inject init mem fail, ret %d\n", ret);
		goto end;
	}

	mm = &dev->inject_mem.inject_mem_mgr;

	g_inject_hash_table = (struct list_head *)inject_get_sub_mem(
		dev, sizeof(struct list_head) * INJECT_HASH_TABLE_SIZE);
	dev->inject_mem.g_inject_hash_table = g_inject_hash_table;
	WARN_ON(g_inject_hash_table == NULL);
	if (g_inject_hash_table == NULL) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_ERROR("inject get sub mem fail, ret %d\n", ret);
		goto err_hash;
	}

	for (; i < INJECT_HASH_TABLE_SIZE; i++)
		INIT_LIST_HEAD(&g_inject_hash_table[i]);

	INIT_LIST_HEAD(&dev->inject_mem.g_inject_list);
	spin_lock_init(&dev->inject_mem.list_lock);
	inject_mm_cnt = (u32)DIV_ROUND_UP((mm->end_addr - mm->cursor),
					  sizeof(struct sxe2_injection));
	usable_mm     = vzalloc(inject_mm_cnt * sizeof(u64));
	DRV_RDMA_LOG_INFO("inject mm cnt %#x, sizeof(u64) %#x, usable mm %#x\n",
			  (u32)inject_mm_cnt, (u32)sizeof(u64),
			  (u32)inject_mm_cnt * (u32)sizeof(u64));
	if (usable_mm == NULL) {
		ret = -EFAULT;
		DRV_RDMA_LOG_ERROR("inject init usable mem fail, ret %d\n",
				   ret);
		goto err_hash;
	}
	mm->usable_array.array_addr = usable_mm;

	spin_lock_init(&mm->usable_array.array_lock);
	mm->usable_array.array_addr[0] = 0;

	DRV_RDMA_LOG_INFO(
		"inject init mem %#x, usable mem %#llx, each injection mem %#x\n",
		(u32)INJECT_PARTITION_SIZE, (u64)inject_mm_cnt * sizeof(u64),
		(u32)sizeof(struct sxe2_injection));

	goto end;

err_hash:
	vfree(mm->base_addr);
	mm->base_addr = NULL;
	mm->end_addr  = NULL;
	mm->cursor    = NULL;
end:
	return ret;
}

static u32 inject_str_hash_code(const char *str)
{
	u32 hash = INJECT_HASH_CODE;

	while (*str)
		hash ^= ((hash << 5) + (hash >> 2) + (*str++));

	return hash;
}

static void inject_set_name(struct inject_name *injection_name, const char *name)
{
	injection_name->name	  = name;
	injection_name->hash_code = inject_str_hash_code(name);
}

static inline struct list_head *
inject_get_hash_head(struct sxe2_rdma_pci_f *dev, u32 hash_code)
{
	struct sxe2_inject_mem *mm = &dev->inject_mem;

	return &mm->g_inject_hash_table[hash_code % INJECT_HASH_TABLE_SIZE];
}

static struct sxe2_injection *inject_find_inner(struct sxe2_rdma_pci_f *dev,
					   const char *name)
{
	struct list_head *pos;
	struct sxe2_injection *injection;
	bool found = false;
	struct list_head *head;
	struct inject_name injection_name;
	unsigned long flags	  = 0;

	if (strlen(name) > SXE2_INJECT_NAME_MAX_LEN)
		goto end;

	inject_set_name(&injection_name, name);

	spin_lock_irqsave(&dev->inject_mem.list_lock, flags);
	head = inject_get_hash_head(dev, injection_name.hash_code);
	list_for_each(pos, head) {
		injection = list_entry(pos, struct sxe2_injection, hash_node);
		if (injection->inject_name.hash_code !=
		    injection_name.hash_code) {
			continue;
		}

		if (strncmp(injection->inject_name.name, injection_name.name,
			    strlen(injection_name.name)) == 0) {
			found = true;
			break;
		}
	}

end:
	spin_unlock_irqrestore(&dev->inject_mem.list_lock, flags);
	return found ? injection : NULL;
}

struct sxe2_injection *inject_find(struct sxe2_rdma_pci_f *dev, const char *name)
{
	struct sxe2_injection *ret = NULL;

	if (dev == NULL || name == NULL) {
		DRV_RDMA_LOG_ERROR("dev/name find fail\n");
		goto end;
	}

	ret = inject_find_inner(dev, name);

end:
	return ret;
}
EXPORT_SYMBOL(inject_find);

s32 inject_register(struct sxe2_rdma_pci_f *dev, const char *name,
		    inject_callback callback, s32 mid)
{
	s32 ret = 0;
	struct sxe2_injection *injection;
	struct list_head *head;
	struct sxe2_inject_usable_array *usable_arr;
	u64 *usable_mm;
	u64 usable_index;
	unsigned long flags	  = 0;

	if (dev == NULL || name == NULL || callback == NULL) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"Inject reg param dev/name/callback is null, ret %d\n",
			ret);
		goto end;
	}

	injection = inject_find_inner(dev, name);
	if (injection != NULL) {
		DRV_RDMA_LOG_WARN("Name=%s exist\n", name);
		goto end;
	}

	usable_arr = &dev->inject_mem.inject_mem_mgr.usable_array;
	usable_mm  = usable_arr->array_addr;
	spin_lock_irqsave(&usable_arr->array_lock, flags);
	usable_index = usable_mm[0];

	if (usable_index) {
		injection = (struct sxe2_injection *)usable_mm[usable_index];
		DRV_RDMA_LOG_INFO("usable index %#llx, usable addr %#llx\n",
				  usable_index, usable_mm[usable_index]);
		usable_mm[usable_index] = 0;
		usable_index--;
		usable_mm[0] = usable_index;
	} else {
		injection = inject_get_sub_mem(dev, sizeof(struct sxe2_injection));
		if (injection == NULL) {
			spin_unlock_irqrestore(&usable_arr->array_lock, flags);
			ret = -ENOMEM;
			DRV_RDMA_LOG_ERROR("inject get sub mem fail, ret %d\n",
					   ret);
			goto end;
		}
	}
	spin_unlock_irqrestore(&usable_arr->array_lock, flags);

	memset(injection, 0, sizeof(struct sxe2_injection));
	injection->alive = 0;
	inject_set_name(&injection->inject_name, name);
	injection->callback = callback;
	injection->mid	    = mid;
	injection->type	    = INJECT_TYPE_BUTT;
	spin_lock_init(&injection->lock);

	spin_lock_irqsave(&dev->inject_mem.list_lock, flags);
	head = inject_get_hash_head(dev, injection->inject_name.hash_code);
	list_add_tail(&injection->hash_node, head);
	list_add_tail(&injection->list_node, &dev->inject_mem.g_inject_list);
	spin_unlock_irqrestore(&dev->inject_mem.list_lock, flags);

	DRV_RDMA_LOG_INFO("inject %s registered\n", name);

end:
	return ret;
}
EXPORT_SYMBOL(inject_register);

s32 inject_unregister(struct sxe2_rdma_pci_f *dev, const char *name)
{
	s32 ret = 0;
	struct sxe2_injection *injection;
	struct sxe2_inject_usable_array *usable_arr;
	u64 *usable_mm;
	u64 usable_index;
	unsigned long flags	  = 0;
	unsigned long flags_array	  = 0;
	unsigned long flags_list	  = 0;

	if (dev == NULL || name == NULL) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"Inject unreg param dev/name is null, ret %d\n", ret);
		goto end;
	}

	injection = inject_find_inner(dev, name);
	if (injection == NULL) {
		ret = -EFAULT;
		DRV_RDMA_LOG_ERROR("Name=%s is not exist, ret %d\n", name, ret);
		goto end;
	}
	inject_lock(injection, &flags);
	usable_arr = &dev->inject_mem.inject_mem_mgr.usable_array;
	usable_mm  = usable_arr->array_addr;
	spin_lock_irqsave(&usable_arr->array_lock, flags_array);
	usable_index = usable_mm[0];

	usable_index++;
	usable_mm[usable_index] = (u64)injection;
	usable_mm[0]		= usable_index;
	spin_unlock_irqrestore(&usable_arr->array_lock, flags_array);

	spin_lock_irqsave(&dev->inject_mem.list_lock, flags_list);
	list_del(&injection->hash_node);
	list_del(&injection->list_node);
	spin_unlock_irqrestore(&dev->inject_mem.list_lock, flags_list);

	inject_unlock(injection, &flags);

	memset(injection, 0, sizeof(struct sxe2_injection));

	DRV_RDMA_LOG_INFO(
		"inject %s unregistered, usable index %#llx, usable addr %#llx\n",
		name, usable_index, usable_mm[usable_index]);

	goto end;

end:
	return ret;
}
EXPORT_SYMBOL(inject_unregister);

static void inject_split_string(char *str, s32 *argc, char *argv[],
				s32 max_argc)
{
	s32 idx	     = 0;
	bool is_head = false;

	if (*str != ' ' && *str != '\t')
		is_head = true;

	while (*str != '\0') {
		if (*str == ' ' || *str == '\t') {
			is_head = true;
			*str	= '\0';
			str++;
			continue;
		}

		if (!is_head) {
			str++;
			continue;
		}

		if (idx < max_argc) {
			argv[idx++] = str;
			is_head	    = false;
		}

		str++;
	}

	if (idx < max_argc)
		argv[idx] = NULL;

	*argc = idx;
}

static inline s32 inject_proc_type(const char *param_val,
				   struct sxe2_injection *injection)
{
	s32 ret					  = 0;

	static struct inject_type_proc s_inject_type[] = {
		{ "pause", INJECT_TYPE_PAUSE },
		{ "abort", INJECT_TYPE_ABORT },
		{ "reset", INJECT_TYPE_RESET },
		{ "callback", INJECT_TYPE_CALLBACK }
	};

	u32 size = ARRAY_SIZE(s_inject_type);
	u32 i	 = 0;

	for (; i < size; i++) {
		if (strncmp(param_val, s_inject_type[i].string,
			    strlen(param_val)) == 0) {
			injection->type = s_inject_type[i].value;
			goto end;
		}
	}

	ret = -EINVAL;
	DRV_RDMA_LOG_ERROR("Invalid type %s, when active inject %s, ret %d\n",
			   param_val, injection->inject_name.name, ret);

end:
	return ret;
}

static inline s32 inject_proc_user_data(const char *param_val,
					struct sxe2_injection *injection)
{
	s32 ret = 0;

	strscpy(injection->user_data, param_val,
		sizeof(injection->user_data) - 1);
	if (injection->user_data[0] == '\0') {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR(
			"Invalid userdata %s, when active inject %s, ret %d\n",
			param_val, injection->inject_name.name, ret);
	}
	return ret;
}

static inline s32 inject_proc_alive(const char *param_val,
				    struct sxe2_injection *injection)
{
	s32 val	    = 0;
	s32 ret	    = 0;
	int count   = 0;

	count = kstrtol(param_val, 0, (long *)&val);
	if (val < 0) {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR(
			"Invalid alive %s, when active inject %s, ret %d\n",
			param_val, injection->inject_name.name, ret);
		goto end;
	}
	injection->alive = val;

end:
	return ret;
}

static struct inject_cmd_param_proc s_inject_proc[] = {
	{ "-t", inject_proc_type },
	{ "-u", inject_proc_user_data },
	{ "-a", inject_proc_alive }
};

static struct inject_cmd_param_proc *inject_get_cmd_param_proc(const char *opt)
{
	struct inject_cmd_param_proc *ret = NULL;

	u32 size = ARRAY_SIZE(s_inject_proc);
	u32 i	 = 0;

	for (; i < size; i++) {
		if (!strncmp(opt, s_inject_proc[i].opt, strlen(opt))) {
			ret = &s_inject_proc[i];
			break;
		}
	}

	return ret;
}

static s32 inject_parse_cmd_param(struct sxe2_injection *injection, s32 argc,
				  char *argv[])
{
	struct inject_cmd_param_proc *param_proc = NULL;
	s32 ret				    = 0;
	s32 i				    = 0;

	for (; i < argc; i++) {
		param_proc = inject_get_cmd_param_proc(argv[i]);
		if (param_proc == NULL) {
			ret = -EINVAL;
			DRV_RDMA_LOG_ERROR(
				"get active cmd param proc fail, ret %d\n",
				ret);
			goto end;
		}

		i++;
		if (i >= argc) {
			ret = -ENOMEM;
			DRV_RDMA_LOG_ERROR(
				"active cmd param incomplete, ret %d\n", ret);
			goto end;
		}

		ret = (s32)param_proc->proc(argv[i], injection);
		if (ret != 0) {
			DRV_RDMA_LOG_ERROR(
				"active injection param fail, ret %d\n", ret);
			goto end;
		}
	}

	ret = 0;

end:
	return ret;
}

void inject_fill(struct sxe2_injection *src, struct sxe2_injection *dst)
{
	unsigned long flags = 0;

	memcpy(dst->user_data, src->user_data, sizeof(dst->user_data));

	dst->type = src->type == INJECT_TYPE_BUTT ? INJECT_TYPE_CALLBACK :
						    src->type;

	if (src->alive == 0)
		src->alive = 1;

	inject_lock(dst, &flags);
	dst->alive = src->alive;
	inject_unlock(dst, &flags);

}

void inject_active_intf(struct sxe2_rdma_pci_f *dev, const char *name,
			const char *cmd)
{
	s32 ret = 0;
	char cmd_tmp_buff[INJECT_CMD_LEN];
	s32 argc = 0;
	char *argv[INJECT_MAX_ARGC];
	struct sxe2_injection *injection = NULL;
	struct sxe2_injection tmp;

	if (dev == NULL || name == NULL) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"inject active param dev/name is null, ret %d\n", ret);
		goto finish;
	}

	injection = inject_find_inner(dev, name);
	if (injection == NULL) {
		ret = -EFAULT;
		DRV_RDMA_LOG_ERROR("Name=%s is not exist, ret %d\n", name, ret);
		goto finish;
	}

	if (injection->alive) {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR("injection %s is alived, ret %d\n", name,
				   ret);
		goto finish;
	}

	memset(&tmp, 0, sizeof(tmp));
	tmp.inject_name.name = injection->inject_name.name;
	tmp.type	     = INJECT_TYPE_BUTT;

	if (cmd == NULL || *cmd == '\0')
		goto finish;

	(void)snprintf(cmd_tmp_buff, INJECT_CMD_LEN, "%s", cmd);

	inject_split_string((char *)cmd_tmp_buff, &argc, argv, INJECT_MAX_ARGC);
	ret = (s32)inject_parse_cmd_param(&tmp, argc, argv);

finish:
	if (ret == 0) {
		inject_fill(&tmp, injection);
		DRV_RDMA_LOG_INFO(
			"inject name:%s user_data:%s, alive:%d type:%d mid:%d\n",
			injection->inject_name.name, injection->user_data,
			injection->alive, injection->type, injection->mid);
	} else {
		DRV_RDMA_LOG_ERROR("inject %s: active failed, ret :%d!\n", name,
				   ret);
	}

}
EXPORT_SYMBOL(inject_active_intf);

void inject_deactive_intf(struct sxe2_rdma_pci_f *dev, const char *name)
{
	struct sxe2_injection *injection;
	unsigned long flags = 0;

	if (dev == NULL || name == NULL) {
		DRV_RDMA_LOG_ERROR("inject active param dev/name is null\n");
		goto end;
	}

	injection = inject_find_inner(dev, name);
	if (injection != NULL) {
		inject_lock(injection, &flags);
		injection->alive = 0;
		inject_unlock(injection, &flags);
	}

end:
	return;
}
EXPORT_SYMBOL(inject_deactive_intf);

static s32 inject_read_and_dec_alive(struct sxe2_injection *injection)
{
	s32 val = 0;
	unsigned long flags = 0;

	inject_lock(injection, &flags);

	val = injection->alive;
	if (injection->alive != 0 && injection->alive != -1)
		injection->alive--;

	inject_unlock(injection, &flags);

	return val;
}

bool inject_execute_callback(struct sxe2_rdma_pci_f *dev, const char *name)
{
	bool ret      = false;
	s32 micro_sec = 0;
	int count = 0;

	struct sxe2_injection *injection = inject_find(dev, name);

	if (dev == NULL || injection == NULL ||
	    inject_read_and_dec_alive(injection) == 0) {
		ret = false;
		goto end;
	}

	switch (injection->type) {
	case INJECT_TYPE_CALLBACK:
		ret = true;
		goto end;

	case INJECT_TYPE_PAUSE:
		count = (s32)kstrtol(injection->user_data, 0, (long *)&micro_sec);
		if (micro_sec >= 0)
			udelay(micro_sec);
		ret = true;
		goto end;

	case INJECT_TYPE_ABORT:
		SXE2_INJECT_BUG();
		ret = false;
		goto end;

	case INJECT_TYPE_RESET:
		ret = true;
		goto end;

	default:
		break;
	}

end:
	return ret;
}
EXPORT_SYMBOL(inject_execute_callback);

s32 inject_count(struct sxe2_rdma_pci_f *dev)
{
	struct list_head *pos = NULL;
	s32 ret		      = 0;
	unsigned long flags	  = 0;

	if (dev == NULL) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("inject count param dev is null, ret %d\n",
				   ret);
		goto end;
	}

	spin_lock_irqsave(&dev->inject_mem.list_lock, flags);
	list_for_each(pos, &dev->inject_mem.g_inject_list) {
		ret++;
	}
	spin_unlock_irqrestore(&dev->inject_mem.list_lock, flags);

end:
	return ret;
}

void inject_clear_intf(struct sxe2_rdma_pci_f *dev)
{
	struct sxe2_injection *pos  = NULL;
	struct sxe2_injection *next = NULL;
	unsigned long flags		  = 0;

	spin_lock_irqsave(&dev->inject_mem.list_lock, flags);
	list_for_each_entry_safe(pos, next, &dev->inject_mem.g_inject_list,
				  list_node) {
		pos->alive = 0;
	}
	spin_unlock_irqrestore(&dev->inject_mem.list_lock, flags);
}
EXPORT_SYMBOL(inject_clear_intf);

s32 inject_uninit(struct sxe2_rdma_pci_f *dev)
{
	s32 ret = 0;
	struct sxe2_inject_mem_mgr *mm;

	if (dev == NULL) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			NULL, "inject unint param dev is null, ret %d\n", ret);
		goto end;
	}

	mm = &dev->inject_mem.inject_mem_mgr;
	inject_clear_intf(dev);

	vfree(mm->usable_array.array_addr);
	mm->usable_array.array_addr = NULL;
	vfree(mm->base_addr);
	mm->base_addr = NULL;
	mm->end_addr  = NULL;
	mm->cursor    = NULL;

end:
	return ret;
}

#endif

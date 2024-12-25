// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2024. Huawei Technologies Co., Ltd */

#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/fs.h>

#if IS_ENABLED(CONFIG_EROFS_FS) || IS_ENABLED(CONFIG_CACHEFILES_ONDEMAND)
static int param_set_bool_on_only_once(const char *s, const struct kernel_param *kp)
{
	int ret;
	bool value, *res = kp->arg;

	if (!s)
		s = "1";

	ret = strtobool(s, &value);
	if (ret)
		return ret;

	if (!value && *res)
		return -EBUSY;

	if (value && !*res)
		WRITE_ONCE(*res, true);

	return 0;
}
#endif

#if IS_ENABLED(CONFIG_EROFS_FS)
bool erofs_enabled;
EXPORT_SYMBOL(erofs_enabled);
module_param_call(erofs_enabled, param_set_bool_on_only_once, param_get_bool,
				  &erofs_enabled, 0644);
#endif

#if IS_ENABLED(CONFIG_CACHEFILES_ONDEMAND)
bool cachefiles_ondemand_enabled;
EXPORT_SYMBOL(cachefiles_ondemand_enabled);
module_param_call(cachefiles_ondemand_enabled, param_set_bool_on_only_once, param_get_bool,
				  &cachefiles_ondemand_enabled, 0644);
#endif

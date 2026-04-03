// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2025 Huawei Technologies Co., Ltd
 */
#include "policy.h"

#include "maio.h"
#include "log.h"
#include "securec.h"
#include <dlfcn.h>

typedef struct maio_operation* (*strategy_init)();

struct policy_mgr {
	void *handle;
	struct maio_operation *strategy;
};

struct policy_mgr g_policy;

static int default_init(void)
{
	return 0;
}

static void default_exit(void)
{
}

static int default_load(struct maio **io)
{
	return 0;
}

static int default_evict(struct maio **io)
{
	return 0;
}

struct maio_operation default_ops = {
	.max_io = 1,
	.init	= default_init,
	.exit	= default_exit,
	.load	= default_load,
	.evict	= default_evict,
};

static void set_default_strategy(void)
{
	g_policy.strategy = &default_ops;
}

int policy_max_io(void)
{
	return g_policy.strategy->max_io;
}

/* return the filled num of io */
int policy_load(struct maio **io)
{
	return g_policy.strategy->load(io);
}

int policy_evict(struct maio **io)
{
	return g_policy.strategy->evict(io);
}

int policy_register(const char *path)
{
	strategy_init sinit;

	if (!path || strlen(path) == 0)
		return -1;

	g_policy.handle = dlopen(path, RTLD_LAZY);
	if (!g_policy.handle) {
		log_error("dlopen failed:%s", dlerror());
		return -1;
	}

	sinit = dlsym(g_policy.handle, "register_strategy");
	if (!sinit) {
		log_error("dlsym failed:%s", dlerror());
		dlclose(g_policy.handle);
		g_policy.handle = NULL;
		return -1;
	}
	g_policy.strategy = sinit();
	if (g_policy.strategy->init())
		return -1;
	log_info("register strategy:%s done.", path);
	return 0;
}

void policy_unregister(void)
{
	if (g_policy.handle) {
		g_policy.strategy->exit();
		dlclose(g_policy.handle);
		g_policy.handle = NULL;
	}
	set_default_strategy();
}

int policy_init(void)
{
	g_policy.handle = NULL;
	set_default_strategy();
	return 0;
}

void policy_exit(void)
{
}

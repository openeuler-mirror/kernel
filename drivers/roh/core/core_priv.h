/* SPDX-License-Identifier: GPL-2.0+ */
// Copyright (c) 2022 Hisilicon Limited.

#ifndef __CORE_PRIV_H__
#define __CORE_PRIV_H__

struct roh_client {
	char *name;
	int (*add)(struct roh_device *device);
	void (*remove)(struct roh_device *device, void *client_data);
	refcount_t uses;
	u32 client_id;
	struct completion uses_zero;
};

int roh_register_client(struct roh_client *client);
void roh_unregister_client(struct roh_client *client);
void roh_set_client_data(struct roh_device *device,
			 struct roh_client *client, void *data);

#endif /* __CORE_PRIV_H__ */

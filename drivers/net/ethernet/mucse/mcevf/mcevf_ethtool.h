/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2020-2026 Mucse Corporation. */

#ifndef _MCEVF_ETHTOOL_H_
#define _MCEVF_ETHTOOL_H_

struct mcevf_stats {
	char stat_string[ETH_GSTRING_LEN];
	int sizeof_stat;
	int stat_offset;
};

#define MCEVF_STAT(_type, _name, _stat)                    \
	{                                                  \
		.stat_string = _name,                      \
		.sizeof_stat = sizeof_field(_type, _stat), \
		.stat_offset = offsetof(_type, _stat)      \
	}

#define MCEVF_NETDEV_STAT(_name, _stat) \
	MCEVF_STAT(struct mcevf_vsi, _name, _stat)

#define MCEVF_OFLD_STAT(_name, _stat) \
	MCEVF_STAT(struct mcevf_vsi, _name, _stat)

#define MCEVF_QUEUE_STAT(_name, _stat) \
	MCEVF_STAT(struct mcevf_ring_stats, _name, _stat)

#define MCEVF_MAX_INTR_TIME (256)
#define MCEVF_MAX_INTR_PKTS (256)

#endif /* _MCEVF_ETHTOOL_H_ */

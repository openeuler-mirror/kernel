/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPHW_PROFILE_H
#define SPHW_PROFILE_H

enum cpu_affinity_work_type {
	WORK_TYPE_AEQ,
	WORK_TYPE_MBOX,
	WORK_TYPE_MGMT_MSG,
	WORK_TYPE_COMM,
};

enum sphw_sw_features {
	SPHW_SW_F_CHANNEL_LOCK = BIT(0),
};

struct sphw_prof_ops {
	void		(*fault_recover)(void *data, u16 src, u16 level);
	int		(*get_work_cpu_affinity)(void *data, u32 work_type);
};

struct sphw_prof_attr {
	void			*priv_data;
	u64			hw_feature_cap;
	u64			sw_feature_cap;
	u64			dft_hw_feature;
	u64			dft_sw_feature;

	struct sphw_prof_ops	*ops;
};

typedef struct sphw_prof_attr *(*sphw_init_prof_attr)(void *hwdev);
typedef void (*sphw_deinit_prof_attr)(struct sphw_prof_attr *porf_attr);

#endif

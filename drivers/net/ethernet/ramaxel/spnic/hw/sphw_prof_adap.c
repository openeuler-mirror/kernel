// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/kernel.h>
#include <linux/semaphore.h>
#include <linux/workqueue.h>
#include <linux/dev_printk.h>

#include "sphw_common.h"
#include "sphw_hwdev.h"
#include "sphw_profile.h"
#include "sphw_prof_adap.h"

typedef bool (*sphw_is_match_prof)(struct sphw_hwdev *hwdev);

static bool is_match_prof_default_adapter(struct sphw_hwdev *hwdev)
{
	/* always match default profile adapter in standard scene */
	return true;
}

enum prof_adapter_type {
	PROF_ADAP_TYPE_PANGEA = 1,

	/* Add prof adapter type before default */
	PROF_ADAP_TYPE_DEFAULT,
};

/**
 * struct sphw_prof_adapter - custom scene's profile adapter
 * @type: adapter type
 * @match: Check whether the current function is used in the custom scene.
 *	Implemented in the current source file
 * @init: When @match return true, the initialization function called in probe.
 *	Implemented in the source file of the custom scene
 * @deinit: When @match return true, the deinitialization function called when
 *	remove. Implemented in the source file of the custom scene
 */
struct sphw_prof_adapter {
	enum prof_adapter_type	type;
	sphw_is_match_prof	match;
	sphw_init_prof_attr	init;
	sphw_deinit_prof_attr	deinit;
};

struct sphw_prof_adapter prof_adap_objs[] = {
	/* Add prof adapter before default profile */
	{
		.type = PROF_ADAP_TYPE_DEFAULT,
		.match = is_match_prof_default_adapter,
		.init = NULL,
		.deinit = NULL,
	},
};

void sphw_init_profile_adapter(struct sphw_hwdev *hwdev)
{
	struct sphw_prof_adapter *prof_obj = NULL;
	u16 num_adap = ARRAY_SIZE(prof_adap_objs);
	u16 i;

	for (i = 0; i < num_adap; i++) {
		prof_obj = &prof_adap_objs[i];
		if (!(prof_obj->match && prof_obj->match(hwdev)))
			continue;

		hwdev->prof_adap_type = prof_obj->type;
		hwdev->prof_attr = prof_obj->init ?
					prof_obj->init(hwdev) : NULL;
		sdk_info(hwdev->dev_hdl, "Find profile adapter, type: %d\n",
			 hwdev->prof_adap_type);

		break;
	}
}

void sphw_deinit_profile_adapter(struct sphw_hwdev *hwdev)
{
	struct sphw_prof_adapter *prof_obj = NULL;
	u16 num_adap = ARRAY_SIZE(prof_adap_objs);
	u16 i;

	for (i = 0; i < num_adap; i++) {
		prof_obj = &prof_adap_objs[i];
		if (hwdev->prof_adap_type != prof_obj->type)
			continue;

		if (prof_obj->deinit)
			prof_obj->deinit(hwdev->prof_attr);
		break;
	}
}

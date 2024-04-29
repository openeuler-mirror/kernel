// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "global.h"
#include <linux/kernel.h>

#define	QOS_DSCP_MAX	63
#define	QOS_PCP_MAX		7

// default value 255 for no global setting
int g_xsc_force_pcp = GLOBAL_UNSET_FORCE_VALUE;
int g_xsc_force_dscp = GLOBAL_UNSET_FORCE_VALUE;

static int is_valid_pcp(int pcp)
{
	if ((pcp >= 0 && pcp <= QOS_PCP_MAX) || pcp == GLOBAL_UNSET_FORCE_VALUE)
		return 0;
	return -1;
}

static int is_valid_dscp(int dscp)
{
	if ((dscp >= 0 && dscp <= QOS_DSCP_MAX) || dscp == GLOBAL_UNSET_FORCE_VALUE)
		return 0;
	return -1;
}

int get_global_force_pcp(void)
{
	return g_xsc_force_pcp;
}

int set_global_force_pcp(int force_pcp)
{
	if (is_valid_pcp(force_pcp) == 0) {
		g_xsc_force_pcp = force_pcp;
		return 0;
	} else {
		return -1;
	}
}

int get_global_force_dscp(void)
{
	return g_xsc_force_dscp;
}

int set_global_force_dscp(int force_dscp)
{
	if (is_valid_dscp(force_dscp) == 0) {
		g_xsc_force_dscp = force_dscp;
		return 0;
	} else {
		return -1;
	}
}

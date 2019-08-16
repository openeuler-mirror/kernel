/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _HNS_HW_V2_TEST_H
#define _HNS_HW_V2_TEST_H

void test_set_cqc_param(unsigned int *period, unsigned int *max_cnt);
void test_set_eq_param(int eq_type, unsigned int *eq_period,
		       unsigned int *eq_max_cnt, unsigned int *eq_arm_st);

#endif

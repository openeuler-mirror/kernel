// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/module.h>

#include "hns_roce_device.h"
#include "hnae3.h"
#include "hns_roce_hw_v2.h"
#include "hns_hw_v2_test.h"

unsigned int hr_cq_period = 0xa;
module_param(hr_cq_period, uint, 0644);
MODULE_PARM_DESC(hr_cq_period, "timeout of cqe to ceqe");

unsigned int hr_cq_max_cnt = 0x1;
module_param(hr_cq_max_cnt, uint, 0644);
MODULE_PARM_DESC(hr_cq_max_cnt, "max cnt of cqe to ceqe");

unsigned int hr_ceq_period = HNS_ROCE_V2_EQ_DEFAULT_INTERVAL;
module_param(hr_ceq_period, uint, 0644);
MODULE_PARM_DESC(hr_ceq_period, "timeout of ceqe to int");

unsigned int hr_aeq_period = HNS_ROCE_V2_EQ_DEFAULT_INTERVAL;
module_param(hr_aeq_period, uint, 0644);
MODULE_PARM_DESC(hr_aeq_period, "timeout of aeqe to int");

unsigned int hr_ceq_max_cnt = 0x1;
module_param(hr_ceq_max_cnt, uint, 0644);
MODULE_PARM_DESC(hr_ceq_max_cnt, "max cnt of ceqe to int");

unsigned int hr_aeq_max_cnt = 0x1;
module_param(hr_aeq_max_cnt, uint, 0644);
MODULE_PARM_DESC(hr_aeq_max_cnt, "max cnt of aeqe to int");

unsigned int hr_ceq_arm_st = HNS_ROCE_V2_EQ_ALWAYS_ARMED;
module_param(hr_ceq_arm_st, uint, 0644);
MODULE_PARM_DESC(hr_ceq_arm_st, "arm state of ceq");

unsigned int hr_aeq_arm_st = HNS_ROCE_V2_EQ_ALWAYS_ARMED;
module_param(hr_aeq_arm_st, uint, 0644);
MODULE_PARM_DESC(hr_aeq_arm_st, "arm state of aeq");

unsigned int func_num = 0x1;
module_param(func_num, uint, 0644);
MODULE_PARM_DESC(func_num, "function num contain pfs and vfs");

unsigned int dump_cqe_en = 0x1;
module_param(dump_cqe_en, uint, 0644);
MODULE_PARM_DESC(dump_cqe_en, "dump cqe while cqe status isn't success nor flush error");

unsigned int v2_resv_pds;
module_param(v2_resv_pds, uint, 0644);
MODULE_PARM_DESC(v2_resv_pds, "reserved pd num, default is 0");

unsigned int v2_resv_qps = 0x8;
module_param(v2_resv_qps, uint, 0644);
MODULE_PARM_DESC(v2_resv_qps, "reserved qp num, default is 8");

unsigned int v2_resv_mrws = 0x1;
module_param(v2_resv_mrws, uint, 0644);
MODULE_PARM_DESC(v2_resv_mrws, "reserved mr/mw num, default is 1");

unsigned int v2_resv_cqs;
module_param(v2_resv_cqs, uint, 0644);
MODULE_PARM_DESC(v2_resv_cqs, "reserved cq num, default is 0");

unsigned int v2_resv_srqs;
module_param(v2_resv_srqs, uint, 0644);
MODULE_PARM_DESC(v2_resv_srqs, "reserved srq num, default is 0");

void test_set_cqc_param(unsigned int *period, unsigned int *max_cnt)
{
	*period = hr_cq_period;
	*max_cnt = hr_cq_max_cnt;
}

void test_set_eq_param(int eq_type, unsigned int *eq_period,
		       unsigned int *eq_max_cnt, unsigned int *eq_arm_st)
{
	if (eq_type == HNS_ROCE_AEQ) {
		*eq_period = hr_aeq_period;
		*eq_max_cnt = hr_aeq_max_cnt;
		*eq_arm_st = hr_aeq_arm_st;
	} else {
		*eq_period = hr_ceq_period;
		*eq_max_cnt = hr_ceq_max_cnt;
		*eq_arm_st = hr_ceq_arm_st;
	}
}

unsigned int get_func_num(void)
{
	if (func_num > 4 || func_num == 0) {
		pr_info("func num config err. config value - %d\n", func_num);
		return 1;
	}

	return func_num;
}

unsigned int test_get_dump_cqe_en(void)
{
	return dump_cqe_en;
}


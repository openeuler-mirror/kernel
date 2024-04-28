// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024, The Linux Foundation. All rights reserved.
 */
#include <linux/arm-smccc.h>
#include <asm/kvm_tmi.h>

u64 tmi_version(void)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_VESION, &res);
	return res.a1;
}

u64 tmi_data_create(u64 data, u64 rd, u64 map_addr, u64 src, u64 level)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_DATA_CREATE, data, rd, map_addr, src, level, &res);
	return res.a1;
}

u64 tmi_data_destroy(u64 rd, u64 map_addr, u64 level)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_DATA_DESTROY, rd, map_addr, level, &res);
	return res.a1;
}

u64 tmi_cvm_activate(u64 rd)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_CVM_ACTIVATE, rd, &res);
	return res.a1;
}

u64 tmi_cvm_create(u64 rd, u64 params_ptr)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_CVM_CREATE, rd, params_ptr, &res);
	return res.a1;
}

u64 tmi_cvm_destroy(u64 rd)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_CVM_DESTROY, rd, &res);
	return res.a1;
}

u64 tmi_tec_create(u64 tec, u64 rd, u64 mpidr, u64 params_ptr)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_TEC_CREATE, tec, rd, mpidr, params_ptr, &res);
	return res.a1;
}

u64 tmi_tec_destroy(u64 tec)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_TEC_DESTROY, tec, &res);
	return res.a1;
}

u64 tmi_tec_enter(u64 tec, u64 run_ptr)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_TEC_ENTER, tec, run_ptr, &res);
	return res.a1;
}

u64 tmi_ttt_create(u64 ttt, u64 rd, u64 map_addr, u64 level)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_TTT_CREATE, ttt, rd, map_addr, level, &res);
	return res.a1;
}

u64 tmi_ttt_destroy(u64 ttt, u64 rd, u64 map_addr, u64 level)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_TTT_DESTROY, ttt, rd, map_addr, level, &res);
	return res.a1;
}

u64 tmi_ttt_map_unprotected(u64 rd, u64 map_addr, u64 level, u64 ttte)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_TTT_MAP_UNPROTECTED, rd, map_addr, level, ttte, &res);
	return res.a1;
}

u64 tmi_ttt_unmap_unprotected(u64 rd, u64 map_addr, u64 level, u64 ns)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_TTT_UNMAP_UNPROTECTED, rd, map_addr, level, ns, &res);
	return res.a1;
}

u64 tmi_ttt_unmap_protected(u64 rd, u64 map_addr, u64 level)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_TTT_UNMAP_PROTECTED, rd, map_addr, level, &res);
	return res.a1;
}

u64 tmi_psci_complete(u64 calling_tec, u64 target_tec)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_PSCI_COMPLETE, calling_tec, target_tec, &res);
	return res.a1;
}

u64 tmi_features(u64 index)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_FEATURES, index, &res);
	return res.a1;
}

u64 tmi_mem_alloc(u64 rd, u64 numa_id, enum tmi_tmm_mem_type tmm_mem_type,
	enum tmi_tmm_map_size tmm_map_size)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_MEM_ALLOC, rd, numa_id, tmm_mem_type, tmm_map_size, &res);
	return res.a1;
}

u64 tmi_mem_free(u64 pa, u64 numa_id, enum tmi_tmm_mem_type tmm_mem_type,
	enum tmi_tmm_map_size tmm_map_size)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_MEM_FREE, pa, numa_id, tmm_mem_type, tmm_map_size, &res);
	return res.a1;
}

u64 tmi_ttt_map_range(u64 rd, u64 map_addr, u64 size, u64 cur_node, u64 target_node)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_TTT_MAP_RANGE, rd, map_addr, size, cur_node, target_node, &res);
	return res.a1;
}

u64 tmi_ttt_unmap_range(u64 rd, u64 map_addr, u64 size, u64 node_id)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_TTT_UNMAP_RANGE, rd, map_addr, size, node_id, &res);
	return res.a1;
}

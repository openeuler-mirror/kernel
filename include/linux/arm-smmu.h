#ifndef _ARM_SMMU_H_
#define _ARM_SMMU_H_

enum arm_smmu_device_config_type {
	ARM_SMMU_MPAM = 0,
};

struct arm_smmu_mpam {
#define ARM_SMMU_DEV_SET_MPAM	(1 << 0)
	int flags;
	int pasid;
	int partid;
	int pmg;
	int s1mpam;
};

#endif

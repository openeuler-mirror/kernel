#ifndef __LINUX_ASCEND_SMMU_H
#define __LINUX_ASCEND_SMMU_H

#include <linux/device.h>

extern int arm_smmu_set_dev_mpam(struct device *dev, int ssid, int partid,
		int pmg, int s1mpam);

#endif /* __LINUX_ASCEND_SMMU_H */

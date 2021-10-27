/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _HISI_MMC_PMIC_
#define _HISI_MMC_PMIC_

#include "linux/types.h"

#if defined(CONFIG_HISI_SPMI)
u32 hisi_pmic_read_reg(const s32 reg);
s32 hisi_pmic_write_reg(const s32 reg, const u32 val);
s32 pmu_ldo2_enable(void);
s32 pmu_ldo2_disable(void);
s32 pmu_ldo2_set_voltage(const u32 volt_value);
s32 pmu_ldo16_enable(void);
s32 pmu_ldo16_disable(void);
s32 pmu_ldo16_set_voltage(const u32 volt_value);
s32 pmu_ldo9_enable(void);
s32 pmu_ldo9_disable(void);
s32 pmu_ldo9_set_voltage(const u32 volt_value);
s32 hisi_adc_get_value(const u32 channel);
s32 ntc_read_temp(const s32 channel, s32 *temp);
u32 hisi_second_pmic_read_reg(const s32 sid, const s32 reg);
s32 get_second_pmu_buck_volt(u32 device_id, u32 channel, u32 *volt_mv);
s32 get_main_pmu_buck_volt(u32 channel, u32 *volt_mv);
s32 get_main_pmu_ldo_volt(u32 channel, u32 *volt_mv);
s32 get_main_pmu_die_id(u8 *die_id, u8 len);
s32 get_second_pmu_die_id(u32 device_id, u8 *die_id, u8 len);
#else
static inline s32 hisi_pmic_read_reg(const s32 reg) { return 0; }
static inline s32 hisi_pmic_write_reg(const s32 reg, const u32 val)
{
	return 0;
}
static inline s32 pmu_ldo2_enable(void) { return 0; }
static inline s32 pmu_ldo2_disable(void) { return 0; }
static inline s32 pmu_ldo2_set_voltage(const u32 volt_value) { return 0; }
static inline s32 pmu_ldo16_enable(void) { return 0; }
static inline s32 pmu_ldo16_disable(void) { return 0; }
static inline s32 pmu_ldo16_set_voltage(const u32 volt_value) { return 0; }
static inline s32 pmu_ldo9_enable(void) { return 0; }
static inline s32 pmu_ldo9_disable(void) { return 0; }
static inline s32 pmu_ldo9_set_voltage(const u32 volt_value) { return 0; }
static inline s32 hisi_adc_get_value(const u32 channel) { return 0; }
static inline s32 ntc_read_temp(const s32 channel, s32 *temp) { return 0; }
static inline u32 hisi_second_pmic_read_reg(const s32 sid, const s32 reg)
{
	return 0;
};
static inline s32 get_second_pmu_buck_volt(u32 device_id,
					u32 channel, u32 *volt_mv)
{
	return 0;
};
static inline s32 get_main_pmu_buck_volt(u32 channel, u32 *volt_mv)
{
	return 0;
};
static inline s32 get_main_pmu_ldo_volt(u32 channel, u32 *volt_mv)
{
	return 0;
};
static inline s32 get_main_pmu_die_id(u8 *die_id, u8 len)
{
	return 0;
};
static inline s32 get_second_pmu_die_id(u32 device_id, u8 *die_id, u8 len)
{
	return 0;
};
#endif

#endif /* _HISI_MMC_PMIC_ */

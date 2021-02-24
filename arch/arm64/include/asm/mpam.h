/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_MPAM_H
#define _ASM_ARM64_MPAM_H

#ifdef CONFIG_MPAM
extern int mpam_rmid_to_partid_pmg(int rmid, int *partid, int *pmg);
#endif

#endif /* _ASM_ARM64_MPAM_H */

/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/fs.h>

#define DEVCG_ACC_MKNOD 1
#define DEVCG_ACC_READ  2
#define DEVCG_ACC_WRITE 4
#define DEVCG_ACC_MASK (DEVCG_ACC_MKNOD | DEVCG_ACC_READ | DEVCG_ACC_WRITE)

#define DEVCG_DEV_BLOCK 1
#define DEVCG_DEV_CHAR  2
#define DEVCG_DEV_ALL   4  /* this represents all devices */

#ifdef CONFIG_CGROUP_DMEM
#include <linux/cgroup-defs.h>
#endif

#if defined(CONFIG_CGROUP_DEVICE) || defined(CONFIG_CGROUP_BPF)
int devcgroup_check_permission(short type, u32 major, u32 minor,
			       short access);
static inline int devcgroup_inode_permission(struct inode *inode, int mask)
{
	short type, access = 0;

	if (likely(!inode->i_rdev))
		return 0;

	if (S_ISBLK(inode->i_mode))
		type = DEVCG_DEV_BLOCK;
	else if (S_ISCHR(inode->i_mode))
		type = DEVCG_DEV_CHAR;
	else
		return 0;

	if (mask & MAY_WRITE)
		access |= DEVCG_ACC_WRITE;
	if (mask & MAY_READ)
		access |= DEVCG_ACC_READ;

	return devcgroup_check_permission(type, imajor(inode), iminor(inode),
					  access);
}

static inline int devcgroup_inode_mknod(int mode, dev_t dev)
{
	short type;

	if (!S_ISBLK(mode) && !S_ISCHR(mode))
		return 0;

	if (S_ISCHR(mode) && dev == WHITEOUT_DEV)
		return 0;

	if (S_ISBLK(mode))
		type = DEVCG_DEV_BLOCK;
	else
		type = DEVCG_DEV_CHAR;

	return devcgroup_check_permission(type, MAJOR(dev), MINOR(dev),
					  DEVCG_ACC_MKNOD);
}

#else
static inline int devcgroup_check_permission(short type, u32 major, u32 minor,
			       short access)
{ return 0; }
static inline int devcgroup_inode_permission(struct inode *inode, int mask)
{ return 0; }
static inline int devcgroup_inode_mknod(int mode, dev_t dev)
{ return 0; }
#endif

/*
 * When CONFIG_CGROUP_DMEM is enabled, cpuacct_cgrp_subsys and dmem_cgrp_subsys
 * share the same set of cgroup_subsys hook functions. Consequently, the hooks for
 * cpuacct_cgrp_subsys must be exposed externally to allow linkage with the dmem
 * cgroup_subsys.
 */
#ifdef CONFIG_CGROUP_DMEM
#define devices_cgrp_id dmem_cgrp_id

int devcgroup_online(struct cgroup_subsys_state *css);
void devcgroup_offline(struct cgroup_subsys_state *css);
struct cgroup_subsys_state *
devcgroup_css_alloc(struct cgroup_subsys_state *parent_css);
void devcgroup_css_free(struct cgroup_subsys_state *css);
extern struct cftype dev_cgroup_files[];
#endif

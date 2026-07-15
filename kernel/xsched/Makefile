# SPDX-License-Identifier: GPL-2.0
obj-y += vstream.o

ifdef CONFIG_XCU_SCHEDULER
obj-y += core.o
obj-$(CONFIG_XCU_SCHED_RT) += rt.o
obj-$(CONFIG_XCU_SCHED_CFS) += cfs.o cfs_quota.o
obj-$(CONFIG_CGROUP_XCU) += cgroup.o
obj-$(CONFIG_CGROUP_DMEM) += dmem.o
endif

ifneq ($(CONFIG_INFINIBAND_NBL),)
obj-$(CONFIG_INFINIBAND_NBL) += nbl_rdma.o
else
# out-of-tree build against a kernel that has no INFINIBAND_NBL symbol
obj-m += nbl_rdma.o
endif

nbl_rdma-objs := main.o     \
		 nbl_v1/nbl_rdma/main.o \
		 nbl_v1/nbl_rdma/hw.o	    \
		 nbl_v1/nbl_rdma/alloc.o    \
		 nbl_v1/nbl_rdma/qp.o       \
		 nbl_v1/nbl_rdma/cq.o       \
		 nbl_v1/nbl_rdma/ceq.o	    \
		 nbl_v1/nbl_rdma/aeq.o      \
		 nbl_v1/nbl_rdma/mr.o       \
		 nbl_v1/nbl_rdma/cqp.o      \
		 nbl_v1/nbl_rdma/wr.o       \
		 nbl_v1/nbl_rdma/device.o   \
		 nbl_v1/nbl_rdma/mem.o      \
		 nbl_v1/nbl_rdma/pd.o       \
		 nbl_v1/nbl_rdma/pble.o     \
		 nbl_v1/nbl_rdma/ah.o       \
		 nbl_v1/nbl_rdma/gid.o      \
		 nbl_v1/nbl_rdma/ctrl.o      \
		 nbl_v1/nbl_rdma/hmc.o	    \
		 nbl_v1/nbl_rdma/counters.o	\
		 nbl_v1/nbl_rdma/debugfs.o	\
		 nbl_v1/nbl_rdma/uds_client.o	\
		 nbl_v1/nbl_rdma/grc.o	\
		 nbl_v1/nbl_rdma/nbl_cong_cfg.o \
		 nbl_v1/nbl_rdma/debugfun.o \
		 nbl_v1/nbl_rdma/tlp.o \
		 nbl_v1/nbl_rdma/mailbox.o \
		 nbl_v1/nbl_rdma/dump_fields.o\
		 nbl_v1/nbl_rdma/lag.o\
		 nbl_v1/nbl_rdma/nbl_qos_cfg.o \
		 nbl_v1/nbl_rdma/sysfs.o \
		 nbl_v1/nbl_rdma/umr.o \
		 nbl_v1/nbl_grc/grc_main.o   \
		 nbl_v1/nbl_grc/grc_mailbox.o \
		 nbl_v1/nbl_grc/grc_hw_rdma.o \
		 nbl_v1/nbl_grc/grc_cqp.o \
		 nbl_v1/nbl_grc/grc_gid.o \
		 nbl_v1/nbl_grc/grc_counters.o \
		 nbl_v2/nbl_rdma/main.o \
		 nbl_v2/nbl_rdma/probe.o \
		 nbl_v2/nbl_rdma/reset.o \
		 nbl_v2/nbl_rdma/resource.o \
		 nbl_v2/nbl_rdma/product.o \
		 nbl_v2/nbl_rdma/rdma_dump_hw.o \
		 nbl_v2/nbl_rdma/hw_common.o \
		 nbl_v2/nbl_rdma/hw_access.o \
		 nbl_v2/nbl_rdma/hw.o	    \
		 nbl_v2/nbl_rdma/fpga_ver.o \
		 nbl_v2/nbl_rdma/alloc.o    \
		 nbl_v2/nbl_rdma/qp.o       \
		 nbl_v2/nbl_rdma/cq.o       \
		 nbl_v2/nbl_rdma/ceq.o	    \
		 nbl_v2/nbl_rdma/aeq.o      \
		 nbl_v2/nbl_rdma/mr.o       \
		 nbl_v2/nbl_rdma/cqp.o      \
		 nbl_v2/nbl_rdma/wr.o       \
		 nbl_v2/nbl_rdma/device.o   \
		 nbl_v2/nbl_rdma/mem.o      \
		 nbl_v2/nbl_rdma/pd.o       \
		 nbl_v2/nbl_rdma/pble.o     \
		 nbl_v2/nbl_rdma/ah.o       \
		 nbl_v2/nbl_rdma/gid.o      \
		 nbl_v2/nbl_rdma/hmc.o	    \
		 nbl_v2/nbl_rdma/counters.o	\
		 nbl_v2/nbl_rdma/debugfs.o	\
		 nbl_v2/nbl_rdma/uds_client.o	\
		 nbl_v2/nbl_rdma/grc.o	\
		 nbl_v2/nbl_rdma/nbl_cong_cfg.o \
		 nbl_v2/nbl_rdma/debugfun.o \
		 nbl_v2/nbl_rdma/tlp.o \
		 nbl_v2/nbl_rdma/mailbox.o \
		 nbl_v2/nbl_rdma/dump_fields.o \
		 nbl_v2/nbl_rdma/srq.o \
		 nbl_v2/nbl_rdma/nbl_qos_cfg.o \
		 nbl_v2/nbl_rdma/nbl_pt_cfg.o \
		 nbl_v2/nbl_rdma/cache_hit.o \
		 nbl_v2/nbl_rdma/lag.o \
		 nbl_v2/nbl_rdma/umr.o \
		 nbl_v2/nbl_rdma/sysfs.o \
		 nbl_v2/nbl_rdma/devx.o \
		 nbl_v2/nbl_grc/grc_main.o   \
		 nbl_v2/nbl_grc/grc_mailbox.o \
		 nbl_v2/nbl_grc/grc_hw_rdma.o \
		 nbl_v2/nbl_grc/grc_cqp.o \
		 nbl_v2/nbl_grc/grc_gid.o \
		 nbl_v2/nbl_grc/grc_counters.o \
		 nbl_v2/nbl_grc/grc_flr.o

# in-tree builds resolve $(src) against the source tree, external (M=)
# builds pass an absolute path; keep both so O= and M= builds work
ccflags-y += -I$(src)
ccflags-y += -I$(srctree)/$(src)
ccflags-y += -I$(src)/nbl_include/
ccflags-y += -I$(srctree)/$(src)/nbl_include/
ccflags-y += -I$(srctree)/include/linux/nbl/
ccflags-y += -DNBL_RDMA_COMPILE

NBL_CORE_DIR := $(abspath $(src)/../../../net/ethernet/nebula-matrix/nbl)
KBUILD_EXTRA_SYMBOLS += $(NBL_CORE_DIR)/Module.symvers

ifndef KERNEL_RELEASE
        KERNEL_RELEASE = $(shell uname -r)
endif

ifndef KERNEL_PATH
        KERNEL_PATH = /lib/modules/$(KERNEL_RELEASE)/build
endif

all:
	make -C $(KERNEL_PATH) M=$(shell pwd) modules -j
clean:
	make -C $(KERNEL_PATH) M=$(shell pwd) clean


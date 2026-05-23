# NIC Makefile
EXPORT_SYMBOL := true

EXTRA_CFLAGS += -DSECUREC_EXPORT_KERNEL_SYMBOL=0

TRUNK_DIR = $(srctree)/drivers/net/ethernet/huawei/hinic5
HWSDK_SRC_PATH = $(TRUNK_DIR)/src/dpu_platform_library/host/sdk/knldk
SDK_DIR := ../../../sdk/knldk/lld

# HWSDK INNER
EXTRA_CFLAGS += -I$(HWSDK_SRC_PATH)/hinic5_cqm
EXTRA_CFLAGS += -I$(HWSDK_SRC_PATH)/crm
EXTRA_CFLAGS += -I$(HWSDK_SRC_PATH)/lld
EXTRA_CFLAGS += -I$(HWSDK_SRC_PATH)/hwif
EXTRA_CFLAGS += -I$(HWSDK_SRC_PATH)/mt
EXTRA_CFLAGS += -I$(HWSDK_SRC_PATH)/include

# HWSDK HEADER
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_platform_library/include
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_platform_library/include/drv_tool_msg
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_platform_library/include/drv_fw_msg/mpu
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_platform_library/host/include/sdk/knldk
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_platform_library/host/include/cfm/fast_msg
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_develop_interface
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_develop_interface/drv_sdk_intf/hisdk
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_develop_interface/drv_sdk_intf/ossl

# DBGTOOL
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_develop_interface/fw_msg_intf/public
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_develop_interface/fw_msg_intf/mag
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_develop_interface/fw_msg_intf/mpu
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_develop_interface/fw_msg_intf/hinic5_cqm
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_develop_interface/fw_msg_intf/bond
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_develop_interface/fw_msg_intf/cfm
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_develop_interface/fw_msg_intf/cfg_mgmt
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/tools/micro_log

#SDK
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_develop_interface
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_develop_interface/drv_srvc_intf
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_develop_interface/drv_sdk_intf/ossl
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_develop_interface/fw_msg_intf/public
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_develop_interface/fw_msg_intf/cfg_mgmt
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_develop_interface/fw_msg_intf/mpu
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_platform_library/host/include/sdk/knldk
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_develop_interface/drv_sdk_intf/hisdk
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_platform_library/host/sdk/knldk/lld

#NIC
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_platform_library/include/drv_tool_msg
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_platform_library/host/service/nic/linux/1588
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_platform_library/host/service/nic/linux/ctrl
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_platform_library/host/service/nic/linux/ethtool
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_platform_library/host/service/nic/linux/ioctl
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_platform_library/host/service/nic/linux/netdev
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_platform_library/host/service/nic/linux/nicio
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_platform_library/host/service/nic/include
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_platform_library/host/service/include
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/common/nic
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_platform_library/host/service/nic/comm
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_develop_interface/fw_msg_intf/nic
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_develop_interface/fw_msg_intf/bond
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_develop_interface/fw_msg_intf/mag
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_develop_interface/fw_msg_intf/cfm
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_develop_interface/drv_srvc_intf/nic
#BOND
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_platform_library/include/drv_fw_msg/cfm
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_platform_library/host/include/cfm/bond
#MPU
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_platform_library/include/drv_fw_msg/mpu

#MACsec
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_develop_interface/fw_msg_intf/macsec
EXTRA_CFLAGS += -I$(TRUNK_DIR)/src/dpu_platform_library/host/service/nic/linux/macsec

ifeq ($(CONFIG_SP_DEVICE), y)
EXTRA_CFLAGS += -DCONFIG_SP_VID_DID
endif

EXTRA_CFLAGS += -Werror -Wno-error=missing-prototypes -Wno-missing-braces

V ?= 0

ifeq ($(RELEASE_TYPE), LLT)
	ccflags-y += -D_LLT_TEST_
else
	ccflags-y += -DHW_CONVERT_ENDIAN
endif

ccflags-y += -D__LINUX__

hisdk5-objs := \
		$(SDK_DIR)/../hinic5_vram/hinic5_vram_common.o \
		$(SDK_DIR)/../hinic5_vram/hinic5_hinic5_vram.o \
		$(SDK_DIR)/../../../cfm/fast_msg/hinic5_fast_msg_init.o \
		$(SDK_DIR)/../../../cfm/fast_msg/hinic5_fast_msg.o \
		$(SDK_DIR)/../crm/hinic5_hwdev.o \
		$(SDK_DIR)/../crm/hinic5_hw_cfg.o \
		$(SDK_DIR)/../crm/hinic5_hw_comm.o \
		$(SDK_DIR)/../crm/hinic5_prof_adap.o \
		$(SDK_DIR)/hinic5_sriov.o \
		$(SDK_DIR)/hinic5_lld.o \
		$(SDK_DIR)/hinic5_bus.o \
		$(SDK_DIR)/hinic5_pcie.o \
		$(SDK_DIR)/hinic5_sysfs.o \
		$(SDK_DIR)/hinic5_dev_mgmt.o \
		$(SDK_DIR)/../hwif/hinic5_common.o \
		$(SDK_DIR)/../hwif/hinic5_hwif.o \
		$(SDK_DIR)/../hwif/hinic5_wq.o \
		$(SDK_DIR)/../hwif/hinic5_cmdq.o \
		$(SDK_DIR)/../hwif/hinic5_enhance_cmdq.o \
		$(SDK_DIR)/../hwif/hinic5_eqs.o \
		$(SDK_DIR)/../hwif/hinic5_mbox.o \
		$(SDK_DIR)/../hwif/hinic5_mgmt.o \
		$(SDK_DIR)/../hwif/hinic5_api_cmd.o \
		$(SDK_DIR)/../hwif/hinic5_hw_api.o \
		$(SDK_DIR)/../hwif/hinic5_sml_lt.o \
		$(SDK_DIR)/../../../../../../src/tools/micro_log/micro_log_comm.o \
		$(SDK_DIR)/../../../../../../src/tools/micro_log/micro_log_procfs_cmd.o \
		$(SDK_DIR)/../../../../../../src/tools/micro_log/micro_log_index.o \
		$(SDK_DIR)/../../../../../../src/tools/micro_log/hinic5_micro_log.o \
		$(SDK_DIR)/../mt/hinic5_fw_update.o \
		$(SDK_DIR)/../mt/hinic5_hw_mt.o \
		$(SDK_DIR)/../mt/hinic5_nictool.o \
		$(SDK_DIR)/../mt/hinic5_non_ptp.o \
		$(SDK_DIR)/../mt/hinic5_devlink.o \
		$(SDK_DIR)/../../ossl/linux/kernel/ossl_knl_linux.o \
		$(SDK_DIR)/../hinic5_cqm/hinic5_cqm_bat_cla.o \
		$(SDK_DIR)/../hinic5_cqm/hinic5_cqm_bitmap_table.o \
		$(SDK_DIR)/../hinic5_cqm/hinic5_cqm_object_intern.o \
		$(SDK_DIR)/../hinic5_cqm/hinic5_cqm_bloomfilter.o \
		$(SDK_DIR)/../hinic5_cqm/hinic5_cqm_cmd.o \
		$(SDK_DIR)/../hinic5_cqm/hinic5_cqm_db.o \
		$(SDK_DIR)/../hinic5_cqm/hinic5_cqm_fast_msg.o \
		$(SDK_DIR)/../hinic5_cqm/hinic5_cqm_object.o \
		$(SDK_DIR)/../hinic5_cqm/hinic5_cqm_main.o \
		$(SDK_DIR)/../hinic5_cqm/hinic5_cqm_cmdq_adapt.o \
		$(SDK_DIR)/../hinic5_cqm/hinic5_cqm_182x_cmdq_adapt/hinic5_cqm_182x_cmdq_ops.o \
		$(SDK_DIR)/../hinic5_cqm/hinic5_cqm_187x_cmdq_adapt/hinic5_cqm_187x_cmdq_ops.o \

hinic5-objs := \
		./1588/hinic5_ptp.o \
		./ctrl/hinic5_main.o \
		./ctrl/hinic5_irq.o \
		./ethtool/hinic5_rss.o \
		./ethtool/hinic5_ntuple.o \
		./ethtool/hinic5_ethtool.o \
		./ethtool/hinic5_ethtool_coalesce.o \
		./ethtool/hinic5_ethtool_lb_test.o \
		./ethtool/hinic5_ethtool_priv_flags.o \
		./ethtool/hinic5_ethtool_port_stats.o \
		./ethtool/hinic5_ethtool_link_stats.o \
		./ethtool/hinic5_tc.o \
		./ioctl/hinic5_dcb.o \
		./ioctl/hinic5_dbg.o \
		./netdev/hinic5_netdev_ops.o \
		./netdev/hinic5_filter.o \
		./nicio/hinic5_tx.o \
		./nicio/hinic5_rx.o \
		./nicio/hinic5_xdp.o \
		./macsec/hinic5_macsec_dfx.o \
		./macsec/hinic5_macsec_main.o \
		./macsec/hinic5_macsec_mgmt.o \
		./macsec/hinic5_macsec_nictool.o \
		./macsec/hinic5_macsec_protocol.o \
		./macsec/hinic5_macsec_service.o \
		../comm/hinic5_nic_cfg.o \
		../comm/hinic5_mag_cfg.o \
		../comm/hinic5_nic_cfg_vf.o \
		../comm/hinic5_rss_cfg.o \
		../comm/hinic5_nic_event.o \
		../comm/hinic5_nic_io.o \
		../comm/hinic5_nic_dbg.o \
		../comm/hinic5_cmdq_adapt.o \
		../comm/182x_cmdq_adapt/182x_cmdq_ops.o \
		../comm/187x_cmdq_adapt/187x_cmdq_ops.o \
		../../../cfm/bond/hinic5_bond_event.o \
		../../../cfm/bond/hinic5_bond.o \

# sdk_attack support
ifneq ($(CONFIG_HINIC5_SDK_DEBUG),)
hisdk5-objs += $(SDK_DIR)/../mt/hinic5_sdk_attack.o
endif

# UB release support
ifeq ($(CONFIG_UB), y)
hisdk5-objs += $(SDK_DIR)/hinic5_ubus.o $(SDK_DIR)/hinic5_ubus_sriov.o
EXTRA_CFLAGS += -D__UBUS_DRIVER__ -DUB_SUPPORT_ENTITY -DUB_SUPPORT_B177
endif

# UB devel support
ifeq ($(CONFIG_UBUS_DEVICE), y)
KBUILD_EXTRA_SYMBOLS += $(UBUS_UBC_BUILD_DIR)/Module.symvers
KBUILD_EXTRA_SYMBOLS += $(UMMU_CORE_BUILD_DIR)/Module.symvers
EXTRA_CFLAGS += -D__UBUS_DRIVER__
hisdk5-objs += $(SDK_DIR)/hinic5_ubus.o
hisdk5-objs += $(SDK_DIR)/hinic5_ubus_sriov.o
ifeq ($(UB_BUILD_B173), y)
EXTRA_CFLAGS += -DUB_SUPPORT_ENTITY
endif
ifeq ($(UB_BUILD_B177), y)
EXTRA_CFLAGS += -DUB_SUPPORT_B177
endif
endif

# Driver Extension
ifneq ($(DPU_HISDK5_DRV_EXTEND_MK),)
$(info Using hisdk5 extension $(DPU_HISDK5_DRV_EXTEND_MK))
export DPU_DRV_MK_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
include $(DPU_HISDK5_DRV_EXTEND_MK)
hisdk5-objs += $(DPU_DRV_HISDK5_EXTEND_OBJS)
endif
ifneq ($(DPU_HINIC5_DRV_EXTEND_MK),)
$(info Using hinic5  extension $(DPU_HINIC5_DRV_EXTEND_MK))
# Dirctory of NIC makefile
export DPU_DRV_MK_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
include $(DPU_HINIC5_DRV_EXTEND_MK)
hinic5-objs += $(DPU_DRV_HINIC5_EXTEND_OBJS)
endif

hinic5-objs += $(hisdk5-objs)
obj-$(CONFIG_HINIC5) += hinic5.o

all:build_info default

build_info:
	mkdir -p build
	@echo "CURDIR=$(CURDIR)" > build/build_src.txt
	@for obj in $(hinic5-objs); do \
		echo $$(realpath $$obj) >> build/build_src.txt; \
	done

KERNEL_VER := $(shell uname -r 2>/dev/null)
KERNEL_DIR := /lib/modules/$(KERNEL_VER)/build

default:
	$(MAKE) -C $(KERNEL_DIR) M=$(shell pwd) -W modules

clean:
	rm -rf *.o *.ko *.order .*.cmd *.mod.* .H* .tm* .tmp_versions Module.symvers *.ko.unsigned null
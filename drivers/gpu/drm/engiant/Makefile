# SPDX-License-Identifier: GPL-2.0
ccflags-y := -I $(src)
ifeq ($(CONFIG_ENGIANT_VS_CHIP_9x00),y)
ccflags-y += -I $(src)/9x00
else ifeq ($(CONFIG_ENGIANT_VS_CHIP_8x00), y)
ccflags-y += -I $(src)/8x00
else
ifeq ($(KBUILD_EXTMOD),)
ccflags-y += -I$(srctree)/drivers/gpu/drm/engiant/9000nano
else
ccflags-y += -I $(src)/9000nano
endif
endif

ifeq ($(CONFIG_DRM_EGT_DP),y)
ifeq ($(KBUILD_EXTMOD),)
ccflags-y += -I$(srctree)/drivers/gpu/drm/engiant/connector
else
ccflags-y += -I $(src)/connector
endif
endif

ifeq ($(CONFIG_DRM_ENGIANT_VS),y)
egt_drm-objs := vs_crtc.o \
		vs_drv.o \
		vs_fb.o \
		vs_gem.o \
		vs_plane.o \
		vs_dc_lut.o \
		vs_dc_property.o \
		vs_dc_drm_property.o \
		vs_simple_enc.o

# link to the 9000nano specify info
egt_drm-objs += 9000nano/info/vs_dc_info_9000nano_0x20000003.o
egt_drm-objs += 9000nano/vs_dc_hw.o
egt_drm-objs += 9000nano/vs_dc.o
egt_drm-objs += 9000nano/preprocess/vs_dc_plane_blender.o
egt_drm-objs += 9000nano/preprocess/vs_dc_preprocess.o
egt_drm-objs += 9000nano/postprocess/vs_dc_postprocess.o
egt_drm-$(CONFIG_ENGIANT_VS_QSPI) += 9000nano/vs_dc_qspi.o
# 9000nano decompress module
egt_drm-$(CONFIG_ENGIANT_VS_DEC) += 9000nano/vs_dc_dec.o

egt_drm-$(CONFIG_ENGIANT_VS_WRITEBACK) += vs_writeback.o
egt_drm-$(CONFIG_ENGIANT_VS_DEBUG) += vs_debug.o
egt_drm-$(CONFIG_ENGIANT_VS_MMU) += vs_dc_mmu.o
egt_drm-$(CONFIG_ENGIANT_VS_VIRTUAL_DISPLAY) += vs_virtual.o
endif

ifeq ($(CONFIG_DRM_EGT_DP),y)
# include $(src)/connector/Makefile
egt_drm-objs += connector/egt_dp.o
egt_drm-objs += connector/egt_dp_init.o
egt_drm-objs += connector/egt_dp_training.o
egt_drm-objs += connector/egt_dp_phy.o
endif

obj-$(CONFIG_DRM_ENGIANT) += egt_drm.o
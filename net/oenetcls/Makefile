# SPDX-License-Identifier: GPL-2.0-only

obj-$(CONFIG_OENETCLS) = oenetcls.o
oenetcls-y                      := oenetcls_main.o oenetcls_ntuple.o oenetcls_flow.o oenetcls_l0.o
ifeq ($(CONFIG_ARM64_SVE),y)
oenetcls-y                      += memcpy-sve.o
endif


# SPDX-License-Identifier: GPL-2.0

obj-$(CONFIG_REMOTE_PAGER) += remote_pager.o

remote_pager-$(CONFIG_REMOTE_PAGER) :=	main.o \
					wait_station.o \
					msg_handler_comm.o \
					msg_chan/msg_layer/msg_layer.o \
					svm_proc_mng.o

remote_pager-$(CONFIG_REMOTE_PAGER_MASTER) += msg_handler_origin.o

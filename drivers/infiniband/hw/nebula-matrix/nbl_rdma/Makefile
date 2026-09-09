obj-$(CONFIG_INFINIBAND_NBL) += nbl_rdma.o

nbl_rdma-objs := main.o     \
		 hw.o	    \
		 alloc.o    \
		 qp.o       \
		 cq.o       \
		 ceq.o	    \
		 aeq.o      \
		 mr.o       \
		 cqp.o      \
		 wr.o       \
		 device.o   \
		 mem.o      \
		 pd.o       \
		 pble.o     \
		 ah.o       \
		 gid.o      \
		 ctrl.o      \
		 hmc.o	    \
		 nbl_adapt.o \
		 counters.o	\
		 debugfs.o	\
		 uds_client.o	\
		 grc.o	\
		 nbl_cong_cfg.o \
		 debugfun.o \
		 tlp.o \
		 mailbox.o \
		 dump_fields.o\
		 lag.o\
		 nbl_qos_cfg.o \
		 sysfs.o \
		 umr.o \
		 ../nbl_grc/grc_main.o   \
		 ../nbl_grc/grc_mailbox.o \
		 ../nbl_grc/grc_hw_rdma.o \
		 ../nbl_grc/grc_cqp.o \
		 ../nbl_grc/grc_gid.o \
		 ../nbl_grc/grc_counters.o

ccflags-y:= -g
ccflags-y += -I$(src)/../nbl_include/

ccflags-y += -DSNIC

# SPDX-License-Identifier: GPL-2.0
CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Werror -g -ggdb -fno-omit-frame-pointer

# linux/nds_p2p.h lives in tools/include/uapi
UAPI_DIR ?= $(abspath ../../../include/uapi)
CPPFLAGS += -I. -I$(UAPI_DIR)

# The library ABI follows the driver UAPI version in linux/nds_p2p.h.
P2P_UAPI_MAJOR := $(shell awk '$$2 == "P2P_UAPI_VERSION_MAJOR" { print $$3 + 0 }' $(UAPI_DIR)/linux/nds_p2p.h)
P2P_UAPI_MINOR := $(shell awk '$$2 == "P2P_UAPI_VERSION_MINOR" { print $$3 + 0 }' $(UAPI_DIR)/linux/nds_p2p.h)
NDS_VERSION := $(P2P_UAPI_MAJOR).$(P2P_UAPI_MINOR)
NDS_LIB := libnds.so.$(NDS_VERSION)
NDS_SONAME := libnds.so.$(NDS_VERSION)

NDS_SRCS := nds_api.c p2p_common.c
NDS_OBJS := $(NDS_SRCS:.c=.o)
NDS_DEPS := $(addprefix .,$(NDS_OBJS:.o=.d))

.PHONY: all binding clean

all: $(NDS_LIB)

binding:
	python3 setup.py build_ext --inplace

$(NDS_LIB): $(NDS_OBJS)
	$(CC) -shared -Wl,-soname,$(NDS_SONAME) -o $@ $(NDS_OBJS) -lpthread
	ln -sf libnds.so.$(NDS_VERSION) libnds.so

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -MMD -MP -MT $@ -MF .$*.d -c -o $@ $<

-include $(NDS_DEPS)

clean:
	rm -f libnds.so libnds.so.* $(NDS_OBJS) $(NDS_DEPS)

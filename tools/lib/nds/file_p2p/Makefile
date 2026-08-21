# SPDX-License-Identifier: GPL-2.0
CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Werror -g -ggdb -fno-omit-frame-pointer
# linux/nds_p2p.h lives in tools/include/uapi
UAPI_DIR ?= $(abspath ../../../include/uapi)
CPPFLAGS += -I. -I$(UAPI_DIR)

NDS_API_VER := $(shell sed -n 's/^[[:space:]]*#define[[:space:]]\+NDS_API_VERSION[[:space:]]\+\([0-9]\+\)u\?.*/\1/p' nds_api.h)
NDS_MAJOR := $(shell echo $$(($(NDS_API_VER) >> 8)))
NDS_MINOR := $(shell echo $$(($(NDS_API_VER) & 255)))
NDS_VERSION := $(NDS_MAJOR).$(NDS_MINOR)
NDS_LIB := libnds.so.$(NDS_VERSION)
NDS_SONAME := libnds.so.$(NDS_VERSION)

NDS_SRCS := nds_api.c p2p_common.c
NDS_OBJS := $(NDS_SRCS:.c=.o)
NDS_DEPS := $(addprefix .,$(NDS_OBJS:.o=.d))

.PHONY: all clean

all: $(NDS_LIB)

$(NDS_LIB): $(NDS_OBJS)
	$(CC) -shared -Wl,-soname,$(NDS_SONAME) -o $@ $(NDS_OBJS) -lpthread
	ln -sf libnds.so.$(NDS_VERSION) libnds.so

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -MMD -MP -MT $@ -MF .$*.d -c -o $@ $<

-include $(NDS_DEPS)

clean:
	rm -f libnds.so libnds.so.* $(NDS_OBJS) $(NDS_DEPS)

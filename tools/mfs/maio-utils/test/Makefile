# SPDX-License-Identifier: GPL-2.0

CC := gcc
CFLAGS := -fPIC -Wall -Werror -O2
CPPFLAGS := -fPIC -Wall -Wno-ignored-attributes -Werror -O2 -std=c++11 -g
LDFLAGS := -shared

CFLAGS += $(addprefix -I,../include)
CPPFLAGS += $(addprefix -I,../include)

C_SRCS := $(wildcard *.c)
CPP_SRCS := $(wildcard *.cpp)
TARGETS := $(C_SRCS:.c=.so) $(CPP_SRCS:.cpp=.so)

all: $(TARGETS)

%.so: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

%.so: %.cpp
	$(CC) $(CPPFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)

.PHONY: all clean

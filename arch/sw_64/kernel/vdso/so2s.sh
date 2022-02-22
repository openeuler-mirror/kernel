#!/bin/sh
# SPDX-License-Identifier: GPL-2.0+
# Copyright 2020 Palmer Dabbelt <palmerdabbelt@google.com>

grep -v "LINUX" | sed 's/\([0-9a-f]*\) T \([a-z0-9_]*\)/.globl\t\2\n\2:\n.quad\t0x\1/'

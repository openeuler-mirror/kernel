// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#include <ub/ubus/ubus.h>

static const struct cfg_ops {
	read_byte_f cfg_read_byte;
	read_word_f cfg_read_word;
	read_dword_f cfg_read_dword;
	write_byte_f cfg_write_byte;
	write_word_f cfg_write_word;
	write_dword_f cfg_write_dword;
} cfg_ops_t;

static struct cfg_ops ub_cfg_ops = {};

int register_ub_cfg_read_ops(read_byte_f rb, read_word_f rw, read_dword_f rdw)
{
	if (rb && rw && rdw) {
		ub_cfg_ops.cfg_read_byte = rb;
		ub_cfg_ops.cfg_read_word = rw;
		ub_cfg_ops.cfg_read_dword = rdw;
		return 0;
	}

	return -EINVAL;
}
EXPORT_SYMBOL_GPL(register_ub_cfg_read_ops);

int register_ub_cfg_write_ops(write_byte_f wb, write_word_f ww, write_dword_f wdw)
{
	if (wb && ww && wdw) {
		ub_cfg_ops.cfg_write_byte = wb;
		ub_cfg_ops.cfg_write_word = ww;
		ub_cfg_ops.cfg_write_dword = wdw;
		return 0;
	}

	return -EINVAL;
}
EXPORT_SYMBOL_GPL(register_ub_cfg_write_ops);

void unregister_ub_cfg_ops(void)
{
	memset(&ub_cfg_ops, 0, sizeof(struct cfg_ops));
}
EXPORT_SYMBOL_GPL(unregister_ub_cfg_ops);

int ub_cfg_read_byte(struct ub_entity *uent, u64 pos, u8 *val)
{
	if (!ub_cfg_ops.cfg_read_byte)
		return -ENODEV;

	return ub_cfg_ops.cfg_read_byte(uent, pos, val);
}
EXPORT_SYMBOL_GPL(ub_cfg_read_byte);

int ub_cfg_read_word(struct ub_entity *uent, u64 pos, u16 *val)
{
	if (!ub_cfg_ops.cfg_read_word)
		return -ENODEV;

	return ub_cfg_ops.cfg_read_word(uent, pos, val);
}
EXPORT_SYMBOL_GPL(ub_cfg_read_word);

int ub_cfg_read_dword(struct ub_entity *uent, u64 pos, u32 *val)
{
	if (!ub_cfg_ops.cfg_read_dword)
		return -ENODEV;

	return ub_cfg_ops.cfg_read_dword(uent, pos, val);
}
EXPORT_SYMBOL_GPL(ub_cfg_read_dword);

int ub_cfg_write_byte(struct ub_entity *uent, u64 pos, u8 val)
{
	if (!ub_cfg_ops.cfg_write_byte)
		return -ENODEV;

	return ub_cfg_ops.cfg_write_byte(uent, pos, val);
}
EXPORT_SYMBOL_GPL(ub_cfg_write_byte);

int ub_cfg_write_word(struct ub_entity *uent, u64 pos, u16 val)
{
	if (!ub_cfg_ops.cfg_write_word)
		return -ENODEV;

	return ub_cfg_ops.cfg_write_word(uent, pos, val);
}
EXPORT_SYMBOL_GPL(ub_cfg_write_word);

int ub_cfg_write_dword(struct ub_entity *uent, u64 pos, u32 val)
{
	if (!ub_cfg_ops.cfg_write_dword)
		return -ENODEV;

	return ub_cfg_ops.cfg_write_dword(uent, pos, val);
}
EXPORT_SYMBOL_GPL(ub_cfg_write_dword);

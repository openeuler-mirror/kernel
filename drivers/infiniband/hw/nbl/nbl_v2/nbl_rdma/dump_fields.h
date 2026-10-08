/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_IB_DUMP_FIELDS_H
#define NBL_IB_DUMP_FIELDS_H

#include "counters.h"

enum NBL_DBG_DUMP_TYPE {
	NBL_DBG_DUMP_QPC,
	NBL_DBG_DUMP_MRT,
	NBL_DBG_DUMP_CQC,
};

void nbl_dump_fields(struct nbl_pci_f *rf, struct nbl_func_file *func_file,
	u8 *data, enum NBL_DBG_DUMP_TYPE type);
void write_to_file_buffer(struct nbl_func_file *func_file, char *fmt, ...) __attribute__
	((format(gnu_printf, 2, 3)));
void nbl_dump_hex_to_file_buffer(struct nbl_func_file *func_file, u8 *buf, int len);
#endif /* NBL_IB_DUMP_FIELDS_H */

/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2018-2019 HiSilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#ifndef HISI_SEC_CRYPTO_H
#define HISI_SEC_CRYPTO_H

#define SEC_IV_SIZE 24
#define SEC_MAX_KEY_SIZE 64

int hisi_sec_register_to_crypto(int fusion_limit);
void hisi_sec_unregister_from_crypto(int fusion_limit);

#endif

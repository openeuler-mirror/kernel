/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_IB_H
#define NBL_IB_H

#define nbl_ib_dbg(_dev, format, arg...)                                       \
	dev_dbg((_dev) ? ((struct nbl_sc_dev *)(_dev))->hw->device : NULL, "%s:%d:(pid %d): "\
		format, __func__, __LINE__, current->pid, ##arg)

#define nbl_ib_err(_dev, format, arg...)                                       \
	dev_err((_dev) ? ((struct nbl_sc_dev *)(_dev))->hw->device : NULL,\
		"%s:%d:(comm %s pid %d): "format,\
		__func__, __LINE__, current->comm, current->pid, ##arg)

#define nbl_ib_err_ratelimited(_dev, format, arg...)                                       \
	dev_err_ratelimited((_dev) ? ((struct nbl_sc_dev *)(_dev))->hw->device : NULL,\
		"%s:%d:(comm %s pid %d): "format,\
		__func__, __LINE__, current->comm, current->pid, ##arg)

#define nbl_ib_warn(_dev, format, arg...)                                      \
	dev_warn((_dev) ? ((struct nbl_sc_dev *)(_dev))->hw->device : NULL, "%s:%d:(pid %d): "\
		format, __func__, __LINE__, current->pid, ##arg)

#define nbl_dev_dbg(device, format, arg...)                                       \
	dev_dbg((device), "%s:%d:(pid %d): " format, __func__,       \
		__LINE__, current->pid, ##arg)

#define nbl_dev_err(device, format, arg...)                                       \
	dev_err((device), "%s:%d:(pid %d): " format, __func__,       \
		__LINE__, current->pid, ##arg)

#define nbl_dev_warn(device, format, arg...)                                      \
	dev_warn((device), "%s:%d:(pid %d): " format, __func__,      \
		 __LINE__, current->pid, ##arg)

#define nbl_dev_info(device, format, arg...)                                      \
	dev_info((device), "%s:%d:(pid %d): " format, __func__,      \
		 __LINE__, current->pid, ##arg)

#define nbl_pr_err(format, arg...)                                             \
	pr_err("[err]%s:%d: " format, __func__, __LINE__, ##arg)

#define nbl_pr_warn(format, arg...)                                            \
	pr_warn("[warn]%s:%d: " format, __func__, __LINE__, ##arg)

#define nbl_pr_notice(format, arg...)                                            \
	pr_notice("[notice]%s:%d: " format, __func__, __LINE__, ##arg)

#define nbl_pr_info(format, arg...)                                            \
	pr_info("[info]%s:%d: " format, __func__, __LINE__, ##arg)

#define nbl_pr_dbg(format, arg...)                                            \
	pr_debug("[dbg]%s:%d: " format, __func__, __LINE__, ##arg)
#endif /* NBL_IB_H */

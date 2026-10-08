/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_DISPATCH_H_
#define _NBL_DISPATCH_H_

#include "nbl_core.h"

#define NBL_DISP_MGT_TO_COMMON(disp_mgt)	((disp_mgt)->common)
#define NBL_DISP_MGT_TO_DEV(disp_mgt)		NBL_COMMON_TO_DEV(NBL_DISP_MGT_TO_COMMON(disp_mgt))

#define NBL_DISP_MGT_TO_RES_OPS_TBL(disp_mgt)	((disp_mgt)->res_ops_tbl)
#define NBL_DISP_MGT_TO_RES_OPS(disp_mgt)	(NBL_DISP_MGT_TO_RES_OPS_TBL(disp_mgt)->ops)
#define NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)	(NBL_DISP_MGT_TO_RES_OPS_TBL(disp_mgt)->priv)
#define NBL_DISP_MGT_TO_CHAN_OPS_TBL(disp_mgt)	((disp_mgt)->chan_ops_tbl)
#define NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt)	(NBL_DISP_MGT_TO_CHAN_OPS_TBL(disp_mgt)->ops)
#define NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt)	(NBL_DISP_MGT_TO_CHAN_OPS_TBL(disp_mgt)->priv)
#define NBL_DISP_MGT_TO_DISP_OPS_TBL(disp_mgt)	((disp_mgt)->disp_ops_tbl)
#define NBL_DISP_MGT_TO_DISP_OPS(disp_mgt)	(NBL_DISP_MGT_TO_DISP_OPS_TBL(disp_mgt)->ops)
#define NBL_DISP_MGT_TO_DISP_PRIV(disp_mgt)	(NBL_DISP_MGT_TO_DISP_OPS_TBL(disp_mgt)->priv)

#define NBL_OPS_CALL_LOCK(disp_mgt, func, ...)							\
({												\
	typeof(disp_mgt) _disp_mgt = (disp_mgt);						\
	typeof(func) _func = (func);								\
	u64 ret = 0;										\
												\
	if (_disp_mgt->ops_lock_required)							\
		mutex_lock(&_disp_mgt->ops_muxtex_lock);					\
												\
	/* The following code can be understand in this way: */ \
	/* if (func has void return value) */ \
	/*     (!_func) ? 0 : _func(__VA_ARGS__); */ \
	/* else */ \
	/*     ret = (!_func) ? 0 : _func(__VA_ARGS__); */ \
	/* __builtin_choose_expr is a gcc builtin function equals to ternary operator. */ \
	/*     __builtin_choose_expr(cond, expr1, expr2) == cond ? expr1 : expr2 */ \
	__builtin_choose_expr(									\
		/* Check if the func has void return value */					\
		__builtin_types_compatible_p(typeof(_func(__VA_ARGS__)), void),			\
		(!_func) ? 0 : _func(__VA_ARGS__),						\
		/* We cannot simply write: */ \
		/*     ret = (!_func) ? 0 : _func(__VA_ARGS__) */ \
		/* although __builtin_choose_expr only compiles the selected branch, */ \
		/* it still checks syntax error on the used branch, */ \
		/* so ret = void return is illegal. We have to wrap a */ \
		/* __builtin_choose_expr again to avoid compiler to form */ \
		/* a sentence as ret = _func(__VA_ARGS__) when return is void */ \
		ret = __builtin_choose_expr(							\
			__builtin_types_compatible_p(typeof(_func(__VA_ARGS__)), void),		\
			0,									\
			(!_func) ? 0 : _func(__VA_ARGS__)					\
		)										\
	);											\
												\
	if (_disp_mgt->ops_lock_required)							\
		mutex_unlock(&_disp_mgt->ops_muxtex_lock);					\
												\
	(typeof(_func(__VA_ARGS__))) ret;							\
})

struct nbl_dispatch_mgt {
	struct nbl_common_info *common;
	struct nbl_resource_ops_tbl *res_ops_tbl;
	struct nbl_channel_ops_tbl *chan_ops_tbl;
	struct nbl_dispatch_ops_tbl *disp_ops_tbl;
	DECLARE_BITMAP(ctrl_lvl, NBL_DISP_CTRL_LVL_MAX);
	struct mutex ops_muxtex_lock;	/* use for the caller not in interrupt */
	/* use for the caller is in interrupt or other can't sleep thread */
	bool ops_lock_required;
};

#endif

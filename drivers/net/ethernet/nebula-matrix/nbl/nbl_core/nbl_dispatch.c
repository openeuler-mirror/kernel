// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_dispatch.h"

/* ************   loc callback macro BEGIN  ************  */
#define DIS2RES_1IN_CB_LOC(op_name, lock, has_ret, ret_type)					\
({												\
	 __typeof__(__builtin_choose_expr(has_ret, ((ret_type)0), (char)0)) _ret = 0;		\
	typeof(lock) _lock = lock;								\
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;			\
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);			\
	size_t _fn_offset = offsetof(struct nbl_resource_ops, op_name);				\
	void *_fn_ptr = *(void **)((char *)res_ops + _fn_offset);				\
	void *res_priv = NBL_DISP_MGT_TO_RES_PRIV(disp_mgt);					\
												\
	if (disp_mgt->ops_lock_required && _lock)						\
		mutex_lock(&disp_mgt->ops_muxtex_lock);						\
												\
	__builtin_choose_expr(has_ret,								\
		(void)(_fn_ptr ? (_ret = ((typeof(_ret) (*)(void *))_fn_ptr)(res_priv)) : 0),	\
		(void)(_fn_ptr ? ((void (*)(void *))_fn_ptr)(res_priv) : (void)0)		\
	);											\
												\
	if (disp_mgt->ops_lock_required && _lock)						\
		mutex_unlock(&disp_mgt->ops_muxtex_lock);					\
												\
	__builtin_choose_expr(has_ret, _ret, (void)0);						\
})

#define DIS2RES_2IN_CB_LOC(op_name, lock, param1, has_ret, ret_type)				\
({												\
	__typeof__(__builtin_choose_expr(has_ret, ((ret_type)0), (char)0)) _ret = 0;		\
	typeof(lock) _lock = lock;								\
	typeof(param1) _param1 = param1;							\
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;			\
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);			\
	size_t _fn_offset = offsetof(struct nbl_resource_ops, op_name);				\
	void *_fn_ptr = *(void **)((char *)res_ops + _fn_offset);				\
	void *res_priv = NBL_DISP_MGT_TO_RES_PRIV(disp_mgt);					\
												\
	if (disp_mgt->ops_lock_required && _lock)						\
		mutex_lock(&disp_mgt->ops_muxtex_lock);						\
												\
	 __builtin_choose_expr(has_ret,								\
		(void)(_fn_ptr ? (_ret = ((typeof(_ret) (*)(void *, typeof(_param1)))_fn_ptr)	\
		       (res_priv, _param1)) : 0),						\
		(void)(_fn_ptr ? ((void (*)(void *, typeof(_param1)))_fn_ptr)			\
		       (res_priv, _param1) : (void)0)						\
	);											\
												\
	if (disp_mgt->ops_lock_required && _lock)						\
		mutex_unlock(&disp_mgt->ops_muxtex_lock);					\
												\
	__builtin_choose_expr(has_ret, _ret, (void)0);						\
})

#define DIS2RES_2IN_OUT_CB_LOC(op_name, lock, param1, output, has_ret, ret_type)		\
({												\
	__typeof__(__builtin_choose_expr(has_ret, ((ret_type)0), (char)0)) _ret = 0;		\
	typeof(lock) _lock = lock;								\
	typeof(param1) _param1 = param1;							\
	typeof(output) _output = output;							\
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;			\
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);			\
	size_t _fn_offset = offsetof(struct nbl_resource_ops, op_name);				\
	void *_fn_ptr = *(void **)((char *)res_ops + _fn_offset);				\
	void *res_priv = NBL_DISP_MGT_TO_RES_PRIV(disp_mgt);					\
												\
	if (disp_mgt->ops_lock_required && _lock)						\
		mutex_lock(&disp_mgt->ops_muxtex_lock);						\
												\
	 __builtin_choose_expr(has_ret,								\
		(void)(_fn_ptr ? (_ret = ((typeof(_ret) (*)(void *, typeof(_param1),		\
			typeof(_output)))_fn_ptr) (res_priv, _param1, _output)) : 0),		\
		(void)(_fn_ptr ? ((void (*)(void *, typeof(_param1), typeof(_output)))_fn_ptr)	\
		       (res_priv, _param1, _output) : (void)0)					\
	);											\
												\
	if (disp_mgt->ops_lock_required && _lock)						\
		mutex_unlock(&disp_mgt->ops_muxtex_lock);					\
												\
	__builtin_choose_expr(has_ret, _ret, (void)0);						\
})

#define DIS2RES_1OUT_CB_LOC(op_name, lock, output, has_ret, ret_type)		\
({												\
	__typeof__(__builtin_choose_expr(has_ret, ((ret_type)0), (char)0)) _ret = 0;		\
	typeof(lock) _lock = lock;								\
	typeof(output) _output = output;							\
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;			\
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);			\
	size_t _fn_offset = offsetof(struct nbl_resource_ops, op_name);				\
	void *_fn_ptr = *(void **)((char *)res_ops + _fn_offset);				\
	void *res_priv = NBL_DISP_MGT_TO_RES_PRIV(disp_mgt);					\
												\
	if (disp_mgt->ops_lock_required && _lock)						\
		mutex_lock(&disp_mgt->ops_muxtex_lock);						\
												\
	__builtin_choose_expr(has_ret,								\
		(void)(_fn_ptr ? (_ret = ((typeof(_ret) (*)(void *, typeof(_output)))_fn_ptr)	\
		       (res_priv, _output)) : 0),						\
		(void)(_fn_ptr ? ((void (*)(void *, typeof(_output)))_fn_ptr)			\
		       (res_priv, _output) : (void)0)						\
	);											\
												\
	if (disp_mgt->ops_lock_required && _lock)						\
		mutex_unlock(&disp_mgt->ops_muxtex_lock);					\
												\
	__builtin_choose_expr(has_ret, _ret, (void)0);						\
})

/* ************   loc callback macro END  ************  */

/* ************   req callback macro BEGIN  ************  */
/* 1 input parameter response member's use retcode */
#define DIS2CH_1IN_RESPMEM2RET_CB_REQ(msg_type, resp_type, resp_mem, ret_type)		\
({												\
	ret_type _ret = 0;									\
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;			\
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);			\
	resp_type result;									\
	struct nbl_chan_send_info chan_send;							\
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);			\
												\
	memset(&result, 0xff, sizeof(result));							\
	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), msg_type, NULL,			\
		      0, &result, sizeof(result), 1);						\
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);			\
	_ret = result.resp_mem;									\
})

/* 2 input parameter response member's use retcode */
#define DIS2CH_2IN_RESPMEM2RET_CB_REQ(param1, msg_type, resp_type, resp_mem, ret_type)		\
({												\
	ret_type _ret = 0;									\
	typeof(param1) _param1 = param1;							\
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;			\
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);			\
	resp_type result;									\
	struct nbl_chan_send_info chan_send;							\
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);			\
												\
	memset(&result, 0xff, sizeof(result));							\
	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), msg_type, _param1,		\
		      sizeof(*_param1), &result, sizeof(result), 1);				\
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);			\
	_ret = result.resp_mem;									\
})

/* response func use resource layer's ret as chan resp's "err" member  */
#define DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param1, msg_type)					\
({												\
	int _ret = 0;										\
	typeof(param1) _param1 = param1;							\
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;			\
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);			\
	struct nbl_chan_send_info chan_send;							\
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);			\
												\
	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), msg_type, _param1,		\
		      sizeof(*_param1), NULL, 0, 1);						\
	_ret = chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);		\
	_ret;									\
})

#define DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ_NOACK(param1, msg_type)				\
({												\
	int _ret = 0;										\
	typeof(param1) _param1 = param1;							\
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;			\
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);			\
	struct nbl_chan_send_info chan_send;							\
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);			\
												\
	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), msg_type, _param1,		\
		      sizeof(*_param1), NULL, 0, 0);						\
	_ret = chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);		\
	_ret;											\
})

#define DIS2CH_2IN_OUT_RESRET_AS_CHRET_CB_REQ(param1, msg_type, output)				\
({												\
	int _ret = 0;										\
	typeof(param1) _param1 = param1;							\
	typeof(output) _output = output;							\
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;			\
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);			\
	struct nbl_chan_send_info chan_send;							\
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);			\
												\
	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), msg_type, _param1,		\
		      sizeof(*_param1), _output, sizeof(*_output), 1);				\
	_ret = chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);		\
	_ret;									\
})

#define DIS2CH_1OUT_RESRET_AS_CHRET_CB_REQ(msg_type, output)					\
({												\
	int _ret = 0;										\
	typeof(output) _output = output;							\
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;			\
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);			\
	struct nbl_chan_send_info chan_send;							\
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);			\
												\
	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), msg_type, NULL,			\
		      0, _output, sizeof(*_output), 1);						\
	_ret = chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);		\
	_ret;											\
})

/* ************   req callback macro END  ************  */

/* ************   resp callback macro BEGIN  ************  */
#define DIS2CH_1IN_RESPMEM2RET_CB_RESP(op_name, lock, msg_type, resp_type,			\
				       resp_mem, ret_type)					\
({												\
	typeof(lock) _lock = lock;								\
	const u32 __msg_type = (msg_type);							\
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;			\
	void *res_priv = NBL_DISP_MGT_TO_RES_PRIV(disp_mgt);					\
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);				\
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);			\
	size_t _fn_offset = offsetof(struct nbl_resource_ops, op_name);				\
	void *_fn_ptr = *(void **)((char *)res_ops + _fn_offset);				\
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);			\
	struct nbl_chan_ack_info chan_ack;							\
	resp_type result;									\
	int err = NBL_CHAN_RESP_OK;								\
	int ret = 0;										\
	memset(&result, 0, sizeof(result));							\
	if (_fn_ptr) {										\
		if (disp_mgt->ops_lock_required && _lock)					\
			mutex_lock(&disp_mgt->ops_muxtex_lock);					\
		result.resp_mem =  ((ret_type (*)(void *))_fn_ptr)(res_priv);			\
		if (disp_mgt->ops_lock_required && _lock)					\
			mutex_unlock(&disp_mgt->ops_muxtex_lock);				\
	}											\
	NBL_CHAN_ACK(chan_ack, src_id, __msg_type, msg_id, err, &result, sizeof(result));	\
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);		\
	if (ret)										\
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %u\n",		\
			ret, __msg_type);							\
})

#define DIS2CH_2IN_RESPMEM2RET_CB_RESP(op_name, lock, in1_type, msg_type, resp_type,		\
				       resp_mem, ret_type, srcid_map)				\
({												\
	in1_type p = (typeof(p))data;								\
	typeof(lock) _lock = lock;								\
	const u32 __msg_type = (msg_type);							\
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;			\
	void *res_priv = NBL_DISP_MGT_TO_RES_PRIV(disp_mgt);					\
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);				\
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);			\
	size_t _fn_offset = offsetof(struct nbl_resource_ops, op_name);				\
	void *_fn_ptr = *(void **)((char *)res_ops + _fn_offset);				\
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);			\
	struct nbl_chan_ack_info chan_ack;							\
	resp_type result;									\
	int err = NBL_CHAN_RESP_OK;								\
	int ret = 0;										\
												\
	srcid_map;										\
	memset(&result, 0, sizeof(result));							\
	if (_fn_ptr) {										\
		if (disp_mgt->ops_lock_required && _lock)					\
			mutex_lock(&disp_mgt->ops_muxtex_lock);					\
		result.resp_mem =  ((ret_type (*)(void *, typeof(p)))_fn_ptr)(res_priv, p);	\
		if (disp_mgt->ops_lock_required && _lock)					\
			mutex_unlock(&disp_mgt->ops_muxtex_lock);				\
	}											\
	NBL_CHAN_ACK(chan_ack, src_id, __msg_type, msg_id, err, &result, sizeof(result));	\
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);		\
	if (ret)										\
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %u\n",		\
			ret, __msg_type);							\
})

#define DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(op_name, lock, in1_type, msg_type,			\
					   srcid_map)						\
({												\
	in1_type in;										\
	typeof(in) *p;										\
	typeof(lock) _lock = lock;								\
	const u32 __msg_type = (msg_type);							\
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;			\
	void *res_priv = NBL_DISP_MGT_TO_RES_PRIV(disp_mgt);					\
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);				\
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);			\
	size_t _fn_offset = offsetof(struct nbl_resource_ops, op_name);				\
	void *_fn_ptr = *(void **)((char *)res_ops + _fn_offset);				\
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);			\
	struct nbl_chan_ack_info chan_ack;							\
	int err = NBL_CHAN_RESP_OK;								\
	int ret = 0;										\
	int copy_len;										\
												\
	copy_len = data_len < sizeof(in) ? data_len : sizeof(in);				\
	memset(&in, 0, sizeof(in));								\
	if (copy_len)										\
		memcpy(&in, data, copy_len);							\
	p = &in;										\
	srcid_map;										\
	if (_fn_ptr) {										\
		if (disp_mgt->ops_lock_required && _lock)					\
			mutex_lock(&disp_mgt->ops_muxtex_lock);					\
		ret =  ((int (*)(void *, typeof(p)))_fn_ptr)(res_priv, p);			\
		if (disp_mgt->ops_lock_required && _lock)					\
			mutex_unlock(&disp_mgt->ops_muxtex_lock);				\
		if (ret)									\
			err = NBL_CHAN_RESP_ERR;						\
	}											\
	NBL_CHAN_ACK(chan_ack, src_id, __msg_type, msg_id, err, NULL, 0);			\
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);		\
	if (ret)										\
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %u\n",		\
			ret, __msg_type);							\
})

#define DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP_NOACK(op_name, lock, in1_type, srcid_map)		\
({												\
	in1_type in;										\
	typeof(in) *p;										\
	typeof(lock) _lock = lock;								\
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;			\
	void *res_priv = NBL_DISP_MGT_TO_RES_PRIV(disp_mgt);					\
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);			\
	size_t _fn_offset = offsetof(struct nbl_resource_ops, op_name);				\
	void *_fn_ptr = *(void **)((char *)res_ops + _fn_offset);				\
	int copy_len;										\
												\
	copy_len = data_len < sizeof(in) ? data_len : sizeof(in);				\
	memset(&in, 0, sizeof(in));								\
	if (copy_len)										\
		memcpy(&in, data, copy_len);							\
	p = &in;										\
	srcid_map;										\
	if (_fn_ptr) {										\
		if (disp_mgt->ops_lock_required && _lock)					\
			mutex_lock(&disp_mgt->ops_muxtex_lock);					\
		((int (*)(void *, typeof(p)))_fn_ptr)(res_priv, p);				\
		if (disp_mgt->ops_lock_required && _lock)					\
			mutex_unlock(&disp_mgt->ops_muxtex_lock);				\
	}											\
})

#define DIS2CH_2IN_RESRET_AS_ACKERR_CB_RESP(op_name, lock, in1_type, msg_type,			\
					    ret_type, srcid_map)				\
({												\
	in1_type in;										\
	typeof(in) *p;										\
	typeof(lock) _lock = lock;								\
	const u32 __msg_type = (msg_type);							\
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;			\
	void *res_priv = NBL_DISP_MGT_TO_RES_PRIV(disp_mgt);					\
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);				\
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);			\
	size_t _fn_offset = offsetof(struct nbl_resource_ops, op_name);				\
	void *_fn_ptr = *(void **)((char *)res_ops + _fn_offset);				\
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);			\
	struct nbl_chan_ack_info chan_ack;							\
	ret_type _ret = 0;									\
	int copy_len;										\
	int _sret;										\
												\
	copy_len = data_len < sizeof(in) ? data_len : sizeof(in);				\
	memset(&in, 0, sizeof(in));								\
	if (copy_len)										\
		memcpy(&in, data, copy_len);							\
	p = &in;										\
	srcid_map;										\
	if (_fn_ptr) {										\
		if (disp_mgt->ops_lock_required && _lock)					\
			mutex_lock(&disp_mgt->ops_muxtex_lock);					\
												\
		_ret = ((typeof(_ret) (*)(void *, typeof(p)))_fn_ptr)(res_priv, p);		\
												\
		if (disp_mgt->ops_lock_required && _lock)					\
			mutex_unlock(&disp_mgt->ops_muxtex_lock);				\
	}											\
	NBL_CHAN_ACK(chan_ack, src_id, __msg_type, msg_id, _ret, NULL, 0);			\
	_sret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);		\
	if (_sret)										\
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %u\n",		\
			_sret, __msg_type);							\
})

#define DIS2CH_2IN_OUT_CB_RESP(op_name, lock, in1_type, msg_type, resp_type,			\
			       srcid_map)							\
({												\
	in1_type in;										\
	typeof(in) *p = &in;									\
	typeof(lock) _lock = lock;								\
	const u32 __msg_type = (msg_type);							\
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;			\
	void *res_priv = NBL_DISP_MGT_TO_RES_PRIV(disp_mgt);					\
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);				\
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);			\
	size_t _fn_offset = offsetof(struct nbl_resource_ops, op_name);				\
	void *_fn_ptr = *(void **)((char *)res_ops + _fn_offset);				\
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);			\
	struct nbl_chan_ack_info chan_ack;							\
	resp_type result;									\
	int err = NBL_CHAN_RESP_OK;								\
	int ret = 0;										\
	int copy_len;										\
												\
	copy_len = data_len < sizeof(in) ? data_len : sizeof(in);				\
	memset(&in, 0, sizeof(in));								\
	if (copy_len)										\
		memcpy(&in, data, copy_len);							\
	p = &in;										\
												\
	srcid_map;										\
	memset(&result, 0, sizeof(result));							\
	if (_fn_ptr) {										\
		if (disp_mgt->ops_lock_required && _lock)					\
			mutex_lock(&disp_mgt->ops_muxtex_lock);					\
		ret =  ((int (*)(void *, typeof(p), typeof(result) *))_fn_ptr)			\
			(res_priv, p, &result);							\
		if (disp_mgt->ops_lock_required && _lock)					\
			mutex_unlock(&disp_mgt->ops_muxtex_lock);				\
		if (ret)									\
			err = NBL_CHAN_RESP_ERR;						\
	}											\
	NBL_CHAN_ACK(chan_ack, src_id, __msg_type, msg_id, err, &result, sizeof(result));	\
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);		\
	if (ret)										\
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %u\n",		\
			ret, __msg_type);							\
})

#define DIS2CH_1OUT_CB_RESP(op_name, lock, msg_type, resp_type, srcid_map)		\
({												\
	typeof(lock) _lock = lock;								\
	const u32 __msg_type = (msg_type);							\
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;			\
	void *res_priv = NBL_DISP_MGT_TO_RES_PRIV(disp_mgt);					\
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);				\
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);			\
	size_t _fn_offset = offsetof(struct nbl_resource_ops, op_name);				\
	void *_fn_ptr = *(void **)((char *)res_ops + _fn_offset);				\
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);			\
	struct nbl_chan_ack_info chan_ack;							\
	resp_type result;									\
	int err = NBL_CHAN_RESP_OK;								\
	int ret = 0;										\
												\
	if (disp_mgt->ops_lock_required && _lock)						\
		mutex_lock(&disp_mgt->ops_muxtex_lock);						\
												\
	memset(&result, 0, sizeof(result));							\
	srcid_map;										\
	if (_fn_ptr)										\
		ret = ((int (*)(void *, typeof(result) *))_fn_ptr)(res_priv, &result);		\
												\
	if (disp_mgt->ops_lock_required && _lock)						\
		mutex_unlock(&disp_mgt->ops_muxtex_lock);					\
												\
	if (ret)										\
		err = NBL_CHAN_RESP_ERR;							\
												\
	NBL_CHAN_ACK(chan_ack, src_id, __msg_type, msg_id, err, &result, sizeof(result));	\
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);		\
	if (ret)										\
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %u\n",		\
			ret, __msg_type);							\
})

/* ************   resp callback macro END  ************  */

/* ************   loc/req/resp callback macro BEGIN  ************  */
static int nbl_disp_init_chip_module_loc(void *priv)
{
	return  DIS2RES_1IN_CB_LOC(init_chip_module, false, true, int);
}

static void nbl_disp_set_driver_status_loc(void *priv, bool active)
{
	DIS2RES_2IN_CB_LOC(set_driver_status, false, active, false, void);
}

static void nbl_disp_get_res_pt_tbl_loc(void *priv, struct nbl_resource_pt_tbl *param)
{
	DIS2RES_2IN_CB_LOC(get_res_pt_tbl, false, param, false, void);
}

static int nbl_disp_init_queue_loc(void *priv)
{
	return  DIS2RES_1IN_CB_LOC(init_queue, false, true, int);
}

static int nbl_disp_init_vsi_loc(void *priv)
{
	return  DIS2RES_1IN_CB_LOC(init_vsi, false, true, int);
}

static int nbl_disp_init_vf_msix_map_loc(void *priv, struct nbl_ch_prm_init_vf_msix_map *param)
{
	return DIS2RES_2IN_CB_LOC(init_vf_msix_map, true, param, true, int);
}

static int nbl_disp_chan_init_vf_msix_map_req(void *priv, struct nbl_ch_prm_init_vf_msix_map *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_INIT_VF_MSIX_MAP);
}

static void nbl_disp_chan_init_vf_msix_map_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(init_vf_msix_map, true,
					   struct nbl_ch_prm_init_vf_msix_map,
					   NBL_CHAN_MSG_INIT_VF_MSIX_MAP, (void)0);
}

static int nbl_disp_configure_msix_map_loc(void *priv, struct nbl_ch_prm_cfg_msix_map *param)
{
	return DIS2RES_2IN_CB_LOC(configure_msix_map, true, param, true, int);
}

static int nbl_disp_chan_configure_msix_map_req(void *priv, struct nbl_ch_prm_cfg_msix_map *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_CONFIGURE_MSIX_MAP);
}

static void nbl_disp_chan_configure_msix_map_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(configure_msix_map, true,
					   struct nbl_ch_prm_cfg_msix_map,
					   NBL_CHAN_MSG_CONFIGURE_MSIX_MAP, p->sfid = src_id);
}

static int nbl_disp_destroy_msix_map_loc(void *priv, u16 *sfid)
{
	return DIS2RES_2IN_CB_LOC(destroy_msix_map, true, sfid, true, int);
}

static int nbl_disp_chan_destroy_msix_map_req(void *priv, u16 *sfid)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(sfid, NBL_CHAN_MSG_DESTROY_MSIX_MAP);
}

static void nbl_disp_chan_destroy_msix_map_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(destroy_msix_map, true, u16,
					   NBL_CHAN_MSG_DESTROY_MSIX_MAP, *p = src_id);
}

static u16 nbl_disp_get_vsi_id_loc(void *priv, struct nbl_ch_prm_get_vsi *param)
{
	return DIS2RES_2IN_CB_LOC(get_vsi_id, false, param, true, u16);
}

static u16 nbl_disp_chan_get_vsi_id_req(void *priv, struct nbl_ch_prm_get_vsi *param)
{
	return DIS2CH_2IN_RESPMEM2RET_CB_REQ(param, NBL_CHAN_MSG_GET_VSI_ID,
		struct nbl_ch_prm_get_vsi, vsi_id, u16);
}

static void nbl_disp_chan_get_vsi_id_resp(void *priv, u16 src_id, u16 msg_id,
					  void *data, u32 data_len)
{
	DIS2CH_2IN_RESPMEM2RET_CB_RESP(get_vsi_id, false, struct nbl_ch_prm_get_vsi *,
				       NBL_CHAN_MSG_GET_VSI_ID, struct nbl_ch_prm_get_vsi, vsi_id,
				       u16,  p->sfid = src_id);
}

static int nbl_disp_enable_mailbox_irq_loc(void *priv, struct nbl_ch_prm_enable_irq *param)
{
	return DIS2RES_2IN_CB_LOC(enable_mailbox_irq, false, param, true, int);
}

static int nbl_disp_chan_enable_mailbox_irq_req(void *priv, struct nbl_ch_prm_enable_irq *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_MAILBOX_ENABLE_IRQ);
}

static void nbl_disp_chan_enable_mailbox_irq_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(enable_mailbox_irq, false,
					   struct nbl_ch_prm_enable_irq,
					   NBL_CHAN_MSG_MAILBOX_ENABLE_IRQ, p->sfid = src_id);
}

static int nbl_disp_enable_abnormal_irq_loc(void *priv, struct nbl_ch_prm_enable_irq *param)
{
	return DIS2RES_2IN_CB_LOC(enable_abnormal_irq, false, param, true, int);
}

static int nbl_disp_enable_sfp_plug_irq_loc(void *priv, struct nbl_ch_prm_enable_irq *param)
{
	return DIS2RES_2IN_CB_LOC(enable_sfp_plug_irq, false, param, true, int);
}

static int nbl_disp_enable_adminq_irq_loc(void *priv, struct nbl_ch_prm_enable_irq *param)
{
	return DIS2RES_2IN_CB_LOC(enable_adminq_irq, false, param, true, int);
}

static int nbl_disp_set_rdma_rx_vsi_remap_loc(void *priv, bool init)
{
	return DIS2RES_2IN_CB_LOC(set_rdma_rx_vsi_remap, false, init, true, int);
}

static u16 nbl_disp_get_global_vector_loc(void *priv, struct nbl_ch_prm_get_global_vec *param)
{
	return DIS2RES_2IN_CB_LOC(get_global_vector, false, param, true, u16);
}

static u16 nbl_disp_chan_get_global_vector_req(void *priv, struct nbl_ch_prm_get_global_vec *param)
{
	return DIS2CH_2IN_RESPMEM2RET_CB_REQ(param, NBL_CHAN_MSG_GET_GLOBAL_VECTOR,
		struct nbl_ch_prm_get_global_vec, vector_id, u16);
}

static void nbl_disp_chan_get_global_vector_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len)
{
	DIS2CH_2IN_RESPMEM2RET_CB_RESP(get_global_vector, false, struct nbl_ch_prm_get_global_vec *,
				       NBL_CHAN_MSG_GET_GLOBAL_VECTOR,
				       struct nbl_ch_prm_get_global_vec, vector_id, u16, (void)0);
}

static int nbl_disp_get_chip_temperature_loc(void *priv, struct nbl_ch_prm_get_hwmon *param)
{
	return DIS2RES_2IN_CB_LOC(get_chip_temperature, false, param, true, int);
}

static int nbl_disp_chan_get_chip_temperature_req(void *priv, struct nbl_ch_prm_get_hwmon *param)
{
	return DIS2CH_2IN_RESPMEM2RET_CB_REQ(param, NBL_CHAN_MSG_GET_CHIP_TEMPERATURE,
		struct nbl_ch_prm_int_comm, val, int);
}

static void nbl_disp_chan_get_chip_temperature_resp(void *priv, u16 src_id, u16 msg_id,
						    void *data, u32 data_len)
{
	DIS2CH_2IN_RESPMEM2RET_CB_RESP(get_chip_temperature, false, struct nbl_ch_prm_get_hwmon *,
				       NBL_CHAN_MSG_GET_CHIP_TEMPERATURE,
				       struct nbl_ch_prm_int_comm, val, int, (void)0);
}

static int nbl_disp_get_module_temperature_loc(void *priv, struct nbl_ch_prm_get_hwmon *param)
{
	return DIS2RES_2IN_CB_LOC(get_module_temperature, false, param, true, int);
}

static int nbl_disp_chan_get_module_temperature_req(void *priv, struct nbl_ch_prm_get_hwmon *param)
{
	return DIS2CH_2IN_RESPMEM2RET_CB_REQ(param, NBL_CHAN_MSG_GET_MODULE_TEMPERATURE,
		struct nbl_ch_prm_int_comm, val, int);
}

static void nbl_disp_chan_get_module_temperature_resp(void *priv, u16 src_id, u16 msg_id,
						      void *data, u32 data_len)
{
	DIS2CH_2IN_RESPMEM2RET_CB_RESP(get_module_temperature, false, struct nbl_ch_prm_get_hwmon *,
				       NBL_CHAN_MSG_GET_MODULE_TEMPERATURE,
				       struct nbl_ch_prm_int_comm, val, int, (void)0);
}

static int nbl_disp_get_mbx_irq_num_loc(void *priv)
{
	return DIS2RES_1IN_CB_LOC(get_mbx_irq_num, false, true, int);
}

static int nbl_disp_chan_get_mbx_irq_num_req(void *priv)
{
	return DIS2CH_1IN_RESPMEM2RET_CB_REQ(NBL_CHAN_MSG_GET_MBX_IRQ_NUM,
		struct nbl_ch_prm_int_comm, val, int);
}

static void nbl_disp_chan_get_mbx_irq_num_resp(void *priv, u16 src_id, u16 msg_id,
					       void *data, u32 data_len)
{
	DIS2CH_1IN_RESPMEM2RET_CB_RESP(get_mbx_irq_num, false, NBL_CHAN_MSG_GET_MBX_IRQ_NUM,
				       struct nbl_ch_prm_int_comm, val, int);
}

static int nbl_disp_get_adminq_irq_num_loc(void *priv)
{
	return DIS2RES_1IN_CB_LOC(get_adminq_irq_num, false, true, int);
}

static int nbl_disp_get_abnormal_irq_num_loc(void *priv)
{
	return DIS2RES_1IN_CB_LOC(get_abnormal_irq_num, false, true, int);
}

static int nbl_disp_get_sfp_plug_irq_num_loc(void *priv)
{
	return DIS2RES_1IN_CB_LOC(get_sfp_plug_irq_num, false, true, int);
}

static int nbl_disp_alloc_rings_loc(void *priv, struct nbl_ring_param *param)
{
	return DIS2RES_2IN_CB_LOC(alloc_rings, false, param, true, int);
}

static void nbl_disp_remove_rings_loc(void *priv)
{
	DIS2RES_1IN_CB_LOC(remove_rings, false, false, void);
}

static dma_addr_t nbl_disp_start_tx_ring_loc(void *priv, struct nbl_tx_ring_start_param *param)
{
	return DIS2RES_2IN_CB_LOC(start_tx_ring, false, param, true, dma_addr_t);
}

static void nbl_disp_stop_tx_ring_loc(void *priv, u8 ring_index)
{
	DIS2RES_2IN_CB_LOC(stop_tx_ring, false, ring_index, false, void);
}

static dma_addr_t nbl_disp_start_rx_ring_loc(void *priv, struct nbl_rx_ring_start_param *param)
{
	return DIS2RES_2IN_CB_LOC(start_rx_ring, false, param, true, dma_addr_t);
}

static void nbl_disp_stop_rx_ring_loc(void *priv, u8 ring_index)
{
	DIS2RES_2IN_CB_LOC(stop_rx_ring, false, ring_index, false, void);
}

static void nbl_disp_kick_rx_ring_loc(void *priv, u16 ring_index)
{
	DIS2RES_2IN_CB_LOC(kick_rx_ring, false, ring_index, false, void);
}

static void nbl_disp_set_rings_xdp_prog_loc(void *priv, void *prog)
{
	DIS2RES_2IN_CB_LOC(set_rings_xdp_prog, false, prog, false, void);
}

static int nbl_disp_register_xdp_rxq_loc(void *priv, u8 ring_index)
{
	return DIS2RES_2IN_CB_LOC(register_xdp_rxq, false, ring_index, true, int);
}

static void nbl_disp_unregister_xdp_rxq_loc(void *priv, u8 ring_index)
{
	DIS2RES_2IN_CB_LOC(unregister_xdp_rxq, false, ring_index, false, void);
}

static int nbl_disp_dump_ring_stats_loc(void *priv, struct nbl_dump_ring_param *param)
{
	return DIS2RES_2IN_CB_LOC(dump_ring_stats, false, param, true, int);
}

static int nbl_disp_dump_ring_loc(void *priv, struct nbl_dump_ring_param *param)
{
	return DIS2RES_2IN_CB_LOC(dump_ring, false, param, true, int);
}

static struct nbl_napi_struct *nbl_disp_get_vector_napi_loc(void *priv, u16 index)
{
	return DIS2RES_2IN_CB_LOC(get_vector_napi, false, index, true, struct nbl_napi_struct *);
}

static void nbl_disp_set_vector_info_loc(void *priv, struct nbl_vec_info_param *param)
{
	DIS2RES_2IN_CB_LOC(set_vector_info, false, param, false, void);
}

static void nbl_disp_register_vsi_ring_loc(void *priv, struct nbl_vsi_ring_param *param)
{
	DIS2RES_2IN_CB_LOC(register_vsi_ring, false, param, false, void);
}

static int nbl_disp_register_net_loc(void *priv, struct nbl_ch_prm_register_net_info *param,
				     struct nbl_register_net_result *output)
{
	return DIS2RES_2IN_OUT_CB_LOC(register_net, true, param, output, true, int);
}

static int nbl_disp_chan_register_net_req(void *priv, struct nbl_ch_prm_register_net_info *param,
					  struct nbl_register_net_result *output)
{
	return DIS2CH_2IN_OUT_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_REGISTER_NET, output);
}

static void nbl_disp_chan_register_net_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	DIS2CH_2IN_OUT_CB_RESP(register_net, true, struct nbl_ch_prm_register_net_info,
			       NBL_CHAN_MSG_REGISTER_NET, struct nbl_register_net_result,
			       p->sfid = src_id);
}

static int nbl_disp_unregister_net_loc(void *priv, u16 *sfid)
{
	return DIS2RES_2IN_CB_LOC(unregister_net, true, sfid, true, int);
}

static int nbl_disp_chan_unregister_net_req(void *priv, u16 *sfid)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(sfid, NBL_CHAN_MSG_UNREGISTER_NET);
}

static void nbl_disp_chan_unregister_net_resp(void *priv, u16 src_id, u16 msg_id,
					      void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(unregister_net, true, u16,
					   NBL_CHAN_MSG_UNREGISTER_NET, *p = src_id);
}

static int nbl_disp_alloc_txrx_queues_loc(void *priv, struct nbl_ch_prm_alloc_txrx_queues *param)
{
	return DIS2RES_2IN_CB_LOC(alloc_txrx_queues, true, param, true, int);
}

static int nbl_disp_chan_alloc_txrx_queues_req(void *priv,
					       struct nbl_ch_prm_alloc_txrx_queues *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_ALLOC_TXRX_QUEUES);
}

static void nbl_disp_chan_alloc_txrx_queues_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(alloc_txrx_queues, true,
					   struct nbl_ch_prm_alloc_txrx_queues,
					   NBL_CHAN_MSG_ALLOC_TXRX_QUEUES, (void)0);
}

static int nbl_disp_free_txrx_queues_loc(void *priv, u16 *vsi_id)
{
	return DIS2RES_2IN_CB_LOC(free_txrx_queues, true, vsi_id, true, int);
}

static int nbl_disp_chan_free_txrx_queues_req(void *priv, u16 *sfid)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(sfid, NBL_CHAN_MSG_FREE_TXRX_QUEUES);
}

static void nbl_disp_chan_free_txrx_queues_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(free_txrx_queues, true, u16,
					   NBL_CHAN_MSG_FREE_TXRX_QUEUES, (void)0);
}

static int nbl_disp_setup_queue_loc(void *priv, struct nbl_ch_prm_setup_queue *param)
{
	return DIS2RES_2IN_CB_LOC(setup_queue, true, param, true, int);
}

static int nbl_disp_chan_setup_queue_req(void *priv, struct nbl_ch_prm_setup_queue *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_SETUP_QUEUE);
}

static void nbl_disp_chan_setup_queue_resp(void *priv, u16 src_id, u16 msg_id,
					   void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(setup_queue, true,
					   struct nbl_ch_prm_setup_queue,
					   NBL_CHAN_MSG_SETUP_QUEUE, (void)0);
}

static int nbl_disp_remove_queue_loc(void *priv, struct nbl_ch_prm_setup_queue *param)
{
	return DIS2RES_2IN_CB_LOC(remove_queue, true, param, true, int);
}

static int nbl_disp_chan_remove_queue_req(void *priv, struct nbl_ch_prm_setup_queue *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_REMOVE_QUEUE);
}

static void nbl_disp_chan_remove_queue_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(remove_queue, true,
					   struct nbl_ch_prm_setup_queue,
					   NBL_CHAN_MSG_REMOVE_QUEUE, (void)0);
}

static int nbl_disp_get_lag_ports_max_loc(void *priv)
{
	return  DIS2RES_1IN_CB_LOC(get_lag_ports_max, false, true, int);
}

static bool nbl_disp_check_lag_nosupport_loc(void *priv)
{
	return  DIS2RES_1IN_CB_LOC(check_lag_nosupport, false, true, bool);
}

/* ************   loc/req/resp callback macro End  ************  */

static int nbl_disp_chan_add_macvlan_req(void *priv, u8 *mac, u16 vlan, u16 vsi)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_add_macvlan param;
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	if (!disp_mgt || !mac)
		return -EINVAL;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	memcpy(param.mac, mac, sizeof(param.mac));
	param.vlan = vlan;
	param.vsi = vsi;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_ADD_MACVLAN, &param, sizeof(param),
		      NULL, 0, 1);

	if (chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send))
		return -EFAULT;

	return 0;
}

static void nbl_disp_chan_add_macvlan_resp(void *priv, u16 src_id, u16 msg_id,
					   void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_add_macvlan *param;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	param = (struct nbl_chan_param_add_macvlan *)data;

	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->add_macvlan,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->mac,
				param->vlan, param->vsi);
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_ADD_MACVLAN, msg_id, err, NULL, 0);
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d\n",
			ret, NBL_CHAN_MSG_ADD_MACVLAN);
}

static void nbl_disp_chan_del_macvlan_req(void *priv, u8 *mac, u16 vlan, u16 vsi)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_del_macvlan param;
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	if (!disp_mgt || !mac)
		return;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	memcpy(param.mac, mac, sizeof(param.mac));
	param.vlan = vlan;
	param.vsi = vsi;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_DEL_MACVLAN, &param, sizeof(param),
		      NULL, 0, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_del_macvlan_resp(void *priv, u16 src_id, u16 msg_id,
					   void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_del_macvlan *param;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	param = (struct nbl_chan_param_del_macvlan *)data;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->del_macvlan,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
			  param->mac, param->vlan, param->vsi);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_DEL_MACVLAN, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_set_decap_set_resp(void *priv, u16 src_id, u16 msg_id,
					     void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(set_decap_set, true,
					   struct nbl_ch_prm_set_decap_set,
					   NBL_CHAN_MSG_SET_DECAP_SET,
					   p->sfid = src_id);
}

static int nbl_disp_add_multi_rule_loc(void *priv, u16 *vsi)
{
	return DIS2RES_2IN_CB_LOC(add_multi_rule, true, vsi, true, int);
}

static int nbl_disp_chan_add_multi_rule_req(void *priv, u16 *vsi)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(vsi, NBL_CHAN_MSG_ADD_MULTI_RULE);
}

static void nbl_disp_chan_add_multi_rule_resp(void *priv, u16 src_id, u16 msg_id,
					      void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(add_multi_rule, true, u16,
					   NBL_CHAN_MSG_ADD_MULTI_RULE, (void)0);
}

static int nbl_disp_del_multi_rule_loc(void *priv, u16 *vsi)
{
	return DIS2RES_2IN_CB_LOC(del_multi_rule, true, vsi, true, int);
}

static int nbl_disp_chan_del_multi_rule_req(void *priv, u16 *vsi)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(vsi, NBL_CHAN_MSG_DEL_MULTI_RULE);
}

static void nbl_disp_chan_del_multi_rule_resp(void *priv, u16 src_id, u16 msg_id,
					      void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(del_multi_rule, true, u16,
					   NBL_CHAN_MSG_DEL_MULTI_RULE, (void)0);
}

static int nbl_disp_cfg_multi_mcast_loc(void *priv, struct nbl_ch_prm_cfg_multi_mcast *param)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	int ret = 0;

	if (param->enable)
		ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->add_multi_mcast,
					NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->vsi);
	else
		NBL_OPS_CALL_LOCK(disp_mgt, res_ops->del_multi_mcast,
				  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->vsi);
	return ret;
}

static int nbl_disp_chan_cfg_multi_mcast_req(void *priv, struct nbl_ch_prm_cfg_multi_mcast *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_CFG_MULTI_MCAST_RULE);
}

static void nbl_disp_chan_cfg_multi_mcast_resp(void *priv, u16 src_id, u16 msg_id,
					       void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_ch_prm_cfg_multi_mcast mcast;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;
	int copy_len;

	copy_len = data_len < sizeof(mcast) ? data_len : sizeof(mcast);
	memset(&mcast, 0, sizeof(mcast));
	if (copy_len)
		memcpy(&mcast, data, copy_len);

	if (mcast.enable)
		ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->add_multi_mcast,
					NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), mcast.vsi);
	else
		NBL_OPS_CALL_LOCK(disp_mgt, res_ops->del_multi_mcast,
				  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), mcast.vsi);
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_CFG_MULTI_MCAST_RULE, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_chan_setup_multi_group_req(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_chan_send_info chan_send;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_SETUP_MULTI_GROUP,
		      NULL, 0, NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_setup_multi_group_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->setup_multi_group,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SETUP_MULTI_GROUP, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_remove_multi_group_req(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_chan_send_info chan_send;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_REMOVE_MULTI_GROUP,
		      NULL, 0, NULL, 0, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_remove_multi_group_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->remove_multi_group,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_REMOVE_MULTI_GROUP, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_chan_register_vsi2q_req(void *priv, u16 vsi_index, u16 vsi_id,
					    u16 queue_offset, u16 queue_num)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_register_vsi2q param = {0};
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.vsi_index = vsi_index;
	param.vsi_id = vsi_id;
	param.queue_offset = queue_offset;
	param.queue_num = queue_num;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_REGISTER_VSI2Q, &param,
		      sizeof(param), NULL, 0, 1);

	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_register_vsi2q_resp(void *priv, u16 src_id, u16 msg_id,
					      void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_register_vsi2q *param = NULL;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;

	param = (struct nbl_chan_param_register_vsi2q *)data;

	err = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->register_vsi2q,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
				param->vsi_index, param->vsi_id,
				param->queue_offset, param->queue_num);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_REGISTER_VSI2Q, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_chan_setup_q2vsi_req(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_SETUP_Q2VSI, &vsi_id,
		      sizeof(vsi_id), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_setup_q2vsi_resp(void *priv, u16 src_id, u16 msg_id,
					   void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	u16 vsi_id;

	vsi_id = *(u16 *)data;

	err = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->setup_q2vsi,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SETUP_Q2VSI, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_remove_q2vsi_req(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_REMOVE_Q2VSI, &vsi_id,
		      sizeof(vsi_id), NULL, 0, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_remove_q2vsi_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	u16 vsi_id;

	vsi_id = *(u16 *)data;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->remove_q2vsi, NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
			  vsi_id);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_REMOVE_Q2VSI, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_chan_setup_rss_req(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_SETUP_RSS, &vsi_id,
		      sizeof(vsi_id), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_setup_rss_resp(void *priv, u16 src_id, u16 msg_id,
					 void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	u16 vsi_id;

	vsi_id = *(u16 *)data;
	err = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->setup_rss, NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
				vsi_id);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SETUP_RSS, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_remove_rss_req(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_REMOVE_RSS, &vsi_id,
		      sizeof(vsi_id), NULL, 0, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_remove_rss_resp(void *priv, u16 src_id, u16 msg_id,
					  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	u16 vsi_id;

	vsi_id = *(u16 *)data;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->remove_rss, NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
			  vsi_id);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_REMOVE_RSS, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_remove_all_queues_req(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_REMOVE_ALL_QUEUES,
		      &vsi_id, sizeof(vsi_id), NULL, 0, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_remove_all_queues_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	u16 vsi_id;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	vsi_id = *(u16 *)data;
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->remove_all_queues,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_REMOVE_ALL_QUEUES, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_chan_cfg_dsch_req(void *priv, u16 vsi_id, bool vld)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_cfg_dsch param = {0};
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.vsi_id = vsi_id;
	param.vld = vld;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_CFG_DSCH, &param, sizeof(param),
		      NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_cfg_dsch_resp(void *priv, u16 src_id, u16 msg_id,
					void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_cfg_dsch *param;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	param = (struct nbl_chan_param_cfg_dsch *)data;

	err = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->cfg_dsch,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->vsi_id, param->vld);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_CFG_DSCH, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_setup_cqs(void *priv, u16 vsi_id, u16 real_qps, bool rss_indir_set)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->setup_cqs,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
				vsi_id, real_qps, rss_indir_set);
	return ret;
}

static int nbl_disp_chan_setup_cqs_req(void *priv, u16 vsi_id, u16 real_qps, bool rss_indir_set)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_setup_cqs param = {0};
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.vsi_id = vsi_id;
	param.real_qps = real_qps;
	param.rss_indir_set = rss_indir_set;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_SETUP_CQS, &param, sizeof(param),
		      NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_setup_cqs_resp(void *priv, u16 src_id, u16 msg_id,
					 void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_setup_cqs param;
	struct nbl_chan_ack_info chan_ack;
	int copy_len;
	int err = NBL_CHAN_RESP_OK;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	memset(&param, 0, sizeof(struct nbl_chan_param_setup_cqs));
	param.rss_indir_set = true;
	copy_len = data_len < sizeof(struct nbl_chan_param_setup_cqs) ?
			data_len : sizeof(struct nbl_chan_param_setup_cqs);
	memcpy(&param, data, copy_len);

	err = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->setup_cqs,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
				param.vsi_id, param.real_qps, param.rss_indir_set);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SETUP_CQS, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_remove_cqs_req(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_REMOVE_CQS, &vsi_id, sizeof(vsi_id),
		      NULL, 0, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_remove_cqs_resp(void *priv, u16 src_id, u16 msg_id,
					  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	u16 vsi_id;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	vsi_id = *(u16 *)data;
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->remove_cqs,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_REMOVE_CQS, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_set_promisc_mode_loc(void *priv, struct nbl_ch_prm_set_promisc_mode *param)
{
	return DIS2RES_2IN_CB_LOC(set_promisc_mode, true, param, true, int);
}

static int nbl_disp_chan_set_promisc_mode_req(void *priv, struct nbl_ch_prm_set_promisc_mode *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_SET_PROSISC_MODE);
}

static void nbl_disp_chan_set_promisc_mode_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(set_promisc_mode, true,
					   struct nbl_ch_prm_set_promisc_mode,
					   NBL_CHAN_MSG_SET_PROSISC_MODE, (void)0);
}

static int nbl_disp_chan_cfg_qdisc_mqprio_req(void *priv, struct nbl_tc_qidsc_param *param)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_CFG_QDISC_MQPRIO,
		      param, sizeof(*param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_cfg_qdisc_mqprio_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_tc_qidsc_param *param = (struct nbl_tc_qidsc_param *)data;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;

	err = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->cfg_qdisc_mqprio,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_CFG_QDISC_MQPRIO, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_chan_set_spoof_check_addr_req(void *priv,
						  struct nbl_ch_prm_set_spoof_check_addr *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_SET_SPOOF_CHECK_ADDR);
}

static void nbl_disp_chan_set_spoof_check_addr_resp(void *priv, u16 src_id, u16 msg_id,
						    void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(set_spoof_check_addr, true,
					   struct nbl_ch_prm_set_spoof_check_addr,
					   NBL_CHAN_MSG_SET_SPOOF_CHECK_ADDR, (void)0);
}

static int nbl_disp_chan_set_vf_spoof_check_req(void *priv,
						struct nbl_ch_prm_set_vf_spoof_check *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_SET_VF_SPOOF_CHECK);
}

static void nbl_disp_chan_set_vf_spoof_check_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(set_vf_spoof_check, true,
					   struct nbl_ch_prm_set_vf_spoof_check,
					   NBL_CHAN_MSG_SET_VF_SPOOF_CHECK, (void)0);
}

static void nbl_disp_chan_get_base_mac_addr_req(void *priv, u8 *mac)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_GET_BASE_MAC_ADDR,
		      NULL, 0, mac, ETH_ALEN, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_base_mac_addr_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	u8 mac[ETH_ALEN];

	NBL_OPS_CALL(res_ops->get_base_mac_addr,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), mac));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_BASE_MAC_ADDR, msg_id, err,
		     mac, ETH_ALEN);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_get_firmware_version_loc(void *priv,
					      struct nbl_ch_prm_get_firmware_version *output)
{
	DIS2RES_1OUT_CB_LOC(get_firmware_version, false, output, false, void);
}

static void nbl_disp_chan_get_firmware_version_req(void *priv,
						   struct nbl_ch_prm_get_firmware_version *output)
{
	(void)DIS2CH_1OUT_RESRET_AS_CHRET_CB_REQ(NBL_CHAN_MSG_GET_FIRMWARE_VERSION, output);
}

static void nbl_disp_chan_get_firmware_version_resp(void *priv, u16 src_id, u16 msg_id,
						    void *data, u32 data_len)
{
	DIS2CH_1OUT_CB_RESP(get_firmware_version, false, NBL_CHAN_MSG_GET_FIRMWARE_VERSION,
			    struct nbl_ch_prm_get_firmware_version, result.sfid = src_id);
}

static int nbl_disp_get_queue_err_stats_loc(void *priv,
					    struct nbl_ch_prm_get_queue_err_stats *param,
					    struct nbl_queue_err_stats *output)
{
	return DIS2RES_2IN_OUT_CB_LOC(get_queue_err_stats, false, param, output, true, int);
}

static int nbl_disp_chan_get_queue_err_stats_req(void *priv,
						 struct nbl_ch_prm_get_queue_err_stats *param,
						 struct nbl_queue_err_stats *output)
{
	return DIS2CH_2IN_OUT_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_GET_QUEUE_ERR_STATS,
						     output);
}

static void nbl_disp_chan_get_queue_err_stats_resp(void *priv, u16 src_id, u16 msg_id,
						   void *data, u32 data_len)
{
	DIS2CH_2IN_OUT_CB_RESP(get_queue_err_stats, false,
			       struct nbl_ch_prm_get_queue_err_stats,
			       NBL_CHAN_MSG_GET_QUEUE_ERR_STATS,
			       struct nbl_queue_err_stats,
			       p->sfid = src_id);
}

static int nbl_disp_get_eth_abnormal_stats_loc(void *priv, u8 *eth_id,
					       struct nbl_eth_abnormal_stats *output)
{
	return DIS2RES_2IN_OUT_CB_LOC(get_eth_abnormal_stats, false, eth_id, output, true, int);
}

static int nbl_disp_chan_get_eth_abnormal_stats_req(void *priv, u8 *eth_id,
						    struct nbl_eth_abnormal_stats *output)
{
	return DIS2CH_2IN_OUT_RESRET_AS_CHRET_CB_REQ(eth_id, NBL_CHAN_MSG_GET_ETH_ABNORMAL_STATS,
					    output);
}

static void nbl_disp_chan_get_eth_abnormal_stats_resp(void *priv, u16 src_id, u16 msg_id,
						      void *data, u32 data_len)
{
	DIS2CH_2IN_OUT_CB_RESP(get_eth_abnormal_stats, false, u8,
			       NBL_CHAN_MSG_GET_ETH_ABNORMAL_STATS,
			       struct nbl_eth_abnormal_stats, (void)0);
}

static int nbl_disp_get_coalesce_loc(void *priv,
				     struct nbl_ch_prm_get_coalesce_req *param,
				     struct nbl_ch_prm_get_coalesce *ec)
{
	return DIS2RES_2IN_OUT_CB_LOC(get_coalesce, false, param, ec, true, int);
}

static int nbl_disp_chan_get_coalesce_req(void *priv,
					  struct nbl_ch_prm_get_coalesce_req *param,
					  struct nbl_ch_prm_get_coalesce *ec)
{
	return DIS2CH_2IN_OUT_RESRET_AS_CHRET_CB_REQ(param,
						     NBL_CHAN_MSG_GET_COALESCE, ec);
}

static void nbl_disp_chan_get_coalesce_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	DIS2CH_2IN_OUT_CB_RESP(get_coalesce, false,
			       struct nbl_ch_prm_get_coalesce_req,
			       NBL_CHAN_MSG_GET_COALESCE,
			       struct nbl_ch_prm_get_coalesce,
			       p->sfid = src_id);
}

static int nbl_disp_set_msix_fast_restrain_loc(void *priv,
					       struct nbl_set_msix_fast_restrain_param *param)
{
	return DIS2RES_2IN_CB_LOC(set_msix_fast_restrain, true, param, true, int);
}

static int nbl_disp_set_suppress_level_fast_loc(void *priv,
						struct nbl_set_intr_suppress_level_fast_param *prm)
{
	return DIS2RES_2IN_CB_LOC(set_intr_suppress_level_fast, true, prm, true, int);
}

static int nbl_disp_set_coalesce_loc(void *priv,
				     struct nbl_ch_prm_set_coalesce *param)
{
	return DIS2RES_2IN_CB_LOC(set_coalesce, true, param, true, int);
}

static int nbl_disp_chan_set_coalesce_req(void *priv,
					  struct nbl_ch_prm_set_coalesce *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_SET_COALESCE);
}

static void nbl_disp_chan_set_coalesce_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(set_coalesce, true,
					   struct nbl_ch_prm_set_coalesce,
					   NBL_CHAN_MSG_SET_COALESCE,
					   p->sfid = src_id);
}

static int nbl_disp_chan_get_rxfh_indir_size_req(void *priv, u16 *vsi_id, u32 *rxfh_indir_size)
{
	return DIS2CH_2IN_OUT_RESRET_AS_CHRET_CB_REQ(vsi_id,
						     NBL_CHAN_MSG_GET_RXFH_INDIR_SIZE,
						     rxfh_indir_size);
}

static void nbl_disp_chan_get_rxfh_indir_size_resp(void *priv, u16 src_id, u16 msg_id,
						   void *data, u32 data_len)
{
	DIS2CH_2IN_OUT_CB_RESP(get_rxfh_indir_size, false, u16,
			       NBL_CHAN_MSG_GET_RXFH_INDIR_SIZE, u32, (void)0);
}

static void nbl_disp_chan_get_rxfh_indir_req(void *priv, u16 vsi_id, u32 *indir, u32 indir_size)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_get_rxfh_indir param = {0};
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.vsi_id = vsi_id;
	param.rxfh_indir_size = indir_size;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_GET_RXFH_INDIR, &param,
		      sizeof(param), indir, indir_size * sizeof(u32), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_rxfh_indir_resp(void *priv, u16 src_id, u16 msg_id,
					      void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_get_rxfh_indir *param;
	struct nbl_chan_ack_info chan_ack;
	u32 *indir;
	int ret = NBL_CHAN_RESP_OK;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	param = (struct nbl_chan_param_get_rxfh_indir *)data;

	indir = kcalloc(param->rxfh_indir_size, sizeof(u32), GFP_KERNEL);
	NBL_OPS_CALL(res_ops->get_rxfh_indir,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->vsi_id, indir));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_RXFH_INDIR, msg_id, ret,
		     indir, param->rxfh_indir_size * sizeof(u32));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);

	kfree(indir);
}

static void nbl_disp_chan_set_rxfh_indir_resp(void *priv, u16 src_id, u16 msg_id,
					      void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_set_rxfh_indir *param;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	param = (struct nbl_chan_param_set_rxfh_indir *)data;

	err = NBL_OPS_CALL(res_ops->set_rxfh_indir,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
			    param->vsi_id, param->indir, param->indir_size));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SET_RXFH_INDIR, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_chan_get_rxfh_rss_key_req(void *priv,
					      struct nbl_ch_prm_get_rxfh_rss_key *param,
					      struct nbl_ch_prm_get_rxfh_key *output)
{
	return DIS2CH_2IN_OUT_RESRET_AS_CHRET_CB_REQ(param,
						     NBL_CHAN_MSG_GET_RXFH_RSS_KEY,
						     output);
}

static void nbl_disp_chan_get_rxfh_rss_key_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	DIS2CH_2IN_OUT_CB_RESP(get_rxfh_rss_key, false, struct nbl_ch_prm_get_rxfh_rss_key,
			       NBL_CHAN_MSG_GET_RXFH_RSS_KEY, struct nbl_ch_prm_get_rxfh_key,
			       (void)0);
}

static int nbl_disp_set_rxfh_rss_key_loc(void *priv,
					 struct nbl_ch_prm_set_rxfh_rss_key *param)
{
	return DIS2RES_2IN_CB_LOC(set_rxfh_rss_key, false, param, true, int);
}

static int nbl_disp_chan_set_rxfh_rss_key_req(void *priv,
					      struct nbl_ch_prm_set_rxfh_rss_key *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_SET_RXFH_RSS_KEY);
}

static void nbl_disp_chan_set_rxfh_rss_key_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(set_rxfh_rss_key, false,
					   struct nbl_ch_prm_set_rxfh_rss_key,
					   NBL_CHAN_MSG_SET_RXFH_RSS_KEY, (void)0);
}

static int nbl_disp_get_rxfh_rss_alg_sel_loc(void *priv, u16 *vsi_id, u8 *alg_sel)
{
	return DIS2RES_2IN_OUT_CB_LOC(get_rss_alg_sel, false, vsi_id, alg_sel, true, int);
}

static int nbl_disp_chan_get_rxfh_rss_alg_sel_req(void *priv, u16 *vsi_id, u8 *alg_sel)
{
	return DIS2CH_2IN_OUT_RESRET_AS_CHRET_CB_REQ(vsi_id,
						     NBL_CHAN_MSG_GET_RXFH_RSS_ALG_SEL,
						     alg_sel);
}

static void nbl_disp_chan_get_rxfh_rss_alg_sel_resp(void *priv, u16 src_id, u16 msg_id,
						    void *data, u32 data_len)
{
	DIS2CH_2IN_OUT_CB_RESP(get_rss_alg_sel, false, u16,
			       NBL_CHAN_MSG_GET_RXFH_RSS_ALG_SEL, u8, (void)0);
}

static int nbl_disp_set_rxfh_rss_alg_sel_loc(void *priv,
					     struct nbl_ch_prm_set_rxfh_rss_alg_sel *param)
{
	return DIS2RES_2IN_CB_LOC(set_rss_alg_sel, false, param, true, int);
}

static int nbl_disp_chan_set_rxfh_rss_alg_sel_req(void *priv,
						  struct nbl_ch_prm_set_rxfh_rss_alg_sel *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_SET_RXFH_RSS_ALG_SEL);
}

static void nbl_disp_chan_set_rxfh_rss_alg_sel_resp(void *priv, u16 src_id, u16 msg_id,
						    void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(set_rss_alg_sel, false,
					   struct nbl_ch_prm_set_rxfh_rss_alg_sel,
					   NBL_CHAN_MSG_SET_RXFH_RSS_ALG_SEL, (void)0);
}

static int nbl_disp_get_hash_fields(void *priv, u16 vsi_id, int flow_type, u64 *hash_fields)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL(res_ops->get_hash_fields,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id, flow_type, hash_fields));
	return ret;
}

static int nbl_disp_chan_get_hash_fields_req(void *priv,
					     u16 vsi_id, int flow_type, u64 *hash_fields)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_get_hash_fields param = {0};
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.vsi_id = vsi_id;
	param.flow_type = flow_type;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_GET_HASH_FIELDS, &param,
		      sizeof(param), hash_fields, sizeof(hash_fields), 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_hash_fields_resp(void *priv, u16 src_id, u16 msg_id,
					       void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_get_hash_fields *param;
	struct nbl_chan_ack_info chan_ack;
	u64 hash_fields = 0;
	int err = NBL_CHAN_RESP_OK;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	param = (struct nbl_chan_param_get_hash_fields *)data;

	err = NBL_OPS_CALL(res_ops->get_hash_fields,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
			    param->vsi_id, param->flow_type, &hash_fields));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_HASH_FIELDS, msg_id, err,
		     &hash_fields, sizeof(hash_fields));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_set_hash_fields(void *priv, u16 vsi_id, int flow_type, u64 hash_fields)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL(res_ops->set_hash_fields,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id, flow_type, hash_fields));
	return ret;
}

static int nbl_disp_chan_set_hash_fields_req(void *priv, u16 vsi_id, int flow_type, u64 hash_fields)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_set_hash_fields param = {0};
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.vsi_id = vsi_id;
	param.flow_type = flow_type;
	param.hash_fields = hash_fields;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_SET_HASH_FIELDS, &param,
		      sizeof(param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_set_hash_fields_resp(void *priv, u16 src_id, u16 msg_id,
					       void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_set_hash_fields *param;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	param = (struct nbl_chan_param_set_hash_fields *)data;

	err = NBL_OPS_CALL(res_ops->set_hash_fields,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
			    param->vsi_id, param->flow_type, param->hash_fields));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SET_HASH_FIELDS, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_chan_get_phy_caps_req(void *priv, u8 *eth_id, struct nbl_phy_caps *phy_caps)
{
	return DIS2CH_2IN_OUT_RESRET_AS_CHRET_CB_REQ(eth_id, NBL_CHAN_MSG_GET_PHY_CAPS, phy_caps);
}

static void nbl_disp_chan_get_phy_caps_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	DIS2CH_2IN_OUT_CB_RESP(get_phy_caps, false, u8,
			       NBL_CHAN_MSG_GET_PHY_CAPS, struct nbl_phy_caps, (void)0);
}

static int nbl_disp_chan_set_sfp_state_req(void *priv, struct nbl_ch_prm_set_sfp_state *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_SET_SFP_STATE);
}

static void nbl_disp_chan_set_sfp_state_resp(void *priv, u16 src_id, u16 msg_id,
					     void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(set_sfp_state, false,
					   struct nbl_ch_prm_set_sfp_state,
					   NBL_CHAN_MSG_SET_SFP_STATE, (void)0);
}

static int nbl_disp_chan_register_rdma_req(void *priv, u16 *vsi_id,
					   struct nbl_rdma_register_param *param)
{
	return DIS2CH_2IN_OUT_RESRET_AS_CHRET_CB_REQ(vsi_id, NBL_CHAN_MSG_REGISTER_RDMA, param);
}

static void nbl_disp_chan_register_rdma_resp(void *priv, u16 src_id, u16 msg_id,
					     void *data, u32 data_len)
{
	DIS2CH_2IN_OUT_CB_RESP(register_rdma, true, u16,
			       NBL_CHAN_MSG_REGISTER_RDMA,
			       struct nbl_rdma_register_param, (void)0);
}

static int nbl_disp_chan_unregister_rdma_req(void *priv, u16 *vsi_id)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(vsi_id, NBL_CHAN_MSG_UNREGISTER_RDMA);
}

static void nbl_disp_chan_unregister_rdma_resp(void *priv, u16 src_id, u16 msg_id,
					       void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(unregister_rdma, true, u16,
					   NBL_CHAN_MSG_UNREGISTER_RDMA, (void)0);
}

static u64 nbl_disp_chan_get_real_hw_addr_req(void *priv, u16 *vsi_id)
{
	return DIS2CH_2IN_RESPMEM2RET_CB_REQ(vsi_id, NBL_CHAN_MSG_GET_REAL_HW_ADDR,
					      struct nbl_ch_prm_u64_comm, val, u64);
}

static void nbl_disp_chan_get_real_hw_addr_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	DIS2CH_2IN_RESPMEM2RET_CB_RESP(get_real_hw_addr, false, u16 *,
				       NBL_CHAN_MSG_GET_REAL_HW_ADDR,
				       struct nbl_ch_prm_u64_comm, val, u64, (void)0);
}

static u16 nbl_disp_chan_get_function_id_req(void *priv, u16 *vsi_id)
{
	return DIS2CH_2IN_RESPMEM2RET_CB_REQ(vsi_id, NBL_CHAN_MSG_GET_FUNCTION_ID,
					     struct nbl_ch_prm_u16_comm, val, u16);
}

static void nbl_disp_chan_get_function_id_resp(void *priv, u16 src_id, u16 msg_id,
					       void *data, u32 data_len)
{
	DIS2CH_2IN_RESPMEM2RET_CB_RESP(get_function_id, false, u16 *,
				       NBL_CHAN_MSG_GET_FUNCTION_ID,
			       struct nbl_ch_prm_u16_comm, val, u16, (void)0);
}

static int nbl_disp_chan_get_real_bdf_req(void *priv, u16 *vsi_id,
					  struct nbl_ch_prm_get_real_bdf *output)
{
	return DIS2CH_2IN_OUT_RESRET_AS_CHRET_CB_REQ(vsi_id, NBL_CHAN_MSG_GET_REAL_BDF, output);
}

static void nbl_disp_chan_get_real_bdf_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	DIS2CH_2IN_OUT_CB_RESP(get_real_bdf, false, u16,
			       NBL_CHAN_MSG_GET_REAL_BDF,
			       struct nbl_ch_prm_get_real_bdf, (void)0);
}

static int nbl_disp_chan_clear_accel_flow_req(void *priv, u16 *vsi_id)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(vsi_id, NBL_CHAN_MSG_CLEAR_ACCEL_FLOW);
}

static void nbl_disp_chan_clear_accel_flow_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(clear_accel_flow, true, u16,
					   NBL_CHAN_MSG_CLEAR_ACCEL_FLOW, (void)0);
}

static int nbl_disp_chan_clear_flow_req(void *priv, u16 *vsi_id)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(vsi_id, NBL_CHAN_MSG_CLEAR_FLOW);
}

static void nbl_disp_chan_clear_flow_resp(void *priv, u16 src_id, u16 msg_id,
					  void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(clear_flow, true, u16,
					   NBL_CHAN_MSG_CLEAR_FLOW, (void)0);
}

static int nbl_disp_chan_clear_queues_req(void *priv, u16 *vsi_id)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(vsi_id, NBL_CHAN_MSG_CLEAR_QUEUE);
}

static void nbl_disp_chan_clear_queues_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(clear_queues, true, u16,
					   NBL_CHAN_MSG_CLEAR_QUEUE, (void)0);
}

static int nbl_disp_chan_disable_phy_flow_req(void *priv, u8 *eth_id)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(eth_id, NBL_CHAN_MSG_DISABLE_PHY_FLOW);
}

static void nbl_disp_chan_disable_phy_flow_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(disable_phy_flow, true, u8,
					   NBL_CHAN_MSG_DISABLE_PHY_FLOW, (void)0);
}

static int nbl_disp_chan_enable_phy_flow_req(void *priv, u8 *eth_id)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(eth_id, NBL_CHAN_MSG_ENABLE_PHY_FLOW);
}

static void nbl_disp_chan_enable_phy_flow_resp(void *priv, u16 src_id, u16 msg_id,
					       void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(enable_phy_flow, true, u8,
					   NBL_CHAN_MSG_ENABLE_PHY_FLOW, (void)0);
}

static void nbl_disp_chan_init_acl_req(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_INIT_ACL, NULL, 0, NULL, 0, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_init_acl_resp(void *priv, u16 src_id, u16 msg_id,
					void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->init_acl, NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_INIT_ACL, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_uninit_acl_req(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_UNINIT_ACL, NULL, 0, NULL, 0, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_uninit_acl_resp(void *priv, u16 src_id, u16 msg_id,
					  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->uninit_acl, NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_UNINIT_ACL, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_chan_set_upcall_rule_req(void *priv,
					     struct nbl_ch_prm_set_upcall *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_SET_UPCALL_RULE);
}

static void nbl_disp_chan_set_upcall_rule_resp(void *priv, u16 src_id, u16 msg_id,
					       void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(set_upcall_rule, false,
					   struct nbl_ch_prm_set_upcall,
					   NBL_CHAN_MSG_SET_UPCALL_RULE, (void)0);
}

static int nbl_disp_chan_unset_upcall_rule_req(void *priv, u8 *eth_id)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(eth_id, NBL_CHAN_MSG_UNSET_UPCALL_RULE);
}

static void nbl_disp_chan_unset_upcall_rule_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(unset_upcall_rule, false, u8,
					   NBL_CHAN_MSG_UNSET_UPCALL_RULE, (void)0);
}

static int nbl_disp_chan_set_shaping_dport_vld_req(void *priv,
						   struct nbl_ch_prm_set_func_vld *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_SET_SHAPING_DPORT_VLD);
}

static void nbl_disp_chan_set_shaping_dport_vld_resp(void *priv, u16 src_id, u16 msg_id,
						     void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(set_shaping_dport_vld, false,
					   struct nbl_ch_prm_set_func_vld,
					   NBL_CHAN_MSG_SET_SHAPING_DPORT_VLD, (void)0);
}

static int nbl_disp_chan_set_dport_fc_th_vld_req(void *priv,
						 struct nbl_ch_prm_set_func_vld *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_SET_DPORT_FC_TH_VLD);
}

static void nbl_disp_chan_set_dport_fc_th_vld_resp(void *priv, u16 src_id, u16 msg_id,
						   void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(set_dport_fc_th_vld, false,
					   struct nbl_ch_prm_set_func_vld,
					   NBL_CHAN_MSG_SET_DPORT_FC_TH_VLD, (void)0);
}

static int nbl_disp_get_my_pf_loc(void *priv, u16 *sfid, u8 *my_pf)
{
	return DIS2RES_2IN_OUT_CB_LOC(get_my_pf, false, sfid, my_pf, true, int);
}

static int nbl_disp_chan_get_my_pf_req(void *priv, u16 *sfid, u8 *my_pf)
{
	return DIS2CH_2IN_OUT_RESRET_AS_CHRET_CB_REQ(sfid, NBL_CHAN_MSG_GET_MY_PF, my_pf);
}

static void nbl_disp_chan_get_my_pf_resp(void *priv, u16 src_id, u16 msg_id,
					 void *data, u32 data_len)
{
	DIS2CH_2IN_OUT_CB_RESP(get_my_pf, false, u16, NBL_CHAN_MSG_GET_MY_PF,
			       u8, *p = src_id);
}

static int nbl_disp_chan_get_eth_id_req(void *priv,
					struct nbl_ch_prm_get_eth_id *param,
					struct nbl_ch_prm_get_eth_id *output)
{
	return DIS2CH_2IN_OUT_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_GET_ETH_ID, output);
}

static void nbl_disp_chan_get_eth_id_resp(void *priv, u16 src_id, u16 msg_id,
					  void *data, u32 data_len)
{
	DIS2CH_2IN_OUT_CB_RESP(get_eth_id, false, struct nbl_ch_prm_get_eth_id,
			       NBL_CHAN_MSG_GET_ETH_ID,
			       struct nbl_ch_prm_get_eth_id, (void)0);
}

static int nbl_disp_register_vsi2q(void *priv, u16 vsi_index, u16 vsi_id,
				   u16 queue_offset, u16 queue_num)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->register_vsi2q,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_index, vsi_id,
				 queue_offset, queue_num);
}

static int nbl_disp_setup_q2vsi(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->setup_q2vsi,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);
}

static void nbl_disp_remove_q2vsi(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->remove_q2vsi,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);
}

static int nbl_disp_setup_rss(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->setup_rss,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);
}

static void nbl_disp_remove_rss(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->remove_rss,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);
}

static void nbl_disp_remove_all_queues(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->remove_all_queues,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);
}

static int nbl_disp_cfg_dsch(void *priv, u16 vsi_id, bool vld)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->cfg_dsch,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id, vld);
	return ret;
}

static void nbl_disp_remove_cqs(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->remove_cqs,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);
}

static u8 *nbl_disp_get_msix_irq_enable_info(void *priv, u16 global_vector_id,
					     u32 *irq_data, u32 *irq_mask_data)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	if (!disp_mgt)
		return NULL;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	return NBL_OPS_CALL(res_ops->get_msix_irq_enable_info,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), global_vector_id,
			    irq_data, irq_mask_data));
}

static int nbl_disp_add_macvlan(void *priv, u8 *mac, u16 vlan, u16 vsi)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	if (!disp_mgt || !mac)
		return -EINVAL;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->add_macvlan,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), mac, vlan, vsi);
	return ret;
}

static void nbl_disp_del_macvlan(void *priv, u8 *mac, u16 vlan, u16 vsi)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	if (!disp_mgt || !mac)
		return;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->del_macvlan,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), mac, vlan, vsi);
}

static int nbl_disp_setup_multi_group(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->setup_multi_group,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
}

static void nbl_disp_remove_multi_group(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->remove_multi_group,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
}

static int nbl_disp_setup_ecn_stats(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->setup_ecn_stats,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
}

static void nbl_disp_remove_ecn_stats(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->remove_ecn_stats,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
}

static int nbl_disp_alloc_kt(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->alloc_kt,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
}

static void nbl_disp_get_net_stats(void *priv, struct nbl_stats *net_stats)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->get_net_stats, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), net_stats));
}

static void nbl_disp_get_private_stat_len(void *priv, u32 *len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->get_private_stat_len,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), len);
}

static int nbl_disp_get_pause_stats_loc(void *priv, u32 *eth_id,
					struct nbl_pause_stats *output)
{
	return DIS2RES_2IN_OUT_CB_LOC(get_pause_stats, false, eth_id, output, true, int);
}

static int nbl_disp_chan_get_pause_stats_req(void *priv, u32 *eth_id,
					     struct nbl_pause_stats *output)
{
	return DIS2CH_2IN_OUT_RESRET_AS_CHRET_CB_REQ(eth_id, NBL_CHAN_MSG_GET_PAUSE_STATS,
					     output);
}

static void nbl_disp_chan_get_pause_stats_resp(void *priv, u16 src_id, u16 msg_id,
					       void *data, u32 data_len)
{
	DIS2CH_2IN_OUT_CB_RESP(get_pause_stats, false, u32,
			       NBL_CHAN_MSG_GET_PAUSE_STATS,
			       struct nbl_pause_stats, (void)0);
}

static void nbl_disp_get_private_stat_data(void *priv, u32 eth_id, u64 *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->get_private_stat_data,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, data, data_len));
}

static void nbl_disp_get_private_stat_data_req(void *priv, u32 eth_id, u64 *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_chan_param_get_private_stat_data param = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.eth_id = eth_id;
	param.data_len = data_len;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_GET_ETH_STATS, &param,
		      sizeof(param), data, data_len, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_private_stat_data_resp(void *priv, u16 src_id, u16 msg_id,
						     void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_get_private_stat_data *param;
	struct nbl_chan_ack_info chan_ack;
	u64 *recv_data;
	int ret = NBL_CHAN_RESP_OK;

	param = (struct nbl_chan_param_get_private_stat_data *)data;
	recv_data = kmalloc(param->data_len, GFP_ATOMIC);
	if (!recv_data) {
		dev_err(dev, "Allocate memory to private_stat_data failed\n");
		return;
	}

	NBL_OPS_CALL(res_ops->get_private_stat_data,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
		      param->eth_id, recv_data, param->data_len));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_ETH_STATS, msg_id,
		     ret, recv_data, param->data_len);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);

	kfree(recv_data);
}

static int nbl_disp_get_eth_ctrl_stats_loc(void *priv, u32 *eth_id,
					   struct nbl_eth_ctrl_stats *output)
{
	return DIS2RES_2IN_OUT_CB_LOC(get_eth_ctrl_stats, false, eth_id, output, true, int);
}

static int nbl_disp_chan_get_eth_ctrl_stats_req(void *priv, u32 *eth_id,
						struct nbl_eth_ctrl_stats *output)
{
	return DIS2CH_2IN_OUT_RESRET_AS_CHRET_CB_REQ(eth_id, NBL_CHAN_MSG_GET_ETH_CTRL_STATS,
						     output);
}

static void nbl_disp_chan_get_eth_ctrl_stats_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	DIS2CH_2IN_OUT_CB_RESP(get_eth_ctrl_stats, false, u32,
			       NBL_CHAN_MSG_GET_ETH_CTRL_STATS,
			       struct nbl_eth_ctrl_stats, (void)0);
}

static int nbl_disp_get_eth_mac_stats_loc(void *priv, u32 *eth_id,
					  struct nbl_eth_mac_stats *output)
{
	return DIS2RES_2IN_OUT_CB_LOC(get_eth_mac_stats, false, eth_id, output, true, int);
}

static int nbl_disp_chan_get_eth_mac_stats_req(void *priv, u32 *eth_id,
					       struct nbl_eth_mac_stats *output)
{
	return DIS2CH_2IN_OUT_RESRET_AS_CHRET_CB_REQ(eth_id, NBL_CHAN_MSG_GET_ETH_MAC_STATS,
						     output);
}

static void nbl_disp_chan_get_eth_mac_stats_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len)
{
	DIS2CH_2IN_OUT_CB_RESP(get_eth_mac_stats, false, u32,
			       NBL_CHAN_MSG_GET_ETH_MAC_STATS,
			       struct nbl_eth_mac_stats, (void)0);
}

static int nbl_disp_get_rmon_stats_loc(void *priv, u32 *eth_id,
				       struct nbl_rmon_stats *output)
{
	return DIS2RES_2IN_OUT_CB_LOC(get_rmon_stats, false, eth_id, output, true, int);
}

static int nbl_disp_chan_get_rmon_stats_req(void *priv, u32 *eth_id,
					    struct nbl_rmon_stats *output)
{
	return DIS2CH_2IN_OUT_RESRET_AS_CHRET_CB_REQ(eth_id, NBL_CHAN_MSG_GET_RMON_STATS,
						     output);
}

static void nbl_disp_chan_get_rmon_stats_resp(void *priv, u16 src_id, u16 msg_id,
					      void *data, u32 data_len)
{
	DIS2CH_2IN_OUT_CB_RESP(get_rmon_stats, false, u32,
			       NBL_CHAN_MSG_GET_RMON_STATS,
			       struct nbl_rmon_stats, (void)0);
}

static void nbl_disp_get_rmon_hist_range(void *priv, const struct ethtool_rmon_hist_range **range)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	return NBL_OPS_CALL(res_ops->get_rmon_hist_range,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), range));
}

static void nbl_disp_fill_private_stat_strings(void *priv, u8 *strings)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->fill_private_stat_strings,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), strings);
}

static u16 nbl_disp_get_max_desc_num(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	u16 ret = 0;

	ret = NBL_OPS_CALL(res_ops->get_max_desc_num, ());
	return ret;
}

static u16 nbl_disp_get_min_desc_num(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	u16 ret = 0;

	ret = NBL_OPS_CALL(res_ops->get_min_desc_num, ());
	return ret;
}

static int nbl_disp_cfg_qdisc_mqprio(void *priv, struct nbl_tc_qidsc_param *param)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->cfg_qdisc_mqprio,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param);
	return ret;
}

static int nbl_disp_set_spoof_check_addr_loc(void *priv,
					     struct nbl_ch_prm_set_spoof_check_addr *param)
{
	return DIS2RES_2IN_CB_LOC(set_spoof_check_addr, true, param, true, int);
}

static int nbl_disp_set_vf_spoof_check_loc(void *priv,
					   struct nbl_ch_prm_set_vf_spoof_check *param)
{
	return DIS2RES_2IN_CB_LOC(set_vf_spoof_check, true, param, true, int);
}

static void nbl_disp_get_base_mac_addr(void *priv, u8 *mac)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->get_base_mac_addr,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), mac);
}

static int nbl_disp_cfg_txrx_vlan_loc(void *priv,
				      struct nbl_cfg_txrx_vlan_param *param)
{
	return DIS2RES_2IN_CB_LOC(cfg_txrx_vlan, false, param, true, int);
}

static void nbl_disp_get_rep_stats_loc(void *priv, struct nbl_get_rep_stats_param *param,
				       struct nbl_rep_stats *output)
{
	DIS2RES_2IN_OUT_CB_LOC(get_rep_stats, false, param, output, false, void);
}

static u16 nbl_disp_get_rep_index_loc(void *priv, u16 *rep_vsi_id)
{
	return DIS2RES_2IN_CB_LOC(get_rep_index, false, rep_vsi_id, true, u16);
}

static void nbl_disp_get_queue_stats_loc(void *priv,
					 struct nbl_get_queue_stats_param *param,
					 struct nbl_queue_stats *output)
{
	DIS2RES_2IN_OUT_CB_LOC(get_queue_stats, false, param, output, false, void);
}

static int nbl_disp_get_rxfh_indir_size_loc(void *priv, u16 *vsi_id, u32 *rxfh_indir_size)
{
	return DIS2RES_2IN_OUT_CB_LOC(get_rxfh_indir_size, false, vsi_id,
				      rxfh_indir_size, true, int);
}

static void nbl_disp_get_rxfh_rss_key_size(void *priv, u32 *rxfh_rss_key_size)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->get_rxfh_rss_key_size,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), rxfh_rss_key_size));
}

static void nbl_disp_get_rxfh_indir(void *priv, u16 vsi_id, u32 *indir, u32 indir_size)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->get_rxfh_indir, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id, indir));
}

static int nbl_disp_set_rxfh_indir(void *priv, u16 vsi_id, const u32 *indir, u32 indir_size)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL(res_ops->set_rxfh_indir,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id, indir, indir_size));
	return ret;
}

static int nbl_disp_chan_set_rxfh_indir_req(void *priv,
					    u16 vsi_id, const u32 *indir, u32 indir_size)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_set_rxfh_indir *param = NULL;
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;
	int ret = 0;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param = kzalloc(sizeof(*param), GFP_KERNEL);
	if (!param)
		return -ENOMEM;

	param->vsi_id = vsi_id;
	param->indir_size = indir_size;
	memcpy(param->indir, indir, indir_size * sizeof(param->indir[0]));

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_SET_RXFH_INDIR, param,
		      sizeof(*param), NULL, 0, 1);
	ret = chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
	kfree(param);
	return ret;
}

static int nbl_disp_get_rxfh_rss_key_loc(void *priv,
					 struct nbl_ch_prm_get_rxfh_rss_key *param,
					 struct nbl_ch_prm_get_rxfh_key *output)
{
	return DIS2RES_2IN_OUT_CB_LOC(get_rxfh_rss_key, false, param, output, true, int);
}

static int nbl_disp_cfg_rx_half_offload_loc(void *priv,
					    struct nbl_cfg_rx_half_offload_param *param)
{
	return DIS2RES_2IN_CB_LOC(cfg_rx_half_offload, false, param, true, int);
}

static int nbl_disp_cfg_rx_vlan_parse_loc(void *priv,
					  struct nbl_ch_prm_cfg_rx_vlan_parse *param)
{
	return DIS2RES_2IN_CB_LOC(cfg_rx_vlan_parse, false, param, true, int);
}

static int nbl_disp_chan_cfg_rx_vlan_parse_req(void *priv,
					       struct nbl_ch_prm_cfg_rx_vlan_parse *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_CFG_RX_VLAN_PARSE);
}

static void nbl_disp_chan_cfg_rx_vlan_parse_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(cfg_rx_vlan_parse, false,
					   struct nbl_ch_prm_cfg_rx_vlan_parse,
					   NBL_CHAN_MSG_CFG_RX_VLAN_PARSE, (void)0);
}

static int nbl_disp_cfg_rss_hash_loc(void *priv,
				     struct nbl_ch_prm_cfg_rss_hash *param)
{
	return DIS2RES_2IN_CB_LOC(cfg_rss_hash, false, param, true, int);
}

static int nbl_disp_chan_cfg_rss_hash_req(void *priv,
					  struct nbl_ch_prm_cfg_rss_hash *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_CFG_RSS_HASH);
}

static void nbl_disp_chan_cfg_rss_hash_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(cfg_rss_hash, false,
					   struct nbl_ch_prm_cfg_rss_hash,
					   NBL_CHAN_MSG_CFG_RSS_HASH, (void)0);
}

static int nbl_disp_get_phy_caps_loc(void *priv, u8 *eth_id, struct nbl_phy_caps *phy_caps)
{
	return DIS2RES_2IN_OUT_CB_LOC(get_phy_caps, false, eth_id, phy_caps, true, int);
}

static int nbl_disp_set_sfp_state_loc(void *priv, struct nbl_ch_prm_set_sfp_state *param)
{
	return DIS2RES_2IN_CB_LOC(set_sfp_state, false, param, true, int);
}

static void nbl_disp_dump_flow(void *priv, struct seq_file *m)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->dump_flow, NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), m);
}

static void nbl_disp_dump_func_info(void *priv, struct seq_file *m)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	if (!disp_mgt)
		return;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->dump_func_info, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), m));
}

static int nbl_disp_get_eth_id_loc(void *priv,
				   struct nbl_ch_prm_get_eth_id *param,
				   struct nbl_ch_prm_get_eth_id *output)
{
	return DIS2RES_2IN_OUT_CB_LOC(get_eth_id, false, param, output, true, int);
}

static void nbl_disp_get_rep_feature(void *priv,
				     struct nbl_register_net_result *register_result)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->get_rep_feature,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), register_result));
}

static int nbl_disp_set_eswitch_mode_loc(void *priv, u16 *switch_mode)
{
	return DIS2RES_2IN_CB_LOC(set_eswitch_mode, false, switch_mode, true, int);
}

static u16 nbl_disp_get_eswitch_mode(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	u16 ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL(res_ops->get_eswitch_mode, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
	return ret;
}

static int nbl_disp_alloc_rep_data_loc(void *priv, struct nbl_alloc_rep_data_param *param)
{
	return DIS2RES_2IN_CB_LOC(alloc_rep_data, false, param, true, int);
}

static void nbl_disp_free_rep_data(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->free_rep_data, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static void nbl_disp_set_rep_netdev_info(void *priv, void *rep_data)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->set_rep_netdev_info,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), rep_data));
}

static void nbl_disp_unset_rep_netdev_info(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->unset_rep_netdev_info, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static struct net_device *nbl_disp_get_rep_netdev_info(void *priv, u16 rep_data_index)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	return NBL_OPS_CALL(res_ops->get_rep_netdev_info, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
			    rep_data_index));
}

static int nbl_disp_set_lag_status_loc(void *priv, bool *lag_en)
{
	return DIS2RES_2IN_CB_LOC(set_lag_status, false, lag_en, true, int);
}

static int nbl_disp_enable_lag_protocol_loc(void *priv,
					    struct nbl_ch_prm_enable_lag_protocol *param)
{
	return DIS2RES_2IN_CB_LOC(enable_lag_protocol, false, param, true, int);
}

static int nbl_disp_chan_cfg_lag_hash_algorithm_req(void *priv,
						    struct nbl_ch_prm_cfg_lag_hash_algorithm *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_CFG_LAG_HASH_ALGORITHM);
}

static void nbl_disp_chan_cfg_lag_hash_algorithm_resp(void *priv, u16 src_id, u16 msg_id,
						      void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(cfg_lag_hash_algorithm, false,
					   struct nbl_ch_prm_cfg_lag_hash_algorithm,
					   NBL_CHAN_MSG_CFG_LAG_HASH_ALGORITHM, (void)0);
}

static int nbl_disp_cfg_lag_hash_algorithm_loc(void *priv,
					       struct nbl_ch_prm_cfg_lag_hash_algorithm *param)
{
	return DIS2RES_2IN_CB_LOC(cfg_lag_hash_algorithm, false, param, true, int);
}

static int nbl_disp_chan_cfg_lag_member_fwd_req(void *priv,
						struct nbl_ch_prm_cfg_lag_member_fwd *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_CFG_LAG_MEMBER_FWD);
}

static void nbl_disp_chan_cfg_lag_member_fwd_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(cfg_lag_member_fwd, false,
					   struct nbl_ch_prm_cfg_lag_member_fwd,
					   NBL_CHAN_MSG_CFG_LAG_MEMBER_FWD, (void)0);
}

static int nbl_disp_cfg_lag_member_fwd_loc(void *priv,
					   struct nbl_ch_prm_cfg_lag_member_fwd *param)
{
	return DIS2RES_2IN_CB_LOC(cfg_lag_member_fwd, false, param, true, int);
}

static int nbl_disp_chan_cfg_lag_member_list_req(void *priv,
						 struct nbl_lag_member_list_param *param)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_lag_member_list_param chan_param = {0};
	struct nbl_chan_send_info chan_send;

	memcpy(&chan_param, param, sizeof(chan_param));

	NBL_CHAN_SEND(chan_send, 0, NBL_CHAN_MSG_CFG_LAG_MEMBER_LIST, &chan_param,
		      sizeof(chan_param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_cfg_lag_member_list_resp(void *priv, u16 src_id, u16 msg_id,
						   void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_lag_member_list_param *param;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	param = (struct nbl_lag_member_list_param *)data;

	ret = NBL_OPS_CALL(res_ops->cfg_lag_member_list,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param));
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_CFG_LAG_MEMBER_LIST, msg_id, err, NULL, 0);
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d\n",
			ret, NBL_CHAN_MSG_CFG_LAG_MEMBER_LIST);
}

static int nbl_disp_cfg_lag_member_list(void *priv, struct nbl_lag_member_list_param *param)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->cfg_lag_member_list,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param));
}

static int nbl_disp_chan_cfg_lag_member_up_attr_req(void *priv,
						    struct nbl_ch_prm_cfg_lag_member_up_attr *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_CFG_LAG_MEMBER_UP_ATTR);
}

static void nbl_disp_chan_cfg_lag_member_up_attr_resp(void *priv, u16 src_id, u16 msg_id,
						      void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(cfg_lag_member_up_attr, false,
					   struct nbl_ch_prm_cfg_lag_member_up_attr,
					   NBL_CHAN_MSG_CFG_LAG_MEMBER_UP_ATTR, (void)0);
}

static int nbl_disp_cfg_lag_member_up_attr_loc(void *priv,
					       struct nbl_ch_prm_cfg_lag_member_up_attr *param)
{
	return DIS2RES_2IN_CB_LOC(cfg_lag_member_up_attr, false, param, true, int);
}

static int nbl_disp_chan_add_lag_flow_req(void *priv, u16 *vsi)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(vsi, NBL_CHAN_MSG_ADD_LAG_FLOW);
}

static void nbl_disp_chan_add_lag_flow_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(add_lag_flow, true, u16,
					   NBL_CHAN_MSG_ADD_LAG_FLOW, (void)0);
}

static int nbl_disp_add_lag_flow_loc(void *priv, u16 *vsi)
{
	return DIS2RES_2IN_CB_LOC(add_lag_flow, true, vsi, true, int);
}

static int nbl_disp_chan_del_lag_flow_req(void *priv, u16 *vsi)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(vsi, NBL_CHAN_MSG_DEL_LAG_FLOW);
}

static void nbl_disp_chan_del_lag_flow_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(del_lag_flow, true, u16,
					   NBL_CHAN_MSG_DEL_LAG_FLOW, (void)0);
}

static int nbl_disp_del_lag_flow_loc(void *priv, u16 *vsi)
{
	return DIS2RES_2IN_CB_LOC(del_lag_flow, true, vsi, true, int);
}

static int nbl_disp_chan_add_lldp_flow_req(void *priv, u16 *vsi)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(vsi, NBL_CHAN_MSG_ADD_LLDP_FLOW);
}

static void nbl_disp_chan_add_lldp_flow_resp(void *priv, u16 src_id, u16 msg_id,
					     void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(add_lldp_flow, true, u16,
					   NBL_CHAN_MSG_ADD_LLDP_FLOW, (void)0);
}

static int nbl_disp_add_lldp_flow_loc(void *priv, u16 *vsi)
{
	return DIS2RES_2IN_CB_LOC(add_lldp_flow, true, vsi, true, int);
}

static int nbl_disp_chan_del_lldp_flow_req(void *priv, u16 *vsi)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(vsi, NBL_CHAN_MSG_DEL_LLDP_FLOW);
}

static void nbl_disp_chan_del_lldp_flow_resp(void *priv, u16 src_id, u16 msg_id,
					     void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(del_lldp_flow, true, u16,
					   NBL_CHAN_MSG_DEL_LLDP_FLOW, (void)0);
}

static int nbl_disp_del_lldp_flow_loc(void *priv, u16 *vsi)
{
	return DIS2RES_2IN_CB_LOC(del_lldp_flow, true, vsi, true, int);
}

static int nbl_disp_chan_cfg_lag_mcc_req(void *priv, struct nbl_ch_prm_cfg_lag_mcc *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_CFG_LAG_MCC);
}

static void nbl_disp_chan_cfg_lag_mcc_resp(void *priv, u16 src_id, u16 msg_id,
					   void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(cfg_lag_mcc, true, struct nbl_ch_prm_cfg_lag_mcc,
					   NBL_CHAN_MSG_CFG_LAG_MCC, (void)0);
}

static int nbl_disp_cfg_lag_mcc_loc(void *priv, struct nbl_ch_prm_cfg_lag_mcc *param)
{
	return DIS2RES_2IN_CB_LOC(cfg_lag_mcc, true, param, true, int);
}

static int nbl_disp_cfg_duppkt_info(void *priv, struct nbl_lag_member_list_param *param)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->cfg_duppkt_info, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param));
}

static int nbl_disp_chan_cfg_duppkt_mcc_req(void *priv, struct nbl_lag_member_list_param *mem_param)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_lag_member_list_param param = {0};
	struct nbl_chan_send_info chan_send;

	memcpy(&param, mem_param, sizeof(param));

	NBL_CHAN_SEND(chan_send, 0, NBL_CHAN_MSG_CFG_DUPPKT_MCC, &param, sizeof(param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_cfg_duppkt_mcc_resp(void *priv, u16 src_id, u16 msg_id,
					      void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_lag_member_list_param *param = NULL;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	param = (struct nbl_lag_member_list_param *)data;

	err = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->cfg_duppkt_mcc,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_CFG_DUPPKT_MCC, msg_id, err, NULL, 0);
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d\n",
			ret, NBL_CHAN_MSG_CFG_DUPPKT_MCC);
}

static int nbl_disp_cfg_duppkt_mcc(void *priv, struct nbl_lag_member_list_param *mem_param)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->cfg_duppkt_mcc,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), mem_param);
}

static int nbl_disp_chan_cfg_bond_shaping_req(void *priv, struct nbl_ch_prm_cfg_bond_shaping *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_CFG_BOND_SHAPING);
}

static void nbl_disp_chan_cfg_bond_shaping_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(cfg_bond_shaping, true,
					   struct nbl_ch_prm_cfg_bond_shaping,
					   NBL_CHAN_MSG_CFG_BOND_SHAPING, (void)0);
}

static int nbl_disp_cfg_bond_shaping_loc(void *priv, struct nbl_ch_prm_cfg_bond_shaping *param)
{
	return DIS2RES_2IN_CB_LOC(cfg_bond_shaping, true, param, true, int);
}

static int nbl_disp_chan_cfg_bgid_back_pressure_req(void *priv,
						    struct nbl_ch_prm_cfg_bgid_back_pressure *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_CFG_BGID_BACK_PRESSURE);
}

static void nbl_disp_chan_cfg_bgid_back_pressure_resp(void *priv, u16 src_id, u16 msg_id,
						      void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(cfg_bgid_back_pressure, true,
					   struct nbl_ch_prm_cfg_bgid_back_pressure,
					   NBL_CHAN_MSG_CFG_BGID_BACK_PRESSURE, (void)0);
}

static int nbl_disp_cfg_bgid_back_pressure_loc(void *priv,
					       struct nbl_ch_prm_cfg_bgid_back_pressure *param)
{
	return DIS2RES_2IN_CB_LOC(cfg_bgid_back_pressure, true, param, true, int);
}

static u32 nbl_disp_get_tx_headroom(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	u32 ret = 0;

	ret = NBL_OPS_CALL(res_ops->get_tx_headroom, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
	return ret;
}

static int nbl_disp_enable_up_rdma_bypass_loc(void *priv,
					      struct nbl_enable_up_rdma_bypass_param *param)
{
	return DIS2RES_2IN_CB_LOC(enable_up_rdma_bypass, false, param, true, int);
}

static int nbl_disp_register_rdma_grc_id_loc(void *priv, u16 *vsi_id, int *grc_id)
{
	return DIS2RES_2IN_OUT_CB_LOC(register_rdma_grc_id, true, vsi_id, grc_id, true, int);
}

static int nbl_disp_unregister_rdma_grc_id_loc(void *priv, u16 *vsi_id)
{
	return DIS2RES_2IN_CB_LOC(unregister_rdma_grc_id, true, vsi_id, true, int);
}

static int nbl_disp_register_rdma_loc(void *priv, u16 *vsi_id,
				      struct nbl_rdma_register_param *param)
{
	return DIS2RES_2IN_OUT_CB_LOC(register_rdma, true, vsi_id, param, true, int);
}

static int nbl_disp_unregister_rdma_loc(void *priv, u16 *vsi_id)
{
	return DIS2RES_2IN_CB_LOC(unregister_rdma, true, vsi_id, true, int);
}

static u8 __iomem *nbl_disp_get_hw_addr(void *priv, size_t *size)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	u8 __iomem *addr = NULL;

	addr = NBL_OPS_CALL(res_ops->get_hw_addr, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), size));
	return addr;
}

static u8 __iomem *nbl_disp_get_rdma_hw_addr(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	u8 __iomem *addr = NULL;

	addr = NBL_OPS_CALL(res_ops->get_rdma_hw_addr, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
	return addr;
}

static u64 nbl_disp_get_real_hw_addr_loc(void *priv, u16 *vsi_id)
{
	return DIS2RES_2IN_CB_LOC(get_real_hw_addr, false, vsi_id, true, u64);
}

static u16 nbl_disp_get_function_id_loc(void *priv, u16 *vsi_id)
{
	return DIS2RES_2IN_CB_LOC(get_function_id, false, vsi_id, true, u16);
}

static int nbl_disp_get_real_bdf_loc(void *priv, u16 *vsi_id,
				     struct nbl_ch_prm_get_real_bdf *output)
{
	return DIS2RES_2IN_OUT_CB_LOC(get_real_bdf, false, vsi_id, output, true, int);
}

static bool nbl_disp_check_fw_heartbeat(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = false;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL(res_ops->check_fw_heartbeat, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
	return ret;
}

static bool nbl_disp_check_fw_reset(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	return NBL_OPS_CALL(res_ops->check_fw_reset, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static int nbl_disp_flash_lock(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->flash_lock, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static int nbl_disp_flash_unlock(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->flash_unlock, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static int nbl_disp_flash_prepare(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->flash_prepare, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static int nbl_disp_flash_image_loc(void *priv, struct nbl_flash_image_param *param)
{
	return DIS2RES_2IN_CB_LOC(flash_image, false, param, true, int);
}

static int nbl_disp_flash_activate(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->flash_activate, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static int nbl_disp_set_eth_loopback_loc(void *priv,
					 struct nbl_ch_prm_set_eth_loopback *param)
{
	return DIS2RES_2IN_CB_LOC(set_eth_loopback, false, param, true, int);
}

static int nbl_disp_chan_set_eth_loopback_req(void *priv,
					      struct nbl_ch_prm_set_eth_loopback *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_SET_ETH_LOOPBACK);
}

static void nbl_disp_chan_set_eth_loopback_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(set_eth_loopback, false,
					   struct nbl_ch_prm_set_eth_loopback,
					   NBL_CHAN_MSG_SET_ETH_LOOPBACK, (void)0);
}

static struct sk_buff *nbl_disp_clean_rx_lb_test_loc(void *priv,
						     u32 *ring_index)
{
	return DIS2RES_2IN_CB_LOC(clean_rx_lb_test, false, ring_index, true,
				  struct sk_buff *);
}

static u32 nbl_disp_check_active_vf_loc(void *priv, u16 *func_id)
{
	return DIS2RES_2IN_CB_LOC(check_active_vf, false, func_id, true, u32);
}

static u32 nbl_disp_chan_check_active_vf_req(void *priv, u16 *func_id)
{
	return DIS2CH_2IN_RESPMEM2RET_CB_REQ(func_id, NBL_CHAN_MSG_CHECK_ACTIVE_VF,
					     struct nbl_ch_prm_int_comm, val, u32);
}

static void nbl_disp_chan_check_active_vf_resp(void *priv, u16 src_id, u16 msg_id,
					       void *data, u32 data_len)
{
	DIS2CH_2IN_RESPMEM2RET_CB_RESP(check_active_vf, false, u16 *,
				       NBL_CHAN_MSG_CHECK_ACTIVE_VF,
				       struct nbl_ch_prm_int_comm, val, u32, *p = src_id);
}

static u32 nbl_disp_get_adminq_tx_buf_size(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	return chan_ops->get_adminq_tx_buf_size(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt));
}

static bool nbl_disp_get_product_flex_cap_loc(void *priv, enum nbl_flex_cap_type *cap_type)
{
	return DIS2RES_2IN_CB_LOC(get_product_flex_cap, false, cap_type, true, bool);
}

static int nbl_disp_set_pmd_debug(void *priv, bool pmd_debug)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->set_pmd_debug,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), pmd_debug));
}

static bool nbl_disp_chan_get_product_flex_cap_req(void *priv,
						   enum nbl_flex_cap_type *cap_type)
{
	return DIS2CH_2IN_RESPMEM2RET_CB_REQ(cap_type, NBL_CHAN_MSG_GET_PRODUCT_FLEX_CAP,
					     struct nbl_ch_prm_bool_comm, val, bool);
}

static void nbl_disp_chan_get_product_flex_cap_resp(void *priv, u16 src_id, u16 msg_id,
						    void *data, u32 data_len)
{
	DIS2CH_2IN_RESPMEM2RET_CB_RESP(get_product_flex_cap, false,
				       enum nbl_flex_cap_type *,
				       NBL_CHAN_MSG_GET_PRODUCT_FLEX_CAP,
				       struct nbl_ch_prm_bool_comm, val, bool, (void)0);
}

static bool nbl_disp_get_product_fix_cap_loc(void *priv, enum nbl_fix_cap_type *cap_type)
{
	return DIS2RES_2IN_CB_LOC(get_product_fix_cap, false, cap_type, true, bool);
}

static int nbl_disp_alloc_ktls_tx_index_loc(void *priv, u16 *vsi)
{
	return DIS2RES_2IN_CB_LOC(alloc_ktls_tx_index, true, vsi, true, int);
}

static int nbl_disp_chan_alloc_ktls_tx_index_req(void *priv, u16 *vsi)
{
	return DIS2CH_2IN_RESPMEM2RET_CB_REQ(vsi, NBL_CHAN_MSG_ALLOC_KTLS_TX_INDEX,
					     struct nbl_ch_prm_int_comm, val, int);
}

static void nbl_disp_chan_alloc_ktls_tx_index_resp(void *priv, u16 src_id, u16 msg_id,
						   void *data, u32 data_len)
{
	DIS2CH_2IN_RESPMEM2RET_CB_RESP(alloc_ktls_tx_index, true, u16 *,
				       NBL_CHAN_MSG_ALLOC_KTLS_TX_INDEX,
				       struct nbl_ch_prm_int_comm, val, int, (void)0);
}

static int nbl_disp_free_ktls_tx_index_loc(void *priv, u32 *index)
{
	return DIS2RES_2IN_CB_LOC(free_ktls_tx_index, true, index, true, int);
}

static int nbl_disp_chan_free_ktls_tx_index_req(void *priv, u32 *index)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(index, NBL_CHAN_MSG_FREE_KTLS_TX_INDEX);
}

static void nbl_disp_chan_free_ktls_tx_index_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(free_ktls_tx_index, true, u32,
					   NBL_CHAN_MSG_FREE_KTLS_TX_INDEX, (void)0);
}

static int nbl_disp_cfg_ktls_tx_keymat_loc(void *priv, struct nbl_ch_prm_cfg_ktls_keymat *param)
{
	return DIS2RES_2IN_CB_LOC(cfg_ktls_tx_keymat, true, param, true, int);
}

static int nbl_disp_chan_cfg_ktls_tx_keymat_req(void *priv,
						struct nbl_ch_prm_cfg_ktls_keymat *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_CFG_KTLS_TX_KEYMAT);
}

static void nbl_disp_chan_cfg_ktls_tx_keymat_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(cfg_ktls_tx_keymat, true,
					   struct nbl_ch_prm_cfg_ktls_keymat,
					   NBL_CHAN_MSG_CFG_KTLS_TX_KEYMAT, (void)0);
}

static int nbl_disp_alloc_ktls_rx_index_loc(void *priv, u16 *vsi)
{
	return DIS2RES_2IN_CB_LOC(alloc_ktls_rx_index, true, vsi, true, int);
}

static int nbl_disp_chan_alloc_ktls_rx_index_req(void *priv, u16 *vsi)
{
	return DIS2CH_2IN_RESPMEM2RET_CB_REQ(vsi, NBL_CHAN_MSG_ALLOC_KTLS_RX_INDEX,
					     struct nbl_ch_prm_int_comm, val, int);
}

static void nbl_disp_chan_alloc_ktls_rx_index_resp(void *priv, u16 src_id, u16 msg_id,
						   void *data, u32 data_len)
{
	DIS2CH_2IN_RESPMEM2RET_CB_RESP(alloc_ktls_rx_index, true, u16 *,
				       NBL_CHAN_MSG_ALLOC_KTLS_RX_INDEX,
				       struct nbl_ch_prm_int_comm, val, int, (void)0);
}

static int nbl_disp_free_ktls_rx_index_loc(void *priv, u32 *index)
{
	return DIS2RES_2IN_CB_LOC(free_ktls_rx_index, true, index, true, int);
}

static int nbl_disp_chan_free_ktls_rx_index_req(void *priv, u32 *index)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(index, NBL_CHAN_MSG_FREE_KTLS_RX_INDEX);
}

static void nbl_disp_chan_free_ktls_rx_index_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(free_ktls_rx_index, true, u32,
					   NBL_CHAN_MSG_FREE_KTLS_RX_INDEX, (void)0);
}

static int nbl_disp_cfg_ktls_rx_keymat_loc(void *priv, struct nbl_ch_prm_cfg_ktls_keymat *param)
{
	return DIS2RES_2IN_CB_LOC(cfg_ktls_rx_keymat, true, param, true, int);
}

static int nbl_disp_chan_cfg_ktls_rx_keymat_req(void *priv,
						struct nbl_ch_prm_cfg_ktls_keymat *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_CFG_KTLS_RX_KEYMAT);
}

static void nbl_disp_chan_cfg_ktls_rx_keymat_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(cfg_ktls_rx_keymat, true,
					   struct nbl_ch_prm_cfg_ktls_keymat,
					   NBL_CHAN_MSG_CFG_KTLS_RX_KEYMAT, (void)0);
}

static int nbl_disp_cfg_ktls_rx_record_loc(void *priv, struct nbl_ch_prm_cfg_ktls_record *param)
{
	return DIS2RES_2IN_CB_LOC(cfg_ktls_rx_record, true, param, true, int);
}

static int nbl_disp_chan_cfg_ktls_rx_record_req(void *priv,
						struct nbl_ch_prm_cfg_ktls_record *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_CFG_KTLS_RX_RECORD);
}

static void nbl_disp_chan_cfg_ktls_rx_record_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(cfg_ktls_rx_record, true,
					   struct nbl_ch_prm_cfg_ktls_record,
					   NBL_CHAN_MSG_CFG_KTLS_RX_RECORD, (void)0);
}

static int nbl_disp_add_ktls_rx_flow_loc(void *priv, struct nbl_ch_prm_cfg_ktls_flow *param)
{
	return DIS2RES_2IN_CB_LOC(add_ktls_rx_flow, true, param, true, int);
}

static int nbl_disp_chan_add_ktls_rx_flow_req(void *priv,
					      struct nbl_ch_prm_cfg_ktls_flow *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_ADD_KTLS_RX_FLOW);
}

static void nbl_disp_chan_add_ktls_rx_flow_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(add_ktls_rx_flow, true,
					   struct nbl_ch_prm_cfg_ktls_flow,
					   NBL_CHAN_MSG_ADD_KTLS_RX_FLOW, (void)0);
}

static int nbl_disp_del_ktls_rx_flow_loc(void *priv, struct nbl_ch_prm_cfg_ktls_flow *param)
{
	return DIS2RES_2IN_CB_LOC(del_ktls_rx_flow, true, param, true, int);
}

static int nbl_disp_chan_del_ktls_rx_flow_req(void *priv,
					      struct nbl_ch_prm_cfg_ktls_flow *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_DEL_KTLS_RX_FLOW);
}

static void nbl_disp_chan_del_ktls_rx_flow_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(del_ktls_rx_flow, true,
					   struct nbl_ch_prm_cfg_ktls_flow,
				       NBL_CHAN_MSG_DEL_KTLS_RX_FLOW, (void)0);
}

static int nbl_disp_alloc_ipsec_tx_index_loc(void *priv, struct nbl_ch_prm_ipsec_index *param)
{
	return DIS2RES_2IN_CB_LOC(alloc_ipsec_tx_index, true, param, true, int);
}

static int nbl_disp_chan_alloc_ipsec_tx_index_req(void *priv,
						  struct nbl_ch_prm_ipsec_index *param)
{
	return DIS2CH_2IN_RESPMEM2RET_CB_REQ(param, NBL_CHAN_MSG_ALLOC_IPSEC_TX_INDEX,
					     struct nbl_ch_prm_ipsec_index, index, int);
}

static void nbl_disp_chan_alloc_ipsec_tx_index_resp(void *priv, u16 src_id, u16 msg_id,
						    void *data, u32 data_len)
{
	DIS2CH_2IN_RESPMEM2RET_CB_RESP(alloc_ipsec_tx_index, true,
				       struct nbl_ch_prm_ipsec_index *,
				       NBL_CHAN_MSG_ALLOC_IPSEC_TX_INDEX,
				       struct nbl_ch_prm_ipsec_index, index, int, (void)0);
}

static int nbl_disp_free_ipsec_tx_index_loc(void *priv, struct nbl_ch_prm_ipsec_index *param)
{
	return DIS2RES_2IN_CB_LOC(free_ipsec_tx_index, true, param, true, int);
}

static int nbl_disp_chan_free_ipsec_tx_index_req(void *priv,
						 struct nbl_ch_prm_ipsec_index *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ_NOACK(param, NBL_CHAN_MSG_FREE_IPSEC_TX_INDEX);
}

static void nbl_disp_chan_free_ipsec_tx_index_resp(void *priv, u16 src_id, u16 msg_id,
						   void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP_NOACK(free_ipsec_tx_index, true,
						 struct nbl_ch_prm_ipsec_index,
						 (void)0);
}

static int nbl_disp_alloc_ipsec_rx_index_loc(void *priv, struct nbl_ch_prm_ipsec_index *param)
{
	return DIS2RES_2IN_CB_LOC(alloc_ipsec_rx_index, true, param, true, int);
}

static int nbl_disp_chan_alloc_ipsec_rx_index_req(void *priv,
						  struct nbl_ch_prm_ipsec_index *param)
{
	return DIS2CH_2IN_RESPMEM2RET_CB_REQ(param, NBL_CHAN_MSG_ALLOC_IPSEC_RX_INDEX,
					     struct nbl_ch_prm_ipsec_index, index, int);
}

static void nbl_disp_chan_alloc_ipsec_rx_index_resp(void *priv, u16 src_id, u16 msg_id,
						    void *data, u32 data_len)
{
	DIS2CH_2IN_RESPMEM2RET_CB_RESP(alloc_ipsec_rx_index, true,
				       struct nbl_ch_prm_ipsec_index *,
				       NBL_CHAN_MSG_ALLOC_IPSEC_RX_INDEX,
				       struct nbl_ch_prm_ipsec_index, index, int, (void)0);
}

static int nbl_disp_free_ipsec_rx_index_loc(void *priv, struct nbl_ch_prm_ipsec_index *param)
{
	return DIS2RES_2IN_CB_LOC(free_ipsec_rx_index, true, param, true, int);
}

static int nbl_disp_chan_free_ipsec_rx_index_req(void *priv,
						 struct nbl_ch_prm_ipsec_index *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ_NOACK(param, NBL_CHAN_MSG_FREE_IPSEC_RX_INDEX);
}

static void nbl_disp_chan_free_ipsec_rx_index_resp(void *priv, u16 src_id, u16 msg_id,
						   void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP_NOACK(free_ipsec_rx_index, true,
						 struct nbl_ch_prm_ipsec_index,
						 (void)0);
}

static int nbl_disp_cfg_ipsec_tx_sad_loc(void *priv, struct nbl_ch_prm_cfg_ipsec_sad *param)
{
	return DIS2RES_2IN_CB_LOC(cfg_ipsec_tx_sad, true, param, true, int);
}

static int nbl_disp_chan_cfg_ipsec_tx_sad_req(void *priv,
					      struct nbl_ch_prm_cfg_ipsec_sad *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_CFG_IPSEC_TX_SAD);
}

static void nbl_disp_chan_cfg_ipsec_tx_sad_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(cfg_ipsec_tx_sad, true,
					   struct nbl_ch_prm_cfg_ipsec_sad,
					   NBL_CHAN_MSG_CFG_IPSEC_TX_SAD, (void)0);
}

static int nbl_disp_cfg_ipsec_rx_sad_loc(void *priv, struct nbl_ch_prm_cfg_ipsec_sad *param)
{
	return DIS2RES_2IN_CB_LOC(cfg_ipsec_rx_sad, true, param, true, int);
}

static int nbl_disp_chan_cfg_ipsec_rx_sad_req(void *priv,
					      struct nbl_ch_prm_cfg_ipsec_sad *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_CFG_IPSEC_RX_SAD);
}

static void nbl_disp_chan_cfg_ipsec_rx_sad_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(cfg_ipsec_rx_sad, true,
					   struct nbl_ch_prm_cfg_ipsec_sad,
					   NBL_CHAN_MSG_CFG_IPSEC_RX_SAD, (void)0);
}

static int nbl_disp_add_ipsec_tx_flow_loc(void *priv, struct nbl_ch_prm_cfg_ipsec_flow *param)
{
	return DIS2RES_2IN_CB_LOC(add_ipsec_tx_flow, true, param, true, int);
}

static int nbl_disp_chan_add_ipsec_tx_flow_req(void *priv,
					       struct nbl_ch_prm_cfg_ipsec_flow *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_ADD_IPSEC_TX_FLOW);
}

static void nbl_disp_chan_add_ipsec_tx_flow_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(add_ipsec_tx_flow, true,
					   struct nbl_ch_prm_cfg_ipsec_flow,
					   NBL_CHAN_MSG_ADD_IPSEC_TX_FLOW, (void)0);
}

static int nbl_disp_del_ipsec_tx_flow_loc(void *priv, struct nbl_ch_prm_cfg_ipsec_flow *param)
{
	return DIS2RES_2IN_CB_LOC(del_ipsec_tx_flow, true, param, true, int);
}

static int nbl_disp_chan_del_ipsec_tx_flow_req(void *priv,
					       struct nbl_ch_prm_cfg_ipsec_flow *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ_NOACK(param, NBL_CHAN_MSG_DEL_IPSEC_TX_FLOW);
}

static void nbl_disp_chan_del_ipsec_tx_flow_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP_NOACK(del_ipsec_tx_flow, true,
						 struct nbl_ch_prm_cfg_ipsec_flow,
						 (void)0);
}

static int nbl_disp_add_ipsec_rx_flow_loc(void *priv, struct nbl_ch_prm_cfg_ipsec_flow *param)
{
	return DIS2RES_2IN_CB_LOC(add_ipsec_rx_flow, true, param, true, int);
}

static int nbl_disp_chan_add_ipsec_rx_flow_req(void *priv,
					       struct nbl_ch_prm_cfg_ipsec_flow *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_ADD_IPSEC_RX_FLOW);
}

static void nbl_disp_chan_add_ipsec_rx_flow_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(add_ipsec_rx_flow, true,
					   struct nbl_ch_prm_cfg_ipsec_flow,
					   NBL_CHAN_MSG_ADD_IPSEC_RX_FLOW, (void)0);
}

static int nbl_disp_del_ipsec_rx_flow_loc(void *priv, struct nbl_ch_prm_cfg_ipsec_flow *param)
{
	return DIS2RES_2IN_CB_LOC(del_ipsec_rx_flow, true, param, true, int);
}

static int nbl_disp_chan_del_ipsec_rx_flow_req(void *priv,
					       struct nbl_ch_prm_cfg_ipsec_flow *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ_NOACK(param, NBL_CHAN_MSG_DEL_IPSEC_RX_FLOW);
}

static void nbl_disp_chan_del_ipsec_rx_flow_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP_NOACK(del_ipsec_rx_flow, true,
						 struct nbl_ch_prm_cfg_ipsec_flow,
						 (void)0);
}

static bool nbl_disp_check_ipsec_status(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->check_ipsec_status, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static u32 nbl_disp_get_dipsec_lft_info(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_dipsec_lft_info, NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
}

static int nbl_disp_handle_dipsec_soft_expire_loc(void *priv, u32 *index)
{
	return DIS2RES_2IN_CB_LOC(handle_dipsec_soft_expire, true, index, true, int);
}

static int nbl_disp_handle_dipsec_hard_expire_loc(void *priv, u32 *index)
{
	return DIS2RES_2IN_CB_LOC(handle_dipsec_hard_expire, true, index, true, int);
}

static u32 nbl_disp_get_uipsec_lft_info(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_uipsec_lft_info, NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
}

static int nbl_disp_handle_uipsec_soft_expire_loc(void *priv, u32 *index)
{
	return DIS2RES_2IN_CB_LOC(handle_uipsec_soft_expire, true, index, true, int);
}

static int nbl_disp_handle_uipsec_hard_expire_loc(void *priv, u32 *index)
{
	return DIS2RES_2IN_CB_LOC(handle_uipsec_hard_expire, true, index, true, int);
}

static int nbl_disp_clear_accel_flow_loc(void *priv, u16 *vsi_id)
{
	return DIS2RES_2IN_CB_LOC(clear_accel_flow, true, vsi_id, true, int);
}

static int nbl_disp_clear_flow_loc(void *priv, u16 *vsi_id)
{
	return DIS2RES_2IN_CB_LOC(clear_flow, true, vsi_id, true, int);
}

static int nbl_disp_clear_queues_loc(void *priv, u16 *vsi_id)
{
	return DIS2RES_2IN_CB_LOC(clear_queues, true, vsi_id, true, int);
}

static int nbl_disp_disable_phy_flow_loc(void *priv, u8 *eth_id)
{
	return DIS2RES_2IN_CB_LOC(disable_phy_flow, true, eth_id, true, int);
}

static int nbl_disp_enable_phy_flow_loc(void *priv, u8 *eth_id)
{
	return DIS2RES_2IN_CB_LOC(enable_phy_flow, true, eth_id, true, int);
}

static void nbl_disp_init_acl(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL(res_ops->init_acl, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static void nbl_disp_uninit_acl(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL(res_ops->uninit_acl, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static int nbl_disp_set_upcall_rule_loc(void *priv,
					struct nbl_ch_prm_set_upcall *param)
{
	return DIS2RES_2IN_CB_LOC(set_upcall_rule, false, param, true, int);
}

static int nbl_disp_unset_upcall_rule_loc(void *priv, u8 *eth_id)
{
	return DIS2RES_2IN_CB_LOC(unset_upcall_rule, false, eth_id, true, int);
}

static int nbl_disp_set_shaping_dport_vld_loc(void *priv,
					      struct nbl_ch_prm_set_func_vld *param)
{
	return DIS2RES_2IN_CB_LOC(set_shaping_dport_vld, false, param, true, int);
}

static int nbl_disp_set_dport_fc_th_vld_loc(void *priv,
					    struct nbl_ch_prm_set_func_vld *param)
{
	return DIS2RES_2IN_CB_LOC(set_dport_fc_th_vld, false, param, true, int);
}

static u16 nbl_disp_get_vsi_global_qid_loc(void *priv,
					   struct nbl_ch_prm_get_vsi_global_qid *param)
{
	return DIS2RES_2IN_CB_LOC(get_vsi_global_qid, false, param, true, u16);
}

static u16 nbl_disp_chan_get_vsi_global_qid_req(void *priv,
						struct nbl_ch_prm_get_vsi_global_qid *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param,
						  NBL_CHAN_MSG_GET_VSI_GLOBAL_QUEUE_ID);
}

static void nbl_disp_chan_get_vsi_global_qid_resp(void *priv, u16 src_id,
						  u16 msg_id, void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_ACKERR_CB_RESP(get_vsi_global_qid, false,
					    struct nbl_ch_prm_get_vsi_global_qid,
					    NBL_CHAN_MSG_GET_VSI_GLOBAL_QUEUE_ID,
					    u16, (void)0);
}

static void
nbl_disp_chan_get_line_rate_info_resp(void *priv, u16 src_id, u16 msg_id,
				      void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	struct nbl_rep_line_rate_info result = {0};

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	NBL_OPS_CALL(res_ops->get_line_rate_info, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), data,
						   &result));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_LINE_RATE_INFO,
		     msg_id, 0, &result, sizeof(struct nbl_rep_line_rate_info));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void
nbl_disp_chan_register_net_rep_resp(void *priv, u16 src_id, u16 msg_id,
				    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_register_net_rep *param;
	struct nbl_chan_ack_info chan_ack;
	struct nbl_register_net_rep_result result = {0};

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	param = (struct nbl_chan_param_register_net_rep *)data;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->register_net_rep,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->pf_id,
			  param->vf_id, &result);
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_REGISTER_NET_REP,
		     msg_id, 0, &result, sizeof(result));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void
nbl_disp_chan_unregister_net_rep_resp(void *priv, u16 src_id, u16 msg_id,
				      void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	u16 vsi_id;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	vsi_id = *(u16 *)data;
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->unregister_net_rep,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_UNREGISTER_NET_REP,
		     msg_id, 0, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void
nbl_disp_chan_register_eth_rep_resp(void *priv, u16 src_id, u16 msg_id,
				    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	u8 eth_id;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	eth_id = *(u8 *)data;
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->register_eth_rep,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id);
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_REGISTER_ETH_REP,
		     msg_id, 0, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void
nbl_disp_chan_get_queue_cxt_resp(void *priv, u16 src_id, u16 msg_id,
				 void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_get_queue_cxt *param;
	struct nbl_chan_ack_info chan_ack;
	u64 cxt;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	param = (struct nbl_chan_param_get_queue_cxt *)data;

	cxt = NBL_OPS_CALL(res_ops->get_queue_ctx,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->vsi_id, param->local_queue));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_QUEUE_CXT,
		     msg_id, 0, &cxt, sizeof(cxt));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void
nbl_disp_chan_init_vdpaq_resp(void *priv, u16 src_id, u16 msg_id,
			      void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_vdpaq_init_info *param;
	struct nbl_chan_ack_info chan_ack;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	param = (struct nbl_chan_vdpaq_init_info *)data;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->init_vdpaq,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), src_id, param->pa, param->size);
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_INIT_VDPAQ,
		     msg_id, 0, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void
nbl_disp_chan_destroy_vdpaq_resp(void *priv, u16 src_id, u16 msg_id,
				 void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->destroy_vdpaq,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), src_id);
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_DESTROY_VDPAQ,
		     msg_id, 0, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void
nbl_disp_chan_get_upcall_port_resp(void *priv, u16 src_id, u16 msg_id,
				   void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	int ret;
	u16 bdf;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	ret = NBL_OPS_CALL(res_ops->get_upcall_port,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), &bdf));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_GET_UPCALL_PORT,
		     msg_id, ret, &bdf, sizeof(u16));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_get_board_info(void *priv, struct nbl_board_port_info *board_info)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_board_info,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), board_info));
}

static void
nbl_disp_chan_get_board_info_req(void *priv, struct nbl_board_port_info *board_info)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_GET_BOARD_INFO, NULL,
		      0, board_info, sizeof(*board_info), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void
nbl_disp_chan_get_board_info_resp(void *priv, u16 src_id, u16 msg_id,
				  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	struct nbl_board_port_info board_info = {0};

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	NBL_OPS_CALL(res_ops->get_board_info,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), &board_info));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_BOARD_INFO,
		     msg_id, 0, &board_info, sizeof(board_info));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void
nbl_disp_chan_cfg_log_resp(void *priv, u16 src_id, u16 msg_id,
			   void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_cfg_log *param;
	struct nbl_chan_ack_info chan_ack;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	param = (struct nbl_chan_param_cfg_log *)data;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->cfg_queue_log,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->vsi_id,
			  param->qps, param->vld);
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_CFG_LOG,
		     msg_id, 0, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void
nbl_disp_chan_unregister_eth_rep_resp(void *priv, u16 src_id, u16 msg_id,
				      void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	u8 eth_id;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	eth_id = *(u8 *)data;
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->unregister_eth_rep,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id);
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_UNREGISTER_ETH_REP,
		     msg_id, 0, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void
nbl_disp_chan_register_upcall_port_resp(void *priv, u16 src_id, u16 msg_id,
					void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	int ret;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->register_upcall_port,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), src_id);
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_REGISTER_UPCALL_PORT,
		     msg_id, ret, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_unregister_upcall_port(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->unregister_upcall_port,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), NBL_COMMON_TO_MGT_PF(common));
}

static void nbl_disp_chan_unregister_upcall_port_req(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	NBL_CHAN_SEND(chan_send, 0, NBL_CHAN_MSG_UNREGISTER_UPCALL_PORT,
		      NULL, 0, NULL, 0, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void
nbl_disp_chan_unregister_upcall_port_resp(void *priv, u16 src_id, u16 msg_id,
					  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->unregister_upcall_port,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), src_id);
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_UNREGISTER_UPCALL_PORT,
		     msg_id, 0, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void
nbl_disp_chan_set_offload_status_resp(void *priv, u16 src_id, u16 msg_id,
				      void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->set_offload_status,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), src_id);
}

static int nbl_disp_check_offload_status(void *priv, bool *is_down)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	return NBL_OPS_CALL(res_ops->check_offload_status,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), is_down));
}

static int nbl_disp_get_port_attributes(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	int ret = 0;

	ret = NBL_OPS_CALL(res_ops->get_port_attributes, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
	if (ret)
		dev_err(dev, "get port attributes failed with ret: %d\n", ret);

	return ret;
}

static int nbl_disp_update_ring_num(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->update_ring_num, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static int nbl_disp_update_rdma_cap(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->update_rdma_cap, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static void nbl_disp_get_rdma_cap_num(void *priv, u16 *cap_num, u16 *my_cap_num)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL(res_ops->get_rdma_cap_num, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), cap_num,
						 my_cap_num));
}

static int nbl_disp_update_rdma_mem_type(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->update_rdma_mem_type, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static int nbl_disp_update_internal_cfg(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->update_internal_cfg, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static int nbl_disp_get_part_number(void *priv, char *part_number)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_part_number,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), part_number));
}

static int nbl_disp_get_serial_number(void *priv, char *serial_number)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_serial_number,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), serial_number));
}

static int nbl_disp_enable_port(void *priv, bool enable)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	int ret = 0;

	ret = NBL_OPS_CALL(res_ops->enable_port, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), enable));
	if (ret)
		dev_err(dev, "enable port failed with ret: %d\n", ret);

	return ret;
}

static void nbl_disp_init_port(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL(res_ops->init_port, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static void nbl_disp_chan_recv_port_notify_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	NBL_OPS_CALL(res_ops->recv_port_notify,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), data));
}

static int nbl_disp_get_fec_stats(void *priv, u8 eth_id,
				  struct nbl_fec_stats *fec_stats)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	int ret = 0;

	ret = NBL_OPS_CALL(res_ops->get_fec_stats,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, fec_stats));
	return ret;
}

static int nbl_disp_chan_get_fec_stats_req(void *priv, u8 eth_id,
					   struct nbl_fec_stats *fec_stats)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_GET_FEC_STATS, &eth_id, sizeof(eth_id),
		      fec_stats, sizeof(*fec_stats), 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_fec_stats_resp(void *priv, u16 src_id, u16 msg_id,
					     void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_chan_ack_info chan_ack;
	struct nbl_fec_stats info = {0};
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	ret = NBL_OPS_CALL(res_ops->get_fec_stats,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), *(u8 *)data, &info));
	if (ret) {
		err = NBL_CHAN_RESP_ERR;
		dev_err(dev, "disp get eth fec stats failed with ret: %d\n", ret);
	}
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_FEC_STATS, msg_id, err,
		     &info, sizeof(info));
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "disp chan send ack failed with ret: %d, msg_type: %d, src_id: %d\n",
			ret, NBL_CHAN_MSG_GET_FEC_STATS, src_id);
}

static int nbl_disp_get_port_state(void *priv, u8 eth_id,
				   struct nbl_port_state *port_state)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	int ret = 0;

	ret = NBL_OPS_CALL(res_ops->get_port_state,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, port_state));
	return ret;
}

static int nbl_disp_chan_get_port_state_req(void *priv, u8 eth_id,
					    struct nbl_port_state *port_state)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_GET_PORT_STATE, &eth_id, sizeof(eth_id),
		      port_state, sizeof(*port_state), 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_port_state_resp(void *priv, u16 src_id, u16 msg_id,
					      void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	struct nbl_port_state info = {0};
	int ret = 0;
	u8 eth_id;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	eth_id = *(u8 *)data;
	ret = NBL_OPS_CALL(res_ops->get_port_state,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, &info));
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_PORT_STATE, msg_id, err,
		     &info, sizeof(info));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_set_port_advertising(void *priv,
					 struct nbl_port_advertising *port_advertising)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	int ret = 0;

	ret = NBL_OPS_CALL(res_ops->set_port_advertising,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), port_advertising));
	return ret;
}

static int nbl_disp_chan_set_port_advertising_req(void *priv,
						  struct nbl_port_advertising *port_advertising)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_SET_PORT_ADVERTISING,
		      port_advertising, sizeof(*port_advertising),
		      NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_set_port_advertising_resp(void *priv, u16 src_id, u16 msg_id,
						    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_port_advertising *param;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	/* fec_sub_mode no use in leonis/draco. so do't need min len copy */
	param = (struct nbl_port_advertising *)data;

	ret = NBL_OPS_CALL(res_ops->set_port_advertising,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param));
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SET_PORT_ADVERTISING, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_get_module_info(void *priv, u8 eth_id, struct ethtool_modinfo *info)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_module_info,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, info));
}

static int nbl_disp_chan_get_module_info_req(void *priv, u8 eth_id, struct ethtool_modinfo *info)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_GET_MODULE_INFO, &eth_id,
		      sizeof(eth_id), info, sizeof(*info), 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_module_info_resp(void *priv, u16 src_id, u16 msg_id,
					       void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	struct ethtool_modinfo info;
	int ret = 0;
	u8 eth_id;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	eth_id = *(u8 *)data;

	ret = NBL_OPS_CALL(res_ops->get_module_info,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, &info));
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_MODULE_INFO, msg_id, err,
		     &info, sizeof(info));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_get_module_eeprom_by_page(void *priv, u8 eth_id,
					      struct nbl_ethtool_module_eeprom *eeprom, u8 *data)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_module_eeprom_by_page,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, eeprom, data));
}

static int nbl_disp_get_module_eeprom(void *priv, u8 eth_id,
				      struct ethtool_eeprom *eeprom, u8 *data)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_module_eeprom,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, eeprom, data));
}

static int nbl_disp_chan_get_module_eeprom_req(void *priv, u8 eth_id,
					       struct ethtool_eeprom *eeprom, u8 *data)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_get_module_eeprom param = {0};
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.eth_id = eth_id;
	memcpy(&param.eeprom, eeprom, sizeof(struct ethtool_eeprom));

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_GET_MODULE_EEPROM,
		      &param, sizeof(param), data, eeprom->len, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_module_eeprom_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_get_module_eeprom *param;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	u8 eth_id;
	struct ethtool_eeprom *eeprom;
	u8 *recv_data;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	param = (struct nbl_chan_param_get_module_eeprom *)data;
	eth_id = param->eth_id;
	eeprom = &param->eeprom;
	recv_data = kmalloc(eeprom->len, GFP_ATOMIC);
	if (!recv_data) {
		dev_err(dev, "Allocate memory to store module eeprom failed\n");
		return;
	}

	ret = NBL_OPS_CALL(res_ops->get_module_eeprom,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, eeprom, recv_data));
	if (ret) {
		err = NBL_CHAN_RESP_ERR;
		dev_err(dev, "Get module eeprom failed with ret: %d\n", ret);
	}

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_MODULE_EEPROM, msg_id, err,
		     recv_data, eeprom->len);
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d, src_id: %d\n",
			ret, NBL_CHAN_MSG_GET_MODULE_EEPROM, src_id);
	kfree(recv_data);
}

static int nbl_disp_get_link_state(void *priv, u8 eth_id, struct nbl_eth_link_info *eth_link_info)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	/* if donot have res_ops->get_link_state(), default eth is up */
	if (res_ops->get_link_state)
		ret = res_ops->get_link_state(NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
					      eth_id, eth_link_info);
	else
		eth_link_info->link_status = 1;

	return ret;
}

static int nbl_disp_chan_get_link_state_req(void *priv, u8 eth_id,
					    struct nbl_eth_link_info *eth_link_info)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_GET_LINK_STATE, &eth_id,
		      sizeof(eth_id), eth_link_info, sizeof(*eth_link_info), 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_link_state_resp(void *priv, u16 src_id, u16 msg_id,
					      void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	u8 eth_id;
	struct nbl_eth_link_info eth_link_info = {0};
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	eth_id = *(u8 *)data;
	ret = res_ops->get_link_state(NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
					 eth_id, &eth_link_info);
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_LINK_STATE, msg_id, err,
		     &eth_link_info, sizeof(eth_link_info));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_get_link_down_count(void *priv, u8 eth_id, u64 *link_down_count)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_link_down_count,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, link_down_count));
}

static int nbl_disp_chan_get_link_down_count_req(void *priv, u8 eth_id, u64 *link_down_count)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_GET_LINK_DOWN_COUNT, &eth_id,
		      sizeof(eth_id), link_down_count, sizeof(*link_down_count), 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_link_down_count_resp(void *priv, u16 src_id, u16 msg_id,
						   void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	u8 eth_id;
	u64 link_down_count = 0;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	eth_id = *(u8 *)data;
	ret = res_ops->get_link_down_count(NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
					 eth_id, &link_down_count);
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_LINK_DOWN_COUNT, msg_id, err,
		     &link_down_count, sizeof(link_down_count));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_get_link_status_opcode(void *priv, u8 eth_id, u32 *link_status_opcode)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_link_status_opcode,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, link_status_opcode));
}

static int nbl_disp_chan_get_link_status_opcode_req(void *priv, u8 eth_id, u32 *link_status_opcode)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_GET_LINK_STATUS_OPCODE, &eth_id,
		      sizeof(eth_id), link_status_opcode, sizeof(*link_status_opcode), 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_link_status_opcode_resp(void *priv, u16 src_id, u16 msg_id,
						      void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	u8 eth_id;
	u32 link_status_opcode = 0;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	eth_id = *(u8 *)data;
	ret = res_ops->get_link_status_opcode(NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
					 eth_id, &link_status_opcode);
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_LINK_STATUS_OPCODE, msg_id, err,
		     &link_status_opcode, sizeof(link_status_opcode));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_get_reg_dump(void *priv, u32 *data, u32 len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL(res_ops->get_reg_dump, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), data, len));
}

static void nbl_disp_chan_get_reg_dump_req(void *priv, u32 *data, u32 len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;
	u32 *result = NULL;

	result = kmalloc(len, GFP_KERNEL);
	if (!result)
		return;

	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_GET_REG_DUMP, &len, sizeof(len),
		      result, len, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);

	memcpy(data, result, len);
	kfree(result);
}

static int nbl_disp_set_wol(void *priv, u8 eth_id, bool enable)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->set_wol,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, enable));
}

static int nbl_disp_chan_set_wol_req(void *priv, u8 eth_id, bool enable)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_send_info chan_send;
	struct nbl_chan_param_set_wol param = {0};
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.eth_id = eth_id;
	param.enable = enable;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_SET_WOL, &param, sizeof(param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_set_wol_resp(void *priv, u16 src_id, u16 msg_id,
				       void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	struct nbl_chan_param_set_wol *param;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	param = (struct nbl_chan_param_set_wol *)data;
	ret = res_ops->set_wol(NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->eth_id, param->enable);
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SET_WOL, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_get_reg_dump_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	u32 *result = NULL;
	u32 len = 0;

	len = *(u32 *)data;
	result = kmalloc(len, GFP_KERNEL);
	if (!result)
		return;

	NBL_OPS_CALL(res_ops->get_reg_dump, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), result, len));

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_REG_DUMP, msg_id, err, result, len);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	kfree(result);
}

static int nbl_disp_get_reg_dump_len(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_reg_dump_len, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static int nbl_disp_chan_get_reg_dump_len_req(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;
	int result = 0;

	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_GET_REG_DUMP_LEN, NULL, 0,
		      &result, sizeof(result), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);

	return result;
}

static void nbl_disp_chan_get_reg_dump_len_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int result = 0;

	result = NBL_OPS_CALL(res_ops->get_reg_dump_len, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_REG_DUMP_LEN, msg_id, err,
		     &result, sizeof(result));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void
nbl_disp_chan_init_offload_fwd_resp(void *priv, u16 src_id, u16 msg_id,
				    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	u16 vsi_id;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	vsi_id = *(u16 *)data;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->init_offload_fwd,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id);
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_INIT_OFLD,
		     msg_id, 0, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void
nbl_disp_chan_init_cmdq_resp(void *priv, u16 src_id, u16 msg_id,
			     void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->init_cmdq,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), data, src_id);
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_INIT_CMDQ,
		     msg_id, 0, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void
nbl_disp_chan_destroy_cmdq_resp(void *priv, u16 src_id, u16 msg_id,
				void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->destroy_cmdq, NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_DESTROY_CMDQ,
		     msg_id, 0, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void
nbl_disp_chan_reset_cmdq_resp(void *priv, u16 src_id, u16 msg_id,
			      void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->reset_cmdq, NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_RESET_CMDQ,
		     msg_id, 0, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void
nbl_disp_chan_offload_flow_rule_resp(void *priv, u16 src_id, u16 msg_id,
				     void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->offload_flow_rule,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), data);
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_OFFLOAD_FLOW_RULE,
		     msg_id, 0, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void
nbl_disp_chan_get_flow_acl_switch_resp(void *priv, u16 src_id, u16 msg_id,
				       void *data, u32 data_len)
{
	u8 acl_enable = false;
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->get_flow_acl_switch,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), &acl_enable);
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_ACL_SWITCH,
		     msg_id, 0, &acl_enable, sizeof(u8));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void
nbl_disp_chan_cfg_tnl_offload_profile_resp(void *priv, u16 src_id, u16 msg_id,
					   void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	u8 mode = *(u8 *)data;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->cfg_tnl_offload_profile,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), mode);
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_CFG_TNL_OFFLOAD_PROFILE,
		     msg_id, 0, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void
nbl_disp_chan_init_rep_resp(void *priv, u16 src_id, u16 msg_id,
			    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	struct nbl_chan_rep_cfg_info *param;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	param = (struct nbl_chan_rep_cfg_info *)data;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->init_rep,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
			  param->vsi_id, param->inner_type, param->outer_type, param->rep_type);
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_INIT_REP,
		     msg_id, 0, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_set_slave_swd_id_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;
	struct nbl_chan_param_slave_swd *param;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	param = (struct nbl_chan_param_slave_swd *)data;

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->set_slave_swd_id,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
			  param->swd_id, param->mgt_pf);
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SET_SLAVE_SWD,
		     msg_id, 0, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void
nbl_disp_chan_init_flow_resp(void *priv, u16 src_id, u16 msg_id,
			     void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->init_flow,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), data);
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_INIT_FLOW,
		     msg_id, 0, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void
nbl_disp_chan_init_flow_draco_resp(void *priv, u16 src_id, u16 msg_id,
				   void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->init_flow,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), data);
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_INIT_FLOW_DRACO,
		     msg_id, 0, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void
nbl_disp_chan_deinit_flow_resp(void *priv, u16 src_id, u16 msg_id,
			       void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_ack_info chan_ack;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->deinit_flow,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_DEINIT_FLOW,
		     msg_id, 0, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_set_eth_mac_addr(void *priv, u8 *mac, u8 eth_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->set_eth_mac_addr,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), mac, eth_id));
}

static int nbl_disp_chan_set_eth_mac_addr_req(void *priv, u8 *mac, u8 eth_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_set_eth_mac_addr param;
	struct nbl_chan_send_info chan_send;
	struct nbl_common_info *common;

	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	memcpy(param.mac, mac, sizeof(param.mac));
	param.eth_id = eth_id;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_SET_ETH_MAC_ADDR,
		      &param, sizeof(param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_set_eth_mac_addr_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops;
	struct nbl_channel_ops *chan_ops;
	struct nbl_chan_param_set_eth_mac_addr *param;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	param = (struct nbl_chan_param_set_eth_mac_addr *)data;

	ret = NBL_OPS_CALL(res_ops->set_eth_mac_addr,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->mac, param->eth_id));
	if (ret)
		err = NBL_CHAN_RESP_ERR;

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SET_ETH_MAC_ADDR, msg_id, err, NULL, 0);
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d\n",
			ret, NBL_CHAN_MSG_SET_ETH_MAC_ADDR);
}

static int nbl_disp_process_abnormal_event(void *priv, struct nbl_abnormal_event_info *abnomal_info)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->process_abnormal_event,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), abnomal_info));
}

static int nbl_disp_process_sfp_plug_event(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->process_sfp_plug_event,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static int nbl_disp_chan_switchdev_init_cmdq_req(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;
	int ret_status = 0;

	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_SWITCHDEV_INIT_CMDQ,
		      NULL, 0, &ret_status, sizeof(ret_status), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
	return ret_status;
}

static void nbl_disp_chan_switchdev_init_cmdq_resp(void *priv, u16 src_id, u16 msg_id,
						   void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;
	int ret_status = 0;

	ret_status = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->switchdev_init_cmdq,
				       NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SWITCHDEV_INIT_CMDQ, msg_id,
		     ret, &ret_status, sizeof(ret_status));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_switchdev_init_cmdq(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->switchdev_init_cmdq,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
}

static int nbl_disp_chan_switchdev_deinit_cmdq_req(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;
	int ret_status = 0;
	u8 tc_inst_id;

	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	tc_inst_id = common->tc_inst_id;
	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_SWITCHDEV_DEINIT_CMDQ,
		      &tc_inst_id, sizeof(tc_inst_id), &ret_status, sizeof(ret_status), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
	if (!ret_status)
		common->tc_inst_id = NBL_TC_FLOW_INST_COUNT;
	return 0;
}

static void nbl_disp_chan_switchdev_deinit_cmdq_resp(void *priv, u16 src_id, u16 msg_id,
						     void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;
	int ret_status = 0;
	u8 tc_inst_id;

	tc_inst_id = *(u8 *)data;
	ret_status = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->switchdev_deinit_cmdq,
				       NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), tc_inst_id);
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SWITCHDEV_DEINIT_CMDQ, msg_id,
		     ret, &ret_status, sizeof(ret_status));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_switchdev_deinit_cmdq(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->switchdev_deinit_cmdq,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
				 common->tc_inst_id);
}

static void nbl_get_tc_flow_parse_info(void *priv, struct nbl_tc_parse_info **parse_info)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->get_tc_flow_parse_info,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), parse_info);
}

static int nbl_disp_add_tc_flow(void *priv, struct nbl_tc_flow_param *param)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->add_tc_flow,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param);
	return ret;
}

static int nbl_disp_del_tc_flow(void *priv, struct nbl_tc_flow_param *param)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	if (!param)
		return -EINVAL;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->del_tc_flow,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param);
	return ret;
}

static bool nbl_disp_tc_tun_encap_lookup(void *priv,
					 struct nbl_rule_action *rule_act,
					 struct nbl_tc_flow_param *param)
{
	bool ret = 0;
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	if (!rule_act || !param)
		return false;

	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->tc_tun_encap_lookup,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
				rule_act, param);
	return ret;
}

static int nbl_disp_tc_tun_encap_del(void *priv, struct nbl_encap_key *key)
{
	int ret = 0;
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	if (!key)
		return -EINVAL;

	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->tc_tun_encap_del,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), key);
	return ret;
}

static int nbl_disp_tc_tun_encap_add(void *priv, struct nbl_rule_action *action)
{
	int ret = 0;
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	if (!action)
		return -EINVAL;

	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->tc_tun_encap_add,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), action);
	return ret;
}

static int nbl_disp_tc_tun_create_header_loc(void *priv,
					     struct nbl_tc_tun_create_header_param *param)
{
	return DIS2RES_2IN_CB_LOC(tc_tun_create_header, true, param, true, int);
}

static int nbl_disp_flow_index_lookup(void *priv, struct nbl_flow_index_key key)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;

	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->flow_index_lookup,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), key);
	return ret;
}

static int nbl_disp_query_tc_stats(void *priv, struct nbl_stats_param *param)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	if (!param)
		return -EINVAL;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL(res_ops->query_tc_stats,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param));
	return ret;
}

static int nbl_disp_set_tc_flow_info(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->set_tc_flow_info,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
}

static int nbl_disp_chan_set_tc_flow_info_req(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;
	int ret_status = 0;

	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_SET_TC_FLOW_INFO,
		      NULL, 0, &ret_status, sizeof(ret_status), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
	return ret_status;
}

static void nbl_disp_chan_set_tc_flow_info_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;
	int ret_status = 0;

	ret_status = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->set_tc_flow_info,
				       (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SET_TC_FLOW_INFO, msg_id,
		     ret, &ret_status, sizeof(ret_status));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_unset_tc_flow_info(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->unset_tc_flow_info,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
}

static int nbl_disp_chan_unset_tc_flow_info_req(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common;
	int ret_status = 0;

	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_UNSET_TC_FLOW_INFO,
		      NULL, 0, &ret_status, sizeof(ret_status), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
	return 0;
}

static void nbl_disp_chan_unset_tc_flow_info_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;
	int ret_status = 0;

	ret_status = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->unset_tc_flow_info,
				       (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_UNSET_TC_FLOW_INFO, msg_id,
		     ret, &ret_status, sizeof(ret_status));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_get_tc_flow_info(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->get_tc_flow_info,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
}

static int nbl_disp_get_owned_pf_bitmap(void *priv,
					unsigned long **owned_pf_bitmap, u8 *max_pf, u16 *bdf)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_owned_pf_bitmap,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), owned_pf_bitmap, max_pf, bdf));
}

static void nbl_disp_adapt_desc_gother(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL(res_ops->adapt_desc_gother, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static void nbl_disp_set_desc_high_throughput(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL(res_ops->set_desc_high_throughput, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static void nbl_disp_flr_clear_rdma(void *priv, u16 vf_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->flr_clear_rdma,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vf_id);
}

static void nbl_disp_flr_clear_net(void *priv, u16 vf_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->flr_clear_net,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vf_id);
}

static void nbl_disp_flr_clear_accel(void *priv, u16 vf_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->flr_clear_accel,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vf_id);
}

static void nbl_disp_flr_clear_queues(void *priv, u16 vf_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->flr_clear_queues,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vf_id);
}

static void nbl_disp_flr_qinfo_cfg(void *priv, u16 vf_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->flr_qinfo_cfg,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vf_id);
}

static void nbl_disp_flr_clear_accel_flow(void *priv, u16 vf_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->flr_clear_accel_flow,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vf_id);
}

static void nbl_disp_flr_clear_flows(void *priv, u16 vf_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->flr_clear_flows,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vf_id);
}

static void nbl_disp_flr_clear_interrupt(void *priv, u16 vf_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->flr_clear_interrupt,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vf_id);
}

static u16 nbl_disp_covert_vfid_to_vsi_id(void *priv, u16 vfid)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->covert_vfid_to_vsi_id,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vfid);
}

static u32 nbl_disp_get_perf_dump_length_loc(void *priv)
{
	return DIS2RES_1IN_CB_LOC(get_perf_dump_length, true, true, u32);
}

static u32 nbl_disp_get_perf_dump_data_loc(void *priv,
					   struct nbl_ch_prm_get_perf_dump_data *param)
{
	return DIS2RES_2IN_CB_LOC(get_perf_dump_data, true, param, true, u32);
}

static int nbl_disp_chan_get_rep_queue_info_req(void *priv,
						struct nbl_ch_prm_get_queue_info *output)
{
	return DIS2CH_1OUT_RESRET_AS_CHRET_CB_REQ(NBL_CHAN_MSG_GET_REP_QUEUE_INFO, output);
}

static void nbl_disp_chan_get_rep_queue_info_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	DIS2CH_1OUT_CB_RESP(get_rep_queue_info, false, NBL_CHAN_MSG_GET_REP_QUEUE_INFO,
			    struct nbl_ch_prm_get_queue_info, (void)0);
}

static int nbl_disp_get_rep_queue_info_loc(void *priv, struct nbl_ch_prm_get_queue_info *output)
{
	return DIS2RES_1OUT_CB_LOC(get_rep_queue_info, false, output, true, int);
}

static int nbl_disp_chan_get_user_queue_info_req(void *priv, u16 *vsi_id,
						 struct nbl_ch_prm_get_queue_info *output)
{
	return DIS2CH_2IN_OUT_RESRET_AS_CHRET_CB_REQ(vsi_id, NBL_CHAN_MSG_GET_USER_QUEUE_INFO,
						     output);
}

static void nbl_disp_chan_get_user_queue_info_resp(void *priv, u16 src_id, u16 msg_id,
						   void *data, u32 data_len)
{
	DIS2CH_2IN_OUT_CB_RESP(get_user_queue_info, false, u16,
			       NBL_CHAN_MSG_GET_USER_QUEUE_INFO,
			       struct nbl_ch_prm_get_queue_info, (void)0);
}

static int nbl_disp_get_user_queue_info_loc(void *priv, u16 *vsi_id,
					    struct nbl_ch_prm_get_queue_info *output)
{
	return DIS2RES_2IN_OUT_CB_LOC(get_user_queue_info, false, vsi_id, output, true, int);
}

static int nbl_disp_ctrl_port_led(void *priv, u8 eth_id,
				  enum nbl_led_reg_ctrl led_ctrl, u32 *led_reg)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->ctrl_port_led,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id, led_ctrl, led_reg));
}

static int nbl_disp_chan_ctrl_port_led_req(void *priv, u8 eth_id,
					   enum nbl_led_reg_ctrl led_ctrl,
					   u32 *led_reg)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_chan_param_ctrl_port_led param = {0};
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.eth_id = eth_id;
	param.led_status = led_ctrl;
	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_CTRL_PORT_LED,
		      &param, sizeof(param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_ctrl_port_led_resp(void *priv, u16 src_id, u16 msg_id,
					     void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	struct nbl_chan_param_ctrl_port_led *param = {0};
	int ret = NBL_CHAN_RESP_OK;

	param = (struct nbl_chan_param_ctrl_port_led *)data;
	ret = NBL_OPS_CALL(res_ops->ctrl_port_led,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
			   param->eth_id, param->led_status, NULL));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_CTRL_PORT_LED, msg_id,
		     ret, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_passthrough_fw_cmd(void *priv, struct nbl_passthrough_fw_cmd_param *param,
				       struct nbl_passthrough_fw_cmd_param *result)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->passthrough_fw_cmd,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param, result));
}

static int nbl_disp_nway_reset(void *priv, u8 eth_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->nway_reset,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), eth_id));
}

static int nbl_disp_chan_nway_reset_req(void *priv, u8 eth_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_NWAY_RESET,
		      &eth_id, sizeof(eth_id), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_nway_reset_resp(void *priv, u16 src_id, u16 msg_id,
					  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	u8 *eth_id;
	int ret = NBL_CHAN_RESP_OK;

	eth_id = (u8 *)data;
	ret = NBL_OPS_CALL(res_ops->nway_reset,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), *eth_id));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_NWAY_RESET, msg_id,
		     ret, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static u16 nbl_disp_get_vf_base_vsi_id(void *priv, u16 func_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_vf_base_vsi_id,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), func_id));
}

static u16 nbl_disp_chan_get_vf_base_vsi_id_req(void *priv, u16 func_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	u16 vf_base_vsi_id = 0;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_GET_VF_BASE_VSI_ID,
		      NULL, 0, &vf_base_vsi_id, sizeof(vf_base_vsi_id), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);

	return vf_base_vsi_id;
}

static void nbl_disp_chan_get_vf_base_vsi_id_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;
	u16 vf_base_vsi_id;

	vf_base_vsi_id = NBL_OPS_CALL(res_ops->get_vf_base_vsi_id,
				      (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), src_id));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_VF_BASE_VSI_ID, msg_id,
		     ret, &vf_base_vsi_id, sizeof(vf_base_vsi_id));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static u16 nbl_disp_get_intr_suppress_level_loc(void *priv,
						struct nbl_get_intr_suppress_level_param *prm)
{
	return DIS2RES_2IN_CB_LOC(get_intr_suppress_level, false, prm, true, u16);
}

static int nbl_disp_set_intr_suppress_level_loc(void *priv,
						struct nbl_ch_prm_set_intr_suppress_level *param)
{
	return DIS2RES_2IN_CB_LOC(set_intr_suppress_level, true, param, true, int);
}

static int nbl_disp_chan_set_suppress_level_req(void *priv,
						struct nbl_ch_prm_set_intr_suppress_level *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ_NOACK(param,
						       NBL_CHAN_MSG_SET_INTL_SUPPRESS_LEVEL);
}

static void nbl_disp_chan_set_intr_suppress_level_resp(void *priv, u16 src_id, u16 msg_id,
						       void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP_NOACK(set_intr_suppress_level, true,
						 struct nbl_ch_prm_set_intr_suppress_level,
						 p->sfid = src_id);
}

static u32 nbl_disp_get_p4_version(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_p4_version,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static int nbl_disp_get_p4_info(void *priv, char *verify_code)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_p4_info,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), verify_code));
}

static int nbl_disp_load_p4(void *priv, struct nbl_load_p4_param *param)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->load_p4, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param));
}

static int nbl_disp_chan_get_p4_used_req(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	int p4_type;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_GET_P4_USED,
		      NULL, 0, &p4_type, sizeof(p4_type), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);

	return p4_type;
}

static void nbl_disp_chan_get_p4_used_resp(void *priv, u16 src_id, u16 msg_id,
					   void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;
	int p4_type;

	p4_type = NBL_OPS_CALL(res_ops->get_p4_used, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_P4_USED, msg_id,
		     ret, &p4_type, sizeof(p4_type));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_get_p4_used(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_p4_used, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static int nbl_disp_set_p4_used_loc(void *priv, int *p4_type)
{
	return DIS2RES_2IN_CB_LOC(set_p4_used, false, p4_type, true, int);
}

static int nbl_disp_chan_cfg_eth_bond_info_req(void *priv, struct nbl_lag_member_list_param *param)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_CFG_ETH_BOND_INFO,
		      param, sizeof(*param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_cfg_eth_bond_info_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;

	ret = NBL_OPS_CALL(res_ops->cfg_eth_bond_info, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
							(struct nbl_lag_member_list_param *)data));

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_CFG_ETH_BOND_INFO, msg_id, ret, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_cfg_eth_bond_info(void *priv, struct nbl_lag_member_list_param *param)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->cfg_eth_bond_info, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
			    param));
}

static int nbl_disp_chan_add_nd_upcall_flow(void *priv, u16 vsi_id, bool for_pmd)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->add_nd_upcall_flow,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id, for_pmd);
}

static int nbl_disp_chan_add_nd_upcall_flow_req(void *priv, u16 vsi_id, bool for_pmd)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = { 0 };
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_chan_param_nd_upcall param = { 0 };

	param.vsi_id = vsi_id;
	param.for_pmd = for_pmd;
	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_ADD_ND_UPCALL_FLOW,
		      &param, sizeof(param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_add_nd_upcall_flow_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_nd_upcall *param =
		(struct nbl_chan_param_nd_upcall *)data;
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;
	int ret;

	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->add_nd_upcall_flow,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
				param->vsi_id, param->for_pmd);
	if (ret) {
		err = NBL_CHAN_RESP_ERR;
		dev_err(dev, "disp set nd dup rule failed with ret: %d\n", ret);
	}

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_ADD_ND_UPCALL_FLOW,
		     msg_id, err, NULL, 0);
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "disp chan send ack failed with ret: %d, msg_type: %d, src_id: %d\n",
			ret, NBL_CHAN_MSG_SET_UPCALL_RULE, src_id);
}

static void nbl_disp_chan_del_nd_upcall_flow(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->del_nd_upcall_flow,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
}

static void nbl_disp_chan_del_nd_upcall_flow_req(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_DEL_ND_UPCALL_FLOW,
		      NULL, 0, NULL, 0, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_del_nd_upcall_flow_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	struct nbl_common_info *common;
	int err = NBL_CHAN_RESP_OK;
	int ret;

	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->del_nd_upcall_flow,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_DEL_ND_UPCALL_FLOW,
		     msg_id, err, NULL, 0);
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "disp chan send ack failed with ret: %d, msg_type: %d, src_id: %d\n",
			ret, NBL_CHAN_MSG_SET_UPCALL_RULE, src_id);
}

static int nbl_disp_chan_get_board_id_req(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	int result = -1;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_GET_BOARD_ID,
		      NULL, 0, &result, sizeof(result), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);

	return result;
}

static void nbl_disp_chan_get_board_id_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK, result = -1;

	result = NBL_OPS_CALL(res_ops->get_board_id, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_BOARD_ID,
		     msg_id, ret, &result, sizeof(result));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_get_board_id(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_board_id, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static dma_addr_t nbl_disp_restore_abnormal_ring_loc(void *priv,
						     struct nbl_abnormal_ring_param *param)
{
	return DIS2RES_2IN_CB_LOC(restore_abnormal_ring, false, param, true,
				  dma_addr_t);
}

static int nbl_disp_restart_abnormal_ring_loc(void *priv,
					      struct nbl_abnormal_ring_param *param)
{
	return DIS2RES_2IN_CB_LOC(restart_abnormal_ring, false, param, true, int);
}

static int nbl_disp_chan_restore_hw_queue_req(void *priv,
					      struct nbl_ch_prm_restore_hw_queue *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_RESTORE_HW_QUEUE);
}

static void nbl_disp_chan_restore_hw_queue_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(restore_hw_queue, true,
					   struct nbl_ch_prm_restore_hw_queue,
					   NBL_CHAN_MSG_RESTORE_HW_QUEUE, (void)0);
}

static int nbl_disp_restore_hw_queue_loc(void *priv,
					 struct nbl_ch_prm_restore_hw_queue *param)
{
	return DIS2RES_2IN_CB_LOC(restore_hw_queue, true, param, true, int);
}

static int nbl_disp_chan_stop_abnormal_hw_queue_req(void *priv,
						    struct nbl_ch_prm_stop_abnormal_hw_queue *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param,
					 NBL_CHAN_MSG_STOP_ABNORMAL_HW_QUEUE);
}

static void nbl_disp_chan_stop_abnormal_hw_queue_resp(void *priv, u16 src_id,
						      u16 msg_id, void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(stop_abnormal_hw_queue, true,
					   struct nbl_ch_prm_stop_abnormal_hw_queue,
					   NBL_CHAN_MSG_STOP_ABNORMAL_HW_QUEUE, (void)0);
}

static int nbl_disp_stop_abnormal_hw_queue_loc(void *priv,
					       struct nbl_ch_prm_stop_abnormal_hw_queue *param)
{
	return DIS2RES_2IN_CB_LOC(stop_abnormal_hw_queue, true, param, true, int);
}

static int nbl_disp_stop_abnormal_sw_queue_loc(void *priv,
					       struct nbl_stop_abnormal_sw_queue_param *param)
{
	return DIS2RES_2IN_CB_LOC(stop_abnormal_sw_queue, true, param, true, int);
}

static u16 nbl_disp_get_local_queue_id_loc(void *priv,
					   struct nbl_get_local_queue_id_param *param)
{
	return DIS2RES_2IN_CB_LOC(get_local_queue_id, false, param, true, u16);
}

static int nbl_disp_chan_get_eth_bond_info_req(void *priv, struct nbl_bond_param *param)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_GET_ETH_BOND_INFO, NULL, 0, param, sizeof(*param), 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_eth_bond_info_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_bond_param result;
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;

	memset(&result, 0, sizeof(result));

	NBL_OPS_CALL(res_ops->get_eth_bond_info, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), &result));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_ETH_BOND_INFO,
		     msg_id, ret, &result, sizeof(result));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_get_eth_bond_info(void *priv, struct nbl_bond_param *param)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_eth_bond_info,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param));
}

static void nbl_disp_cfg_eth_bond_event(void *priv, bool enable)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL(res_ops->cfg_eth_bond_event, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), enable));
}

static int nbl_disp_set_bridge_mode(void *priv, u16 bmode)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->set_bridge_mode,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
				 NBL_COMMON_TO_MGT_PF(common), bmode);
}

static int nbl_disp_chan_set_bridge_mode_req(void *priv, u16 bmode)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_SET_BRIDGE_MODE, &bmode, sizeof(bmode), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_set_bridge_mode_resp(void *priv, u16 src_id, u16 msg_id,
					       void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;
	u16 *bmode;

	bmode = (u16 *)data;
	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->set_bridge_mode,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), src_id, *bmode);
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SET_BRIDGE_MODE,
		     msg_id, ret, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static u16 nbl_disp_get_vf_function_id(void *priv, u16 vsi_id, int vf_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_vf_function_id,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id, vf_id));
}

static u16 nbl_disp_chan_get_vf_function_id_req(void *priv, u16 vsi_id, int vf_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_chan_param_get_vf_func_id param;
	struct nbl_common_info *common;
	u16 func_id = 0;

	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	param.vsi_id = vsi_id;
	param.vf_id = vf_id;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_GET_VF_FUNCTION_ID, &param,
		      sizeof(param), &func_id, sizeof(func_id), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);

	return func_id;
}

static void nbl_disp_chan_get_vf_function_id_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_get_vf_func_id *param;
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;
	u16 func_id;

	param = (struct nbl_chan_param_get_vf_func_id *)data;
	func_id = NBL_OPS_CALL(res_ops->get_vf_function_id,
			       (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->vsi_id, param->vf_id));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_VF_FUNCTION_ID, msg_id,
		     ret, &func_id, sizeof(func_id));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static u16 nbl_disp_get_vf_vsi_id(void *priv, u16 vsi_id, int vf_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_vf_vsi_id,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id, vf_id));
}

static u16 nbl_disp_chan_get_vf_vsi_id_req(void *priv, u16 vsi_id, int vf_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_chan_param_get_vf_vsi_id param;
	struct nbl_common_info *common;
	u16 vf_vsi = 0;

	common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	param.vsi_id = vsi_id;
	param.vf_id = vf_id;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_GET_VF_VSI_ID, &param,
		      sizeof(param), &vf_vsi, sizeof(vf_vsi), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);

	return vf_vsi;
}

static void nbl_disp_chan_get_vf_vsi_id_resp(void *priv, u16 src_id, u16 msg_id,
					     void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_get_vf_vsi_id *param;
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;
	u16 vsi_id;

	param = (struct nbl_chan_param_get_vf_vsi_id *)data;
	vsi_id = NBL_OPS_CALL(res_ops->get_vf_vsi_id,
			      (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->vsi_id, param->vf_id));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_VF_VSI_ID, msg_id,
		     ret, &vsi_id, sizeof(vsi_id));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_register_func_mac(void *priv, u8 *mac, u16 func_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL(res_ops->register_func_mac,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), mac, func_id));
}

static bool nbl_disp_check_vf_is_active(void *priv, u16 func_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = false;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL(res_ops->check_vf_is_active,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), func_id));
	return ret;
}

static bool nbl_disp_chan_check_vf_is_active_req(void *priv, u16 func_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	bool is_active;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_CHECK_VF_IS_ACTIVE, &func_id, sizeof(func_id),
		      &is_active, sizeof(is_active), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);

	return is_active;
}

static void nbl_disp_chan_check_vf_is_active_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_chan_ack_info chan_ack;
	u16 func_id;
	bool is_active;
	int err = NBL_CHAN_RESP_OK;
	int ret = 0;

	func_id = *(u16 *)data;

	is_active = NBL_OPS_CALL(res_ops->check_vf_is_active,
				 (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), func_id));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_CHECK_VF_IS_ACTIVE, msg_id,
		     err, &is_active, sizeof(is_active));
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d\n",
			ret, NBL_CHAN_CHECK_VF_IS_ACTIVE);
}

static int nbl_disp_check_vf_is_vdpa(void *priv, u16 func_id, u8 *is_vdpa)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = false;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL(res_ops->check_vf_is_vdpa,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), func_id, is_vdpa));
	return ret;
}

static int nbl_disp_chan_check_vf_is_vdpa_req(void *priv, u16 func_id, u8 *is_vdpa)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_CHECK_VF_IS_VDPA, &func_id, sizeof(func_id),
		      is_vdpa, sizeof(*is_vdpa), 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_check_vf_is_vdpa_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(disp_mgt->common);
	struct nbl_chan_ack_info chan_ack;
	u16 func_id;
	int err = NBL_CHAN_RESP_OK;
	u8 is_vdpa = 0;
	int ret = 0;

	func_id = *(u16 *)data;

	err = NBL_OPS_CALL(res_ops->check_vf_is_vdpa,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), func_id, &is_vdpa));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_CHECK_VF_IS_VDPA, msg_id,
		     err, &is_vdpa, sizeof(is_vdpa));
	ret = chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	if (ret)
		dev_err(dev, "channel send ack failed with ret: %d, msg_type: %d\n",
			ret, NBL_CHAN_CHECK_VF_IS_VDPA);
}

static int nbl_disp_get_vdpa_vf_stats(void *priv, u16 func_id, struct nbl_vf_stats *vf_stats)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = false;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL(res_ops->get_vdpa_vf_stats,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), func_id, vf_stats));
	return ret;
}

static int nbl_disp_chan_get_vdpa_vf_stats_req(void *priv, u16 func_id,
					       struct nbl_vf_stats *vf_stats)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_GET_VDPA_VF_STATS,
		      &func_id, sizeof(func_id), vf_stats, sizeof(*vf_stats), 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_vdpa_vf_stats_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	u16 func_id;
	struct nbl_vf_stats vf_stats = {0};
	int err = NBL_CHAN_RESP_OK;

	func_id = *(u16 *)data;

	err = NBL_OPS_CALL(res_ops->get_vdpa_vf_stats,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), func_id, &vf_stats));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_VDPA_VF_STATS, msg_id,
		     err, &vf_stats, sizeof(vf_stats));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_get_uvn_pkt_drop_stats(void *priv, u16 vsi_id,
					   u16 num_queues, u32 *uvn_stat_pkt_drop)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	int ret = 0;

	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->get_uvn_pkt_drop_stats,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
				vsi_id, num_queues, uvn_stat_pkt_drop);
	return ret;
}

static int nbl_disp_chan_get_uvn_pkt_drop_stats_req(void *priv, u16 vsi_id, u16 num_queues,
						    u32 *uvn_stat_pkt_drop)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_chan_param_get_uvn_pkt_drop_stats param = {0};
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.vsi_id = vsi_id;
	param.num_queues = num_queues;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_GET_UVN_PKT_DROP_STATS,
		      &param, sizeof(param),
		      uvn_stat_pkt_drop, num_queues * sizeof(*uvn_stat_pkt_drop), 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_uvn_pkt_drop_stats_resp(void *priv, u16 src_id, u16 msg_id,
						      void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_get_uvn_pkt_drop_stats *param = {0};
	struct nbl_chan_ack_info chan_ack;
	u32 *uvn_stat_pkt_drop = NULL;
	int err = NBL_CHAN_RESP_OK;

	param = (struct nbl_chan_param_get_uvn_pkt_drop_stats *)data;
	uvn_stat_pkt_drop = kcalloc(param->num_queues, sizeof(*uvn_stat_pkt_drop), GFP_KERNEL);
	if (!uvn_stat_pkt_drop) {
		err = -ENOMEM;
		goto send_ack;
	}

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->get_uvn_pkt_drop_stats,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
			  param->vsi_id, param->num_queues, uvn_stat_pkt_drop);
send_ack:
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_GET_UVN_PKT_DROP_STATS, msg_id,
		     err, uvn_stat_pkt_drop, param->num_queues * sizeof(*uvn_stat_pkt_drop));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);

	kfree(uvn_stat_pkt_drop);
}

static int nbl_disp_get_pkt_drop_stats(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	int ret = 0;

	ret = NBL_OPS_CALL(res_ops->get_pkt_drop_stats,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
	return ret;
}

static int nbl_disp_chan_get_pkt_drop_stats_req(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_GET_PKT_DROP_STATS,
		      NULL, 0, NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_pkt_drop_stats_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int err = NBL_CHAN_RESP_OK;

	err = NBL_OPS_CALL(res_ops->get_pkt_drop_stats,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_GET_PKT_DROP_STATS, msg_id,
		     err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_get_total_pkt_drop_stats(void *priv, u8 eth_id, enum nbl_stat_type type,
					     struct nbl_chan_param_drop_stats_resp *drop_stats)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_chan_param_get_total_drop param;
	int ret = 0;

	param.eth_id = eth_id;
	param.op_type = type;
	ret = NBL_OPS_CALL(res_ops->get_total_pkt_drop_stats,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), &param, drop_stats));

	return ret;
}

static int
nbl_disp_chan_get_total_pkt_drop_stats_req(void *priv, u8 eth_id, enum nbl_stat_type type,
					   struct nbl_chan_param_drop_stats_resp *drop_stats)

{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_chan_param_get_total_drop param;

	param.eth_id = eth_id;
	param.op_type = type;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_GET_TOTAL_PKT_DROP_STATS,
		      &param, sizeof(param), drop_stats, sizeof(*drop_stats), 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_get_total_pkt_drop_stats_resp(void *priv, u16 src_id, u16 msg_id,
							void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int copy_len;
	struct nbl_chan_param_drop_stats_resp drop_stats = {0};
	struct nbl_chan_param_get_total_drop param;
	int err = NBL_CHAN_RESP_OK;

	memset(&param, 0, sizeof(param));
	copy_len = data_len < sizeof(param) ? data_len : sizeof(param);
	memcpy(&param, data, copy_len);

	err = NBL_OPS_CALL(res_ops->get_total_pkt_drop_stats,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), &param, &drop_stats));
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_GET_TOTAL_PKT_DROP_STATS, msg_id,
		     err, &drop_stats, sizeof(drop_stats));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_chan_register_func_mac_req(void *priv, u8 *mac, u16 func_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_chan_param_register_func_mac param;
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.func_id = func_id;
	ether_addr_copy(param.mac, mac);

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_REGISTER_FUNC_MAC, &param, sizeof(param), NULL, 0, 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_register_func_mac_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_register_func_mac *param;
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;

	param = (struct nbl_chan_param_register_func_mac *)data;
	NBL_OPS_CALL(res_ops->register_func_mac,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->mac, param->func_id));

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_REGISTER_FUNC_MAC, msg_id, ret, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_register_func_trust(void *priv, u16 func_id,
					bool trusted, bool *should_notify)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->register_func_trust,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), func_id,
			    trusted, should_notify));
}

static int nbl_disp_chan_register_func_trust_req(void *priv, u16 func_id,
						 bool trusted, bool *should_notify)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_chan_param_register_trust param;
	bool result;
	int ret;

	param.func_id = func_id;
	param.trusted = trusted;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_REGISTER_FUNC_TRUST, &param, sizeof(param),
		      &result, sizeof(result), 1);
	ret = chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
	if (!ret)
		*should_notify = result;

	return ret;
}

static void nbl_disp_chan_register_func_trust_resp(void *priv, u16 src_id, u16 msg_id,
						   void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_register_trust *param;
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;
	bool notify = false;

	param = (struct nbl_chan_param_register_trust *)data;
	ret = NBL_OPS_CALL(res_ops->register_func_trust,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->func_id,
			   param->trusted, &notify));

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_REGISTER_FUNC_TRUST,
		     msg_id, ret, &notify, sizeof(notify));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_register_func_vlan(void *priv, u16 func_id, u16 vlan_tci,
				       u16 vlan_proto, bool *should_notify)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->register_func_vlan,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), func_id, vlan_tci,
			    vlan_proto, should_notify));
}

static int nbl_disp_chan_register_func_vlan_req(void *priv, u16 func_id, u16 vlan_tci,
						u16 vlan_proto, bool *should_notify)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_chan_param_register_vlan param;
	bool result;
	int ret;

	param.func_id = func_id;
	param.vlan_tci = vlan_tci;
	param.vlan_proto = vlan_proto;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_REGISTER_FUNC_VLAN, &param, sizeof(param),
		      &result, sizeof(result), 1);
	ret = chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
	if (!ret)
		*should_notify = result;

	return ret;
}

static void nbl_disp_chan_register_func_vlan_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_register_vlan *param;
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;
	bool notify = false;

	param = (struct nbl_chan_param_register_vlan *)data;
	ret = NBL_OPS_CALL(res_ops->register_func_vlan,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->func_id,
			   param->vlan_tci, param->vlan_proto, &notify));

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_REGISTER_FUNC_VLAN,
		     msg_id, ret, &notify, sizeof(notify));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_register_func_rate(void *priv, u16 func_id, int rate)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->register_func_rate,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), func_id, rate));
}

static int nbl_disp_chan_register_func_rate_req(void *priv, u16 func_id, int tx_rate)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_chan_param_set_tx_rate param;
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.func_id = func_id;
	param.tx_rate = tx_rate;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_REGISTER_FUNC_RATE, &param, sizeof(param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_register_func_rate_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_set_tx_rate *param;
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;

	param = (struct nbl_chan_param_set_tx_rate *)data;
	ret = NBL_OPS_CALL(res_ops->register_func_rate,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->func_id, param->tx_rate));

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_REGISTER_FUNC_RATE, msg_id, ret, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_set_tx_rate(void *priv, u16 func_id, int tx_rate, int burst)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->set_tx_rate,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), func_id, tx_rate, burst));
}

static int nbl_disp_chan_set_tx_rate_req(void *priv, u16 func_id, int tx_rate, int burst)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_chan_param_set_txrx_rate param;
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.func_id = func_id;
	param.txrx_rate = tx_rate;
	param.burst = burst;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_SET_TX_RATE, &param, sizeof(param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_set_tx_rate_resp(void *priv, u16 src_id, u16 msg_id,
					   void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_set_txrx_rate *param;
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;

	param = (struct nbl_chan_param_set_txrx_rate *)data;
	ret = NBL_OPS_CALL(res_ops->set_tx_rate,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->func_id,
			   param->txrx_rate, param->burst));

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SET_TX_RATE, msg_id, ret, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_set_rx_rate(void *priv, u16 func_id, int rx_rate, int burst)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->set_rx_rate,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), func_id, rx_rate, burst));
}

static int nbl_disp_chan_set_rx_rate_req(void *priv, u16 func_id, int rx_rate, int burst)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_chan_param_set_txrx_rate param;
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);

	param.func_id = func_id;
	param.txrx_rate = rx_rate;
	param.burst = burst;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_SET_RX_RATE, &param, sizeof(param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_set_rx_rate_resp(void *priv, u16 src_id, u16 msg_id,
					   void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_set_txrx_rate *param;
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;

	param = (struct nbl_chan_param_set_txrx_rate *)data;
	ret = NBL_OPS_CALL(res_ops->set_rx_rate,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->func_id,
			   param->txrx_rate, param->burst));

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_SET_RX_RATE, msg_id, ret, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_register_func_link_forced(void *priv, u16 func_id, u8 link_forced,
					      bool *should_notify)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->register_func_link_forced,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), func_id,
			     link_forced, should_notify));
}

static int nbl_disp_chan_register_func_link_forced_req(void *priv, u16 func_id, u8 link_forced,
						       bool *should_notify)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_chan_param_register_func_link_forced param;
	struct nbl_chan_param_register_func_link_forced result;
	int ret = 0;

	param.func_id = func_id;
	param.link_forced = link_forced;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_REGISTER_FUNC_LINK_FORCED, &param, sizeof(param),
		      &result, sizeof(result), 1);
	ret = chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
	if (ret)
		return ret;

	*should_notify = result.should_notify;
	return 0;
}

static void nbl_disp_chan_register_func_link_forced_resp(void *priv, u16 src_id, u16 msg_id,
							 void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_register_func_link_forced *param;
	struct nbl_chan_param_register_func_link_forced result = {0};
	struct nbl_chan_ack_info chan_ack;
	int ret = NBL_CHAN_RESP_OK;

	param = (struct nbl_chan_param_register_func_link_forced *)data;
	ret = NBL_OPS_CALL(res_ops->register_func_link_forced,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
			   param->func_id, param->link_forced, &result.should_notify));

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_REGISTER_FUNC_LINK_FORCED,
		     msg_id, ret, &result, sizeof(result));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_get_link_forced(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_link_forced,
			    (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id));
}

static int nbl_disp_chan_get_link_forced_req(void *priv, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	int link_forced = 0;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_GET_LINK_FORCED, &vsi_id, sizeof(vsi_id),
		      &link_forced, sizeof(link_forced), 1);
	chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);

	return link_forced;
}

static void nbl_disp_chan_get_link_forced_resp(void *priv, u16 src_id, u16 msg_id,
					       void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int ret = 0;

	ret = NBL_OPS_CALL(res_ops->get_link_forced,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), *(u16 *)data));

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_LINK_FORCED,
		     msg_id, NBL_CHAN_RESP_OK, &ret, sizeof(ret));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static void nbl_disp_setup_rdma_id(void *priv, struct ida *adev_ida, struct ida *grc_adev_ida,
				   struct mutex *lock)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL(res_ops->setup_rdma_id,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), adev_ida, grc_adev_ida, lock));
}

static void nbl_disp_remove_rdma_id(void *priv, struct ida *adev_ida, struct ida *grc_adev_ida,
				    struct mutex *lock)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL(res_ops->remove_rdma_id,
		     (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), adev_ida, grc_adev_ida, lock));
}

static int nbl_disp_check_mtu(void *priv, bool force_xdp, int new_mtu, int *max_mtu)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL(res_ops->check_mtu,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), force_xdp, new_mtu, max_mtu));
	return ret;
}

static int nbl_disp_set_mtu(void *priv, u16 vsi_id, u16 mtu)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops;
	int ret = 0;

	res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	ret = NBL_OPS_CALL(res_ops->set_mtu, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id, mtu));
	return ret;
}

static int nbl_disp_chan_set_mtu_req(void *priv, u16 vsi_id, u16 mtu)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_chan_param_set_mtu param = {0};

	param.mtu = mtu;
	param.vsi_id = vsi_id;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common), NBL_CHAN_MSG_MTU_SET,
		      &param, sizeof(param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt),
				  &chan_send);
}

static void nbl_disp_chan_set_mtu_resp(void *priv,
				       u16 src_id, u16 msg_id, void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	struct nbl_chan_param_set_mtu *param = NULL;
	int err = NBL_CHAN_RESP_OK;

	param = (struct nbl_chan_param_set_mtu *)data;
	err = NBL_OPS_CALL(res_ops->set_mtu,
			   (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->vsi_id, param->mtu));

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_MTU_SET, msg_id, err, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_chan_get_fd_flow_req(void *priv, u16 vsi_id, u32 location,
					 enum nbl_chan_fdir_rule_type rule_type,
					 struct nbl_chan_param_fdir_replace *cmd)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_chan_param_get_fd_flow param = {0};
	int ret = 0;

	param.vsi_id = vsi_id;
	param.location = location;
	param.rule_type = rule_type;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_GET_FD_FLOW, &param,
		      sizeof(param), cmd, NBL_CHAN_FDIR_FLOW_RULE_SIZE, 1);
	ret = chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
	if (ret)
		return ret;

	return 0;
}

static void nbl_disp_chan_get_fd_flow_resp(void *priv, u16 src_id, u16 msg_id,
					   void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_get_fd_flow *param = NULL;
	struct nbl_chan_param_fdir_replace *result;
	struct nbl_chan_ack_info chan_ack;
	int ret = 0;

	result = kzalloc(NBL_CHAN_FDIR_FLOW_RULE_SIZE, GFP_KERNEL);
	if (!result) {
		ret = -ENOMEM;
		goto send_ack;
	}
	param = (struct nbl_chan_param_get_fd_flow *)data;
	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->get_fd_flow,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->vsi_id, param->location,
				param->rule_type, result);
send_ack:
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_FD_FLOW, msg_id,
		     ret, result, sizeof(*result) + result->tlv_length);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
	kfree(result);
}

static int nbl_disp_get_fd_flow(void *priv, u16 vsi_id, u32 location,
				enum nbl_chan_fdir_rule_type rule_type,
				struct nbl_chan_param_fdir_replace *cmd)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->get_fd_flow,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), vsi_id, location,
				 rule_type, cmd);
}

static int nbl_disp_chan_get_fd_flow_cnt_req(void *priv, enum nbl_chan_fdir_rule_type rule_type,
					     u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_chan_param_fdir_flowcnt param;
	int result = 0, ret = 0;

	param.rule_type = rule_type;
	param.vsi = vsi_id;
	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_GET_FD_FLOW_CNT, &param,
		      sizeof(param), &result, sizeof(result), 1);
	ret = chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
	if (ret)
		return ret;

	return result;
}

static void nbl_disp_chan_get_fd_flow_cnt_resp(void *priv, u16 src_id, u16 msg_id,
					       void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	struct nbl_chan_param_fdir_flowcnt *param;
	int result = 0, err = NBL_CHAN_RESP_OK;

	param = (struct nbl_chan_param_fdir_flowcnt *)data;
	result = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->get_fd_flow_cnt,
				   NBL_DISP_MGT_TO_RES_PRIV(disp_mgt),
				   param->rule_type, param->vsi);
	if (result < 0) {
		err = result;
		result = 0;
	}

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_FD_FLOW_CNT, msg_id,
		     err, &result, sizeof(result));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_get_fd_flow_cnt(void *priv, enum nbl_chan_fdir_rule_type rule_type, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->get_fd_flow_cnt,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), rule_type, vsi_id);
}

static int nbl_disp_chan_get_fd_flow_all_req(void *priv,
					     struct nbl_chan_param_get_fd_flow_all *param,
					     u32 *rule_locs)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_chan_result_get_fd_flow_all *result = NULL;
	int ret = 0;

	result = (struct nbl_chan_result_get_fd_flow_all *)rule_locs;
	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_GET_FD_FLOW_ALL, param,
		      sizeof(*param), result, sizeof(*result), 1);
	ret = chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
	if (ret)
		goto send_fail;
send_fail:
	return ret;
}

static void nbl_disp_chan_get_fd_flow_all_resp(void *priv, u16 src_id, u16 msg_id,
					       void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_get_fd_flow_all *param = NULL;
	struct nbl_chan_result_get_fd_flow_all *result = NULL;
	struct nbl_chan_ack_info chan_ack;
	int ret = 0;

	result = kzalloc(sizeof(*result), GFP_KERNEL);
	if (!result) {
		ret = -ENOMEM;
		goto send_ack;
	}

	param = (struct nbl_chan_param_get_fd_flow_all *)data;
	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->get_fd_flow_all,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param, result->rule_locs);

send_ack:
	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_FD_FLOW_ALL, msg_id,
		     ret, result, sizeof(*result));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);

	kfree(result);
}

static int nbl_disp_get_fd_flow_all(void *priv, struct nbl_chan_param_get_fd_flow_all *param,
				    u32 *rule_locs)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->get_fd_flow_all,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param, rule_locs);
}

static int nbl_disp_chan_get_fd_flow_max_req(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};
	int ret = 0, result = 0;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_GET_FD_FLOW_MAX, NULL, 0, &result, sizeof(result), 1);
	ret = chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
	if (ret)
		return ret;

	return result;
}

static void nbl_disp_chan_get_fd_flow_max_resp(void *priv, u16 src_id, u16 msg_id,
					       void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_ack_info chan_ack;
	int result = 0, err = NBL_CHAN_RESP_OK;

	result = NBL_OPS_CALL(res_ops->get_fd_flow_max, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
	if (result < 0) {
		err = result;
		result = 0;
	}

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_GET_FD_FLOW_MAX, msg_id,
		     err, &result, sizeof(result));
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_get_fd_flow_max(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL(res_ops->get_fd_flow_max, (NBL_DISP_MGT_TO_RES_PRIV(disp_mgt)));
}

static int nbl_disp_chan_replace_fd_flow_req(void *priv, struct nbl_chan_param_fdir_replace *info)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_chan_send_info chan_send = {0};

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_REPLACE_FD_FLOW, info,
		      sizeof(struct nbl_chan_param_fdir_replace) + info->tlv_length, NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_replace_fd_flow_resp(void *priv, u16 src_id, u16 msg_id,
					       void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_fdir_replace *param = NULL;
	struct nbl_chan_ack_info chan_ack;
	int ret = 0;

	param = (struct nbl_chan_param_fdir_replace *)data;

	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->replace_fd_flow,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_REPLACE_FD_FLOW, msg_id, ret, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_replace_fd_flow(void *priv, struct nbl_chan_param_fdir_replace *info)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->replace_fd_flow,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), info);
}

static int nbl_disp_chan_remove_fd_flow_req(void *priv, enum nbl_chan_fdir_rule_type rule_type,
					    u32 loc, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_chan_param_fdir_del param = {0};
	struct nbl_chan_send_info chan_send = {0};

	param.rule_type = rule_type;
	param.location = loc;
	param.vsi = vsi_id;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_REMOVE_FD_FLOW, &param, sizeof(param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_remove_fd_flow_resp(void *priv, u16 src_id, u16 msg_id,
					      void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_fdir_del *param = NULL;
	struct nbl_chan_ack_info chan_ack;
	int ret = 0;

	param = (struct nbl_chan_param_fdir_del *)data;

	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->remove_fd_flow,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->rule_type,
				param->location, param->vsi);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_REMOVE_FD_FLOW, msg_id, ret, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_remove_fd_flow(void *priv, enum nbl_chan_fdir_rule_type rule_type,
				   u32 loc, u16 vsi_id)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->remove_fd_flow,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), rule_type, loc, vsi_id);
}

static int nbl_disp_chan_config_fd_flow_state_req(void *priv,
						  enum nbl_chan_fdir_rule_type rule_type,
						  u16 vsi_id, u16 state)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_common_info *common = NBL_DISP_MGT_TO_COMMON(disp_mgt);
	struct nbl_chan_param_config_fd_flow_state param = {0};
	struct nbl_chan_send_info chan_send = {0};

	param.rule_type = rule_type;
	param.vsi_id = vsi_id;
	param.state = state;

	NBL_CHAN_SEND(chan_send, NBL_COMMON_TO_MGT_PF(common),
		      NBL_CHAN_MSG_CFG_FD_FLOW_STATE, &param, sizeof(param), NULL, 0, 1);
	return chan_ops->send_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_send);
}

static void nbl_disp_chan_config_fd_flow_state_resp(void *priv, u16 src_id, u16 msg_id,
						    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	struct nbl_chan_param_config_fd_flow_state *param = NULL;
	struct nbl_chan_ack_info chan_ack;
	int ret = 0;

	param = (struct nbl_chan_param_config_fd_flow_state *)data;

	ret = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->config_fd_flow_state,
				NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), param->rule_type,
				param->vsi_id, param->state);

	NBL_CHAN_ACK(chan_ack, src_id, NBL_CHAN_MSG_CFG_FD_FLOW_STATE, msg_id, ret, NULL, 0);
	chan_ops->send_ack(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt), &chan_ack);
}

static int nbl_disp_config_fd_flow_state(void *priv, enum nbl_chan_fdir_rule_type rule_type,
					 u16 vsi_id, u16 state)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	return NBL_OPS_CALL_LOCK(disp_mgt, res_ops->config_fd_flow_state,
				 NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), rule_type, vsi_id, state);
}

static void nbl_disp_cfg_fd_update_event(void *priv, bool enable)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->cfg_fd_update_event,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), enable);
}

static void nbl_disp_cfg_mirror_outputport_event_loc(void *priv, bool enable)
{
	DIS2RES_2IN_CB_LOC(cfg_mirror_outputport_event, true, enable, false, void);
}

static void nbl_disp_dump_fd_flow(void *priv, struct seq_file *m)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->dump_fd_flow,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), m);
}

static int nbl_disp_alloc_macsec_txsc_index(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	int index = 0;

	index = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->alloc_macsec_txsc_index,
				  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
	return index;
}

static void nbl_disp_free_macsec_txsc_index(void *priv, u8 index)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->free_macsec_txsc_index,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), index);
}

static int nbl_disp_alloc_macsec_rxsc_index(void *priv)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);
	int index = 0;

	index = NBL_OPS_CALL_LOCK(disp_mgt, res_ops->alloc_macsec_rxsc_index,
				  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt));
	return index;
}

static void nbl_disp_free_macsec_rxsc_index(void *priv, u8 index)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->free_macsec_rxsc_index,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), index);
}

static void nbl_disp_cfg_macsec_fs(void *priv, u32 index, struct nbl_macsec_fs *macsec_fs)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->cfg_macsec_fs,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), index, macsec_fs);
}

static void nbl_disp_cfg_macsec_txsc(void *priv, u32 index, struct nbl_macsec_tx_sc *tx_sc)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->cfg_macsec_txsc,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), index, tx_sc);
}

static void nbl_disp_cfg_macsec_rxsc(void *priv, u32 index, struct nbl_macsec_rx_sc *rx_sc)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->cfg_macsec_rxsc,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), index, rx_sc);
}

static void nbl_disp_cfg_macsec_sa(void *priv, u32 index, struct nbl_macsec_sa *sa, bool is_tx)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_resource_ops *res_ops = NBL_DISP_MGT_TO_RES_OPS(disp_mgt);

	NBL_OPS_CALL_LOCK(disp_mgt, res_ops->cfg_macsec_sa,
			  NBL_DISP_MGT_TO_RES_PRIV(disp_mgt), index, sa, is_tx);
}

static int nbl_disp_chan_get_xdp_queue_info_req(void *priv, u16 *param,
						struct nbl_ch_prm_get_queue_info *output)
{
	return DIS2CH_2IN_OUT_RESRET_AS_CHRET_CB_REQ(param,
						     NBL_CHAN_MSG_GET_XDP_QUEUE_INFO,
						     output);
}

static void nbl_disp_chan_get_xdp_queue_info_resp(void *priv, u16 src_id, u16 msg_id,
						  void *data, u32 data_len)
{
	DIS2CH_2IN_OUT_CB_RESP(get_xdp_queue_info, false, u16,
			       NBL_CHAN_MSG_GET_XDP_QUEUE_INFO,
			       struct nbl_ch_prm_get_queue_info, (void)0);
}

static int nbl_disp_get_xdp_queue_info_loc(void *priv, u16 *param,
					   struct nbl_ch_prm_get_queue_info *output)
{
	return DIS2RES_2IN_OUT_CB_LOC(get_xdp_queue_info, false, param, output, true, int);
}

static void nbl_disp_set_hw_status_loc(void *priv, enum nbl_hw_status hw_status)
{
	DIS2RES_2IN_CB_LOC(set_hw_status, true, hw_status, false, void);
}

static void nbl_disp_check_hw_status_loc(void *priv)
{
	DIS2RES_1IN_CB_LOC(check_hw_status, true, false, void);
}

static enum nbl_hw_status nbl_disp_get_hw_status_loc(void *priv)
{
	return DIS2RES_1IN_CB_LOC(get_hw_status, true, true, enum nbl_hw_status);
}

static void nbl_disp_get_active_func_bitmaps_loc(void *priv, unsigned long *bitmap, int max_func)
{
	DIS2RES_2IN_OUT_CB_LOC(get_active_func_bitmaps, true, max_func, bitmap, false, void);
}

static int nbl_disp_set_tc_wgt_loc(void *priv, struct nbl_ch_prm_set_tc_wgt *param)
{
	return DIS2RES_2IN_CB_LOC(set_tc_wgt, true, param, true, int);
}

static int nbl_disp_chan_set_tc_wgt_req(void *priv, struct nbl_ch_prm_set_tc_wgt *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_SET_TC_WGT);
}

static void nbl_disp_chan_set_tc_wgt_resp(void *priv, u16 src_id, u16 msg_id,
					  void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(set_tc_wgt, true,
					   struct nbl_ch_prm_set_tc_wgt,
					   NBL_CHAN_MSG_SET_TC_WGT, (void)0);
}

static int nbl_disp_configure_rdma_bw_loc(void *priv, struct nbl_ch_prm_configure_rdma_bw *param)
{
	return DIS2RES_2IN_CB_LOC(configure_rdma_bw, true, param, true, int);
}

static int
nbl_disp_chan_configure_rdma_bw_req(void *priv, struct nbl_ch_prm_configure_rdma_bw *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_CONFIGURE_RDMA_BW);
}

static void nbl_disp_chan_configure_rdma_bw_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(configure_rdma_bw, true,
					   struct nbl_ch_prm_configure_rdma_bw,
					   NBL_CHAN_MSG_CONFIGURE_RDMA_BW, (void)0);
}

static int nbl_disp_configure_qos_loc(void *priv, struct nbl_ch_prm_configure_qos *param)
{
	return DIS2RES_2IN_CB_LOC(configure_qos, true, param, true, int);
}

static int nbl_disp_chan_configure_qos_req(void *priv, struct nbl_ch_prm_configure_qos *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_CONFIGURE_QOS);
}

static void nbl_disp_chan_configure_qos_resp(void *priv, u16 src_id, u16 msg_id,
					     void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(configure_qos, true,
					   struct nbl_ch_prm_configure_qos,
					   NBL_CHAN_MSG_CONFIGURE_QOS, (void)0);
}

static int nbl_disp_set_pfc_buffer_size_loc(void *priv,
					    struct nbl_ch_prm_set_pfc_buffer_size *param)
{
	return DIS2RES_2IN_CB_LOC(set_pfc_buffer_size, true, param, true, int);
}

static int nbl_disp_chan_set_pfc_buffer_size_req(void *priv,
						 struct nbl_ch_prm_set_pfc_buffer_size *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_SET_PFC_BUFFER_SIZE);
}

static void nbl_disp_chan_set_pfc_buffer_size_resp(void *priv, u16 src_id, u16 msg_id,
						   void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(set_pfc_buffer_size, true,
					   struct nbl_ch_prm_set_pfc_buffer_size,
					   NBL_CHAN_MSG_SET_PFC_BUFFER_SIZE, (void)0);
}

static int
nbl_disp_get_pfc_buffer_size_loc(void *priv, struct nbl_ch_prm_get_pfc_buffer_size *param,
				 struct nbl_ch_prm_get_pfc_buffer_size_resp *output)
{
	return DIS2RES_2IN_OUT_CB_LOC(get_pfc_buffer_size, true, param, output, true, int);
}

static int
nbl_disp_chan_get_pfc_buffer_size_req(void *priv, struct nbl_ch_prm_get_pfc_buffer_size *param,
				      struct nbl_ch_prm_get_pfc_buffer_size_resp *output)
{
	return DIS2CH_2IN_OUT_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_GET_PFC_BUFFER_SIZE,
						     output);
}

static void nbl_disp_chan_get_pfc_buffer_size_resp(void *priv, u16 src_id, u16 msg_id,
						   void *data, u32 data_len)
{
	DIS2CH_2IN_OUT_CB_RESP(get_pfc_buffer_size, true, struct nbl_ch_prm_get_pfc_buffer_size,
			       NBL_CHAN_MSG_GET_PFC_BUFFER_SIZE,
			       struct nbl_ch_prm_get_pfc_buffer_size_resp, (void)0);
}

static int nbl_disp_set_rate_limit_loc(void *priv, struct nbl_ch_prm_set_rate_limit *param)
{
	return DIS2RES_2IN_CB_LOC(set_rate_limit, true, param, true, int);
}

static int
nbl_disp_chan_set_rate_limit_req(void *priv, struct nbl_ch_prm_set_rate_limit *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_SET_RATE_LIMIT);
}

static void nbl_disp_chan_set_rate_limit_resp(void *priv, u16 src_id, u16 msg_id,
					      void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(set_rate_limit, true,
					   struct nbl_ch_prm_set_rate_limit,
					   NBL_CHAN_MSG_SET_RATE_LIMIT, p->sfid = src_id);
}

static int nbl_disp_register_dev_name_loc(void *priv, struct nbl_ch_prm_pf_name *param)
{
	return DIS2RES_2IN_CB_LOC(register_dev_name, true, param, true, int);
}

static int
nbl_disp_chan_register_dev_name_req(void *priv, struct nbl_ch_prm_pf_name *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_REGISTER_PF_NAME);
}

static void nbl_disp_chan_register_dev_name_resp(void *priv, u16 src_id, u16 msg_id,
						 void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(register_dev_name, true,
					   struct nbl_ch_prm_pf_name,
					   NBL_CHAN_MSG_REGISTER_PF_NAME, (void)0);
}

static int nbl_disp_get_dev_name_loc(void *priv, struct nbl_ch_prm_pf_name *param,
				     struct nbl_ch_prm_pf_name *output)
{
	return DIS2RES_2IN_OUT_CB_LOC(get_dev_name, true, param, output, true, int);
}

static int
nbl_disp_chan_get_dev_name_req(void *priv, struct nbl_ch_prm_pf_name *param,
			       struct nbl_ch_prm_pf_name *output)
{
	return DIS2CH_2IN_OUT_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_GET_PF_NAME, output);
}

static void nbl_disp_chan_get_dev_name_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	DIS2CH_2IN_OUT_CB_RESP(get_dev_name, true, struct nbl_ch_prm_pf_name,
			       NBL_CHAN_MSG_GET_PF_NAME,
			       struct nbl_ch_prm_pf_name, (void)0);
}

static int
nbl_disp_get_mirror_table_id_loc(void *priv, struct nbl_ch_prm_get_mirror_table_id *param,
				 struct nbl_ch_prm_get_mirror_table_id *output)
{
	return DIS2RES_2IN_OUT_CB_LOC(get_mirror_table_id, true, param, output, true, int);
}

static int
nbl_disp_chan_get_mirror_table_id_req(void *priv, struct nbl_ch_prm_get_mirror_table_id *param,
				      struct nbl_ch_prm_get_mirror_table_id *output)
{
	return DIS2CH_2IN_OUT_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_GET_MIRROR_TABLE_ID,
						     output);
}

static void nbl_disp_chan_get_mirror_table_id_resp(void *priv, u16 src_id, u16 msg_id,
						   void *data, u32 data_len)
{
	DIS2CH_2IN_OUT_CB_RESP(get_mirror_table_id, true,
			       struct nbl_ch_prm_get_mirror_table_id,
			       NBL_CHAN_MSG_GET_MIRROR_TABLE_ID,
			       struct nbl_ch_prm_get_mirror_table_id, (void)0);
}

static int nbl_disp_configure_mirror_loc(void *priv, struct nbl_ch_prm_mirror *param)
{
	return DIS2RES_2IN_CB_LOC(configure_mirror, true, param, true, int);
}

static int nbl_disp_configure_tx_mirror_to_rdma_loc(void *priv,
						    struct nbl_ch_prm_tx_mirror_to_rdma *param)
{
	return DIS2RES_2IN_CB_LOC(configure_tx_mirror_to_rdma, true, param, true, int);
}

static int nbl_disp_chan_configure_mirror_req(void *priv, struct nbl_ch_prm_mirror *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_CONFIGURE_MIRROR);
}

static void nbl_disp_chan_configure_mirror_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(configure_mirror, true, struct nbl_ch_prm_mirror,
					   NBL_CHAN_MSG_CONFIGURE_MIRROR, p->sfid = src_id);
}

static int nbl_disp_configure_mirror_table_loc(void *priv,
					       struct nbl_ch_prm_mirror_table *param)
{
	return DIS2RES_2IN_CB_LOC(configure_mirror_table, true, param, true, int);
}

static int nbl_disp_chan_configure_mirror_table_req(void *priv,
						    struct nbl_ch_prm_mirror_table *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_CONFIGURE_MIRROR_TABLE);
}

static void nbl_disp_chan_configure_mirror_table_resp(void *priv, u16 src_id, u16 msg_id,
						      void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(configure_mirror_table, true,
					   struct nbl_ch_prm_mirror_table,
					   NBL_CHAN_MSG_CONFIGURE_MIRROR_TABLE, (void)0);
}

static int nbl_disp_clear_mirror_cfg_loc(void *priv, u16 *sfid)
{
	return DIS2RES_2IN_CB_LOC(clear_mirror_cfg, true, sfid, true, int);
}

static int nbl_disp_chan_clear_mirror_cfg_req(void *priv, u16 *sfid)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(sfid, NBL_CHAN_MSG_CLEAR_MIRROR_CFG);
}

static void nbl_disp_chan_clear_mirror_cfg_resp(void *priv, u16 src_id, u16 msg_id,
						void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(clear_mirror_cfg, true, u16,
					   NBL_CHAN_MSG_CLEAR_MIRROR_CFG, *p = src_id);
}

static int nbl_disp_check_flow_table_spec_loc(void *priv, struct nbl_ch_prm_flow_table_spec *param)
{
	return DIS2RES_2IN_CB_LOC(check_flow_table_spec, true, param, true, int);
}

static int
nbl_disp_chan_check_flow_table_spec_req(void *priv, struct nbl_ch_prm_flow_table_spec *param)
{
	return DIS2CH_2IN_RESRET_AS_CHRET_CB_REQ(param, NBL_CHAN_MSG_CHECK_FLOWTABLE_SPEC);
}

static void
nbl_disp_chan_check_flow_table_spec_resp(void *priv, u16 src_id, u16 msg_id,
					 void *data, u32 data_len)
{
	DIS2CH_2IN_RESRET_AS_CHRET_CB_RESP(check_flow_table_spec, true,
					   struct nbl_ch_prm_flow_table_spec,
					   NBL_CHAN_MSG_CHECK_FLOWTABLE_SPEC, (void)0);
}

static u32 nbl_disp_get_dvn_desc_req_loc(void *priv)
{
	return DIS2RES_1IN_CB_LOC(get_dvn_desc_req, false, true, u32);
}

static void nbl_disp_set_dvn_desc_req_loc(void *priv, u32 desc_req)
{
	DIS2RES_2IN_CB_LOC(set_dvn_desc_req, false, desc_req, false, void);
}

static void nbl_disp_set_rx_csum_drop_loc(void *priv, bool flag)
{
	DIS2RES_2IN_CB_LOC(set_rx_csum_drop, false, flag, false, void);
}

static void nbl_disp_cfg_vlan_filtering_loc(void *priv, bool filter)
{
	DIS2RES_2IN_CB_LOC(cfg_vlan_filtering, false, filter, false, void);
}

static void nbl_disp_set_xdp_enhance_loc(void *priv, bool flag)
{
	DIS2RES_2IN_CB_LOC(set_xdp_enhance, false, flag, false, void);
}

static void nbl_disp_dump_abnormal_intr_loc(void *priv, struct seq_file *m)
{
	DIS2RES_2IN_CB_LOC(dump_abnormal_intr, false, m, false, void);
}

/* NBL_DISP_SET_OPS(disp_op_name, res_func, ctrl_lvl, msg_type, msg_req, msg_resp)
 * ctrl_lvl is to define when this disp_op should go directly to res_op, not sending a channel msg.
 *
 * Use X Macros to reduce codes in channel_op and disp_op setup/remove
 */
#define NBL_DISP_OPS_TBL									\
do {												\
	NBL_DISP_SET_OPS(init_chip_module, nbl_disp_init_chip_module_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(set_driver_status, nbl_disp_set_driver_status_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(get_res_pt_tbl, nbl_disp_get_res_pt_tbl_loc,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(init_queue, nbl_disp_init_queue_loc,					\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(init_vsi, nbl_disp_init_vsi_loc,					\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(init_vf_msix_map, nbl_disp_init_vf_msix_map_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_INIT_VF_MSIX_MAP,			\
			 nbl_disp_chan_init_vf_msix_map_req,					\
			 nbl_disp_chan_init_vf_msix_map_resp);					\
	NBL_DISP_SET_OPS(configure_msix_map, nbl_disp_configure_msix_map_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CONFIGURE_MSIX_MAP,		\
			 nbl_disp_chan_configure_msix_map_req,					\
			 nbl_disp_chan_configure_msix_map_resp);				\
	NBL_DISP_SET_OPS(destroy_msix_map, nbl_disp_destroy_msix_map_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_DESTROY_MSIX_MAP,			\
			 nbl_disp_chan_destroy_msix_map_req,					\
			 nbl_disp_chan_destroy_msix_map_resp);					\
	NBL_DISP_SET_OPS(enable_mailbox_irq, nbl_disp_enable_mailbox_irq_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_MAILBOX_ENABLE_IRQ,		\
			 nbl_disp_chan_enable_mailbox_irq_req,					\
			 nbl_disp_chan_enable_mailbox_irq_resp);				\
	NBL_DISP_SET_OPS(enable_abnormal_irq, nbl_disp_enable_abnormal_irq_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(enable_sfp_plug_irq, nbl_disp_enable_sfp_plug_irq_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(enable_adminq_irq, nbl_disp_enable_adminq_irq_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(set_rdma_rx_vsi_remap, nbl_disp_set_rdma_rx_vsi_remap_loc,		\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(get_global_vector, nbl_disp_get_global_vector_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_GLOBAL_VECTOR,			\
			 nbl_disp_chan_get_global_vector_req,					\
			 nbl_disp_chan_get_global_vector_resp);					\
	NBL_DISP_SET_OPS(alloc_rings, nbl_disp_alloc_rings_loc,					\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(remove_rings, nbl_disp_remove_rings_loc,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(start_tx_ring, nbl_disp_start_tx_ring_loc,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(stop_tx_ring, nbl_disp_stop_tx_ring_loc,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(start_rx_ring, nbl_disp_start_rx_ring_loc,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(stop_rx_ring, nbl_disp_stop_rx_ring_loc,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(kick_rx_ring, nbl_disp_kick_rx_ring_loc,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(dump_ring, nbl_disp_dump_ring_loc,					\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(dump_ring_stats, nbl_disp_dump_ring_stats_loc,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(set_rings_xdp_prog, nbl_disp_set_rings_xdp_prog_loc,			\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(register_xdp_rxq, nbl_disp_register_xdp_rxq_loc,			\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(unregister_xdp_rxq, nbl_disp_unregister_xdp_rxq_loc,			\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(get_vector_napi, nbl_disp_get_vector_napi_loc,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(set_vector_info, nbl_disp_set_vector_info_loc,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(register_vsi_ring, nbl_disp_register_vsi_ring_loc,			\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(register_net, nbl_disp_register_net_loc,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_REGISTER_NET,			\
			 nbl_disp_chan_register_net_req, nbl_disp_chan_register_net_resp);	\
	NBL_DISP_SET_OPS(unregister_net, nbl_disp_unregister_net_loc,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_UNREGISTER_NET,			\
			 nbl_disp_chan_unregister_net_req, nbl_disp_chan_unregister_net_resp);	\
	NBL_DISP_SET_OPS(alloc_txrx_queues, nbl_disp_alloc_txrx_queues_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_ALLOC_TXRX_QUEUES,			\
			 nbl_disp_chan_alloc_txrx_queues_req,					\
			 nbl_disp_chan_alloc_txrx_queues_resp);					\
	NBL_DISP_SET_OPS(free_txrx_queues, nbl_disp_free_txrx_queues_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_FREE_TXRX_QUEUES,			\
			 nbl_disp_chan_free_txrx_queues_req,					\
			 nbl_disp_chan_free_txrx_queues_resp);					\
	NBL_DISP_SET_OPS(register_vsi2q, nbl_disp_register_vsi2q,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_REGISTER_VSI2Q,			\
			 nbl_disp_chan_register_vsi2q_req,					\
			 nbl_disp_chan_register_vsi2q_resp);					\
	NBL_DISP_SET_OPS(setup_q2vsi, nbl_disp_setup_q2vsi,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SETUP_Q2VSI,			\
			 nbl_disp_chan_setup_q2vsi_req,						\
			 nbl_disp_chan_setup_q2vsi_resp);					\
	NBL_DISP_SET_OPS(remove_q2vsi, nbl_disp_remove_q2vsi,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_REMOVE_Q2VSI,			\
			 nbl_disp_chan_remove_q2vsi_req,					\
			 nbl_disp_chan_remove_q2vsi_resp);					\
	NBL_DISP_SET_OPS(setup_rss, nbl_disp_setup_rss,						\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SETUP_RSS,				\
			 nbl_disp_chan_setup_rss_req,						\
			 nbl_disp_chan_setup_rss_resp);						\
	NBL_DISP_SET_OPS(remove_rss, nbl_disp_remove_rss,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_REMOVE_RSS,			\
			 nbl_disp_chan_remove_rss_req,						\
			 nbl_disp_chan_remove_rss_resp);					\
	NBL_DISP_SET_OPS(setup_queue, nbl_disp_setup_queue_loc,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SETUP_QUEUE,			\
			 nbl_disp_chan_setup_queue_req, nbl_disp_chan_setup_queue_resp);	\
	NBL_DISP_SET_OPS(remove_queue, nbl_disp_remove_queue_loc,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_REMOVE_QUEUE,			\
			 nbl_disp_chan_remove_queue_req, nbl_disp_chan_remove_queue_resp);	\
	NBL_DISP_SET_OPS(remove_all_queues, nbl_disp_remove_all_queues,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_REMOVE_ALL_QUEUES,			\
			 nbl_disp_chan_remove_all_queues_req,					\
			 nbl_disp_chan_remove_all_queues_resp);					\
	NBL_DISP_SET_OPS(cfg_dsch, nbl_disp_cfg_dsch,						\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CFG_DSCH,				\
			 nbl_disp_chan_cfg_dsch_req, nbl_disp_chan_cfg_dsch_resp);		\
	NBL_DISP_SET_OPS(setup_cqs, nbl_disp_setup_cqs,						\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SETUP_CQS,				\
			 nbl_disp_chan_setup_cqs_req, nbl_disp_chan_setup_cqs_resp);		\
	NBL_DISP_SET_OPS(remove_cqs, nbl_disp_remove_cqs,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_REMOVE_CQS,			\
			 nbl_disp_chan_remove_cqs_req, nbl_disp_chan_remove_cqs_resp);		\
	NBL_DISP_SET_OPS(cfg_qdisc_mqprio, nbl_disp_cfg_qdisc_mqprio,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CFG_QDISC_MQPRIO,			\
			 nbl_disp_chan_cfg_qdisc_mqprio_req,					\
			 nbl_disp_chan_cfg_qdisc_mqprio_resp);					\
	NBL_DISP_SET_OPS(get_msix_irq_enable_info, nbl_disp_get_msix_irq_enable_info,		\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(add_macvlan, nbl_disp_add_macvlan,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_ADD_MACVLAN,			\
			 nbl_disp_chan_add_macvlan_req, nbl_disp_chan_add_macvlan_resp);	\
	NBL_DISP_SET_OPS(del_macvlan, nbl_disp_del_macvlan,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_DEL_MACVLAN,			\
			 nbl_disp_chan_del_macvlan_req, nbl_disp_chan_del_macvlan_resp);	\
	NBL_DISP_SET_OPS(dummy_func, NULL, NBL_DISP_CTRL_LVL_MGT,				\
			 NBL_CHAN_MSG_SET_DECAP_SET, NULL,					\
			 nbl_disp_chan_set_decap_set_resp);					\
	NBL_DISP_SET_OPS(add_multi_rule, nbl_disp_add_multi_rule_loc,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_ADD_MULTI_RULE,			\
			 nbl_disp_chan_add_multi_rule_req, nbl_disp_chan_add_multi_rule_resp);	\
	NBL_DISP_SET_OPS(del_multi_rule, nbl_disp_del_multi_rule_loc,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_DEL_MULTI_RULE,			\
			 nbl_disp_chan_del_multi_rule_req, nbl_disp_chan_del_multi_rule_resp);	\
	NBL_DISP_SET_OPS(setup_multi_group, nbl_disp_setup_multi_group,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SETUP_MULTI_GROUP,			\
			 nbl_disp_chan_setup_multi_group_req,					\
			 nbl_disp_chan_setup_multi_group_resp);					\
	NBL_DISP_SET_OPS(cfg_multi_mcast, nbl_disp_cfg_multi_mcast_loc,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CFG_MULTI_MCAST_RULE,		\
			 nbl_disp_chan_cfg_multi_mcast_req, nbl_disp_chan_cfg_multi_mcast_resp);\
	NBL_DISP_SET_OPS(alloc_kt, nbl_disp_alloc_kt,						\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(setup_ecn_stats, nbl_disp_setup_ecn_stats,				\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(remove_ecn_stats, nbl_disp_remove_ecn_stats,				\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(remove_multi_group, nbl_disp_remove_multi_group,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_REMOVE_MULTI_GROUP,		\
			 nbl_disp_chan_remove_multi_group_req,					\
			 nbl_disp_chan_remove_multi_group_resp);				\
	NBL_DISP_SET_OPS(dump_flow, nbl_disp_dump_flow,						\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(dump_func_info, nbl_disp_dump_func_info,				\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(get_vsi_id, nbl_disp_get_vsi_id_loc,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_VSI_ID,			\
			 nbl_disp_chan_get_vsi_id_req, nbl_disp_chan_get_vsi_id_resp);		\
	NBL_DISP_SET_OPS(get_my_pf, nbl_disp_get_my_pf_loc,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_MY_PF,				\
			 nbl_disp_chan_get_my_pf_req, nbl_disp_chan_get_my_pf_resp);		\
	NBL_DISP_SET_OPS(get_eth_id, nbl_disp_get_eth_id_loc,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_ETH_ID,			\
			 nbl_disp_chan_get_eth_id_req, nbl_disp_chan_get_eth_id_resp);		\
	NBL_DISP_SET_OPS(set_lag_status, nbl_disp_set_lag_status_loc,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(enable_lag_protocol, nbl_disp_enable_lag_protocol_loc,			\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(cfg_lag_hash_algorithm, nbl_disp_cfg_lag_hash_algorithm_loc,		\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CFG_LAG_HASH_ALGORITHM,		\
			 nbl_disp_chan_cfg_lag_hash_algorithm_req,				\
			 nbl_disp_chan_cfg_lag_hash_algorithm_resp);				\
	NBL_DISP_SET_OPS(cfg_lag_member_fwd, nbl_disp_cfg_lag_member_fwd_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CFG_LAG_MEMBER_FWD,		\
			 nbl_disp_chan_cfg_lag_member_fwd_req,					\
			 nbl_disp_chan_cfg_lag_member_fwd_resp);				\
	NBL_DISP_SET_OPS(cfg_lag_member_list, nbl_disp_cfg_lag_member_list,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CFG_LAG_MEMBER_LIST,		\
			 nbl_disp_chan_cfg_lag_member_list_req,					\
			 nbl_disp_chan_cfg_lag_member_list_resp);				\
	NBL_DISP_SET_OPS(cfg_lag_member_up_attr, nbl_disp_cfg_lag_member_up_attr_loc,		\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CFG_LAG_MEMBER_UP_ATTR,		\
			 nbl_disp_chan_cfg_lag_member_up_attr_req,				\
			 nbl_disp_chan_cfg_lag_member_up_attr_resp);				\
	NBL_DISP_SET_OPS(add_lldp_flow, nbl_disp_add_lldp_flow_loc,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_ADD_LLDP_FLOW,			\
			 nbl_disp_chan_add_lldp_flow_req, nbl_disp_chan_add_lldp_flow_resp);	\
	NBL_DISP_SET_OPS(del_lldp_flow, nbl_disp_del_lldp_flow_loc,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_DEL_LLDP_FLOW,			\
			 nbl_disp_chan_del_lldp_flow_req, nbl_disp_chan_del_lldp_flow_resp);	\
	NBL_DISP_SET_OPS(add_lag_flow, nbl_disp_add_lag_flow_loc,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_ADD_LAG_FLOW,			\
			 nbl_disp_chan_add_lag_flow_req, nbl_disp_chan_add_lag_flow_resp);	\
	NBL_DISP_SET_OPS(del_lag_flow, nbl_disp_del_lag_flow_loc,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_DEL_LAG_FLOW,			\
			 nbl_disp_chan_del_lag_flow_req, nbl_disp_chan_del_lag_flow_resp);	\
	NBL_DISP_SET_OPS(cfg_duppkt_info, nbl_disp_cfg_duppkt_info,				\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(cfg_duppkt_mcc, nbl_disp_cfg_duppkt_mcc,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CFG_DUPPKT_MCC,			\
			 nbl_disp_chan_cfg_duppkt_mcc_req, nbl_disp_chan_cfg_duppkt_mcc_resp);	\
	NBL_DISP_SET_OPS(cfg_lag_mcc, nbl_disp_cfg_lag_mcc_loc,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CFG_LAG_MCC,			\
			 nbl_disp_chan_cfg_lag_mcc_req, nbl_disp_chan_cfg_lag_mcc_resp);	\
	NBL_DISP_SET_OPS(cfg_bond_shaping, nbl_disp_cfg_bond_shaping_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CFG_BOND_SHAPING,			\
			 nbl_disp_chan_cfg_bond_shaping_req,					\
			 nbl_disp_chan_cfg_bond_shaping_resp);					\
	NBL_DISP_SET_OPS(cfg_bgid_back_pressure, nbl_disp_cfg_bgid_back_pressure_loc,		\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CFG_BGID_BACK_PRESSURE,		\
			 nbl_disp_chan_cfg_bgid_back_pressure_req,				\
			 nbl_disp_chan_cfg_bgid_back_pressure_resp);				\
	NBL_DISP_SET_OPS(set_promisc_mode, nbl_disp_set_promisc_mode_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_PROSISC_MODE,			\
			 nbl_disp_chan_set_promisc_mode_req,					\
			 nbl_disp_chan_set_promisc_mode_resp);					\
	NBL_DISP_SET_OPS(set_spoof_check_addr, nbl_disp_set_spoof_check_addr_loc,		\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_SPOOF_CHECK_ADDR,		\
			 nbl_disp_chan_set_spoof_check_addr_req,				\
			 nbl_disp_chan_set_spoof_check_addr_resp);				\
	NBL_DISP_SET_OPS(set_vf_spoof_check, nbl_disp_set_vf_spoof_check_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_VF_SPOOF_CHECK,		\
			 nbl_disp_chan_set_vf_spoof_check_req,					\
			 nbl_disp_chan_set_vf_spoof_check_resp);				\
	NBL_DISP_SET_OPS(get_base_mac_addr, nbl_disp_get_base_mac_addr,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_BASE_MAC_ADDR,			\
			 nbl_disp_chan_get_base_mac_addr_req,					\
			 nbl_disp_chan_get_base_mac_addr_resp);					\
	NBL_DISP_SET_OPS(get_eth_mac_stats, nbl_disp_get_eth_mac_stats_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_ETH_MAC_STATS,			\
			 nbl_disp_chan_get_eth_mac_stats_req,					\
			 nbl_disp_chan_get_eth_mac_stats_resp);					\
	NBL_DISP_SET_OPS(get_rmon_stats, nbl_disp_get_rmon_stats_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_RMON_STATS,			\
			 nbl_disp_chan_get_rmon_stats_req,					\
			 nbl_disp_chan_get_rmon_stats_resp);					\
	NBL_DISP_SET_OPS(get_rmon_hist_range, nbl_disp_get_rmon_hist_range,			\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(get_tx_headroom, nbl_disp_get_tx_headroom,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(get_rep_feature, nbl_disp_get_rep_feature,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(set_eswitch_mode, nbl_disp_set_eswitch_mode_loc,			\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(get_eswitch_mode, nbl_disp_get_eswitch_mode,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(alloc_rep_data, nbl_disp_alloc_rep_data_loc,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(free_rep_data, nbl_disp_free_rep_data,					\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(set_rep_netdev_info, nbl_disp_set_rep_netdev_info,			\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(unset_rep_netdev_info, nbl_disp_unset_rep_netdev_info,			\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(get_rep_netdev_info, nbl_disp_get_rep_netdev_info,			\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(get_rep_stats, nbl_disp_get_rep_stats_loc,				\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_rep_index, nbl_disp_get_rep_index_loc,				\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_firmware_version, nbl_disp_get_firmware_version_loc,		\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_FIRMWARE_VERSION,		\
			 nbl_disp_chan_get_firmware_version_req,				\
			 nbl_disp_chan_get_firmware_version_resp);				\
	NBL_DISP_SET_OPS(get_queue_stats, nbl_disp_get_queue_stats_loc,			\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_queue_err_stats, nbl_disp_get_queue_err_stats_loc,		\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_QUEUE_ERR_STATS,		\
			 nbl_disp_chan_get_queue_err_stats_req,					\
			 nbl_disp_chan_get_queue_err_stats_resp);				\
	NBL_DISP_SET_OPS(get_net_stats, nbl_disp_get_net_stats,					\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_private_stat_len, nbl_disp_get_private_stat_len,			\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_private_stat_data, nbl_disp_get_private_stat_data,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_ETH_STATS,			\
			 nbl_disp_get_private_stat_data_req,					\
			 nbl_disp_chan_get_private_stat_data_resp);				\
	NBL_DISP_SET_OPS(get_eth_ctrl_stats, nbl_disp_get_eth_ctrl_stats_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_ETH_CTRL_STATS,		\
			 nbl_disp_chan_get_eth_ctrl_stats_req,					\
			 nbl_disp_chan_get_eth_ctrl_stats_resp);				\
	NBL_DISP_SET_OPS(get_pause_stats, nbl_disp_get_pause_stats_loc,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_PAUSE_STATS,			\
			 nbl_disp_chan_get_pause_stats_req,					\
			 nbl_disp_chan_get_pause_stats_resp);					\
	NBL_DISP_SET_OPS(fill_private_stat_strings, nbl_disp_fill_private_stat_strings,		\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_eth_abnormal_stats, nbl_disp_get_eth_abnormal_stats_loc,		\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_ETH_ABNORMAL_STATS,		\
			 nbl_disp_chan_get_eth_abnormal_stats_req,				\
			 nbl_disp_chan_get_eth_abnormal_stats_resp);				\
	NBL_DISP_SET_OPS(get_max_desc_num, nbl_disp_get_max_desc_num,				\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_min_desc_num, nbl_disp_get_min_desc_num,				\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(set_eth_loopback, nbl_disp_set_eth_loopback_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_ETH_LOOPBACK,			\
			 nbl_disp_chan_set_eth_loopback_req,					\
			 nbl_disp_chan_set_eth_loopback_resp);					\
	NBL_DISP_SET_OPS(clean_rx_lb_test, nbl_disp_clean_rx_lb_test_loc,		\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_coalesce, nbl_disp_get_coalesce_loc,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_COALESCE,			\
			 nbl_disp_chan_get_coalesce_req,					\
			 nbl_disp_chan_get_coalesce_resp);					\
	NBL_DISP_SET_OPS(set_coalesce, nbl_disp_set_coalesce_loc,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_COALESCE,			\
			 nbl_disp_chan_set_coalesce_req,					\
			 nbl_disp_chan_set_coalesce_resp);					\
	NBL_DISP_SET_OPS(set_msix_fast_restrain, nbl_disp_set_msix_fast_restrain_loc,	\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(set_intr_suppress_level_fast, nbl_disp_set_suppress_level_fast_loc,\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_intr_suppress_level, nbl_disp_get_intr_suppress_level_loc,	\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(set_intr_suppress_level, nbl_disp_set_intr_suppress_level_loc,	\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_INTL_SUPPRESS_LEVEL,		\
			 nbl_disp_chan_set_suppress_level_req,				\
			 nbl_disp_chan_set_intr_suppress_level_resp);				\
	NBL_DISP_SET_OPS(get_rxfh_indir_size, nbl_disp_get_rxfh_indir_size_loc,		\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_RXFH_INDIR_SIZE,		\
			 nbl_disp_chan_get_rxfh_indir_size_req,					\
			 nbl_disp_chan_get_rxfh_indir_size_resp);				\
	NBL_DISP_SET_OPS(get_rxfh_rss_key_size, nbl_disp_get_rxfh_rss_key_size,			\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_rxfh_indir, nbl_disp_get_rxfh_indir,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_RXFH_INDIR,			\
			 nbl_disp_chan_get_rxfh_indir_req, nbl_disp_chan_get_rxfh_indir_resp);	\
	NBL_DISP_SET_OPS(set_rxfh_indir, nbl_disp_set_rxfh_indir,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_RXFH_INDIR,			\
			 nbl_disp_chan_set_rxfh_indir_req, nbl_disp_chan_set_rxfh_indir_resp);	\
	NBL_DISP_SET_OPS(get_rxfh_rss_key, nbl_disp_get_rxfh_rss_key_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_RXFH_RSS_KEY,			\
			 nbl_disp_chan_get_rxfh_rss_key_req,					\
			 nbl_disp_chan_get_rxfh_rss_key_resp);					\
	NBL_DISP_SET_OPS(set_rxfh_rss_key, nbl_disp_set_rxfh_rss_key_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_RXFH_RSS_KEY,			\
			 nbl_disp_chan_set_rxfh_rss_key_req,					\
			 nbl_disp_chan_set_rxfh_rss_key_resp);					\
	NBL_DISP_SET_OPS(get_rxfh_rss_alg_sel, nbl_disp_get_rxfh_rss_alg_sel_loc,		\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_RXFH_RSS_ALG_SEL,		\
			 nbl_disp_chan_get_rxfh_rss_alg_sel_req,				\
			 nbl_disp_chan_get_rxfh_rss_alg_sel_resp);				\
	NBL_DISP_SET_OPS(set_rxfh_rss_alg_sel, nbl_disp_set_rxfh_rss_alg_sel_loc,		\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_RXFH_RSS_ALG_SEL,		\
			 nbl_disp_chan_set_rxfh_rss_alg_sel_req,				\
			 nbl_disp_chan_set_rxfh_rss_alg_sel_resp);				\
	NBL_DISP_SET_OPS(cfg_rx_half_offload, nbl_disp_cfg_rx_half_offload_loc,			\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(cfg_rx_vlan_parse, nbl_disp_cfg_rx_vlan_parse_loc,			\
			 NBL_DISP_CTRL_LVL_MGT,							\
			 NBL_CHAN_MSG_CFG_RX_VLAN_PARSE,					\
			 nbl_disp_chan_cfg_rx_vlan_parse_req,					\
			 nbl_disp_chan_cfg_rx_vlan_parse_resp);					\
	NBL_DISP_SET_OPS(cfg_rss_hash, nbl_disp_cfg_rss_hash_loc,				\
			 NBL_DISP_CTRL_LVL_MGT,							\
			 NBL_CHAN_MSG_CFG_RSS_HASH,						\
			 nbl_disp_chan_cfg_rss_hash_req,					\
			 nbl_disp_chan_cfg_rss_hash_resp);					\
	NBL_DISP_SET_OPS(cfg_txrx_vlan, nbl_disp_cfg_txrx_vlan_loc,				\
			 NBL_DISP_CTRL_LVL_NET,	-1, NULL, NULL);				\
	NBL_DISP_SET_OPS(enable_up_rdma_bypass, nbl_disp_enable_up_rdma_bypass_loc,		\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(setup_rdma_id, nbl_disp_setup_rdma_id,					\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(remove_rdma_id, nbl_disp_remove_rdma_id,				\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(register_rdma_grc_id, nbl_disp_register_rdma_grc_id_loc,		\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(unregister_rdma_grc_id, nbl_disp_unregister_rdma_grc_id_loc,	    \
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(register_rdma, nbl_disp_register_rdma_loc,			      \
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_REGISTER_RDMA,			\
			 nbl_disp_chan_register_rdma_req, nbl_disp_chan_register_rdma_resp);	\
	NBL_DISP_SET_OPS(unregister_rdma, nbl_disp_unregister_rdma_loc,			  \
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_UNREGISTER_RDMA,			\
			 nbl_disp_chan_unregister_rdma_req, nbl_disp_chan_unregister_rdma_resp);\
	NBL_DISP_SET_OPS(get_hw_addr, nbl_disp_get_hw_addr,					\
			 NBL_DISP_CTRL_LVL_ALWAYS, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_rdma_hw_addr, nbl_disp_get_rdma_hw_addr,				\
			 NBL_DISP_CTRL_LVL_ALWAYS, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_real_hw_addr, nbl_disp_get_real_hw_addr_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_REAL_HW_ADDR,			\
			 nbl_disp_chan_get_real_hw_addr_req,					\
			 nbl_disp_chan_get_real_hw_addr_resp);					\
	NBL_DISP_SET_OPS(get_function_id, nbl_disp_get_function_id_loc,			  \
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_FUNCTION_ID,			\
			 nbl_disp_chan_get_function_id_req, nbl_disp_chan_get_function_id_resp);\
	NBL_DISP_SET_OPS(get_real_bdf, nbl_disp_get_real_bdf_loc,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_REAL_BDF,			\
			 nbl_disp_chan_get_real_bdf_req, nbl_disp_chan_get_real_bdf_resp);	\
	NBL_DISP_SET_OPS(check_fw_heartbeat, nbl_disp_check_fw_heartbeat,			\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(check_fw_reset, nbl_disp_check_fw_reset,				\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(flash_lock, nbl_disp_flash_lock,					\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(flash_unlock, nbl_disp_flash_unlock,					\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(flash_prepare, nbl_disp_flash_prepare,					\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(flash_image, nbl_disp_flash_image_loc,				  \
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(flash_activate, nbl_disp_flash_activate,				\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_phy_caps, nbl_disp_get_phy_caps_loc,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_PHY_CAPS,			\
			 nbl_disp_chan_get_phy_caps_req,					\
			 nbl_disp_chan_get_phy_caps_resp);					\
	NBL_DISP_SET_OPS(set_sfp_state, nbl_disp_set_sfp_state_loc,			      \
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_SFP_STATE,			\
			 nbl_disp_chan_set_sfp_state_req,					\
			 nbl_disp_chan_set_sfp_state_resp);					\
	NBL_DISP_SET_OPS(passthrough_fw_cmd, nbl_disp_passthrough_fw_cmd,			\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(check_active_vf, nbl_disp_check_active_vf_loc,			  \
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CHECK_ACTIVE_VF,			\
			 nbl_disp_chan_check_active_vf_req,					\
			 nbl_disp_chan_check_active_vf_resp);					\
	NBL_DISP_SET_OPS(get_adminq_tx_buf_size, nbl_disp_get_adminq_tx_buf_size,		\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_product_flex_cap, nbl_disp_get_product_flex_cap_loc,		\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_PRODUCT_FLEX_CAP,		\
			 nbl_disp_chan_get_product_flex_cap_req,				\
			 nbl_disp_chan_get_product_flex_cap_resp);				\
	NBL_DISP_SET_OPS(get_product_fix_cap, nbl_disp_get_product_fix_cap_loc,		  \
			 NBL_DISP_CTRL_LVL_ALWAYS, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(alloc_ktls_tx_index, nbl_disp_alloc_ktls_tx_index_loc,		  \
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_ALLOC_KTLS_TX_INDEX,		\
			 nbl_disp_chan_alloc_ktls_tx_index_req,					\
			 nbl_disp_chan_alloc_ktls_tx_index_resp);				\
	NBL_DISP_SET_OPS(free_ktls_tx_index, nbl_disp_free_ktls_tx_index_loc,		    \
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_FREE_KTLS_TX_INDEX,		\
			 nbl_disp_chan_free_ktls_tx_index_req,					\
			 nbl_disp_chan_free_ktls_tx_index_resp);				\
	NBL_DISP_SET_OPS(cfg_ktls_tx_keymat, nbl_disp_cfg_ktls_tx_keymat_loc,		    \
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CFG_KTLS_TX_KEYMAT,		\
			 nbl_disp_chan_cfg_ktls_tx_keymat_req,					\
			 nbl_disp_chan_cfg_ktls_tx_keymat_resp);				\
	NBL_DISP_SET_OPS(alloc_ktls_rx_index, nbl_disp_alloc_ktls_rx_index_loc,		  \
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_ALLOC_KTLS_RX_INDEX,		\
			 nbl_disp_chan_alloc_ktls_rx_index_req,					\
			 nbl_disp_chan_alloc_ktls_rx_index_resp);				\
	NBL_DISP_SET_OPS(free_ktls_rx_index, nbl_disp_free_ktls_rx_index_loc,		    \
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_FREE_KTLS_RX_INDEX,		\
			 nbl_disp_chan_free_ktls_rx_index_req,					\
			 nbl_disp_chan_free_ktls_rx_index_resp);				\
	NBL_DISP_SET_OPS(cfg_ktls_rx_keymat, nbl_disp_cfg_ktls_rx_keymat_loc,		    \
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CFG_KTLS_RX_KEYMAT,		\
			 nbl_disp_chan_cfg_ktls_rx_keymat_req,					\
			 nbl_disp_chan_cfg_ktls_rx_keymat_resp);				\
	NBL_DISP_SET_OPS(cfg_ktls_rx_record, nbl_disp_cfg_ktls_rx_record_loc,		    \
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CFG_KTLS_RX_RECORD,		\
			 nbl_disp_chan_cfg_ktls_rx_record_req,					\
			 nbl_disp_chan_cfg_ktls_rx_record_resp);				\
	NBL_DISP_SET_OPS(add_ktls_rx_flow, nbl_disp_add_ktls_rx_flow_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_ADD_KTLS_RX_FLOW,			\
			 nbl_disp_chan_add_ktls_rx_flow_req,					\
			 nbl_disp_chan_add_ktls_rx_flow_resp);					\
	NBL_DISP_SET_OPS(del_ktls_rx_flow, nbl_disp_del_ktls_rx_flow_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_DEL_KTLS_RX_FLOW,			\
			 nbl_disp_chan_del_ktls_rx_flow_req,					\
			 nbl_disp_chan_del_ktls_rx_flow_resp);					\
	NBL_DISP_SET_OPS(alloc_ipsec_tx_index, nbl_disp_alloc_ipsec_tx_index_loc,		\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_ALLOC_IPSEC_TX_INDEX,		\
			 nbl_disp_chan_alloc_ipsec_tx_index_req,				\
			 nbl_disp_chan_alloc_ipsec_tx_index_resp);				\
	NBL_DISP_SET_OPS(free_ipsec_tx_index, nbl_disp_free_ipsec_tx_index_loc,		  \
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_FREE_IPSEC_TX_INDEX,		\
			 nbl_disp_chan_free_ipsec_tx_index_req,					\
			 nbl_disp_chan_free_ipsec_tx_index_resp);				\
	NBL_DISP_SET_OPS(alloc_ipsec_rx_index, nbl_disp_alloc_ipsec_rx_index_loc,		\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_ALLOC_IPSEC_RX_INDEX,		\
			 nbl_disp_chan_alloc_ipsec_rx_index_req,				\
			 nbl_disp_chan_alloc_ipsec_rx_index_resp);				\
	NBL_DISP_SET_OPS(free_ipsec_rx_index, nbl_disp_free_ipsec_rx_index_loc,		  \
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_FREE_IPSEC_RX_INDEX,		\
			 nbl_disp_chan_free_ipsec_rx_index_req,					\
			 nbl_disp_chan_free_ipsec_rx_index_resp);				\
	NBL_DISP_SET_OPS(cfg_ipsec_tx_sad, nbl_disp_cfg_ipsec_tx_sad_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CFG_IPSEC_TX_SAD,			\
			 nbl_disp_chan_cfg_ipsec_tx_sad_req,					\
			 nbl_disp_chan_cfg_ipsec_tx_sad_resp);					\
	NBL_DISP_SET_OPS(cfg_ipsec_rx_sad, nbl_disp_cfg_ipsec_rx_sad_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CFG_IPSEC_RX_SAD,			\
			 nbl_disp_chan_cfg_ipsec_rx_sad_req,					\
			 nbl_disp_chan_cfg_ipsec_rx_sad_resp);					\
	NBL_DISP_SET_OPS(add_ipsec_tx_flow, nbl_disp_add_ipsec_tx_flow_loc,		      \
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_ADD_IPSEC_TX_FLOW,			\
			 nbl_disp_chan_add_ipsec_tx_flow_req,					\
			 nbl_disp_chan_add_ipsec_tx_flow_resp);					\
	NBL_DISP_SET_OPS(del_ipsec_tx_flow, nbl_disp_del_ipsec_tx_flow_loc,		      \
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_DEL_IPSEC_TX_FLOW,			\
			 nbl_disp_chan_del_ipsec_tx_flow_req,					\
			 nbl_disp_chan_del_ipsec_tx_flow_resp);					\
	NBL_DISP_SET_OPS(add_ipsec_rx_flow, nbl_disp_add_ipsec_rx_flow_loc,		      \
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_ADD_IPSEC_RX_FLOW,			\
			 nbl_disp_chan_add_ipsec_rx_flow_req,					\
			 nbl_disp_chan_add_ipsec_rx_flow_resp);					\
	NBL_DISP_SET_OPS(del_ipsec_rx_flow, nbl_disp_del_ipsec_rx_flow_loc,		      \
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_DEL_IPSEC_RX_FLOW,			\
			 nbl_disp_chan_del_ipsec_rx_flow_req,					\
			 nbl_disp_chan_del_ipsec_rx_flow_resp);					\
	NBL_DISP_SET_OPS(check_ipsec_status, nbl_disp_check_ipsec_status,			\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(get_dipsec_lft_info, nbl_disp_get_dipsec_lft_info,			\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(handle_dipsec_soft_expire, nbl_disp_handle_dipsec_soft_expire_loc,      \
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(handle_dipsec_hard_expire, nbl_disp_handle_dipsec_hard_expire_loc,      \
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(get_uipsec_lft_info, nbl_disp_get_uipsec_lft_info,			\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(handle_uipsec_soft_expire, nbl_disp_handle_uipsec_soft_expire_loc,      \
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(handle_uipsec_hard_expire, nbl_disp_handle_uipsec_hard_expire_loc,      \
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(get_mbx_irq_num, nbl_disp_get_mbx_irq_num_loc,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_MBX_IRQ_NUM,			\
			 nbl_disp_chan_get_mbx_irq_num_req,					\
			 nbl_disp_chan_get_mbx_irq_num_resp);					\
	NBL_DISP_SET_OPS(get_adminq_irq_num, nbl_disp_get_adminq_irq_num_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_abnormal_irq_num, nbl_disp_get_abnormal_irq_num_loc,		\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_sfp_plug_irq_num, nbl_disp_get_sfp_plug_irq_num_loc,		\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(clear_accel_flow, nbl_disp_clear_accel_flow_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CLEAR_ACCEL_FLOW,			\
			 nbl_disp_chan_clear_accel_flow_req,					\
			 nbl_disp_chan_clear_accel_flow_resp);					\
	NBL_DISP_SET_OPS(clear_flow, nbl_disp_clear_flow_loc,				    \
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CLEAR_FLOW,			\
			 nbl_disp_chan_clear_flow_req, nbl_disp_chan_clear_flow_resp);		\
	NBL_DISP_SET_OPS(clear_queues, nbl_disp_clear_queues_loc,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CLEAR_QUEUE,			\
			 nbl_disp_chan_clear_queues_req, nbl_disp_chan_clear_queues_resp);	\
	NBL_DISP_SET_OPS(disable_phy_flow, nbl_disp_disable_phy_flow_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_DISABLE_PHY_FLOW,			\
			 nbl_disp_chan_disable_phy_flow_req,					\
			 nbl_disp_chan_disable_phy_flow_resp);					\
	NBL_DISP_SET_OPS(enable_phy_flow, nbl_disp_enable_phy_flow_loc,			  \
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_ENABLE_PHY_FLOW,			\
			 nbl_disp_chan_enable_phy_flow_req,					\
			 nbl_disp_chan_enable_phy_flow_resp);					\
	NBL_DISP_SET_OPS(init_acl, nbl_disp_init_acl,						\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_INIT_ACL,				\
			 nbl_disp_chan_init_acl_req,						\
			 nbl_disp_chan_init_acl_resp);						\
	NBL_DISP_SET_OPS(uninit_acl, nbl_disp_uninit_acl,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_UNINIT_ACL,			\
			 nbl_disp_chan_uninit_acl_req,						\
			 nbl_disp_chan_uninit_acl_resp);					\
	NBL_DISP_SET_OPS(set_upcall_rule, nbl_disp_set_upcall_rule_loc,			  \
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_UPCALL_RULE,			\
			 nbl_disp_chan_set_upcall_rule_req,					\
			 nbl_disp_chan_set_upcall_rule_resp);					\
	NBL_DISP_SET_OPS(unset_upcall_rule, nbl_disp_unset_upcall_rule_loc,		      \
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_UNSET_UPCALL_RULE,			\
			 nbl_disp_chan_unset_upcall_rule_req,					\
			 nbl_disp_chan_unset_upcall_rule_resp);					\
	NBL_DISP_SET_OPS(set_shaping_dport_vld, nbl_disp_set_shaping_dport_vld_loc,	      \
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_SHAPING_DPORT_VLD,		\
			 nbl_disp_chan_set_shaping_dport_vld_req,				\
			 nbl_disp_chan_set_shaping_dport_vld_resp);				\
	NBL_DISP_SET_OPS(set_dport_fc_th_vld, nbl_disp_set_dport_fc_th_vld_loc,		  \
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_DPORT_FC_TH_VLD,		\
			 nbl_disp_chan_set_dport_fc_th_vld_req,					\
			 nbl_disp_chan_set_dport_fc_th_vld_resp);				\
	NBL_DISP_SET_OPS(check_offload_status, nbl_disp_check_offload_status,			\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_reg_dump, nbl_disp_get_reg_dump,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_REG_DUMP,			\
			 nbl_disp_chan_get_reg_dump_req,					\
			 nbl_disp_chan_get_reg_dump_resp);					\
	NBL_DISP_SET_OPS(get_reg_dump_len, nbl_disp_get_reg_dump_len,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_REG_DUMP_LEN,			\
			 nbl_disp_chan_get_reg_dump_len_req,					\
			 nbl_disp_chan_get_reg_dump_len_resp);					\
	NBL_DISP_SET_OPS(get_p4_info, nbl_disp_get_p4_info,					\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(load_p4, nbl_disp_load_p4,						\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_p4_used, nbl_disp_get_p4_used,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_P4_USED,			\
			 nbl_disp_chan_get_p4_used_req,	nbl_disp_chan_get_p4_used_resp);	\
	NBL_DISP_SET_OPS(set_p4_used, nbl_disp_set_p4_used_loc,				  \
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_p4_version, nbl_disp_get_p4_version,				\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_board_id, nbl_disp_get_board_id,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_BOARD_ID,			\
			 nbl_disp_chan_get_board_id_req, nbl_disp_chan_get_board_id_resp);	\
	NBL_DISP_SET_OPS(restore_abnormal_ring, nbl_disp_restore_abnormal_ring_loc,		\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(restart_abnormal_ring, nbl_disp_restart_abnormal_ring_loc,		\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(restore_hw_queue, nbl_disp_restore_hw_queue_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_RESTORE_HW_QUEUE,			\
			 nbl_disp_chan_restore_hw_queue_req,					\
			 nbl_disp_chan_restore_hw_queue_resp);					\
	NBL_DISP_SET_OPS(stop_abnormal_hw_queue, nbl_disp_stop_abnormal_hw_queue_loc,\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_STOP_ABNORMAL_HW_QUEUE,		\
			 nbl_disp_chan_stop_abnormal_hw_queue_req,				\
			 nbl_disp_chan_stop_abnormal_hw_queue_resp);				\
	NBL_DISP_SET_OPS(stop_abnormal_sw_queue, nbl_disp_stop_abnormal_sw_queue_loc,		\
			 NBL_DISP_CTRL_LVL_NET, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_local_queue_id, nbl_disp_get_local_queue_id_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(dummy_func, NULL, NBL_DISP_CTRL_LVL_MGT,				\
			 NBL_CHAN_MSG_REGISTER_NET_REP, NULL,					\
			 nbl_disp_chan_register_net_rep_resp);					\
	NBL_DISP_SET_OPS(dummy_func, NULL, NBL_DISP_CTRL_LVL_MGT,				\
			 NBL_CHAN_MSG_UNREGISTER_NET_REP, NULL,					\
			 nbl_disp_chan_unregister_net_rep_resp);				\
	NBL_DISP_SET_OPS(dummy_func, NULL, NBL_DISP_CTRL_LVL_MGT,				\
			 NBL_CHAN_MSG_REGISTER_ETH_REP, NULL,					\
			 nbl_disp_chan_register_eth_rep_resp);					\
	NBL_DISP_SET_OPS(dummy_func, NULL, NBL_DISP_CTRL_LVL_MGT,				\
			 NBL_CHAN_MSG_UNREGISTER_ETH_REP, NULL,					\
			 nbl_disp_chan_unregister_eth_rep_resp);				\
	NBL_DISP_SET_OPS(get_vsi_global_qid, nbl_disp_get_vsi_global_qid_loc,			\
			 NBL_DISP_CTRL_LVL_MGT,							\
			 NBL_CHAN_MSG_GET_VSI_GLOBAL_QUEUE_ID,					\
			 nbl_disp_chan_get_vsi_global_qid_req,					\
			 nbl_disp_chan_get_vsi_global_qid_resp);				\
	NBL_DISP_SET_OPS(dummy_func, NULL, NBL_DISP_CTRL_LVL_MGT,				\
			 NBL_CHAN_MSG_GET_LINE_RATE_INFO,					\
			 NULL, nbl_disp_chan_get_line_rate_info_resp);				\
	NBL_DISP_SET_OPS(dummy_func, NULL, NBL_DISP_CTRL_LVL_MGT,				\
			 NBL_CHAN_MSG_REGISTER_UPCALL_PORT, NULL,				\
			 nbl_disp_chan_register_upcall_port_resp);				\
	NBL_DISP_SET_OPS(unregister_upcall_port, nbl_disp_unregister_upcall_port,		\
			 NBL_DISP_CTRL_LVL_MGT,							\
			 NBL_CHAN_MSG_UNREGISTER_UPCALL_PORT,					\
			 nbl_disp_chan_unregister_upcall_port_req,				\
			 nbl_disp_chan_unregister_upcall_port_resp);				\
	NBL_DISP_SET_OPS(dummy_func, NULL, NBL_DISP_CTRL_LVL_MGT,				\
			 NBL_CHAN_MSG_SET_OFFLOAD_STATUS, NULL,					\
			 nbl_disp_chan_set_offload_status_resp);				\
	NBL_DISP_SET_OPS(get_port_attributes, nbl_disp_get_port_attributes,			\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(update_ring_num, nbl_disp_update_ring_num,				\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(update_rdma_cap, nbl_disp_update_rdma_cap,				\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_rdma_cap_num, nbl_disp_get_rdma_cap_num,				\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(update_rdma_mem_type, nbl_disp_update_rdma_mem_type,			\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(update_internal_cfg, nbl_disp_update_internal_cfg,			\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_part_number, nbl_disp_get_part_number,				\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_serial_number, nbl_disp_get_serial_number,				\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(enable_port, nbl_disp_enable_port,					\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(init_port, nbl_disp_init_port,						\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(dummy_func, NULL,							\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_ADMINQ_PORT_NOTIFY,		\
			 NULL,									\
			 nbl_disp_chan_recv_port_notify_resp);					\
	NBL_DISP_SET_OPS(get_port_state, nbl_disp_get_port_state,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_PORT_STATE,			\
			 nbl_disp_chan_get_port_state_req,					\
			 nbl_disp_chan_get_port_state_resp);					\
	NBL_DISP_SET_OPS(get_fec_stats, nbl_disp_get_fec_stats,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_FEC_STATS,			\
			 nbl_disp_chan_get_fec_stats_req,					\
			 nbl_disp_chan_get_fec_stats_resp);					\
	NBL_DISP_SET_OPS(set_port_advertising, nbl_disp_set_port_advertising,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_PORT_ADVERTISING,		\
			 nbl_disp_chan_set_port_advertising_req,				\
			 nbl_disp_chan_set_port_advertising_resp);				\
	NBL_DISP_SET_OPS(get_module_info, nbl_disp_get_module_info,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_MODULE_INFO,			\
			 nbl_disp_chan_get_module_info_req,					\
			 nbl_disp_chan_get_module_info_resp);					\
	NBL_DISP_SET_OPS(get_module_eeprom, nbl_disp_get_module_eeprom,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_MODULE_EEPROM,			\
			 nbl_disp_chan_get_module_eeprom_req,					\
			 nbl_disp_chan_get_module_eeprom_resp);					\
	NBL_DISP_SET_OPS(get_module_eeprom_by_page, nbl_disp_get_module_eeprom_by_page,		\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_link_state, nbl_disp_get_link_state,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_LINK_STATE,			\
			 nbl_disp_chan_get_link_state_req,					\
			 nbl_disp_chan_get_link_state_resp);					\
	NBL_DISP_SET_OPS(get_link_down_count, nbl_disp_get_link_down_count,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_LINK_DOWN_COUNT,		\
			 nbl_disp_chan_get_link_down_count_req,					\
			 nbl_disp_chan_get_link_down_count_resp);				\
	NBL_DISP_SET_OPS(get_link_status_opcode, nbl_disp_get_link_status_opcode,		\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_LINK_STATUS_OPCODE,		\
			 nbl_disp_chan_get_link_status_opcode_req,				\
			 nbl_disp_chan_get_link_status_opcode_resp);				\
	NBL_DISP_SET_OPS(set_wol, nbl_disp_set_wol,						\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_WOL,				\
			 nbl_disp_chan_set_wol_req, nbl_disp_chan_set_wol_resp);		\
	NBL_DISP_SET_OPS(cfg_eth_bond_event, nbl_disp_cfg_eth_bond_event,			\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(dummy_func, NULL, NBL_DISP_CTRL_LVL_MGT,				\
			 NBL_CHAN_MSG_INIT_OFLD, NULL,						\
			 nbl_disp_chan_init_offload_fwd_resp);					\
	NBL_DISP_SET_OPS(dummy_func, NULL, NBL_DISP_CTRL_LVL_MGT,				\
			 NBL_CHAN_MSG_INIT_CMDQ, NULL,						\
			 nbl_disp_chan_init_cmdq_resp);						\
	NBL_DISP_SET_OPS(dummy_func, NULL, NBL_DISP_CTRL_LVL_MGT,				\
			 NBL_CHAN_MSG_DESTROY_CMDQ, NULL,					\
			 nbl_disp_chan_destroy_cmdq_resp);					\
	NBL_DISP_SET_OPS(dummy_func, NULL, NBL_DISP_CTRL_LVL_MGT,				\
			 NBL_CHAN_MSG_RESET_CMDQ, NULL,						\
			 nbl_disp_chan_reset_cmdq_resp);					\
	NBL_DISP_SET_OPS(dummy_func, NULL, NBL_DISP_CTRL_LVL_MGT,				\
			 NBL_CHAN_MSG_OFFLOAD_FLOW_RULE, NULL,					\
			 nbl_disp_chan_offload_flow_rule_resp);					\
	NBL_DISP_SET_OPS(dummy_func, NULL, NBL_DISP_CTRL_LVL_MGT,				\
			 NBL_CHAN_MSG_GET_ACL_SWITCH, NULL,					\
			 nbl_disp_chan_get_flow_acl_switch_resp);				\
	NBL_DISP_SET_OPS(dummy_func, NULL, NBL_DISP_CTRL_LVL_MGT,				\
			 NBL_CHAN_MSG_CFG_TNL_OFFLOAD_PROFILE, NULL,				\
			 nbl_disp_chan_cfg_tnl_offload_profile_resp);				\
	NBL_DISP_SET_OPS(dummy_func, NULL, NBL_DISP_CTRL_LVL_MGT,				\
			 NBL_CHAN_MSG_INIT_REP, NULL,						\
			 nbl_disp_chan_init_rep_resp);						\
	NBL_DISP_SET_OPS(dummy_func, NULL, NBL_DISP_CTRL_LVL_MGT,				\
			 NBL_CHAN_MSG_SET_SLAVE_SWD, NULL,					\
			 nbl_disp_chan_set_slave_swd_id_resp);					\
	NBL_DISP_SET_OPS(dummy_func, NULL, NBL_DISP_CTRL_LVL_MGT,				\
			 NBL_CHAN_MSG_INIT_FLOW, NULL,						\
			 nbl_disp_chan_init_flow_resp);						\
	NBL_DISP_SET_OPS(dummy_func, NULL, NBL_DISP_CTRL_LVL_MGT,				\
			 NBL_CHAN_MSG_INIT_FLOW_DRACO, NULL,					\
			 nbl_disp_chan_init_flow_draco_resp);					\
	NBL_DISP_SET_OPS(dummy_func, NULL, NBL_DISP_CTRL_LVL_MGT,				\
			 NBL_CHAN_MSG_DEINIT_FLOW, NULL,					\
			 nbl_disp_chan_deinit_flow_resp);					\
	NBL_DISP_SET_OPS(dummy_func, NULL, NBL_DISP_CTRL_LVL_MGT,				\
			 NBL_CHAN_MSG_GET_QUEUE_CXT, NULL,					\
			 nbl_disp_chan_get_queue_cxt_resp);					\
	NBL_DISP_SET_OPS(dummy_func, NULL, NBL_DISP_CTRL_LVL_MGT,				\
			 NBL_CHAN_MSG_CFG_LOG, NULL,						\
			 nbl_disp_chan_cfg_log_resp);						\
	NBL_DISP_SET_OPS(dummy_func, NULL, NBL_DISP_CTRL_LVL_MGT,				\
			 NBL_CHAN_MSG_INIT_VDPAQ, NULL,						\
			 nbl_disp_chan_init_vdpaq_resp);					\
	NBL_DISP_SET_OPS(dummy_func, NULL, NBL_DISP_CTRL_LVL_MGT,				\
			 NBL_CHAN_MSG_DESTROY_VDPAQ, NULL,					\
			 nbl_disp_chan_destroy_vdpaq_resp);					\
	NBL_DISP_SET_OPS(dummy_func, NULL, NBL_DISP_CTRL_LVL_MGT,				\
			 NBL_CHAN_GET_UPCALL_PORT, NULL,					\
			 nbl_disp_chan_get_upcall_port_resp);					\
	NBL_DISP_SET_OPS(set_eth_mac_addr, nbl_disp_set_eth_mac_addr,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_ETH_MAC_ADDR,			\
			 nbl_disp_chan_set_eth_mac_addr_req,					\
			 nbl_disp_chan_set_eth_mac_addr_resp);					\
	NBL_DISP_SET_OPS(get_chip_temperature, nbl_disp_get_chip_temperature_loc,		\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_CHIP_TEMPERATURE,		\
			 nbl_disp_chan_get_chip_temperature_req,				\
			 nbl_disp_chan_get_chip_temperature_resp);				\
	NBL_DISP_SET_OPS(get_module_temperature, nbl_disp_get_module_temperature_loc,		\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_MODULE_TEMPERATURE,		\
			 nbl_disp_chan_get_module_temperature_req,				\
			 nbl_disp_chan_get_module_temperature_resp);				\
	NBL_DISP_SET_OPS(process_abnormal_event, nbl_disp_process_abnormal_event,		\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(process_sfp_plug_event, nbl_disp_process_sfp_plug_event,		\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(switchdev_init_cmdq, nbl_disp_switchdev_init_cmdq,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SWITCHDEV_INIT_CMDQ,		\
			 nbl_disp_chan_switchdev_init_cmdq_req,					\
			 nbl_disp_chan_switchdev_init_cmdq_resp);				\
	NBL_DISP_SET_OPS(switchdev_deinit_cmdq, nbl_disp_switchdev_deinit_cmdq,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SWITCHDEV_DEINIT_CMDQ,		\
			 nbl_disp_chan_switchdev_deinit_cmdq_req,				\
			 nbl_disp_chan_switchdev_deinit_cmdq_resp);				\
	NBL_DISP_SET_OPS(get_tc_flow_parse_info, nbl_get_tc_flow_parse_info,			\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(add_tc_flow, nbl_disp_add_tc_flow,					\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(del_tc_flow, nbl_disp_del_tc_flow,					\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(tc_tun_encap_lookup, nbl_disp_tc_tun_encap_lookup,			\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(tc_tun_encap_del, nbl_disp_tc_tun_encap_del,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(tc_tun_encap_add, nbl_disp_tc_tun_encap_add,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(tc_tun_create_header, nbl_disp_tc_tun_create_header_loc,		\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(flow_index_lookup, nbl_disp_flow_index_lookup,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(set_tc_flow_info, nbl_disp_set_tc_flow_info,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_TC_FLOW_INFO,			\
			 nbl_disp_chan_set_tc_flow_info_req,					\
			 nbl_disp_chan_set_tc_flow_info_resp);					\
	NBL_DISP_SET_OPS(unset_tc_flow_info, nbl_disp_unset_tc_flow_info,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_UNSET_TC_FLOW_INFO,		\
			 nbl_disp_chan_unset_tc_flow_info_req,					\
			 nbl_disp_chan_unset_tc_flow_info_resp);				\
	NBL_DISP_SET_OPS(get_tc_flow_info, nbl_disp_get_tc_flow_info,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(query_tc_stats, nbl_disp_query_tc_stats,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(get_owned_pf_bitmap, nbl_disp_get_owned_pf_bitmap,			\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(adapt_desc_gother, nbl_disp_adapt_desc_gother,				\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(set_desc_high_throughput, nbl_disp_set_desc_high_throughput,		\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(flr_clear_net, nbl_disp_flr_clear_net,					\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(flr_clear_accel, nbl_disp_flr_clear_accel,				\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(flr_qinfo_cfg, nbl_disp_flr_qinfo_cfg,					\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(flr_clear_queues, nbl_disp_flr_clear_queues,				\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(flr_clear_accel_flow, nbl_disp_flr_clear_accel_flow,			\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(flr_clear_flows, nbl_disp_flr_clear_flows,				\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(flr_clear_interrupt, nbl_disp_flr_clear_interrupt,			\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(flr_clear_rdma, nbl_disp_flr_clear_rdma,				\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(covert_vfid_to_vsi_id, nbl_disp_covert_vfid_to_vsi_id,			\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(ctrl_port_led, nbl_disp_ctrl_port_led,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CTRL_PORT_LED,			\
			 nbl_disp_chan_ctrl_port_led_req, nbl_disp_chan_ctrl_port_led_resp);	\
	NBL_DISP_SET_OPS(nway_reset, nbl_disp_nway_reset,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_NWAY_RESET,			\
			 nbl_disp_chan_nway_reset_req, nbl_disp_chan_nway_reset_resp);		\
	NBL_DISP_SET_OPS(get_rep_queue_info, nbl_disp_get_rep_queue_info_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_REP_QUEUE_INFO,		\
			 nbl_disp_chan_get_rep_queue_info_req,					\
			 nbl_disp_chan_get_rep_queue_info_resp);				\
	NBL_DISP_SET_OPS(get_user_queue_info, nbl_disp_get_user_queue_info_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_USER_QUEUE_INFO,		\
			 nbl_disp_chan_get_user_queue_info_req,					\
			 nbl_disp_chan_get_user_queue_info_resp);				\
	NBL_DISP_SET_OPS(get_board_info, nbl_disp_get_board_info, NBL_DISP_CTRL_LVL_MGT,	\
			 NBL_CHAN_MSG_GET_BOARD_INFO, nbl_disp_chan_get_board_info_req,		\
			 nbl_disp_chan_get_board_info_resp);					\
	NBL_DISP_SET_OPS(get_vf_base_vsi_id, nbl_disp_get_vf_base_vsi_id,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_VF_BASE_VSI_ID,		\
			 nbl_disp_chan_get_vf_base_vsi_id_req,					\
			 nbl_disp_chan_get_vf_base_vsi_id_resp);				\
	NBL_DISP_SET_OPS(cfg_eth_bond_info, nbl_disp_cfg_eth_bond_info,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CFG_ETH_BOND_INFO,			\
			 nbl_disp_chan_cfg_eth_bond_info_req,					\
			 nbl_disp_chan_cfg_eth_bond_info_resp);					\
	NBL_DISP_SET_OPS(get_eth_bond_info, nbl_disp_get_eth_bond_info,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_ETH_BOND_INFO,			\
			 nbl_disp_chan_get_eth_bond_info_req,					\
			 nbl_disp_chan_get_eth_bond_info_resp);					\
	NBL_DISP_SET_OPS(add_nd_upcall_flow, nbl_disp_chan_add_nd_upcall_flow,			\
			 NBL_DISP_CTRL_LVL_MGT,							\
			 NBL_CHAN_MSG_ADD_ND_UPCALL_FLOW,					\
			 nbl_disp_chan_add_nd_upcall_flow_req,					\
			 nbl_disp_chan_add_nd_upcall_flow_resp);				\
	NBL_DISP_SET_OPS(del_nd_upcall_flow, nbl_disp_chan_del_nd_upcall_flow,			\
			 NBL_DISP_CTRL_LVL_MGT,							\
			 NBL_CHAN_MSG_DEL_ND_UPCALL_FLOW,					\
			 nbl_disp_chan_del_nd_upcall_flow_req,					\
			 nbl_disp_chan_del_nd_upcall_flow_resp);				\
	NBL_DISP_SET_OPS(set_bridge_mode, nbl_disp_set_bridge_mode,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_BRIDGE_MODE,			\
			 nbl_disp_chan_set_bridge_mode_req,					\
			 nbl_disp_chan_set_bridge_mode_resp);					\
	NBL_DISP_SET_OPS(get_vf_function_id, nbl_disp_get_vf_function_id,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_VF_FUNCTION_ID,		\
			 nbl_disp_chan_get_vf_function_id_req,					\
			 nbl_disp_chan_get_vf_function_id_resp);				\
	NBL_DISP_SET_OPS(get_vf_vsi_id, nbl_disp_get_vf_vsi_id,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_VF_VSI_ID,			\
			 nbl_disp_chan_get_vf_vsi_id_req,					\
			 nbl_disp_chan_get_vf_vsi_id_resp);					\
	NBL_DISP_SET_OPS(check_vf_is_active, nbl_disp_check_vf_is_active,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_CHECK_VF_IS_ACTIVE,			\
			 nbl_disp_chan_check_vf_is_active_req,					\
			 nbl_disp_chan_check_vf_is_active_resp);				\
	NBL_DISP_SET_OPS(check_vf_is_vdpa, nbl_disp_check_vf_is_vdpa,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_CHECK_VF_IS_VDPA,			\
			 nbl_disp_chan_check_vf_is_vdpa_req,					\
			 nbl_disp_chan_check_vf_is_vdpa_resp);					\
	NBL_DISP_SET_OPS(get_vdpa_vf_stats, nbl_disp_get_vdpa_vf_stats,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_VDPA_VF_STATS,			\
			 nbl_disp_chan_get_vdpa_vf_stats_req,					\
			 nbl_disp_chan_get_vdpa_vf_stats_resp);					\
	NBL_DISP_SET_OPS(get_uvn_pkt_drop_stats, nbl_disp_get_uvn_pkt_drop_stats,		\
			 NBL_DISP_CTRL_LVL_MGT,							\
			 NBL_CHAN_GET_UVN_PKT_DROP_STATS,					\
			 nbl_disp_chan_get_uvn_pkt_drop_stats_req,				\
			 nbl_disp_chan_get_uvn_pkt_drop_stats_resp);				\
	NBL_DISP_SET_OPS(get_pkt_drop_stats, nbl_disp_get_pkt_drop_stats,		\
			 NBL_DISP_CTRL_LVL_MGT,							\
			 NBL_CHAN_GET_PKT_DROP_STATS,					\
			 nbl_disp_chan_get_pkt_drop_stats_req,				\
			 nbl_disp_chan_get_pkt_drop_stats_resp);				\
	NBL_DISP_SET_OPS(get_total_pkt_drop_stats,					\
			 nbl_disp_get_total_pkt_drop_stats,				\
			 NBL_DISP_CTRL_LVL_MGT,							\
			 NBL_CHAN_GET_TOTAL_PKT_DROP_STATS,				\
			 nbl_disp_chan_get_total_pkt_drop_stats_req,			\
			 nbl_disp_chan_get_total_pkt_drop_stats_resp);			\
	NBL_DISP_SET_OPS(set_pmd_debug, nbl_disp_set_pmd_debug,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_PMD_DEBUG,			\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(register_func_mac, nbl_disp_register_func_mac,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_REGISTER_FUNC_MAC,			\
			 nbl_disp_chan_register_func_mac_req,					\
			 nbl_disp_chan_register_func_mac_resp);					\
	NBL_DISP_SET_OPS(set_tx_rate, nbl_disp_set_tx_rate,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_TX_RATE,			\
			 nbl_disp_chan_set_tx_rate_req, nbl_disp_chan_set_tx_rate_resp);	\
	NBL_DISP_SET_OPS(set_rx_rate, nbl_disp_set_rx_rate,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_RX_RATE,			\
			 nbl_disp_chan_set_rx_rate_req, nbl_disp_chan_set_rx_rate_resp);	\
	NBL_DISP_SET_OPS(register_func_link_forced, nbl_disp_register_func_link_forced,		\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_REGISTER_FUNC_LINK_FORCED,		\
			 nbl_disp_chan_register_func_link_forced_req,				\
			 nbl_disp_chan_register_func_link_forced_resp);				\
	NBL_DISP_SET_OPS(get_link_forced, nbl_disp_get_link_forced,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_LINK_FORCED,			\
			 nbl_disp_chan_get_link_forced_req, nbl_disp_chan_get_link_forced_resp);\
	NBL_DISP_SET_OPS(register_func_trust, nbl_disp_register_func_trust,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_REGISTER_FUNC_TRUST,		\
			 nbl_disp_chan_register_func_trust_req,					\
			 nbl_disp_chan_register_func_trust_resp);				\
	NBL_DISP_SET_OPS(register_func_vlan, nbl_disp_register_func_vlan,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_REGISTER_FUNC_VLAN,		\
			 nbl_disp_chan_register_func_vlan_req,					\
			 nbl_disp_chan_register_func_vlan_resp);				\
	NBL_DISP_SET_OPS(register_func_rate, nbl_disp_register_func_rate,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_REGISTER_FUNC_RATE,		\
			 nbl_disp_chan_register_func_rate_req,					\
			 nbl_disp_chan_register_func_rate_resp);				\
	NBL_DISP_SET_OPS(set_mtu, nbl_disp_set_mtu,						\
			 NBL_DISP_CTRL_LVL_MGT,	NBL_CHAN_MSG_MTU_SET,				\
			 nbl_disp_chan_set_mtu_req,						\
			 nbl_disp_chan_set_mtu_resp);						\
	NBL_DISP_SET_OPS(check_mtu, nbl_disp_check_mtu,						\
			 NBL_DISP_CTRL_LVL_NET,	-1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_fd_flow, nbl_disp_get_fd_flow,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_FD_FLOW,			\
			 nbl_disp_chan_get_fd_flow_req, nbl_disp_chan_get_fd_flow_resp);	\
	NBL_DISP_SET_OPS(get_fd_flow_cnt, nbl_disp_get_fd_flow_cnt,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_FD_FLOW_CNT,			\
			 nbl_disp_chan_get_fd_flow_cnt_req, nbl_disp_chan_get_fd_flow_cnt_resp);\
	NBL_DISP_SET_OPS(get_fd_flow_all, nbl_disp_get_fd_flow_all,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_FD_FLOW_ALL,			\
			 nbl_disp_chan_get_fd_flow_all_req, nbl_disp_chan_get_fd_flow_all_resp);\
	NBL_DISP_SET_OPS(get_fd_flow_max, nbl_disp_get_fd_flow_max,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_FD_FLOW_MAX,			\
			 nbl_disp_chan_get_fd_flow_max_req, nbl_disp_chan_get_fd_flow_max_resp);\
	NBL_DISP_SET_OPS(replace_fd_flow, nbl_disp_replace_fd_flow,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_REPLACE_FD_FLOW,			\
			 nbl_disp_chan_replace_fd_flow_req, nbl_disp_chan_replace_fd_flow_resp);\
	NBL_DISP_SET_OPS(remove_fd_flow, nbl_disp_remove_fd_flow,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_REMOVE_FD_FLOW,			\
			 nbl_disp_chan_remove_fd_flow_req, nbl_disp_chan_remove_fd_flow_resp);	\
	NBL_DISP_SET_OPS(config_fd_flow_state, nbl_disp_config_fd_flow_state,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CFG_FD_FLOW_STATE,			\
			 nbl_disp_chan_config_fd_flow_state_req,				\
			 nbl_disp_chan_config_fd_flow_state_resp);				\
	NBL_DISP_SET_OPS(cfg_fd_update_event, nbl_disp_cfg_fd_update_event,			\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(dump_fd_flow, nbl_disp_dump_fd_flow,					\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_hash_fields, nbl_disp_get_hash_fields,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_HASH_FIELDS,			\
			 nbl_disp_chan_get_hash_fields_req,					\
			 nbl_disp_chan_get_hash_fields_resp);					\
	NBL_DISP_SET_OPS(set_hash_fields, nbl_disp_set_hash_fields,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_HASH_FIELDS,			\
			 nbl_disp_chan_set_hash_fields_req,					\
			 nbl_disp_chan_set_hash_fields_resp);					\
	NBL_DISP_SET_OPS(alloc_macsec_txsc_index, nbl_disp_alloc_macsec_txsc_index,		\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(free_macsec_txsc_index, nbl_disp_free_macsec_txsc_index,		\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(alloc_macsec_rxsc_index, nbl_disp_alloc_macsec_rxsc_index,		\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(free_macsec_rxsc_index, nbl_disp_free_macsec_rxsc_index,		\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(cfg_macsec_fs, nbl_disp_cfg_macsec_fs,					\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(cfg_macsec_txsc, nbl_disp_cfg_macsec_txsc,				\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(cfg_macsec_rxsc, nbl_disp_cfg_macsec_rxsc,				\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(cfg_macsec_sa, nbl_disp_cfg_macsec_sa,					\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_xdp_queue_info, nbl_disp_get_xdp_queue_info_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_XDP_QUEUE_INFO,		\
			 nbl_disp_chan_get_xdp_queue_info_req,					\
			 nbl_disp_chan_get_xdp_queue_info_resp);				\
	NBL_DISP_SET_OPS(set_hw_status, nbl_disp_set_hw_status_loc,				\
			 NBL_DISP_CTRL_LVL_ALWAYS, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(check_hw_status, nbl_disp_check_hw_status_loc,				\
			 NBL_DISP_CTRL_LVL_ALWAYS, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_hw_status, nbl_disp_get_hw_status_loc,				\
			 NBL_DISP_CTRL_LVL_ALWAYS, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(get_active_func_bitmaps, nbl_disp_get_active_func_bitmaps_loc,		\
			 NBL_DISP_CTRL_LVL_ALWAYS, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(configure_rdma_bw, nbl_disp_configure_rdma_bw_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CONFIGURE_RDMA_BW,			\
			 nbl_disp_chan_configure_rdma_bw_req,					\
			 nbl_disp_chan_configure_rdma_bw_resp);					\
	NBL_DISP_SET_OPS(configure_qos, nbl_disp_configure_qos_loc,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CONFIGURE_QOS,			\
			 nbl_disp_chan_configure_qos_req,					\
			 nbl_disp_chan_configure_qos_resp);					\
	NBL_DISP_SET_OPS(set_tc_wgt, nbl_disp_set_tc_wgt_loc,					\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_TC_WGT,			\
			 nbl_disp_chan_set_tc_wgt_req,						\
			 nbl_disp_chan_set_tc_wgt_resp);					\
	NBL_DISP_SET_OPS(get_pfc_buffer_size, nbl_disp_get_pfc_buffer_size_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_PFC_BUFFER_SIZE,		\
			 nbl_disp_chan_get_pfc_buffer_size_req,					\
			 nbl_disp_chan_get_pfc_buffer_size_resp);				\
	NBL_DISP_SET_OPS(set_pfc_buffer_size, nbl_disp_set_pfc_buffer_size_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_PFC_BUFFER_SIZE,		\
			 nbl_disp_chan_set_pfc_buffer_size_req,					\
			 nbl_disp_chan_set_pfc_buffer_size_resp);				\
	NBL_DISP_SET_OPS(set_rate_limit, nbl_disp_set_rate_limit_loc,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_SET_RATE_LIMIT,			\
			 nbl_disp_chan_set_rate_limit_req,					\
			 nbl_disp_chan_set_rate_limit_resp);					\
	NBL_DISP_SET_OPS(get_perf_dump_length, nbl_disp_get_perf_dump_length_loc,		\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(get_perf_dump_data, nbl_disp_get_perf_dump_data_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(register_dev_name, nbl_disp_register_dev_name_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_REGISTER_PF_NAME,			\
			 nbl_disp_chan_register_dev_name_req,					\
			 nbl_disp_chan_register_dev_name_resp);					\
	NBL_DISP_SET_OPS(get_dev_name, nbl_disp_get_dev_name_loc,				\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_PF_NAME,			\
			 nbl_disp_chan_get_dev_name_req,					\
			 nbl_disp_chan_get_dev_name_resp);					\
	NBL_DISP_SET_OPS(get_mirror_table_id, nbl_disp_get_mirror_table_id_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_GET_MIRROR_TABLE_ID,		\
			 nbl_disp_chan_get_mirror_table_id_req,					\
			 nbl_disp_chan_get_mirror_table_id_resp);				\
	NBL_DISP_SET_OPS(configure_mirror, nbl_disp_configure_mirror_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CONFIGURE_MIRROR,			\
			 nbl_disp_chan_configure_mirror_req,					\
			 nbl_disp_chan_configure_mirror_resp);					\
	NBL_DISP_SET_OPS(configure_tx_mirror_to_rdma, nbl_disp_configure_tx_mirror_to_rdma_loc,	\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(configure_mirror_table, nbl_disp_configure_mirror_table_loc,		\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CONFIGURE_MIRROR_TABLE,		\
			 nbl_disp_chan_configure_mirror_table_req,				\
			 nbl_disp_chan_configure_mirror_table_resp);				\
	NBL_DISP_SET_OPS(clear_mirror_cfg, nbl_disp_clear_mirror_cfg_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CLEAR_MIRROR_CFG,			\
			 nbl_disp_chan_clear_mirror_cfg_req,					\
			 nbl_disp_chan_clear_mirror_cfg_resp);					\
	NBL_DISP_SET_OPS(cfg_mirror_outputport_event, nbl_disp_cfg_mirror_outputport_event_loc,	\
			 NBL_DISP_CTRL_LVL_MGT, -1, NULL, NULL);				\
	NBL_DISP_SET_OPS(check_flow_table_spec, nbl_disp_check_flow_table_spec_loc,		\
			 NBL_DISP_CTRL_LVL_MGT, NBL_CHAN_MSG_CHECK_FLOWTABLE_SPEC,		\
			 nbl_disp_chan_check_flow_table_spec_req,				\
			 nbl_disp_chan_check_flow_table_spec_resp);				\
	NBL_DISP_SET_OPS(get_dvn_desc_req, nbl_disp_get_dvn_desc_req_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(set_dvn_desc_req, nbl_disp_set_dvn_desc_req_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(set_rx_csum_drop, nbl_disp_set_rx_csum_drop_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(set_xdp_enhance, nbl_disp_set_xdp_enhance_loc,				\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(dump_abnormal_intr, nbl_disp_dump_abnormal_intr_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(cfg_vlan_filtering, nbl_disp_cfg_vlan_filtering_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(get_lag_ports_max, nbl_disp_get_lag_ports_max_loc,			\
			 NBL_DISP_CTRL_LVL_MGT, -1,						\
			 NULL, NULL);								\
	NBL_DISP_SET_OPS(check_lag_nosupport, nbl_disp_check_lag_nosupport_loc,			\
			 NBL_DISP_CTRL_LVL_NET, -1,						\
			 NULL, NULL);								\
} while (0)

/* Structure starts here, adding an op should not modify anything below */
static int nbl_disp_setup_msg(struct nbl_dispatch_mgt *disp_mgt)
{
	struct nbl_channel_ops *chan_ops = NBL_DISP_MGT_TO_CHAN_OPS(disp_mgt);
	int ret = 0;

	mutex_init(&disp_mgt->ops_muxtex_lock);
	disp_mgt->ops_lock_required = true;

#define NBL_DISP_SET_OPS(disp_op, res_func, ctrl_lvl, msg_type, msg_req, msg_resp)		\
do {												\
	typeof(msg_type) _msg_type = (msg_type);						\
	if (_msg_type >= 0)									\
		ret += chan_ops->register_msg(NBL_DISP_MGT_TO_CHAN_PRIV(disp_mgt),		\
					      _msg_type, msg_resp, disp_mgt);			\
} while (0)
	NBL_DISP_OPS_TBL;
#undef  NBL_DISP_SET_OPS

	return ret;
}

/* Ctrl lvl means that if a certain level is set, then all disp_ops that decleared this lvl
 * will go directly to res_ops, rather than send a channel msg, and vice versa.
 */
static int nbl_disp_setup_ctrl_lvl(struct nbl_dispatch_mgt *disp_mgt, u32 lvl)
{
	struct nbl_dispatch_ops *disp_ops;

	disp_ops = NBL_DISP_MGT_TO_DISP_OPS(disp_mgt);

	set_bit(lvl, disp_mgt->ctrl_lvl);

#define NBL_DISP_SET_OPS(disp_op, res_func, ctrl, msg_type, msg_req, msg_resp)			\
do {												\
	disp_ops->NBL_NAME(disp_op) = test_bit(ctrl, disp_mgt->ctrl_lvl) ? res_func : msg_req; ;\
} while (0)
	NBL_DISP_OPS_TBL;
#undef  NBL_DISP_SET_OPS

	return 0;
}

static int nbl_disp_setup_disp_mgt(struct nbl_common_info *common,
				   struct nbl_dispatch_mgt **disp_mgt)
{
	struct device *dev;

	dev = NBL_COMMON_TO_DEV(common);
	*disp_mgt = devm_kzalloc(dev, sizeof(struct nbl_dispatch_mgt), GFP_KERNEL);
	if (!*disp_mgt)
		return -ENOMEM;

	NBL_DISP_MGT_TO_COMMON(*disp_mgt) = common;
	return 0;
}

static void nbl_disp_remove_disp_mgt(struct nbl_common_info *common,
				     struct nbl_dispatch_mgt **disp_mgt)
{
	struct device *dev;

	dev = NBL_COMMON_TO_DEV(common);
	devm_kfree(dev, *disp_mgt);
	*disp_mgt = NULL;
}

static void nbl_disp_remove_ops(struct device *dev, struct nbl_dispatch_ops_tbl **disp_ops_tbl)
{
	devm_kfree(dev, NBL_DISP_OPS_TBL_TO_OPS(*disp_ops_tbl));
	devm_kfree(dev, *disp_ops_tbl);
	*disp_ops_tbl = NULL;
}

static int nbl_disp_setup_ops(struct device *dev, struct nbl_dispatch_ops_tbl **disp_ops_tbl,
			      struct nbl_dispatch_mgt *disp_mgt)
{
	struct nbl_dispatch_ops *disp_ops;

	*disp_ops_tbl = devm_kzalloc(dev, sizeof(struct nbl_dispatch_ops_tbl), GFP_KERNEL);
	if (!*disp_ops_tbl)
		return -ENOMEM;

	disp_ops = devm_kzalloc(dev, sizeof(struct nbl_dispatch_ops), GFP_KERNEL);
	if (!disp_ops)
		return -ENOMEM;

	NBL_DISP_OPS_TBL_TO_OPS(*disp_ops_tbl) = disp_ops;
	NBL_DISP_OPS_TBL_TO_PRIV(*disp_ops_tbl) = disp_mgt;

	return 0;
}

int nbl_disp_init(void *p, struct nbl_init_param *param)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct device *dev = NBL_ADAPTER_TO_DEV(adapter);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	struct nbl_dispatch_mgt **disp_mgt =
		(struct nbl_dispatch_mgt **)&NBL_ADAPTER_TO_DISP_MGT(adapter);
	struct nbl_dispatch_ops_tbl **disp_ops_tbl = &NBL_ADAPTER_TO_DISP_OPS_TBL(adapter);
	struct nbl_resource_ops_tbl *res_ops_tbl = NBL_ADAPTER_TO_RES_OPS_TBL(adapter);
	struct nbl_channel_ops_tbl *chan_ops_tbl = NBL_ADAPTER_TO_CHAN_OPS_TBL(adapter);
	int ret = 0;

	ret = nbl_disp_setup_disp_mgt(common, disp_mgt);
	if (ret)
		goto setup_mgt_fail;

	ret = nbl_disp_setup_ops(dev, disp_ops_tbl, *disp_mgt);
	if (ret)
		goto setup_ops_fail;

	NBL_DISP_MGT_TO_RES_OPS_TBL(*disp_mgt) = res_ops_tbl;
	NBL_DISP_MGT_TO_CHAN_OPS_TBL(*disp_mgt) = chan_ops_tbl;
	NBL_DISP_MGT_TO_DISP_OPS_TBL(*disp_mgt) = *disp_ops_tbl;

	ret = nbl_disp_setup_msg(*disp_mgt);
	if (ret)
		goto setup_msg_fail;

	if (param->caps.has_ctrl) {
		ret = nbl_disp_setup_ctrl_lvl(*disp_mgt, NBL_DISP_CTRL_LVL_MGT);
		if (ret)
			goto setup_msg_fail;
	}

	if (param->caps.has_net) {
		ret = nbl_disp_setup_ctrl_lvl(*disp_mgt, NBL_DISP_CTRL_LVL_NET);
		if (ret)
			goto setup_msg_fail;
	}

	ret = nbl_disp_setup_ctrl_lvl(*disp_mgt, NBL_DISP_CTRL_LVL_ALWAYS);
	if (ret)
		goto setup_msg_fail;

	return 0;

setup_msg_fail:
	nbl_disp_remove_ops(dev, disp_ops_tbl);
setup_ops_fail:
	nbl_disp_remove_disp_mgt(common, disp_mgt);
setup_mgt_fail:
	return ret;
}

void nbl_disp_remove(void *p)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct device *dev;
	struct nbl_common_info *common;
	struct nbl_dispatch_mgt **disp_mgt;
	struct nbl_dispatch_ops_tbl **disp_ops_tbl;

	if (!adapter)
		return;

	dev = NBL_ADAPTER_TO_DEV(adapter);
	common = NBL_ADAPTER_TO_COMMON(adapter);
	disp_mgt = (struct nbl_dispatch_mgt **)&NBL_ADAPTER_TO_DISP_MGT(adapter);
	disp_ops_tbl = &NBL_ADAPTER_TO_DISP_OPS_TBL(adapter);

	nbl_disp_remove_ops(dev, disp_ops_tbl);

	nbl_disp_remove_disp_mgt(common, disp_mgt);
}

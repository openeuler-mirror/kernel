// SPDX-License-Identifier: GPL-2.0
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>

#include "nds_api_internal.h"
#include <linux/nds_p2p.h>

/*
 * Opaque ctx wrapper: Python holds the pointer as a PyCapsule named "nds_io_ctx".
 */
static const char *nds_ctx_capsule_name = "nds_io_ctx";

static void nds_ctx_capsule_destructor(PyObject *capsule)
{
	struct nds_io_ctx *ctx = PyCapsule_GetPointer(capsule, nds_ctx_capsule_name);

	if (ctx)
		nds_io_destroy_ctx(ctx);
}

static struct nds_io_ctx *nds_ctx_from_obj(PyObject *obj)
{
	struct nds_io_ctx *ctx;

	if (!PyCapsule_CheckExact(obj)) {
		PyErr_SetString(PyExc_TypeError, "ctx must be an nds_io_ctx capsule");
		return NULL;
	}
	ctx = PyCapsule_GetPointer(obj, nds_ctx_capsule_name);
	if (!ctx)
		PyErr_SetString(PyExc_ValueError, "invalid or destroyed nds_io_ctx");
	return ctx;
}

static int parse_nds_iov(PyObject *obj, struct nds_io_vec **iov_out,
			 uint32_t *iov_cnt_out)
{
	struct nds_io_vec *iov;
	PyObject *seq;
	Py_ssize_t count;
	Py_ssize_t i;

	seq = PySequence_Fast(obj, "iov must be a sequence of (buf_addr, buf_len)");
	if (!seq)
		return -1;
	count = PySequence_Fast_GET_SIZE(seq);
	if (count <= 0 || count > NDS_IO_MAX_IOV) {
		Py_DECREF(seq);
		PyErr_SetString(PyExc_ValueError, "iov count out of range");
		return -1;
	}
	iov = calloc((size_t)count, sizeof(*iov));
	if (!iov) {
		Py_DECREF(seq);
		PyErr_NoMemory();
		return -1;
	}
	for (i = 0; i < count; i++) {
		unsigned long long addr;
		unsigned int len;

		if (!PyArg_ParseTuple(PySequence_Fast_GET_ITEM(seq, i), "KI",
				      &addr, &len)) {
			free(iov);
			Py_DECREF(seq);
			return -1;
		}
		iov[i].buf_addr = addr;
		iov[i].buf_len = len;
	}
	Py_DECREF(seq);
	*iov_out = iov;
	*iov_cnt_out = (uint32_t)count;
	return 0;
}

static int py_parse_fs_desc(PyObject *fd_seq, struct nds_fs_desc *desc,
			    int32_t **fds_out)
{
	PyObject *seq = NULL;
	int32_t *fds = NULL;
	Py_ssize_t count;
	Py_ssize_t i;

	seq = PySequence_Fast(fd_seq, "fs_fds must be a sequence of ints");
	if (!seq)
		return -1;
	count = PySequence_Fast_GET_SIZE(seq);
	if (count < 0 || count > UINT32_MAX) {
		Py_DECREF(seq);
		PyErr_SetString(PyExc_ValueError, "fs_fds count out of range");
		return -1;
	}
	fds = calloc((size_t)(count ? count : 1), sizeof(*fds));
	if (!fds) {
		Py_DECREF(seq);
		PyErr_NoMemory();
		return -1;
	}
	for (i = 0; i < count; i++) {
		long v = PyLong_AsLong(PySequence_Fast_GET_ITEM(seq, i));

		if (PyErr_Occurred() || v < 0 || v > INT32_MAX) {
			if (!PyErr_Occurred())
				PyErr_SetString(PyExc_ValueError,
						"invalid fd in fs_fds");
			free(fds);
			Py_DECREF(seq);
			return -1;
		}
		fds[i] = (int32_t)v;
	}
	Py_DECREF(seq);

	desc->fs_fd = fds;
	desc->fs_fd_cnt = (uint32_t)count;
	desc->reserved = 0;
	*fds_out = fds;
	return 0;
}

static PyObject *py_nds_init(PyObject *Py_UNUSED(self), PyObject *args)
{
	struct nds_init_param param = { };
	unsigned int flags = 0;
	int ret;

	/* init([flags=0]) */
	if (!PyArg_ParseTuple(args, "|I", &flags))
		return NULL;
	param.flags = flags;

	Py_BEGIN_ALLOW_THREADS
	ret = nds_init(&param);
	Py_END_ALLOW_THREADS
	return PyLong_FromLong(ret);
}

static PyObject *py_nds_register_fs(PyObject *Py_UNUSED(self), PyObject *args)
{
	struct nds_fs_desc desc = { };
	PyObject *fd_seq;
	int32_t *fds;
	int ret;

	if (!PyArg_ParseTuple(args, "O", &fd_seq))
		return NULL;
	if (py_parse_fs_desc(fd_seq, &desc, &fds))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = nds_register_fs(&desc);
	Py_END_ALLOW_THREADS
	free(fds);
	return PyLong_FromLong(ret);
}

static PyObject *py_nds_unregister_fs(PyObject *Py_UNUSED(self),
				      PyObject *args)
{
	struct nds_fs_desc desc = { };
	PyObject *fd_seq;
	int32_t *fds;
	int ret;

	if (!PyArg_ParseTuple(args, "O", &fd_seq))
		return NULL;
	if (py_parse_fs_desc(fd_seq, &desc, &fds))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = nds_unregister_fs(&desc);
	Py_END_ALLOW_THREADS
	free(fds);
	return PyLong_FromLong(ret);
}

static PyObject *py_nds_exit(PyObject *Py_UNUSED(self),
			     PyObject *Py_UNUSED(ignored))
{
	int ret;

	Py_BEGIN_ALLOW_THREADS
	ret = nds_exit();
	Py_END_ALLOW_THREADS
	return PyLong_FromLong(ret);
}

static PyObject *py_nds_register_mem(PyObject *Py_UNUSED(self), PyObject *args)
{
	unsigned long long addr;
	unsigned long long size;
	int flags = 0;
	int ret;

	if (!PyArg_ParseTuple(args, "KK|i", &addr, &size, &flags))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = nds_register_mem((void *)(uintptr_t)addr, size, flags);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong(ret);
}

static PyObject *py_nds_unregister_mem(PyObject *Py_UNUSED(self), PyObject *args)
{
	unsigned long long addr;
	unsigned long long size;
	int flags = 0;
	int ret;

	if (!PyArg_ParseTuple(args, "KK|i", &addr, &size, &flags))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = nds_unregister_mem((void *)(uintptr_t)addr, size, flags);
	Py_END_ALLOW_THREADS
	return PyLong_FromLong(ret);
}

static PyObject *py_nds_io_new_ctx(PyObject *Py_UNUSED(self), PyObject *args)
{
	struct nds_io_ctx_param param = { };
	struct nds_io_ctx *ctx = NULL;
	unsigned int max_io_cnt;
	unsigned int flags = 0;
	int ret;

	if (!PyArg_ParseTuple(args, "I|I", &max_io_cnt, &flags))
		return NULL;
	param.max_io_cnt = max_io_cnt;
	param.flags = flags;

	Py_BEGIN_ALLOW_THREADS
	ret = nds_io_new_ctx(&param, &ctx);
	Py_END_ALLOW_THREADS
	if (ret)
		return PyLong_FromLong(ret);

	return PyCapsule_New(ctx, nds_ctx_capsule_name, nds_ctx_capsule_destructor);
}

static PyObject *py_nds_io_destroy_ctx(PyObject *Py_UNUSED(self), PyObject *args)
{
	PyObject *capsule;
	struct nds_io_ctx *ctx;
	int ret;

	if (!PyArg_ParseTuple(args, "O", &capsule))
		return NULL;
	ctx = nds_ctx_from_obj(capsule);
	if (!ctx)
		return NULL;

	/* Disable auto-destroy; this call owns the teardown. */
	if (PyCapsule_SetDestructor(capsule, NULL) < 0)
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = nds_io_destroy_ctx(ctx);
	Py_END_ALLOW_THREADS

	/* Invalidate capsule so later use fails cleanly. */
	if (PyCapsule_SetName(capsule, "nds_io_ctx_destroyed") < 0)
		return NULL;
	return PyLong_FromLong(ret);
}

static PyObject *py_nds_io_dup_fd_for_test(PyObject *Py_UNUSED(self),
					   PyObject *args)
{
	PyObject *capsule;
	struct nds_io_ctx *ctx;
	int fd;

	if (!PyArg_ParseTuple(args, "O", &capsule))
		return NULL;
	ctx = nds_ctx_from_obj(capsule);
	if (!ctx)
		return NULL;

	fd = fcntl(ctx->p2p_fd, F_DUPFD_CLOEXEC, 0);
	return PyLong_FromLong(fd < 0 ? -errno : fd);
}

static PyObject *py_nds_io_submit(PyObject *Py_UNUSED(self), PyObject *args)
{
	PyObject *capsule;
	PyObject *iocb_seq;
	PyObject *seq;
	struct nds_io_ctx *ctx;
	struct nds_io_cb *cbs = NULL;
	struct nds_io_vec **iov = NULL;
	Py_ssize_t count;
	Py_ssize_t i;
	int ret;

	if (!PyArg_ParseTuple(args, "OO", &capsule, &iocb_seq))
		return NULL;
	ctx = nds_ctx_from_obj(capsule);
	if (!ctx)
		return NULL;

	seq = PySequence_Fast(iocb_seq, "iocbs must be a sequence");
	if (!seq)
		return NULL;
	count = PySequence_Fast_GET_SIZE(seq);
	if (count < 0 || count > INT_MAX) {
		Py_DECREF(seq);
		PyErr_SetString(PyExc_ValueError, "iocb count out of range");
		return NULL;
	}
	if (!count) {
		Py_DECREF(seq);
		return PyLong_FromLong(0);
	}

	cbs = calloc((size_t)count, sizeof(*cbs));
	iov = calloc((size_t)count, sizeof(*iov));
	if (!cbs || !iov) {
		free(cbs);
		free(iov);
		Py_DECREF(seq);
		return PyErr_NoMemory();
	}

	for (i = 0; i < count; i++) {
		PyObject *item = PySequence_Fast_GET_ITEM(seq, i);
		PyObject *fd_py;
		PyObject *iov_py;
		unsigned int opcode;
		unsigned int rw_flags = 0;
		unsigned long long offset;
		unsigned long long user_data = 0;
		long long fd;
		int host_pid = 0;

		/*
		 * iocb tuple:
		 * (opcode, fd, offset, iov
		 *  [, rw_flags=0, host_pid=0, user_data=0])
		 * iov: sequence of (buf_addr, buf_len)
		 */
		if (!PyArg_ParseTuple(item, "IOKO|IiK",
				      &opcode, &fd_py, &offset, &iov_py,
				      &rw_flags, &host_pid,
				      &user_data)) {
			goto parse_error;
		}
		fd = PyLong_AsLongLong(fd_py);
		if (PyErr_Occurred())
			goto parse_error;
		if (fd < 0 || fd > INT32_MAX) {
			PyErr_SetString(PyExc_ValueError, "fd out of range");
			goto parse_error;
		}
		if (parse_nds_iov(iov_py, &iov[i], &cbs[i].iov_cnt))
			goto parse_error;
		cbs[i].opcode = opcode;
		cbs[i].rw_flags = rw_flags;
		cbs[i].obj.fd = (int32_t)fd;
		cbs[i].offset = offset;
		cbs[i].user_data = user_data;
		cbs[i].iov = iov[i];
		cbs[i].host_pid = (int32_t)host_pid;
	}
	Py_DECREF(seq);

	Py_BEGIN_ALLOW_THREADS
	ret = nds_io_submit(ctx, (int)count, cbs);
	Py_END_ALLOW_THREADS

	for (i = 0; i < count; i++)
		free(iov[i]);
	free(iov);
	free(cbs);
	return PyLong_FromLong(ret);

parse_error:
	for (i = 0; i < count; i++)
		free(iov[i]);
	free(iov);
	free(cbs);
	Py_DECREF(seq);
	return NULL;
}

static PyObject *py_nds_io_getevents(PyObject *Py_UNUSED(self), PyObject *args)
{
	PyObject *capsule;
	struct nds_io_ctx *ctx;
	struct nds_io_event *events = NULL;
	struct timespec ts_storage;
	struct timespec *timeout = NULL;
	int min_nr;
	int nr;
	double timeout_sec = -1.0;
	PyObject *list;
	int ret;
	int i;

	if (!PyArg_ParseTuple(args, "Oii|d", &capsule, &min_nr, &nr, &timeout_sec))
		return NULL;
	ctx = nds_ctx_from_obj(capsule);
	if (!ctx)
		return NULL;
	if (min_nr < 0 || nr < 0 || min_nr > nr)
		return PyLong_FromLong(-EINVAL);
	if (!nr)
		return PyList_New(0);
	if (!isfinite(timeout_sec) ||
	    (timeout_sec >= 0.0 &&
	     timeout_sec > (double)INT64_MAX / 1000000000.0))
		return PyLong_FromLong(-EINVAL);

	events = calloc((size_t)nr, sizeof(*events));
	if (!events)
		return PyErr_NoMemory();

	if (timeout_sec >= 0.0) {
		ts_storage.tv_sec = (time_t)timeout_sec;
		ts_storage.tv_nsec =
			(long)((timeout_sec - (double)ts_storage.tv_sec) *
			       1000000000.0);
		timeout = &ts_storage;
	}

	Py_BEGIN_ALLOW_THREADS;
	ret = nds_io_getevents(ctx, min_nr, nr, events, timeout);
	Py_END_ALLOW_THREADS;

	if (ret < 0) {
		free(events);
		return PyLong_FromLong(ret);
	}

	list = PyList_New(ret);
	if (!list) {
		free(events);
		return NULL;
	}
	for (i = 0; i < ret; i++) {
		PyObject *tup;

		tup = Py_BuildValue("(KL)",
				    (unsigned long long)events[i].user_data,
				    (long long)events[i].res);
		if (!tup) {
			Py_DECREF(list);
			free(events);
			return NULL;
		}
		PyList_SET_ITEM(list, i, tup);
	}
	free(events);
	return list;
}

static PyMethodDef NdsMethods[] = {
	{ "init", py_nds_init, METH_VARARGS,
	  "init([flags=0]) -> int\n" },
	{ "exit", py_nds_exit, METH_NOARGS,
	  "exit() -> int\n" },
	{ "register_fs", py_nds_register_fs, METH_VARARGS,
	  "register_fs(fs_fds) -> int\n"
	  "fs_fds: file/block fds identifying topologies to add\n" },
	{ "unregister_fs", py_nds_unregister_fs, METH_VARARGS,
	  "unregister_fs(fs_fds) -> int\n"
	  "Currently a no-op; topologies remain until exit().\n" },
	{ "register_mem", py_nds_register_mem, METH_VARARGS,
	  "register_mem(addr, size[, flags=0]) -> int\n" },
	{ "unregister_mem", py_nds_unregister_mem, METH_VARARGS,
	  "unregister_mem(addr, size[, flags=0]) -> int\n"
	  "size must match the registered range.\n" },
	{ "io_new_ctx", py_nds_io_new_ctx, METH_VARARGS,
	  "io_new_ctx(max_io_cnt[, flags=0]) -> ctx capsule | negative errno\n" },
	{ "io_destroy_ctx", py_nds_io_destroy_ctx, METH_VARARGS,
	  "io_destroy_ctx(ctx) -> int\n" },
	{ "_io_dup_fd_for_test", py_nds_io_dup_fd_for_test, METH_VARARGS,
	  "Internal test hook: duplicate the context fd.\n" },
	{ "io_submit", py_nds_io_submit, METH_VARARGS,
	  "io_submit(ctx, iocbs) -> int\n\n"
	  "iocb: (opcode, fd, offset, iov"
	  "[, rw_flags=0, host_pid=0, user_data=0])\n"
	  "iov: sequence of (buf_addr, buf_len)\n" },
	{ "io_getevents", py_nds_io_getevents, METH_VARARGS,
	  "io_getevents(ctx, min_nr, nr[, timeout_sec=-1]) -> list|int\n\n"
		  "On success returns [(user_data, res), ...].\n"
		  "On failure returns negative errno.\n"
		  "timeout_sec must be finite; < 0 waits forever and 0 is non-blocking.\n" },
	{ NULL, NULL, 0, NULL }
};

static struct PyModuleDef nds_module = {
	.m_base = PyModuleDef_HEAD_INIT,
	.m_name = "nds",
	.m_doc = "NDS GDS-aligned P2P API",
	.m_size = -1,
	.m_methods = NdsMethods,
};

PyMODINIT_FUNC PyInit_nds(void)
{
	PyObject *module;

	module = PyModule_Create(&nds_module);
	if (!module)
		return NULL;

	if (PyModule_AddIntConstant(module, "NDS_API_VERSION", NDS_API_VERSION) ||
	    PyModule_AddIntConstant(module, "NDS_IO_MAX_IO_CNT",
				    NDS_IO_MAX_IO_CNT) ||
	    PyModule_AddIntConstant(module, "NDS_IO_MAX_IOV", NDS_IO_MAX_IOV) ||
	    PyModule_AddIntConstant(module, "NDS_IO_OP_PREAD", NDS_IO_OP_PREAD) ||
	    PyModule_AddIntConstant(module, "NDS_IO_OP_PWRITE", NDS_IO_OP_PWRITE) ||
	    PyModule_AddIntConstant(module, "NDS_IO_F_REGISTERED_MEM",
				    NDS_IO_F_REGISTERED_MEM) ||
	    PyModule_AddIntConstant(module, "_IOCTL_DRAIN_IO",
				    IOCTL_DRAIN_IO)) {
		Py_DECREF(module);
		return NULL;
	}
	return module;
}

// SPDX-License-Identifier: GPL-2.0
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "file_p2p_api.h"

static int parse_iovs(PyObject *object, struct p2p_iov **iov_out,
		      unsigned int *iov_nr_out)
{
	struct p2p_iov *iov;
	PyObject *sequence;
	Py_ssize_t count;
	Py_ssize_t i;

	sequence = PySequence_Fast(object, "IOVs must be a sequence");
	if (!sequence)
		return -1;
	count = PySequence_Fast_GET_SIZE(sequence);
	if (count <= 0 || count > UINT_MAX ||
	    (size_t)count > SIZE_MAX / sizeof(*iov)) {
		PyErr_SetString(PyExc_ValueError,
				"IOVs must be a non-empty bounded sequence");
		Py_DECREF(sequence);
		return -1;
	}

	iov = calloc(count, sizeof(*iov));
	if (!iov) {
		PyErr_NoMemory();
		Py_DECREF(sequence);
		return -1;
	}

	for (i = 0; i < count; i++) {
		PyObject *entry;
		PyObject **items;
		unsigned long long addr;
		unsigned long long size;

		entry = PySequence_Fast(PySequence_Fast_GET_ITEM(sequence, i),
					"IOV must be (addr, size)");
		if (!entry)
			goto error;
		if (PySequence_Fast_GET_SIZE(entry) != 2) {
			PyErr_SetString(PyExc_ValueError,
					"IOV must be (addr, size)");
			Py_DECREF(entry);
			goto error;
		}
		items = PySequence_Fast_ITEMS(entry);
		addr = PyLong_AsUnsignedLongLong(items[0]);
		size = PyLong_AsUnsignedLongLong(items[1]);
		Py_DECREF(entry);
		if (PyErr_Occurred())
			goto error;
		if (size > UINT32_MAX) {
			PyErr_SetString(PyExc_ValueError,
					"IOV size exceeds the 32-bit UAPI limit");
			goto error;
		}
		iov[i].addr = addr;
		iov[i].size = (uint32_t)size;
		iov[i].reserved = 0;
	}

	Py_DECREF(sequence);
	*iov_out = iov;
	*iov_nr_out = count;
	return 0;

error:
	free(iov);
	Py_DECREF(sequence);
	return -1;
}

static PyObject *py_rw_file(PyObject *Py_UNUSED(self), PyObject *args)
{
	int dev_fd = 0;
	unsigned int op = 0;
	const char *file_name = NULL;
	unsigned long file_offset = 0;
	struct p2p_iov *iov = NULL;
	unsigned int iov_nr = 0;
	PyObject *py_iovs = NULL;
	long long mem_handle = 0;
	unsigned int flags = 0;
	int host_pid = 0;
	int ret = 0;

	if (!PyArg_ParseTuple(args, "iIskOLI|i", &dev_fd, &op, &file_name, &file_offset,
			      &py_iovs, &mem_handle, &flags, &host_pid))
		return NULL;
	if (parse_iovs(py_iovs, &iov, &iov_nr))
		return NULL;

	struct io_parameter param = {
		.op = op,
		.host_pid = host_pid,
		.file_name = file_name,
		.file_offset = file_offset,
		.iov = iov,
		.iov_nr = iov_nr,
		.flags = flags,
		.mem_handle = (uint64_t)mem_handle,
	};

	Py_BEGIN_ALLOW_THREADS
	ret = rw_file(dev_fd, &param);
	Py_END_ALLOW_THREADS

	free(iov);
	return PyLong_FromLong((long)ret);
}

static PyObject *py_register_mem(PyObject *Py_UNUSED(self), PyObject *args)
{
	struct p2p_mem_register_param param = { };
	int dev_fd;
	int ret;

	if (!PyArg_ParseTuple(args, "iKK", &dev_fd, &param.addr, &param.size))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = register_mem(dev_fd, &param);
	Py_END_ALLOW_THREADS

	if (ret)
		Py_RETURN_NONE;
	return PyLong_FromLongLong((long long)param.mem_handle);
}

static PyObject *py_unregister_mem(PyObject *Py_UNUSED(self), PyObject *args)
{
	struct p2p_mem_unregister_param param = { };
	long long mem_handle;
	int dev_fd;
	int ret;

	if (!PyArg_ParseTuple(args, "iL", &dev_fd, &mem_handle))
		return NULL;
	param.mem_handle = (uint64_t)mem_handle;

	Py_BEGIN_ALLOW_THREADS
	ret = unregister_mem(dev_fd, &param);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)ret);
}

static PyObject *py_drain_io(PyObject *Py_UNUSED(self), PyObject *args)
{
	int dev_fd = 0;
	int ret = 0;

	if (!PyArg_ParseTuple(args, "i", &dev_fd)) {
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS
	ret = drain_io(dev_fd);
	Py_END_ALLOW_THREADS

	return PyLong_FromLong((long)ret);
}

static PyObject *py_new_p2p_fd(PyObject *Py_UNUSED(self),
			       PyObject *Py_UNUSED(ignored))
{
	int ret = new_p2p_fd();

	return PyLong_FromLong((long)ret);
}

static PyObject *py_add_topo(PyObject *Py_UNUSED(self), PyObject *args)
{
	const char *dev;
	int dev_fd;
	int ret;

	if (!PyArg_ParseTuple(args, "is", &dev_fd, &dev))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = add_topo(dev_fd, dev);
	Py_END_ALLOW_THREADS
	return PyLong_FromLong((long)ret);
}

static PyObject *py_close_p2p_fd(PyObject *Py_UNUSED(self), PyObject *args)
{
	int dev_fd = 0;

	if (!PyArg_ParseTuple(args, "i", &dev_fd)) {
		return NULL;
	}

	close_p2p_fd(dev_fd);

	Py_RETURN_NONE;
}

static PyMethodDef FileP2PMethods[] = {
	{ "rw_file", py_rw_file, METH_VARARGS,
	  "rw_file(dev_fd, op, file_name, file_offset, iovs, mem_handle, flags"
	  "[, host_pid]) -> int\n\n"
	  "Read from or write to a p2p I/O target.\n"
	  "\n"
	  "Parameters:\n"
	  "    dev_fd (int): File descriptor of p2p device.\n"
	  "    op (int): P2P_IO_READ or P2P_IO_WRITE.\n"
	  "    file_name (str): Name of the I/O target.\n"
	  "    file_offset (int): Starting file offset.\n"
	  "    iovs (sequence): Device-memory (address, size) pairs.\n"
	  "    mem_handle (int): Registered-memory handle, or zero.\n"
	  "    flags (int): P2P I/O flags.\n"
	  "    host_pid (int, optional): PID owning unregistered IOV addresses;\n"
	  "        zero or omitted selects the current process. Must be zero for\n"
	  "        registered memory.\n"
	  "\n"
	  "Returns:\n"
	  "    int: 0 on success, non-zero on error.\n" },
	{ "register_mem", py_register_mem, METH_VARARGS,
	  "register_mem(dev_fd, addr, size) -> int | None\n\n"
	  "Register a device-memory VA range and return its handle.\n"
	  "The handle may be negative. Returns None on failure.\n" },
	{ "unregister_mem", py_unregister_mem, METH_VARARGS,
	  "unregister_mem(dev_fd, mem_handle) -> int\n\n"
	  "Synchronously unregister a device-memory handle.\n" },
	{ "drain_io", py_drain_io, METH_VARARGS,
	  "drain_io(dev_fd) -> int\n\n"
	  "Drain I/O from p2p device.\n"
	  "\n"
	  "Parameters:\n"
	  "    dev_fd (int): File descriptor of p2p device.\n"
	  "\n"
	  "Returns:\n"
	  "    int: 0 on success, non-zero on error.\n" },
	{ "new_p2p_fd", py_new_p2p_fd, METH_NOARGS,
	  "new_p2p_fd() -> int\n\n"
	  "New p2p device file descriptor.\n"
	  "\n"
	  "Returns:\n"
	  "    int: File descriptor on success, negative errno on error.\n" },
	{ "add_topo", py_add_topo, METH_VARARGS,
	  "add_topo(dev_fd, dev) -> int\n\n"
	  "Discover and register the required block-device topology.\n"
	  "Returns 0 on success or a negative errno.\n" },
	{ "close_p2p_fd", py_close_p2p_fd, METH_VARARGS,
	  "close_p2p_fd(dev_fd) -> None\n\n"
	  "Close p2p device file descriptor.\n"
	  "\n"
	  "Parameters:\n"
	  "    dev_fd (int): File descriptor of p2p device.\n"
	  "\n"
	  "Returns:\n"
	  "    None\n" },
	{ NULL, NULL, 0, NULL }
};

static struct PyModuleDef file_p2p_module = {
	.m_base = PyModuleDef_HEAD_INIT,
	.m_name = "file_p2p",
	.m_doc = "p2p file access",
	.m_size = -1,
	.m_methods = FileP2PMethods,
};

PyMODINIT_FUNC PyInit_file_p2p(void)
{
	PyObject *module;

	module = PyModule_Create(&file_p2p_module);
	if (!module)
		return NULL;
	if (PyModule_AddIntConstant(module, "P2P_IO_F_REGISTERED_MEM",
				    P2P_IO_F_REGISTERED_MEM)) {
		Py_DECREF(module);
		return NULL;
	}
	if (PyModule_AddIntConstant(module, "P2P_IO_READ", P2P_IO_READ) ||
	    PyModule_AddIntConstant(module, "P2P_IO_WRITE", P2P_IO_WRITE)) {
		Py_DECREF(module);
		return NULL;
	}
	return module;
}

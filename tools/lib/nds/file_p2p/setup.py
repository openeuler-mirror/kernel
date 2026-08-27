from setuptools import setup, Extension

file_p2p_module = Extension(
    "file_p2p",
    sources=["file_p2p_api.c", "py_file_p2p_api.c", "p2p_common.c"],
    depends=["file_p2p_api.h", "p2p_dev_uapi.h", "p2p_common.h"],
    extra_compile_args=["-Wall", "-Wextra"],
)

nds_module = Extension(
    "nds",
    sources=["nds_api.c", "py_nds_api.c", "p2p_common.c"],
    depends=["nds_api.h", "nds_api_internal.h", "p2p_dev_uapi.h", "p2p_common.h"],
    extra_compile_args=["-Wall", "-Wextra", "-pthread"],
    extra_link_args=["-pthread"],
)

setup(
    name="file_p2p",
    version="1.0",
    ext_modules=[file_p2p_module, nds_module],
)

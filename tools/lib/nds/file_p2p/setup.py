from setuptools import setup, Extension

UAPI_DIR = "../../../include/uapi"
UAPI_HDR = UAPI_DIR + "/linux/nds_p2p.h"

file_p2p_module = Extension(
    "file_p2p",
    sources=["file_p2p_api.c", "py_file_p2p_api.c", "p2p_common.c"],
    include_dirs=[UAPI_DIR],
    depends=["file_p2p_api.h", UAPI_HDR, "p2p_common.h"],
    extra_compile_args=["-Wall", "-Wextra"],
)

nds_module = Extension(
    "nds",
    sources=["nds_api.c", "py_nds_api.c", "p2p_common.c"],
    include_dirs=[UAPI_DIR],
    depends=["nds_api.h", "nds_api_internal.h", UAPI_HDR, "p2p_common.h"],
    extra_compile_args=["-Wall", "-Wextra", "-pthread"],
    extra_link_args=["-pthread"],
)

setup(
    name="file_p2p",
    version="1.0",
    ext_modules=[file_p2p_module, nds_module],
)

AC_PREREQ([2.69])
AC_INIT([warpdrive], [0.1], [liguozhu@hisilicon.com])
AC_CONFIG_SRCDIR([wd.c])
AM_INIT_AUTOMAKE([1.10 no-define])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

AM_PROG_AR
AC_PROG_LIBTOOL
AM_PROG_LIBTOOL
LT_INIT
AM_PROG_CC_C_O

AC_DEFINE([HAVE_SVA], [0], [enable SVA support])
AC_ARG_ENABLE([sva],
	      [ --enable-sva 	enable to support sva feature],
	      AC_DEFINE([HAVE_SVA], [1]))
AC_DEFINE([HAVE_DYNDRV], [0], [enable dynamicaly driver load support])
AC_ARG_ENABLE([dyndrv],
	      [ --enable-dyndrv 	enable to support dynamically load driver library],
	      AC_DEFINE([HAVE_DYNDRV], [1]))
AM_CONDITIONAL([DYNDRV], [test "x$enable_dyndrv" = "xyes"])
AC_DEFINE([HAVE_NUMA], [0], [enable NUMA support])
AC_ARG_ENABLE([numa],
	      [ --enable-numa 	enable to support numa system],
	      AC_DEFINE([HAVE_NUMA], [1]))

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h sys/ioctl.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
#Remove this at first for rpl_malloc error!
#AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([memset munmap])

AC_CONFIG_FILES([Makefile
                 test/Makefile])
AC_OUTPUT

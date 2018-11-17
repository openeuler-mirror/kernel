ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = foreign subdir-objects
AM_CFLAGS=-Wall -O0 -fno-strict-aliasing

if DYNDRV
lib_LTLIBRARIES=libwd.la libhisi_zip.la libhisi_hpre.la
libwd_la_SOURCES=wd.c wd_adapter.c wd_util.c wd_comp.c wd_rsa.c wd_dh.c
libhisi_zip_la_SOURCES=drv/hisi_zip_udrv.c
libhisi_hpre_la_SOURCES=drv/hisi_hpre_udrv.c
else
lib_LTLIBRARIES=libwd.la
libwd_la_SOURCES=wd.c wd_adapter.c wd_util.c wd_comp.c wd_rsa.c wd_dh.c drv/hisi_zip_udrv.c drv/hisi_hpre_udrv.c
endif
SUBDIRS=. test

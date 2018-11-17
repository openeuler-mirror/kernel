AM_CFLAGS=-Wall -O0 -fno-strict-aliasing -ldl -lpthread

bin_PROGRAMS=test_hisi_zip test_hisi_hpre

test_hisi_zip_SOURCES=test_hisi_zip.c
test_hisi_hpre_SOURCES=test_hisi_hpre.c

test_hisi_zip_LDADD=../.libs/libwd.so
test_hisi_hpre_LDADD=../.libs/libwd.so ./libcrypto.so

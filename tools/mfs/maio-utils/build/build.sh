#!/bin/bash

LOCAL_PATH="$(readlink -e "$(dirname "$0")")"
PRJ_PATH="$(readlink -e "${LOCAL_PATH}/..")"
THIRD_SUB="${PRJ_PATH}/thirdparty"
Lib_PATH="${PRJ_PATH}/lib"

ARCH=$(uname -m)

function build_zlog() {
	local zlog_dir=${THIRD_SUB}/zlog
	local build_path=${zlog_dir}/build
	mkdir ${build_path}
	mkdir -p ${Lib_PATH}/zlog
	cd ${zlog_dir}
	make PREFIX=`pwd`/build/zlog
	make PREFIX=`pwd`/build/zlog install
	cp -rdp ${build_path}/zlog/include ${Lib_PATH}/zlog
	cp -rdp ${build_path}/zlog/lib ${Lib_PATH}/zlog
	cd -
}

function build_securec() {
	local securec_dir=${THIRD_SUB}/securec
	local securec_lib=${securec_dir}/build/securec/lib
	mkdir -p ${securec_lib}
	mkdir -p ${Lib_PATH}/securec
	cd ${securec_dir}
	if [ "${ARCH}" = "aarch64" ]; then
		make -f aarch64-so.mk
	else
		make -f x86-so.mk
	fi
	cp -rdp include build/securec
	cp libsecurec.so build/securec/lib
	cp -rdp build/securec/include ${Lib_PATH}/securec
	cp -rdp build/securec/lib ${Lib_PATH}/securec
	cd -
}

function build_libnuma() {
	local libnuma_dir=${THIRD_SUB}/libnuma
	local build_path=${libnuma_dir}/build
	mkdir ${build_path}
	mkdir -p ${Lib_PATH}/libnuma
	cd ${libnuma_dir}
	./autogen.sh
	./configure --prefix=`pwd`/build
	make -j4
	make install
	cp -rdp build/include ${Lib_PATH}/libnuma
	cp -rdp build/lib ${Lib_PATH}/libnuma
	cd -
}

function prepare_thirdparty() {
	build_jsoncpp
	build_zlog
	build_securec
	build_libnuma
}

function build_program() {
	local BUILD_TYPE=$1

	set -x
	if [ "${BUILD_TYPE}" == "release" ]; then
		cmake .. -DCMAKE_BUILD_TYPE=Release
	else
		cmake .. -DCMAKE_BUILD_TYPE=Debug
	fi
	set +x

	make clean
	make VERBOSE=1 -j
}

function main() {
	local ACTION="$1"
	local PARAMETER="$2"

	if [ "${ACTION}" == "prepare" ]; then
		prepare_thirdparty
	fi
	if [ "$ACTION" == "build" ]; then
		build_program $PARAMETER
	fi
}

main $@
exit $?

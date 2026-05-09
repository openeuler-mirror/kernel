#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
msg()
{
	echo -e $1
}

exit_builtin_auxiliary_enabled() { exit 0; }
exit_kconfig_invalid() { exit 1; }
exit_need_oot_auxiliary() { exit 2; }
exit_not_found_failure() { exit 3; }

find_aux_bus_inc()
{
	aux_bus_inc=$(find -L ${ksrc} -name "auxiliary_bus.h")
	msg "auxiliary_bus.h location: ${aux_bus_inc}"
}

LINUX_INCLUDE_DIR="include/linux"

find_config_file()
{
	file_locations=(${ksrc}/include/generated/autoconf.h \
			${ksrc}/include/linux/autoconf.h \
			/boot/bmlinux.autoconf.h)

	for file in "${file_locations[@]}"; do
		if [ -f ${file} ]; then
			kconfig=${file}
			break
		fi
	done

	if [ -z ${kconfig} ]; then
		msg "Kernel config file not found at any of the expected locations."
	fi
}

get_config_auxiliary_bus()
{
	# CONFIG_AUXILIARY_BUS=0 corresponds to CONFIG_AUXILIARY_BUS=n
	# CONFIG_AUXILIARY_BUS=1 corresponds to CONFIG_AUXILIARY_BUS=y
	# CONFIG_AUXILIARY_BUS= corresponds to CONFIG_AUXILIARY_BUS not available in the kernel
	CONFIG_AUXILIARY_BUS=$(grep CONFIG_AUXILIARY_BUS ${kconfig} | awk -F" " '{print $3}')
	msg "CONFIG_AUXILIARY_BUS=${CONFIG_AUXILIARY_BUS}"
}

ksrc=""
verbose=0

options=$(getopt -o "k:vh" --long ksrc:,verbose,help -- "$@")
eval set -- "$options"
while :; do
	case $1 in
	-k|--ksrc) ksrc=$2; shift;;
	-v|--verbose) verbose=1 ;;
	-h|--help) usage && exit 0;;
	--) shift; break;;
	 esac
	 shift
done

if [ $verbose == 1 ]; then
	set -x
fi

set -x
find_config_file

if [ ! -z $kconfig ]; then
	# if we found the kernel .config file then exit the script based on various
	# conditions that depend on the CONFIG_AUXILIARY_BUS string being found
	get_config_auxiliary_bus

	if [ -z "$CONFIG_AUXILIARY_BUS" ]; then
		msg "CONFIG_AUXILIARY_BUS not found in ${kconfig}."
		# CONFIG_AUXILIARY_BUS string was not found, so OOT auxiliary is needed
		exit_need_oot_auxiliary
	elif [ "$CONFIG_AUXILIARY_BUS" = "1" ]; then
		msg "CONFIG_AUXILIARY_BUS=y in ${kconfig}."
		# CONFIG_AUXILIARY_BUS=y, so OOT auxiliary is not needed
		exit_builtin_auxiliary_enabled
	else
		msg ""
		msg "kernel $build_kernel supports auxiliary bus, but CONFIG_AUXILIARY_BUS"
		msg "is not set in ${kconfig}. Rebuild your kernel with"
		msg "CONFIG_AUXILIARY_BUS=y"
		msg ""
		# CONFIG_AUXILIARY_BUS is not "=y", but the string was found, so report
		# the failure so it can be used to fail build/install
		exit_kconfig_invalid
	fi
else
	if [ ! -d "${ksrc}/${LINUX_INCLUDE_DIR}" ] && \
	   [ ! -d "${ksrc}/source/${LINUX_INCLUDE_DIR}" ]; then
		echo "${ksrc}/${LINUX_INCLUDE_DIR} and " \
		     "${ksrc}/source/${LINUX_INCLUDE_DIR} do not exist"
		exit_not_found_failure
	fi

	# We didn't find a kernel .config file, so check to see if auxiliary_bus.h
	# is found in the kernel source include directory
	find_aux_bus_inc

	if [ -f "$aux_bus_inc" ]; then
		# AUXILIARY_MODULE_PREFIX is defined only in out-of-tree auxiliary bus
		if [ $(grep -c AUXILIARY_MODULE_PREFIX $aux_bus_inc) -eq 0 ]; then
			msg "in-tree auxiliary_bus.h found at ${ksrc}/${LINUX_INCLUDE_DIR}"
			# If auxiliary_bus.h is included at ${ksrc} and it isn't our OOT version,
			# then don't build OOT auxiliary as part of the driver makefile
			exit_builtin_auxiliary_enabled
		else
			msg "OOT auxiliary_bus.h found at ${ksrc}/${LINUX_INCLUDE_DIR}"
			# If auxiliary bus is included at ${ksrc} and it is our OOT version, then
			# build OOT auxiliary as part of the driver makefile
			exit_need_oot_auxiliary
		fi
	else
		msg "auxiliary_bus.h not found at ${ksrc}/${LINUX_INCLUDE_DIR}"
		exit_need_oot_auxiliary
	fi
fi

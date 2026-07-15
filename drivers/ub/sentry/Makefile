# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the sentry drivers.

obj-$(CONFIG_UB_SENTRY) += sentry_msg_helper.o
obj-$(CONFIG_UB_SENTRY) += sentry_reporter.o
obj-$(CONFIG_UB_SENTRY_REMOTE) += sentry_urma_comm.o
obj-$(CONFIG_UB_SENTRY_REMOTE) += sentry_uvb_comm.o
obj-$(CONFIG_UB_SENTRY_REMOTE) += sentry_remote_reporter.o

sentry_msg_helper-y := smh_core.o smh_message.o
sentry_reporter-y := sentry_local_reporter.o oom_rate_limit.o
sentry_remote_reporter-y := sentry_remote_server.o sentry_remote_client.o

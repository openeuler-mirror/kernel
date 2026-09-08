// SPDX-License-Identifier: GPL-2.0
/*
 * HiSilicon PCIe Trace and Tuning (PTT) support
 * Copyright (c) 2022 HiSilicon Technologies Co., Ltd.
 */

#include <byteswap.h>
#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/bitops.h>
#include <linux/kernel.h>
#include <linux/log2.h>
#include <linux/types.h>
#include <asm-generic/unaligned.h>
#include <linux/zalloc.h>
#include <stdlib.h>
#include <unistd.h>

#include "auxtrace.h"
#include "color.h"
#include "debug.h"
#include "evsel.h"
#include "hisi-ptt.h"
#include "hisi-ptt-decoder/hisi-ptt-pkt-decoder.h"
#include "machine.h"
#include "session.h"
#include "tool.h"
#include <internal/lib.h>

struct hisi_ptt {
	struct auxtrace auxtrace;
	u32 auxtrace_type;
	struct perf_session *session;
	struct machine *machine;
	u32 pmu_type;
	u32 pattern;
};

static int hisi_ptt_pkt_size[] = {
	[HISI_PTT_4DW_PKT]	= 16,
	[HISI_PTT_8DW_PKT]	= 32,
};

static enum hisi_ptt_pkt_type hisi_ptt_check_packet_type(unsigned char *buf,
							 size_t len)
{
	uint32_t head;

	if (len < HISI_PTT_FIELD_LENGTH)
		return HISI_PTT_4DW_PKT;

	head = get_unaligned_le32(buf);

	if ((HISI_PTT_8DW_CHECK_MASK & head) == HISI_PTT_IS_8DW_PKT)
		return HISI_PTT_8DW_PKT;

	return HISI_PTT_4DW_PKT;
}

static void hisi_ptt_dump(struct hisi_ptt *ptt, unsigned char *buf, size_t len)
{
	const char *color = PERF_COLOR_BLUE;
	struct hisi_ptt_pkt_buf pkt_buf;

	pkt_buf.buf = buf;
	pkt_buf.pos = 0;
	pkt_buf.pkt_type = hisi_ptt_check_packet_type(buf, len);
	pkt_buf.len = round_down(len, hisi_ptt_pkt_size[pkt_buf.pkt_type]);
	pkt_buf.pkt_msg_type = HISI_PTT_PKT_TYPE_UNKNOWN;
	pkt_buf.pattern = (size_t)ptt->pattern;
	color_fprintf(stdout, color, ". ... HISI PTT data: size %zu bytes, pattern %zu\n",
		      pkt_buf.len, pkt_buf.pattern);

	while (pkt_buf.pos < pkt_buf.len) {
		if (!hisi_ptt_pkt_desc(&pkt_buf))
			color_fprintf(stdout, color, " Bad packet!\n");
	}
}

static void hisi_ptt_dump_event(struct hisi_ptt *ptt, unsigned char *buf,
				size_t len)
{
	printf(".\n");

	hisi_ptt_dump(ptt, buf, len);
}

static int hisi_ptt_process_event(struct perf_session *session __maybe_unused,
				  union perf_event *event __maybe_unused,
				  struct perf_sample *sample __maybe_unused,
				  struct perf_tool *tool __maybe_unused)
{
	return 0;
}

static int hisi_ptt_process_auxtrace_event(struct perf_session *session,
					   union perf_event *event,
					   struct perf_tool *tool __maybe_unused)
{
	struct hisi_ptt *ptt = container_of(session->auxtrace, struct hisi_ptt,
					    auxtrace);
	int fd = perf_data__fd(session->data);
	u64 size = event->auxtrace.size;
	off_t data_offset;
	ssize_t err;
	void *data;

	if (size > SSIZE_MAX)
		return -EINVAL;

	data = malloc(size);
	if (!data)
		return -errno;

	if (perf_data__is_pipe(session->data)) {
		data_offset = 0;
	} else {
		data_offset = lseek(fd, 0, SEEK_CUR);
		if (data_offset == -1) {
			free(data);
			return -errno;
		}
	}

	err = readn(fd, data, size);
	if (err != (ssize_t)size) {
		free(data);
		return -errno;
	}

	if (dump_trace)
		hisi_ptt_dump_event(ptt, data, size);

	free(data);
	return 0;
}

static int hisi_ptt_flush(struct perf_session *session __maybe_unused,
			  struct perf_tool *tool __maybe_unused)
{
	return 0;
}

static void hisi_ptt_free_events(struct perf_session *session __maybe_unused)
{
}

static void hisi_ptt_free(struct perf_session *session)
{
	struct hisi_ptt *ptt = container_of(session->auxtrace, struct hisi_ptt,
					    auxtrace);

	session->auxtrace = NULL;
	free(ptt);
}

static bool hisi_ptt_evsel_is_auxtrace(struct perf_session *session,
				       struct evsel *evsel)
{
	struct hisi_ptt *ptt = container_of(session->auxtrace, struct hisi_ptt, auxtrace);

	return evsel->core.attr.type == ptt->pmu_type;
}

static void hisi_ptt_print_info(u32 type, u32 pattern)
{
	if (!dump_trace)
		return;

	fprintf(stdout, "  PMU Type           %" PRIu32 "\n", type);
	fprintf(stdout, "  Data Pattern       %" PRIu32 "\n", pattern);
}

int hisi_ptt_process_auxtrace_info(union perf_event *event,
				   struct perf_session *session)
{
	struct perf_record_auxtrace_info *auxtrace_info = &event->auxtrace_info;
	struct hisi_ptt *ptt;
	size_t priv_size;

	if (auxtrace_info->header.size < HISI_PTT_AUXTRACE_PRIV_SIZE_LEGACY +
				sizeof(struct perf_record_auxtrace_info))
		return -EINVAL;
	priv_size = auxtrace_info->header.size -
		    sizeof(struct perf_record_auxtrace_info);

	ptt = zalloc(sizeof(*ptt));
	if (!ptt)
		return -ENOMEM;

	ptt->session = session;
	ptt->machine = &session->machines.host; /* No kvm support */
	ptt->auxtrace_type = auxtrace_info->type;
	ptt->pmu_type = auxtrace_info->priv[0];
	ptt->pattern = priv_size >= HISI_PTT_AUXTRACE_PRIV_SIZE_V1 ?
		       (u32)auxtrace_info->priv[1] : HISI_PTT_PATTERN_LEGACY;

	ptt->auxtrace.process_event = hisi_ptt_process_event;
	ptt->auxtrace.process_auxtrace_event = hisi_ptt_process_auxtrace_event;
	ptt->auxtrace.flush_events = hisi_ptt_flush;
	ptt->auxtrace.free_events = hisi_ptt_free_events;
	ptt->auxtrace.free = hisi_ptt_free;
	ptt->auxtrace.evsel_is_auxtrace = hisi_ptt_evsel_is_auxtrace;
	session->auxtrace = &ptt->auxtrace;

	hisi_ptt_print_info(ptt->pmu_type, ptt->pattern);

	return 0;
}

// SPDX-License-Identifier: GPL-2.0
#include "tests.h"
#include <stdio.h>
#include "cpumap.h"
#include "event.h"
#include "util/synthetic-events.h"
#include <string.h>
#include <linux/bitops.h>
#include <perf/cpumap.h>
#include "debug.h"

struct machine;

static int process_event_mask(struct perf_tool *tool __maybe_unused,
			 union perf_event *event,
			 struct perf_sample *sample __maybe_unused,
			 struct machine *machine __maybe_unused)
{
	struct perf_record_cpu_map *map_event = &event->cpu_map;
	struct perf_record_record_cpu_map *mask;
	struct perf_record_cpu_map_data *data;
	struct perf_cpu_map *map;
	int i;

	data = &map_event->data;

	TEST_ASSERT_VAL("wrong type", data->type == PERF_CPU_MAP__MASK);

	mask = (struct perf_record_record_cpu_map *)data->data;

	TEST_ASSERT_VAL("wrong nr",   mask->nr == 1);

	for (i = 0; i < 20; i++) {
		TEST_ASSERT_VAL("wrong cpu", test_bit(i, mask->mask));
	}

	map = cpu_map__new_data(data);
	TEST_ASSERT_VAL("wrong nr",  map->nr == 20);

	for (i = 0; i < 20; i++) {
		TEST_ASSERT_VAL("wrong cpu", map->map[i].cpu == i);
	}

	perf_cpu_map__put(map);
	return 0;
}

static int process_event_cpus(struct perf_tool *tool __maybe_unused,
			 union perf_event *event,
			 struct perf_sample *sample __maybe_unused,
			 struct machine *machine __maybe_unused)
{
	struct perf_record_cpu_map *map_event = &event->cpu_map;
	struct cpu_map_entries *cpus;
	struct perf_record_cpu_map_data *data;
	struct perf_cpu_map *map;

	data = &map_event->data;

	TEST_ASSERT_VAL("wrong type", data->type == PERF_CPU_MAP__CPUS);

	cpus = (struct cpu_map_entries *)data->data;

	TEST_ASSERT_VAL("wrong nr",   cpus->nr == 2);
	TEST_ASSERT_VAL("wrong cpu",  cpus->cpu[0] == 1);
	TEST_ASSERT_VAL("wrong cpu",  cpus->cpu[1] == 256);

	map = cpu_map__new_data(data);
	TEST_ASSERT_VAL("wrong nr",  map->nr == 2);
	TEST_ASSERT_VAL("wrong cpu", map->map[0].cpu == 1);
	TEST_ASSERT_VAL("wrong cpu", map->map[1].cpu == 256);
	TEST_ASSERT_VAL("wrong refcnt", refcount_read(&map->refcnt) == 1);
	perf_cpu_map__put(map);
	return 0;
}


int test__cpu_map_synthesize(struct test *test __maybe_unused, int subtest __maybe_unused)
{
	struct perf_cpu_map *cpus;

	/* This one is better stores in mask. */
	cpus = perf_cpu_map__new("0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19");

	TEST_ASSERT_VAL("failed to synthesize map",
		!perf_event__synthesize_cpu_map(NULL, cpus, process_event_mask, NULL));

	perf_cpu_map__put(cpus);

	/* This one is better stores in cpu values. */
	cpus = perf_cpu_map__new("1,256");

	TEST_ASSERT_VAL("failed to synthesize map",
		!perf_event__synthesize_cpu_map(NULL, cpus, process_event_cpus, NULL));

	perf_cpu_map__put(cpus);
	return 0;
}

static int cpu_map_print(const char *str)
{
	struct perf_cpu_map *map = perf_cpu_map__new(str);
	char buf[100];

	if (!map)
		return -1;

	cpu_map__snprint(map, buf, sizeof(buf));
	return !strcmp(buf, str);
}

int test__cpu_map_print(struct test *test __maybe_unused, int subtest __maybe_unused)
{
	TEST_ASSERT_VAL("failed to convert map", cpu_map_print("1"));
	TEST_ASSERT_VAL("failed to convert map", cpu_map_print("1,5"));
	TEST_ASSERT_VAL("failed to convert map", cpu_map_print("1,3,5,7,9,11,13,15,17,19,21-40"));
	TEST_ASSERT_VAL("failed to convert map", cpu_map_print("2-5"));
	TEST_ASSERT_VAL("failed to convert map", cpu_map_print("1,3-6,8-10,24,35-37"));
	TEST_ASSERT_VAL("failed to convert map", cpu_map_print("1,3-6,8-10,24,35-37"));
	TEST_ASSERT_VAL("failed to convert map", cpu_map_print("1-10,12-20,22-30,32-40"));
	return 0;
}

int test__cpu_map_merge(struct test *test __maybe_unused, int subtest __maybe_unused)
{
	struct perf_cpu_map *a = perf_cpu_map__new("4,2,1");
	struct perf_cpu_map *b = perf_cpu_map__new("4,5,7");
	struct perf_cpu_map *c = perf_cpu_map__merge(a, b);
	char buf[100];

	TEST_ASSERT_VAL("failed to merge map: bad nr", c->nr == 5);
	cpu_map__snprint(c, buf, sizeof(buf));
	TEST_ASSERT_VAL("failed to merge map: bad result", !strcmp(buf, "1-2,4-5,7"));
	perf_cpu_map__put(b);
	perf_cpu_map__put(c);
	return 0;
}

static int __test__cpu_map_intersect(const char *lhs, const char *rhs, int nr, const char *expected)
{
	struct perf_cpu_map *a = perf_cpu_map__new(lhs);
	struct perf_cpu_map *b = perf_cpu_map__new(rhs);
	struct perf_cpu_map *c = perf_cpu_map__intersect(a, b);
	char buf[100];

	TEST_ASSERT_EQUAL("failed to intersect map: bad nr", perf_cpu_map__nr(c), nr);
	cpu_map__snprint(c, buf, sizeof(buf));
	TEST_ASSERT_VAL("failed to intersect map: bad result", !strcmp(buf, expected));
	perf_cpu_map__put(a);
	perf_cpu_map__put(b);
	perf_cpu_map__put(c);
	return 0;
}

static int test__cpu_map_intersect(struct test_suite *test __maybe_unused,
				   int subtest __maybe_unused)
{
	int ret;

	ret = __test__cpu_map_intersect("4,2,1", "4,5,7", 1, "4");
	if (ret)
		return ret;
	ret = __test__cpu_map_intersect("1-8", "6-9", 3, "6-8");
	if (ret)
		return ret;
	ret = __test__cpu_map_intersect("1-8,12-20", "6-9,15", 4, "6-8,15");
	if (ret)
		return ret;
	ret = __test__cpu_map_intersect("4,2,1", "1", 1, "1");
	if (ret)
		return ret;
	ret = __test__cpu_map_intersect("1", "4,2,1", 1, "1");
	if (ret)
		return ret;
	ret = __test__cpu_map_intersect("1", "1", 1, "1");
	return ret;
}

DEFINE_SUITE("Synthesize cpu map", cpu_map_synthesize);
DEFINE_SUITE("Print cpu map", cpu_map_print);
DEFINE_SUITE("Merge cpu map", cpu_map_merge);
DEFINE_SUITE("Intersect cpu map", cpu_map_intersect);

// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/kernel.h>
#include "linux/string.h"
#include "zxic_common.h"
#include "dpp_cmd_shell.h"

#ifndef whitespace
#define whitespace(c) (((c) == ' ') || ((c) == '\t'))
#endif

#define DPP_CMD_ARG_NUM_MAX (15)

u32 dpp_cmd_help(void)
{
	u32 i = 0;
	u32 list_index = 0;

	list_index = ARRAY_SIZE(dpp_commands);

	for (i = 0; i < list_index; i++)
		ZXIC_COMM_PRINT("%-40s | %s\n", dpp_commands[i].name, dpp_commands[i].doc);

	return DPP_OK;
}

u32 dpp_cmd_atoi(char *str)
{
	u32 n = 0;
	s32 rc = 0;

	if (!str)
		return 0x0;

	if ((str[0] == '0') && (str[1] == 'x'))
		rc = sscanf(str, "0x%x", &n);
	else if ((str[0] == '0') && (str[1] == 'X'))
		rc = sscanf(str, "0X%x", &n);
	else
		rc = kstrtouint(str, 10, &n);

	if (rc < 0)
		return 0;

	return n;
}

struct DPP_COMMAND *dpp_cmd_find(char *name)
{
	u32 i = 0;
	u32 list_index = 0;

	list_index = ARRAY_SIZE(dpp_commands);

	for (i = 0; i < list_index; i++) {
		if (strcmp(name, dpp_commands[i].name) == 0)
			return &dpp_commands[i];
	}

	return ((struct DPP_COMMAND *)NULL);
}

u32 dpp_cmd_strtok(char *str, char **arg_v, u32 *arg_num)
{
	char *p_tok = NULL;
	const char *delim = " ();\t";
	u32 i = 0;

	ZXIC_COMM_CHECK_POINT(str);
	ZXIC_COMM_CHECK_POINT(arg_v);
	ZXIC_COMM_CHECK_POINT(arg_num);

	ZXIC_COMM_MEMSET(arg_v, 0, DPP_CMD_ARG_NUM_MAX * sizeof(char *));

	p_tok = strsep(&str, delim);
	ZXIC_COMM_CHECK_POINT(p_tok);

	arg_v[0] = p_tok;

	i = 1;
	while (p_tok && (i < DPP_CMD_ARG_NUM_MAX)) {
		p_tok = strsep(&str, delim);
		if (!p_tok)
			break;
		arg_v[i++] = p_tok;
	}

	*arg_num = i;

	return DPP_OK;
}

char *dpp_cmd_trim(char *line)
{
	char *s;
	char *t;

	ZXIC_COMM_CHECK_POINT_RETURN_NULL(line);

	for (s = line; whitespace(*s); s++)
		;

	if (*s == 0)
		return s;

	t = s + strlen(s) - 1;
	while ((t > s) && whitespace(*t))
		t--;
	*++t = '\0';

	return s;
}

u32 dpp_cmd_exec(char *line)
{
	u32 i = 0;
	u32 rc = DPP_OK;
	u32 arg_num = 0;
	u32 len = 0;
	char *word = 0;
	char *arg_v[DPP_CMD_ARG_NUM_MAX] = { 0 };
	struct DPP_COMMAND *command = NULL;

	u32 (*func0)(void);
	u32 (*func1)(u32 a0);
	u32 (*func2)(u32 a0, u32 a1);
	u32 (*func3)(u32 a0, u32 a1, u32 a2);
	u32 (*func4)(u32 a0, u32 a1, u32 a2, u32 a3);
	u32 (*func5)(u32 a0, u32 a1, u32 a2, u32 a3, u32 a4);
	u32 (*func6)(u32 a0, u32 a1, u32 a2, u32 a3, u32 a4, u32 a5);
	u32 (*func7)(u32 a0, u32 a1, u32 a2, u32 a3, u32 a4, u32 a5, u32 a6);
	u32 (*func8)(u32 a0, u32 a1, u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7);
	u32 (*func9)(u32 a0, u32 a1, u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7, u32 a8);
	u32 (*func10)(u32 a0, u32 a1, u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7, u32 a8,
		      u32 a9);
	u32 (*func11)(u32 a0, u32 a1, u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7, u32 a8,
		      u32 a9, u32 a10);
	u32 (*func12)(u32 a0, u32 a1, u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7, u32 a8,
		      u32 a9, u32 a10, u32 a11);

	ZXIC_COMM_CHECK_POINT(line);

	len = ZXIC_COMM_STRLEN(line);
	if (len == 0) {
		ZXIC_COMM_PRINT("%s: len is 0.\n", __func__);
		return DPP_OK;
	}

	i = 0;
	while (line[i % (len + 1)] && whitespace(line[i % (len + 1)]))
		i++;
	word = line + i;

	while (line[i % (len + 1)] && !whitespace(line[i % (len + 1)]))
		i++;

	if (line[i % (len + 1)])
		line[i++] = '\0';

	command = dpp_cmd_find(word);
	ZXIC_COMM_CHECK_POINT(command);
	ZXIC_COMM_CHECK_POINT(command->func);

	while (whitespace(line[i % (len + 1)]))
		i++;

	word = line + i;

	rc = dpp_cmd_strtok(word, arg_v, &arg_num);
	ZXIC_COMM_CHECK_RC(rc, "dpp_cmd_strtok");
	ZXIC_COMM_CHECK_INDEX(arg_num, 0, DPP_CMD_ARG_NUM_MAX);

	switch (arg_num) {
	case 0: {
		func0 = command->func;
		((*(func0))());
		break;
	}
	case 1: {
		func1 = command->func;
		((*(func1))(dpp_cmd_atoi(arg_v[0])));
		break;
	}
	case 2: {
		func2 = command->func;
		((*(func2))(dpp_cmd_atoi(arg_v[0]), dpp_cmd_atoi(arg_v[1])));
		break;
	}
	case 3: {
		func3 = command->func;
		((*(func3))(dpp_cmd_atoi(arg_v[0]), dpp_cmd_atoi(arg_v[1]),
			    dpp_cmd_atoi(arg_v[2])));
		break;
	}
	case 4: {
		func4 = command->func;
		((*(func4))(dpp_cmd_atoi(arg_v[0]), dpp_cmd_atoi(arg_v[1]), dpp_cmd_atoi(arg_v[2]),
			    dpp_cmd_atoi(arg_v[3])));
		break;
	}
	case 5: {
		func5 = command->func;
		((*(func5))(dpp_cmd_atoi(arg_v[0]), dpp_cmd_atoi(arg_v[1]), dpp_cmd_atoi(arg_v[2]),
			    dpp_cmd_atoi(arg_v[3]), dpp_cmd_atoi(arg_v[4])));
		break;
	}
	case 6: {
		func6 = command->func;
		((*(func6))(dpp_cmd_atoi(arg_v[0]), dpp_cmd_atoi(arg_v[1]), dpp_cmd_atoi(arg_v[2]),
			    dpp_cmd_atoi(arg_v[3]), dpp_cmd_atoi(arg_v[4]),
			    dpp_cmd_atoi(arg_v[5])));
		break;
	}
	case 7: {
		func7 = command->func;
		((*(func7))(dpp_cmd_atoi(arg_v[0]), dpp_cmd_atoi(arg_v[1]), dpp_cmd_atoi(arg_v[2]),
			    dpp_cmd_atoi(arg_v[3]), dpp_cmd_atoi(arg_v[4]), dpp_cmd_atoi(arg_v[5]),
			    dpp_cmd_atoi(arg_v[6])));
		break;
	}
	case 8: {
		func8 = command->func;
		((*(func8))(dpp_cmd_atoi(arg_v[0]), dpp_cmd_atoi(arg_v[1]), dpp_cmd_atoi(arg_v[2]),
			    dpp_cmd_atoi(arg_v[3]), dpp_cmd_atoi(arg_v[4]), dpp_cmd_atoi(arg_v[5]),
			    dpp_cmd_atoi(arg_v[6]), dpp_cmd_atoi(arg_v[7])));
		break;
	}
	case 9: {
		func9 = command->func;
		((*(func9))(dpp_cmd_atoi(arg_v[0]), dpp_cmd_atoi(arg_v[1]), dpp_cmd_atoi(arg_v[2]),
			    dpp_cmd_atoi(arg_v[3]), dpp_cmd_atoi(arg_v[4]), dpp_cmd_atoi(arg_v[5]),
			    dpp_cmd_atoi(arg_v[6]), dpp_cmd_atoi(arg_v[7]),
			    dpp_cmd_atoi(arg_v[8])));
		break;
	}
	case 10: {
		func10 = command->func;
		((*(func10))(dpp_cmd_atoi(arg_v[0]), dpp_cmd_atoi(arg_v[1]), dpp_cmd_atoi(arg_v[2]),
			     dpp_cmd_atoi(arg_v[3]), dpp_cmd_atoi(arg_v[4]), dpp_cmd_atoi(arg_v[5]),
			     dpp_cmd_atoi(arg_v[6]), dpp_cmd_atoi(arg_v[7]), dpp_cmd_atoi(arg_v[8]),
			     dpp_cmd_atoi(arg_v[9])));
		break;
	}
	case 11: {
		func11 = command->func;
		((*(func11))(dpp_cmd_atoi(arg_v[0]), dpp_cmd_atoi(arg_v[1]), dpp_cmd_atoi(arg_v[2]),
			     dpp_cmd_atoi(arg_v[3]), dpp_cmd_atoi(arg_v[4]), dpp_cmd_atoi(arg_v[5]),
			     dpp_cmd_atoi(arg_v[6]), dpp_cmd_atoi(arg_v[7]), dpp_cmd_atoi(arg_v[8]),
			     dpp_cmd_atoi(arg_v[9]), dpp_cmd_atoi(arg_v[10])));
		break;
	}
	case 12: {
		func12 = command->func;
		((*(func12))(dpp_cmd_atoi(arg_v[0]), dpp_cmd_atoi(arg_v[1]), dpp_cmd_atoi(arg_v[2]),
			     dpp_cmd_atoi(arg_v[3]), dpp_cmd_atoi(arg_v[4]), dpp_cmd_atoi(arg_v[5]),
			     dpp_cmd_atoi(arg_v[6]), dpp_cmd_atoi(arg_v[7]), dpp_cmd_atoi(arg_v[8]),
			     dpp_cmd_atoi(arg_v[9]), dpp_cmd_atoi(arg_v[10]),
			     dpp_cmd_atoi(arg_v[11])));
		break;
	}
	default: {
		ZXIC_COMM_PRINT("%s: err [arg_num:%d] oversize.\n", __func__, arg_num);
		break;
	}
	}

	return DPP_OK;
}

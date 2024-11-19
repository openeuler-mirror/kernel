{
	"precise: test 1",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_LD_MAP_FD(BPF_REG_6, 0),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_ST_MEM(BPF_DW, BPF_REG_FP, -8, 0),
	BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
	BPF_EXIT_INSN(),

	BPF_MOV64_REG(BPF_REG_9, BPF_REG_0),

	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
	BPF_EXIT_INSN(),

	BPF_MOV64_REG(BPF_REG_8, BPF_REG_0),

	BPF_ALU64_REG(BPF_SUB, BPF_REG_9, BPF_REG_8), /* map_value_ptr -= map_value_ptr */
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_9),
	BPF_JMP_IMM(BPF_JLT, BPF_REG_2, 8, 1),
	BPF_EXIT_INSN(),

	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 1), /* R2=inv(umin=1, umax=8) */
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_FP),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -8),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_TRACEPOINT,
	.fixup_map_array_48b = { 1 },
	.result = VERBOSE_ACCEPT,
	.errstr =
	"26: (85) call bpf_probe_read_kernel#113\
	last_idx 26 first_idx 20\
	regs=4 stack=0 before 25\
	regs=4 stack=0 before 24\
	regs=4 stack=0 before 23\
	regs=4 stack=0 before 22\
	regs=4 stack=0 before 20\
	parent didn't have regs=4 stack=0 marks\
	last_idx 19 first_idx 10\
	regs=4 stack=0 before 19\
	regs=200 stack=0 before 18\
	regs=300 stack=0 before 17\
	regs=201 stack=0 before 15\
	regs=201 stack=0 before 14\
	regs=200 stack=0 before 13\
	regs=200 stack=0 before 12\
	regs=200 stack=0 before 11\
	regs=200 stack=0 before 10\
	parent already had regs=0 stack=0 marks",
},
{
	"precise: test 2",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_LD_MAP_FD(BPF_REG_6, 0),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_ST_MEM(BPF_DW, BPF_REG_FP, -8, 0),
	BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
	BPF_EXIT_INSN(),

	BPF_MOV64_REG(BPF_REG_9, BPF_REG_0),

	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
	BPF_EXIT_INSN(),

	BPF_MOV64_REG(BPF_REG_8, BPF_REG_0),

	BPF_ALU64_REG(BPF_SUB, BPF_REG_9, BPF_REG_8), /* map_value_ptr -= map_value_ptr */
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_9),
	BPF_JMP_IMM(BPF_JLT, BPF_REG_2, 8, 1),
	BPF_EXIT_INSN(),

	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 1), /* R2=inv(umin=1, umax=8) */
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_FP),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -8),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_TRACEPOINT,
	.fixup_map_array_48b = { 1 },
	.result = VERBOSE_ACCEPT,
	.flags = BPF_F_TEST_STATE_FREQ,
	.errstr =
	"26: (85) call bpf_probe_read_kernel#113\
	last_idx 26 first_idx 22\
	regs=4 stack=0 before 25\
	regs=4 stack=0 before 24\
	regs=4 stack=0 before 23\
	regs=4 stack=0 before 22\
	parent didn't have regs=4 stack=0 marks\
	last_idx 20 first_idx 20\
	regs=4 stack=0 before 20\
	parent didn't have regs=4 stack=0 marks\
	last_idx 19 first_idx 17\
	regs=4 stack=0 before 19\
	regs=200 stack=0 before 18\
	regs=300 stack=0 before 17\
	parent already had regs=0 stack=0 marks",
},
{
	"precise: cross frame pruning",
	.insns = {
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_prandom_u32),
	BPF_MOV64_IMM(BPF_REG_8, 0),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
	BPF_MOV64_IMM(BPF_REG_8, 1),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_prandom_u32),
	BPF_MOV64_IMM(BPF_REG_9, 0),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
	BPF_MOV64_IMM(BPF_REG_9, 1),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 1, 0, 4),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 1, 1),
	BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_2, 0),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, 0),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_XDP,
	.flags = BPF_F_TEST_STATE_FREQ,
	.errstr = "!read_ok",
	.result = REJECT,
},
{
	"precise: ST zero to stack insn is supported",
	.insns = {
	BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_3, 123, 0),
	/* not a register spill, so we stop precision propagation for R4 here */
	BPF_ST_MEM(BPF_DW, BPF_REG_3, -8, 0),
	BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_10, -8),
	BPF_MOV64_IMM(BPF_REG_0, -1),
	BPF_JMP_REG(BPF_JGT, BPF_REG_4, BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_XDP,
	.flags = BPF_F_TEST_STATE_FREQ,
	.errstr = "5: (2d) if r4 > r0 goto pc+0\
	last_idx 5 first_idx 5\
	parent didn't have regs=10 stack=0 marks\
	last_idx 4 first_idx 2\
	regs=10 stack=0 before 4\
	regs=10 stack=0 before 3\
	last_idx 5 first_idx 5\
	parent didn't have regs=1 stack=0 marks\
	last_idx 4 first_idx 2\
	regs=1 stack=0 before 4",
	.result = VERBOSE_ACCEPT,
	.retval = -1,
},
{
	"precise: STX insn causing spi > allocated_stack",
	.insns = {
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_prandom_u32),
	/* make later reg spill more interesting by having somewhat known scalar */
	BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xff),
	BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_3, 123, 0),
	BPF_STX_MEM(BPF_DW, BPF_REG_3, BPF_REG_0, -8),
	BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_10, -8),
	BPF_MOV64_IMM(BPF_REG_0, -1),
	BPF_JMP_REG(BPF_JGT, BPF_REG_4, BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_XDP,
	.flags = BPF_F_TEST_STATE_FREQ,
	.errstr = "last_idx 7 first_idx 7\
	parent didn't have regs=10 stack=0 marks\
	last_idx 6 first_idx 4\
	regs=10 stack=0 before 6\
	regs=10 stack=0 before 5\
	regs=0 stack=1 before 4\
	parent didn't have regs=1 stack=0 marks\
	last_idx 3 first_idx 3\
	regs=1 stack=0 before 3\
	regs=1 stack=0 before 2\
	regs=1 stack=0 before 1\
	parent didn't have regs=1 stack=0 marks\
	last_idx 0 first_idx 0\
	regs=1 stack=0 before 0\
	last_idx 7 first_idx 7",
	.result = VERBOSE_ACCEPT,
	.retval = -1,
},

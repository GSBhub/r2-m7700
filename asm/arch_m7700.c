#include <string.h>
#include <r_arch.h>
#include <r_lib.h>

/*
 * RAsmOp was removed from the public API in r2 6.x.  Define a minimal shim
 * here so the internal m7700.c disassembler can compile without modification.
 * r_asm_op_set_asm is likewise no longer exported; provide a static version.
 */
typedef struct {
	int size;
	RStrBuf buf_asm;
} RAsmOp;

static inline void r_asm_op_set_asm(RAsmOp *op, const char *str) {
	r_strbuf_set(&op->buf_asm, str);
}

#include "./arch/m7700.c"

/* Classify a decoded mnemonic into an r2 op type and set jump/fail/ptr. */
static void m7700_classify_op(RAnalOp *op, const char *mnemonic) {
	/* Extract the bare mnemonic (first token, before any space or tab) */
	char mn[8] = {0};
	int i = 0;
	while (i < 7 && mnemonic[i] && mnemonic[i] != ' ' && mnemonic[i] != '\t') {
		mn[i] = mnemonic[i];
		i++;
	}

	/* Unconditional calls */
	if (!strcmp(mn, "JSR") || !strcmp(mn, "JSL")) {
		op->type = R_ANAL_OP_TYPE_CALL;
		/* Extract target address from mnemonic string (first hex token after mnemonic) */
		const char *p = mnemonic + i;
		while (*p == ' ' || *p == '\t') p++;
		if (*p) {
			op->jump = (ut64)strtoull(p, NULL, 0);
		}
		op->fail = op->addr + op->size;
		return;
	}
	/* Returns */
	if (!strcmp(mn, "RTS") || !strcmp(mn, "RTL") || !strcmp(mn, "RTI")) {
		op->type = R_ANAL_OP_TYPE_RET;
		return;
	}
	/* Unconditional jumps */
	if (!strcmp(mn, "JMP") || !strcmp(mn, "BRA") || !strcmp(mn, "BRL")) {
		op->type = R_ANAL_OP_TYPE_JMP;
		const char *p = mnemonic + i;
		while (*p == ' ' || *p == '\t') p++;
		if (*p) {
			op->jump = (ut64)strtoull(p, NULL, 0);
		}
		return;
	}
	/* Conditional branches */
	if (!strcmp(mn, "BEQ") || !strcmp(mn, "BNE") ||
	    !strcmp(mn, "BCC") || !strcmp(mn, "BCS") ||
	    !strcmp(mn, "BMI") || !strcmp(mn, "BPL") ||
	    !strcmp(mn, "BVC") || !strcmp(mn, "BVS") ||
	    !strcmp(mn, "BLT") || !strcmp(mn, "BGE") ||
	    !strcmp(mn, "BBC") || !strcmp(mn, "BBS")) {
		op->type = R_ANAL_OP_TYPE_CJMP;
		const char *p = mnemonic + i;
		while (*p == ' ' || *p == '\t') p++;
		if (*p) {
			op->jump = (ut64)strtoull(p, NULL, 0);
		}
		op->fail = op->addr + op->size;
		return;
	}
	/* Software interrupt / break */
	if (!strcmp(mn, "BRK") || !strcmp(mn, "COP")) {
		op->type = R_ANAL_OP_TYPE_SWI;
		return;
	}
	op->type = R_ANAL_OP_TYPE_MOV;
}

static bool m7700_decode(RArchSession *s, RAnalOp *op, RArchDecodeMask mask) {
	if (!op || !op->bytes) {
		return false;
	}

	/*
	 * m7700_disassemble still takes an RAsm* to read a->pc for branch
	 * target calculation.  Stack-allocate a zeroed RAsm and fill only pc;
	 * no other fields are touched by the disassembler.
	 */
	RAsm fake_a;
	memset(&fake_a, 0, sizeof(RAsm));
	fake_a.pc = op->addr;

	RAsmOp fake_op = {0};
	r_strbuf_init(&fake_op.buf_asm);
	fake_op.size = 1;

	int size = m7700_disassemble(&fake_a, &fake_op, op->bytes,
		op->size > 0 ? op->size : 64);
	op->size = (size > 0) ? size : 1;

	const char *dis = r_strbuf_get(&fake_op.buf_asm);
	m7700_classify_op(op, dis);

	if (mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = strdup(dis);
	}
	r_strbuf_fini(&fake_op.buf_asm);
	return size > 0;
}

static char *m7700_regs(RArchSession *s) {
	return strdup(
		"=SP	s\n"
		"=ZF	zf\n"
		"=CF	cf\n"
		"=SF	nf\n"
		"=OF	of\n"
		"=PC	pc\n"
		"=A0	a\n"
		"=A1	b\n"
		"=A2	x\n"
		"=A3	y\n"
		"gpr	pc	.16 8	0\n"
		"gpr	pch	.8  16	0\n"
		"gpr	pcl	.8  8	0\n"
		"gpr	pg	.8  0	0\n"
		"gpr	s	.16 24	0\n"
		"gpr	ax	.16 40	0\n"
		"gpr	al	.8  40	0\n"
		"gpr	bx	.16 56	0\n"
		"gpr	bl	.8  56	0\n"
		"gpr	x	.16  72	0\n"
		"gpr	xl	.8  72	0\n"
		"gpr	y	.16  88	0\n"
		"gpr	yl	.8  88	0\n"
		"gpr	db	.8	96	0\n"
		"gpr	dpr	.16	104	0\n"
		"gpr	ps	.8	120	0\n"
		"flg	cf	.1	127	0\n"
		"flg	zf	.1	126	0\n"
		"flg	id	.1	125	0\n"
		"flg	dm	.1	124	0\n"
		"flg	ix	.1	123	0\n"
		"flg	m	.1	122	0\n"
		"flg	of	.1	121	0\n"
		"flg	nf	.1	120	0\n"
		"gpr	ipr	.4	128	0\n"
	);
}

static RArchPlugin r_arch_plugin_m7700 = {
	.meta = {
		.name    = "m7700",
		.desc    = "Disassembly plugin for Mitsubishi M7700",
		.license = "None",
	},
	.arch   = "m7700",
	.bits   = R_SYS_BITS_PACK(16),
	.decode = m7700_decode,
	.regs   = m7700_regs,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type       = R_LIB_TYPE_ARCH,
	.data       = &r_arch_plugin_m7700,
	.version    = R2_VERSION,
	.abiversion = R2_ABIVERSION,
};
#endif

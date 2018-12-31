/*
	m7700 instructions

	m and x flags select between word, byte operations for each instruction
	This allows for some instructions to be 8 bit, and some to be 16 bit. 

	Each instruction also has an addressing mode that can fall into one of 28 different categories. 

	There are a grand total of 103 instructions for the base m7700, each has a few permutations for each of the
	addressing/bit length mode above.


 */
#define OPS 256  // total ops size for our structs

#define ut24 int // define ut24 int field, used for the multiple-param func calls - functionally same as the ut32 struct that comes with radare2, but this is a better name since we're just using the lower 3 bytes
#define byte unsigned char

// credit to http://www.alcyone.org.uk/ssm/m7700ds.c for the tables for params/ops

// string labels for each instruction

const char *instruction_set[] = {

	"ADC", "AND", "ASL", "BCC", "BCS", "BEQ", "BIT", "BMI", "BNE",  "BPL", "BRA",
	"BRK", "BRL", "BVC", "BVS", "CLC", "CLD", "CLI", "CLV", "CMP",  "COP", "CPX",
	"CPY", "DEA", "DEC", "DEX", "DEY", "EOR", "INA", "INC", "INX",  "INY", "JML",
	"JMP", "JSL", "JSR", "LDA", "LDX", "LDY", "LSR", "MVN", "MVP",  "NOP", "ORA",
	"PEA", "PEI", "PER", "PHA", "PHT", "PHD", "PHK", "PHP", "PHX",  "PHY", "PLA",
	"PLT", "PLD", "PLP", "PLX", "PLY", "CLP", "ROL", "ROR", "RTI",  "RTL", "RTS",
	"SBC", "SEC", "SED", "SEI", "SEP", "STA", "STP", "STX", "STY",  "STZ", "TAX",
	"TAY", "TAS", "TAD", "TDA", "TRB", "TSB", "TSA", "TSX", "TXA",  "TXS", "TXY",
	"TYA", "TYX", "WIT", "WDM", "XBA", "XCE", "MPY", "DIV", "MPYS", "DIVS", "RLA",
	"EXTS","EXTZ","LDT", "LDM", "UNK", "SEB", "SEM", "CLM", "STB",  "LDB", "ADCB",
	"SBCB","EORB","TBX", "CMPB","INB", "DEB", "TXB", "TYB", "LSRB", "ORB", "CLB",
	"BBC", "BBS", "TBY", "ANDB","PUL", "PSH", "PLB", "XAB", "PHB",  "TBS", "TBD",
	"TDB"
};

// enumeration of the above  
enum
{
	ADC, AND, ASL, BCC, BCS, BEQ, BIT, BMI, BNE, BPL, BRA,
	BRK, BRL, BVC, BVS, CLC, CLD, CLI, CLV, CMP, COP, CPX,
	CPY, DEA, DEC, DEX, DEY, EOR, INA, INC, INX, INY, JML,
	JMP, JSL, JSR, LDA, LDX, LDY, LSR, MVN, MVP, NOP, ORA,
	PEA, PEI, PER, PHA, PHT, PHD, PHK, PHP, PHX, PHY, PLA,
	PLB, PLD, PLP, PLX, PLY, CLP, ROL, ROR, RTI, RTL, RTS,
	SBC, SEC, SED, SEI, SEP, STA, STP, STX, STY, STZ, TAX,
	TAY, TAS, TAD, TDA, TRB, TSB, TSA, TSX, TXA, TXS, TXY,
	TYA, TYX, WIT, WDM, XBA, XCE, MPY, DIV, MPYS, DIVS, RLA,
	EXTS, EXTZ, LDT, LDM, UNK, SEB, SEM, CLM, STB, LDB, ADCB,
	SBCB, EORB, TBX, CMPB, INB, DEB, TXB, TYB, LSRB, ORB, CLB,
	BBC, BBS, TBY, ANDB, PUL, PSH, PLAB, XAB, PHB, TBS, TBD,
	TDB
};

// addressing mode bits
enum
{
	I, /* ignore */
	M, /* check m bit */
	X  /* check x bit */
};

// register label enum
enum
{
	IMP, ACC, RELB, RELW, IMM, A, AI, AL, ALX, AX, AXI,
	AY, D, DI, DIY, DLI, DLIY, DX, DXI, DY, S, SIY,
	SIG /*, MVN , MVP , PEA , PEI , PER */, LDM4, LDM5, LDM4X, LDM5X,
	BBCD, BBCA, ACCB
} reg;

// general layout of the opcodes
typedef struct {

	unsigned char op;
	unsigned char flag;
	unsigned char arg;

} OpCode;

// params for each instruction (all prefixes not described below)
static const OpCode ops[OPS] = {
	{ BRK, I, SIG },{ ORA, M, DXI },{ UNK, I, SIG },{ ORA, M, S },
{ SEB, M, LDM4 },{ ORA, M, D },{ ASL, M, D },{ ORA, M, DLI },
{ PHP, I, IMP },{ ORA, M, IMM },{ ASL, M, ACC },{ PHD, I, IMP },
{ SEB, M, LDM5 },{ ORA, M, A },{ ASL, M, A },{ ORA, M, AL },
// 0x10
{ BPL, I, RELB },{ ORA, M, DIY },{ ORA, M, DI },{ ORA, M, SIY },
{ CLB, M, LDM4 },{ ORA, M, DX },{ ASL, M, DX },{ ORA, M, DLIY },
{ CLC, I, IMP },{ ORA, M, AY },{ DEA, I, IMP },{ TAS, I, IMP },
{ CLB, M, LDM5 },{ ORA, M, AX },{ ASL, M, AX },{ ORA, M, ALX },
// 0x20
{ JSR, I, A },{ AND, M, DXI },{ JSL, I, AL },{ AND, M, S },
{ BBS, M, BBCD },{ AND, M, D },{ ROL, M, D },{ AND, M, DLI },
{ PLP, I, IMP },{ AND, M, IMM },{ ROL, M, ACC },{ PLD, I, IMP },
{ BBS, M, BBCA },{ AND, M, A },{ ROL, M, A },{ AND, M, AL },
// 0x30
{ BMI, I, RELB },{ AND, M, DIY },{ AND, M, DI },{ AND, M, SIY },
{ BBC, M, BBCD },{ AND, M, DX },{ ROL, M, DX },{ AND, M, DLIY },
{ SEC, I, IMP },{ AND, M, AY },{ INA, I, IMP },{ TSA, I, IMP },
{ BBC, M, BBCA },{ AND, M, AX },{ ROL, M, AX },{ AND, M, ALX },
// 0x40
{ RTI, I, IMP },{ EOR, M, DXI },{ WDM, I, IMP },{ EOR, M, S },
{ MVP, I, MVP },{ EOR, M, D },{ LSR, M, D },{ EOR, M, DLI },
{ PHA, I, IMP },{ EOR, M, IMM },{ LSR, M, ACC },{ PHK, I, IMP },
{ JMP, I, A },{ EOR, M, A },{ LSR, M, A },{ EOR, M, AL },
// 0x50
{ BVC, I, RELB },{ EOR, M, DIY },{ EOR, M, DI },{ EOR, M, SIY },
{ MVN, I, MVN },{ EOR, M, DX },{ LSR, M, DX },{ EOR, M, DLIY },
{ CLI, I, IMP },{ EOR, M, AY },{ PHY, I, IMP },{ TAD, I, IMP },
{ JMP, I, AL },{ EOR, M, AX },{ LSR, M, AX },{ EOR, M, ALX },
// 0x60
{ RTS, I, IMP },{ ADC, M, DXI },{ PER, I, PER },{ ADC, M, S },
{ LDM, M, LDM4 },{ ADC, M, D },{ ROR, M, D },{ ADC, M, DLI },
{ PLA, I, IMP },{ ADC, M, IMM },{ ROR, M, ACC },{ RTL, I, IMP },
{ JMP, I, AI },{ ADC, M, A },{ ROR, M, A },{ ADC, M, AL },
// 0x70
{ BVS, I, RELB },{ ADC, M, DIY },{ ADC, M, DI },{ ADC, M, SIY },
{ LDM, M, LDM4X },{ ADC, M, DX },{ ROR, M, DX },{ ADC, M, DLIY },
{ SEI, I, IMP },{ ADC, M, AY },{ PLY, I, IMP },{ TDA, I, IMP },
{ JMP, I, AXI },{ ADC, M, AX },{ ROR, M, AX },{ ADC, M, ALX },
// 0x80
{ BRA, I, RELB },{ STA, M, DXI },{ BRL, I, RELW },{ STA, M, S },
{ STY, X, D },{ STA, M, D },{ STX, X, D },{ STA, M, DLI },
{ DEY, I, IMP },{ BIT, M, IMM },{ TXA, I, IMP },{ PHT, I, IMP },
{ STY, X, A },{ STA, M, A },{ STX, X, A },{ STA, M, AL },
// 0x90
{ BCC, I, RELB },{ STA, M, DIY },{ STA, M, DI },{ STA, M, SIY },
{ STY, X, DX },{ STA, M, DX },{ STX, X, DY },{ STA, M, DLIY },
{ TYA, I, IMP },{ STA, M, AY },{ TXS, I, IMP },{ TXY, I, IMP },
{ LDM, M, LDM5 },{ STA, M, AX },{ LDM, M, LDM5X },{ STA, M, ALX },
// 0xA0
{ LDY, X, IMM },{ LDA, M, DXI },{ LDX, X, IMM },{ LDA, M, S },
{ LDY, X, D },{ LDA, M, D },{ LDX, X, D },{ LDA, M, DLI },
{ TAY, I, IMP },{ LDA, M, IMM },{ TAX, I, IMP },{ PLB, I, IMP },
{ LDY, X, A },{ LDA, M, A },{ LDX, X, A },{ LDA, M, AL },
// 0xB0
{ BCS, I, RELB },{ LDA, M, DIY },{ LDA, M, DI },{ LDA, M, SIY },
{ LDY, X, DX },{ LDA, M, DX },{ LDX, X, DY },{ LDA, M, DLIY },
{ CLV, I, IMP },{ LDA, M, AY },{ TSX, I, IMP },{ TYX, I, IMP },
{ LDY, X, AX },{ LDA, M, AX },{ LDX, X, AY },{ LDA, M, ALX },
// 0xC0
{ CPY, X, IMM },{ CMP, M, DXI },{ CLP, I, IMM },{ CMP, M, S },
{ CPY, X, D },{ CMP, M, D },{ DEC, M, D },{ CMP, M, DLI },
{ INY, I, IMP },{ CMP, M, IMM },{ DEX, I, IMP },{ WIT, I, IMP },
{ CPY, X, A },{ CMP, M, A },{ DEC, M, A },{ CMP, M, AL },
// 0xD0
{ BNE, I, RELB },{ CMP, M, DIY },{ CMP, M, DI },{ CMP, M, SIY },
{ PEI, I, PEI },{ CMP, M, DX },{ DEC, M, DX },{ CMP, M, DLIY },
{ CLM, I, IMP },{ CMP, M, AY },{ PHX, I, IMP },{ STP, I, IMP },
{ JML, I, AI },{ CMP, M, AX },{ DEC, M, AX },{ CMP, M, ALX },
// 0xE0
{ CPX, X, IMM },{ SBC, M, DXI },{ SEP, I, IMM },{ SBC, M, S },
{ CPX, X, D },{ SBC, M, D },{ INC, M, D },{ SBC, M, DLI },
{ INX, M, IMP },{ SBC, M, IMM },{ NOP, I, IMP },{ PSH, I, IMM },
{ CPX, X, A },{ SBC, M, A },{ INC, M, A },{ SBC, M, AL },
// 0xF0
{ BEQ, I, RELB },{ SBC, M, DIY },{ SBC, M, DI },{ SBC, M, SIY },
{ PEA, I, PEA },{ SBC, M, DX },{ INC, M, DX },{ SBC, M, DLIY },
{ SEM, I, IMP },{ SBC, M, AY },{ PLX, I, IMP },{ PUL, I, IMM },
{ JSR, I, AXI },{ SBC, M, AX },{ INC, M, AX },{ SBC, M, ALX }
};

// params for each instruction prefixed with x42
static const OpCode ops42[OPS] = {
	{ UNK, I, SIG },{ ORB, M, DXI },{ UNK, I, SIG },{ ORB, M, S },
{ UNK, I, SIG },{ ORB, M, D },{ UNK, I, SIG },{ ORB, M, DLI },
{ UNK, I, SIG },{ ORB, M, IMM },{ ASL, M, ACCB },{ UNK, I, SIG },
{ UNK, I, SIG },{ ORB, M, A },{ UNK, I, SIG },{ ORB, M, AL },
// 0x10
{ UNK, I, SIG },{ ORB, M, DIY },{ ORB, M, DI },{ ORB, M, SIY },
{ UNK, I, SIG },{ ORB, M, DX },{ UNK, I, SIG },{ ORB, M, DLIY },
{ UNK, I, SIG },{ ORB, M, AY },{ DEB, I, IMP },{ TBS, I, IMP },
{ UNK, I, SIG },{ ORB, M, AX },{ UNK, I, SIG },{ ORB, M, ALX },
// 0x20
{ UNK, I, SIG },{ ANDB, M, DXI },{ UNK, I, SIG },{ ANDB, M, S },
{ UNK, I, SIG },{ ANDB, M, D },{ UNK, I, SIG },{ ANDB, M, DLI },
{ UNK, I, SIG },{ ANDB, M, IMM },{ ROL, M, ACCB },{ UNK, I, SIG },
{ UNK, I, SIG },{ ANDB, M, A },{ UNK, I, SIG },{ ANDB, M, AL },
// 0x30
{ UNK, I, SIG },{ AND, M, DIY },{ AND, M, DI },{ AND, M, SIY },
{ UNK, I, SIG },{ AND, M, DX },{ UNK, I, SIG },{ AND, M, DLIY },
{ UNK, I, SIG },{ AND, M, AY },{ INB, I, IMP },{ TSB, I, IMP },
{ UNK, I, SIG },{ AND, M, AX },{ UNK, I, SIG },{ AND, M, ALX },
// 0x40
{ UNK, I, SIG },{ EORB, M, DXI },{ UNK, I, SIG },{ EORB, M, S },
{ UNK, I, SIG },{ EORB, M, D },{ UNK, I, SIG },{ EORB, M, DLI },
{ PHB, I, IMP },{ EORB, M, IMM },{ LSRB, M, ACC },{ UNK, I, SIG },
{ UNK, I, SIG },{ EORB, M, A },{ UNK, I, SIG },{ EORB, M, AL },
// 0x50
{ UNK, I, SIG },{ EORB, M, DIY },{ EORB, M, DI },{ EORB, M, SIY },
{ UNK, I, SIG },{ EORB, M, DX },{ UNK, I, SIG },{ EORB, M, DLIY },
{ UNK, I, SIG },{ EORB, M, AY },{ UNK, I, SIG },{ TBD, I, IMP },
{ UNK, I, SIG },{ EORB, M, AX },{ UNK, I, SIG },{ EORB, M, ALX },
// 0x60
{ UNK, I, SIG },{ ADCB, M, DXI },{ UNK, I, SIG },{ ADCB, M, S },
{ UNK, I, SIG },{ ADCB, M, D },{ UNK, I, SIG },{ ADCB, M, DLI },
{ PLAB,I, IMP },{ ADCB, M, IMM },{ ROR, M, ACC },{ UNK, I, SIG },
{ UNK, I, SIG },{ ADCB, M, A },{ UNK, I, SIG },{ ADCB, M, AL },
// 0x70
{ UNK, I, SIG },{ ADCB, M, DIY },{ ADCB, M, DI },{ ADCB, M, SIY },
{ UNK, I, SIG },{ ADCB, M, DX },{ UNK, I, SIG },{ ADCB, M, DLIY },
{ UNK, I, SIG },{ ADCB, M, AY },{ UNK, I, SIG },{ TDB, I, IMP },
{ UNK, I, SIG },{ ADCB, M, AX },{ UNK, I, SIG },{ ADCB, M, ALX },
// 0x80
{ UNK, I, SIG },{ STB, M, DXI },{ UNK, I, SIG },{ STB, M, S },
{ UNK, I, SIG },{ STB, M, D },{ UNK, I, SIG },{ STB, M, DLI },
{ UNK, I, SIG },{ UNK, I, SIG },{ TXB, I, IMP },{ UNK, I, SIG },
{ UNK, I, SIG },{ STB, M, A },{ UNK, I, SIG },{ STB, M, AL },
// 0x90
{ UNK, I, SIG },{ STB, M, DIY },{ STB, M, DI },{ STB, M, SIY },
{ UNK, I, SIG },{ STB, M, DX },{ UNK, I, SIG },{ STB, M, DLIY },
{ TYB, I, IMP },{ STB, M, AY },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ STB, M, AX },{ UNK, I, SIG },{ STB, M, ALX },
// 0xA0
{ UNK, I, SIG },{ LDB, M, DXI },{ UNK, I, SIG },{ LDB, M, S },
{ UNK, I, SIG },{ LDB, M, D },{ UNK, I, SIG },{ LDB, M, DLI },
{ TBY, I, IMP },{ LDB, M, IMM },{ TBX, I, IMP },{ UNK, I, SIG },
{ UNK, I, SIG },{ LDB, M, A },{ UNK, I, SIG },{ LDB, M, AL },
// 0xB0
{ UNK, I, SIG },{ LDB, M, DIY },{ LDB, M, DI },{ LDB, M, SIY },
{ UNK, I, SIG },{ LDB, M, DX },{ UNK, I, SIG },{ LDB, M, DLIY },
{ UNK, I, SIG },{ LDB, M, AY },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ LDB, M, AX },{ UNK, I, SIG },{ LDB, M, ALX },
// 0xC0
{ UNK, I, SIG },{ CMPB, M, DXI },{ UNK, I, SIG },{ CMPB, M, S },
{ UNK, I, SIG },{ CMPB, M, D },{ UNK, I, SIG },{ CMPB, M, DLI },
{ UNK, I, SIG },{ CMPB, M, IMM },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ CMPB, M, A },{ UNK, I, SIG },{ CMPB, M, AL },
// 0xD0
{ UNK, I, SIG },{ CMPB, M, DIY },{ CMPB, M, DI },{ CMPB, M, SIY },
{ UNK, I, SIG },{ CMPB, M, DX },{ UNK, I, SIG },{ CMPB, M, DLIY },
{ UNK, I, SIG },{ CMPB, M, AY },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ CMPB, M, AX },{ UNK, I, SIG },{ CMPB, M, ALX },
// 0xE0
{ UNK, I, SIG },{ SBCB, M, DXI },{ UNK, I, SIG },{ SBCB, M, S },
{ UNK, I, SIG },{ SBCB, M, D },{ UNK, I, SIG },{ SBCB, M, DLI },
{ UNK, I, SIG },{ SBCB, M, IMM },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ SBCB, M, A },{ UNK, I, SIG },{ SBCB, M, AL },
// 0xF0
{ UNK, I, SIG },{ SBCB, M, DIY },{ SBCB, M, DI },{ SBCB, M, SIY },
{ UNK, I, SIG },{ SBCB, M, DX },{ UNK, I, SIG },{ SBCB, M, DLIY },
{ UNK, I, SIG },{ SBCB, M, AY },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ SBCB, M, AX },{ UNK, I, SIG },{ SBCB, M, ALX }
};

// params for each instruction prefixed with x89
static const OpCode ops89[OPS] = {
	{ UNK, I, SIG },{ MPY, M, DXI },{ UNK, I, SIG },{ MPY, M, S },
{ UNK, I, SIG },{ MPY, M, D },{ UNK, I, SIG },{ MPY, M, DLI },
{ UNK, I, SIG },{ MPY, M, IMM },{ UNK, I, SIG },{ PHD, I, IMP },
{ UNK, I, SIG },{ MPY, M, A },{ UNK, I, SIG },{ MPY, M, AL },
// 0x10
{ UNK, I, SIG },{ MPY, M, DIY },{ MPY, M, DI },{ MPY, M, SIY },
{ UNK, I, SIG },{ MPY, M, DX },{ UNK, I, SIG },{ MPY, M, DLIY },
{ UNK, I, SIG },{ MPY, M, AY },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ MPY, M, AX },{ UNK, I, SIG },{ MPY, M, ALX },
// 0x20
{ UNK, I, SIG },{ DIV, M, DXI },{ UNK, I, SIG },{ DIV, M, S },
{ UNK, I, SIG },{ DIV, M, D },{ UNK, I, SIG },{ DIV, M, DLI },
{ XAB, I, IMP },{ DIV, M, IMM },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ DIV, M, A },{ UNK, I, SIG },{ DIV, M, AL },
// 0x30
{ UNK, I, SIG },{ DIV, M, DIY },{ DIV, M, DI },{ DIV, M, SIY },
{ UNK, I, SIG },{ DIV, M, DX },{ UNK, I, SIG },{ DIV, M, DLIY },
{ UNK, I, SIG },{ DIV, M, AY },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ DIV, M, AX },{ UNK, I, SIG },{ DIV, M, ALX },
// 0x40
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ RLA, M, IMM },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
// 0x50
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
// 0x60
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
// 0x70
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
// 0x80
{ UNK, I, SIG },{ MPYS, M, DXI },{ UNK, I, SIG },{ MPYS, M, S },
{ UNK, I, SIG },{ MPYS, M, D },{ UNK, I, SIG },{ MPYS, M, DLI },
{ UNK, I, SIG },{ MPYS, M, IMM },{ UNK, I, SIG },{ EXTS, I, A },
{ UNK, I, SIG },{ MPYS, M, A },{ UNK, I, SIG },{ MPYS, M, AL },
// 0x90
{ UNK, I, SIG },{ MPYS, M, DIY },{ MPYS, M, DI },{ MPYS, M, SIY },
{ UNK, I, SIG },{ MPYS, M, DX },{ UNK, I, SIG },{ MPYS, M, DLIY },
{ UNK, I, SIG },{ MPYS, M, AY },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ MPYS, M, AX },{ UNK, I, SIG },{ MPYS, M, ALX },
// 0xA0
{ UNK, I, SIG },{ DIVS, M, DXI },{ UNK, I, SIG },{ DIVS, M, S },
{ UNK, I, SIG },{ DIVS, M, D },{ UNK, I, SIG },{ DIVS, M, DLI },
{ UNK, I, SIG },{ DIVS, M, IMM },{ UNK, I, SIG },{ EXTZ, I, A },
{ UNK, I, SIG },{ DIVS, M, A },{ UNK, I, SIG },{ DIVS, M, AL },
// 0xB0
{ UNK, I, SIG },{ DIVS, M, DIY },{ DIVS, M, DI },{ DIVS, M, SIY },
{ UNK, I, SIG },{ DIVS, M, DX },{ UNK, I, SIG },{ DIVS, M, DLIY },
{ UNK, I, SIG },{ DIVS, M, AY },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ DIVS, M, AX },{ UNK, I, SIG },{ DIVS, M, ALX },
// 0xC0
{ UNK, I, SIG },{ UNK, I, SIG },{ LDT, I, IMM },{ UNK, I, SIG },
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
// 0xD0
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
// 0xE0
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
// 0xF0
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },
{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG },{ UNK, I, SIG }
};

static ut8 read_8(const ut8* data, unsigned int offset);
static ut16 read_16(const ut8* data, unsigned int offset);
static ut24 read_24(const ut8* data, unsigned int offset);

static OpCode* GET_OPCODE(ut16 instruction, byte offset);

static bool GLOB_M = true;
static bool GLOB_X = false;
static bool GLOB_I = false;
// global trackers for the flag bits - defaults to M=1, X=0

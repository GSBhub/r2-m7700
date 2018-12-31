#include <string.h>
#include <r_asm.h>
#include <r_lib.h>
#include "m7700.h"

/*
 Simple helper functions to read N bytes from the buffer
*/
static ut8 read_8(const ut8 *data, unsigned int offset) {

	ut8 ret = data[offset];
	return ret;
}

static ut16 read_16(const ut8 *data, unsigned int offset) {

	ut16 ret = data[offset];
	return ret | data[offset + 1] << 8;
}

static ut24 read_24(const ut8 *data, unsigned int offset) {

	ut24 ret = data[offset];
	ret |= ret | data[offset + 1] << 8;
	return ret | data[offset + 2] << 16;
}

char* int_8_str(unsigned int val)
{
   static char str[20];

   val &= 0xff;

   if(val & 0x80)
      snprintf(str, 20, "-$%x", (0-val) & 0x7f);
   else
      snprintf(str, 20, "$%x", val & 0x7f);

   return str;
}

/*
	Reads args from the opcode prefix arrays in the header, based off of prefix

	Each prefix contains func name, the addressing flag bit, and the arg
 */
static OpCode* GET_OPCODE(ut16 instruction, byte prefix) {

	return (prefix == 0x89 ? ops89 + instruction : (prefix == 0x42 ? ops42 + instruction : ops + instruction));
}

static char* parse_args(OpCode *opcd, RAsmOp *op, ut8 *buf, int prefix, bool flag_x, bool flag_m, RAsm* a){

	const int bufsize= 60; 
	char* args = (char*)(malloc(bufsize));	// alloc bufspace
	
	switch (opcd->arg) {

		case IMP : // implied addressing mode - single instruction addressed to int. register
			snprintf(args, bufsize, "0");
			break;

	// accumulator register used
		case ACC :
			if (flag_x){

				snprintf(args, bufsize, "1,al");
			} else {
				snprintf(args, bufsize, "1,ax");
			}
			break;
		case ACCB :
			if (flag_x){

				snprintf(args, bufsize, "1,bl");
			} else {

				snprintf(args, bufsize, "1,bx");
			}
			break;

		// below occasonally causes segfault for some reason
		case RELB :
			op->size++;
			snprintf(args, bufsize, "1,0x%02x", (a->pc + op->size + read_8(buf, op->size - 1)) & 0xffff); // Need to add a way to parse the param from the instruction in buff for last param
		break;

		case RELW :
		case PER : 
			op->size+=2;
			snprintf(args, bufsize, "1,0x%04x", (a->pc + op->size + read_16(buf, op->size - 2)) & 0xffff); // Need to add a way to parse the param from the instruction in buff for last param
		break;

		case IMM : // immediate addressing - format: acc val

			// check addressing mode - first is for 16 bit addressing mode, second for 8 bit
			if (flag_m || flag_x) { // larger condition
				if (prefix == 42)  //b
					snprintf(args, bufsize, "2,bx,#0x%04x", read_16(buf, op->size));		
				
				else			    //a 
					snprintf(args, bufsize, "2,ax,#0x%04x", read_16(buf, op->size));	
				
				op->size += 2;	
			}
			else { // smaller instruction/params
				if (prefix == 42)//b
					snprintf(args, bufsize, "2,bl,#0x%02x", read_8(buf, op->size));			
				else			 //a
					snprintf(args, bufsize, "2,al,#0x%02x", read_8(buf, op->size));			
				op->size++;
			}
			
		break;

		case BBCD :
			// check addressing mode - first is for 16 bit addressing mode, second for 8 bit
			if (flag_m || flag_x){ // larger flags asserted	
				snprintf(args, bufsize,"3,#0x%04x,0x%02x,0x%04hx\0", read_16(buf, op->size+1), read_8(buf, op->size), (ut16)(a->pc + op->size + 5 + read_8(buf, op->size+3)));
				op->size += 4;
			}
			else {// smaller
				snprintf(args, bufsize,"3,#0x%02x,0x%02x,0x%04hx\0", read_8(buf, op->size+1), read_8(buf, op->size), (ut16)(a->pc + op->size + 4 +  read_8(buf, op->size+2)));
				op->size += 3;		
			}
		break;

		case BBCA :
			// check addressing mode - first is for 16 bit addressing mode, second for 8 bit
			if (flag_m || flag_x) { // larger
				snprintf(args, bufsize,"3,#0x%04x,$0x%04x,0x%04hx\0", read_16(buf, op->size+2), read_16(buf, op->size), ((ut16)(a->pc + op->size + 5)+ (char)read_8(buf, op->size+4)));
				op->size += 5;
			}
			else { // smaller
				snprintf(args, bufsize,"3,#0x%02x,$0x%04x,0x%04hx\0", read_8(buf, op->size+2), read_16(buf, op->size), ((ut16)(a->pc + op->size + 4) + (char)read_8(buf, op->size+3)));
				op->size += 4;		
			}
			
		break;

		case LDM4 : // ldm
			if (flag_m || flag_x) { // larger
				snprintf(args, bufsize,"2,#%04hx,$0x%02x\0", read_16(buf, op->size+1), read_8(buf, op->size));
				op->size += 3;
			}
			else { // smaller
				snprintf(args, bufsize,"2,#%02x,$0x%02x\0", read_8(buf, op->size+1), read_8(buf, op->size));
				op->size += 2;	
			}
		break;
		
		case LDM5 : // ldm long
			if (flag_m || flag_x) { // larger
				snprintf(args, bufsize,"2,#%04hx,$0x%04hx\0", read_16(buf, op->size+2), read_16(buf, op->size));
				op->size += 4;
			}
			
			else { //smaller
				snprintf(args, bufsize,"2,#%02x,$0x%04hx\0", read_8(buf, op->size+2), read_16(buf, op->size));
				op->size += 3;
			}
		break;

		case LDM4X : // ldm X direct
			if (flag_m || flag_x) {// larger
				snprintf(args, bufsize,"3,#$%04hx,$%02x,xl\0", read_16(buf, op->size+1), read_8(buf, op->size));
				op->size += 3;
			}
			else { // smaller
				snprintf(args, bufsize,"3,#$%02x,$%02x,xl\0", read_8(buf, op->size+1), read_8(buf, op->size));
				op->size += 2;
			}
		break;

		case LDM5X : // ldm x direct long	
			if (flag_m || flag_x) {// larger
				snprintf(args, bufsize,"3,#$%04hx,$%04x,xl\0", read_16(buf, op->size+2), read_16(buf, op->size));
				op->size += 4;
			}
			else {// smaller
				snprintf(args, bufsize,"3,#$%02x,$04hx,xl\0", read_8(buf, op->size+2), read_16(buf, op->size));
				op->size += 3;
			}
		break;

		// end LDM specific instructions 

		case A : // accumulator addressing mode
		case PEA : 
			snprintf(args, bufsize,"1,0x%04hx\0", read_16(buf, op->size));			
			op->size +=2;
		break;
		case AI :
			snprintf(args, bufsize,"1,($%04x)\0", read_16(buf, op->size));
			op->size +=2;
		break;
	
		case AL :
			snprintf(args, bufsize,"1,$%08x\0", read_24(buf, op->size)); // might need to be set to 06x
			op->size += 3;
		break;
	
		case ALX : 
			snprintf(args, bufsize,"2,$%08x,xl\0", read_24(buf, op->size));
			op->size += 3;
		break;
		case AX :
			snprintf(args, bufsize,"2,$%04hx,xl\0", read_16(buf, op->size));
			op->size += 2;
		break;
		case AXI :
			snprintf(args, bufsize,"2,$%04hx,xl)\0", read_16(buf, op->size));
			op->size += 2;
		break;
		case AY :
			snprintf(args, bufsize,"2,$%04hx,yl\0", read_16(buf, op->size));
			op->size += 2;
		break;

		case D : // direct addressing mode

				if (prefix == 42){
					snprintf(args, bufsize,"2,bl,$0x%02x\0", read_8(buf, op->size));

				} else {
					snprintf(args, bufsize,"2,al,$0x%02x\0", read_8(buf, op->size));
				}
				op->size++;

			//}

		break;
		case DI : // direct indirect addressing mode
		case PEI :
			snprintf(args, bufsize,"1,($%02x)\0", read_8(buf, op->size));
			op->size++;
		break;
		case DIY : // direct indexed Y addressing mode
			snprintf(args, bufsize,"2,yl,($%02x)\0", read_8(buf, op->size));
			op->size++;
		break;
		case DLI :
			snprintf(args, bufsize,"1,[$%02x]\0", read_8(buf, op->size));		
			op->size++;
		break;
		case DLIY :
			snprintf(args, bufsize,"1,yl,[$%02x]\0", read_8(buf, op->size));
			op->size++;
		break;	
		case DX ://direct indexed X addressing mode
		
			snprintf(args, bufsize,"2,xl,$%02x\0", read_8(buf, op->size));
			op->size++;
		break;
		case DXI :  
			snprintf(args, bufsize,"2,xl,($%02x)\0", read_8(buf, op->size));
			op->size++;
		break;
		case DY :
			snprintf(args, bufsize,"2,yl,$%02x\0", read_8(buf, op->size));
			op->size++;
		break;

	// causes segfault
		case S: 
			snprintf(args, bufsize,"1,%s\0", int_8_str(read_8(buf, op->size)));
			op->size++;
		break;
		case SIY : 
			snprintf(args, bufsize,"3,yl,%s\0", int_8_str(read_8(buf, op->size)));
			op->size++;
		break;
		case SIG : 
			snprintf(args, bufsize,"1,$%02x\0", read_8(buf, op->size));
			op->size += 2;
		break;

		case MVN :
		case MVP :
			snprintf(args, bufsize,"2,$%02x,$%02x\0", read_8(buf, op->size+1), read_8(buf, op->size));
			op->size += 2;
		break;	
		default:
			break;
	}

	return args;

}

/*
	Takes null terminated string array, converts to int
*/
static int get_dest(char* params){
	
	int ret = 0;
	ret = (int)strtol(params, NULL, 0);
	return ret;
}

/* Main disassembly func hook to R2

	R2 Gives global fields a, op, buf, and len for populating a and op
	
*/
static int m7700_disassemble(RAsm *a, RAsmOp *op, ut8 *buf, ut64 len) {
	
	op->size = 1;
	char arg[50];
	ut16 instruction;
	OpCode* opcd;
	char* buf_asm = (char*)malloc(50);
	int prefix = 0;
	instruction = read_8(buf, 0); // grab instruction from buffer, with offset of 0

	// pull the prefix of the instruction off, grabing from the tables corresponding to the addressing mode
	switch (instruction){
		// first two cases, remove prefix - otherwise just pass instruction
		case 0x42: // x42 prefix - 
			//snprintf(dest, bufsize,"b"); // b reg prefix;
			instruction = read_8(buf, 1); // grab next instruction from buffer, with offset of 1
			opcd = GET_OPCODE (instruction, 0x42); // grab opcode from instruction
			op->size++;
			prefix = 42;
			break;
		case 0x89: // x89 prefix  -
			instruction = read_8(buf, 1); // grab next instruction from buffer, with offset of 1
			opcd = GET_OPCODE (instruction, 0x89); // grab opcode from instruction
			op->size++; 
			prefix = 89;
			break;
		default:   // other prefixes
			//snprintf(dest, bufsize,"a");
			opcd = GET_OPCODE (instruction, 0x00); // grab opcode from instruction
			break;
	}

	 switch (opcd->op){
	// // Data len selection flag mutators
	
	 case SEM:
	 	GLOB_M = true;
	 	if (!M_FLAGS_SET[a->pc]){
	 		M_FLAGS_SET[a->pc] = true;
	 		M_FLAGS[a->pc] = true;
	 	}
	 	break;
	 case CLM: 
	 	GLOB_M = false;
	 	if (!M_FLAGS_SET[a->pc]){
	 		M_FLAGS_SET[a->pc] = true;
	 		M_FLAGS[a->pc] = false;
	 	}
	 	break;
		
	// case SEP:
	//  	GLOB_X = true;

	//  	if (!X_FLAGS_SET[a->pc]){
	//  		X_FLAGS_SET[a->pc] = true;
	//  		X_FLAGS[a->pc] = true;
	//  	}
	//  	break;
	// case CLP:
	//  	GLOB_X = false;
	//  	if (!X_FLAGS_SET[a->pc]){
	//  		X_FLAGS_SET[a->pc] = true;
	//  		X_FLAGS[a->pc] = false;
	//  	}
	//  	break;

	 default:
	 	break;
	};

	if (!M_FLAGS_SET[a->pc]){

		M_FLAGS[a->pc] = GLOB_M;
		M_FLAGS_SET[a->pc] = true;
	} else {

		GLOB_M = M_FLAGS[a->pc];
	}
	
	char* opname = instruction_set[opcd->op];
	strcat(opname, "\0");

    strcpy (buf_asm, opname); // Depreciated after August 2018 RStrBuf update
	
	// // parse all variables, tokenize them, parse
	char* vars = strtok(parse_args(opcd, op, buf, prefix, !(GLOB_X) && (opcd->flag == X), !(GLOB_M) && opcd->flag == M, a), ",");
	char* var_copy;

	vars = vars + 2; // drop leading argno and space
	int i = 0;

	strcpy (arg, "\0");

  	while (vars != NULL)
  	{
		if (i > 1){
			strcat (arg, " ");
    		strcat (arg, vars);
    		vars = strtok (NULL, " ,.-");
	  	}
		else if (i == 1) {
    		strcat (arg, vars);
    		vars = strtok (NULL, " ,.-");
		}
		else {
			vars = strtok (NULL, " ,.-");
		}
		i++;
  	}
	  if (strcmp(opname, "JSR")){ // attempt to define the boundaries for the JSR

	  	int dest_addr = get_dest(arg);

	  	if (!M_FLAGS_SET[dest_addr]){
	  		M_FLAGS[dest_addr] = GLOB_M;
	  		M_FLAGS_SET[dest_addr] = true;
	  	}
	  }  

	//op->buf_inc += op->size;
	
    if (*arg) {
		// r_strbuf_appendf(buf_asm, " ");
		// r_strbuf_appendf(buf_asm, arg);
		// r_strbuf_appendf(buf_asm, " --  m:");
		// r_strbuf_appendf(buf_asm, M_FLAGS[a->pc] ? "1" : "0");
		// r_strbuf_appendf(buf_asm, " x:");
		// r_strbuf_appendf(buf_asm, " x:");
		// r_strbuf_appendf(buf_asm,  X_FLAGS[a->pc] ? "1" : "0");
		//r_strbuf_appendf(buf_asm, "\0");
        strcat (buf_asm, " ");
        strcat (buf_asm, arg);
		strcat (buf_asm, " --  m:");
		strcat (buf_asm, M_FLAGS[a->pc] ? "1" : "0");
		strcat (buf_asm, " x:");
		strcat (buf_asm, X_FLAGS[a->pc] ? "1" : "0");
		strcat (buf_asm, "\0"); 
    }
	
	strncpy (r_strbuf_get (&op->buf_asm), buf_asm, sizeof (op->buf_asm));
	r_hex_bin2str (buf, op->size, r_strbuf_get (&op->buf_hex));
	// 	//op->buf_asm = sb;
	//free(vars);
	return op->size;
}
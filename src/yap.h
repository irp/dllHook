#ifndef __YAP_H__
#define __YAP_H__

#include <Windows.h>

typedef PBYTE (NTAPI *DISASM_FUNC) (struct _INSTRUCTION_TABLE* pInsTab,
	                            PBYTE p_where,                
			            PBYTE pb_from); 

/* Flag */
#define FUNC_ADD        0x02   
#define NO_SIB          0x0f    
#define SIB_PRESENT     0x10

/* strutture */
typedef const struct _INSTRUCTION_TABLE {

	ULONG opcode;
	ULONG modrm;
	ULONG sib;
	ULONG flag;            
	//PPREFIX_TABLE pprefixTab;
	DISASM_FUNC disasmFunc;

	LONG opcode_size32;   
	LONG opcode_size16;   

}INSTRUCTION_TABLE, *PINSTRUCTION_TABLE;

//typedef PBYTE ( *DISASM_FUNC)(PINSTRUCTION_TABLE pInsTab, PBYTE p_where, PBYTE pb_from);
BOOL seg_override;
BOOL opsize_override = FALSE;
BOOL addsize_override = FALSE;
BOOL lock;
BOOL repeat;
BOOL modrm_on = FALSE;

typedef const struct _PONTE {

	BYTE copied[30]; 
	BYTE f_codeSize;
	PBYTE pstay;       
	PVOID phook;         

}PONTE, *PPONTE;

/*              */

const BYTE modrm_table[256] = {

        0,0,0,0,1,4,0,0,0,0,0,0,1,4,0,0,0,0,0,0,
	1,4,0,0,0,0,0,0,1,4,0,0,0,0,0,0,1,4,0,0, 
	0,0,0,0,1,4,0,0,0,0,0,0,1,4,0,0,0,0,0,0, 
	1,4,0,0,1,1,1,1,2,1,1,1,1,1,1,1,2,1,1,1,                  
        1,1,1,1,2,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,
	2,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,2,1,1,1,
	1,1,1,1,2,1,1,1,4,4,4,4,5,4,4,4,4,4,4,4,
	5,4,4,4,4,4,4,4,5,4,4,4,4,4,4,4,5,4,4,4,                  
        4,4,4,4,5,4,4,4,4,4,4,4,5,4,4,4,4,4,4,4,
	5,4,4,4,4,4,4,4,5,4,4,4,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,                  
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0   
  
}; 

//PPREFIX_TABLE pprefixTab;

/* functions */
//DISASM_FUNC b_copy;
PBYTE try_dis (__in PBYTE p_where,
	       __in PBYTE pb_from);

extern "C" VOID NTAPI dis_jmpE9 (__in PBYTE pb_from,
	                         __in PINSTRUCTION_TABLE pInsTab, 
				 __in DWORD entry_point);

PBYTE  b_copy (__in struct _INSTRUCTION_TABLE* pInsTab,
	       __in PBYTE p_where,                 
	       __in PBYTE pb_from);

PBYTE  p_copy (__in struct _INSTRUCTION_TABLE* pInsTab,
	       __in PBYTE p_where,               
	       __in PBYTE pb_from);

PBYTE j_copy (__in struct _INSTRUCTION_TABLE* pInsTab,
	      __in PBYTE p_where,                 
	      __in PBYTE pb_from);

/*                           */

PBYTE  p_copy (__in struct _INSTRUCTION_TABLE* pInsTab,
	       __in PBYTE p_where,                 
	       __in PBYTE pb_from) {  

                  printf("PREFIX!\n");                  
		  if (pInsTab->opcode == 0x66) { //operand size override prefix
                               opsize_override = TRUE;
			       PBYTE pNext = b_copy(pInsTab, p_where, pb_from);
			       return pNext; }

		  else if(pInsTab->opcode == 0x67) { //address size override prefix
				addsize_override = TRUE;
				PBYTE pNext = b_copy(pInsTab, p_where, pb_from);
				return pNext; }

		  else { PBYTE pNext = b_copy(pInsTab, p_where, pb_from); 

			return pNext; }

}

PBYTE j_coyp (__in struct _INSTRUCTION_TABLE* pInsTab,
	      __in PBYTE p_where,                 
              __in PBYTE pb_from) {

				   return NULL;
}

PBYTE  b_copy (__in struct _INSTRUCTION_TABLE* pInsTab,
	       __in PBYTE p_where,                
	       __in PBYTE pb_from) {                

                  opsize_override = FALSE;
		  addsize_override = FALSE;
		  LONG target_length = (pInsTab->flag & FUNC_ADD)
				?(addsize_override ? pInsTab->opcode_size16 : pInsTab->opcode_size32) 
				:(opsize_override ? pInsTab->opcode_size16 : pInsTab->opcode_size32);
				    //looking for modrm and sib with intel table
					if (pInsTab->modrm != 0) {    
						modrm_on = TRUE;
						BYTE b_modrm = pb_from[pInsTab->modrm];
						BYTE b_flag = modrm_table[b_modrm]; 
						printf("modrm byte:%x\n", pb_from[pInsTab->modrm]);
						target_length += b_flag & NO_SIB; // aggiungo il sib se presente
						if (b_flag & SIB_PRESENT) {
							BYTE b_sib = pb_from[pInsTab->modrm + 1];
							printf("sib byte:%x\n", pb_from[pInsTab->modrm+1]);
					        if ((b_sib & 0x07) == 0x05) { 
								if ((b_modrm & 0xc0) == 0x00) {   //first square intel table   
									target_length += 4; }
								else if ((b_modrm & 0xc0) == 0x40) { //second 
									target_length += 1; }
								else if ((b_modrm & 0xc0) == 0x80) { //third
									target_length += 4; }
							}
						}
					}

					printf("target length: %d\n", target_length); 
					RtlCopyMemory(p_where, pb_from, 1); 
				        PBYTE pNext = pb_from + target_length;
					printf("next byte: %x\n", *pNext);

				    return pNext;

}  

/*                  */

/* macro */                      /*mod,sib,flag,func,size32,size16*/

#define oneByte_MACRO                0, 0, 0, &b_copy, 1, 1
#define twoByte_MACRO                0, 0, 0, &b_copy, 2, 2
#define trefiveByte_MACRO            0, 0, 0, &b_copy, 5, 3
#define twoByteModrm_MACRO           1, 0, 0, &b_copy, 2, 2      
#define prefix_MACRO                 0, 0, 0, &p_copy, 1, 1
/* instruction set */  

const INSTRUCTION_TABLE deco[256] = {

	{ 0x00, twoByteModrm_MACRO }, { 0x01, twoByteModrm_MACRO }, { 0x02, twoByteModrm_MACRO }, { 0x03, twoByteModrm_MACRO },
	{ 0x04, twoByte_MACRO }, { 0x05, trefiveByte_MACRO }, //ADD no imm8/16/32

	{ 0x06, oneByte_MACRO }, { 0x07, oneByte_MACRO },  //PUSH ES, POP ES

	{ 0x08, twoByteModrm_MACRO }, { 0x09, twoByteModrm_MACRO }, { 0x0A, twoByteModrm_MACRO }, { 0x0B, twoByteModrm_MACRO },
	{ 0x0C, oneByte_MACRO }, { 0x0D, oneByte_MACRO },  //OR

	{ 0x0E, oneByte_MACRO }, { 0x0F, oneByte_MACRO }, //PUSH CS, POP FS, GS

        { 0x10, twoByteModrm_MACRO }, { 0x11, twoByteModrm_MACRO }, { 0x12, twoByteModrm_MACRO }, { 0x13, twoByteModrm_MACRO },
	{ 0x14, twoByte_MACRO },  { 0x15, trefiveByte_MACRO }, //ADC no imm8/16

	{ 0x16, oneByte_MACRO }, { 0x17, oneByte_MACRO }, //PUSH SS, POP SS

	{ 0x18, twoByteModrm_MACRO }, { 0x19, twoByteModrm_MACRO }, { 0x1A, twoByteModrm_MACRO }, { 0x1B, twoByteModrm_MACRO },
        { 0x1C, twoByte_MACRO }, { 0x1D, trefiveByte_MACRO }, //SBB no imm8/16

	{ 0x1E, oneByte_MACRO }, { 0x1F, oneByte_MACRO }, //PUSH DS, POP DS

	{ 0x20, twoByteModrm_MACRO }, { 0x21, twoByteModrm_MACRO }, { 0x22, twoByteModrm_MACRO }, { 0x23, twoByteModrm_MACRO }, 
	{ 0x24, twoByte_MACRO }, { 0x25, trefiveByte_MACRO }, //AND no imm8/16/32

	{ 0x26, prefix_MACRO }, //prefix

	{ 0x27, oneByte_MACRO }, //DAA (decimal adjust AL after addiction)

        { 0x28, twoByteModrm_MACRO }, { 0x29, twoByteModrm_MACRO }, { 0x2A, twoByteModrm_MACRO }, { 0x2B, twoByteModrm_MACRO },
	{ 0x2C, twoByte_MACRO }, { 0x2D, trefiveByte_MACRO }, //SUB no imm8/16/32

        { 0x2E, prefix_MACRO }, //prefix

        { 0x2F, oneByte_MACRO }, //DAS (DAA for subtractions)

	{ 0x30, twoByteModrm_MACRO }, { 0x31, twoByteModrm_MACRO }, { 0x32, twoByteModrm_MACRO }, { 0x33, twoByteModrm_MACRO },
	{ 0x34, twoByte_MACRO }, { 0x35, trefiveByte_MACRO }, //XOR no imm8/16/32

	{ 0x36, prefix_MACRO }, //prefix

	{ 0x37, oneByte_MACRO }, //AAA (ascii adjust AL for addictions)

        { 0x38, oneByte_MACRO }, { 0x39, oneByte_MACRO }, { 0x3A, oneByte_MACRO }, { 0x3B, oneByte_MACRO },
	{ 0x3C, oneByte_MACRO }, { 0x3D, oneByte_MACRO }, //CMP

	{ 0x3E, prefix_MACRO }, //prefix

	{ 0x3F, oneByte_MACRO }, //AAS (AAA for subtractions)

	{ 0x40, oneByte_MACRO }, { 0x41, oneByte_MACRO }, { 0x42, oneByte_MACRO }, { 0x43, oneByte_MACRO },
	{ 0x44, oneByte_MACRO }, { 0x45, oneByte_MACRO }, { 0x46, oneByte_MACRO }, { 0x47, oneByte_MACRO }, //INC

	{ 0x48, oneByte_MACRO }, { 0x49, oneByte_MACRO }, { 0x4A, oneByte_MACRO }, { 0x4B, oneByte_MACRO },
        { 0x4C, oneByte_MACRO }, { 0x4D, oneByte_MACRO }, { 0x4E, oneByte_MACRO }, { 0x4F, oneByte_MACRO }, //DEC
  
	{ 0x50, oneByte_MACRO }, { 0x51, oneByte_MACRO }, { 0x52, oneByte_MACRO }, { 0x53, oneByte_MACRO }, 
	{ 0x54, oneByte_MACRO }, { 0x55, oneByte_MACRO }, { 0x56, oneByte_MACRO }, { 0x57, oneByte_MACRO }, //PUSH r

	{ 0x58, oneByte_MACRO }, { 0x59, oneByte_MACRO }, { 0x5A, oneByte_MACRO }, { 0x5B, oneByte_MACRO },
	{ 0x5C, oneByte_MACRO }, { 0x5D, oneByte_MACRO }, { 0x5E, oneByte_MACRO }, { 0x5F, oneByte_MACRO }, //POP r

        { 0x60, oneByte_MACRO }, { 0x61, oneByte_MACRO }, //PUSHAD, POPAD (pushano e poppano i general registers nello e dallo stack)

	{ 0x62, oneByte_MACRO }, //??
	{ 0x63, oneByte_MACRO }, //??

	{ 0x64, prefix_MACRO }, { 0x65, prefix_MACRO }, 
	{ 0x66, prefix_MACRO }, { 0x67, prefix_MACRO }, //OperandOverride and AddressOverride prefix

	{ 0x68, trefiveByte_MACRO }, //PUSH imm16/32

	{ 0x69, oneByte_MACRO }, //??

        { 0x6A, twoByte_MACRO }, //PUSH imm8

        { 0x6B, oneByte_MACRO }, //??

	{ 0x6C, oneByte_MACRO }, { 0x6D, oneByte_MACRO }, { 0x6E, oneByte_MACRO }, { 0x6F, oneByte_MACRO }, //INS, OUTS

	{ 0x70, oneByte_MACRO },
	{ 0x71, oneByte_MACRO },
	{ 0x72, oneByte_MACRO },
	{ 0x73, oneByte_MACRO },
        { 0x74, oneByte_MACRO },
        { 0x75, oneByte_MACRO },
	{ 0x76, oneByte_MACRO },
	{ 0x77, oneByte_MACRO },
	{ 0x78, twoByteModrm_MACRO },     
	{ 0x79, oneByte_MACRO },
	{ 0x7A, oneByte_MACRO },
	{ 0x7B, oneByte_MACRO },
	{ 0x7C, oneByte_MACRO },
	{ 0x7D, oneByte_MACRO },
        { 0x7E, oneByte_MACRO },
        { 0x7F, oneByte_MACRO },

	{ 0x80, oneByte_MACRO },  //??
	{ 0x81, oneByte_MACRO },  //??

	{ 0x82, twoByte_MACRO },  //MOV AL, src

	{ 0x83, oneByte_MACRO },  //??

	{ 0x84, twoByteModrm_MACRO }, { 0x85, twoByteModrm_MACRO }, //TEST

	{ 0x86, twoByteModrm_MACRO }, { 0x87, twoByteModrm_MACRO }, //XCHG r, r/m

        { 0x88, twoByteModrm_MACRO }, { 0x89, twoByteModrm_MACRO }, { 0x8A, twoByteModrm_MACRO }, { 0x8B, twoByteModrm_MACRO },
	{ 0x8C, twoByteModrm_MACRO },    // MOV r, r/m etc.., 

	{ 0x8D, twoByteModrm_MACRO }, { 0x8E, twoByteModrm_MACRO }, { 0x8F, twoByteModrm_MACRO }, //LEA, MOV sRegister, r/m, POP

	{ 0x90, oneByte_MACRO },  //NOP (XCHG EAX, EAX)

	{ 0x91, oneByte_MACRO }, { 0x92, oneByte_MACRO }, { 0x93, oneByte_MACRO }, { 0x94, oneByte_MACRO },
	{ 0x95, oneByte_MACRO }, { 0x96, oneByte_MACRO }, { 0x97, oneByte_MACRO }, //XCHG ax, ..., r

	{ 0x98, oneByte_MACRO }, //??
	{ 0x99, oneByte_MACRO }, //??
	{ 0x9A, oneByte_MACRO }, //??

	{ 0x9B, oneByte_MACRO }, //WAIT

        { 0x9C, oneByte_MACRO }, { 0x9D, oneByte_MACRO }, { 0x9E, oneByte_MACRO }, { 0x9F, oneByte_MACRO }, //PUSHFS, POPFD, SAHF, LAHF
	//SAHF, LAHF settano da AH alcuni flag dell'EFLAGS, PUSHFD, POPFD pushano nello stack l'EFLAG

	{ 0xA4, oneByte_MACRO }, { 0xA5, oneByte_MACRO }, //MOVS, MOVSD  mov ES:(E)DI, DS:(E)SI

        { 0xA6, oneByte_MACRO }, { 0xA7, oneByte_MACRO }, //CMP

	{ 0xA8, twoByte_MACRO }, { 0xA9, trefiveByte_MACRO }, //TEST

	{ 0xAA, oneByte_MACRO }, { 0xAB, oneByte_MACRO }, { 0xAC, oneByte_MACRO }, { 0xAD, oneByte_MACRO },
	{ 0xAE, oneByte_MACRO }, { 0xAF, oneByte_MACRO }, //STOS, LODS, SCAS salvano in ES:(E)DI da AX, etc..

        { 0xB0, twoByte_MACRO }, { 0xB1, twoByte_MACRO }, { 0xB2, twoByte_MACRO }, { 0xB3, twoByte_MACRO },
  	{ 0xB4, twoByte_MACRO }, { 0xB5, twoByte_MACRO }, { 0xB6, twoByte_MACRO }, { 0xB7, twoByte_MACRO }, //MOV r, r/m etc...

	{ 0xB8, trefiveByte_MACRO }, { 0xB9, trefiveByte_MACRO }, { 0xBA, trefiveByte_MACRO }, { 0xBB, trefiveByte_MACRO },
	{ 0xBC, trefiveByte_MACRO }, { 0xBD, trefiveByte_MACRO }, { 0xBE, trefiveByte_MACRO }, { 0xBF, trefiveByte_MACRO }, //MOB r, imm...

        { 0xC0, oneByte_MACRO },
        { 0xC1, oneByte_MACRO },
        { 0xC2, oneByte_MACRO },
        { 0xC3, oneByte_MACRO },
        { 0xC4, oneByte_MACRO },
        { 0xC5, oneByte_MACRO },
        { 0xC6, oneByte_MACRO },
        { 0xC7, oneByte_MACRO },
        { 0xC8, oneByte_MACRO },
        { 0xC9, oneByte_MACRO },
        { 0xCA, oneByte_MACRO },
        { 0xCB, oneByte_MACRO },
        { 0xCC, oneByte_MACRO },
        { 0xCD, oneByte_MACRO },
        { 0xCE, oneByte_MACRO },
        { 0xCF, oneByte_MACRO },

	{ 0xD0, oneByte_MACRO },
	{ 0xD1, oneByte_MACRO },  
	{ 0xD2, trefiveByte_MACRO },        
	{ 0xD3, trefiveByte_MACRO }, 
        { 0xD4, trefiveByte_MACRO },
	{ 0xD5, trefiveByte_MACRO }, 
	{ 0xD6, trefiveByte_MACRO },        
	{ 0xD7, trefiveByte_MACRO }, 
        { 0xD8, trefiveByte_MACRO },
	{ 0xD9, trefiveByte_MACRO },
	{ 0xDA, trefiveByte_MACRO },        
	{ 0xDB, trefiveByte_MACRO }, 
        { 0xDC, trefiveByte_MACRO },
	{ 0xDD, trefiveByte_MACRO },
	{ 0xDE, trefiveByte_MACRO },
	{ 0xDF, trefiveByte_MACRO },

	{ 0xE0, trefiveByte_MACRO },
	{ 0xE1, trefiveByte_MACRO },
	{ 0xE2, trefiveByte_MACRO },
	{ 0xE3, trefiveByte_MACRO },
	{ 0xE4, trefiveByte_MACRO },
	{ 0xE5, trefiveByte_MACRO },
	{ 0xE6, trefiveByte_MACRO },       
	{ 0xE7, trefiveByte_MACRO }, 
        { 0xE8, trefiveByte_MACRO },
	{ 0xE9, trefiveByte_MACRO }, 
	{ 0xEA, trefiveByte_MACRO },
	{ 0xEB, trefiveByte_MACRO },
	{ 0xEC, trefiveByte_MACRO },
	{ 0xED, trefiveByte_MACRO },
	{ 0xEE, trefiveByte_MACRO },
	{ 0xEF, trefiveByte_MACRO },

	{ 0xF0, prefix_MACRO }, //prefix LOCK 

	{ 0xF1, trefiveByte_MACRO }, 

        { 0xF2, prefix_MACRO }, { 0xF3, prefix_MACRO }, //prefix REPNE, REPE

	{ 0xF4, trefiveByte_MACRO },        
	{ 0xF5, trefiveByte_MACRO }, 
        { 0xF6, trefiveByte_MACRO },
	{ 0xF7, trefiveByte_MACRO },
	{ 0xF8, trefiveByte_MACRO },
	{ 0xF9, trefiveByte_MACRO },
	{ 0xFA, trefiveByte_MACRO },
	{ 0xFB, trefiveByte_MACRO },
	{ 0xFC, trefiveByte_MACRO },
	{ 0xFD, trefiveByte_MACRO },
	{ 0xFE, trefiveByte_MACRO },
	{ 0xFF, trefiveByte_MACRO },


};

#endif 
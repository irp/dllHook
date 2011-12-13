#ifndef __BITCH_H__
#define __BITCH_H__

#include <Windows.h>
#include <stdio.h>

#include "yap.h"

PBYTE try_dis (__in PBYTE p_where,
	       __in PBYTE pb_from) {

	PINSTRUCTION_TABLE pInsTab = &deco[pb_from[0]];
	printf("opcode: %x\n", pb_from[0]);

	return (pInsTab->disasmFunc)((struct _INSTRUCTION_TABLE*)pInsTab, p_where, pb_from);


}

extern "C" PPONTE NTAPI set_ponte
	() {

	/*	MEMORY_BASIC_INFORMATION mem_inf;
		SIZE_T returned_buff = VirtualQuery(pTar, &mem_inf, sizeof(mem_inf));						   
		if (returned_buff == 0) { printf("No bytes returned in the info buffer\n"); return NULL; } */

	PVOID pAdd = VirtualAlloc(NULL, 0x10000, 
				  MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (pAdd != NULL) {
		 printf ("Memory allocated for ponte, looking for write permissions!\n");
		 DWORD Oldpro;
		 VirtualProtect(pAdd, 0x10000, PAGE_EXECUTE_READWRITE, &Oldpro);
		 PPONTE pPonte = (PPONTE)pAdd;
		 ZeroMemory(pPonte->copied, sizeof(PONTE)); 
		 ZeroMemory(&pPonte->phook, sizeof(PONTE));
		 printf("Now memory is filled by zeros.\n");
		 return pPonte; }

	return NULL;

}

extern "C" VOID NTAPI stuff
	(__in PBYTE pTar,
	 __in PVOID pfHook) {

		 DWORD oldPro;
		 printf("Setting WRITE access on 5 bytes target.\n");
	 	 VirtualProtect(pTar, 0x1000, PAGE_EXECUTE_READWRITE, &oldPro);
		 PPONTE pPonte;
		 pPonte = set_ponte();
		 if (pPonte == NULL) { printf("Cannot allocate ponte.\n"); }
		 else { 
		 pPonte->phook = pfHook;  
		 int count = 0, jmpSize = 5;
		 PBYTE pbTar = pTar;
		 while (count < jmpSize) {  

			 PBYTE oldpTar = pTar;
			 pTar = try_dis(&pPonte->copied[count], pTar);			 

			 if (modrm_on == TRUE) {
				RtlCopyMemory(&pPonte->copied[count+1], &oldpTar[1], 1); 
				count++; } 

	          count++; 

	          }

		  printf("Stuff copied in ponte, writing jmp in the first 5 bytes...\n");
		  PBYTE jmpToHookBytes = pbTar + 5; //5 bytes jmp immediate, first instruction after jmp
		  *pbTar++ = 0xe9;
		  *((signed int*&)pbTar)++ = (signed int)((PBYTE)pfHook - jmpToHookBytes);

		  *pTar++=0xe9;
		  *((signed int*&)pTar)++ = (signed int)(jmpToHookBytes - (pTar + 5));
		  printf("Jmp in Ponte!\n");

          }

}

/* 
extern "C" VOID NTAPI dis_jmpE9  (__in PBYTE pb_from,
	                          __in DWORD entry_point) {
					
	WORD addr16;
	BYTE first = pb_from[1];
	BYTE second = pb_from[2];

	 __asm { push ebx									         
	         mov bl, first
		 mov bh, second
		 mov addr16, bx
		 pop ebx }
									 					

}
*/
									
#endif
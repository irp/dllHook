/* This is the file.dll called by loader.exe, it just hook OpenProcess with a jmp to an ExitProcess(0) call */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "bitch.h"


extern "C" VOID NTAPI HookFunc() {     ExitProcess(0);    }

BOOL WINAPI DllMain(
  __in  HINSTANCE hinstDLL,
  __in  DWORD fdwReason,
  __in  LPVOID lpvReserved
) {

	if (fdwReason == DLL_PROCESS_ATTACH) {

	    HMODULE hModule = LoadLibraryEx(TEXT("kernel32.dll"), NULL, 0);
	    if (hModule == NULL) { printf("LoadLibrary failed with code:%d\n", GetLastError()); }
	    PBYTE procAdd = (PBYTE)GetProcAddress(hModule, "OpenProcess");
	    if (procAdd == NULL) { printf("GetProcAddress failed with code:%d\n", GetLastError()); }
	    printf("PBYTE procAdd: %x\n", *procAdd);
	    stuff(procAdd, HookFunc);

	}

	return TRUE;

}
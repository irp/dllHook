#include <windows.h>
#include <stdio.h>
#include <Tlhelp32.h>
#include <tchar.h>

int __cdecl main (int argc, 
	          char **argv) {

	printf("Select the process: %s", argv[1]);
	int a = getchar();

	/* Get pid from process name and inject file.dll into the target address space 
	   NOTE: kernel32.dll is mapped at the same address for every process in the system */
	   
	HANDLE hThread, hProc;
	LPVOID pBase;
	DWORD pID; 
	PROCESSENTRY32 lppe = {sizeof (PROCESSENTRY32)};
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) { printf("Cannot get the snapshot of all processes.\n"); }
        BOOL first = Process32First(hSnap, &lppe);	                                    
	if (first == TRUE) {
		while (Process32Next(hSnap, &lppe) == TRUE) {

			if (strcmp(lppe.szExeFile, argv[1]) == 0) {	

				__try {

				    pID = lppe.th32ProcessID; 
				    
				    hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
	                            if (hProc == NULL) { 
					    printf("Cannot open desired process.\n");
					    __leave; } 

	                            HMODULE hModule = LoadLibraryEx(TEXT("kernel32.dll"), NULL, 0);
	                            if (hModule == NULL) { 
					    printf("LoadLibrary failed with code:%d\n", GetLastError()); 
					    __leave; }
	                            PTHREAD_START_ROUTINE procAdd = (PTHREAD_START_ROUTINE)GetProcAddress(hModule, 
	                                                                                           "LoadLibraryA");

	                            pBase = VirtualAllocEx(hProc, NULL, sizeof("C:\\file.dll"),
						           MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);	
	                            if (pBase == NULL) { 
					    printf("Cannot allocate in page region.\n");
					    __leave; }
	                            if(!WriteProcessMemory(hProc, pBase, "C:\\file.dll", sizeof("C:\\file.dll"), NULL)) {
					    printf("Cannot write in process memory.\n"); 
					    __leave; }

	                            hThread = CreateRemoteThread(hProc, NULL, 0, procAdd, pBase, 0, NULL);
	                            if (hThread == NULL) {
					    printf("Cannot create the thread.\n"); 
					    __leave; }
				    }
				
				__finally {

					if (hThread != NULL) { CloseHandle(hThread); }
					if (hProc != NULL) { CloseHandle(hProc); }
					if (pBase != NULL) { VirtualFreeEx(hProc, pBase, sizeof("C:\\file.dll"),
						                           MEM_RELEASE); }
						                           
			        } 
				
	                printf("Dll injected\n");
			    
		        break;
		        
			}
        
		}

	}

	else { printf("Cannot find first process in snapshot list.\n"); }

        CloseHandle(hSnap);

	/*    */ 
    
	int c = getchar();
	return 0;

}



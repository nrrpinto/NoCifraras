// ProcList.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <Windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <TlHelp32.h>
#include <strsafe.h>

int maxCOUNT = 256;
bool first = true;

int Error(const char* text) {
	printf("%s (%d)\n", text, GetLastError());
	return 1;
}

int ReadProcesses(_Inout_ DWORD* pids, _Inout_ wchar_t** pidName) {

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return Error("Failed to create snapshot");

	PROCESSENTRY32W pe;

	pe.dwSize = sizeof(pe);

	if (!Process32First(hSnapshot, &pe))
		return Error("Failed in Process32First");

	int i = 0;
	

	do {
		//printf("PID:%6d (PPID:%6d): %30ws (Threads=%d) (Priority=%d)\n",
		//	pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile, pe.cntThreads, pe.pcPriClassBase);
		if (i > maxCOUNT - 1) return 1;
		
		// Captured PID
		pids[i] = (DWORD) malloc(sizeof(DWORD));
		pids[i] = pe.th32ProcessID;

		// Captures process name of the PID
		size_t size = wcslen(pe.szExeFile) + 1;
		pidName[i] = calloc(size, sizeof(wchar_t));
		if (pidName[i]) {
			wcscpy_s(pidName[i], size, pe.szExeFile);
		}
		else {
			wprintf(L"A pidName[i] is NULL");
		}
		
		//pidName[i] = pe.szExeFile;

		//wprintf(L"## PID: %5d | Name:  %10ws\n", pids[i], pidName[i]);

		// LAST
		i++;
	} while (Process32Next(hSnapshot, &pe));

	CloseHandle(hSnapshot);

	return i;
}

int copy_pids_name(_In_ wchar_t** pidNameSrc, _Inout_ wchar_t** pidNameDst, _In_ int numCurrProcesses) {
	for (int i = 0;i < numCurrProcesses;i++) {
		size_t size = wcslen(pidNameSrc[i]) + 1;
		pidNameDst[i] = calloc(size, sizeof(wchar_t));
		wcscpy_s(pidNameDst[i], size, pidNameSrc[i]);
	}
	return 1;
}

int find_differences(	_In_ wchar_t** pidList1, 
						_In_ wchar_t** pidList2) {
	WORD diff_pid_num = { 0 };
	return 0;
}

int get_pids_diff(	_In_ DWORD* ProcNumber1, 
					_In_ DWORD* ProcNumber2, 
					_In_ int iterator1,	
					_In_ int iterator2, 
					_Out_ DWORD* pids_change, 
					_Out_ int* num_pids_changed) {

	int k = 0;
	for (int i = 0;i < iterator1;i++) {
		bool exists = false;
		for (int j = 0;j < iterator2;j++) {
			if (ProcNumber1[i] == ProcNumber2[j]) {
				exists = true;
				break;
			}
		}
		if (!exists) {
			pids_change[k] = (DWORD)malloc(sizeof(DWORD));
			pids_change[k] = ProcNumber1[i];
			k++;
		}
	}
	*num_pids_changed = k;
	return 0;
}

int list_pids_changed(_In_ DWORD* pids_change, _In_ int changed) {
	wprintf(L"PIDS Changed: ");
	for (int i = 0; i < changed;i++) {
		wprintf(L"\t%d\n", pids_change[i]);
	}
	return 0;
}

int main() {
	
	DWORD* pids = calloc(maxCOUNT, sizeof(DWORD));
	DWORD* pids_old = calloc(maxCOUNT, sizeof(DWORD));
	
	wchar_t** pidName = calloc(maxCOUNT, sizeof(wchar_t*));
	wchar_t** pidName_old = calloc(maxCOUNT, sizeof(wchar_t*));

	// numOldProcesses - contains the number of old processes
	int numOldProcesses = 0;
	int pids_change_size = 254;
	DWORD* pids_change = calloc(pids_change_size,sizeof(DWORD)); // buffer to keep record of processes changed - It means terminated or created.


	for (;;) {
		ZeroMemory(pids, maxCOUNT);
		ZeroMemory(pidName, maxCOUNT);
		
		// numCurrProcesses - contains the number of current processes
		int numCurrProcesses = 0;

		if (pidName) {
			numCurrProcesses = ReadProcesses(pids, pidName);
		}
		else {
			wprintf(L"The pidName variable is NULL");
		}
		
		if (numCurrProcesses == 1) {
			maxCOUNT *= 2;
			continue;
		}

		for (int j = 0;j < numCurrProcesses;j++) {
			wprintf(L"@@[%d]@ PID: %5d | Name:  %10ws\n",j, pids[j], pidName[j]);
		}

		if (first) {
			first = false;
			pids_old = pids;
			numOldProcesses = numCurrProcesses;
			continue;
		}

		wprintf(L"numCurrProcesses %d\n", numCurrProcesses);
		wprintf(L"numOldProcesses %d\n", numOldProcesses);

		int num_pids_changed = 0;

		if (numOldProcesses > 0 && numCurrProcesses > 0 && numOldProcesses > numCurrProcesses) {
			wprintf(L"Processes terminated.\n");
			int re = get_pids_diff(pids_old, pids, numOldProcesses, numCurrProcesses, pids_change, &num_pids_changed);
		}
		else if (numOldProcesses > 0 && numCurrProcesses > 0 && numOldProcesses < numCurrProcesses) {
			wprintf(L"Processes started.\n");
			int re = get_pids_diff(pids, pids_old, numCurrProcesses, numOldProcesses, pids_change, &num_pids_changed);
		}

		wprintf(L"Pids changed: %d\n", num_pids_changed);

		list_pids_changed(pids_change, num_pids_changed);
		
		// Clean pids_old before fill it with more information
		ZeroMemory(pids_old, maxCOUNT);
		ZeroMemory(pidName_old, maxCOUNT);
		// Set the old PID array
		pids_old = pids;
		numOldProcesses = numCurrProcesses;

		// Get char to make the screen stop
		char c = getchar();
		if (c == 'e') return 0;
	}
}
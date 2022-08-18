// ProcList.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <Windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <TlHelp32.h>
#include <strsafe.h>
#include <Psapi.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#pragma warning(disable : 4996)
#pragma warning(disable : 2371)
#pragma warning(disable : 6387)
#pragma warning(disable : 28193)
//#include "..\Injector\Injector.h"

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

#ifndef MAX_BUF
#define MAX_BUF 200
#endif

int maxCOUNT = 256;
bool first = true;
char DLLMonitor86[] = "f4d0mon86.dll";
char DLLMonitor64[] = "f4d0mon64.dll";
char InjectorEXE86[] = "Injector86.exe";
char InjectorEXE64[] = "Injector64.exe";
const wchar_t white_list[] = L"C:\\windows\\white_list.exe";

int Error(const char* text) {
	printf("%s (%d)\n", text, GetLastError());
	return 1;
}

/*
*/
DWORD GetProcessBit(_In_ int ProcessID)
{
	typedef BOOL(WINAPI* pfnIsWow64Process)(HANDLE, PBOOL);

	// Open a handle to the target process
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);
	if (!hProcess)
		return Error("[GetProcessBit] Failed to open process");

	BOOL IsWoW64 = FALSE;

	HMODULE hModule = GetModuleHandleW(L"kernel32");

	if (hModule)
	{
		pfnIsWow64Process IsWow64Process = (pfnIsWow64Process)GetProcAddress(hModule, "IsWow64Process");

		if (IsWow64Process(hProcess, &IsWoW64))
			return IsWoW64 ? 32 : 64;
	}
	return 0;
}

/*
*/
LPCWSTR GetProcessNamebyID(_In_ DWORD ProcessID)
{
	LPCWSTR ProcessName = L"";

	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32W ProcessEntry = { 0 };

		ProcessEntry.dwSize = sizeof(ProcessEntry);

		if (Process32FirstW(hProcessSnap, &ProcessEntry))
		{
			do {
				if (ProcessEntry.th32ProcessID == ProcessID)
				{
					ProcessName = ProcessEntry.szExeFile;
					break;
				}
			} while (Process32NextW(hProcessSnap, &ProcessEntry));
		}
		CloseHandle(hProcessSnap);
	}
	return ProcessName;
}

LPWSTR GetFullpathbyID(_In_ int ProcessID)
{
	LPWSTR tempFullPath = malloc(MAX_PATH);

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessID);
	if (hProcess == NULL)
	{
		printf("Handle ISSUE!\n");
		return FALSE;
	}
	if (GetModuleFileNameExW(hProcess, NULL, tempFullPath, MAX_PATH * 2) != 0)
	{
		return tempFullPath;
	}
	else
	{
		printf("Here 2\n");
		return FALSE;
	}
}

BOOL WriteToWhiteList(_In_ char* hash)
{
	HANDLE hFile;
	hFile = CreateFile(white_list,
		GENERIC_READ | FILE_APPEND_DATA,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
		//FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_FILE_NOT_FOUND)
		{
			hFile = CreateFile(white_list,
				GENERIC_READ | FILE_APPEND_DATA,
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				NULL,
				CREATE_NEW,
				FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
				//FILE_ATTRIBUTE_NORMAL,
				NULL);
		}
		else
		{
			CloseHandle(hFile);
			return FALSE;
		}
	}

	DWORD dwMoved = SetFilePointer(hFile, 0l, NULL, FILE_END);
	if (dwMoved == INVALID_SET_FILE_POINTER) {
		printf("Terminal failure: Unable to set file pointer to end-of-file.\n");
		return FALSE;
	}

	DWORD bytesWritten;
	DWORD result1 = WriteFile(hFile, hash, strlen(hash), &bytesWritten, NULL);

	printf("Bytes written %d\n", bytesWritten);

	char newline[] = "\n";
	DWORD result2 = WriteFile(hFile, newline, strlen(newline), &bytesWritten, NULL);

	CloseHandle(hFile);

	if (result1 != 0 && result2 != 0)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL isInWhiteListHash(_In_ const char* hash)
{
	HANDLE hFile;
	hFile = CreateFile(white_list,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
		return FALSE;
	}

	int i = 0;
	for (;;)
	{
		BOOL result;
		LPVOID lpBuffer = (char*)malloc(64);
		LPVOID lpBufferDelete = (char*)malloc(1);
		i++;
		result = ReadFile(hFile, lpBuffer, 64, NULL, NULL);
		if (strlen(lpBuffer) != 64)
		{
			CloseHandle(hFile);
			return FALSE;
		}
		if (CompareStringA(LOCALE_USER_DEFAULT, LINGUISTIC_IGNORECASE, lpBuffer, 64, hash, 64) == CSTR_EQUAL)
		{
			CloseHandle(hFile);
			return TRUE;
		}

		result = ReadFile(hFile, lpBufferDelete, 1, NULL, NULL);
		VirtualFree(lpBuffer, 0, MEM_RELEASE);

	}

	CloseHandle(hFile);
	return FALSE;
}

void CleanCalculate(BCRYPT_ALG_HANDLE hAlg, BCRYPT_HASH_HANDLE hHash, PBYTE pbHashObject, PBYTE pbHash)
{
	if (hAlg)
		BCryptCloseAlgorithmProvider(hAlg, 0);

	if (hHash)
		BCryptDestroyHash(hHash);

	if (pbHashObject)
		HeapFree(GetProcessHeap(), 0, pbHashObject);

	if (pbHash)
		HeapFree(GetProcessHeap(), 0, pbHash);
}

char* CalculateSHA256(_In_ LPCWSTR FilePath)
{

	BCRYPT_ALG_HANDLE       hAlg = NULL;
	BCRYPT_HASH_HANDLE      hHash = NULL;
	NTSTATUS                status = STATUS_UNSUCCESSFUL;
	DWORD                   cbData = 0,
		cbHash = 0,
		cbHashObject = 0;
	PBYTE                   pbHashObject = NULL;
	PBYTE                   pbHash = NULL;

	//open an algorithm handle
	if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
		&hAlg,
		BCRYPT_SHA256_ALGORITHM,
		NULL,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
		CleanCalculate(hAlg, hHash, pbHashObject, pbHash);
		return;
	}

	//calculate the size of the buffer to hold the hash object
	if (!NT_SUCCESS(status = BCryptGetProperty(
		hAlg,
		BCRYPT_OBJECT_LENGTH,
		(PBYTE)&cbHashObject,   //Address of buffer that received the property value - BUFFER SIZE TO HOLD THE HASH
		sizeof(DWORD),
		&cbData,                //Number of bytes that were copied to the cbHashObject buffer
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
		CleanCalculate(hAlg, hHash, pbHashObject, pbHash);
		return;
	}

	//allocate the hash object on the heap
	pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
	if (NULL == pbHashObject)
	{
		wprintf(L"**** memory allocation failed\n");
		CleanCalculate(hAlg, hHash, pbHashObject, pbHash);
		return;
	}

	//calculate the length of the hash
	if (!NT_SUCCESS(status = BCryptGetProperty(
		hAlg,
		BCRYPT_HASH_LENGTH,
		(PBYTE)&cbHash,         //Address of buffer that received the property value - HASH LENGTH
		sizeof(DWORD),
		&cbData,                //Number of bytes that were copied to the cbHashObject buffer
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
		CleanCalculate(hAlg, hHash, pbHashObject, pbHash);
		return;
	}

	//allocate the hash buffer on the heap
	pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
	if (NULL == pbHash)
	{
		wprintf(L"**** memory allocation failed\n");
		CleanCalculate(hAlg, hHash, pbHashObject, pbHash);
		return;
	}

	//create a hash
	if (!NT_SUCCESS(status = BCryptCreateHash(
		hAlg,
		&hHash,
		pbHashObject,
		cbHashObject,
		NULL,
		0,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptCreateHash\n", status);
		CleanCalculate(hAlg, hHash, pbHashObject, pbHash);
		return;
	}

	// Open file to hash
	HANDLE hFile;
	hFile = CreateFile(FilePath,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	DWORD fSize = GetFileSize(hFile, &fSize);
	BOOL result;
	LPVOID lpBuffer = (char*)malloc(fSize);
	DWORD readBytes = 1;
	// Read file to hash and store it on a buffer
	result = ReadFile(hFile, lpBuffer, fSize, &readBytes, NULL);
	
	// Hash the content of the file
	if (!NT_SUCCESS(status = BCryptHashData(hHash, (PCWSTR)lpBuffer, fSize, 0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptFinishHash\n", status);
		CleanCalculate(hAlg, hHash, pbHashObject, pbHash);
		CloseHandle(hFile);
		VirtualFree(lpBuffer, 0, MEM_RELEASE);
		return;
	}

	//close the hash
	if (!NT_SUCCESS(status = BCryptFinishHash(
		hHash,
		pbHash,
		cbHash,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptFinishHash\n", status);
		CleanCalculate(hAlg, hHash, pbHashObject, pbHash);
		CloseHandle(hFile);
		VirtualFree(lpBuffer, 0, MEM_RELEASE);
		return;
	}

	char* hashResult = malloc(65 * sizeof(char));
	char* str_buf = malloc(5 * sizeof(char));
	memset(hashResult, 0, 65 * sizeof(char));
	memset(str_buf, 0, 5 * sizeof(char));
	for (int i = 0; i < 32; ++i)
	{
		sprintf_s(str_buf, 4, "%02x", pbHash[i]);
		//printf("%s", str_buf);
		strcat_s(hashResult, 65, str_buf);
		//printf("%02x", pbHash[i]);
	}
	hashResult[64] = 0x0D;
	// printf("\nThe HASH: %s\n", hashResult);

	CleanCalculate(hAlg, hHash, pbHashObject, pbHash);
	CloseHandle(hFile);
	VirtualFree(lpBuffer, 0, MEM_RELEASE);
	VirtualFree(str_buf, 0, MEM_RELEASE);

	return hashResult;
	
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
		//pidNameDst[i] = calloc(size, sizeof(wchar_t));
		if(pidNameDst[i] != 0)
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
					_Out_ int* num_pids_changed) 
{

	int k = 0;
	for (int i = 0;i < iterator1;i++) 
	{
		bool exists = false;
		for (int j = 0;j < iterator2;j++) 
		{
			if (ProcNumber1[i] == ProcNumber2[j]) 
			{
				exists = true;
				break;
			}
		}
		if (!exists) 
		{
			//pids_change[k] = (DWORD)malloc(sizeof(DWORD));
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
	DWORD* pids_change = (DWORD *)calloc(pids_change_size,sizeof(DWORD)); // buffer to keep record of processes changed - It means terminated or created.

	const int buffer_size = 400;
	
	char space[] = " ";
	
	char path[MAX_BUF];

	getcwd(path, MAX_BUF);

	int numCurrProcesses = 0;
	int num_pids_changed = 0;

	
	

	for (;;) {
		ZeroMemory(pids, maxCOUNT);
		ZeroMemory(pidName, maxCOUNT);
		
		// numCurrProcesses - contains the number of current processes
		numCurrProcesses = 0;

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
			//wprintf(L"@@[%d]@ PID: %5d | Name:  %10ws\n",j, pids[j], pidName[j]);
		}

		if (first) {
			first = false;
			pids_old = pids;
			numOldProcesses = numCurrProcesses;
			continue;
		}

		// wprintf(L"numCurrProcesses %d\n", numCurrProcesses);
		// wprintf(L"numOldProcesses %d\n", numOldProcesses);

		num_pids_changed = 0;

		if (numOldProcesses > 0 && numCurrProcesses > 0 && numOldProcesses > numCurrProcesses) {
			//int re = get_pids_diff(pids_old, pids, numOldProcesses, numCurrProcesses, pids_change, &num_pids_changed);
			//for (int i = 0; i < num_pids_changed;i++)
			//{
			//  wprintf(L"#### TERMINATING PROCESS ######################################\n");
			//	wprintf(L"[MAIN] [Processes terminated] [PID: %d] [PNAME: %ws] \n", pids_change[i]);
			//}
		}
		else if (numOldProcesses > 0 && numCurrProcesses > 0 && numOldProcesses < numCurrProcesses) {
			
			
			int re = get_pids_diff(pids, pids_old, numCurrProcesses, numOldProcesses, pids_change, &num_pids_changed);

			for (int i = 0; i < num_pids_changed;i++) 
			{
				wprintf(L"#### NEW PROCESS ##############################################\n");
				// Basic info of the PID and Process name
				LPCWSTR ProcessName = L"";
				ProcessName = GetProcessNamebyID(pids_change[i]);
				wprintf(L"[MAIN] [Processes started] [PID: %d] [PNAME: %ws] \n", pids_change[i], ProcessName);

				// Manage existence of the hash in the white list
				LPWSTR FullPath = GetFullpathbyID(pids_change[i]);
				wprintf(L"[MAIN] FULLPATH: \"%ws\"\n", FullPath);
				//char* thisFileHash = CalculateSHA256(FullPath);
				//printf("[MAIN] HASH: %s\n", thisFileHash);

				//if (isInWhiteListHash(thisFileHash))
				//{
				//	wprintf(L"[MAIN] [PID: %d] [FullPath: %ws] File IS in white list! NOT injecting the monitor DLL.\n", pids_change[i], FullPath);
				//	continue;
				//}
				//else 
				//{
				//	wprintf(L"[MAIN] [PID: %d] [FullPath: %ws] File NOT in white list! Will inject monitor DLL.\n", pids_change[i], FullPath);
				//}

				// Get BITNESS of the process
				DWORD bitness = GetProcessBit(pids_change[i]);
				if (!(bitness == 32 || bitness == 64))
				{
					wprintf(L"[MAIN] [PID: %d] [PNAME: %ws] Issue identifying Bitness: %d NOT injecting the monitor DLL.\n", pids_change[i], ProcessName, bitness);
					continue;
				}
				
				// Create fullpathfor DLLMonitor
				char DLLPath[150] = " ";
				strcat_s(DLLPath, 150, "\"");
				strcat_s(DLLPath, 150, path);
				strcat_s(DLLPath, 150, "\\");
				if(bitness == 32)
					strcat_s(DLLPath, 150, DLLMonitor86);
				else if (bitness == 64)
					strcat_s(DLLPath, 150, DLLMonitor64);

				strcat_s(DLLPath, 150, "\"");
				
				// Create the command line to inject the DLL
				char command_line[400] = " ";
				char pid[6];
				_itoa_s(pids_change[i], pid, 6, 10);
				
				if (bitness == 32)
					strcat_s(command_line, buffer_size, InjectorEXE86);
				else if (bitness == 64)
					strcat_s(command_line, buffer_size, InjectorEXE64);

				strcat_s(command_line, buffer_size, space);
				strcat_s(command_line, buffer_size, pid);
				strcat_s(command_line, buffer_size, space);
				strcat_s(command_line, buffer_size, DLLPath);

				// Print and execute the command line that will INJECT the Monitor DLL 
				//printf("[MAIN] [DEBUG] COMMAND LINE: ");
				//printf(command_line);printf("\n");
				system(command_line);
				
				// Free resources
				VirtualFree(command_line, 0, MEM_RELEASE);
				VirtualFree(DLLPath, 0, MEM_RELEASE);
			}
		}

		if (num_pids_changed > 0) {
			//wprintf(L"Pids changed: %d\n", num_pids_changed);
			//list_pids_changed(pids_change, num_pids_changed);
		}
		
		// Clean pids_old before fill it with more information
		/*if(pids_old != 0)
			ZeroMemory(pids_old, maxCOUNT);
		if(pidName_old != 0)
			ZeroMemory(pidName_old, maxCOUNT);*/
		ZeroMemory(pids_old, maxCOUNT);
		ZeroMemory(pidName_old, maxCOUNT);
		// Set the old PID array
		pids_old = pids;
		numOldProcesses = numCurrProcesses;

		// Get char to make the screen stop
		/*char c = getchar();
		if (c == 'e') return 0;*/
		Sleep(1);
	}
}

#include <Windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <TlHelp32.h>
#include <strsafe.h>
#include <bcrypt.h>
#include <Psapi.h>
#include <wchar.h>
#include <string.h>
#pragma comment(lib, "bcrypt.lib")


LPWSTR GetFullpathbyID(_In_ int ProcessID)
{
	LPWSTR tempFullPath = malloc(MAX_PATH);

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessID);
	if (hProcess == NULL)
	{
		printf("Handle ISSUE!\n");
		return FALSE;
	}
	if (GetModuleFileNameExW(hProcess, NULL, tempFullPath, MAX_PATH*2) != 0)
	{
		return tempFullPath;
	}
	else
	{
		printf("Here 2\n");
		return FALSE;
	}
}

void main(int argc, char** argv)
{
	int PID = (int)argv[1];
	LPWSTR FullPath = GetFullpathbyID(12804);
	if(wcslen(FullPath) > 0)
		printf("Path successfully collected!\n");
	else
		printf("Error getting FullPath!\n");
	//wprintf(L"The path is: %ws\n", FullPath);
	wprintf(L"FULL PATH: %ws",FullPath);
}
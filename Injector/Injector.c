#include "Injector.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <winnt.h>

#pragma warning(disable : 4996)

SYSTEM_INFO SystemInfo;

int Error(const char* msg) {
	printf("%s | (%u)\n", msg, GetLastError());
	return FALSE;
}

/*
*/
DWORD GetProcessBit(_In_ HANDLE ProcessHandle)
{
	typedef BOOL(WINAPI* pfnIsWow64Process)(HANDLE, PBOOL);

	BOOL IsWoW64 = FALSE;

	HMODULE hModule = GetModuleHandleW(L"kernel32");

	if (hModule)
	{
		pfnIsWow64Process IsWow64Process = (pfnIsWow64Process)GetProcAddress(hModule, "IsWow64Process");

		if (!IsWow64Process)
			return 32;

		if (IsWow64Process(ProcessHandle, &IsWoW64))
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

int isDllInjected(HANDLE hProcess, char* DLLname)
{
	HMODULE hMods[1024];
	DWORD cbNeeded;
	unsigned int i;

	// Get a list of all the modules in this process.

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];

			// Get the full path to the module's file.
			if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
			{
				//_tprintf(TEXT("\t%s (0x%08X)\n"), szModName, hMods[i]);
				int size = wcslen(szModName) + 1;
				char vOut[MAX_PATH];
				wcstombs_s(NULL, vOut, wcslen(szModName) + 1, szModName, wcslen(szModName) + 1);

				if (strstr(vOut, DLLname) != NULL)
				{
					//_tprintf(TEXT("\t%s (0x%08X)\n"), szModName, hMods[i]);
					return TRUE;
				}

			}
		}
	}

	return FALSE;
}

BOOLEAN SetProcessPrivilege(_In_ HANDLE hProcess, _In_ LPCWSTR PrivilegeName, _In_ BOOLEAN EnablePrivilege, _In_opt_ PBOOLEAN IsEnabled)
{
	BOOLEAN Result = FALSE;

	HANDLE TokenHandle = 0;

	if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle))
	{
		LUID Luid = { 0 };

		if (LookupPrivilegeValueW(NULL, PrivilegeName, &Luid))
		{
			TOKEN_PRIVILEGES PreviousState = { 0 }, NewState = { 0 };

			NewState.PrivilegeCount = 1;
			NewState.Privileges[0].Luid = Luid;
			NewState.Privileges[0].Attributes = EnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

			DWORD ReturnLength = 0;

			Result = AdjustTokenPrivileges(TokenHandle, FALSE, &NewState, sizeof(TOKEN_PRIVILEGES), &PreviousState, &ReturnLength);

			if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
			{
				SetLastError(ERROR_PRIVILEGE_NOT_HELD);
				Result = FALSE;
			}
			else if (Result && IsEnabled)
			{
				if (PreviousState.PrivilegeCount == 0)
					*IsEnabled = EnablePrivilege;
				else
					*IsEnabled = (PreviousState.Privileges[0].Attributes & SE_PRIVILEGE_ENABLED) ? TRUE : FALSE;
			}
		}
		CloseHandle(TokenHandle);
	}
	return Result;
}

// Credits to CAPEMON Loader
PIMAGE_NT_HEADERS GetNtHeaders(PVOID BaseAddress)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)BaseAddress;

	__try
	{
		if (!pDosHeader->e_lfanew)
		{
			printf("[GetNtHeaders] pointer to PE header zero.\n");
			return NULL;
		}

		return (PIMAGE_NT_HEADERS)((PBYTE)BaseAddress + pDosHeader->e_lfanew);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		printf("[GetNtHeaders] Exception occurred reading around base address 0x%p\n", BaseAddress);
		return NULL;
	}
}

// Traditional VirtualAllocEx, WriteProcessMemory, LoadLibraryA, CreateRemoteThread
int standard_DLL_injection(_In_ HANDLE hProcess, _In_ int _pid, _In_ const char* _dllpath)
{
	// Prepare DLL path to load
	void* buffer = VirtualAllocEx(hProcess, NULL, 1 << 16, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!buffer)
		return Error("Failed to allocate buffer in target process");

	// Copy the DLL path to the allocated buffer
	if (!WriteProcessMemory(hProcess, buffer, _dllpath, strlen(_dllpath) + 1, NULL))
		return Error("Failed to write to target process");

	DWORD tid;
	LPTHREAD_START_ROUTINE lpsr = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"Kernel32"), "LoadLibraryA");
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, lpsr, buffer, 0, &tid);
	if (!hThread)
		return Error("Failed to create remote thread");

	printf("Thread %u created successfully!\n", tid);
	if (WAIT_OBJECT_0 == WaitForSingleObject(hThread, 10000))
		printf("Thread exited.\n");
	else
		printf("Thread still haging around ...\n");

	// 
	VirtualFreeEx(hProcess, buffer, 0, MEM_RELEASE);

	CloseHandle(hThread);

	return TRUE;
}

// Reflective Inject DLL via thread - credit to CAPEMON Loader
int reflective_DLL_injection(_In_ HANDLE hProcess, _In_ const char* _dllpath)
{
	SIZE_T FileSize, BytesRead;
	void* Buffer, * RemoteBuffer, * RemoteEntryPoint;
	OSVERSIONINFO OSVersion;
	SIZE_T BytesWritten;
	HANDLE hFile, RemoteThreadHandle;
	DWORD ExitCode;
	_RtlCreateUserThread RtlCreateUserThread;
	_RtlNtStatusToDosError RtlNtStatusToDosError;
	int RetVal = 0;

	if (!SystemInfo.dwPageSize)
		GetSystemInfo(&SystemInfo);

	if (!SystemInfo.dwPageSize)
	{
		Error("[reflective_DLL_injection] Failed to obtain system page size");
	}
	printf("_dllpath: %s ",_dllpath);
	hFile = CreateFileA(_dllpath, GENERIC_READ, 0, (LPSECURITY_ATTRIBUTES)NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, (HANDLE)NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		Error("[reflective_DLL_injection] Error with CreateFile");
		return FALSE;
	}
	FileSize = GetFileSize(hFile, NULL);

	Buffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!Buffer)
	{
		Error("[reflective_DLL_injection] Error with VirtualAlloc");
		return FALSE;
	}

	if (!ReadFile(hFile, Buffer, (DWORD)FileSize, (LPDWORD)&BytesRead, NULL))
	{
		Error("[reflective_DLL_injection] Error with ReadFile");
		return FALSE;
	}

	RemoteBuffer = (PCHAR)VirtualAllocEx(hProcess, NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (RemoteBuffer == NULL)
	{
		Error("[reflective_DLL_injection] Error with allocate buffer in target");
		return FALSE;
	}

	if (WriteProcessMemory(hProcess, RemoteBuffer, Buffer, FileSize, &BytesWritten) == FALSE || BytesWritten != FileSize)
	{
		Error("[reflective_DLL_injection] Error with write image to target");
		return FALSE;
	}

	RemoteEntryPoint = (PBYTE)RemoteBuffer + GetNtHeaders(Buffer)->OptionalHeader.AddressOfEntryPoint;

	OSVersion.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

	if (!GetVersionEx(&OSVersion))
	{
		Error("[reflective_DLL_injection] Error with get OS version");
		return FALSE;
	}

	if (OSVersion.dwMajorVersion < 6)
	{
		RemoteThreadHandle = CreateRemoteThread(hProcess, NULL, 0, RemoteEntryPoint, NULL, 0, NULL);

		if (!RemoteThreadHandle)
		{
			Error("[reflective_DLL_injection] Error with CreateRemoteThread failed");
			return FALSE;
		}
		else
		{
			WaitForSingleObject(RemoteThreadHandle, INFINITE);
			GetExitCodeThread(RemoteThreadHandle, &ExitCode);
			CloseHandle(RemoteThreadHandle);
			VirtualFreeEx(hProcess, RemoteBuffer, SystemInfo.dwPageSize, MEM_RELEASE);

			if (ExitCode)
			{
				SetLastError(ExitCode);
				Error("[reflective_DLL_injection] Error with CreateRemoteThread injection failed");
				return FALSE;
			}

			printf("[reflective_DLL_injection] Successfully injected Dll into process via CreateRemoteThread.\n");

			return TRUE;
		}
	}
	else
	{
		RtlCreateUserThread = (_RtlCreateUserThread)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlCreateUserThread");

		RetVal = RtlCreateUserThread(hProcess, NULL, 0, 0, 0, 0, (PTHREAD_START_ROUTINE)RemoteEntryPoint, NULL, &RemoteThreadHandle, NULL);

		if (!NT_SUCCESS(RetVal))
		{
			RemoteThreadHandle = NULL;
			Error("[reflective_DLL_injection] Error with RtlCreateUserThread failed");
			return FALSE;
		}
		else if (RemoteThreadHandle)
		{
			WaitForSingleObject(RemoteThreadHandle, INFINITE);
			GetExitCodeThread(RemoteThreadHandle, &ExitCode);
			CloseHandle(RemoteThreadHandle);
			VirtualFreeEx(hProcess, RemoteBuffer, SystemInfo.dwPageSize, MEM_RELEASE);

			if (!ExitCode)
			{
				RtlNtStatusToDosError = (_RtlNtStatusToDosError)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlNtStatusToDosError");
				SetLastError(RtlNtStatusToDosError(ExitCode));
				Error("[reflective_DLL_injection] Error with RtlCreateUserThread injection failed");
				return FALSE;
			}
		}

		printf("[reflective_DLL_injection] Successfully injected Dll into process via RtlCreateUserThread.\n");

		return TRUE;
	}

	VirtualFreeEx(hProcess, Buffer, 0, MEM_RELEASE);
	CloseHandle(hFile);
}



int my_injection(int _pid, const char* _dllpath) 
{
	LPCWSTR ProcessName = L"";
	ProcessName = GetProcessNamebyID(_pid);

	if (SetProcessPrivilege(GetCurrentProcess(), L"SeDebugPrivilege", TRUE, NULL)) // Нужны права админа, иначе ошибка ERROR_PRIVILEGE_NOT_HELD
		printf("[INJECTOR] [MY_INJECTION] [PID: %d] [PNAME: %ws] Successfully set of the Debug Privilege!\n", _pid, ProcessName);
	else
		printf("[INJECTOR] [MY_INJECTION] [PID: %d] [PNAME: %ws] Error setting Debug Priviledge! Try with Administrator account.\n", _pid, ProcessName);

	// Open a handle to the target process
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, _pid);
	if (!hProcess)
		return Error("Failed to open process");

	// Standard DLL Injection
	standard_DLL_injection(hProcess, _pid, _dllpath);
	
	if (isDllInjected(hProcess, _dllpath))
	{
		printf("[INJECTOR] [MY_INJECTION] [PID: %d] [PNAME: %ws] Successfully injected using standard DLL injection!\n", _pid, ProcessName);
		CloseHandle(hProcess);
		return TRUE;
	}

	// Reflective DLL Injection
	//reflective_DLL_injection(hProcess,_dllpath);
	//
	//if (isDllInjected(hProcess, _dllpath))
	//{
	//	printf("[my_injection] Successfully injected using Reflective DLL injection!\n");
	//	CloseHandle(hProcess);
	//	return TRUE;
	//}

	// Close process handle
	CloseHandle(hProcess);

}

int main(int argc, const char* argv[]) {
	
	// Check arguments
	if (argc < 3) {
		printf("Usage: injector <pid> <dllpath>\n");
		return FALSE;
	}

	if (my_injection(atoi(argv[1]), argv[2]))
	{
		printf("[MAIN] DLL successfully injected!\n");
	}
	else
	{
		printf("[MAIN] DLL was not injected!\n");
	}
}
#include <Windows.h>
#include <stdio.h>

int Error(const char* msg) {
	printf("%s | (%u)\n", msg, ::GetLastError());
	return 1;
}

BOOLEAN SetProcessPrivilege(_In_ HANDLE ProcessHandle, _In_ LPCWSTR PrivilegeName, _In_ BOOLEAN EnablePrivilege, _In_opt_ PBOOLEAN IsEnabled)
{
	BOOLEAN Result = FALSE;

	HANDLE TokenHandle = 0;

	if (OpenProcessToken(ProcessHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle))
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

int main(int argc, const char* argv[]) {
	
	// Check arguments
	if (argc < 3) {
		printf("Usage: injector <pid> <dllpath>\n");
		return 0;
	}

	if (SetProcessPrivilege(GetCurrentProcess(), L"SeDebugPrivilege", TRUE, NULL)) // Нужны права админа, иначе ошибка ERROR_PRIVILEGE_NOT_HELD
		wprintf_s(L"Successfully!\n");
	else
		wprintf_s(L"Error setting Debug Priviledge! Try in Administrator mode.\n");

	// Open a handle to the target process
	HANDLE hProcess = OpenProcess(
		PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD,
		FALSE,
		atoi(argv[1]));
	if (!hProcess)
		return Error("Failed to open process");

	// Prepare DLL path to load
	void* buffer = VirtualAllocEx(hProcess, nullptr, 1 << 16, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!buffer)
		return Error("Failed to allocate buffer in target process");
	
	// Copy the DLL path to the allocated buffer
	if (!::WriteProcessMemory(hProcess, buffer, argv[2], ::strlen(argv[2]) + 1, nullptr))
		return Error("Failed to write to target process");

	DWORD tid;
	HANDLE hThread = ::CreateRemoteThread(hProcess,
		nullptr,
		0,
		(LPTHREAD_START_ROUTINE)::GetProcAddress(::GetModuleHandle(L"Kernel32"), "LoadLibraryA"),
		buffer,
		0,
		&tid);
	if (!hThread)
		return Error("Failed to create remote thread");

	printf("Thread %u created successfully!\n", tid);
	if (WAIT_OBJECT_0 == WaitForSingleObject(hThread, 10000))
		printf("Thread exited.\n");
	else
		printf("Thread still haging around ...\n");

	// 
	::VirtualFreeEx(hProcess, buffer, 0, MEM_RELEASE);

	::CloseHandle(hThread);
	::CloseHandle(hProcess);
}
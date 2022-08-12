#include <Windows.h>
#include <stdio.h>

int Error(const char* msg) {
	printf("%s | (%u)\n", msg, ::GetLastError());
	return 1;
}

int main(int argc, const char* argv[]) {
	
	// Check arguments
	if (argc < 3) {
		printf("Usage: injector <pid> <dllpath>\n");
		return 0;
	}

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
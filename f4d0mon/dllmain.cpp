// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <wincrypt.h>
#include <bcrypt.h>
#include <TlHelp32.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "Crypt32.lib")

// Declare functions
LPCWSTR GetProcessNamebyID(_In_ DWORD ProcessID);
DWORD GetThreadOwnerIDbyID(_In_ DWORD ThreadID);
////////////////////////////////////////////

#ifndef MAKEULONGLONG
#define MAKEULONGLONG(ldw, hdw) ((ULONGLONG(hdw) << 32) | ((ldw) & 0xFFFFFFFF))
#endif

#ifndef MAXULONGLONG
#define MAXULONGLONG ((ULONGLONG)~((ULONGLONG)0))
#endif

DWORD GetProcessMainThread(DWORD dwProcID)
{
    DWORD dwMainThreadID = 0;
    ULONGLONG ullMinCreateTime = MAXULONGLONG;

    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap != INVALID_HANDLE_VALUE) 
    {
        THREADENTRY32 th32;
        th32.dwSize = sizeof(THREADENTRY32);
        BOOL bOK = TRUE;
        for (bOK = Thread32First(hThreadSnap, &th32); bOK; bOK = Thread32Next(hThreadSnap, &th32)) 
        {
            if (th32.th32OwnerProcessID == dwProcID) 
            {
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, TRUE, th32.th32ThreadID);
                if (hThread) 
                {
                    FILETIME afTimes[4] = { 0 };
                    if (GetThreadTimes(hThread, &afTimes[0], &afTimes[1], &afTimes[2], &afTimes[3])) 
                    {
                        ULONGLONG ullTest = MAKEULONGLONG(afTimes[0].dwLowDateTime, afTimes[0].dwHighDateTime);
                        if (ullTest && ullTest < ullMinCreateTime) 
                        {
                            ullMinCreateTime = ullTest;
                            dwMainThreadID = th32.th32ThreadID; // let it be main... :)
                        }
                    }
                    CloseHandle(hThread);
                }
            }
        }
#ifndef UNDER_CE
        CloseHandle(hThreadSnap);
#else
        CloseToolhelp32Snapshot(hThreadSnap);
#endif
    }

    return dwMainThreadID;
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

/*
*/
DWORD GetThreadOwnerIDbyID(_In_ DWORD ThreadID)
{
    DWORD OwnerProcessID = 0;

    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (hThreadSnap != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 ThreadEntry = { 0 };

        ThreadEntry.dwSize = sizeof(ThreadEntry);

        if (Thread32First(hThreadSnap, &ThreadEntry))
        {
            do {
                if (ThreadEntry.th32ThreadID == ThreadID)
                {
                    OwnerProcessID = ThreadEntry.th32OwnerProcessID;
                    break;
                }
            } while (Thread32Next(hThreadSnap, &ThreadEntry));
        }
        CloseHandle(hThreadSnap);
    }
    return OwnerProcessID;
}

/////////////////////////////////////////////////////////////////
 ///////////////////////////////////////////////////////////////
  /////////////////////////////////////////////////////////////
   /////////    D T O U R S   F U N C T I O N S     //////////
    /////////////////////////////////////////////////////////
     ///////////////////////////////////////////////////////
      /////////////////////////////////////////////////////


//BCryptEncrypt
decltype(::BCryptEncrypt)* BCryptEncryptOrg = ::BCryptEncrypt;

//CryptEncrypt
decltype(::CryptEncrypt)* CryptEncryptOrg = ::CryptEncrypt;

//////////////////////////////////////////

//BCryptEncrypt
NTSTATUS WINAPI BCryptEncryptHooked(
    _Inout_ BCRYPT_KEY_HANDLE   hKey,
    _In_    PUCHAR              pbInput,
    _In_    ULONG               cbInput,
    _In_    VOID* pPaddingInfo,
    _Inout_ PUCHAR              pbIV,
    _In_    ULONG               cbIV,
    _Out_   PUCHAR              pbOutput,
    _In_    ULONG               cbOutput,
    _Out_   ULONG* pcbResult,
    _In_    ULONG               dwFlags) {
    
    LPCWSTR ProcessName = L"";
    DWORD ThreadOwnerID = 0;
    ProcessName = GetProcessNamebyID(::GetCurrentProcessId());
    //ThreadOwnerID = GetThreadOwnerIDbyID(::GetCurrentThreadId());
    DWORD MainThread = GetProcessMainThread(::GetCurrentProcessId());
    char message[128];
    //sprintf_s(message, "[F4D0] [%ws] [%ul] [%ld] --> call to BCryptEncrypt", ProcessName, MainThread, ::GetCurrentThreadId());
    sprintf_s(message, "[F4D0] [%ws] --> call to BCryptEncrypt", ProcessName);
    OutputDebugStringA(message);

    NTSTATUS status = BCryptEncryptOrg(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);

    return status;
}

//CryptEncrypt
BOOL WINAPI CryptEncryptHooked(
    _In_ HCRYPTKEY  hKey,
    _In_ HCRYPTHASH hHash,
    _In_ BOOL       Final,
    _In_ DWORD      dwFlags,
    _Inout_ BYTE* pbData,
    _Inout_ DWORD* pdwDataLen,
    _In_ DWORD      dwBufLen) {

    LPCWSTR ProcessName = L"";
    ProcessName = GetProcessNamebyID(::GetCurrentProcessId());
    char message[64];
    sprintf_s(message, "[F4D0] [%ws] --> call to CryptEncrypt", ProcessName);
    OutputDebugStringA(message);
    
    BOOL status = CryptEncryptOrg(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);

    return status;
}

bool HookFunctions() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    // The functions to attach
    DetourAttach((PVOID*)&BCryptEncryptOrg, BCryptEncryptHooked);
    DetourAttach((PVOID*)&CryptEncryptOrg, CryptEncryptHooked);
    auto error = DetourTransactionCommit();
    return error == ERROR_SUCCESS;
}

bool DeHookFunctions() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    // The functions to deattach
    DetourDetach((PVOID*)&BCryptEncryptOrg, BCryptEncryptHooked);
    DetourDetach((PVOID*)&CryptEncryptOrg, CryptEncryptHooked);
    auto error = DetourTransactionCommit();
    return error == ERROR_SUCCESS;
}

/// <summary>
/// 
/// </summary>
/// <returns></returns>
int sayHello() {
    wchar_t text[128];
    ::StringCchPrintf(text, _countof(text), L"Injected into process %u", ::GetCurrentProcessId());
    ::MessageBox(nullptr, text, L"Injected.Dll", MB_OK);
    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            if (!HookFunctions()) 
            {
                LPCWSTR ProcessName = L"";
                ProcessName = GetProcessNamebyID(::GetCurrentProcessId());
                char message[64];
                sprintf_s(message, "[F4D0] [%ws] DLL_PROCESS_ATTACH ERROR Attaching", ProcessName);
                OutputDebugStringA(message);
            }
            else
            {
                LPCWSTR ProcessName = L"";
                ProcessName = GetProcessNamebyID(::GetCurrentProcessId());
                char message[64];
                sprintf_s(message, "[F4D0] [%ws] DLL_PROCESS_ATTACH SUCCESS Attaching", ProcessName);
                OutputDebugStringA(message);
            }
            break;
        case DLL_THREAD_ATTACH:
            if (!HookFunctions())
                OutputDebugStringA("[F4D0] DLL_THREAD_ATTACH ERROR Attaching");
            else
                OutputDebugStringA("[F4D0] DLL_THREAD_ATTACH SUCCESS Attaching");
            break;
        case DLL_THREAD_DETACH:
            /*if (!DeHookFunctions())
                OutputDebugStringA("[F4D0] DLL_THREAD_DETACH ERROR Detaching");
            else
                OutputDebugStringA("[F4D0] DLL_THREAD_DETACH SUCCESS Detaching");*/
            break;
        case DLL_PROCESS_DETACH:
            /*if (!DeHookFunctions())
                OutputDebugStringA("[F4D0] DLL_PROCESS_DETACH ERROR Detaching.");
            else
                OutputDebugStringA("[F4D0] DLL_PROCESS_DETACH SUCCESS Detaching.");*/
            break;
    }
    return TRUE;
}


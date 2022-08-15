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

const int cps_CE_th = 20; // Calls per second CryptEncrypt threshold
const int cps_BCE_th = 20; // Calls per second BCryptEncrypt threshold

int cps_CE = 0; // Calls per second CryptEncrypt - to monitor current calls per second
int cps_BCE = 0; // Calls per second BCryptEncrypt - to monitor current calls per second

SYSTEMTIME ct_CE, ct_BCE, ot_CE, ot_BCE; // current time (ct), old time (ot), difference (df) for CryptEncrypt and BCryptEncrypt

BOOL CE_warn = TRUE;
BOOL BCE_warn = TRUE;

BOOL first_CE = TRUE;
BOOL first_BCE = TRUE;



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

// Calculates difference of time, first parameter minus second parameter

BOOL count_BCryptEncrypt(LPCWSTR ProcessName)
{
    if (first_BCE)
    {
        GetSystemTime(&ot_BCE);
        GetSystemTime(&ct_BCE);
        first_BCE = FALSE;
        cps_BCE++;
        return TRUE;
    }

    GetSystemTime(&ct_BCE);

    // TO REMOVE - JUST DEBUG
    //char message1[128];
    //sprintf_s(message1, "[F4D0] [%ws] [OT: %04d-%02d-%02d %02d:%02d:%02d] [CT: %04d-%02d-%02d %02d:%02d:%02d] [Total: %d]", ProcessName, 
    //    ot_BCE.wYear, ot_BCE.wMonth, ot_BCE.wDay, ot_BCE.wHour, ot_BCE.wMinute, ot_BCE.wSecond, 
    //    ct_BCE.wYear, ct_BCE.wMonth, ct_BCE.wDay, ct_BCE.wHour, ct_BCE.wMinute, ct_BCE.wSecond,
    //    cps_BCE);
    //OutputDebugStringA(message1);

    if (ct_BCE.wSecond > ot_BCE.wSecond || ct_BCE.wMinute > ot_BCE.wMinute)
    {
        char message[128];
        sprintf_s(message, "[F4D0] [BCryptEncrypt] [%04d-%02d-%02d %02d:%02d:%02d] [%ws] [Total: %d]", ot_BCE.wYear, ot_BCE.wMonth, ot_BCE.wDay, ot_BCE.wHour, ot_BCE.wMinute, ot_BCE.wSecond, ProcessName, cps_BCE);
        OutputDebugStringA(message);

        // reset the counter for the next period of time
        cps_BCE = 0;
        BCE_warn = TRUE;
    }
    else
    {
        cps_BCE++;
    }

    if (cps_BCE > cps_BCE_th && BCE_warn)
    {
        char message[128];
        sprintf_s(message, "[F4D0] [BCryptEncrypt] [%04d-%02d-%02d %02d:%02d:%02d] [%ws] [Total: %d] Crossed the threshold!", ct_BCE.wYear, ct_BCE.wMonth, ct_BCE.wDay, ct_BCE.wHour, ct_BCE.wMinute, ct_BCE.wSecond, ProcessName, cps_BCE);
        OutputDebugStringA(message);
        BCE_warn = FALSE;
    }

    // Copy current time to old time
    ot_BCE = ct_BCE;
    return TRUE;
}

BOOL count_CryptEncrypt(LPCWSTR ProcessName)
{

    if (first_CE)
    {
        GetSystemTime(&ot_CE);
        GetSystemTime(&ct_CE);
        first_CE = FALSE;
        cps_CE++;
        return TRUE;
    }

    GetSystemTime(&ct_CE);
    
    // TO REMOVE - JUST DEBUG
    //char message1[128];
    //sprintf_s(message1, "[F4D0] [%ws] [OT: %04d-%02d-%02d %02d:%02d:%02d] [CT: %04d-%02d-%02d %02d:%02d:%02d] [Total: %d]", ProcessName, 
    //    ot_CE.wYear, ot_CE.wMonth, ot_CE.wDay, ot_CE.wHour, ot_CE.wMinute, ot_CE.wSecond, 
    //    ct_CE.wYear, ct_CE.wMonth, ct_CE.wDay, ct_CE.wHour, ct_CE.wMinute, ct_CE.wSecond,
    //    cps_CE);
    //OutputDebugStringA(message1);

    if (ct_CE.wSecond > ot_CE.wSecond || ct_CE.wMinute > ot_CE.wMinute)
    {
        char message[128];
        sprintf_s(message, "[F4D0] [CryptEncrypt] [%04d-%02d-%02d %02d:%02d:%02d] [%ws] [Total: %d]", ot_CE.wYear, ot_CE.wMonth, ot_CE.wDay, ot_CE.wHour, ot_CE.wMinute, ot_CE.wSecond, ProcessName, cps_CE);
        OutputDebugStringA(message);

        // reset the counter for the next period of time
        cps_CE = 0;
        CE_warn = TRUE;
    }
    else
    {
        cps_CE++;
    }

    if (cps_CE > cps_CE_th && CE_warn)
    {
        char message[128];
        sprintf_s(message, "[F4D0] [CryptEncrypt] [%04d-%02d-%02d %02d:%02d:%02d] [%ws] [Total: %d] Crossed the threshold!", ct_CE.wYear, ct_CE.wMonth, ct_CE.wDay, ct_CE.wHour, ct_CE.wMinute, ct_CE.wSecond, ProcessName, cps_CE);
        OutputDebugStringA(message);
        CE_warn = FALSE;
    }

    // Copy current time to old time
    ot_CE = ct_CE;
    return TRUE;
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
    
    //DWORD ThreadOwnerID = 0;
    //DWORD MainThread = GetProcessMainThread(::GetCurrentProcessId());
    //char message[128];
    //sprintf_s(message, "[F4D0] [%ws] [%ul] [%ld] --> [BCryptEncrypt]", ProcessName, MainThread, ::GetCurrentThreadId());
    //OutputDebugStringA(message);
    
    LPCWSTR ProcessName = L"";
    ProcessName = GetProcessNamebyID(::GetCurrentProcessId());

    count_BCryptEncrypt(ProcessName);

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

    //DWORD ThreadOwnerID = 0;
    //DWORD MainThread = GetProcessMainThread(::GetCurrentProcessId());
    //char message[128];
    //sprintf_s(message, "[F4D0] [%ws] [%ul] [%ld] --> [CryptEncrypt]", ProcessName, MainThread, ::GetCurrentThreadId());
    //OutputDebugStringA(message);

    LPCWSTR ProcessName = L"";
    ProcessName = GetProcessNamebyID(::GetCurrentProcessId());
    
    count_CryptEncrypt(ProcessName);

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

                // TODO: check if the application is on a white list, and save the state into a BOOL.
                // it can be used later today if the application starts to make calls to CryptEncrypt API.
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
            {
                LPCWSTR ProcessName = L"";
                ProcessName = GetProcessNamebyID(::GetCurrentProcessId());
                char message[64];
                sprintf_s(message, "[F4D0] [%ws] DLL_THREAD_ATTACH ERROR Attaching", ProcessName);
                OutputDebugStringA(message);
            }
            else
            {
                LPCWSTR ProcessName = L"";
                ProcessName = GetProcessNamebyID(::GetCurrentProcessId());
                char message[64];
                sprintf_s(message, "[F4D0] [%ws] DLL_THREAD_ATTACH SUCCESS Attaching", ProcessName);
                OutputDebugStringA(message);
            }
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


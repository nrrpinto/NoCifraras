// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <wincrypt.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "Crypt32.lib")


// ###################################################


// ###################################################

//BCryptCreateHash
decltype(::BCryptCreateHash)* BCryptCreateHashOrg = ::BCryptCreateHash;

//BCryptDecrypt
decltype(::BCryptDecrypt)* BCryptDecryptOrg = ::BCryptDecrypt;

//BCryptDestroyHash
decltype(::BCryptDestroyHash)* BCryptDestroyHashOrg = ::BCryptDestroyHash;

//BCryptDestroyKey
decltype(::BCryptDestroyKey)* BCryptDestroyKeyOrg = ::BCryptDestroyKey;

//BCryptDuplicateKey
decltype(::BCryptDuplicateKey)* BCryptDuplicateKeyOrg = ::BCryptDuplicateKey;

//BCryptEncrypt
decltype(::BCryptEncrypt)* BCryptEncryptOrg = ::BCryptEncrypt;

//BCryptExportKey
decltype(::BCryptExportKey)* BCryptExportKeyOrg = ::BCryptExportKey;

//BCryptFinalizeKeyPair
decltype(::BCryptFinalizeKeyPair)* BCryptFinalizeKeyPairOrg = ::BCryptFinalizeKeyPair;

//BCryptFinishHash
decltype(::BCryptFinishHash)* BCryptFinishHashOrg = ::BCryptFinishHash;

//BCryptGenerateKeyPair
decltype(::BCryptGenerateKeyPair)* BCryptGenerateKeyPairOrg = ::BCryptGenerateKeyPair;

//BCryptGenerateSymmetricKey
decltype(::BCryptGenerateSymmetricKey)* BCryptGenerateSymmetricKeyOrg = ::BCryptGenerateSymmetricKey;

//BCryptGenRandom
decltype(::BCryptGenRandom)* BCryptGenRandomOrg = ::BCryptGenRandom;

//BCryptGetProperty
decltype(::BCryptGetProperty)* BCryptGetPropertyOrg = ::BCryptGetProperty;

//BCryptHashData
decltype(::BCryptHashData)* BCryptHashDataOrg = ::BCryptHashData;

//BCryptImportKey
decltype(::BCryptImportKey)* BCryptImportKeyOrg = ::BCryptImportKey;

//BCryptImportKeyPair
decltype(::BCryptImportKeyPair)* BCryptImportKeyPairOrg = ::BCryptImportKeyPair;

//BCryptOpenAlgorithmProvider
decltype(::BCryptOpenAlgorithmProvider)* BCryptOpenAlgorithmProviderOrg = ::BCryptOpenAlgorithmProvider;

//BCryptSetProperty
decltype(::BCryptSetProperty)* BCryptSetPropertyOrg = ::BCryptSetProperty;

//CryptAcquireContext
// decltype(::CryptAcquireContext)* CryptAcquireContextOrg = ::CryptAcquireContext;

//CryptAcquireContextA
decltype(::CryptAcquireContextA)* CryptAcquireContextAOrg = ::CryptAcquireContextA;

//CryptAcquireContextW
decltype(::CryptAcquireContextW)* CryptAcquireContextWOrg = ::CryptAcquireContextW;

//CryptCreateHash
decltype(::CryptCreateHash)* CryptCreateHashOrg = ::CryptCreateHash;

//CryptDecrypt
decltype(::CryptDecrypt)* CryptDecryptOrg = ::CryptDecrypt;

//CryptEncrypt
decltype(::CryptEncrypt)* CryptEncryptOrg = ::CryptEncrypt;

//CryptGenRandom
decltype(::CryptGenRandom)* CryptGenRandomOrg = ::CryptGenRandom;

//CryptHashData
decltype(::CryptHashData)* CryptHashDataOrg = ::CryptHashData;

//CryptImportKey
decltype(::CryptImportKey)* CryptImportKeyOrg = ::CryptImportKey;

//CryptReleaseContext
decltype(::CryptReleaseContext)* CryptReleaseContextOrg = ::CryptReleaseContext;

//CryptGetUserKey
decltype(::CryptGetUserKey)* CryptGetUserKeyOrg = ::CryptGetUserKey;

//CryptGenKey
decltype(::CryptGenKey)* CryptGenKeyOrg = ::CryptGenKey;

//CryptExportKey
decltype(::CryptExportKey)* CryptExportKeyOrg = ::CryptExportKey;

//CryptDeriveKey
decltype(::CryptDeriveKey)* CryptDeriveKeyOrg = ::CryptDeriveKey;

//CryptDestroyHash
decltype(::CryptDestroyHash)* CryptDestroyHashOrg = ::CryptDestroyHash;

//CryptDestroyKey
decltype(::CryptDestroyKey)* CryptDestroyKeyOrg = ::CryptDestroyKey;

//CryptStringToBinaryA
//decltype(::CryptStringToBinaryA)* CryptStringToBinaryAOrg = ::CryptStringToBinaryA;

//////////////////////////////////////////

//BCryptCreateHash
NTSTATUS WINAPI BCryptCreateHashHooked(
    _Inout_ BCRYPT_ALG_HANDLE   hAlgorithm,
    _Out_   BCRYPT_HASH_HANDLE* phHash,
    _Out_   PUCHAR              pbHashObject,
    _In_    ULONG               cbHashObject,
    _In_    PUCHAR              pbSecret,
    _In_    ULONG               cbSecret,
    _In_    ULONG               dwFlags) {

    OutputDebugStringA("[F4D0] --> call to BCryptCreateHash");
    
    NTSTATUS status = BCryptCreateHashOrg(hAlgorithm, phHash, pbHashObject, cbHashObject, pbSecret, cbSecret, dwFlags);

    return status;

}

//BCryptDecrypt
NTSTATUS WINAPI BCryptDecryptHooked(
    _Inout_ BCRYPT_KEY_HANDLE hKey,
    _In_    PUCHAR            pbInput,
    _In_    ULONG             cbInput,
    _In_    VOID*             pPaddingInfo,
    _Inout_ PUCHAR            pbIV,
    _In_    ULONG             cbIV,
    _Out_   PUCHAR            pbOutput,
    _In_    ULONG             cbOutput,
    _Out_   ULONG*            pcbResult,
    _In_    ULONG             dwFlags) {
    
    OutputDebugStringA("[F4D0] --> call to BCryptDecrypt");

    NTSTATUS status = BCryptDecryptOrg(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);

    return status;

}
//BCryptDestroyHash
NTSTATUS  WINAPI BCryptDestroyHashHooked(
    _Inout_ BCRYPT_HASH_HANDLE hHash) {

    OutputDebugStringA("[F4D0] --> call to BCryptDestroyHash");
    
    NTSTATUS status = BCryptDestroyHashOrg(hHash);

    return status;

}
//BCryptDestroyKey
NTSTATUS  WINAPI BCryptDestroyKeyHooked(
    _Inout_ BCRYPT_KEY_HANDLE hKey) {

    OutputDebugStringA("[F4D0] --> call to BCryptDestroyKey");

    NTSTATUS status = BCryptDestroyKeyOrg(hKey);

    return status;

}
//BCryptDuplicateKey
NTSTATUS  WINAPI BCryptDuplicateKeyHooked(
    _In_  BCRYPT_KEY_HANDLE     hKey,
    _Out_ BCRYPT_KEY_HANDLE*    phNewKey,
    _Out_ PUCHAR                pbKeyObject,
    _In_  ULONG                 cbKeyObject,
    _In_  ULONG                 dwFlags) {

    OutputDebugStringA("[F4D0] --> call to BCryptDuplicateKey");

    NTSTATUS status = BCryptDuplicateKeyOrg(hKey, phNewKey, pbKeyObject, cbKeyObject, dwFlags);

    return status;

}
//BCryptEncrypt
NTSTATUS WINAPI BCryptEncryptHooked(
    _Inout_ BCRYPT_KEY_HANDLE   hKey,
    _In_    PUCHAR              pbInput,
    _In_    ULONG               cbInput,
    _In_    VOID*               pPaddingInfo,
    _Inout_ PUCHAR              pbIV,
    _In_    ULONG               cbIV,
    _Out_   PUCHAR              pbOutput,
    _In_    ULONG               cbOutput,
    _Out_   ULONG*              pcbResult,
    _In_    ULONG               dwFlags) {

    OutputDebugStringA("[F4D0] --> call to BCryptEncrypt");

    NTSTATUS status = BCryptEncryptOrg(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);

    return status;

}
//BCryptExportKey
NTSTATUS WINAPI BCryptExportKeyHooked(
    _In_  BCRYPT_KEY_HANDLE hKey,
    _In_  BCRYPT_KEY_HANDLE hExportKey,
    _In_  LPCWSTR           pszBlobType,
    _Out_ PUCHAR            pbOutput,
    _In_  ULONG             cbOutput,
    _Out_ ULONG*            pcbResult,
    _In_  ULONG             dwFlags) {

    OutputDebugStringA("[F4D0] --> call to BCryptExportKey");

    NTSTATUS status = BCryptExportKeyOrg(hKey, hExportKey, pszBlobType, pbOutput, cbOutput, pcbResult, dwFlags);

    return status;

}
//BCryptFinalizeKeyPair
NTSTATUS WINAPI BCryptFinalizeKeyPairHooked(
    _Inout_ BCRYPT_KEY_HANDLE hKey,
    _In_ ULONG             dwFlags) {

    OutputDebugStringA("[F4D0] --> call to BCryptFinalizeKeyPair");

    NTSTATUS status = BCryptFinalizeKeyPairOrg(hKey, dwFlags);

    return status;

}
//BCryptFinishHash
NTSTATUS WINAPI BCryptFinishHashHooked(
    _Inout_ BCRYPT_HASH_HANDLE hHash,
    _Out_   PUCHAR             pbOutput,
    _In_    ULONG              cbOutput,
    _In_    ULONG              dwFlags) {

    OutputDebugStringA("[F4D0] --> call to BCryptFinishHash");
    
    NTSTATUS status = BCryptFinishHashOrg(hHash, pbOutput, cbOutput, dwFlags);

    return status;

}
//BCryptGenerateKeyPair
NTSTATUS WINAPI BCryptGenerateKeyPairHooked(
    _Inout_ BCRYPT_ALG_HANDLE hAlgorithm,
    _Out_   BCRYPT_KEY_HANDLE* phKey,
    _In_    ULONG             dwLength,
    _In_    ULONG             dwFlags) {

    OutputDebugStringA("[F4D0] --> call to BCryptGenerateKeyPair");

    NTSTATUS status = BCryptGenerateKeyPairOrg(hAlgorithm, phKey, dwLength, dwFlags);

    return status;

}
//BCryptGenerateSymmetricKey
NTSTATUS WINAPI BCryptGenerateSymmetricKeyHooked(
    _Inout_ BCRYPT_ALG_HANDLE hAlgorithm,
    _Out_   BCRYPT_KEY_HANDLE* phKey,
    _Out_   PUCHAR            pbKeyObject,
    _In_    ULONG             cbKeyObject,
    _In_    PUCHAR            pbSecret,
    _In_    ULONG             cbSecret,
    _In_    ULONG             dwFlags) {

    OutputDebugStringA("[F4D0] --> call to BCryptGenerateSymmetricKey");
    
    NTSTATUS status = BCryptGenerateSymmetricKeyOrg(hAlgorithm, phKey, pbKeyObject, cbKeyObject, pbSecret, cbSecret, dwFlags);

    return status;

}
//BCryptGenRandom
NTSTATUS WINAPI BCryptGenRandomHooked(
    _Inout_ BCRYPT_ALG_HANDLE hAlgorithm,
    _Inout_ PUCHAR            pbBuffer,
    _In_    ULONG             cbBuffer,
    _In_    ULONG             dwFlags) {

    OutputDebugStringA("[F4D0] --> call to BCryptGenRandom");
    
    NTSTATUS status = BCryptGenRandomOrg(hAlgorithm, pbBuffer, cbBuffer, dwFlags);

    return status;

}
//BCryptGetProperty
NTSTATUS WINAPI BCryptGetPropertyHooked(
    _In_  BCRYPT_HANDLE hObject,
    _In_  LPCWSTR       pszProperty,
    _Out_ PUCHAR        pbOutput,
    _In_  ULONG         cbOutput,
    _Out_ ULONG*        pcbResult,
    _In_  ULONG         dwFlags) {

    OutputDebugStringA("[F4D0] --> call to BCryptGetProperty");
    
    NTSTATUS status = BCryptGetPropertyOrg(hObject, pszProperty, pbOutput, cbOutput, pcbResult, dwFlags);

    return status;

}
//BCryptHashData
NTSTATUS WINAPI BCryptHashDataHooked(
    _Inout_ BCRYPT_HASH_HANDLE hHash,
    _In_    PUCHAR             pbInput,
    _In_    ULONG              cbInput,
    _In_    ULONG              dwFlags) {

    OutputDebugStringA("[F4D0] --> call to BCryptHashData");
    
    NTSTATUS status = BCryptHashDataOrg(hHash, pbInput, cbInput, dwFlags);

    return status;

}
//BCryptImportKey
NTSTATUS WINAPI BCryptImportKeyHooked(
    _In_    BCRYPT_ALG_HANDLE hAlgorithm,
    _In_    BCRYPT_KEY_HANDLE hImportKey,
    _In_    LPCWSTR           pszBlobType,
    _Out_   BCRYPT_KEY_HANDLE* phKey,
    _Out_   PUCHAR            pbKeyObject,
    _In_    ULONG             cbKeyObject,
    _In_    PUCHAR            pbInput,
    _In_    ULONG             cbInput,
    _In_    ULONG             dwFlags) {

    OutputDebugStringA("[F4D0] --> call to BCryptImportKey");
    
    NTSTATUS status = BCryptImportKeyOrg(hAlgorithm, hImportKey, pszBlobType, phKey, pbKeyObject, cbKeyObject, pbInput, cbInput, dwFlags);

    return status;

}
//BCryptImportKeyPair
NTSTATUS WINAPI BCryptImportKeyPairHooked(
    _In_    BCRYPT_ALG_HANDLE hAlgorithm,
    _Inout_ BCRYPT_KEY_HANDLE hImportKey,
    _In_    LPCWSTR           pszBlobType,
    _Out_   BCRYPT_KEY_HANDLE* phKey,
    _In_    PUCHAR            pbInput,
    _In_    ULONG             cbInput,
    _In_    ULONG             dwFlags) {

    OutputDebugStringA("[F4D0] --> call to BCryptImportKeyPair");
    
    NTSTATUS status = BCryptImportKeyPairOrg(hAlgorithm, hImportKey, pszBlobType, phKey, pbInput, cbInput, dwFlags);

    return status;

}
//BCryptOpenAlgorithmProvider
NTSTATUS WINAPI BCryptOpenAlgorithmProviderHooked(
    _Out_ BCRYPT_ALG_HANDLE* phAlgorithm,
    _In_  LPCWSTR           pszAlgId,
    _In_  LPCWSTR           pszImplementation,
    _In_  ULONG             dwFlags) {

    OutputDebugStringA("[F4D0] --> call to BCryptOpenAlgorithmProvider");
    
    NTSTATUS status = BCryptOpenAlgorithmProviderOrg(phAlgorithm, pszAlgId, pszImplementation, dwFlags);

    return status;

}
//BCryptSetProperty
NTSTATUS WINAPI BCryptSetPropertyHooked(
    _Inout_ BCRYPT_HANDLE hObject,
    _In_    LPCWSTR       pszProperty,
    _In_    PUCHAR        pbInput,
    _In_    ULONG         cbInput,
    _In_    ULONG         dwFlags) {

    OutputDebugStringA("[F4D0] --> call to BCryptSetProperty");
    
    NTSTATUS status = BCryptSetPropertyOrg(hObject, pszProperty, pbInput, cbInput, dwFlags);

    return status;

}

//CryptAcquireContextA
BOOL WINAPI CryptAcquireContextAHooked(
    _Out_ HCRYPTPROV* phProv,
    _In_  LPCSTR     szContainer,
    _In_  LPCSTR     szProvider,
    _In_  DWORD      dwProvType,
    _In_  DWORD      dwFlags) {

    OutputDebugStringA("[F4D0] --> call to CryptAcquireContextA");
    
    BOOL status = CryptAcquireContextAOrg(phProv, szContainer, szProvider, dwProvType, dwFlags);

    return status;

}
//CryptAcquireContextW
BOOL WINAPI CryptAcquireContextWHooked(
    _Out_ HCRYPTPROV* phProv,
    _In_  LPCWSTR    szContainer,
    _In_  LPCWSTR    szProvider,
    _In_  DWORD      dwProvType,
    _In_  DWORD      dwFlags) {

    OutputDebugStringA("[F4D0] --> call to CryptAcquireContextW");
    
    BOOL status = CryptAcquireContextWOrg(phProv, szContainer, szProvider, dwProvType, dwFlags);

    return status;

}
//CryptCreateHash
BOOL WINAPI CryptCreateHashHooked(
    _In_  HCRYPTPROV hProv,
    _In_  ALG_ID     Algid,
    _In_  HCRYPTKEY  hKey,
    _In_  DWORD      dwFlags,
    _Out_ HCRYPTHASH* phHash) {

    OutputDebugStringA("[F4D0] --> call to CryptCreateHash");
    
    BOOL status = CryptCreateHashOrg(hProv, Algid, hKey, dwFlags, phHash);

    return status;

}
//CryptDecrypt
BOOL WINAPI CryptDecryptHooked(
    _In_ HCRYPTKEY  hKey,
    _In_ HCRYPTHASH hHash,
    _In_ BOOL       Final,
    _In_ DWORD      dwFlags,
    _Inout_ BYTE* pbData,
    _Inout_ DWORD* pdwDataLen) {

    OutputDebugStringA("[F4D0] --> call to CryptDecrypt");
    
    BOOL status = CryptDecryptOrg(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);

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

    OutputDebugStringA("[F4D0] --> call to CryptEncrypt");
    
    BOOL status = CryptEncryptOrg(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);

    return status;

}
//CryptGenRandom
BOOL WINAPI CryptGenRandomHooked(
    _In_ HCRYPTPROV hProv,
    _In_ DWORD      dwLen,
    _Inout_ BYTE* pbBuffer) {

    OutputDebugStringA("[F4D0] --> call to CryptGenRandom");
    
    BOOL status = CryptGenRandomOrg(hProv, dwLen, pbBuffer);

    return status;

}
//CryptHashData
BOOL WINAPI CryptHashDataHooked(
    _In_ HCRYPTHASH hHash,
    _In_ const BYTE* pbData,
    _In_ DWORD      dwDataLen,
    _In_ DWORD      dwFlags) {

    OutputDebugStringA("[F4D0] --> call to CryptHashData");
    
    BOOL status = CryptHashDataOrg(hHash, pbData, dwDataLen, dwFlags);

    return status;

}
//CryptImportKey
BOOL WINAPI CryptImportKeyHooked(
    _In_  HCRYPTPROV hProv,
    _In_  const BYTE* pbData,
    _In_  DWORD      dwDataLen,
    _In_  HCRYPTKEY  hPubKey,
    _In_  DWORD      dwFlags,
    _Out_ HCRYPTKEY* phKey) {

    OutputDebugStringA("[F4D0] --> call to CryptImportKey");
    
    BOOL status = CryptImportKeyOrg(hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey);

    return status;

}
//CryptReleaseContext
BOOL WINAPI CryptReleaseContextHooked(
    _In_ HCRYPTPROV hProv,
    _In_ DWORD      dwFlags) {

    OutputDebugStringA("[F4D0] --> call to CryptReleaseContext");
    
    BOOL status = CryptReleaseContextOrg(hProv, dwFlags);

    return status;

}


//CryptGetUserKey
BOOL WINAPI CryptGetUserKeyHooked(
    _In_  HCRYPTPROV hProv,
    _In_  DWORD      dwKeySpec,
    _Out_ HCRYPTKEY* phUserKey) {

    OutputDebugStringA("[F4D0] --> call to CryptGetUserKey");

    BOOL status = CryptGetUserKeyOrg(hProv, dwKeySpec, phUserKey);

    return status;

}

//CryptGenKey

BOOL WINAPI CryptGenKeyHooked(
    _In_  HCRYPTPROV hProv,
    _In_  ALG_ID     Algid,
    _In_  DWORD      dwFlags,
    _Out_ HCRYPTKEY* phKey) {

    OutputDebugStringA("[F4D0] --> call to CryptGenKey");

    BOOL status = CryptGenKeyOrg(hProv, Algid, dwFlags, phKey);

    return status;

}

//CryptExportKey
BOOL WINAPI CryptExportKeyHooked(
    _In_      HCRYPTKEY hKey,
    _In_      HCRYPTKEY hExpKey,
    _In_      DWORD     dwBlobType,
    _In_      DWORD     dwFlags,
    _Out_     BYTE* pbData,
    _Inout_ DWORD* pdwDataLen) {

    OutputDebugStringA("[F4D0] --> call to CryptExportKey");

    BOOL status = CryptExportKeyOrg(hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen);

    return status;

}

//CryptDeriveKey
BOOL WINAPI CryptDeriveKeyHooked(
    _In_      HCRYPTPROV hProv,
    _In_      ALG_ID     Algid,
    _In_      HCRYPTHASH hBaseData,
    _In_      DWORD      dwFlags,
    _Inout_ HCRYPTKEY* phKey) {

    OutputDebugStringA("[F4D0] --> call to CryptDeriveKey");

    BOOL status = CryptDeriveKeyOrg(hProv, Algid, hBaseData, dwFlags, phKey);

    return status;

}

//CryptDestroyHash
BOOL WINAPI CryptDestroyHashHooked(
    _In_ HCRYPTHASH hHash) {

    OutputDebugStringA("[F4D0] --> call to CryptDestroyHash");

    BOOL status = CryptDestroyHashOrg(hHash);

    return status;

}

//CryptDestroyKey
BOOL WINAPI CryptDestroyKeyHooked(
    _In_ HCRYPTKEY hKey) {

    OutputDebugStringA("[F4D0] --> call to CryptDestroyKey");

    BOOL status = CryptDestroyKeyOrg(hKey);

    return status;

}


////CryptStringToBinaryA
//BOOL WINAPI CryptStringToBinaryAHooked(
//    _In_    LPCSTR pszString,
//    _In_    DWORD  cchString,
//    _In_    DWORD  dwFlags,
//    _In_    BYTE* pbBinary,
//    _Inout_ DWORD* pcbBinary,
//    _Out_   DWORD* pdwSkip,
//    _Out_   DWORD* pdwFlags) {
//
//    BOOL status = CryptStringToBinaryAOrg(pszString, cchString, dwFlags, pbBinary, pcbBinary, pdwSkip, pdwFlags);
//    return status;
//
//}


bool HookFunctions() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    // The functions to attach
    //DetourAttach((PVOID*)&BCryptCreateHashOrg, BCryptCreateHashHooked);
    //DetourAttach((PVOID*)&BCryptDecryptOrg, BCryptDecryptHooked);
    //DetourAttach((PVOID*)&BCryptDestroyHashOrg, BCryptDestroyHashHooked);
    //DetourAttach((PVOID*)&BCryptDestroyKeyOrg, BCryptDestroyKeyHooked);
    //DetourAttach((PVOID*)&BCryptDuplicateKeyOrg, BCryptDuplicateKeyHooked);
    //DetourAttach((PVOID*)&BCryptEncryptOrg, BCryptEncryptHooked);
    //DetourAttach((PVOID*)&BCryptExportKeyOrg, BCryptExportKeyHooked);
    //DetourAttach((PVOID*)&BCryptFinalizeKeyPairOrg, BCryptFinalizeKeyPairHooked);
    //DetourAttach((PVOID*)&BCryptFinishHashOrg, BCryptFinishHashHooked);
    //DetourAttach((PVOID*)&BCryptGenerateKeyPairOrg, BCryptGenerateKeyPairHooked);
    //DetourAttach((PVOID*)&BCryptGenerateSymmetricKeyOrg, BCryptGenerateSymmetricKeyHooked);
    //DetourAttach((PVOID*)&BCryptGenRandomOrg, BCryptGenRandomHooked);
    //DetourAttach((PVOID*)&BCryptGetPropertyOrg, BCryptGetPropertyHooked);
    //DetourAttach((PVOID*)&BCryptHashDataOrg, BCryptHashDataHooked);
    //DetourAttach((PVOID*)&BCryptImportKeyOrg, BCryptImportKeyHooked);
    //DetourAttach((PVOID*)&BCryptImportKeyPairOrg, BCryptImportKeyPairHooked);
    //DetourAttach((PVOID*)&BCryptOpenAlgorithmProviderOrg, BCryptOpenAlgorithmProviderHooked);
    //DetourAttach((PVOID*)&BCryptSetPropertyOrg, BCryptSetPropertyHooked);
    //DetourAttach((PVOID*)&CryptAcquireContextAOrg, CryptAcquireContextAHooked);
    //DetourAttach((PVOID*)&CryptAcquireContextWOrg, CryptAcquireContextWHooked);
    //DetourAttach((PVOID*)&CryptCreateHashOrg, CryptCreateHashHooked);
    //DetourAttach((PVOID*)&CryptDecryptOrg, CryptDecryptHooked);
    DetourAttach((PVOID*)&CryptEncryptOrg, CryptEncryptHooked);
    //DetourAttach((PVOID*)&CryptGenRandomOrg, CryptGenRandomHooked);
    //DetourAttach((PVOID*)&CryptHashDataOrg, CryptHashDataHooked);
    //DetourAttach((PVOID*)&CryptImportKeyOrg, CryptImportKeyHooked);
    //DetourAttach((PVOID*)&CryptReleaseContextOrg, CryptReleaseContextHooked);
    //DetourAttach((PVOID*)&CryptGetUserKeyOrg, CryptGetUserKeyHooked);
    //DetourAttach((PVOID*)&CryptGenKeyOrg, CryptGenKeyHooked);
    //DetourAttach((PVOID*)&CryptExportKeyOrg, CryptExportKeyHooked);
    //DetourAttach((PVOID*)&CryptDeriveKeyOrg, CryptDeriveKeyHooked);
    //DetourAttach((PVOID*)&CryptDestroyHashOrg, CryptDestroyHashHooked);
    //DetourAttach((PVOID*)&CryptDestroyKeyOrg, CryptDestroyKeyHooked);
    /*DetourAttach((PVOID*)&CryptStringToBinaryAOrg, CryptStringToBinaryAHooked);*/
    auto error = DetourTransactionCommit();
    return error == ERROR_SUCCESS;
}

bool DeHookFunctions() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    // The functions to deattach
    //DetourDetach((PVOID*)&BCryptCreateHashOrg, BCryptCreateHashHooked);
    //DetourDetach((PVOID*)&BCryptDecryptOrg, BCryptDecryptHooked);
    //DetourDetach((PVOID*)&BCryptDestroyHashOrg, BCryptDestroyHashHooked);
    //DetourDetach((PVOID*)&BCryptDestroyKeyOrg, BCryptDestroyKeyHooked);
    //DetourDetach((PVOID*)&BCryptDuplicateKeyOrg, BCryptDuplicateKeyHooked);
    //DetourDetach((PVOID*)&BCryptEncryptOrg, BCryptEncryptHooked);
    //DetourDetach((PVOID*)&BCryptExportKeyOrg, BCryptExportKeyHooked);
    //DetourDetach((PVOID*)&BCryptFinalizeKeyPairOrg, BCryptFinalizeKeyPairHooked);
    //DetourDetach((PVOID*)&BCryptFinishHashOrg, BCryptFinishHashHooked);
    //DetourDetach((PVOID*)&BCryptGenerateKeyPairOrg, BCryptGenerateKeyPairHooked);
    //DetourDetach((PVOID*)&BCryptGenerateSymmetricKeyOrg, BCryptGenerateSymmetricKeyHooked);
    //DetourDetach((PVOID*)&BCryptGenRandomOrg, BCryptGenRandomHooked);
    //DetourDetach((PVOID*)&BCryptGetPropertyOrg, BCryptGetPropertyHooked);
    //DetourDetach((PVOID*)&BCryptHashDataOrg, BCryptHashDataHooked);
    //DetourDetach((PVOID*)&BCryptImportKeyOrg, BCryptImportKeyHooked);
    //DetourDetach((PVOID*)&BCryptImportKeyPairOrg, BCryptImportKeyPairHooked);
    //DetourDetach((PVOID*)&BCryptOpenAlgorithmProviderOrg, BCryptOpenAlgorithmProviderHooked);
    //DetourDetach((PVOID*)&BCryptSetPropertyOrg, BCryptSetPropertyHooked);
    //DetourDetach((PVOID*)&CryptAcquireContextAOrg, CryptAcquireContextAHooked);
    //DetourDetach((PVOID*)&CryptAcquireContextWOrg, CryptAcquireContextWHooked);
    //DetourDetach((PVOID*)&CryptCreateHashOrg, CryptCreateHashHooked);
    //DetourDetach((PVOID*)&CryptDecryptOrg, CryptDecryptHooked);
    DetourDetach((PVOID*)&CryptEncryptOrg, CryptEncryptHooked);
    //DetourDetach((PVOID*)&CryptGenRandomOrg, CryptGenRandomHooked);
    //DetourDetach((PVOID*)&CryptHashDataOrg, CryptHashDataHooked);
    //DetourDetach((PVOID*)&CryptImportKeyOrg, CryptImportKeyHooked);
    //DetourDetach((PVOID*)&CryptReleaseContextOrg, CryptReleaseContextHooked);
    //DetourDetach((PVOID*)&CryptGetUserKeyOrg, CryptGetUserKeyHooked);
    //DetourDetach((PVOID*)&CryptGenKeyOrg, CryptGenKeyHooked);
    //DetourDetach((PVOID*)&CryptExportKeyOrg, CryptExportKeyHooked);
    //DetourDetach((PVOID*)&CryptDeriveKeyOrg, CryptDeriveKeyHooked);
    //DetourDetach((PVOID*)&CryptDestroyHashOrg, CryptDestroyHashHooked);
    //DetourDetach((PVOID*)&CryptDestroyKeyOrg, CryptDestroyKeyHooked);
    /*DetourDetach((PVOID*)&CryptStringToBinaryAOrg, CryptStringToBinaryAHooked);*/
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
                OutputDebugStringA("[F4D0] DLL_PROCESS_ATTACH ERROR Attaching");
            else
                OutputDebugStringA("[F4D0] DLL_PROCESS_ATTACH SUCCESS Attaching");
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


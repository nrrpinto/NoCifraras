// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (C) Microsoft. All rights reserved.
/*++

Abstract:

    Sample program for SHA 256 hashing using CNG

--*/


#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#pragma warning(disable : 4996)
#pragma warning(disable : 28193)


#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

void main(void)
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
        goto Cleanup;
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
        goto Cleanup;
    }

    //allocate the hash object on the heap
    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    if (NULL == pbHashObject)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
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
        goto Cleanup;
    }

    //allocate the hash buffer on the heap
    pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
    if (NULL == pbHash)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
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
        goto Cleanup;
    }

/////////////////////////////////////////////////////////////////////////////////////

    HANDLE hFile;
    hFile = CreateFile(L"Injector.exe",
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
    
    //DWORD fSize = 0;

    DWORD fSize = GetFileSize(hFile, &fSize);

    printf("SIZE of file: %d\n", fSize);

    BOOL result;
    LPVOID lpBuffer = (char*)malloc(fSize);
    DWORD readBytes = 1;
    result = ReadFile(hFile, lpBuffer, fSize, &readBytes, NULL);
    BCryptHashData(hHash, (PCWSTR)lpBuffer, fSize, 0);

    HANDLE hFile2;
    hFile2 = CreateFile(L"Injector2.exe",
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    DWORD writtenBytes = 1;
    WriteFile(hFile2, (PCWSTR)lpBuffer, fSize, &writtenBytes, NULL);

/////////////////////////////////////////////////////////////////////////////////////

    //close the hash
    if (!NT_SUCCESS(status = BCryptFinishHash(
        hHash,
        pbHash,
        cbHash,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptFinishHash\n", status);
        goto Cleanup;
    }
    //PCWSTR hashResult = (PCWSTR)pbHash;
    wprintf(L"Success!\n");

    char* hashResult = malloc(65 * sizeof(char));
    char* str_buf = malloc(5 * sizeof(char));
    memset(hashResult, 0, 65 * sizeof(char));
    memset(str_buf, 0, 5 * sizeof(char));
    for (int i = 0; i < 32; ++i)
    {
        sprintf_s(str_buf, 4, "%02x", pbHash[i]);
        printf("%s", str_buf);
        strcat_s(hashResult, 65, str_buf);
        //printf("%02x", pbHash[i]);
    }
    printf("\nThe HASH: %s", hashResult);

Cleanup:

    if (hAlg)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    if (hHash)
    {
        BCryptDestroyHash(hHash);
    }

    if (pbHashObject)
    {
        HeapFree(GetProcessHeap(), 0, pbHashObject);
    }

    if (pbHash)
    {
        HeapFree(GetProcessHeap(), 0, pbHash);
    }

}

////////////////////////////////////////////////////////////////////////////////
// ////////////////////////////////////////////////////////////////////////////////
// ////////////////////////////////////////////////////////////////////////////////
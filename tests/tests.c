#include <windows.h>
#include <stdio.h>
#include <string.h>

#pragma warning(disable : 4996)
#pragma warning(disable : 2371)

const wchar_t white_list[] = L"C:\\windows\\white_list.exe";

BOOL ListWhiteList()
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
            printf("FINISH\n");
            return FALSE;
            break;
        }
        printf("Position %d [%d]: %s\n", i, strlen((char*)lpBuffer), (char*)lpBuffer);
        result = ReadFile(hFile, lpBufferDelete, 1, NULL, NULL);
        VirtualFree(lpBuffer, 0, MEM_RELEASE);

    }
    return FALSE;
}

BOOL WriteToWhiteList(char* hash)
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

BOOL isInWhiteListHash(const char* hash)
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

int main(void)
{
    //BOOL result;
    //result= WriteToWhiteList("01054A3B2C17536B951D0E866C6231B1B9D34E348D5701EBEC4F47B54DC3186F");
    //printf("Result first %d\n", result);
    //printf("Last error: %d\n", GetLastError());
    //
    //result = WriteToWhiteList("8BCF2885A462E1C7FA460F6762979DE83B22A2629BA8CE5E7FD76BC09605A129");
    //printf("Result second %d\n", result);
    //printf("Last error: %d\n", GetLastError());

    //if (isInWhiteListHash("8BCF2885A462E1C7FA460F6762879DE83B22A2629BA8CE5E7FD76BC09605A129"))
    //    printf("Hash is present on the whitelist!");
    //else
    //    printf("Hash is NOT present on the whitelist!");
    
    //printf("PUTA 0\n");
    //char calc_hash[65] = "";
    //printf("PUTA 1\n");
    ////calc2_sha256("c:\\windows\\write.exe", calc_hash);
    //printf("PUTA 2\n");
    //printf("Hash calculated: %s", calc_hash);


}
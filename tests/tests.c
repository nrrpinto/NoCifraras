#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>

// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
// and compile with -DPSAPI_VERSION=1

int isDllInjected(DWORD processID, char* DLLname)
{
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i;

    // Print the process identifier.

    printf("\nProcess ID: %u\n", processID);

    // Get a handle to the process.

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, processID);
    if (NULL == hProcess)
        return 1;

    // Get a list of all the modules in this process.

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            TCHAR szModName[MAX_PATH];

            // Get the full path to the module's file.

            if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
                sizeof(szModName) / sizeof(TCHAR)))
            {
                //_tprintf(TEXT("\t%s (0x%08X)\n"), szModName, hMods[i]);
                int size = wcslen(szModName) + 1;
                char vOut[MAX_PATH];
                wcstombs_s(NULL, vOut, wcslen(szModName) + 1, szModName, wcslen(szModName) + 1);


               /* printf("szModName: %s\n", vOut);
                printf("DLLname: %s\n", DLLname);*/
                // Print the module name and handle value.
                if (strstr(vOut, DLLname) != NULL)
                {
                    _tprintf(TEXT("\t%s (0x%08X)\n"), szModName, hMods[i]);
                }
                //else
                //{
                //    _tprintf(TEXT("\tDLLname not found!!\n"));
                //}
                
            }
        }
    }

    // Release the handle to the process.

    CloseHandle(hProcess);

    return 0;
}

int main(void)
{

    isDllInjected(26764, "f4d0mon.dll");

    /*char* ModName = "C:\\Users\\Nuno Pinto\\OneDrive\\Cyber_Security\\_STUDY\\Master_Reversing_Malware\\M11.TFM\\code\\Chapter03\\x64\\Release\\f4d0mon.dll";
    char* DLL = "f4d0mon.dll";

    char* result = strstr(ModName, DLL);
    if(result != NULL)
    {
        printf("Result: %s\n", result);
    }
    else
    {
        printf("NOT FOUND!!");
    }
    */

    return 0;
}
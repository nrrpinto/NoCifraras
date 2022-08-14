#include <stdio.h>
#include <strsafe.h>
#include <string.h>
#include <stdlib.h>
#include <Windows.h>

#ifndef MAX_BUF
#define MAX_BUF 200
#endif

char DLLMonitor[] = "f4d0mon.dll";
char InjectorEXE[] = "Injector.exe";

int main()
{
    const int buffer_size = 400;
    char command_line[400] = " ";
    char space[] = " ";
    char DLLPath[150];
    char path[MAX_BUF];

    getcwd(path, MAX_BUF);

    // Create fullpathfor DLLMonitor
    strcat_s(DLLPath, 150, "\"");
    strcat_s(DLLPath, 150, path);
    strcat_s(DLLPath, 150, "\\");
    strcat_s(DLLPath, 150, DLLMonitor);
    strcat_s(DLLPath, 150, "\"");

    // Create the command line to inject the DLL
    strcat_s(command_line, buffer_size, InjectorEXE);
    strcat_s(command_line, buffer_size, space);
    strcat_s(command_line, buffer_size, "21936");
    strcat_s(command_line, buffer_size, space);
    strcat_s(command_line, buffer_size, DLLPath);
    
    printf(command_line);
    system(command_line);

    return 0;
}
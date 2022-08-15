#include <windows.h>
#include <stdio.h>


SYSTEMTIME time_difference(const SYSTEMTIME pSr, const SYSTEMTIME pSl)
{
    SYSTEMTIME t_res;
    FILETIME v_ftime;
    ULARGE_INTEGER v_ui;
    __int64 v_right, v_left, v_res;
    SystemTimeToFileTime(&pSr, &v_ftime);
    v_ui.LowPart = v_ftime.dwLowDateTime;
    v_ui.HighPart = v_ftime.dwHighDateTime;
    v_right = v_ui.QuadPart;

    SystemTimeToFileTime(&pSl, &v_ftime);
    v_ui.LowPart = v_ftime.dwLowDateTime;
    v_ui.HighPart = v_ftime.dwHighDateTime;
    v_left = v_ui.QuadPart;

    v_res = v_right - v_left;

    v_ui.QuadPart = v_res;
    v_ftime.dwLowDateTime = v_ui.LowPart;
    v_ftime.dwHighDateTime = v_ui.HighPart;
    FileTimeToSystemTime(&v_ftime, &t_res);
    return t_res;
}

int main(void)
{
    SYSTEMTIME st, lt, res;

    
    
    GetLocalTime(&lt);
    Sleep(1000);
    GetLocalTime(&st);
    
    printf("The old time is: %04d-%02d-%02d %02d:%02d:%02d\n", lt.wYear, lt.wMonth, lt.wDay, lt.wHour, lt.wMinute, lt.wSecond);
    printf("The new time is: %04d-%02d-%02d %02d:%02d:%02d\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    res = time_difference(st, lt);

    printf("%04d-%02d-%02d %02d:%02d:%02d\n", res.wYear, res.wMonth, res.wDay, res.wHour, res.wMinute, res.wSecond);



}
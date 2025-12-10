#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <algorithm>

class ProcessFinder {
public:
    // 輸入 "bsass.exe"，回傳 PID。沒找到回傳 0
    static DWORD FindPidByName(const std::wstring& processName) {
        DWORD pid = 0;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                    pid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
        return pid;
    }
};
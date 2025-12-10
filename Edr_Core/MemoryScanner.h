#pragma once
#include <windows.h>
#include <vector>
#include <iostream>
#include <string>

class MemoryScanner {
public:
    MemoryScanner() {}

    // [重構] 增加 filter 參數，預設只回傳已提交(Commit)的記憶體
    std::vector<MEMORY_BASIC_INFORMATION> ScanProcess(DWORD pid, bool onlyCommitted = true) {
        std::vector<MEMORY_BASIC_INFORMATION> regions;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hProcess == NULL) {
            // 在實務上，這裡應該寫 Log 或 throw exception，這裡先簡單 print
            return regions;
        }

        unsigned char* address = 0;
        MEMORY_BASIC_INFORMATION mbi;

        while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {

            // [重構] 過濾邏輯
            if (!onlyCommitted || mbi.State == MEM_COMMIT) {
                regions.push_back(mbi);
            }

            address = (unsigned char*)mbi.BaseAddress + mbi.RegionSize;
        }

        CloseHandle(hProcess);
        return regions;
    }

    // [新增功能] 判斷該記憶體區塊是否「可疑」(RWX)
    // RWX (Read-Write-Execute) 是惡意 Shellcode 最愛的權限
    bool IsSuspiciousRegion(const MEMORY_BASIC_INFORMATION& mbi) {
        if (mbi.State != MEM_COMMIT) return false;

        // 檢查 Protect 屬性是否包含 EXECUTE_READWRITE
        if (mbi.Protect == PAGE_EXECUTE_READWRITE) return true;

        // 有些 Malware 會用 EXECUTE_WRITECOPY
        if (mbi.Protect == PAGE_EXECUTE_WRITECOPY) return true;

        return false;
    }
};
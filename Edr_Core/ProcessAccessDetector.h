#pragma once
#include <windows.h>

class ProcessAccessDetector {
public:
    ProcessAccessDetector() : m_victimPid(0) {}

    void SetVictimPid(DWORD pid) {
        m_victimPid = pid;
    }

    // [新增] 加入白名單
    void AddWhitelist(const std::wstring& processName) {
        std::wstring lowerName = processName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
        m_whitelist.push_back(lowerName);
    }

    // [修改] 增加 attackerName 參數，並進行白名單檢查
    bool IsAccessingVictim(DWORD targetPid, const std::wstring& attackerName) {
        // 1. PID 檢查
        if (m_victimPid == 0) return false;
        if (targetPid != m_victimPid) return false;

        // 2. 白名單檢查
        std::wstring lowerAttacker = attackerName;
        std::transform(lowerAttacker.begin(), lowerAttacker.end(), lowerAttacker.begin(), ::towlower);

        for (const auto& allowed : m_whitelist) {
            // [修正] 改用 "==" 進行完全比對
            // 這樣 ttaskmgr.exe != taskmgr.exe，就不會被誤判為白名單
            if (lowerAttacker == allowed) {
                return false; // 是自己人，放行
            }
        }

        return true; // 是受害者，且不在白名單內 -> 報警
    }

private:
    DWORD m_victimPid;
    std::vector<std::wstring> m_whitelist; // [新增] 白名單列表
};
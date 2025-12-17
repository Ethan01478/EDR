//#pragma once
//#include <windows.h>
//
//class ProcessAccessDetector {
//public:
//    ProcessAccessDetector() : m_victimPid(0) {}
//
//    void SetVictimPid(DWORD pid) {
//        m_victimPid = pid;
//    }
//
//    // [新增] 加入白名單
//    void AddWhitelist(const std::wstring& processName) {
//        std::wstring lowerName = processName;
//        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
//        m_whitelist.push_back(lowerName);
//    }
//
//    // [修改] 增加 attackerName 參數，並進行白名單檢查
//    bool IsAccessingVictim(DWORD targetPid, const std::wstring& attackerName) {
//        // 1. PID 檢查
//        if (m_victimPid == 0) return false;
//        if (targetPid != m_victimPid) return false;
//
//        // 2. 白名單檢查
//        std::wstring lowerAttacker = attackerName;
//        std::transform(lowerAttacker.begin(), lowerAttacker.end(), lowerAttacker.begin(), ::towlower);
//
//        for (const auto& allowed : m_whitelist) {
//            // [修正] 改用 "==" 進行完全比對
//            // 這樣 ttaskmgr.exe != taskmgr.exe，就不會被誤判為白名單
//            if (lowerAttacker == allowed) {
//                return false; // 是自己人，放行
//            }
//        }
//
//        return true; // 是受害者，且不在白名單內 -> 報警
//    }
//
//private:
//    DWORD m_victimPid;
//    std::vector<std::wstring> m_whitelist; // [新增] 白名單列表
//};


#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <algorithm>
#include <iostream>

class ProcessAccessDetector {
public:
    ProcessAccessDetector() : m_protectPid(0) {}

    void SetVictimPid(DWORD pid) {
        m_protectPid = pid;
    }

    // [修改] 加入完整路徑到白名單 (自動轉小寫)
    void AddWhitelistPath(const std::wstring& fullPath) {
        std::wstring lowerPath = fullPath;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
        m_whitelist.push_back(lowerPath);
    }

    bool IsWhitelisted(const std::wstring& attackerFullPath) {
        if (attackerFullPath.empty()) return false;
        std::wstring lowerAttacker = attackerFullPath;
        std::transform(lowerAttacker.begin(), lowerAttacker.end(), lowerAttacker.begin(), ::towlower);

        for (const auto& allowedPath : m_whitelist) {
            if (lowerAttacker == allowedPath) {
                return true; // 在白名單內
            }
        }
        return false;
    }

    // [修改] 比對傳入的 attackerFullPath 是否在白名單內
    bool IsAccessingVictim(DWORD targetPid, const std::wstring& attackerFullPath) {
        // 1. PID 檢查
        if (m_protectPid == 0 || targetPid != m_protectPid) return false;

        // 2. 如果路徑是空的，視為可疑 (無法驗證身分)，直接不給過 (或者你可以選擇 return false 視策略而定)
        if (attackerFullPath.empty()) return true;

        // 3. 轉小寫以進行比對
        std::wstring lowerAttacker = attackerFullPath;
        std::transform(lowerAttacker.begin(), lowerAttacker.end(), lowerAttacker.begin(), ::towlower);

        // 4. 白名單嚴格比對
        for (const auto& allowedPath : m_whitelist) {
            if (lowerAttacker == allowedPath) {
                // [DEBUG] 白名單生效
                // wprintf(L"[INFO] Allowed access by whitelisted path: %s\n", attackerFullPath.c_str());
                return false; // 是自己人，放行
            }
        }

        return true; // 是受害者，且路徑不在白名單 -> 報警
    }
private:
    DWORD m_protectPid;
    std::vector<std::wstring> m_whitelist;
};
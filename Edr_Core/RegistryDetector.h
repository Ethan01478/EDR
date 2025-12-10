#pragma once
#include <string>
#include <algorithm>
#include <vector>

class RegistryDetector {
public:
    RegistryDetector() {}

    bool Analyze(const std::wstring& registryPath) {
        std::wstring lowerPath = registryPath;
        // 1. 轉小寫 (標準化)
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

        // 2. [必要條件] 必須是在 Software 機碼下
        // 這能排除 HKLM\SYSTEM 或 HKLM\SAM 等其他位置
        if (lowerPath.find(L"software") == std::wstring::npos) {
            return false;
        }

        // 3. [必要條件] 必須包含目標 "bombe"
        if (lowerPath.find(L"bombe") == std::wstring::npos) {
            return false;
        }

        // 4. [排除條件] 絕對不能是 User Hive (HKCU / HKU)
        // Kernel 路徑中，HKCU 必定位於 \REGISTRY\USER\ 下
        // 只要看到這個關鍵字，就代表它是使用者層級的，直接忽略
        if (lowerPath.find(L"\\registry\\user") != std::wstring::npos) {
            return false;
        }

        // 到了這裡，我們確認：
        // - 有 software
        // - 有 bombe
        // - 不是 user
        // 結論：這只能是 HKLM\SOFTWARE\BOMBE (包含相對路徑與 WoW64)
        return true;
    }

private:
    std::vector<std::wstring> m_targetSubstrings;
};
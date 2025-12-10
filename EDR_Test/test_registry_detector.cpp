#include "pch.h"
#include "gtest/gtest.h"
// 假設我們將在 Core 裡建立這個 header
#include "RegistryDetector.h" 

TEST(RegistryDetectorTest, DetectsAccessToBombeKey) {
    // Arrange
    // 這是我們要測試的邏輯核心
    RegistryDetector detector;

    // 模擬 ETW 抓到的路徑 (Kernel 裡的路徑通常長這樣)
    // HKEY_LOCAL_MACHINE: \registry\machine
    // HKEY_USERS: \registry\user
    // HKEY_CURRENT_USER: \registry\user\[user_sid]
    // HKEY_CLASSES_ROOT: \registry\machine\software\classes

    /*std::wstring suspiciousPath = L"\\REGISTRY\\MACHINE\\SOFTWARE\\BOMBE";
    std::wstring normalPath = L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft";
    std::wstring testPath = L"\\REGISTRY\\USER\\SOFTWARE\\BOMBE";*/

    //// Act
    //bool isMalicious = detector.Analyze(suspiciousPath);
    ////bool isNormal = detector.Analyze(normalPath);
    //bool isNormal = detector.Analyze(testPath);

    //// Assert
    //EXPECT_TRUE(isMalicious) << "Should detect access to BOMBE key";
    //EXPECT_FALSE(isNormal) << "Should ignore normal keys";
    
    std::vector<std::pair<std::wstring, bool>> testCases = {
        // [O] HKLM 標準路徑 -> 抓
        { L"\\REGISTRY\\MACHINE\\SOFTWARE\\BOMBE", true },

        // [O] 相對路徑 -> 抓
        { L"SOFTWARE\\BOMBE", true },

        // [O] WoW64 路徑 -> 抓
        { L"\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\BOMBE", true },

        // [X] HKCU (User Hive) -> 忽略 (因為我們排除了 \registry\user)
        { L"\\REGISTRY\\USER\\S-1-5-21-XXX-XXX\\SOFTWARE\\BOMBE", false },

        // [X] SYSTEM Hive -> 忽略 (因為路徑裡沒有 "software")
        { L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\BOMBE", false },
        // [X] 不含 bombe -> 忽略
		{ L"\\REGISTRY\\MACHINE\\SOFTWARE\\MICROSOFT", false }

    };

    for (const auto& testCase : testCases) {
        std::wstring path = testCase.first;
        bool expected = testCase.second;

        std::string pathStr;
        pathStr.reserve(path.size()); // 預留空間優化效能
        for (wchar_t wc : path) {
            pathStr.push_back(static_cast<char>(wc));
        }

        SCOPED_TRACE("Testing Path: " + pathStr);

        EXPECT_EQ(detector.Analyze(path), expected);
    }
}
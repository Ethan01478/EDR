#include "pch.h"
#include "gtest/gtest.h"
#include "ProcessAccessDetector.h"
#include <string>
#include <vector>

// 輔助函式：將 wstring 轉為 string 以便在 GTest 錯誤訊息中顯示
std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    return std::string(wstr.begin(), wstr.end());
}

TEST(ProcessAccessDetectorTest, DetectsAccessToVictimWithFullPath) {
    // Arrange
    ProcessAccessDetector detector;
    DWORD victimPid = 1234;
    detector.SetVictimPid(victimPid);

    // 設定白名單：只有位於 System32 下的 Taskmgr 才是好人
    std::wstring safePath = L"C:\\Windows\\System32\\Taskmgr.exe";
    detector.AddWhitelistPath(safePath);

    std::vector<std::pair<std::wstring, bool>> testCases = {
        // 格式: { 攻擊者路徑, 預期結果(True=報警/可疑, False=放行) }

        // 1. 標準白名單測試
        { L"C:\\Windows\\System32\\Taskmgr.exe", false },      // 完全符合 -> 放行
        { L"c:\\windows\\system32\\taskmgr.exe", false },      // 大小寫不同 -> 放行 (Windows路徑不分大小寫)

        // 2. 路徑偽裝測試 (最重要的新功能！)
        { L"C:\\Users\\Hacker\\Taskmgr.exe", true },           // 名字對，但路徑錯 -> 抓！
        { L"D:\\Games\\Taskmgr.exe", true },                   // 名字對，但路徑錯 -> 抓！
        { L"Taskmgr.exe", true },                              // 只有檔名沒有路徑 -> 抓！(因為不等於完整路徑)

        // 3. 惡意程式測試
        { L"C:\\Temp\\malv1.exe", true },                      // 未知程式 -> 抓！
        { L"C:\\Windows\\System32\\Notepad.exe", true },       // 同路徑但不在白名單 -> 抓！

        // 4. 模糊比對測試
        { L"C:\\Windows\\System32\\TaskmgrBad.exe", true },    // 前綴符合但檔名不對 -> 抓！
        { L"C:\\Windows\\System32\\Taskmgr.exe.bak", true },   // 後綴多餘 -> 抓！

        // 5. 空路徑測試 (根據程式碼邏輯)
        { L"", true }                                          // 路徑解析失敗 -> 抓！
    };

    for (const auto& testCase : testCases) {
        std::wstring attackerPath = testCase.first;
        bool expected = testCase.second;

        std::string pathStr = WStringToString(attackerPath);
        SCOPED_TRACE("Testing Attacker Path: " + (pathStr.empty() ? "<EMPTY>" : pathStr));

        // Act
        bool result = detector.IsAccessingVictim(victimPid, attackerPath);

        // Assert
        EXPECT_EQ(result, expected);
    }
}

TEST(ProcessAccessDetectorTest, IgnoresNonVictimTargets) {
    // Arrange
    ProcessAccessDetector detector;
    detector.SetVictimPid(1234); // 保護 PID 1234

    // Act
    // 攻擊者存取 PID 9999 (不是受害者)
    bool result = detector.IsAccessingVictim(9999, L"C:\\Temp\\malware.exe");

    // Assert
    // 應該回傳 false (忽略)，因為這不是我們要保護的目標
    EXPECT_FALSE(result);
}
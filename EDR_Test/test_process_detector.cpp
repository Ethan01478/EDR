#include "pch.h"
#include "gtest/gtest.h"
#include "ProcessAccessDetector.h" 

TEST(ProcessAccessDetectorTest, DetectsAccessToVictim) {
    // Arrange
    ProcessAccessDetector detector;
    detector.SetVictimPid(1234);
    detector.AddWhitelist(L"Taskmgr.exe");

    std::vector<std::pair<std::wstring, bool>> testCases = {
        { L"malv1.exe", true },          // 未知的壞人 -> 應該偵測
        { L"Taskmgr.exe", false },        // 白名單內的好人 -> 應該忽略
        { L"taskMGR.exe", false },        // 大小寫混合測試 -> 應該忽略
		{ L"notepad.exe", true },       // 沒在白名單
        { L"ttaskmgr.exe", true },       // 偽裝者 -> 抓！
        { L"fake_Taskmgr.exe", true }    // 偽裝者 -> 抓！
    };

    for (const auto& testCase : testCases) {
        std::wstring attackerName = testCase.first;
        bool expected = testCase.second;
        std::string nameStr;
        nameStr.reserve(attackerName.size());
        for (wchar_t wc : attackerName) {
            nameStr.push_back(static_cast<char>(wc));
        }
        SCOPED_TRACE("Testing Attacker Name: " + nameStr);
        // Act
        bool result = detector.IsAccessingVictim(1234, attackerName);
        // Assert
        EXPECT_EQ(result, expected);
	}

}
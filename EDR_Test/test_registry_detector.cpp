#include "pch.h"
#include "gtest/gtest.h"
// 假設我們將在 Core 裡建立這個 header
#include "RegistryDetector.h" 

TEST(RegistryDetectorTest, ECP_LogicVerification) {
    RegistryDetector detector;

    // --- Partition 1: 有效等價類 (Should Return TRUE) ---
    // 代表性樣本：惡意軟體可能使用的各種路徑格式
    std::vector<std::wstring> maliciousInputs = {
        L"\\REGISTRY\\MACHINE\\SOFTWARE\\BOMBE",             // [標準絕對路徑]
        L"SOFTWARE\\BOMBE",                                  // [相對路徑]
        L"\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\BOMBE" // [WoW64 轉導路徑]
    };

    for (const auto& path : maliciousInputs) {
        SCOPED_TRACE("Testing Malicious Partition: " + std::string(path.begin(), path.end()));
        EXPECT_TRUE(detector.Analyze(path)) << "Failed to detect malicious path";
    }

    // --- Partition 2: 無效等價類 (Should Return FALSE) ---
    // 代表性樣本：系統正常運作但不應觸發警報的路徑
    std::vector<std::wstring> benignInputs = {
        L"\\REGISTRY\\USER\\S-1-5-21-XXX\\SOFTWARE\\BOMBE", // [User Hive] - 規則定義只監控 Machine
        L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet\\Services",// [Non-Software] - 非目標 Hive
        L"\\REGISTRY\\MACHINE\\SOFTWARE\\MICROSOFT"          // [Irrelevant App] - 正常軟體
    };

    for (const auto& path : benignInputs) {
        SCOPED_TRACE("Testing Benign Partition: " + std::string(path.begin(), path.end()));
        EXPECT_FALSE(detector.Analyze(path)) << "False positive on benign path";
    }
}

TEST(RegistryDetectorTest, Robustness_ErrorHandling) {
    RegistryDetector detector;

    // Case 1: 空輸入 (Empty Input)
    // 預期：回傳 false，且不應該 Crash 或拋出 Exception
    EXPECT_FALSE(detector.Analyze(L"")) << "Should handle empty string gracefully";

    // Case 2: 極長字串 (Buffer Overflow / DoS Simulation)
    // 模擬駭客試圖用超長路徑癱瘓 EDR 分析引擎
    std::wstring longString(32768, L'A'); // 超過 Windows MAX_PATH 很多的長度
    EXPECT_FALSE(detector.Analyze(longString)) << "Should handle verify long string without crashing";

    // Case 3: 特殊字元與非標準格式 (Malformed Input)
    // 測試 parser 是否會因為奇怪的符號而發生記憶體錯誤
    std::wstring malformedPath = L"\\\\?\\GlobalRoot\\Device\\HarddiskVolume1\\Invalid|Char*In?Path";
    EXPECT_FALSE(detector.Analyze(malformedPath)) << "Should handle malformed paths";
}
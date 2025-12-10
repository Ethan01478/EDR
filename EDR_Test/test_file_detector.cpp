#include "pch.h" // 如果你的專案有使用 Precompiled Headers
#include <gtest/gtest.h>
#include "FileDetector.h"

// ------------------------------------------------------------------------
// 測試夾具 (Test Fixture)
// ------------------------------------------------------------------------
class FileDetectorTest : public ::testing::Test {
protected:
    FileDetector* detector;

    void SetUp() override {
        // 每個測試開始前建立一個新的 detector
        detector = new FileDetector();
    }

    void TearDown() override {
        // 測試結束後清理
        delete detector;
    }
};

// ------------------------------------------------------------------------
// Test Case 1: 測試標準的 Chrome/Edge 路徑 (Positive Case)
// ------------------------------------------------------------------------
TEST_F(FileDetectorTest, DetectsStandardLoginDataPaths) {
    // 模擬 Chrome 的路徑
    std::wstring chromePath = L"C:\\Users\\bombe\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data";
    EXPECT_TRUE(detector->Analyze(chromePath)) << "Should detect Chrome Login Data";

    // 模擬 Edge 的路徑
    std::wstring edgePath = L"C:\\Users\\User\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data";
    EXPECT_TRUE(detector->Analyze(edgePath)) << "Should detect Edge Login Data";
}

// ------------------------------------------------------------------------
// Test Case 2: 測試大小寫不敏感 (Case Insensitivity)
// ------------------------------------------------------------------------
TEST_F(FileDetectorTest, IgnoresCaseDifferences) {
    // 測試全大寫
    EXPECT_TRUE(detector->Analyze(L"C:\\USERS\\ADMIN\\LOGIN DATA"));

    // 測試混合大小寫
    EXPECT_TRUE(detector->Analyze(L"C:\\Users\\Admin\\loGiN DaTa"));
}

// ------------------------------------------------------------------------
// Test Case 3: 測試正常檔案 (Negative Case)
// ------------------------------------------------------------------------
TEST_F(FileDetectorTest, IgnoresSafeFiles) {
    // 系統檔案
    EXPECT_FALSE(detector->Analyze(L"C:\\Windows\\System32\\kernel32.dll"));

    // 一般文件
    EXPECT_FALSE(detector->Analyze(L"C:\\Users\\User\\Documents\\ProjectProposal.docx"));

    // 包含 "Login" 但沒有 "Data" 的檔案 (測試模糊比對邊界)
    EXPECT_FALSE(detector->Analyze(L"C:\\Users\\User\\Desktop\\Login_Script.bat"));
}

// ------------------------------------------------------------------------
// Test Case 4: 邊界測試 (Edge Cases)
// ------------------------------------------------------------------------
TEST_F(FileDetectorTest, HandlesEmptyAndWeirdPaths) {
    // 空字串
    EXPECT_FALSE(detector->Analyze(L""));

    // 只有檔名沒有路徑
    EXPECT_TRUE(detector->Analyze(L"Login Data"));

    // 備份檔 (根據目前的 substring 邏輯，這應該要被偵測到)
    EXPECT_TRUE(detector->Analyze(L"D:\\Backup\\2025\\Chrome_Login Data.bak"));
}
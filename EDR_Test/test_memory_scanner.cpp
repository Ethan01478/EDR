#include "pch.h"
#include "gtest/gtest.h"
#include <windows.h>
#include <vector>

// 假設這將是我們在 Core 裡面的 Header
#include "MemoryScanner.h" 

TEST(MemoryScannerTest, EnumerateRegionsReturnsNonEmptyList) {
    // Arrange
    MemoryScanner scanner;
    DWORD myPid = GetCurrentProcessId();

    // Act
    // 我們預期由一個 Scan 函數回傳記憶體區塊列表
    std::vector<MEMORY_BASIC_INFORMATION> regions = scanner.ScanProcess(myPid);

    // Assert
    // 任何活著的 Process 肯定都有記憶體區塊 (PE Header, Stack, Heap...)
    EXPECT_FALSE(regions.empty()) << "Should return memory regions for a valid process";

    // 進一步驗證：應該至少要找到一個 MEM_COMMIT (已使用) 的區塊
    bool foundCommit = false;
    for (const auto& region : regions) {
        if (region.State == MEM_COMMIT) {
            foundCommit = true;
            break;
        }
    }
    EXPECT_TRUE(foundCommit) << "Should find at least one committed memory region";
}

TEST(MemoryScannerTest, DetectsSuspiciousRWXRegion) {
    MemoryScanner scanner;
    MEMORY_BASIC_INFORMATION suspiciousMbi = { 0 };
    suspiciousMbi.State = MEM_COMMIT;
    suspiciousMbi.Protect = PAGE_EXECUTE_READWRITE; // 這是最可疑的權限

    MEMORY_BASIC_INFORMATION normalMbi = { 0 };
    normalMbi.State = MEM_COMMIT;
    normalMbi.Protect = PAGE_READONLY;

    EXPECT_TRUE(scanner.IsSuspiciousRegion(suspiciousMbi));
    EXPECT_FALSE(scanner.IsSuspiciousRegion(normalMbi));
}
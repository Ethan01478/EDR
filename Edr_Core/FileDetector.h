#pragma once
#include <string>
#include <vector>

class FileDetector {
public:
    FileDetector();
    ~FileDetector();

    // 核心分析功能：輸入檔案路徑，回傳是否為敏感檔案
    bool Analyze(const std::wstring& filePath);

private:
    // 輔助函式：轉小寫以進行不分大小寫的比對
    std::wstring ToLower(const std::wstring& str);
};
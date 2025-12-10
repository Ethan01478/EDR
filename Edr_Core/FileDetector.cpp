#include "pch.h" // 如果你的專案沒用 Precompiled Header，這行可以拿掉
#include "FileDetector.h"
#include <algorithm>
#include <cwctype>

FileDetector::FileDetector() {}

FileDetector::~FileDetector() {}

bool FileDetector::Analyze(const std::wstring& filePath) {
    if (filePath.empty()) return false;

    // 1. 轉小寫 (Case-insensitive check)
    // 這樣 "login data", "Login Data", "LOGIN DATA" 都能抓到
    std::wstring lowerPath = ToLower(filePath);

    // 2. 規則比對
    // Rule 1: Chrome/Edge 的 Login Data 資料庫
    if (lowerPath.find(L"login data") != std::wstring::npos) {
        return true;
    }

    // [擴充] 未來可以在這裡加更多規則，例如：
    // if (lowerPath.find(L"wallet.dat") != std::wstring::npos) return true;
    // if (lowerPath.find(L"id_rsa") != std::wstring::npos) return true;

    return false;
}

std::wstring FileDetector::ToLower(const std::wstring& str) {
    std::wstring lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    return lower;
}
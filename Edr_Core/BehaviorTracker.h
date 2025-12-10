#pragma once
#include <windows.h>
#include <map>
#include <mutex>
#include <string>
#include <set>
#include <vector>

// 定義可疑行為類型
enum class SuspiciousAction {
    RegistryAccess,
    FileAccess,
    ProcessAccess
};

struct BehaviorScore {
    bool hasRegistry = false;
    bool hasFile = false;
    bool hasProcess = false;

    // 記錄詳細資訊以供 Log 使用
    std::vector<std::wstring> logs;

    int GetCount() const {
        return (hasRegistry ? 1 : 0) + (hasFile ? 1 : 0) + (hasProcess ? 1 : 0);
    }
};

class BehaviorTracker {
public:
    // 回傳 true 代表該 Process 的行為分數剛剛達到閾值 (>= 2)
    // 這樣我們可以只在達到那一刻觸發警報，避免重複觸發
    bool AddBehavior(DWORD pid, SuspiciousAction action, const std::wstring& detail) {
        std::lock_guard<std::mutex> lock(m_mutex);

        // 如果已經被標記為惡意程式，就不再重複計算 (避免洗版)
        if (m_detectedPids.count(pid)) return false;

        BehaviorScore& score = m_scores[pid];

        // 記錄行為與 Log
        switch (action) {
        case SuspiciousAction::RegistryAccess:
            if (!score.hasRegistry) {
                score.hasRegistry = true;
                score.logs.push_back(L"[Registry] " + detail);
            }
            break;
        case SuspiciousAction::FileAccess:
            if (!score.hasFile) {
                score.hasFile = true;
                score.logs.push_back(L"[File] " + detail);
            }
            break;
        case SuspiciousAction::ProcessAccess:
            if (!score.hasProcess) {
                score.hasProcess = true;
                score.logs.push_back(L"[Process] " + detail);
            }
            break;
        }

        // 檢查是否達到閾值 (2分)
        if (score.GetCount() >= 2) {
            m_detectedPids.insert(pid);
            return true; // 觸發警報！
        }

        return false;
    }

    std::vector<std::wstring> GetLogs(DWORD pid) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_scores.count(pid)) return m_scores[pid].logs;
        return {};
    }

    void RemovePid(DWORD pid) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_scores.erase(pid);
        m_detectedPids.erase(pid);
    }

private:
    std::map<DWORD, BehaviorScore> m_scores;
    std::set<DWORD> m_detectedPids; // 已定罪名單，防止重複警報
    std::mutex m_mutex;
};
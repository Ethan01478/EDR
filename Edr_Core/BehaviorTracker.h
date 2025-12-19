#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <map>
#include <mutex>
#include <string>
#include <set>
#include <vector>
#include <deque>
#include <iostream>

// 定義可疑行為類型
enum class SuspiciousAction {
    RegistryAccess,
    FileAccess,
    ProcessAccess,
    Injection
};

// 嫌疑犯結構 (用於 Handle/Access 階段的暫存)
struct SuspectInfo {
    DWORD pid;
    ULONGLONG timestamp;
    std::wstring type;
    std::wstring name;
    std::wstring fullPath;
};

// 注入記錄結構 (用於 CreateRemoteThread 階段的確證)
struct InjectionRecord {
    DWORD injectorPid;
    std::wstring injectorName;
};

struct BehaviorScore {
    bool hasRegistry = false;
    bool hasFile = false;
    bool hasProcess = false;
    bool hasInjection = false;
    ULONGLONG deathTime = 0;

    std::vector<std::wstring> logs;

    int GetCount() const {
        return  (hasRegistry ? 1 : 0) + (hasFile ? 1 : 0) + (hasProcess ? 1 : 0);
    }
};

class BehaviorTracker {
public:
    // ----------------------------------------------------------------
    // [新功能] 1. 登記注入關係 (誰注入了誰)
    // ----------------------------------------------------------------
    void RegisterInjection(DWORD victimPid, DWORD injectorPid, const std::wstring& injectorName) {
        std::lock_guard<std::mutex> lock(m_injectionMutex);
        m_injectionMap[victimPid] = { injectorPid, injectorName };
    }

    // ----------------------------------------------------------------
    // [新功能] 2. 查詢兇手 (如果此 PID 是受害者，回傳兇手名字)
    // ----------------------------------------------------------------
    std::wstring GetInjectorName(DWORD victimPid) {
        std::lock_guard<std::mutex> lock(m_injectionMutex);
        auto it = m_injectionMap.find(victimPid);
        if (it != m_injectionMap.end()) {
            return it->second.injectorName;
        }
        return L"";
    }

    // ----------------------------------------------------------------
    // 3. 登記嫌疑犯 (包含名字備份) - 用於 ObHandle 監控
    // ----------------------------------------------------------------
    void RegisterSuspect(DWORD pid, const std::wstring& type, const std::wstring& name, const std::wstring& path) {
        std::lock_guard<std::mutex> lock(m_candidateMutex);
        ULONGLONG now = GetTickCount64();

        // 清理過期資料 (>5秒)
        while (!m_candidates.empty() && (now - m_candidates.front().timestamp > 5000)) {
            m_candidates.pop_front();
        }

        m_candidates.push_back({ pid, now, type, name, path });
    }

    // ----------------------------------------------------------------
    // 4. 取得近期嫌疑犯 (回傳完整結構)
    // ----------------------------------------------------------------
    std::vector<SuspectInfo> GetRecentSuspects(DWORD timeWindowMs) {
        std::lock_guard<std::mutex> lock(m_candidateMutex);
        std::vector<SuspectInfo> result;
        std::set<DWORD> uniquePids;
        ULONGLONG now = GetTickCount64();

        // 從最新開始找
        for (auto it = m_candidates.rbegin(); it != m_candidates.rend(); ++it) {
            if (now - it->timestamp <= timeWindowMs) {
                if (uniquePids.find(it->pid) == uniquePids.end()) {
                    result.push_back(*it);
                    uniquePids.insert(it->pid);
                }
            }
            else {
                break;
            }
        }
        return result;
    }

    // ----------------------------------------------------------------
    // 5. 檢查記憶體位址是否在 Image 範圍內 (反 Shellcode)
    // ----------------------------------------------------------------
    bool IsAddressInImage(DWORD pid, void* address) {
        if (pid == 0 || address == nullptr) return false;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) return false;

        HMODULE modules[1024];
        DWORD cbNeeded = 0;
        bool found = false;
        uintptr_t targetAddr = reinterpret_cast<uintptr_t>(address);

        if (EnumProcessModules(hProcess, modules, sizeof(modules), &cbNeeded)) {
            int count = cbNeeded / sizeof(HMODULE);
            for (int i = 0; i < count; i++) {
                MODULEINFO mi = { 0 };
                if (GetModuleInformation(hProcess, modules[i], &mi, sizeof(mi))) {
                    uintptr_t base = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
                    uintptr_t end = base + mi.SizeOfImage;
                    if (targetAddr >= base && targetAddr < end) {
                        found = true;
                        break;
                    }
                }
            }
        }
        CloseHandle(hProcess);
        return found;
    }

    // ----------------------------------------------------------------
    // 舊有功能保留 (Behavior Score)
    // ----------------------------------------------------------------
    bool AddBehavior(DWORD pid, SuspiciousAction action, const std::wstring& detail) {
        std::lock_guard<std::mutex> lock(m_mutex);

        BehaviorScore& score = m_scores[pid];
        switch (action) {
        case SuspiciousAction::RegistryAccess: if (!score.hasRegistry) { score.hasRegistry = true; score.logs.push_back(L"[Reg] " + detail); } break;
        case SuspiciousAction::FileAccess: if (!score.hasFile) { score.hasFile = true; score.logs.push_back(L"[File] " + detail); } break;
        case SuspiciousAction::ProcessAccess: if (!score.hasProcess) { score.hasProcess = true; score.logs.push_back(L"[Proc] " + detail); } break;
        case SuspiciousAction::Injection: if (!score.hasInjection) { score.hasInjection = true; score.logs.push_back(L"[Inj] " + detail); } break;
        }

		int currentScore = 0;
        {
            std::lock_guard<std::mutex> lock(count_mutex);
            currentScore = score.GetCount();
		    printf("score:%d\n", currentScore);
        }

        if (m_detectedPids.count(pid)) return true;

        bool isMalware = false;

        if (score.hasInjection) {
            if (currentScore >= 1) isMalware = true;
        }
        else {
            if (currentScore >= 2) isMalware = true;
        }

        if (isMalware) {
            m_detectedPids.insert(pid);
            return true;
        }
        return false;
    }

    void RemovePid(DWORD pid) {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = m_scores.find(pid);
        if (it != m_scores.end()) {
            // 標記死亡時間
            it->second.deathTime = GetTickCount64();
        }

        // 注入關係也可以選擇延遲刪除，或者直接刪除 (視需求而定)
        // 這裡為了簡單，注入關係我們通常可以直接刪，或者另外用一個類似機制的 map
        {
            std::lock_guard<std::mutex> injLock(m_injectionMutex);
            m_injectionMap.erase(pid);
        }

        // [關鍵] 順便執行一次清理，把那些「死很久」的清掉
        PurgeStaleRecords();
    }

private:
    std::map<DWORD, BehaviorScore> m_scores;
    std::set<DWORD> m_detectedPids;

    // 注入關係表: <Victim PID, InjectionRecord>
    std::map<DWORD, InjectionRecord> m_injectionMap;
    std::mutex m_injectionMutex;

    std::deque<SuspectInfo> m_candidates;
    std::mutex m_mutex;
    std::mutex count_mutex;
    std::mutex m_candidateMutex;

    // [設定] 寬限期 (毫秒)，例如 5 秒
    const ULONGLONG GRACE_PERIOD_MS = 5000;

    // [內部功能] 清理真正過期的資料
    void PurgeStaleRecords() {
        // 注意：這個函式必須在外部已經 lock m_mutex 的情況下呼叫
        ULONGLONG now = GetTickCount64();

        for (auto it = m_scores.begin(); it != m_scores.end(); ) {
            // 如果 deathTime != 0 (已死) 且 (現在時間 - 死亡時間 > 寬限期)
            if (it->second.deathTime != 0 && (now - it->second.deathTime > GRACE_PERIOD_MS)) {
                // 真正刪除
                m_detectedPids.erase(it->first); // 同步移除偵測名單
                it = m_scores.erase(it);
            }
            else {
                ++it;
            }
        }
    }
};
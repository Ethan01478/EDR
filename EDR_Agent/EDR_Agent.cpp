#define WIN32_LEAN_AND_MEAN

// =========================================================
// [CONFIG] Contest Configuration
// =========================================================
#define USER_SECRET "0xBGaqjzZL7khGY5AcFs3oi0lIMmkvMF"
//#define USER_SECRET "YYJRAusNp2hR669NEF2xFpEfZQ6HAmaI" 
#define SUBMISSION_HOST L"submit.bombe.top"
#define SUBMISSION_PATH L"/submitEdrAns"
#define MALWARE_PREFIX L"BOMBE_EDR_FLAG_"

#include <initguid.h> 
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <mutex>
#include <algorithm>
#include <thread>
#include <set>
#include <evntrace.h>
#include <winhttp.h> 

#include "krabs/krabs.hpp"
#include "RegistryDetector.h"
#include "ProcessFinder.h"
#include "ProcessAccessDetector.h"
#include "MalwareScanner.h"
#include "FileDetector.h"
#include "BehaviorTracker.h"

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "uuid.lib")
#pragma comment(lib, "winhttp.lib") 

// =========================================================
// Submission Logic
// =========================================================
bool g_hasSubmitted = false;
std::mutex g_submissionMutex;

std::string WideToAnsi(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

void SubmitMalware(std::wstring filename) {
    std::lock_guard<std::mutex> lock(g_submissionMutex);
    if (g_hasSubmitted) return;
    wprintf(L"[SUBMISSION] Submitting detected malware: %s\n", filename.c_str());
    size_t lastSlash = filename.find_last_of(L"\\");
    if (lastSlash != std::wstring::npos) {
        filename = filename.substr(lastSlash + 1);
    }
    if (filename.find(MALWARE_PREFIX) == std::wstring::npos) return;

    HINTERNET hSession = WinHttpOpen(L"EDR_Agent/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession) {
        HINTERNET hConnect = WinHttpConnect(hSession, SUBMISSION_HOST, INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (hConnect) {
            HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", SUBMISSION_PATH, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
            if (hRequest) {
                std::string json = "{\"answer\": \"" + WideToAnsi(filename) + "\", \"secret\": \"" + USER_SECRET + "\"}";
                std::wstring headers = L"Content-Type: application/json\r\n";

                if (WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)headers.length(), (LPVOID)json.c_str(), (DWORD)json.length(), (DWORD)json.length(), 0)) {
                    WinHttpReceiveResponse(hRequest, NULL);
                    g_hasSubmitted = true;
                }
                WinHttpCloseHandle(hRequest);
            }
            WinHttpCloseHandle(hConnect);
        }
        WinHttpCloseHandle(hSession);
    }
}

// =========================================================
// Helpers & Globals
// =========================================================

void KillEtwSession(const std::wstring& sessionName) {
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
    EVENT_TRACE_PROPERTIES* pSessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    if (pSessionProperties) {
        ZeroMemory(pSessionProperties, bufferSize);
        pSessionProperties->Wnode.BufferSize = bufferSize;
        pSessionProperties->Wnode.Guid = { 0 };
        pSessionProperties->Wnode.ClientContext = 1;
        pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        ControlTraceW(0, sessionName.c_str(), pSessionProperties, EVENT_TRACE_CONTROL_STOP);
        free(pSessionProperties);
    }
}

class ProcessFreezer {
public:
    ProcessFreezer(DWORD pid) {}
    ~ProcessFreezer() {}
};

struct ProcessInfo {
    std::wstring name;
    std::wstring fullPath;
    DWORD parentPid;
};

std::map<DWORD, ProcessInfo> processMap;
std::map<DWORD, ProcessInfo> g_processHistory;
std::mutex mapMutex;

std::set<DWORD> g_detectedMalwarePids;
std::mutex g_scanSetMutex;
std::mutex g_consoleMutex;

DWORD g_currentVictimPid = 0;

RegistryDetector g_registryDetector;
ProcessFinder g_processFinder;
ProcessAccessDetector g_accessDetector;
MalwareScanner g_Scanner;
FileDetector g_fileDetector;
BehaviorTracker g_behaviorTracker;

// Kernel Trace Object Guid
static const GUID ObTraceGuid = { 0xC8AD7295, 0x9D27, 0x41f1, { 0x95, 0xF8, 0x18, 0x54, 0x4B, 0x9E, 0x4C, 0x5A } };
static const GUID AuditApiCallsGuid = { 0xe02a841c, 0x75a3, 0x4fa7, { 0xaf, 0xc8, 0xae, 0x09, 0xcf, 0x9b, 0x7f, 0x23 } };
 
// ---------------------------------------------------------
// Path & Process Helpers
// ---------------------------------------------------------

std::wstring AnsiToWide(const std::string& str) {
    if (str.empty()) return L"";
    int size_needed = MultiByteToWideChar(CP_ACP, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_ACP, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

std::wstring DevicePathToDosPath(const std::wstring& devicePath) {
    static std::map<std::wstring, std::wstring> deviceMap;
    static bool initialized = false;
    if (!initialized) {
        wchar_t driveStrings[512];
        if (GetLogicalDriveStringsW(512, driveStrings)) {
            wchar_t* drive = driveStrings;
            while (*drive) {
                wchar_t targetPath[MAX_PATH];
                std::wstring driveName = drive;
                if (!driveName.empty() && driveName.back() == L'\\') driveName.pop_back();
                if (QueryDosDeviceW(driveName.c_str(), targetPath, MAX_PATH)) {
                    deviceMap[targetPath] = driveName;
                }
                drive += wcslen(drive) + 1;
            }
        }
        initialized = true;
    }
    for (const auto& pair : deviceMap) {
        if (devicePath.find(pair.first) == 0) {
            return pair.second + devicePath.substr(pair.first.length());
        }
    }
    return devicePath;
}

std::wstring GetSystem32Path() {
    wchar_t buffer[MAX_PATH];
    if (GetSystemDirectoryW(buffer, MAX_PATH) > 0) return std::wstring(buffer);
    return L"C:\\Windows\\System32";
}

std::wstring GetProcessNameByPid(DWORD pid) {
    if (pid == 0) return L"System Idle";
    if (pid == 4) return L"System";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return L"Unknown";
    wchar_t buffer[MAX_PATH];
    std::wstring result = L"Unknown";
    if (GetProcessImageFileNameW(hProcess, buffer, MAX_PATH) > 0) {
        std::wstring fullPath = buffer;
        size_t lastSlash = fullPath.find_last_of(L"\\");
        result = (lastSlash != std::wstring::npos) ? fullPath.substr(lastSlash + 1) : fullPath;
    }
    CloseHandle(hProcess);
    return result;
}

std::wstring ResolveProcessName(DWORD pid) {
    std::wstring name = L"Unknown";
    bool found = false;
    {
        std::lock_guard<std::mutex> lock(mapMutex);
        if (processMap.find(pid) != processMap.end()) {
            name = processMap[pid].name;
            found = true;
        }
        else if (g_processHistory.find(pid) != g_processHistory.end()) {
            name = g_processHistory[pid].name;
            found = true;
        }
    }
    if (!found) name = GetProcessNameByPid(pid);
    size_t lastSlash = name.find_last_of(L"\\");
    if (lastSlash != std::wstring::npos) name = name.substr(lastSlash + 1);
    return name;
}

std::wstring ResolveProcessPath(DWORD pid) {
    std::wstring fullPath = L"";
    bool found = false;
    {
        std::lock_guard<std::mutex> lock(mapMutex);
        if (processMap.find(pid) != processMap.end()) {
            fullPath = processMap[pid].fullPath;
            found = true;
        }
        else if (g_processHistory.find(pid) != g_processHistory.end()) {
            fullPath = g_processHistory[pid].fullPath;
            found = true;
        }
    }

    if (!found || fullPath.empty()) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProcess) {
            wchar_t buffer[MAX_PATH];
            if (GetProcessImageFileNameW(hProcess, buffer, MAX_PATH) > 0) {
                fullPath = DevicePathToDosPath(buffer);
            }
            CloseHandle(hProcess);
        }
    }
    return fullPath;
}

// ---------------------------------------------------------
// [Core Logic] Shell & Attribution Helpers
// ---------------------------------------------------------

bool IsShellProcess(const std::wstring& path) {
    if (path.empty()) return false;
    std::wstring lowerPath = path;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), towlower);

    static const std::vector<std::wstring> shells = {
        L"\\cmd.exe", L"\\powershell.exe", L"\\pwsh.exe",
        L"\\explorer.exe", L"\\conhost.exe", L"\\services.exe"
    };

    for (const auto& s : shells) {
        if (lowerPath.size() >= s.size() &&
            lowerPath.compare(lowerPath.size() - s.size(), s.size(), s) == 0) {
            return true;
        }
    }
    return false;
}

DWORD GetRealParentPid(DWORD pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == pid) {
                CloseHandle(hSnapshot);
                return pe32.th32ParentProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return 0;
}

// ---------------------------------------------------------
// Scanning Logic
// ---------------------------------------------------------

bool IsEtwPatched(DWORD pid) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;
    void* pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwEventWrite) return false;
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return false;
    unsigned char buffer[1] = { 0 };
    SIZE_T bytesRead = 0;
    bool isPatched = false;
    if (ReadProcessMemory(hProcess, pEtwEventWrite, buffer, 1, &bytesRead)) {
        if (buffer[0] == 0xC3 || buffer[0] == 0xC2) isPatched = true;
    }
    CloseHandle(hProcess);
    return isPatched;
}

bool PerformUnifiedScan(DWORD pid, bool isCaughtAlive, const std::wstring& fullPath, std::wstring& outSource) {
    if (isCaughtAlive && IsEtwPatched(pid)) {
        outSource = L"Defense Evasion (ETW Patching Detected)";
        return true;
    }
    if (isCaughtAlive && g_Scanner.ScanProcessMemory(pid)) {
        outSource = L"Memory (Unpacked Payload)";
        return true;
    }
    {
        std::lock_guard<std::mutex> l(g_scanSetMutex);
        if (g_detectedMalwarePids.find(pid) != g_detectedMalwarePids.end()) return true;
    }
    if (!fullPath.empty() && g_Scanner.ScanFile(fullPath)) return true;
    return false;
}

void HandleConfirmedMalware(DWORD pid, const std::wstring& processName, const std::wstring& fullPath, const std::wstring& detectionSource) {
    std::lock_guard<std::mutex> lock(g_consoleMutex);
    wprintf(L"\n==========================================================\n");
    wprintf(L"[!!!] MALWARE DETECTED [!!!]\n");
    wprintf(L"    PID           : %d\n", pid);
    wprintf(L"    Process Name  : %s\n", processName.c_str());
    wprintf(L"    Full Path     : %s\n", fullPath.c_str());
    wprintf(L"    Detection Src : %s\n", detectionSource.c_str());
    wprintf(L"==========================================================\n");

    std::wstring injectorName = g_behaviorTracker.GetInjectorName(pid);
    if (!injectorName.empty()) {
        //wprintf(L"[INFO] Process %d is a VICTIM of Injection.\n", pid);
        //wprintf(L"[INFO] Real Culprit (Injector) is: %s\n", injectorName.c_str());
        size_t lastSlash = injectorName.find_last_of(L"\\");
        if (lastSlash != std::wstring::npos) injectorName = injectorName.substr(lastSlash + 1);
        //wprintf(L"[INFO] Redirecting Submission to: %s\n", injectorName.c_str());
        SubmitMalware(injectorName);
        return;
    }
    //wprintf(L"[INFO] Submitting Detected Process: %s\n", processName.c_str());
    SubmitMalware(processName);
}

// ---------------------------------------------------------
// ETW Callbacks
// ---------------------------------------------------------

void OnProcessStart(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);
    if (schema.event_opcode() == 1) {
        krabs::parser parser(schema);
        try {
            std::string ansiName = parser.parse<std::string>(L"ImageFileName");
            DWORD ppid = parser.parse<DWORD>(L"ParentProcessId");
            DWORD pid = schema.process_id();
            if (pid <= 4) return;

            std::wstring imagePath = AnsiToWide(ansiName);
            std::wstring dosPath = DevicePathToDosPath(imagePath);
            size_t lastSlash = imagePath.find_last_of(L"\\");
            std::wstring shortName = (lastSlash != std::wstring::npos) ? imagePath.substr(lastSlash + 1) : imagePath;

            if (!dosPath.empty()) {
                std::lock_guard<std::mutex> lock(mapMutex);
                processMap[pid] = { shortName, dosPath, ppid };
            }
            else {
                std::lock_guard<std::mutex> lock(mapMutex);
                processMap[pid] = { shortName, imagePath, ppid };
                dosPath = imagePath;
            }

            bool alreadyDetected = false;
            {
                std::lock_guard<std::mutex> listLock(g_scanSetMutex);
                if (g_detectedMalwarePids.find(pid) != g_detectedMalwarePids.end()) alreadyDetected = true;
            }
            if (!alreadyDetected && !dosPath.empty() && g_Scanner.ScanFile(dosPath)) {
                { std::lock_guard<std::mutex> listLock(g_scanSetMutex); g_detectedMalwarePids.insert(pid); }
                HandleConfirmedMalware(pid, shortName, dosPath, L"File Scan (OnProcessStart)");
            }
        }
        catch (...) {}
    }
}

void OnProcessStop(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);
    if (schema.event_opcode() == 2) {
        DWORD pid = schema.process_id();

        {
            std::lock_guard<std::mutex> lock(mapMutex);
            auto it = processMap.find(pid);
            if (it != processMap.end()) {
                // 將活著的 process 資訊移入歷史區，供遲到的 event 查詢名字
                g_processHistory[pid] = it->second;
                processMap.erase(it);
            }

            // [優化] 不要一次全清空，避免遲到的 Event 查不到名字
            // 如果歷史紀錄太多，只刪除開頭的 (假設 map 自動排序，雖然不完全準確代表時間，但堪用)
            // 或者你可以更懶一點，設定大一點的 buffer，例如 5000
            if (g_processHistory.size() > 5000) {
                g_processHistory.erase(g_processHistory.begin());
            }
        }

        // [關鍵] 這裡呼叫 RemovePid 是正確的。
        // 因為我們已經修改了 BehaviorTracker，這裡只是去設定 "deathTime"，
        // 並不會把分數資料刪掉。
        g_behaviorTracker.RemovePid(pid);
    }
}

void OnImageLoad(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);
    if (schema.event_opcode() == 10) {
        krabs::parser parser(schema);
        try {
            std::wstring fullPath = parser.parse<std::wstring>(L"FileName");
            DWORD pid = schema.process_id();
            size_t lastSlash = fullPath.find_last_of(L"\\");
            std::wstring shortName = (lastSlash != std::wstring::npos) ? fullPath.substr(lastSlash + 1) : fullPath;

            if (fullPath.length() > 4 && fullPath.substr(fullPath.length() - 4) == L".exe") {
                if (g_Scanner.ScanFile(fullPath)) {
                    { std::lock_guard<std::mutex> listLock(g_scanSetMutex); g_detectedMalwarePids.insert(pid); }
                    HandleConfirmedMalware(pid, shortName, fullPath, L"File Scan (OnImageLoad)");
                }
                {
                    std::lock_guard<std::mutex> lock(mapMutex);
                    processMap[pid] = { shortName, fullPath, 0 };
                }
            }
        }
        catch (...) {}
    }
}

void OnRegistryEvent(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);
    int opcode = schema.event_opcode();
    if (opcode == 10 || opcode == 11 || opcode == 16 || opcode == 22) {
        krabs::parser parser(schema);
        std::wstring keyName;
        try { keyName = parser.parse<std::wstring>(L"KeyName"); }
        catch (...) { try { keyName = parser.parse<std::wstring>(L"BaseName"); } catch (...) { return; } }
        if (keyName.empty()) return;

        if (g_registryDetector.Analyze(keyName)) {
            DWORD pid = schema.process_id();
            std::wstring exeName = ResolveProcessName(pid);
            std::wstring fullPath = ResolveProcessPath(pid);

            if (g_behaviorTracker.AddBehavior(pid, SuspiciousAction::RegistryAccess, keyName)) {
                HandleConfirmedMalware(pid, exeName, fullPath, L"Behavior Score (Registry Access)");
            }
            else {
                ProcessFreezer freezer(pid);
                std::wstring source;
                if (PerformUnifiedScan(pid, true, fullPath, source)) {
                    { std::lock_guard<std::mutex> l(g_scanSetMutex); g_detectedMalwarePids.insert(pid); }
                    HandleConfirmedMalware(pid, exeName, fullPath, L"Unified Scan Triggered by Registry: " + source);
                }
            }
        }
    }
}

void OnFileIoEvent(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);
    if (schema.event_opcode() == 0 || schema.event_opcode() == 64) {
        try {
            krabs::parser parser(schema);
            std::wstring fileName;
            try { fileName = parser.parse<std::wstring>(L"FileName"); }
            catch (...) { try { fileName = parser.parse<std::wstring>(L"OpenPath"); } catch (...) { return; } }
            if (fileName.empty()) return;

            if (g_fileDetector.Analyze(fileName)) {
                DWORD pid = schema.process_id();
                if (pid == 4 || pid == GetCurrentProcessId()) return;
                std::wstring exeName = ResolveProcessName(pid);
                std::wstring fullPath = ResolveProcessPath(pid);

				//printf("attacker pid:%d\n", pid);
                if (g_behaviorTracker.AddBehavior(pid, SuspiciousAction::FileAccess, fileName)) {
                    HandleConfirmedMalware(pid, exeName, fullPath, L"Behavior Score (File Access)");
                }
                else {
                    ProcessFreezer freezer(pid);
                    std::wstring source;
                    if (PerformUnifiedScan(pid, true, fullPath, source)) {
                        { std::lock_guard<std::mutex> l(g_scanSetMutex); g_detectedMalwarePids.insert(pid); }
                        HandleConfirmedMalware(pid, exeName, fullPath, L"Unified Scan Triggered by File: " + source);
                    }
                }
            }
        }
        catch (...) {}
    }
}

void OnApiCallEvent(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);

    // 取得 Event ID
    // 1, 5   = OpenProcess
    uint16_t eventId = schema.event_id();

    if (eventId == 1 || eventId == 5) {
        krabs::parser parser(schema);
        try {
            DWORD targetPid = parser.parse<DWORD>(L"TargetProcessId");
            DWORD attackerPid = schema.process_id();
            if (attackerPid == targetPid) return;

            if (g_currentVictimPid != 0 && targetPid == g_currentVictimPid) {
                std::wstring attackerName = L"Unknown";
                std::wstring fullPath = L"";

                // --- 解析攻擊者名稱 (保持不變) ---
                {
                    std::lock_guard<std::mutex> lock(mapMutex);
                    if (processMap.find(attackerPid) != processMap.end()) {
                        attackerName = processMap[attackerPid].name;
                        fullPath = processMap[attackerPid].fullPath;
                    }
                    else if (g_processHistory.find(attackerPid) != g_processHistory.end()) {
                        attackerName = g_processHistory[attackerPid].name;
                        fullPath = g_processHistory[attackerPid].fullPath;
                    }
                }
                if (attackerName == L"Unknown") attackerName = ResolveProcessName(attackerPid);
                size_t lastSlash = attackerName.find_last_of(L"\\");
                if (lastSlash != std::wstring::npos) attackerName = attackerName.substr(lastSlash + 1);
                // -------------------------------------

                if (g_accessDetector.IsAccessingVictim(targetPid, attackerName)) {
                    // [修改點] 根據 Event ID 決定 Log 內容
                    std::wstring operationType = L"Unknown Access";
                    SuspiciousAction actionType = SuspiciousAction::ProcessAccess; // 預設行為

                    if (eventId == 1 || eventId == 5) {
                        operationType = L"OpenProcess";
                        actionType = SuspiciousAction::ProcessAccess;
                    }

                    // 組合詳細訊息
                    std::wstring detail = operationType + L" on PID " + std::to_wstring(targetPid);

                    // 這裡使用通用的 SuspiciousAction::ProcessAccess (如果你沒有定義特定的 MemoryRead/Write)
                    // 如果你有定義特定的 enum，請將上面的 actionType 傳入
                    
                    //printf("attacker pid:%d\n", attackerPid);
                    if (g_behaviorTracker.AddBehavior(attackerPid, SuspiciousAction::ProcessAccess, detail)) {
                        HandleConfirmedMalware(attackerPid, attackerName, fullPath, L"Access process memory: score");
                    }
                    else {
                        ProcessFreezer freezer(attackerPid);
                        bool isCaughtAlive = true;
                        std::wstring source;
                        // 對這類行為進行掃描
                        if (PerformUnifiedScan(attackerPid, isCaughtAlive, fullPath, source)) {
                            { std::lock_guard<std::mutex> l(g_scanSetMutex); g_detectedMalwarePids.insert(attackerPid); }
                            HandleConfirmedMalware(attackerPid, attackerName, fullPath, L"Access process memory, static scanning");
                        }
                    }
                }
            }
        }
        catch (...) {}
    }
}



// ---------------------------------------------------------
// [Kernel Callbacks] Handle & Thread (Injection Detection)
// ---------------------------------------------------------

void OnKernelHandleEvent(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);
    // Opcode 32 = Handle Create
    if (schema.event_opcode() != 32) return;

    DWORD actorPid = schema.process_id();
    if (actorPid <= 4 || actorPid == GetCurrentProcessId()) return;

    krabs::parser parser(schema);
    try {
        DWORD accessMask = 0;
        try { accessMask = parser.parse<DWORD>(L"GrantedAccess"); }
        catch (...) { try { accessMask = parser.parse<DWORD>(L"AccessMask"); } catch (...) { return; } }

        // 0x20=VM_WRITE, 0x02=CREATE_THREAD, 0x1F0FFF=ALL_ACCESS
        bool isDangerous = (accessMask & 0x0020) || (accessMask & 0x0002) || (accessMask == 0x1F0FFF);

        if (isDangerous) {
            std::wstring actorPath = ResolveProcessPath(actorPid);
            // 白名單略過
            if (!actorPath.empty() && g_accessDetector.IsWhitelisted(actorPath)) return;

            // [修改] 改用 AddBehavior 進行關聯分析
            // 這裡記錄 ProcessAccess，如果之前已經有其他行為導致分數足夠，才會回傳 true
            if (g_behaviorTracker.AddBehavior(actorPid, SuspiciousAction::ProcessAccess, L"Dangerous Handle Access")) {
                std::wstring actorName = ResolveProcessName(actorPid);
                HandleConfirmedMalware(actorPid, actorName, actorPath, L"Behavior: Process Access + Suspicious Activity");
            }
            // 觸發掃描 (因為行為分數已達標)
            std::wstring actorName = ResolveProcessName(actorPid);
            if (g_Scanner.ScanProcessMemory(actorPid)) {
                { std::lock_guard<std::mutex> l(g_scanSetMutex); g_detectedMalwarePids.insert(actorPid); }
                HandleConfirmedMalware(actorPid, actorName, actorPath, L"Behavior: Process Access + Suspicious Activity");
            }
        }
    }
    catch (...) {}
}

void OnKernelThreadEvent(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);
    if (schema.event_opcode() != 1) return; // 只看 Start

    DWORD actorPid = schema.process_id();
    krabs::parser parser(schema);

    try {
        DWORD targetPid = parser.parse<DWORD>(L"ProcessId");

        // 1. 基礎過濾
        if (actorPid == targetPid) return;
        if (actorPid <= 4 || targetPid <= 4) return;
        if (actorPid == GetCurrentProcessId()) return;

        // 2. 準備路徑資訊
        std::wstring actorPath = ResolveProcessPath(actorPid);

        // 3. [Shell 豁免邏輯] 解決 cmd.exe 誤判
        if (IsShellProcess(actorPath)) {
            DWORD realParent = GetRealParentPid(targetPid);
            if (realParent == actorPid) return; // Cmd 啟動 Loader -> 正常
            if (realParent == 0) return;        // Process 正在出生 -> 正常
        }

        // 4. 惡意注入偵測
        std::wstring targetName = ResolveProcessName(targetPid);
        std::wstring actorName = ResolveProcessName(actorPid);

        if (!actorPath.empty() && g_accessDetector.IsWhitelisted(actorPath)) return;

        // [命中] 紀錄注入關係
        g_behaviorTracker.RegisterInjection(targetPid, actorPid, actorName);

        // [修改] 改用 AddBehavior 進行關聯分析
        // 這裡記錄 Injection。根據你的邏輯，只要有 Injection 且 (Reg/File/Proc 其中之一) 存在，就會回傳 true。
        // 正常情況下，OpenProcess (ProcessAccess) 會先發生，所以這裡通常會觸發 True。
        if (g_behaviorTracker.AddBehavior(actorPid, SuspiciousAction::Injection, L"Remote Thread Creation")) {

            // 行為分數達標，發動掃描
            bool malwareFound = false;
            if (g_Scanner.ScanProcessMemory(actorPid)) {
                malwareFound = true;
                { std::lock_guard<std::mutex> l(g_scanSetMutex); g_detectedMalwarePids.insert(actorPid); }
                HandleConfirmedMalware(actorPid, actorName, actorPath, L"Behavior: Injection + Suspicious Context");
            }

            // 如果掃描不到 (可能混淆過)，但行為已確認惡意，依然回報
            if (!malwareFound) {
                HandleConfirmedMalware(actorPid, actorName, actorPath, L"Behavior: Injection Threshold Met");
            }
        }

        // 5. 檢查 StartAddress 是否為 Shellcode (針對被注入後的狀況 - 驗屍)
        void* startAddress = parser.parse<void*>(L"StartAddress");
        if (startAddress != nullptr) {
            if (!g_behaviorTracker.IsAddressInImage(targetPid, startAddress)) {
                std::wstring injectorName = g_behaviorTracker.GetInjectorName(targetPid);
                std::wstring detectMsg = L"Non-Image Thread Execution";
                if (!injectorName.empty()) {
                    detectMsg += L" (Injected by " + injectorName + L")";
                }
                if (g_Scanner.ScanProcessMemory(targetPid)) {
                    HandleConfirmedMalware(targetPid, targetName, L"", detectMsg);
                }
            }
        }
    }
    catch (...) {}
}

// =========================================================
// Main Function
// =========================================================

int main() {
    //SetConsoleOutputCP(CP_UTF8);
    //wprintf(L"[INIT] Starting EDR Agent (iwqjirjiqw)...\n");

    // 清除舊 Session
    KillEtwSession(L"MyEDR_Kernel_Trace");
    KillEtwSession(L"MyEDR_Api_Trace");

    // 設定題目目標
    std::wstring victimName = L"bsass.exe";
    DWORD victimPid = ProcessFinder::FindPidByName(victimName);
    if (victimPid != 0) {
        g_currentVictimPid = victimPid;
        g_accessDetector.SetVictimPid(victimPid);
        std::wstring sys32 = GetSystem32Path();
        g_accessDetector.AddWhitelistPath(sys32 + L"\\csrss.exe");
        g_accessDetector.AddWhitelistPath(sys32 + L"\\lsass.exe");
        g_accessDetector.AddWhitelistPath(sys32 + L"\\svchost.exe");
    }

    // 設定 Kernel Trace
    krabs::kernel_trace kTrace(L"MyEDR_Kernel_Trace");

    // Enable Providers
    krabs::kernel_provider pProcess(EVENT_TRACE_FLAG_PROCESS, krabs::guids::process);
    pProcess.add_on_event_callback(OnProcessStart);
    pProcess.add_on_event_callback(OnProcessStop);
    kTrace.enable(pProcess);

    krabs::kernel_provider pImage(EVENT_TRACE_FLAG_IMAGE_LOAD, krabs::guids::image_load);
    pImage.add_on_event_callback(OnImageLoad);
    kTrace.enable(pImage);


    krabs::kernel_provider pThread(EVENT_TRACE_FLAG_THREAD, krabs::guids::thread);
    pThread.add_on_event_callback(OnKernelThreadEvent);
    kTrace.enable(pThread);

    // 0x40 = EVENT_TRACE_FLAG_HANDLES
    krabs::kernel_provider pHandle(0x40, ObTraceGuid);
    pHandle.add_on_event_callback(OnKernelHandleEvent);
    kTrace.enable(pHandle);

    krabs::kernel_provider pRegistry(EVENT_TRACE_FLAG_REGISTRY, krabs::guids::registry);
    pRegistry.add_on_event_callback(OnRegistryEvent);
    kTrace.enable(pRegistry);

    krabs::kernel_provider pFile(EVENT_TRACE_FLAG_FILE_IO_INIT, krabs::guids::file_io);
    pFile.add_on_event_callback(OnFileIoEvent);
    kTrace.enable(pFile);

    krabs::user_trace uTrace(L"MyEDR_Api_Trace");
    krabs::provider<> pApi(AuditApiCallsGuid);
    pApi.add_on_event_callback(OnApiCallEvent);
    uTrace.enable(pApi);



    // 啟動監控
    std::thread kThread([&]() {
        try {
            //wprintf(L"[INFO] Starting Kernel Trace...\n");
            kTrace.start();
        }
        catch (const std::exception& e) {
            wprintf(L"[ERROR] Kernel Trace Failed: %hs\n", e.what());
        }
        });

    std::thread uThread([&]() { try { uTrace.start(); } catch (...) {} });

    if (kThread.joinable()) kThread.join();
    if (uThread.joinable()) uThread.join();

    return 0;
}

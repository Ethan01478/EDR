#define WIN32_LEAN_AND_MEAN

// =========================================================
// [CONFIG] Secret
// =========================================================
#define USER_SECRET "0xBGaqjzZL7khGY5AcFs3oi0lIMmkvMF" 
#define SUBMISSION_HOST L"submit.bombe.top"
#define SUBMISSION_PATH L"/submitEdrAns"
#define MALWARE_PREFIX L"BOMBE_EDR_FLAG_"

#include <initguid.h> 
#include <windows.h>
#include <psapi.h>
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

// Krabs ETW Library
#include "krabs/krabs.hpp"

// Core Modules
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

// ---------------------------------------------------------
// Global & Submission State
// ---------------------------------------------------------
bool g_hasSubmitted = false;
std::mutex g_submissionMutex;

// Convert Wide String to String for JSON
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

    // Filter: Only submit if filename matches the competition format
    if (filename.find(MALWARE_PREFIX) == std::wstring::npos) return;

    // HTTP Request Setup
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

// ---------------------------------------------------------
// Native API (Freezer Removed/Disabled)
// ---------------------------------------------------------
// 為了遵守規則，我們不再使用 Suspend/Resume
// typedef LONG(NTAPI* pNtSuspendProcess)(HANDLE ProcessHandle);
// typedef LONG(NTAPI* pNtResumeProcess)(HANDLE ProcessHandle);

void InitNativeFunctions() {
    // Empty - No longer needed for killing/suspending
}

// ProcessFreezer class is now a dummy implementation to keep logic intact without side effects
class ProcessFreezer {
public:
    ProcessFreezer(DWORD pid) : m_frozen(false) {
        // [DISABLED] Do not suspend process to comply with rules
    }
    ~ProcessFreezer() {
        // [DISABLED]
    }
    bool IsFrozen() const { return false; } // Always false
private:
    bool m_frozen;
};

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

// ---------------------------------------------------------
// Global Data Structures
// ---------------------------------------------------------
struct ProcessInfo {
    std::wstring name;
    std::wstring fullPath;
    DWORD parentPid;
};

struct PendingSuspicion {
    std::wstring type;
    std::wstring details;
};

std::map<DWORD, ProcessInfo> processMap;
std::map<DWORD, ProcessInfo> g_processHistory;
std::mutex mapMutex;

std::map<DWORD, std::vector<PendingSuspicion>> g_pendingSuspicionMap;
std::mutex g_pendingMutex;

std::set<DWORD> g_registryScannedPids;
std::set<DWORD> g_apiScannedPids;
std::set<DWORD> g_fileScannedPids;
std::set<DWORD> g_detectedMalwarePids;
std::mutex g_scanSetMutex;
std::mutex g_consoleMutex;

std::unordered_map<DWORD, std::wstring> g_processCache;
std::mutex g_cacheMutex;

DWORD g_currentVictimPid = 0;

RegistryDetector g_registryDetector;
ProcessFinder g_processFinder;
ProcessAccessDetector g_accessDetector;
MalwareScanner g_Scanner;
FileDetector g_fileDetector;
BehaviorTracker g_behaviorTracker;

static const GUID AuditApiCallsGuid = { 0xe02a841c, 0x75a3, 0x4fa7, { 0xaf, 0xc8, 0xae, 0x09, 0xcf, 0x9b, 0x7f, 0x23 } };

// ---------------------------------------------------------
// Helpers
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
                    std::wstring deviceName = targetPath;
                    deviceMap[deviceName] = driveName;
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
            name = g_processHistory[pid].name + L" (Dead)";
            found = true;
        }
    }
    if (!found) name = GetProcessNameByPid(pid);
    size_t lastSlash = name.find_last_of(L"\\");
    if (lastSlash != std::wstring::npos) name = name.substr(lastSlash + 1);
    return name;
}

// ---------------------------------------------------------
// Unified Scan Logic
// ---------------------------------------------------------
bool PerformUnifiedScan(DWORD pid, bool isCaughtAlive, const std::wstring& fullPath, std::wstring& outSource) {
    if (isCaughtAlive) {
        HANDLE hCheck = OpenProcess(PROCESS_VM_READ, FALSE, pid);
        if (hCheck) {
            CloseHandle(hCheck);
            if (g_Scanner.ScanProcessMemory(pid)) return true;
        }
    }
    {
        std::lock_guard<std::mutex> l(g_scanSetMutex);
        if (g_detectedMalwarePids.find(pid) != g_detectedMalwarePids.end()) return true;
    }
    if (!fullPath.empty()) {
        if (g_Scanner.ScanFile(fullPath)) return true;
    }
    return false;
}

void HandleConfirmedMalware(DWORD pid, const std::wstring& processName, const std::wstring& fullPath) {
	//wprintf(L"[ALERT] Malware Detected: PID=%d Name=%s Path=%s\n", pid, processName.c_str(), fullPath.c_str());
    // 1. Submit to API (Only Report)
    SubmitMalware(processName);

    // [DISABLED] Do not terminate process
    /*
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess) {
        TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
    }
    */
}

// ---------------------------------------------------------
// ETW Callbacks
// ---------------------------------------------------------

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
                    HandleConfirmedMalware(pid, shortName, fullPath);
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

            bool isMalware = false;
            if (!dosPath.empty()) {
                bool alreadyDetected = false;
                {
                    std::lock_guard<std::mutex> listLock(g_scanSetMutex);
                    if (g_detectedMalwarePids.find(pid) != g_detectedMalwarePids.end()) alreadyDetected = true;
                }
                if (!alreadyDetected) {
                    if (g_Scanner.ScanFile(dosPath)) {
                        isMalware = true;
                        { std::lock_guard<std::mutex> listLock(g_scanSetMutex); g_detectedMalwarePids.insert(pid); }
                        HandleConfirmedMalware(pid, shortName, dosPath);
                    }
                }
            }

            if (!isMalware) {
                std::lock_guard<std::mutex> pendingLock(g_pendingMutex);
                auto it = g_pendingSuspicionMap.find(pid);
                if (it != g_pendingSuspicionMap.end()) {
                    g_pendingSuspicionMap.erase(it);
                }
            }
        }
        catch (const std::exception&) {}
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
                g_processHistory[pid] = it->second;
                processMap.erase(it);
            }
        }
        {
            std::lock_guard<std::mutex> lock(g_cacheMutex);
            g_processCache.erase(pid);
        }
        if (g_processHistory.size() > 2000) g_processHistory.clear();
        g_behaviorTracker.RemovePid(pid);
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
            std::wstring exeName = L"Unknown";
            std::wstring fullPath = L"";

            {
                std::lock_guard<std::mutex> lock(mapMutex);
                if (processMap.find(pid) != processMap.end()) {
                    exeName = processMap[pid].name;
                    fullPath = processMap[pid].fullPath;
                }
                else if (g_processHistory.find(pid) != g_processHistory.end()) {
                    exeName = g_processHistory[pid].name + L" (Dead)";
                    fullPath = g_processHistory[pid].fullPath;
                }
            }
            if (exeName == L"Unknown") exeName = ResolveProcessName(pid);
            size_t lastSlash = exeName.find_last_of(L"\\");
            if (lastSlash != std::wstring::npos) exeName = exeName.substr(lastSlash + 1);

            if (g_behaviorTracker.AddBehavior(pid, SuspiciousAction::RegistryAccess, keyName)) {
                HandleConfirmedMalware(pid, exeName, fullPath);
            }
            else {
                // Freezer is now harmless (won't freeze)
                ProcessFreezer freezer(pid);
                bool isCaughtAlive = true; // Assume true for memory scan attempt
                std::wstring source;
                if (PerformUnifiedScan(pid, isCaughtAlive, fullPath, source)) {
                    { std::lock_guard<std::mutex> l(g_scanSetMutex); g_detectedMalwarePids.insert(pid); }
                    HandleConfirmedMalware(pid, exeName, fullPath);
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

                std::wstring exeName = L"Unknown";
                std::wstring fullPath = L"";

                {
                    std::lock_guard<std::mutex> lock(mapMutex);
                    if (processMap.find(pid) != processMap.end()) {
                        exeName = processMap[pid].name;
                        fullPath = processMap[pid].fullPath;
                    }
                    else if (g_processHistory.find(pid) != g_processHistory.end()) {
                        exeName = g_processHistory[pid].name + L" (Dead)";
                        fullPath = g_processHistory[pid].fullPath;
                    }
                }
                if (exeName == L"Unknown") exeName = ResolveProcessName(pid);
                size_t lastSlash = exeName.find_last_of(L"\\");
                if (lastSlash != std::wstring::npos) exeName = exeName.substr(lastSlash + 1);

                if (g_behaviorTracker.AddBehavior(pid, SuspiciousAction::FileAccess, fileName)) {
                    HandleConfirmedMalware(pid, exeName, fullPath);
                }
                else {
                    ProcessFreezer freezer(pid);
                    bool isCaughtAlive = true;
                    std::wstring source;
                    if (PerformUnifiedScan(pid, isCaughtAlive, fullPath, source)) {
                        { std::lock_guard<std::mutex> l(g_scanSetMutex); g_detectedMalwarePids.insert(pid); }
                        HandleConfirmedMalware(pid, exeName, fullPath);
                    }
                }
            }
        }
        catch (...) {}
    }
}

void OnApiCallEvent(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);
    if (schema.event_id() == 1 || schema.event_id() == 5) {
        krabs::parser parser(schema);
        try {
            DWORD targetPid = parser.parse<DWORD>(L"TargetProcessId");
            DWORD attackerPid = schema.process_id();
            if (attackerPid == targetPid) return;

            if (g_currentVictimPid != 0 && targetPid == g_currentVictimPid) {
                std::wstring attackerName = L"Unknown";
                std::wstring fullPath = L"";
                {
                    std::lock_guard<std::mutex> lock(mapMutex);
                    if (processMap.find(attackerPid) != processMap.end()) {
                        attackerName = processMap[attackerPid].name;
                        fullPath = processMap[attackerPid].fullPath;
                    }
                    else if (g_processHistory.find(attackerPid) != g_processHistory.end()) {
                        attackerName = g_processHistory[attackerPid].name + L" (Dead)";
                        fullPath = g_processHistory[attackerPid].fullPath;
                    }
                }
                if (attackerName == L"Unknown") attackerName = ResolveProcessName(attackerPid);
                size_t lastSlash = attackerName.find_last_of(L"\\");
                if (lastSlash != std::wstring::npos) attackerName = attackerName.substr(lastSlash + 1);

                if (g_accessDetector.IsAccessingVictim(targetPid, attackerName)) {
                    std::wstring detail = L"OpenProcess on PID " + std::to_wstring(targetPid);
                    if (g_behaviorTracker.AddBehavior(attackerPid, SuspiciousAction::ProcessAccess, detail)) {
                        HandleConfirmedMalware(attackerPid, attackerName, fullPath);
                    }
                    else {
                        ProcessFreezer freezer(attackerPid);
                        bool isCaughtAlive = true;
                        std::wstring source;
                        if (PerformUnifiedScan(attackerPid, isCaughtAlive, fullPath, source)) {
                            { std::lock_guard<std::mutex> l(g_scanSetMutex); g_detectedMalwarePids.insert(attackerPid); }
                            HandleConfirmedMalware(attackerPid, attackerName, fullPath);
                        }
                    }
                }
            }
        }
        catch (...) {}
    }
}

int main() {
    InitNativeFunctions();
    KillEtwSession(L"MyEDR_Kernel_Trace");
    KillEtwSession(L"MyEDR_Api_Trace");

    std::wstring victimName = L"bsass.exe";
    DWORD victimPid = ProcessFinder::FindPidByName(victimName);
    if (victimPid != 0) {
        g_currentVictimPid = victimPid;
        g_accessDetector.SetVictimPid(victimPid);
    }

    krabs::kernel_trace kTrace(L"MyEDR_Kernel_Trace");
    krabs::kernel_provider pProcess(EVENT_TRACE_FLAG_PROCESS, krabs::guids::process);
    pProcess.add_on_event_callback(OnProcessStart);
    pProcess.add_on_event_callback(OnProcessStop);
    kTrace.enable(pProcess);

    krabs::kernel_provider pImage(EVENT_TRACE_FLAG_IMAGE_LOAD, krabs::guids::image_load);
    pImage.add_on_event_callback(OnImageLoad);
    kTrace.enable(pImage);

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

    std::thread kThread([&]() { try { kTrace.start(); } catch (...) {} });
    std::thread uThread([&]() { try { uTrace.start(); } catch (...) {} });

    if (kThread.joinable()) kThread.join();
    if (uThread.joinable()) uThread.join();

    return 0;
}
#include "pch.h"
// injector.cpp — Инжектор DLL с логированием, отчётом в JSON (UTF-8), с указанием процессов и времени
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <sstream>
#include <ctime>
#include <codecvt>

#pragma comment(lib, "psapi.lib")

// Уровни логирования
enum LogLevel { LOG_INFO, LOG_ERROR };

struct InjectResult {
    DWORD pid;
    std::wstring processName;
};

void LogEvent(LogLevel level, const wchar_t* message) {
    WORD type = (level == LOG_ERROR) ? EVENTLOG_ERROR_TYPE : EVENTLOG_INFORMATION_TYPE;
    HANDLE hEventLog = RegisterEventSourceW(NULL, L"DragBlockInjector");
    if (hEventLog) {
        LPCWSTR strings[1] = { message };
        ReportEventW(hEventLog, type, 0, 0, NULL, 1, 0, strings, NULL);
        DeregisterEventSource(hEventLog);
    }
}

bool IsGuiProcess(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return false;
    HMODULE hMods[1024]; DWORD cbNeeded;
    bool found = false;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i) {
            wchar_t szModName[MAX_PATH];
            if (GetModuleBaseNameW(hProcess, hMods[i], szModName, MAX_PATH)) {
                if (_wcsicmp(szModName, L"user32.dll") == 0) {
                    found = true; break;
                }
            }
        }
    }
    CloseHandle(hProcess);
    return found;
}

std::wstring GetProcessName(DWORD pid) {
    std::wstring result = L"<unknown>";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess) {
        wchar_t buffer[MAX_PATH] = { 0 };
        if (GetModuleBaseNameW(hProcess, NULL, buffer, MAX_PATH)) {
            result = buffer;
        }
        CloseHandle(hProcess);
    }
    return result;
}

bool InjectDLL(DWORD pid, const std::wstring& dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    LPVOID allocMem = VirtualAllocEx(hProcess, NULL, (dllPath.length() + 1) * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!allocMem) { CloseHandle(hProcess); return false; }

    if (!WriteProcessMemory(hProcess, allocMem, dllPath.c_str(), (dllPath.length() + 1) * sizeof(wchar_t), NULL)) {
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE); CloseHandle(hProcess); return false;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"Kernel32");
    FARPROC loadLib = GetProcAddress(hKernel32, "LoadLibraryW");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLib, allocMem, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE); CloseHandle(hProcess); return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
    CloseHandle(hThread); CloseHandle(hProcess);
    return true;
}

std::vector<DWORD> FindMatchingProcesses(const std::wstring& nameFragment, bool guiOnly, bool injectAllMode) {
    std::vector<DWORD> pids;
    PROCESSENTRY32W entry; entry.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            std::wstring exe(entry.szExeFile);
            if (injectAllMode || exe.find(nameFragment) != std::wstring::npos) {
                if (!guiOnly || IsGuiProcess(entry.th32ProcessID)) {
                    pids.push_back(entry.th32ProcessID);
                }
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return pids;
}

std::string GetCurrentTimestamp() {
    std::time_t now = std::time(nullptr);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    return buf;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        std::wcout << L"Usage:\n"
            L"  injector.exe <name_fragment> <path_to_dll>                - inject into first matching process\n"
            L"  injector.exe /all <name_fragment> <path_to_dll> [/gui]   - inject into all matching processes\n"
            L"  injector.exe /all <path_to_dll> [/gui]                   - inject into all processes (optionally GUI-only)\n"
            L"\nOptions:\n"
            L"  /all   — inject into multiple processes\n"
            L"  /gui   — limit to GUI applications only (those with user32.dll loaded)\n";
        return 1;
    }

    std::wstring nameFragment, dllPath;
    bool injectAll = false, guiOnly = false, injectEverything = false;
    int index = 1;
    if (std::wstring(argv[index]) == L"/all") { injectAll = true; index++; }

    if (argc <= index) {
        std::wcerr << L"Invalid arguments.\n";
        return 1;
    }

    if (injectAll && (argc - index == 1 || (argc - index == 2 && std::wstring(argv[argc - 1]) == L"/gui"))) {
        dllPath = argv[index];
        if (argc > index + 1 && std::wstring(argv[index + 1]) == L"/gui") guiOnly = true;
        injectEverything = true;
    }
    else {
        nameFragment = argv[index];
        dllPath = argv[index + 1];
        if (argc > index + 2 && std::wstring(argv[index + 2]) == L"/gui") guiOnly = true;
    }

    std::vector<DWORD> pids = FindMatchingProcesses(nameFragment, guiOnly, injectEverything);
    if (pids.empty()) {
        std::wcerr << L"No matching processes found." << std::endl;
        LogEvent(LOG_ERROR, L"Target process(es) not found");
        return 1;
    }

    std::vector<InjectResult> successList, failList;
    for (DWORD pid : pids) {
        std::wstring pname = GetProcessName(pid);
        std::wcout << L"Injecting into [" << pid << L"] " << pname << L"... ";
        if (InjectDLL(pid, dllPath)) {
            std::wcout << L"[OK]\n";
            successList.push_back({ pid, pname });
        }
        else {
            std::wcout << L"[FAIL]\n";
            failList.push_back({ pid, pname });
        }
        if (!injectAll) break;
    }

    std::ofstream outJson("injector.json", std::ios::out | std::ios::binary);
    outJson << "{\n";
    outJson << "  \"timestamp\": \"" << GetCurrentTimestamp() << "\",\n";
    outJson << "  \"dll\": \"" << std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(dllPath) << "\",\n";
    outJson << "  \"guiOnly\": " << (guiOnly ? "true" : "false") << ",\n";
    outJson << "  \"success\": [\n";
    for (size_t i = 0; i < successList.size(); ++i) {
        outJson << "    { \"pid\": " << successList[i].pid << ", \"name\": \"" << std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(successList[i].processName) << "\" }";
        if (i + 1 < successList.size()) outJson << ",";
        outJson << "\n";
    }
    outJson << "  ],\n  \"failed\": [\n";
    for (size_t i = 0; i < failList.size(); ++i) {
        outJson << "    { \"pid\": " << failList[i].pid << ", \"name\": \"" << std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(failList[i].processName) << "\" }";
        if (i + 1 < failList.size()) outJson << ",";
        outJson << "\n";
    }
    outJson << "  ]\n}";
    outJson.close();

    return !successList.empty() ? 0 : 1;
}

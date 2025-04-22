#include "pch.h"
// injector.cpp — Инжектор DLL с логированием в системный журнал (совместим с DragBlock)
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <iostream>

#pragma comment(lib, "psapi.lib")

// Уровни логирования
enum LogLevel { LOG_INFO, LOG_ERROR };

// Запись события в журнал Windows
void LogEvent(LogLevel level, const wchar_t* message)
{
    WORD type = (level == LOG_ERROR) ? EVENTLOG_ERROR_TYPE : EVENTLOG_INFORMATION_TYPE;
    HANDLE hEventLog = RegisterEventSourceW(NULL, L"DragBlockInjector");
    if (hEventLog) {
        LPCWSTR strings[1] = { message };
        ReportEventW(hEventLog, type, 0, 0, NULL, 1, 0, strings, NULL);
        DeregisterEventSource(hEventLog);
    }
}

// Проверка, загружен ли user32.dll (GUI-приложение)
bool IsGuiProcess(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return false;

    HMODULE hMods[1024];
    DWORD cbNeeded;
    bool found = false;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i) {
            wchar_t szModName[MAX_PATH];
            if (GetModuleBaseNameW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                if (_wcsicmp(szModName, L"user32.dll") == 0) {
                    found = true;
                    break;
                }
            }
        }
    }
    CloseHandle(hProcess);
    return found;
}

// Инжекция DLL через CreateRemoteThread
bool InjectDLL(DWORD pid, const std::wstring& dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        LogEvent(LOG_ERROR, L"Failed to open target process");
        return false;
    }

    LPVOID allocMem = VirtualAllocEx(hProcess, NULL, (dllPath.length() + 1) * sizeof(wchar_t),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!allocMem) {
        LogEvent(LOG_ERROR, L"Failed to allocate memory in target process");
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, allocMem, dllPath.c_str(),
        (dllPath.length() + 1) * sizeof(wchar_t), NULL)) {
        LogEvent(LOG_ERROR, L"Failed to write DLL path to process memory");
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"Kernel32");
    FARPROC loadLib = GetProcAddress(hKernel32, "LoadLibraryW");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)loadLib, allocMem, 0, NULL);
    if (!hThread) {
        LogEvent(LOG_ERROR, L"Failed to create remote thread");
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    LogEvent(LOG_INFO, L"DLL injection succeeded");

    VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

// Поиск PID всех процессов по частичному совпадению имени и фильтрам
std::vector<DWORD> FindMatchingProcesses(const std::wstring& nameFragment, bool guiOnly) {
    std::vector<DWORD> pids;
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            std::wstring exe(entry.szExeFile);
            if (exe.find(nameFragment) != std::wstring::npos) {
                if (!guiOnly || IsGuiProcess(entry.th32ProcessID)) {
                    pids.push_back(entry.th32ProcessID);
                }
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return pids;
}

// Точка входа
int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        std::wcout << L"Usage:\n"
            L"  injector.exe <name_fragment> <path_to_dll>               (first match)\n"
            L"  injector.exe /all <name_fragment> <path_to_dll> [/gui]  (all matches, optionally GUI-only)\n";
        return 1;
    }

    std::wstring nameFragment;
    std::wstring dllPath;
    bool injectAll = false;
    bool guiOnly = false;

    int index = 1;
    if (std::wstring(argv[index]) == L"/all") {
        injectAll = true;
        index++;
    }

    if (argc <= index + 1) {
        std::wcerr << L"Invalid arguments.\n";
        return 1;
    }

    nameFragment = argv[index];
    dllPath = argv[index + 1];

    if (argc > index + 2 && std::wstring(argv[index + 2]) == L"/gui") {
        guiOnly = true;
    }

    std::vector<DWORD> pids = FindMatchingProcesses(nameFragment, guiOnly);
    if (pids.empty()) {
        std::wcerr << L"No matching processes found: " << nameFragment << std::endl;
        LogEvent(LOG_ERROR, L"Target process(es) not found");
        return 1;
    }

    bool anySuccess = false;
    for (DWORD pid : pids) {
        std::wcout << L"Injecting into PID: " << pid << L"... ";
        if (InjectDLL(pid, dllPath)) {
            std::wcout << L"[OK]\n";
            anySuccess = true;
        }
        else {
            std::wcout << L"[FAIL]\n";
        }
        if (!injectAll) break; // если не /all — инжект только в первый найденный
    }

    return anySuccess ? 0 : 1;
}

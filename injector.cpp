#include "pch.h"

// injector.cpp — Инжектор DLL с логированием в системный журнал (совместим с DragBlock)
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <string>
#include <iostream>

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

// Поиск PID процесса по имени
DWORD FindProcessId(const std::wstring& processName) {
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (!_wcsicmp(entry.szExeFile, processName.c_str())) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return 0;
}

// Точка входа
int wmain(int argc, wchar_t* argv[]) {
    if (argc != 3) {
        std::wcout << L"Usage: injector.exe <process.exe> <path_to_dll>\n";
        return 1;
    }

    std::wstring procName = argv[1];
    std::wstring dllPath = argv[2];

    DWORD pid = FindProcessId(procName);
    if (!pid) {
        std::wcerr << L"Process not found: " << procName << std::endl;
        LogEvent(LOG_ERROR, L"Target process not found");
        return 1;
    }

    if (InjectDLL(pid, dllPath)) {
        std::wcout << L"Injection succeeded.\n";
    }
    else {
        std::wcerr << L"Injection failed.\n";
    }

    return 0;
}

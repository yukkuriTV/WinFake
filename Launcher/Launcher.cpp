#include <windows.h>
#include <commdlg.h>
#include <cwchar>

bool EnableDebugPrivilege()
{
    HANDLE token{};
    if (!OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &token))
        return false;

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;

    if (!LookupPrivilegeValueW(
        nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
    {
        CloseHandle(token);
        return false;
    }

    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(token);

    return GetLastError() == ERROR_SUCCESS;
}

bool IsTargetWow64(HANDLE process)
{
    USHORT processMachine{};
    USHORT nativeMachine{};

    if (!IsWow64Process2(process, &processMachine, &nativeMachine))
        return false;

    return processMachine != IMAGE_FILE_MACHINE_UNKNOWN;
}

bool InjectDLL64(HANDLE process, const wchar_t* dllPath)
{
    SIZE_T size = (wcslen(dllPath) + 1) * sizeof(wchar_t);

    LPVOID remote = VirtualAllocEx(
        process, nullptr, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remote)
        return false;

    if (!WriteProcessMemory(process, remote, dllPath, size, nullptr))
        return false;

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC loadLib = GetProcAddress(kernel32, "LoadLibraryW");

    if (!loadLib)
        return false;

    HANDLE th = CreateRemoteThread(
        process, nullptr, 0,
        (LPTHREAD_START_ROUTINE)loadLib,
        remote, 0, nullptr);

    if (!th)
        return false;

    WaitForSingleObject(th, INFINITE);

    DWORD exitCode{};
    GetExitCodeThread(th, &exitCode);

    CloseHandle(th);
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);

    return exitCode != 0;
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
    EnableDebugPrivilege();

    // ==========================
    // 対象 exe 選択
    // ==========================
    wchar_t exePath[MAX_PATH]{};

    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFilter = L"EXE (*.exe)\0*.exe\0";
    ofn.lpstrFile = exePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST;

    if (!GetOpenFileNameW(&ofn))
        return 0;

    // ==========================
    // プロセス起動（停止）
    // ==========================
    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    if (!CreateProcessW(
        exePath,
        nullptr,
        nullptr,
        nullptr,
        FALSE,
        CREATE_SUSPENDED,
        nullptr,
        nullptr,
        &si,
        &pi))
    {
        MessageBoxW(nullptr, L"プロセス起動失敗", L"Launcher", MB_ICONERROR);
        return 1;
    }

    // ==========================
    // x86 判定
    // ==========================
    if (IsTargetWow64(pi.hProcess))
    {
        // x86 → Injectorx86.exe に丸投げ
        TerminateProcess(pi.hProcess, 0);

        wchar_t injectorPath[MAX_PATH]{};
        GetModuleFileNameW(nullptr, injectorPath, MAX_PATH);

        wchar_t* p = wcsrchr(injectorPath, L'\\');
        if (p)
            *(p + 1) = L'\0';

        wcscat_s(injectorPath, L"Injectorx86.exe");

        STARTUPINFOW si2{};
        PROCESS_INFORMATION pi2{};
        si2.cb = sizeof(si2);

        CreateProcessW(
            injectorPath,
            nullptr,
            nullptr,
            nullptr,
            FALSE,
            0,
            nullptr,
            nullptr,
            &si2,
            &pi2);

        CloseHandle(pi2.hThread);
        CloseHandle(pi2.hProcess);
        return 0;
    }

    // ==========================
    // x64 DLL 注入
    // ==========================
    wchar_t dllPath[MAX_PATH]{};
    GetModuleFileNameW(nullptr, dllPath, MAX_PATH);

    wchar_t* p = wcsrchr(dllPath, L'\\');
    if (p)
        *(p + 1) = L'\0';

    wcscat_s(dllPath, L"Spoof.dll");

    if (!InjectDLL64(pi.hProcess, dllPath))
    {
        MessageBoxW(nullptr, L"Spoof.dll 注入失敗", L"Launcher", MB_ICONERROR);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 2;
    }

    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}


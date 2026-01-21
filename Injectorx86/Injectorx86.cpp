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

bool InjectDLL(HANDLE process, const wchar_t* dllPath)
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
    // プロセス起動（停止状態）
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
        MessageBoxW(nullptr, L"32bitプロセス起動失敗", L"Injectorx86", MB_ICONERROR);
        return 1;
    }

    // ==========================
    // DLL パス構築
    // ==========================
    wchar_t dllPath[MAX_PATH]{};
    GetModuleFileNameW(nullptr, dllPath, MAX_PATH);

    wchar_t* p = wcsrchr(dllPath, L'\\');
    if (p)
        *(p + 1) = L'\0';

    wcscat_s(dllPath, L"WinFakex86.dll");

    // ==========================
    // DLL 注入
    // ==========================
    if (!InjectDLL(pi.hProcess, dllPath))
    {
        MessageBoxW(nullptr, L"WinFakex86.dll 注入失敗", L"Injectorx86", MB_ICONERROR);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 2;
    }

    // ==========================
    // 実行再開
    // ==========================
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}

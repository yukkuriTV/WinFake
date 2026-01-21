#include "pch.h"
#include <windows.h>
#include "MinHook.h"

// ========================
// 偽装バージョン
// ========================
#define SPOOF_MAJOR 10
#define SPOOF_MINOR 0
#define SPOOF_BUILD 26200

// ========================
// 常駐制御
// ========================
static HANDLE gExitEvent = nullptr;

// ========================
// RtlGetVersion
// ========================
typedef LONG(WINAPI* RtlGetVersion_t)(PRTL_OSVERSIONINFOW);
static RtlGetVersion_t RealRtlGetVersion = nullptr;

LONG WINAPI HookedRtlGetVersion(PRTL_OSVERSIONINFOW info)
{
    LONG ret = RealRtlGetVersion(info);
    if (!info) return ret;

    info->dwMajorVersion = SPOOF_MAJOR;
    info->dwMinorVersion = SPOOF_MINOR;
    info->dwBuildNumber = SPOOF_BUILD;
    return ret;
}

// ========================
// RtlGetNtVersionNumbers
// ========================
typedef VOID(WINAPI* RtlGetNtVersionNumbers_t)(
    LPDWORD, LPDWORD, LPDWORD);

static RtlGetNtVersionNumbers_t RealRtlGetNtVersionNumbers = nullptr;

VOID WINAPI HookedRtlGetNtVersionNumbers(
    LPDWORD major, LPDWORD minor, LPDWORD build)
{
    DWORD origBuild = build ? *build : 0;

    if (major) *major = SPOOF_MAJOR;
    if (minor) *minor = SPOOF_MINOR;
    if (build)
        *build = (origBuild & 0xF0000000) | (SPOOF_BUILD & 0x0FFFFFFF);
}

// ========================
// GetVersionEx
// ========================
typedef BOOL(WINAPI* GetVersionExW_t)(LPOSVERSIONINFOW);
typedef BOOL(WINAPI* GetVersionExA_t)(LPOSVERSIONINFOA);

static GetVersionExW_t RealGetVersionExW = nullptr;
static GetVersionExA_t RealGetVersionExA = nullptr;

BOOL WINAPI HookedGetVersionExW(LPOSVERSIONINFOW info)
{
    BOOL ret = RealGetVersionExW(info);
    if (!info) return ret;

    info->dwMajorVersion = SPOOF_MAJOR;
    info->dwMinorVersion = SPOOF_MINOR;
    info->dwBuildNumber = SPOOF_BUILD;
    return ret;
}

BOOL WINAPI HookedGetVersionExA(LPOSVERSIONINFOA info)
{
    BOOL ret = RealGetVersionExA(info);
    if (!info) return ret;

    info->dwMajorVersion = SPOOF_MAJOR;
    info->dwMinorVersion = SPOOF_MINOR;
    info->dwBuildNumber = SPOOF_BUILD;
    return ret;
}

// ========================
// VerifyVersionInfo
// ========================
typedef BOOL(WINAPI* VerifyVersionInfoW_t)(
    LPOSVERSIONINFOW, DWORD, DWORDLONG);
typedef BOOL(WINAPI* VerifyVersionInfoA_t)(
    LPOSVERSIONINFOA, DWORD, DWORDLONG);

static VerifyVersionInfoW_t RealVerifyVersionInfoW = nullptr;
static VerifyVersionInfoA_t RealVerifyVersionInfoA = nullptr;

BOOL WINAPI HookedVerifyVersionInfoW(
    LPOSVERSIONINFOW, DWORD, DWORDLONG)
{
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL WINAPI HookedVerifyVersionInfoA(
    LPOSVERSIONINFOA, DWORD, DWORDLONG)
{
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

// ========================
// フック初期化スレッド
// ========================
DWORD WINAPI InitHookThread(LPVOID)
{
    MH_Initialize();

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");

    MH_CreateHook(
        GetProcAddress(ntdll, "RtlGetVersion"),
        HookedRtlGetVersion,
        (void**)&RealRtlGetVersion);

    MH_CreateHook(
        GetProcAddress(ntdll, "RtlGetNtVersionNumbers"),
        HookedRtlGetNtVersionNumbers,
        (void**)&RealRtlGetNtVersionNumbers);

    MH_CreateHook(
        GetProcAddress(kernel32, "GetVersionExW"),
        HookedGetVersionExW,
        (void**)&RealGetVersionExW);

    MH_CreateHook(
        GetProcAddress(kernel32, "GetVersionExA"),
        HookedGetVersionExA,
        (void**)&RealGetVersionExA);

    MH_CreateHook(
        GetProcAddress(kernel32, "VerifyVersionInfoW"),
        HookedVerifyVersionInfoW,
        (void**)&RealVerifyVersionInfoW);

    MH_CreateHook(
        GetProcAddress(kernel32, "VerifyVersionInfoA"),
        HookedVerifyVersionInfoA,
        (void**)&RealVerifyVersionInfoA);

    MH_EnableHook(MH_ALL_HOOKS);
    return 0;
}

// ========================
// 常駐スレッド
// ========================
DWORD WINAPI KeepAliveThread(LPVOID)
{
    MessageBoxW(
        nullptr,
        L"Spoof.dll が動作中です。\n\n"
        L"Ctrl + Alt + End で終了します。",
        L"Spoof.dll",
        MB_OK | MB_ICONINFORMATION
    );

    RegisterHotKey(nullptr, 1, MOD_CONTROL | MOD_ALT, VK_END);

    MSG msg{};
    while (WaitForSingleObject(gExitEvent, 50) != WAIT_OBJECT_0)
    {
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE))
        {
            if (msg.message == WM_HOTKEY && msg.wParam == 1)
            {
                SetEvent(gExitEvent);
                break;
            }
        }
    }

    UnregisterHotKey(nullptr, 1);
    return 0;
}

// ========================
// DllMain
// ========================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);

        gExitEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

        CreateThread(nullptr, 0, InitHookThread, nullptr, 0, nullptr);
        CreateThread(nullptr, 0, KeepAliveThread, nullptr, 0, nullptr);
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        if (gExitEvent)
        {
            SetEvent(gExitEvent);
            CloseHandle(gExitEvent);
            gExitEvent = nullptr;
        }
    }
    return TRUE;
}







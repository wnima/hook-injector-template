#include "pch.h"
#include <stdio.h>

// FunHookProc: SetWindowsHookEx entry point.
// On first call, loads HookCore.dll to initialize hooks in the target process.
// This lazy approach prevents HookCore loading during the injector's local
// LoadLibraryW (used to find FunHookProc's address), avoiding the double-load
// problem where DllMain would run in the wrong process context.

static HMODULE g_hHookCore = nullptr;

LRESULT CALLBACK FunHookProc(int code, WPARAM wParam, LPARAM lParam)
{
    // Lazy init: load HookCore.dll on first invocation
    if (!g_hHookCore) {
        WCHAR selfPath[MAX_PATH];
        HMODULE hSelf;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCWSTR)FunHookProc, &hSelf);
        GetModuleFileNameW(hSelf, selfPath, MAX_PATH);

        WCHAR corePath[MAX_PATH];
        WCHAR* lastSlash = wcsrchr(selfPath, L'\\');
        if (lastSlash) {
            wcscpy_s(corePath, MAX_PATH, selfPath);
            WCHAR* slash = wcsrchr(corePath, L'\\');
            if (slash) *(slash + 1) = L'\0';
            wcscat_s(corePath, MAX_PATH, L"HookCore.dll");

            OutputDebugStringA("[HookEx] Loading HookCore.dll...\n");
            g_hHookCore = LoadLibraryW(corePath);
            if (!g_hHookCore) {
                char buf[256];
                sprintf_s(buf, "[HookEx] Failed to load HookCore.dll (err=%lu)\n", GetLastError());
                OutputDebugStringA(buf);
            }
        }
    }

    return CallNextHookEx(nullptr, code, wParam, lParam);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        OutputDebugStringA("[HookEx] DLL loaded\n");
        break;

    case DLL_PROCESS_DETACH:
        // HookCore 留在目标进程中继续挂钩，不释放
        OutputDebugStringA("[HookEx] DLL unloaded, HookCore stays resident\n");
        break;
    }
    return TRUE;
}

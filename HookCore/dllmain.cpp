#include "pch.h"
#include "Hooks.h"

HMODULE g_hHookCoreModule = nullptr;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(lpReserved);

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        g_hHookCoreModule = hModule;
        DisableThreadLibraryCalls(hModule);
        OutputDebugStringA("[HookCore] DLL loaded\n");
        if (InitializeHooks())
        {
            ApplyHookConfiguration();
        }
        CreateControlInspectorWindow();
        break;

    case DLL_PROCESS_DETACH:
        DestroyControlInspectorWindow();
        CleanupHooks();
        OutputDebugStringA("[HookCore] DLL unloaded\n");
        break;
    }
    return TRUE;
}

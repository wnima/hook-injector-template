#pragma once

// Hook config protocol via named file mapping (Local\HookCoreConfig)
// Injector writes config before injection; HookCore DLL reads it in DllMain.
// If mapping doesn't exist, DLL falls back to no hooks.

#define HOOK_CONFIG_MAGIC     0x484F4F4B   // 'HOOK'
#define HOOK_CONFIG_MAPPING   L"Local\\HookCoreConfig"
#define MAX_FUNC_HOOKS        8

typedef struct _HookFuncConfig {
    WCHAR dllName[64];
    WCHAR funcName[64];
} HookFuncConfig;

typedef struct _HookConfig {
    DWORD magic;

    // Function hooks: list of {dll, function} pairs
    DWORD funcHookCount;
    HookFuncConfig funcHooks[MAX_FUNC_HOOKS];

    // Address hook
    DWORD enableAddressHook;
    DWORD_PTR addressValue;
} HookConfig;

// Injector side: create mapping and write config (returns handle, or NULL on failure)
inline HANDLE CreateHookConfigMapping(const HookConfig* cfg) {
    DWORD size = sizeof(HookConfig);
    HANDLE hMapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr,
        PAGE_READWRITE, 0, size, HOOK_CONFIG_MAPPING);
    if (!hMapping) return nullptr;
    void* p = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, size);
    if (!p) { CloseHandle(hMapping); return nullptr; }
    memcpy(p, cfg, size);
    UnmapViewOfFile(p);
    return hMapping;
}

// DLL side: open mapping and read config (returns true on success)
inline bool ReadHookConfig(HookConfig* cfg) {
    HANDLE hMapping = OpenFileMappingW(FILE_MAP_READ, FALSE, HOOK_CONFIG_MAPPING);
    if (!hMapping) return false;
    void* p = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, sizeof(HookConfig));
    if (!p) { CloseHandle(hMapping); return false; }
    memcpy(cfg, p, sizeof(HookConfig));
    UnmapViewOfFile(p);
    CloseHandle(hMapping);
    return (cfg->magic == HOOK_CONFIG_MAGIC);
}

// Injector side: close mapping after injection completes
inline void CloseHookConfigMapping(HANDLE hMapping) {
    if (hMapping) CloseHandle(hMapping);
}

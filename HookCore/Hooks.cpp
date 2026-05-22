// ============================================================================
// HookCore\Hooks.cpp — 所有 Hook 实现的统一入口
// ============================================================================
//
// 包含:
//   - MessageBoxA Hook (标题/内容添加 "[HookCore]" 前缀)
//   - CreateFileW  Hook (文件打开操作记录到 DebugView)
//   - 地址 Hook     (指定内存地址的 inline hook)
//   - 状态查询 API  (已安装钩子信息)
//
// 每个钩子包含重入检测 (TLS 深度计数器) 和 SEH 异常保护。

#include "pch.h"
#include "Hooks.h"
#include "HookConfig.h"
#include "CICtrlDialog.h"

// ========== 注入器配置存储 ==========
static HookConfig g_config = {};
static bool       g_hasConfig = false;
static std::vector<std::string> g_dynamicHookNames;
static void*      g_targetAddress = (void*)0x00406E3E;

// ========== 原始函数类型定义 ==========
typedef int (WINAPI* MessageBoxAType)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
typedef HANDLE (WINAPI* CreateFileWType)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

// ========== 原始函数指针 ==========
static MessageBoxAType g_originalMessageBoxA = nullptr;
static CreateFileWType g_originalCreateFileW = nullptr;

// ========== TLS 重入防护 ==========
__declspec(thread) int g_messageBoxHookDepth = 0;
__declspec(thread) int g_createFileHookDepth = 0;

// ========== HookedMessageBoxA ==========
static int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    if (g_messageBoxHookDepth > 0)
        return g_originalMessageBoxA(hWnd, lpText, lpCaption, uType);

    g_messageBoxHookDepth++;

    __try
    {
        char newText[2048] = "";
        if (lpText)
        {
            lstrcatA(newText, "[HookCore] ");
            lstrcatA(newText, lpText);
        }
        else
        {
            lstrcatA(newText, "[HookCore] ");
        }

        char newCaption[1024] = "";
        if (lpCaption)
        {
            lstrcatA(newCaption, "[HookCore] ");
            lstrcatA(newCaption, lpCaption);
        }
        else
        {
            lstrcatA(newCaption, "[HookCore] ");
        }

        int result = g_originalMessageBoxA(hWnd, newText, newCaption, uType);
        g_messageBoxHookDepth--;
        return result;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        g_messageBoxHookDepth--;
        return g_originalMessageBoxA(hWnd, lpText, lpCaption, uType);
    }
}

// ========== HookedCreateFileW ==========
static HANDLE WINAPI HookedCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    if (g_createFileHookDepth > 0)
        return g_originalCreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
            lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

    g_createFileHookDepth++;

    __try
    {
        if (lpFileName)
        {
            char logBuf[1024] = "";
            lstrcatA(logBuf, "[HookCore] CreateFileW called: ");
            WideCharToMultiByte(CP_UTF8, 0, lpFileName, -1,
                logBuf + lstrlenA(logBuf), (int)(sizeof(logBuf) - lstrlenA(logBuf) - 1),
                nullptr, nullptr);
            logBuf[sizeof(logBuf) - 1] = '\0';
            lstrcatA(logBuf, "\n");
            OutputDebugStringA(logBuf);
        }

        HANDLE result = g_originalCreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
            lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
        g_createFileHookDepth--;
        return result;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        g_createFileHookDepth--;
        return g_originalCreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
            lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    }
}

// ========== InitializeHooks ==========
bool InitializeHooks()
{
    // 尝试读取注入器配置（命名文件映射）
    if (ReadHookConfig(&g_config)) {
        g_hasConfig = true;
        char logBuf[128];
        sprintf_s(logBuf, "[HookCore] Config from injector: %lu func hooks, addr=%s\n",
            g_config.funcHookCount, g_config.enableAddressHook ? "yes" : "no");
        OutputDebugStringA(logBuf);
    }

    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (hUser32)
        g_originalMessageBoxA = (MessageBoxAType)GetProcAddress(hUser32, "MessageBoxA");

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32)
        g_originalCreateFileW = (CreateFileWType)GetProcAddress(hKernel32, "CreateFileW");

    if (!g_originalMessageBoxA && !g_originalCreateFileW)
    {
        OutputDebugStringA("[HookCore] InitializeHooks: Failed to get any proc addresses\n");
        return false;
    }

    OutputDebugStringA("[HookCore] InitializeHooks: Proc addresses obtained\n");
    return true;
}

// ========== 动态 Hook 回调（通用日志）==========
static bool __stdcall DynamicHookCallback(void* context) {
    const char* name = (const char*)context;
    char buf[256];
    sprintf_s(buf, "[HookCore] %s called\n", name ? name : "?");
    OutputDebugStringA(buf);
    return false;
}

// ========== ApplyHookConfiguration ==========
void ApplyHookConfiguration() {
    if (g_hasConfig) {
        // ---- 按注入器配置安装 ----
        const HookConfig& cfg = g_config;

        // 函数 Hook
        for (DWORD i = 0; i < cfg.funcHookCount && i < MAX_FUNC_HOOKS; i++) {
            HMODULE hMod = GetModuleHandleW(cfg.funcHooks[i].dllName);
            if (!hMod) {
                char buf[256];
                sprintf_s(buf, "[HookCore] Config func hook: module '%ls' not loaded\n",
                    cfg.funcHooks[i].dllName);
                OutputDebugStringA(buf);
                continue;
            }

            char funcNameA[64] = {};
            WideCharToMultiByte(CP_ACP, 0, cfg.funcHooks[i].funcName, -1,
                funcNameA, 64, nullptr, nullptr);
            void* funcAddr = GetProcAddress(hMod, funcNameA);
            if (!funcAddr) {
                char buf[256];
                sprintf_s(buf, "[HookCore] Config func hook: '%s' not found\n", funcNameA);
                OutputDebugStringA(buf);
                continue;
            }

            // 存储名称供回调使用
            char nameBuf[128];
            sprintf_s(nameBuf, "Func:%s", funcNameA);
            g_dynamicHookNames.push_back(nameBuf);
            const char* ctx = g_dynamicHookNames.back().c_str();

            CHookManager::GetInstance().InstallAddressHook(
                funcAddr, DynamicHookCallback, (void*)ctx, false);

            char buf[256];
            sprintf_s(buf, "[HookCore] Dynamic func hook installed: %s @ 0x%p\n",
                funcNameA, funcAddr);
            OutputDebugStringA(buf);
        }

        // 地址 Hook
        if (cfg.enableAddressHook && cfg.addressValue != 0) {
            g_targetAddress = (void*)cfg.addressValue;
            InstallMyAddressHook();
        }

        OutputDebugStringA("[HookCore] Configuration applied\n");
    } else {
        OutputDebugStringA("[HookCore] No config, no hooks installed\n");
    }
}

// ========== CleanupHooks ==========
void CleanupHooks()
{
    CHookManager::GetInstance().UninstallAllHooks();
    CHookManager::GetInstance().UninstallAllAddressHooks();
    OutputDebugStringA("[HookCore] CleanupHooks: All hooks uninstalled\n");
}

// ========== InstallMessageBoxHook ==========
bool InstallMessageBoxHook()
{
    if (!g_originalMessageBoxA)
    {
        OutputDebugStringA("[HookCore] InstallMessageBoxHook: original not found\n");
        return false;
    }
    bool result = CHookManager::GetInstance().InstallHook(
        (void*)g_originalMessageBoxA, (void*)HookedMessageBoxA, "MessageBoxA");
    if (result)
        OutputDebugStringA("[HookCore] MessageBoxA hook installed\n");
    return result;
}

bool UninstallMessageBoxHook()
{
    return CHookManager::GetInstance().UninstallHook("MessageBoxA");
}

// ========== InstallCreateFileHook ==========
bool InstallCreateFileHook()
{
    if (!g_originalCreateFileW)
    {
        OutputDebugStringA("[HookCore] InstallCreateFileHook: original not found\n");
        return false;
    }
    bool result = CHookManager::GetInstance().InstallHook(
        (void*)g_originalCreateFileW, (void*)HookedCreateFileW, "CreateFileW");
    if (result)
        OutputDebugStringA("[HookCore] CreateFileW hook installed\n");
    return result;
}

bool UninstallCreateFileHook()
{
    return CHookManager::GetInstance().UninstallHook("CreateFileW");
}

// ========== 状态查询 API ==========

size_t GetHookCount()
{
    return CHookManager::GetInstance().GetHookCount();
}

size_t GetAddressHookCount()
{
    return CHookManager::GetInstance().GetAddressHookCount();
}

size_t GetHookNames(char* buffer, size_t bufferSize)
{
    if (!buffer || bufferSize == 0) return 0;

    std::vector<std::string> names;
    CHookManager::GetInstance().GetAllHookNames(names);

    size_t written = 0;
    buffer[0] = '\0';

    for (size_t i = 0; i < names.size(); i++)
    {
        const char* name = names[i].c_str();
        size_t nameLen = strlen(name);
        size_t needed = (written > 0 ? 1 : 0) + nameLen + 1;

        if (written + needed > bufferSize)
            break;

        if (written > 0)
        {
            lstrcatA(buffer, ",");
            written++;
        }
        lstrcatA(buffer, name);
        written += nameLen;
    }
    return written;
}

bool IsHookActive(const char* functionName)
{
    if (!functionName) return false;
    return CHookManager::GetInstance().IsHookInstalled(functionName);
}

// ========== 地址 Hook 实现 ==========


void SetTargetAddress(void* address)
{
    g_targetAddress = address;
}

void* GetTargetAddress()
{
    return g_targetAddress;
}

static LONG g_workerBusy = 0;

// ===== 控件查找器 =====

struct ControlCriteria {
    const WCHAR* className;   // nullptr = 不限制
    int          ctrlId;      // 0 = 不限制
    RECT         rect;        // 全0 = 不限制 (用 left 做容差)
    int          rectTolerance; // rect 匹配容差 (像素)
};

// 读取控件属性
static void ReadControlInfo(HWND hCtrl, WCHAR* outBuf, int outLen) {
    WCHAR cls[128] = {};
    WCHAR text[256] = {};
    GetClassNameW(hCtrl, cls, 128);
    GetWindowTextW(hCtrl, text, 256);
    RECT rc; GetWindowRect(hCtrl, &rc);
    int id = (int)GetWindowLongW(hCtrl, GWL_ID);
    DWORD style = (DWORD)GetWindowLongW(hCtrl, GWL_STYLE);

    _snwprintf_s(outBuf, outLen, _TRUNCATE,
        L"HWND=0x%p Class=%s Text=\"%s\" ID=%d Rect=(%d,%d,%dx%d) Style=0x%08X",
        hCtrl, cls, text, id,
        rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, style);
}

// 修改控件文本
static void ModifyControlText(HWND hCtrl, const WCHAR* newText) {
    SetWindowTextW(hCtrl, newText);
}

// 修改控件位置/大小
static void ModifyControlRect(HWND hCtrl, int x, int y, int w, int h) {
    SetWindowPos(hCtrl, nullptr, x, y, w, h, SWP_NOZORDER);
}

// 按条件查找控件
static HWND FindControl(HWND hParent, const ControlCriteria& crit) {
    struct Ctx { const ControlCriteria& crit; HWND result; };
    Ctx ctx = { crit, nullptr };

    EnumChildWindows(hParent, [](HWND hChild, LPARAM lp) -> BOOL {
        auto* ctx = (Ctx*)lp;
        auto& c = ctx->crit;

        // class name
        if (c.className) {
            WCHAR cls[128];
            GetClassNameW(hChild, cls, 128);
            if (_wcsicmp(cls, c.className) != 0) return TRUE;
        }
        // ctrl id
        if (c.ctrlId != 0) {
            int id = (int)GetWindowLongW(hChild, GWL_ID);
            if (id != c.ctrlId) return TRUE;
        }
        // rect
        if (c.rect.left != 0 || c.rect.top != 0 || c.rect.right != 0 || c.rect.bottom != 0) {
            RECT rc; GetWindowRect(hChild, &rc);
            int t = c.rectTolerance ? c.rectTolerance : 2;
            if (abs(rc.left   - c.rect.left  ) > t) return TRUE;
            if (abs(rc.top    - c.rect.top   ) > t) return TRUE;
            if (abs(rc.right  - c.rect.right ) > t) return TRUE;
            if (abs(rc.bottom - c.rect.bottom) > t) return TRUE;
        }

        ctx->result = hChild;
        return FALSE; // 停止枚举
    }, (LPARAM)&ctx);

    return ctx.result;
}

// ===== 工作线程 =====

static DWORD WINAPI AddressWorkerProc(LPVOID) {
    Sleep(500);
    HWND hWnd = FindWindowW(nullptr, L"RSA Tool Info");
    if (!hWnd) {
        OutputDebugStringA("[HookCore] AddressWorker: RSA Tool Info not found\n");
        InterlockedExchange(&g_workerBusy, 0);
        return 0;
    }

    WCHAR buf[512];
    _snwprintf_s(buf, 512, _TRUNCATE, L"[HookCore] AddressWorker: found RSA window 0x%p\n", hWnd);
    OutputDebugStringW(buf);

    // --- 示例：按 Class + ID 定位控件，然后读取 ---
    ControlCriteria crit = {};
    crit.className = L"Edit";           // 例如查找 Button
    crit.ctrlId = 1026;                // 可选：限定 Ctrl ID
    //crit.rect = {10, 20, 100, 50};    // 可选：限定位置

    HWND hCtrl = FindControl(hWnd, crit);
    if (hCtrl) {
        WCHAR info[512];
        ReadControlInfo(hCtrl, info, 512);
        OutputDebugStringW(L"[HookCore] AddressWorker: found control ->\n");
        OutputDebugStringW(info);
        OutputDebugStringW(L"\n");

        // 示例操作：
        ModifyControlText(hCtrl, L"新文本");
        // ModifyControlRect(hCtrl, 10, 20, 200, 30);
    } else {
        OutputDebugStringA("[HookCore] AddressWorker: control not found\n");
    }

    InterlockedExchange(&g_workerBusy, 0);
    return 0;
}

static bool __stdcall CustomAddressCallback(void* context)
{
    UNREFERENCED_PARAMETER(context);

    WCHAR logBuf[128];
    _snwprintf_s(logBuf, 128, _TRUNCATE, L"[HookCore] Address 0x%p hit\n", g_targetAddress);
    OutputDebugStringW(logBuf);

    // 防堆积：仅当前一个 worker 已退出时才创建新线程
    if (!InterlockedExchange(&g_workerBusy, 1)) {
        HANDLE h = CreateThread(nullptr, 0, AddressWorkerProc, nullptr, 0, nullptr);
        if (h) CloseHandle(h);
    }

    return false;
}

bool InstallMyAddressHook()
{
    if (!g_targetAddress)
    {
        OutputDebugStringA("[HookCore] InstallMyAddressHook: no target address set, skipping\n");
        return false;
    }

    if (CHookManager::GetInstance().IsAddressHookInstalled(g_targetAddress))
    {
        OutputDebugStringA("[HookCore] InstallMyAddressHook: already installed\n");
        return true;
    }

    bool result = CHookManager::GetInstance().InstallAddressHook(
        g_targetAddress, CustomAddressCallback, nullptr, false);

    if (result)
    {
        char logBuf[128];
        sprintf_s(logBuf, "[HookCore] Address hook installed at 0x%p\n", g_targetAddress);
        OutputDebugStringA(logBuf);
    }
    return result;
}

bool UninstallMyAddressHook()
{
    if (!g_targetAddress) return false;
    return CHookManager::GetInstance().UninstallAddressHook(g_targetAddress);
}

// ========== 控件检查器窗口（MFC 对话框）==========

void CreateControlInspectorWindow()
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	StartCICtrlThread();
}

void DestroyControlInspectorWindow()
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	StopCICtrlThread();
}

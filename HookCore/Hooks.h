#pragma once

extern "C" {
    // 初始化钩子系统（获取原始 API 地址）
    bool InitializeHooks();

    // 根据注入器配置安装 Hook（替换硬编码 Install* 调用）
    // 如果有注入器配置则按配置安装，否则回退到默认行为
    void ApplyHookConfiguration();

    // 清理所有已安装的钩子
    void CleanupHooks();

    // MessageBoxA 钩子: 弹窗内容前添加 "[HookCore]" 前缀
    bool InstallMessageBoxHook();
    bool UninstallMessageBoxHook();

    // CreateFileW 钩子: 将文件打开操作记录到 DebugView
    bool InstallCreateFileHook();
    bool UninstallCreateFileHook();

    // ========== 状态查询 API ==========

    size_t GetHookCount();
    size_t GetAddressHookCount();
    size_t GetHookNames(char* buffer, size_t bufferSize);
    bool IsHookActive(const char* functionName);

    // ========== 地址 Hook API ==========

    void SetTargetAddress(void* address);
    void* GetTargetAddress();
    bool InstallMyAddressHook();
    bool UninstallMyAddressHook();

    // ========== 控件检查器窗口 ==========

    void CreateControlInspectorWindow();
    void DestroyControlInspectorWindow();
}

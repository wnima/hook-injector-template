# DLL Injector

Windows DLL 注入工具，支持三种注入方式，包含 Hook 引擎和控件检查器窗口。

## 项目结构

| 目录 | 说明 |
|---|---|
| `Injector/` | MFC GUI 注入器，三种注入方式均在此实现 |
| `HookCore/` | Hook 引擎 DLL，HookManager + MessageBoxA/CreateFileW/地址 Hook + 控件检查器窗口 |
| `HookDLL_HookEx/` | SetWindowsHookEx 注入 Stub，DllMain 中加载 HookCore.dll |

## 注入方式

- **远程线程注入** — `CreateRemoteThread` + `LoadLibraryW`，直接注入 HookCore.dll
- **APC 注入** — `QueueUserAPC` + `LoadLibraryW`，直接注入 HookCore.dll
- **SetWindowsHookEx 注入** — `WH_GETMESSAGE` 消息钩子，注入 HookDLL_HookEx.dll 后由 Stub 加载 HookCore.dll

## 构建

需要 Visual Studio 2022。

1. 打开 `Injector/Injector.sln`
2. 选择配置：Debug/Release，x86/x64
3. 生成解决方案

## 使用

1. 启动 `Injector.exe`，选择目标进程
2. 选择注入方式，或通过界面配置函数 Hook / 地址 Hook 参数
3. 点击注入

注入成功后，目标进程会弹出 `HookCore - <进程名>` 控件检查器窗口，可查看目标进程的窗口控件信息。

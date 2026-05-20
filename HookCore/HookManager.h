#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>

typedef bool (__stdcall *AddressHookCallback)(void* context);

class CHookManager
{
public:
    static CHookManager& GetInstance();

    ~CHookManager();

    // Function hooks
    bool InstallHook(void* targetFunction, void* hookFunction, const std::string& functionName);
    bool UninstallHook(const std::string& functionName);
    void UninstallAllHooks();
    bool IsHookInstalled(const std::string& functionName);
    void* GetOriginalFunction(const std::string& functionName);
    size_t GetHookCount();
    void GetAllHookNames(std::vector<std::string>& names);

    // Address hooks
    bool InstallAddressHook(void* targetAddress, AddressHookCallback callback,
                            void* context = nullptr, bool skipOriginalInstruction = false);
    bool UninstallAddressHook(void* targetAddress);
    void UninstallAllAddressHooks();
    bool UpdateAddressHookCallback(void* targetAddress, AddressHookCallback newCallback,
                                   void* newContext = nullptr);
    bool EnableAddressHook(void* targetAddress, bool enable);
    bool IsAddressHookInstalled(void* targetAddress);
    size_t GetAddressHookCount();

private:
    CHookManager();
    CHookManager(const CHookManager&) = delete;
    CHookManager& operator=(const CHookManager&) = delete;

    struct HookInfo {
        void* targetFunction;
        void* hookFunction;
        void* originalBytes;
        size_t originalInstructionLength;
        bool isInstalled;
        std::string functionName;
    };

    struct AddressHookInfo {
        void* targetAddress;
        AddressHookCallback callback;
        void* context;
        bool skipOriginalInstruction;
        bool isInstalled;
        size_t originalInstructionLength;
        BYTE* originalBytes;
        void* trampolineAddress;
        void* trampolineStub;
    };

    bool PerformAddressHook(AddressHookInfo& info);
    bool RemoveAddressHook(AddressHookInfo& info);

    CRITICAL_SECTION m_cs;
    std::unordered_map<std::string, HookInfo> m_hooks;
    std::unordered_map<void*, AddressHookInfo> m_addressHooks;
    std::vector<void*> m_trampolineBlocks;
};

class CSLock {
public:
    CSLock(CRITICAL_SECTION& cs) : m_cs(cs) { EnterCriticalSection(&m_cs); }
    ~CSLock() { LeaveCriticalSection(&m_cs); }
private:
    CRITICAL_SECTION& m_cs;
};

// Helpers
size_t GetInstructionLength(const void* address, size_t minBytes);
void CreateJumpInstruction(void* from, void* to, void* outBuffer, size_t& outSize);

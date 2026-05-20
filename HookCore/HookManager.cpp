#include "pch.h"
#include <cstring>
#include <cstdio>
#include <cstdarg>
#pragma comment(lib, "kernel32.lib")

// ========== Logging ==========
static void WriteLog(const char* fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    int wlen = MultiByteToWideChar(CP_UTF8, 0, buf, -1, nullptr, 0);
    if (wlen > 0) {
        WCHAR* wbuf = (WCHAR*)_alloca(wlen * sizeof(WCHAR));
        MultiByteToWideChar(CP_UTF8, 0, buf, -1, wbuf, wlen);
        OutputDebugStringW(wbuf);
    }

    FILE* f = nullptr;
    if (fopen_s(&f, "HookMgr.log", "a") == 0 && f) {
        fputs(buf, f);
        fclose(f);
    }
}

// ========== Instruction Length Decoder ==========
size_t GetInstructionLength(const void* address, size_t minBytes) {
    const BYTE* p = (const BYTE*)address;
    const BYTE* start = p;
#ifdef _WIN64
    bool is64 = true;
#else
    bool is64 = false;
#endif

    while ((size_t)(p - start) < minBytes) {
        const BYTE* instrStart = p;
        BYTE opcode = *p;

        bool hasREX = false;
        size_t rexOffset = 0;

        // Prefixes
        while (true) {
            BYTE b = *p;
            if (is64 && (b & 0xF0) == 0x40) { hasREX = true; rexOffset = 1; p++; continue; }
            if (b == 0x26 || b == 0x2E || b == 0x36 || b == 0x3E ||
                b == 0x64 || b == 0x65) { p++; continue; }
            if (b == 0x66) { p++; continue; }
            if (b == 0x67) { p++; continue; }
            if (b == 0xF0) { p++; continue; }
            if (b == 0xF2 || b == 0xF3) { p++; continue; }
            break;
        }

        opcode = *p;
        size_t len = 1;
        bool hasModRM = false;

        if ((opcode & 0x07) == 0x05 && opcode <= 0x3F) {
            len += (is64 && hasREX ? 8 : 4);
        }
        else if (opcode >= 0x88 && opcode <= 0x8F) hasModRM = true;
        else if (opcode >= 0x00 && opcode <= 0x3B) hasModRM = true;
        else if (opcode >= 0x50 && opcode <= 0x5F) { /* PUSH/POP reg */ }
        else if (opcode >= 0x70 && opcode <= 0x7F) { len += 1; }
        else if (opcode == 0x0F) {
            p++; len++;
            BYTE op2 = *p;
            if (op2 >= 0x80 && op2 <= 0x8F) { len += 4; }
            else if (op2 == 0x1F) { /* NOP */ }
            else { hasModRM = true; }
        }
        else if (opcode == 0xA0 || opcode == 0xA1 || opcode == 0xA2 || opcode == 0xA3) {
            len += (is64 ? 8 : 4);
        }
        else if (opcode >= 0xB0 && opcode <= 0xB7) { len += 1; }
        else if (opcode >= 0xB8 && opcode <= 0xBF) {
            len += (is64 ? (hasREX ? 8 : 4) : 4);
            if (is64 && hasREX) len = 1 + 8;
        }
        else if (opcode == 0x68 || opcode == 0x6A) { len += (opcode == 0x6A ? 1 : (is64 ? 8 : 4)); }
        else if (opcode == 0xC2 || opcode == 0xCA) { len += 2; }
        else if (opcode == 0xC3 || opcode == 0xCB) { /* RET */ }
        else if ((opcode & 0xFE) == 0xC6) hasModRM = true;  // MOV reg8, imm8
        else if (opcode == 0xC7) hasModRM = true;  // MOV r/m32, imm32
        else if (opcode == 0xE8 || opcode == 0xE9) { len += 4; }
        else if (opcode == 0xEB) { len += 1; }
        else if (opcode == 0xFF) hasModRM = true;
        else if (opcode == 0x81 || opcode == 0x83) hasModRM = true;
        else if (opcode == 0x85) hasModRM = true;
        else if (opcode == 0x8D) hasModRM = true;
        else if (opcode >= 0x40 && opcode <= 0x4F) { /* REX prefix - already handled */ }
        else { hasModRM = true; }

        if (hasModRM) {
            BYTE modrm = p[len];
            len++;
            BYTE mod = (modrm >> 6) & 3;
            BYTE rm = modrm & 7;

            bool hasSIB = false;
            if (mod != 3 && rm == 4) { hasSIB = true; }

            if (hasSIB) {
                BYTE sib = p[len];
                len++;
                BYTE base = sib & 7;
                if (mod == 0 && base == 5) {
                    len += 4; // disp32
                }
            }

            if (mod == 1) { len += 1; }           // disp8
            else if (mod == 2) { len += 4; }       // disp32
            else if (mod == 0 && rm == 5) { len += 4; } // [rip+disp32] or [disp32]

            // Immediate
            BYTE op = *(instrStart + rexOffset);
            if (op == 0x81 || op == 0x83 || op == 0xC7 || (op >= 0x80 && op <= 0x83) ||
                (op & 0xF8) == 0xC0 || (op & 0xF8) == 0xD0) {
                BYTE op2 = op;
                if (op >= 0x80 && op <= 0x83) {
                    len += (op == 0x81 ? 4 : (op == 0x83 ? 1 : 1));
                }
            }
            else if (op == 0xF7 || op == 0xF6) {
                len += (op & 1) ? 4 : 1;
            }
        }

        p = instrStart + len;
    }
    return (size_t)(p - start);
}

// ========== JMP Instruction Generator ==========
void CreateJumpInstruction(void* from, void* to, void* outBuffer, size_t& outSize) {
#ifdef _WIN64
    INT64 distance = (INT64)((BYTE*)to - ((BYTE*)from + 5));
    if (distance >= (INT64)0xFFFFFFFF80000000LL && distance <= 0x7FFFFFFFLL) {
        BYTE* buf = (BYTE*)outBuffer;
        buf[0] = 0xE9;
        INT32 rel32 = (INT32)distance;
        memcpy(buf + 1, &rel32, 4);
        outSize = 5;
    } else {
        // Far JMP via FF 25 (RIP-relative indirect)
        BYTE* buf = (BYTE*)outBuffer;
        buf[0] = 0xFF;
        buf[1] = 0x25;
        DWORD zero = 0;
        memcpy(buf + 2, &zero, 4);
        memcpy(buf + 6, &to, 8);
        outSize = 14;
    }
#else
    BYTE* buf = (BYTE*)outBuffer;
    buf[0] = 0xE9;
    INT32 rel32 = (INT32)((BYTE*)to - ((BYTE*)from + 5));
    memcpy(buf + 1, &rel32, 4);
    outSize = 5;
#endif
}

// ========== Trampoline helper ==========
static void RemoveTrampolineBlock(std::vector<void*>& blocks, void* addr) {
    auto it = std::find(blocks.begin(), blocks.end(), addr);
    if (it != blocks.end()) {
        blocks.erase(it);
    }
}

// ========== CHookManager ==========

CHookManager& CHookManager::GetInstance() {
    static CHookManager instance;
    return instance;
}

CHookManager::CHookManager() {
    InitializeCriticalSection(&m_cs);
}

CHookManager::~CHookManager() {
    UninstallAllHooks();
    UninstallAllAddressHooks();
    DeleteCriticalSection(&m_cs);
}

// ========== Function Hooks ==========

bool CHookManager::InstallHook(void* targetFunction, void* hookFunction, const std::string& functionName) {
    CSLock lock(m_cs);

    if (targetFunction == nullptr || hookFunction == nullptr) {
        WriteLog("[HookMgr] Error: null function pointer\n");
        return false;
    }

    if (m_hooks.find(functionName) != m_hooks.end()) {
        WriteLog("[HookMgr] Error: hook '%s' already exists\n", functionName.c_str());
        return false;
    }

    size_t instLen = GetInstructionLength(targetFunction, 5);
    HookInfo info;
    info.targetFunction = targetFunction;
    info.hookFunction = hookFunction;
    info.functionName = functionName;
    info.isInstalled = false;
    info.originalInstructionLength = instLen;
    info.originalBytes = new BYTE[instLen];
    memcpy(info.originalBytes, targetFunction, instLen);

    // Build trampoline: [original bytes] [JMP back to target+instLen]
    size_t jmpBackSize;
    void* trampoline = VirtualAlloc(nullptr, instLen + 14, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampoline) {
        WriteLog("[HookMgr] Error: Failed to allocate trampoline for '%s'\n", functionName.c_str());
        delete[] info.originalBytes;
        return false;
    }
    m_trampolineBlocks.push_back(trampoline);

    memcpy(trampoline, info.originalBytes, instLen);
    void* returnAddr = (BYTE*)targetFunction + instLen;
    CreateJumpInstruction((BYTE*)trampoline + instLen, returnAddr, (BYTE*)trampoline + instLen, jmpBackSize);

    // Patch target: JMP to hook function
    BYTE jmpInstruction[14];
    size_t actualJumpSize;
    CreateJumpInstruction(targetFunction, hookFunction, jmpInstruction, actualJumpSize);

    DWORD oldProtect;
    if (!VirtualProtect(targetFunction, instLen, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        DWORD err = GetLastError();
        WriteLog("[HookMgr] Error: VirtualProtect failed (err=%lu) for '%s'\n", err, functionName.c_str());
        RemoveTrampolineBlock(m_trampolineBlocks, trampoline);
        VirtualFree(trampoline, 0, MEM_RELEASE);
        delete[] info.originalBytes;
        return false;
    }

    memset(targetFunction, 0x90, instLen);
    memcpy(targetFunction, jmpInstruction, actualJumpSize);

    DWORD dummy;
    VirtualProtect(targetFunction, instLen, oldProtect, &dummy);
    FlushInstructionCache(GetCurrentProcess(), targetFunction, instLen);

    info.isInstalled = true;
    m_hooks[functionName] = info;

    WriteLog("[HookMgr] Hook installed: %s\n", functionName.c_str());
    return true;
}

bool CHookManager::UninstallHook(const std::string& functionName) {
    CSLock lock(m_cs);

    auto it = m_hooks.find(functionName);
    if (it == m_hooks.end()) {
        WriteLog("[HookMgr] Error: hook '%s' not found\n", functionName.c_str());
        return false;
    }

    HookInfo& info = it->second;
    if (!info.isInstalled) return false;

    DWORD oldProtect;
    if (!VirtualProtect(info.targetFunction, info.originalInstructionLength, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        WriteLog("[HookMgr] Error: VirtualProtect failed during uninstall of '%s'\n", functionName.c_str());
        return false;
    }

    memcpy(info.targetFunction, info.originalBytes, info.originalInstructionLength);
    VirtualProtect(info.targetFunction, info.originalInstructionLength, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), info.targetFunction, info.originalInstructionLength);

    delete[] info.originalBytes;
    m_hooks.erase(it);

    WriteLog("[HookMgr] Hook uninstalled: %s\n", functionName.c_str());
    return true;
}

void CHookManager::UninstallAllHooks() {
    CSLock lock(m_cs);

    std::vector<std::string> names;
    for (auto& pair : m_hooks) {
        if (pair.second.isInstalled) {
            names.push_back(pair.first);
        }
    }
    for (auto& name : names) {
        UninstallHook(name);
    }
    m_hooks.clear();
    WriteLog("[HookMgr] All hooks uninstalled\n");
}

bool CHookManager::IsHookInstalled(const std::string& functionName) {
    CSLock lock(m_cs);
    auto it = m_hooks.find(functionName);
    return (it != m_hooks.end() && it->second.isInstalled);
}

void* CHookManager::GetOriginalFunction(const std::string& functionName) {
    CSLock lock(m_cs);
    auto it = m_hooks.find(functionName);
    if (it != m_hooks.end()) {
        return it->second.targetFunction;
    }
    return nullptr;
}

size_t CHookManager::GetHookCount() {
    CSLock lock(m_cs);
    return m_hooks.size();
}

void CHookManager::GetAllHookNames(std::vector<std::string>& names) {
    CSLock lock(m_cs);
    names.clear();
    for (auto& pair : m_hooks) {
        names.push_back(pair.first);
    }
}

// ========== Address Hooks ==========

bool CHookManager::InstallAddressHook(void* targetAddress, AddressHookCallback callback,
                                       void* context, bool skipOriginal) {
    CSLock lock(m_cs);

    if (targetAddress == nullptr || callback == nullptr) {
        WriteLog("[HookMgr] Error: null parameter for address hook\n");
        return false;
    }

    if (m_addressHooks.find(targetAddress) != m_addressHooks.end()) {
        WriteLog("[HookMgr] Error: address hook already exists at 0x%p\n", targetAddress);
        return false;
    }

    AddressHookInfo info;
    info.targetAddress = targetAddress;
    info.callback = callback;
    info.context = context;
    info.skipOriginalInstruction = skipOriginal;
    info.isInstalled = false;
    info.originalInstructionLength = 0;
    info.trampolineAddress = nullptr;
    info.trampolineStub = nullptr;
    info.originalBytes = nullptr;

    if (PerformAddressHook(info)) {
        info.isInstalled = true;
        m_addressHooks[targetAddress] = info;
        WriteLog("[HookMgr] Address hook installed - 0x%p\n", targetAddress);
        return true;
    }

    WriteLog("[HookMgr] Error: Address hook install failed - 0x%p\n", targetAddress);
    return false;
}

bool CHookManager::UninstallAddressHook(void* targetAddress) {
    CSLock lock(m_cs);

    auto it = m_addressHooks.find(targetAddress);
    if (it == m_addressHooks.end()) {
        WriteLog("[HookMgr] Error: Address hook not found - 0x%p\n", targetAddress);
        return false;
    }

    AddressHookInfo& info = it->second;
    if (!info.isInstalled) {
        WriteLog("[HookMgr] Warning: Address hook not installed - 0x%p\n", targetAddress);
        return false;
    }

    if (RemoveAddressHook(info)) {
        m_addressHooks.erase(it);
        WriteLog("[HookMgr] Address hook uninstalled - 0x%p\n", targetAddress);
        return true;
    }

    WriteLog("[HookMgr] Error: Address hook uninstall failed - 0x%p\n", targetAddress);
    return false;
}

void CHookManager::UninstallAllAddressHooks() {
    CSLock lock(m_cs);

    std::vector<void*> addresses;
    for (auto& pair : m_addressHooks) {
        if (pair.second.isInstalled) {
            addresses.push_back(pair.first);
        }
    }
    for (auto* addr : addresses) {
        UninstallAddressHook(addr);
    }
    m_addressHooks.clear();
    WriteLog("[HookMgr] All address hooks uninstalled\n");
}

bool CHookManager::UpdateAddressHookCallback(void* targetAddress, AddressHookCallback newCallback, void* newContext) {
    CSLock lock(m_cs);

    auto it = m_addressHooks.find(targetAddress);
    if (it == m_addressHooks.end()) return false;

    it->second.callback = newCallback;
    it->second.context = newContext;
    return true;
}

bool CHookManager::EnableAddressHook(void* targetAddress, bool enable) {
    CSLock lock(m_cs);

    auto it = m_addressHooks.find(targetAddress);
    if (it == m_addressHooks.end()) return false;

    AddressHookInfo& info = it->second;

    if (enable && !info.isInstalled) {
        BYTE jmpInstruction[14];
        size_t actualJumpSize;
        CreateJumpInstruction(info.targetAddress, info.trampolineStub, jmpInstruction, actualJumpSize);

        DWORD oldProtect;
        if (!VirtualProtect(info.targetAddress, info.originalInstructionLength,
                           PAGE_EXECUTE_READWRITE, &oldProtect)) {
            WriteLog("[HookMgr] Error: EnableAddressHook VirtualProtect failed\n");
            return false;
        }

        memset(info.targetAddress, 0x90, info.originalInstructionLength);
        memcpy(info.targetAddress, jmpInstruction, actualJumpSize);
        VirtualProtect(info.targetAddress, info.originalInstructionLength, oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), info.targetAddress, info.originalInstructionLength);

        info.isInstalled = true;
        return true;
    }
    else if (!enable && info.isInstalled) {
        DWORD oldProtect;
        if (!VirtualProtect(info.targetAddress, info.originalInstructionLength,
                           PAGE_EXECUTE_READWRITE, &oldProtect)) {
            WriteLog("[HookMgr] Error: EnableAddressHook VirtualProtect failed\n");
            return false;
        }

        memcpy(info.targetAddress, info.originalBytes, info.originalInstructionLength);
        VirtualProtect(info.targetAddress, info.originalInstructionLength, oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), info.targetAddress, info.originalInstructionLength);

        info.isInstalled = false;
        return true;
    }

    return true;
}

bool CHookManager::IsAddressHookInstalled(void* targetAddress) {
    CSLock lock(m_cs);
    auto it = m_addressHooks.find(targetAddress);
    return (it != m_addressHooks.end() && it->second.isInstalled);
}

size_t CHookManager::GetAddressHookCount() {
    CSLock lock(m_cs);
    return m_addressHooks.size();
}

// ========== Address Hook Core ==========

bool CHookManager::PerformAddressHook(AddressHookInfo& addressHookInfo) {
    void* targetAddress = addressHookInfo.targetAddress;

    size_t instLen = GetInstructionLength(targetAddress, 5);
    addressHookInfo.originalInstructionLength = instLen;
    addressHookInfo.originalBytes = new BYTE[instLen];
    memcpy(addressHookInfo.originalBytes, targetAddress, instLen);

    // Trampoline layout: [original bytes(instLen)] [stub(64)] [jmp back(14)] [address table(16)]
    const size_t stubSize = 96;
    const size_t jmpBackMax = 14;
    const size_t addrTableSize = 16;
    const size_t trampolineSize = instLen + stubSize + jmpBackMax + addrTableSize;

    addressHookInfo.trampolineAddress = nullptr;
#ifdef _WIN64
    for (int attempt = 0; attempt < 16; attempt++) {
        INT64 offset = (INT64)((attempt % 2 == 0 ? 1 : -1) * (0x10000000LL << (attempt / 2)));
        if (attempt == 0) offset = 0;
        void* hint = (BYTE*)targetAddress + offset;
        hint = (void*)((DWORD64)hint & ~0xFFFFLL);
        addressHookInfo.trampolineAddress = VirtualAlloc(hint, trampolineSize,
                                                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (addressHookInfo.trampolineAddress) break;
    }
#endif
    if (!addressHookInfo.trampolineAddress) {
        addressHookInfo.trampolineAddress = VirtualAlloc(nullptr, trampolineSize,
                                                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    if (!addressHookInfo.trampolineAddress) {
        WriteLog("[HookMgr] Error: Failed to allocate trampoline memory\n");
        delete[] addressHookInfo.originalBytes;
        addressHookInfo.originalBytes = nullptr;
        return false;
    }

    m_trampolineBlocks.push_back(addressHookInfo.trampolineAddress);

    BYTE* tramp = (BYTE*)addressHookInfo.trampolineAddress;
    size_t offset = 0;

    // 1) Copy original bytes
    memcpy(tramp + offset, addressHookInfo.originalBytes, instLen);
    offset += instLen;

    // 1.5) JMP back: tramp+instLen -> targetAddress+instLen
    void* returnAddr = (BYTE*)targetAddress + instLen;
    size_t retJmpSize;
    CreateJumpInstruction(tramp + offset, returnAddr, tramp + offset, retJmpSize);
    offset += retJmpSize;

    // 2) Build stub
    BYTE* stubStart = tramp + offset;
    BYTE* addressTable = tramp + trampolineSize - addrTableSize;

#ifdef _WIN64
    // --- x64 stub ---
    BYTE* p = stubStart;

    // push volatile regs (x64 calling convention)
    p[0] = 0x41; p[1] = 0x53; // push r11
    p += 2; p[0] = 0x41; p[1] = 0x52; // push r10
    p += 2; p[0] = 0x41; p[1] = 0x51; // push r9
    p += 2; p[0] = 0x41; p[1] = 0x50; // push r8
    p += 2; p[0] = 0x52;            // push rdx
    p += 1; p[0] = 0x51;            // push rcx
    p += 1; p[0] = 0x50;            // push rax
    p += 1;

    // sub rsp, 32 (shadow space)
    p[0] = 0x48; p[1] = 0x83; p[2] = 0xEC; p[3] = 0x20;
    p += 4;

    // mov rcx, [rip + disp32] -> context from addressTable[0]
    p[0] = 0x48; p[1] = 0x8B; p[2] = 0x0D;
    DWORD ctxDisp = (DWORD)((addressTable - (p + 7)));
    memcpy(p + 3, &ctxDisp, 4);
    p += 7;

    // call [rip + disp32] -> callback from addressTable[8]
    p[0] = 0xFF; p[1] = 0x15;
    DWORD cbDisp = (DWORD)((addressTable + 8 - (p + 6)));
    memcpy(p + 2, &cbDisp, 4);
    p += 6;

    // add rsp, 32
    p[0] = 0x48; p[1] = 0x83; p[2] = 0xC4; p[3] = 0x20;
    p += 4;

    // test rax, rax
    p[0] = 0x48; p[1] = 0x85; p[2] = 0xC0;
    p += 3;

    // pop regs (reverse order)
    p[0] = 0x58; // pop rax
    p += 1; p[0] = 0x59; // pop rcx
    p += 1; p[0] = 0x5A; // pop rdx
    p += 1; p[0] = 0x41; p[1] = 0x58; // pop r8
    p += 2; p[0] = 0x41; p[1] = 0x59; // pop r9
    p += 2; p[0] = 0x41; p[1] = 0x5A; // pop r10
    p += 2; p[0] = 0x41; p[1] = 0x5B; // pop r11
    p += 2;

    // jnz .skip_to_original (if callback returned true -> skip original)
    p[0] = 0x75;
    BYTE* jnzPatch = p + 1;
    p += 2;

    // zero (execute original): JMP to trampoline's original bytes
    size_t jmpToOrigSize;
    CreateJumpInstruction(p, tramp, p, jmpToOrigSize);
    p += jmpToOrigSize;

    // .skip_to_original: JMP past original instruction
    *jnzPatch = (BYTE)(p - (jnzPatch + 1));
    size_t jmpToSkipSize;
    void* skipAddr = (BYTE*)targetAddress + instLen;
    CreateJumpInstruction(p, skipAddr, p, jmpToSkipSize);
    p += jmpToSkipSize;

    // NOP fill
    while (p < stubStart + stubSize) {
        *p++ = 0x90;
    }

    addressHookInfo.trampolineStub = stubStart;

    // Address table: [context ptr(8)] [callback ptr(8)]
    void* ctxPtr = addressHookInfo.context;
    void* cbPtr = (void*)addressHookInfo.callback;
    memcpy(addressTable, &ctxPtr, 8);
    memcpy(addressTable + 8, &cbPtr, 8);

#else
    // --- x86 stub ---
    BYTE* p = stubStart;

    // pushad
    p[0] = 0x60; p += 1;

    // push context -- x86 FF 35 uses absolute address
    p[0] = 0xFF; p[1] = 0x35;
    DWORD ctxAddr = (DWORD)(addressTable);
    memcpy(p + 2, &ctxAddr, 4);
    p += 6;

    // call [addressTable + 4]
    p[0] = 0xFF; p[1] = 0x15;
    DWORD cbAddr = (DWORD)(addressTable + 4);
    memcpy(p + 2, &cbAddr, 4);
    p += 6;

    // test eax, eax
    p[0] = 0x85; p[1] = 0xC0; p += 2;

    // popad
    p[0] = 0x61; p += 1;

    // jnz .skip_to_original
    p[0] = 0x75;
    BYTE* jnzPatch = p + 1;
    p += 2;

    // zero: JMP to original bytes
    size_t jmpToOrigSize = 0;
    CreateJumpInstruction(p, tramp, p, jmpToOrigSize);
    p += jmpToOrigSize;

    // .skip_to_original: JMP past original instruction
    *jnzPatch = (BYTE)(p - (jnzPatch + 1));
    size_t jmpToSkipSize;
    void* skipAddr = (BYTE*)targetAddress + instLen;
    CreateJumpInstruction(p, skipAddr, p, jmpToSkipSize);
    p += jmpToSkipSize;

    // NOP fill
    while (p < stubStart + stubSize) {
        *p++ = 0x90;
    }

    addressHookInfo.trampolineStub = stubStart;

    // Address table: [context ptr(4)] [callback ptr(4)]
    void* ctxPtr = addressHookInfo.context;
    void* cbPtr = (void*)addressHookInfo.callback;
    memcpy(addressTable, &ctxPtr, 4);
    memcpy(addressTable + 4, &cbPtr, 4);
#endif

    // Patch target address with JMP to stub
    DWORD oldProtect;
    if (!VirtualProtect(targetAddress, instLen, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        DWORD err = GetLastError();
        WriteLog("[HookMgr] Error: VirtualProtect failed (err=%lu)\n", err);
        RemoveTrampolineBlock(m_trampolineBlocks, addressHookInfo.trampolineAddress);
        VirtualFree(addressHookInfo.trampolineAddress, 0, MEM_RELEASE);
        addressHookInfo.trampolineAddress = nullptr;
        delete[] addressHookInfo.originalBytes;
        addressHookInfo.originalBytes = nullptr;
        return false;
    }

    BYTE jmpInstruction[14];
    size_t actualJumpSize;
    CreateJumpInstruction(targetAddress, addressHookInfo.trampolineStub, jmpInstruction, actualJumpSize);

    memset(targetAddress, 0x90, instLen);
    memcpy(targetAddress, jmpInstruction, actualJumpSize);

    DWORD dummy;
    VirtualProtect(targetAddress, instLen, oldProtect, &dummy);
    FlushInstructionCache(GetCurrentProcess(), targetAddress, instLen);

    WriteLog("[HookMgr] Address hook installed (inst length: %zu) - 0x%p\n", instLen, targetAddress);
    return true;
}

bool CHookManager::RemoveAddressHook(AddressHookInfo& addressHookInfo) {
    void* targetAddress = addressHookInfo.targetAddress;
    size_t instructionLength = addressHookInfo.originalInstructionLength;
    BYTE* originalBytes = addressHookInfo.originalBytes;
    void* trampolineAddress = addressHookInfo.trampolineAddress;

    if (!originalBytes) {
        return false;
    }

    DWORD oldProtect;
    if (!VirtualProtect(targetAddress, instructionLength, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        DWORD err = GetLastError();
        WriteLog("[HookMgr] Error: VirtualProtect failed (err=%lu)\n", err);
        return false;
    }

    memcpy(targetAddress, originalBytes, instructionLength);
    VirtualProtect(targetAddress, instructionLength, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), targetAddress, instructionLength);

    if (trampolineAddress) {
        RemoveTrampolineBlock(m_trampolineBlocks, trampolineAddress);
        VirtualFree(trampolineAddress, 0, MEM_RELEASE);
        addressHookInfo.trampolineAddress = nullptr;
    }

    delete[] originalBytes;
    addressHookInfo.originalBytes = nullptr;

    return true;
}

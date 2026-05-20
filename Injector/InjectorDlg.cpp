
// InjectorDlg.cpp : implementation file
//

#include "pch.h"
#include "framework.h"
#include "Injector.h"
#include "InjectorDlg.h"
#include "afxdialogex.h"
#include <TlHelp32.h>
#include <psapi.h>
#include <map>
#include "../HookCore/HookConfig.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CInjectorDlg 对话框

CInjectorDlg::CInjectorDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_INJECTOR_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CInjectorDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO_INJECTION_METHOD, m_injectionMethod);
	DDX_Control(pDX, IDC_EDIT_DLL_PATH, m_editDllPath);
	DDX_Control(pDX, IDC_LIST_PROCESS, m_processList);
	DDX_Control(pDX, IDC_CHECK_FUNCTION_HOOK, m_checkFuncHook);
	DDX_Control(pDX, IDC_COMBO_HOOK_DLL, m_comboHookDll);
	DDX_Control(pDX, IDC_COMBO_HOOK_FUNC, m_comboHookFunc);
	DDX_Control(pDX, IDC_CHECK_ADDRESS_HOOK, m_checkAddrHook);
	DDX_Control(pDX, IDC_EDIT_HOOK_ADDRESS, m_editHookAddress);
}

BEGIN_MESSAGE_MAP(CInjectorDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_INJECTOR, &CInjectorDlg::OnBnClickedButtonInjector)
	ON_BN_CLICKED(IDC_BUTTON_SELECT_DLL, &CInjectorDlg::OnBnClickedButtonSelectDll)
	ON_BN_CLICKED(IDC_BUTTON_REFRESH, &CInjectorDlg::OnBnClickedButtonRefresh)
	ON_CBN_SELCHANGE(IDC_COMBO_HOOK_DLL, &CInjectorDlg::OnCbnSelchangeComboHookDll)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST_PROCESS, &CInjectorDlg::OnLvnItemchangedListProcess)
END_MESSAGE_MAP()


// CInjectorDlg 消息处理程序

BOOL CInjectorDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	SetIcon(m_hIcon, TRUE);
	SetIcon(m_hIcon, FALSE);

	SetWindowText(_T("DLL注入器"));

	// 初始化注入方式下拉框
	m_injectionMethod.AddString(_T("远程线程注入"));
	m_injectionMethod.AddString(_T("APC 注入"));
	m_injectionMethod.AddString(_T("SetWindowsHookEx 注入"));
	m_injectionMethod.SetCurSel(0);

	// 初始化进程列表
	InitProcessList();
	RefreshProcessList();

	// Hook 配置默认值
	m_checkFuncHook.SetCheck(BST_UNCHECKED);
	m_checkAddrHook.SetCheck(BST_UNCHECKED);
	SetDlgItemTextW(IDC_EDIT_HOOK_ADDRESS, L"00406E3E");

	return TRUE;
}

void CInjectorDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this);
		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

HCURSOR CInjectorDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

// ========== 进程列表管理 ==========

void CInjectorDlg::InitProcessList()
{
	m_processList.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	m_processList.InsertColumn(0, _T("进程名"), LVCFMT_LEFT, 160);
	m_processList.InsertColumn(1, _T("PID"), LVCFMT_LEFT, 80);
	m_processList.InsertColumn(2, _T("窗口标题"), LVCFMT_LEFT, 180);
}

void CInjectorDlg::RefreshProcessList()
{
	m_processList.DeleteAllItems();

	// 枚举所有顶层窗口，建立 PID -> 窗口标题 映射
	std::map<DWORD, CString> pidToTitle;
	EnumWindows([](HWND hWnd, LPARAM lParam) -> BOOL {
		auto* map = reinterpret_cast<std::map<DWORD, CString>*>(lParam);
		if (!::IsWindowVisible(hWnd)) return TRUE;
		DWORD pid = 0;
		::GetWindowThreadProcessId(hWnd, &pid);
		if (pid == 0) return TRUE;
		if (map->find(pid) != map->end()) return TRUE;
		WCHAR title[256] = {};
		::GetWindowTextW(hWnd, title, 256);
		if (title[0] == L'\0') return TRUE;
		(*map)[pid] = title;
		return TRUE;
	}, reinterpret_cast<LPARAM>(&pidToTitle));

	PROCESSENTRY32W processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
		return;

	if (Process32FirstW(processesSnapshot, &processInfo))
	{
		int index = 0;
		do
		{
			m_processList.InsertItem(index, processInfo.szExeFile);

			CString pidStr;
			pidStr.Format(_T("%lu"), processInfo.th32ProcessID);
			m_processList.SetItemText(index, 1, pidStr);

			auto titleIt = pidToTitle.find(processInfo.th32ProcessID);
			if (titleIt != pidToTitle.end()) {
				m_processList.SetItemText(index, 2, titleIt->second);
			} else {
				m_processList.SetItemText(index, 2, _T(""));
			}

			index++;
		} while (Process32NextW(processesSnapshot, &processInfo));
	}

	CloseHandle(processesSnapshot);
}

DWORD CInjectorDlg::GetSelectedProcessId()
{
	int selectedIndex = m_processList.GetNextItem(-1, LVNI_SELECTED);
	if (selectedIndex == -1)
		return 0;

	CString pidStr = m_processList.GetItemText(selectedIndex, 1);
	return _wtoi(pidStr);
}

DWORD CInjectorDlg::FindProcessId(const std::wstring& processName)
{
	PROCESSENTRY32W processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	std::wstring searchName = processName;
	size_t pos = processName.find_last_of(L"\\/");
	if (pos != std::wstring::npos) {
		searchName = processName.substr(pos + 1);
	}

	Process32FirstW(processesSnapshot, &processInfo);

	do {
		if (!_wcsicmp(processInfo.szExeFile, searchName.c_str())) {
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	} while (Process32NextW(processesSnapshot, &processInfo));

	CloseHandle(processesSnapshot);
	return 0;
}

// ========== 注入操作 ==========

void CInjectorDlg::OnBnClickedButtonInjector()
{
	CString dllPath;
	m_editDllPath.GetWindowText(dllPath);

	if (dllPath.IsEmpty()) {
		MessageBoxA(0, "请先选择动态链接库", "提示", MB_OK | MB_ICONWARNING);
		return;
	}

	if (GetFileAttributesW(dllPath) == INVALID_FILE_ATTRIBUTES) {
		MessageBoxA(0, "DLL 文件不存在!", "错误", MB_OK | MB_ICONERROR);
		return;
	}

	DWORD processId = GetSelectedProcessId();
	if (processId == 0) {
		MessageBoxA(0, "请先在列表中选择一个进程", "提示", MB_OK | MB_ICONWARNING);
		return;
	}

	int injectionMethod = m_injectionMethod.GetCurSel();

	bool success = false;
	if (injectionMethod == 2) {
		// HookEx: config must be written AFTER LoadLibraryW (local load)
		// because DllMain runs during LoadLibraryW and would crash trying
		// to install hooks at target-process-only addresses in the injector.
		success = InjectDLL_SetWindowsHookEx(processId, dllPath);
	} else {
		HANDLE hMapping = nullptr;
		WriteHookConfig(hMapping);

		switch (injectionMethod) {
			case 0:
				success = InjectDLL(processId, dllPath);
				break;
			case 1:
				success = InjectDLL_APC(processId, dllPath);
				break;
			default:
				CloseHookConfig(hMapping);
				MessageBoxA(0, "未知的注入方式", "错误", MB_OK | MB_ICONERROR);
				return;
		}

		CloseHookConfig(hMapping);
	}

	if (success) {
		char successMsg[256];
		sprintf_s(successMsg, "注入成功!\n进程 ID: %lu", processId);
		MessageBoxA(NULL, successMsg, "成功", MB_OK | MB_ICONINFORMATION);
	}
}

void CInjectorDlg::OnBnClickedButtonSelectDll()
{
	CFileDialog dlg(TRUE, NULL, NULL, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT, _T("动态链接库(*.dll)|*.dll|所有文件(*.*)|*.*||"), NULL);
	if (dlg.DoModal() == IDOK)
	{
		SetDlgItemTextW(IDC_EDIT_DLL_PATH, dlg.GetPathName());
	}
}

void CInjectorDlg::OnBnClickedButtonRefresh()
{
	RefreshProcessList();
}

// ========== 注入实现 ==========

bool CInjectorDlg::InjectDLL(DWORD processId, const CString& dllPath)
{
	HANDLE hProcess = OpenProcess(
		PROCESS_CREATE_THREAD |
		PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE |
		PROCESS_VM_READ,
		FALSE,
		processId
	);

	if (hProcess == NULL) {
		DWORD error = GetLastError();
		char errorMsg[256];
		sprintf_s(errorMsg, "无法打开进程! 错误代码: %lu", error);
		MessageBoxA(NULL, errorMsg, "错误", MB_OK | MB_ICONERROR);
		return false;
	}

	SIZE_T dllPathSize = ((wcslen((LPCWSTR)dllPath) + 1) * sizeof(WCHAR));
	LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (remoteMemory == NULL) {
		DWORD error = GetLastError();
		char errorMsg[256];
		sprintf_s(errorMsg, "无法分配远程内存! 错误代码: %lu", error);
		MessageBoxA(NULL, errorMsg, "错误", MB_OK | MB_ICONERROR);
		CloseHandle(hProcess);
		return false;
	}

	if (!WriteProcessMemory(hProcess, remoteMemory, (LPCVOID)(LPCWSTR)dllPath, dllPathSize, NULL)) {
		DWORD error = GetLastError();
		char errorMsg[256];
		sprintf_s(errorMsg, "无法写入远程内存! 错误代码: %lu", error);
		MessageBoxA(NULL, errorMsg, "错误", MB_OK | MB_ICONERROR);
		VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
	if (hKernel32 == NULL) {
		MessageBoxA(NULL, "无法获取 kernel32.dll 句柄!", "错误", MB_OK | MB_ICONERROR);
		VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	LPTHREAD_START_ROUTINE loadLibraryAddr =
		(LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");

	if (loadLibraryAddr == NULL) {
		MessageBoxA(NULL, "无法获取 LoadLibraryW 地址!", "错误", MB_OK | MB_ICONERROR);
		VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, loadLibraryAddr, remoteMemory, 0, NULL);

	if (hRemoteThread == NULL) {
		DWORD error = GetLastError();
		char errorMsg[256];
		sprintf_s(errorMsg, "无法创建远程线程! 错误代码: %lu", error);
		MessageBoxA(NULL, errorMsg, "错误", MB_OK | MB_ICONERROR);
		VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	WaitForSingleObject(hRemoteThread, INFINITE);

	DWORD exitCode;
	GetExitCodeThread(hRemoteThread, &exitCode);

	CloseHandle(hRemoteThread);
	VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
	CloseHandle(hProcess);

	if (exitCode == 0) {
		MessageBoxA(NULL, "DLL 加载失败!", "错误", MB_OK | MB_ICONERROR);
		return false;
	}

	char successMsg[512];
	sprintf_s(successMsg, "DLL 注入成功!\n进程 ID: %lu\nDLL 模块句柄: 0x%08X", processId, exitCode);
	MessageBoxA(NULL, successMsg, "成功", MB_OK | MB_ICONINFORMATION);

	return true;
}

// APC 注入
bool CInjectorDlg::InjectDLL_APC(DWORD processId, const CString& dllPath)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, processId);
	if (!hProcess)
	{
		MessageBoxA(nullptr, "无法打开进程", "错误", MB_OK | MB_ICONERROR);
		return false;
	}

	THREADENTRY32 threadInfo;
	threadInfo.dwSize = sizeof(threadInfo);

	HANDLE threadsSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (threadsSnapshot == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hProcess);
		return false;
	}

	SIZE_T dllPathSize = ((wcslen((LPCWSTR)dllPath) + 1) * sizeof(WCHAR));
	LPVOID remoteMemory = VirtualAllocEx(hProcess, nullptr, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!remoteMemory)
	{
		CloseHandle(threadsSnapshot);
		CloseHandle(hProcess);
		return false;
	}

	WriteProcessMemory(hProcess, remoteMemory, (LPCVOID)(LPCWSTR)dllPath, dllPathSize, nullptr);

	HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
	if (!hKernel32)
	{
		CloseHandle(threadsSnapshot);
		CloseHandle(hProcess);
		MessageBoxA(nullptr, "无法获取 kernel32.dll 句柄", "错误", MB_OK | MB_ICONERROR);
		return false;
	}

	LPTHREAD_START_ROUTINE loadLibraryAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
	if (!loadLibraryAddr)
	{
		CloseHandle(threadsSnapshot);
		CloseHandle(hProcess);
		MessageBoxA(nullptr, "无法获取 LoadLibraryW 地址", "错误", MB_OK | MB_ICONERROR);
		return false;
	}

	bool success = false;
	if (Thread32First(threadsSnapshot, &threadInfo))
	{
		do
		{
			if (threadInfo.th32OwnerProcessID == processId)
			{
				HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadInfo.th32ThreadID);
				if (hThread)
				{
					QueueUserAPC((PAPCFUNC)loadLibraryAddr, hThread, (ULONG_PTR)remoteMemory);
					CloseHandle(hThread);
					success = true;
				}
			}
		} while (Thread32Next(threadsSnapshot, &threadInfo));
	}

	CloseHandle(threadsSnapshot);
	CloseHandle(hProcess);

	if (success)
	{
		MessageBoxA(nullptr, "APC 注入成功（需要等待线程进入可警告状态）", "成功", MB_OK | MB_ICONINFORMATION);
	}
	else
	{
		MessageBoxA(nullptr, "APC 注入失败", "错误", MB_OK | MB_ICONERROR);
	}

	return success;
}

// SetWindowsHookEx 注入
bool CInjectorDlg::InjectDLL_SetWindowsHookEx(DWORD processId, const CString& dllPath)
{
	HMODULE hDll = LoadLibraryW(dllPath);
	if (!hDll) {
		DWORD error = GetLastError();
		char msg[256];
		sprintf_s(msg, "无法加载 DLL，错误代码: %lu", error);
		MessageBoxA(nullptr, msg, "错误", MB_OK | MB_ICONERROR);
		return false;
	}

	HOOKPROC hookProc = (HOOKPROC)GetProcAddress(hDll, "FunHookProc");
	if (!hookProc) {
		MessageBoxA(nullptr, "无法找到 FunHookProc 导出函数", "错误", MB_OK | MB_ICONERROR);
		FreeLibrary(hDll);
		return false;
	}

	THREADENTRY32 threadInfo;
	threadInfo.dwSize = sizeof(threadInfo);
	HANDLE threadsSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (threadsSnapshot == INVALID_HANDLE_VALUE) {
		MessageBoxA(nullptr, "无法枚举线程", "错误", MB_OK | MB_ICONERROR);
		FreeLibrary(hDll);
		return false;
	}

	DWORD targetThreadId = 0;
	if (Thread32First(threadsSnapshot, &threadInfo)) {
		do {
			if (threadInfo.th32OwnerProcessID == processId) {
				targetThreadId = threadInfo.th32ThreadID;
				break;
			}
		} while (Thread32Next(threadsSnapshot, &threadInfo));
	}
	CloseHandle(threadsSnapshot);

	if (targetThreadId == 0) {
		MessageBoxA(nullptr, "未找到目标进程的线程", "错误", MB_OK | MB_ICONERROR);
		FreeLibrary(hDll);
		return false;
	}

	// Write config AFTER local LoadLibraryW (DllMain ran without config, OK)
	// and BEFORE SetWindowsHookExW (DllMain will read config in target process)
	HANDLE hMapping = nullptr;
	WriteHookConfig(hMapping);

	HHOOK hHook = SetWindowsHookExW(WH_GETMESSAGE, hookProc, hDll, targetThreadId);
	if (!hHook) {
		DWORD error = GetLastError();
		char msg[256];
		sprintf_s(msg, "SetWindowsHookEx 失败，错误代码: %lu", error);
		MessageBoxA(nullptr, msg, "错误", MB_OK | MB_ICONERROR);
		CloseHookConfig(hMapping);
		FreeLibrary(hDll);
		return false;
	}

	PostThreadMessageW(targetThreadId, WM_NULL, 0, 0);
	Sleep(100);

	UnhookWindowsHookEx(hHook);
	CloseHookConfig(hMapping);
	FreeLibrary(hDll);

	MessageBoxA(nullptr, "SetWindowsHookEx 注入已触发（等待目标进程处理消息队列）", "成功", MB_OK | MB_ICONINFORMATION);
	return true;
}

// ========== Hook 配置传递 ==========

void CInjectorDlg::WriteHookConfig(HANDLE& hMapping) {
	hMapping = nullptr;

	// 仅当用户勾选了 Hook 选项或配置非空时才创建映射
	bool funcEnabled = (m_checkFuncHook.GetCheck() == BST_CHECKED);
	bool addrEnabled = (m_checkAddrHook.GetCheck() == BST_CHECKED);

	if (!funcEnabled && !addrEnabled) {
		// 创建一个空的"禁用所有 Hook"配置
		HookConfig cfg = {};
		cfg.magic = HOOK_CONFIG_MAGIC;
		cfg.funcHookCount = 0;
		cfg.enableAddressHook = 0;
		hMapping = CreateHookConfigMapping(&cfg);
		return;
	}

	HookConfig cfg = {};
	cfg.magic = HOOK_CONFIG_MAGIC;

	// 函数 Hook
	if (funcEnabled) {
		CString dll, func;
		int sel = m_comboHookDll.GetCurSel();
		if (sel != CB_ERR) m_comboHookDll.GetLBText(sel, dll);
		sel = m_comboHookFunc.GetCurSel();
		if (sel != CB_ERR) m_comboHookFunc.GetLBText(sel, func);
		if (!dll.IsEmpty() && !func.IsEmpty()) {
			wcscpy_s(cfg.funcHooks[0].dllName, dll);
			wcscpy_s(cfg.funcHooks[0].funcName, func);
			cfg.funcHookCount = 1;
		}
	}

	// 地址 Hook
	if (addrEnabled) {
		CString addrStr;
		m_editHookAddress.GetWindowTextW(addrStr);
		if (!addrStr.IsEmpty()) {
			DWORD_PTR addr = 0;
			// 支持 0x 前缀的十六进制
			if (addrStr.GetLength() > 2 && (addrStr[0] == L'0' && (addrStr[1] == L'x' || addrStr[1] == L'X')))
				swscanf_s(addrStr.Mid(2).GetString(), L"%Ix", &addr);
			else
				swscanf_s(addrStr.GetString(), L"%Ix", &addr);
			cfg.enableAddressHook = 1;
			cfg.addressValue = addr;
		}
	}

	hMapping = CreateHookConfigMapping(&cfg);
}

void CInjectorDlg::CloseHookConfig(HANDLE& hMapping) {
	CloseHookConfigMapping(hMapping);
	hMapping = nullptr;
}

// ========== Hook 配置 UI 交互 ==========

void CInjectorDlg::OnCbnSelchangeComboHookDll() {
	int sel = m_comboHookDll.GetCurSel();
	if (sel != CB_ERR && sel < (int)m_modulePaths.size()) {
		PopulateExportList(m_modulePaths[sel]);
	}
}

void CInjectorDlg::OnLvnItemchangedListProcess(NMHDR* pNMHDR, LRESULT* pResult) {
	LPNMLISTVIEW pNMLV = (LPNMLISTVIEW)pNMHDR;
	if ((pNMLV->uChanged & LVIF_STATE) && (pNMLV->uNewState & LVIS_SELECTED)) {
		DWORD pid = GetSelectedProcessId();
		if (pid != 0)
			PopulateModuleList(pid);
	}
	*pResult = 0;
}

// ========== 模块列表填充（目标进程已加载的 DLL）==========

void CInjectorDlg::PopulateModuleList(DWORD pid) {
	m_comboHookDll.ResetContent();
	m_comboHookFunc.ResetContent();
	m_modulePaths.clear();

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (hSnapshot == INVALID_HANDLE_VALUE) return;

	MODULEENTRY32W me = { sizeof(me) };
	if (Module32FirstW(hSnapshot, &me)) {
		do {
			int idx = m_comboHookDll.AddString(me.szModule);
			if (idx >= 0) {
				if (idx >= (int)m_modulePaths.size())
					m_modulePaths.resize(idx + 1);
				m_modulePaths[idx] = me.szExePath;
			}
		} while (Module32NextW(hSnapshot, &me));
	}
	CloseHandle(hSnapshot);
}

// ========== PE 导出表解析 ==========

static DWORD RvaToOffset(BYTE* base, DWORD rva, IMAGE_SECTION_HEADER* sections, WORD numSections) {
	for (WORD i = 0; i < numSections; i++) {
		DWORD secStart = sections[i].VirtualAddress;
		DWORD secEnd   = secStart + sections[i].Misc.VirtualSize;
		if (rva >= secStart && rva < secEnd)
			return rva - secStart + sections[i].PointerToRawData;
	}
	return 0;
}

void CInjectorDlg::PopulateExportList(const CString& modulePath) {
	m_comboHookFunc.ResetContent();

	HANDLE hFile = CreateFileW(modulePath, GENERIC_READ, FILE_SHARE_READ,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) return;

	HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
	CloseHandle(hFile);
	if (!hMapping) return;

	BYTE* base = (BYTE*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	CloseHandle(hMapping);
	if (!base) return;

	// DOS header
	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) { UnmapViewOfFile(base); return; }

	// NT headers
	IMAGE_NT_HEADERS32* nt32 = (IMAGE_NT_HEADERS32*)(base + dos->e_lfanew);
	if (nt32->Signature != IMAGE_NT_SIGNATURE) { UnmapViewOfFile(base); return; }

	DWORD exportRVA = 0;
	IMAGE_SECTION_HEADER* sections = nullptr;
	WORD numSections = 0;

	if (nt32->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
		exportRVA = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		sections = IMAGE_FIRST_SECTION(nt32);
		numSections = nt32->FileHeader.NumberOfSections;
	} else if (nt32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
		IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)nt32;
		exportRVA = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		sections = IMAGE_FIRST_SECTION(nt64);
		numSections = nt64->FileHeader.NumberOfSections;
	}

	if (exportRVA == 0 || numSections == 0) { UnmapViewOfFile(base); return; }

	DWORD exportOffset = RvaToOffset(base, exportRVA, sections, numSections);
	if (exportOffset == 0) { UnmapViewOfFile(base); return; }

	IMAGE_EXPORT_DIRECTORY* expDir = (IMAGE_EXPORT_DIRECTORY*)(base + exportOffset);
	if (expDir->NumberOfNames == 0) { UnmapViewOfFile(base); return; }

	DWORD namesOffset = RvaToOffset(base, expDir->AddressOfNames, sections, numSections);
	DWORD ordsOffset  = RvaToOffset(base, expDir->AddressOfNameOrdinals, sections, numSections);
	if (namesOffset == 0 || ordsOffset == 0) { UnmapViewOfFile(base); return; }

	DWORD* names = (DWORD*)(base + namesOffset);
	WORD*  ords  = (WORD*)(base + ordsOffset);

	for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
		DWORD nameOffset = RvaToOffset(base, names[i], sections, numSections);
		if (nameOffset == 0) continue;

		const char* name = (const char*)(base + nameOffset);

		// 跳过 forwarded exports (RVA 指向另一个导出目录的字符串)
		DWORD funcRVA = 0;
		{
			DWORD funcOffset = RvaToOffset(base,
				expDir->AddressOfFunctions + ords[i] * sizeof(DWORD),
				sections, numSections);
			if (funcOffset) funcRVA = *(DWORD*)(base + funcOffset);
		}
		if (funcRVA >= exportRVA && funcRVA < exportRVA + 0x100000) continue;

		int len = MultiByteToWideChar(CP_ACP, 0, name, -1, nullptr, 0);
		if (len > 1) {
			WCHAR* wname = (WCHAR*)_alloca(len * sizeof(WCHAR));
			MultiByteToWideChar(CP_ACP, 0, name, -1, wname, len);
			m_comboHookFunc.AddString(wname);
		}
	}

	UnmapViewOfFile(base);
}

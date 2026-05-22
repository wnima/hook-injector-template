#include "pch.h"
#include "CICtrlDialog.h"

#define IDI_HOOKCORE 101

// ---- 跨线程通信用全局变量 ----
static HWND   g_hCICtrlDlg    = nullptr;
static HANDLE g_ciThread      = nullptr;
static HANDLE g_ciStopEvent   = nullptr;
static HANDLE g_ciDelayThread = nullptr;

// ============ CICtrlDialog ============

IMPLEMENT_DYNAMIC(CICtrlDialog, CDialog)

CICtrlDialog::CICtrlDialog(CWnd* pParent)
    : CDialog(IDD_CONTROL_INSPECTOR, pParent)
{
}

CICtrlDialog::~CICtrlDialog()
{
}

BEGIN_MESSAGE_MAP(CICtrlDialog, CDialog)
    ON_WM_SIZE()
    ON_WM_DESTROY()
    ON_BN_CLICKED(IDC_CI_REFRESH, &CICtrlDialog::OnBnClickedRefresh)
END_MESSAGE_MAP()

void CICtrlDialog::DoDataExchange(CDataExchange* pDX)
{
    CDialog::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_CI_LIST, m_listCtrl);
}

void CICtrlDialog::FillModuleInfo(ControlInfo& ci)
{
    ci.hModule = (HMODULE)GetWindowLongPtrW(ci.hWnd, GWLP_HINSTANCE);
    if (ci.hModule) {
        WCHAR fullPath[MAX_PATH] = {};
        GetModuleFileNameW(ci.hModule, fullPath, MAX_PATH);
        WCHAR* name = wcsrchr(fullPath, L'\\');
        wcscpy_s(ci.moduleName, name ? name + 1 : fullPath);
    } else {
        wcscpy_s(ci.moduleName, L"-");
    }
}

BOOL CALLBACK CICtrlDialog::EnumChildProc(HWND hChild, LPARAM lParam)
{
    auto* list = reinterpret_cast<std::vector<ControlInfo>*>(lParam);
    ControlInfo ci = {};
    ci.hWnd = hChild;
    ci.hParent = ::GetParent(hChild);
    ::GetClassNameW(hChild, ci.className, 256);
    ::GetWindowTextW(hChild, ci.windowText, 512);
    ::GetWindowRect(hChild, &ci.rect);
    ci.ctrlId = (int)::GetWindowLongW(hChild, GWL_ID);
    ci.style  = (DWORD)::GetWindowLongW(hChild, GWL_STYLE);
    FillModuleInfo(ci);
    list->push_back(ci);
    return TRUE;
}

BOOL CALLBACK CICtrlDialog::EnumTopProc(HWND hWnd, LPARAM lParam)
{
    DWORD pid;
    ::GetWindowThreadProcessId(hWnd, &pid);
    if (pid != ::GetCurrentProcessId()) return TRUE;

    auto* list = reinterpret_cast<std::vector<ControlInfo>*>(lParam);
    ControlInfo ci = {};
    ci.hWnd = hWnd;
    ci.hParent = ::GetParent(hWnd);
    ::GetClassNameW(hWnd, ci.className, 256);
    ::GetWindowTextW(hWnd, ci.windowText, 512);
    ::GetWindowRect(hWnd, &ci.rect);
    ci.ctrlId = (int)::GetWindowLongW(hWnd, GWL_ID);
    ci.style  = (DWORD)::GetWindowLongW(hWnd, GWL_STYLE);
    FillModuleInfo(ci);
    list->push_back(ci);

    ::EnumChildWindows(hWnd, EnumChildProc, lParam);
    return TRUE;
}

void CICtrlDialog::RefreshControlList()
{
    m_listCtrl.DeleteAllItems();
    m_controls.clear();

    EnumWindows(EnumTopProc, reinterpret_cast<LPARAM>(&m_controls));

    WCHAR buf[512];
    for (size_t i = 0; i < m_controls.size(); i++) {
        auto& c = m_controls[i];

        LVITEMW item = {};
        item.mask = LVIF_TEXT;
        item.iItem = (int)i;

        _snwprintf_s(buf, 512, L"0x%p", c.hWnd);
        item.pszText = buf;
        int idx = m_listCtrl.InsertItem(&item);

        _snwprintf_s(buf, 512, L"0x%p", c.hParent);
        m_listCtrl.SetItemText(idx, COL_PARENT, buf);
        m_listCtrl.SetItemText(idx, COL_CLASS, c.className);
        m_listCtrl.SetItemText(idx, COL_TEXT,  c.windowText);
        _snwprintf_s(buf, 512, L"(%d,%d) %dx%d",
            c.rect.left, c.rect.top,
            c.rect.right - c.rect.left, c.rect.bottom - c.rect.top);
        m_listCtrl.SetItemText(idx, COL_RECT, buf);
        _snwprintf_s(buf, 512, L"%d (0x%X)", c.ctrlId, c.ctrlId);
        m_listCtrl.SetItemText(idx, COL_CTRLID, buf);
        _snwprintf_s(buf, 512, L"0x%08X", c.style);
        m_listCtrl.SetItemText(idx, COL_STYLE, buf);
        m_listCtrl.SetItemText(idx, COL_MODULE, c.moduleName);
        _snwprintf_s(buf, 512, L"0x%p", c.hModule);
        m_listCtrl.SetItemText(idx, COL_BASE, buf);
    }
}

BOOL CICtrlDialog::OnInitDialog()
{
    CDialog::OnInitDialog();

    WCHAR exePath[MAX_PATH];
    const WCHAR* procName = L"Unknown";
    if (GetModuleFileNameW(nullptr, exePath, MAX_PATH)) {
        WCHAR* name = wcsrchr(exePath, L'\\');
        procName = name ? name + 1 : exePath;
    }
    WCHAR title[256];
    _snwprintf_s(title, 256, _TRUNCATE, L"控件信息 - %s", procName);
    SetWindowTextW(title);

    HICON hIcon = LoadIconW(AfxGetResourceHandle(), MAKEINTRESOURCEW(IDI_HOOKCORE));
    SetIcon(hIcon, TRUE);
    SetIcon(hIcon, FALSE);

    m_listCtrl.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    const WCHAR* headers[] = {
        L"HWND[句柄]", L"Parent[父句柄]", L"Class", L"Text",
        L"Position[(X,Y) WxH]", L"Ctrl ID[控件ID]", L"Style",
        L"模块", L"基址"
    };
    const int widths[] = { 80, 80, 110, 150, 120, 80, 90, 140, 80 };
    for (int col = 0; col < COL_COUNT; col++) {
        m_listCtrl.InsertColumn(col, headers[col], LVCFMT_LEFT, widths[col]);
    }

    SetWindowPos(nullptr, 0, 0, 960, 520, SWP_NOMOVE | SWP_NOZORDER);

    RefreshControlList();

    g_hCICtrlDlg = m_hWnd;
    return TRUE;
}

void CICtrlDialog::OnSize(UINT nType, int cx, int cy)
{
    CDialog::OnSize(nType, cx, cy);

    if (m_listCtrl.GetSafeHwnd()) {
        m_listCtrl.SetWindowPos(nullptr, 0, 0, cx, cy - 36, SWP_NOZORDER);
    }
    if (GetDlgItem(IDC_CI_REFRESH)) {
        GetDlgItem(IDC_CI_REFRESH)->SetWindowPos(nullptr, 6, cy - 30, 80, 24, SWP_NOZORDER);
    }
}

void CICtrlDialog::OnBnClickedRefresh()
{
    RefreshControlList();
}

void CICtrlDialog::OnDestroy()
{
    g_hCICtrlDlg = nullptr;
    CDialog::OnDestroy();
}

// ============ 线程管理 ============

static DWORD WINAPI CIThreadProc(LPVOID)
{
    AFX_MANAGE_STATE(AfxGetStaticModuleState());

    CICtrlDialog dlg;
    dlg.DoModal();
    return 0;
}

static DWORD WINAPI CIDelayThreadProc(LPVOID)
{
    AFX_MANAGE_STATE(AfxGetStaticModuleState());

    DWORD result = WaitForSingleObject(g_ciStopEvent, 200);
    if (result == WAIT_OBJECT_0) {
        OutputDebugStringA("[HookCore] CI window aborted (DLL unloading)\n");
        return 0;
    }
    g_ciThread = CreateThread(nullptr, 0, CIThreadProc, nullptr, 0, nullptr);
    OutputDebugStringA("[HookCore] Control Inspector dialog created (MFC)\n");
    return 0;
}

void StartCICtrlThread()
{
    g_ciStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_ciDelayThread = CreateThread(nullptr, 0, CIDelayThreadProc, nullptr, 0, nullptr);
}

void StopCICtrlThread()
{
    if (g_ciStopEvent) {
        SetEvent(g_ciStopEvent);
    }
    if (g_ciDelayThread) {
        WaitForSingleObject(g_ciDelayThread, 3000);
        CloseHandle(g_ciDelayThread);
        g_ciDelayThread = nullptr;
    }
    if (g_ciStopEvent) {
        CloseHandle(g_ciStopEvent);
        g_ciStopEvent = nullptr;
    }

    if (g_hCICtrlDlg) {
        ::PostMessageW(g_hCICtrlDlg, WM_CLOSE, 0, 0);
        g_hCICtrlDlg = nullptr;
    }
    if (g_ciThread) {
        WaitForSingleObject(g_ciThread, 3000);
        CloseHandle(g_ciThread);
        g_ciThread = nullptr;
    }
}

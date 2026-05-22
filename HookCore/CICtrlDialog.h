#pragma once
#include <vector>

#define IDD_CONTROL_INSPECTOR   200
#define IDC_CI_LIST             2001
#define IDC_CI_REFRESH          2002

struct ControlInfo {
    HWND hWnd;
    HWND hParent;
    WCHAR className[256];
    WCHAR windowText[512];
    WCHAR moduleName[MAX_PATH];
    HMODULE hModule;
    RECT rect;
    int  ctrlId;
    DWORD style;
};

enum { COL_HWND, COL_PARENT, COL_CLASS, COL_TEXT, COL_RECT, COL_CTRLID, COL_STYLE, COL_MODULE, COL_BASE, COL_COUNT };

class CICtrlDialog : public CDialog
{
    DECLARE_DYNAMIC(CICtrlDialog)

public:
    CICtrlDialog(CWnd* pParent = nullptr);
    virtual ~CICtrlDialog();

    enum { IDD = IDD_CONTROL_INSPECTOR };

protected:
    virtual void DoDataExchange(CDataExchange* pDX) override;
    virtual BOOL OnInitDialog() override;
    afx_msg void OnSize(UINT nType, int cx, int cy);
    afx_msg void OnBnClickedRefresh();
    afx_msg void OnDestroy();
    DECLARE_MESSAGE_MAP()

private:
    CListCtrl m_listCtrl;
    std::vector<ControlInfo> m_controls;

    void RefreshControlList();
    static void FillModuleInfo(ControlInfo& ci);
    static BOOL CALLBACK EnumChildProc(HWND hChild, LPARAM lParam);
    static BOOL CALLBACK EnumTopProc(HWND hWnd, LPARAM lParam);
};

// 线程管理（由 Hooks.cpp 调用）
void StartCICtrlThread();
void StopCICtrlThread();

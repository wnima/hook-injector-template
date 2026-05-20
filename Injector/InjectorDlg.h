// InjectorDlg.h : header file
//

#pragma once
#include "afxdialogex.h"
#include <string>
#include <vector>

class CInjectorDlg : public CDialogEx
{
public:
	CInjectorDlg(CWnd* pParent = nullptr);

#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_INJECTOR_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);

protected:
	HICON m_hIcon;

	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()

public:
	CComboBox m_injectionMethod;
	CEdit m_editDllPath;
	CListCtrl m_processList;
	CButton m_checkFuncHook;
	CComboBox m_comboHookDll;
	CComboBox m_comboHookFunc;
	CButton m_checkAddrHook;
	CEdit   m_editHookAddress;

	afx_msg void OnBnClickedButtonInjector();
	afx_msg void OnBnClickedButtonSelectDll();
	afx_msg void OnBnClickedButtonRefresh();
	afx_msg void OnCbnSelchangeComboHookDll();
	afx_msg void OnLvnItemchangedListProcess(NMHDR* pNMHDR, LRESULT* pResult);

	void InitProcessList();
	void RefreshProcessList();
	DWORD GetSelectedProcessId();
	DWORD FindProcessId(const std::wstring& processName);

	bool InjectDLL(DWORD processId, const CString& dllPath);
	bool InjectDLL_APC(DWORD processId, const CString& dllPath);
	bool InjectDLL_SetWindowsHookEx(DWORD processId, const CString& dllPath);

	void WriteHookConfig(HANDLE& hMapping);
	void CloseHookConfig(HANDLE& hMapping);

	void PopulateModuleList(DWORD pid);
	void PopulateExportList(const CString& modulePath);

private:
	std::vector<CString> m_modulePaths;
};

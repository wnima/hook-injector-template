// ProcessListDlg.h: 进程列表子对话框头文件

#pragma once
#include <string>
#include "afxdialogex.h"

// CProcessListDlg 进程列表子对话框

class CProcessListDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CProcessListDlg)

public:
	CProcessListDlg(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~CProcessListDlg();

	// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_PROCESS_LIST_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持

	DECLARE_MESSAGE_MAP()

public:
	CListCtrl m_processList;

	// 初始化进程列表列
	void InitColumns();

	// 刷新进程列表
	void RefreshProcessList();

	// 获取当前选中进程的 PID
	DWORD GetSelectedProcessId();

	// 获取当前选中行的索引
	int GetSelectedIndex();

	// 通过进程名查找进程 ID
	DWORD FindProcessId(const std::wstring& processName);
};

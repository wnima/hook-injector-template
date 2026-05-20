// ProcessListDlg.cpp: 进程列表子对话框实现文件

#include "pch.h"
#include "framework.h"
#include "Injector.h"
#include "ProcessListDlg.h"
#include <TlHelp32.h>

// CProcessListDlg

IMPLEMENT_DYNAMIC(CProcessListDlg, CDialogEx)

CProcessListDlg::CProcessListDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_PROCESS_LIST_DIALOG, pParent)
{
}

CProcessListDlg::~CProcessListDlg()
{
}

void CProcessListDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_PROCESS, m_processList);
}

BEGIN_MESSAGE_MAP(CProcessListDlg, CDialogEx)
END_MESSAGE_MAP()

// CProcessListDlg 消息处理程序

void CProcessListDlg::InitColumns()
{
	m_processList.InsertColumn(0, _T("进程名"), LVCFMT_LEFT, 130);
	m_processList.InsertColumn(1, _T("PID"), LVCFMT_LEFT, 70);
	m_processList.InsertColumn(2, _T("窗口标题"), LVCFMT_LEFT, 170);
}

void CProcessListDlg::RefreshProcessList()
{
	m_processList.DeleteAllItems();

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

			m_processList.SetItemText(index, 2, _T(""));

			index++;
		} while (Process32NextW(processesSnapshot, &processInfo));
	}

	CloseHandle(processesSnapshot);
}

DWORD CProcessListDlg::GetSelectedProcessId()
{
	int selectedIndex = m_processList.GetNextItem(-1, LVNI_SELECTED);
	if (selectedIndex == -1)
		return 0;

	CString pidStr = m_processList.GetItemText(selectedIndex, 1);
	return _wtoi(pidStr);
}

int CProcessListDlg::GetSelectedIndex()
{
	return m_processList.GetNextItem(-1, LVNI_SELECTED);
}

DWORD CProcessListDlg::FindProcessId(const std::wstring& processName)
{
	PROCESSENTRY32W processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	// 提取文件名（不含路径）
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

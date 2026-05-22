#include "pch.h"
#include "Hooks.h"

class CHookCoreApp : public CWinApp
{
public:
	CHookCoreApp() {}

	virtual BOOL InitInstance() override
	{
		OutputDebugStringA("[HookCore] DLL loaded\n");
		if (InitializeHooks())
		{
			ApplyHookConfiguration();
		}
		CreateControlInspectorWindow();
		return TRUE;
	}

	virtual int ExitInstance() override
	{
		DestroyControlInspectorWindow();
		CleanupHooks();
		OutputDebugStringA("[HookCore] DLL unloaded\n");
		return CWinApp::ExitInstance();
	}
};

CHookCoreApp theApp;

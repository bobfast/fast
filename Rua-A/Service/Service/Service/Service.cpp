#include <afx.h>
#include <afxwin.h>
#include <stdio.h>
#include <winsvc.h>
#include <string>
#define _CRT_SECURE_NO_WARNINGS

static SERVICE_STATUS   g_sStatus;
void ServiceMainFn(DWORD argc, LPTSTR* argv);
void ServiceHandlerFn(DWORD opCode);

DWORD                   g_dwNowState = 0; //현재 상태
SERVICE_STATUS_HANDLE   g_hSrv = 0; //서비스 모듈의 핸들
HANDLE                  g_hExitEvent = 0; //나가기 위핸 핸들
CString nameofservice = "Hooking";
CString nameofdisplay = "HookALL";


void WriteDebug(const char* szDebug)
{
	FILE *fp; 
	fp = fopen("D:\\BoB\\Project_10.03\\log.txt", "at");
	fprintf(fp, szDebug);
	fclose(fp);
}

BOOL InstallService()
{
	SC_HANDLE schService = NULL;
	SC_HANDLE schSCManager = NULL;
	TCHAR szError[MAX_PATH] = { 0, };
	BOOL bRet = FALSE;
	WCHAR szPath[512] = L"D:\BoB\Project_10.03\Detours-master\bin.X64\withdll.exe";
	CString AA= "Explanation";
	if (::GetModuleFileName(NULL, szPath,512) == 0)
	{
		WriteDebug("Unable to install Hooking \n");
		printf("Unable to install Hooking \n");
		return bRet;
	}
	schSCManager = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL != schSCManager)
	{
		schService = ::CreateService(
			schSCManager, // SCManager database
			nameofservice, // name of service
			nameofdisplay, // name to display
			SERVICE_ALL_ACCESS, // desired access
			SERVICE_WIN32_OWN_PROCESS, // service type
			SERVICE_DEMAND_START, // start type
			SERVICE_ERROR_NORMAL, // error control type
			szPath, // service's binary
			NULL, // no load ordering group
			NULL, // no tag identifier  (종속성을 추가해 주는 부분 )
			NULL, // dependencies
			NULL, // LocalSystem account
			NULL); // no password
		if (NULL != schService)
		{
			SERVICE_DESCRIPTION srvdesc = { 0, };
			srvdesc.lpDescription = LPWSTR(*AA);//설명입니다. 하드코딩
			if (FALSE == ::ChangeServiceConfig2(schService, SERVICE_CONFIG_DESCRIPTION, &srvdesc))
			{
				WriteDebug("ChangeServiceConfig2 Error \n");
				printf("ChangeServiceConfig2 Error \n");
				bRet = FALSE;
			}
			printf("Hooking installed \n");
			WriteDebug("Hooking installed \n");
			::CloseServiceHandle(schService);
			bRet = TRUE;
		}
		else
		{
			printf("CreateService failed \n");
			WriteDebug("CreateService failed \n");
			bRet = FALSE;
		}
		::CloseServiceHandle(schSCManager);
	}

	else
	{
		printf("OpenSCManager failed \n");
		WriteDebug("OpenSCManager failed \n");
		bRet = FALSE;
	}

	if (FALSE == bRet)
	{
		return FALSE;
	}
	printf("성공\n");
	return bRet;
}

BOOL RemoveService()
{
	SC_HANDLE schService = NULL;
	SC_HANDLE schSCManager = NULL;
	TCHAR szError[MAX_PATH] = { 0, };
	BOOL bRet = FALSE;
	schSCManager = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL != schSCManager)
	{
		schService = ::OpenService(schSCManager, nameofservice, SERVICE_ALL_ACCESS);
		if (NULL != schService)
		{
			if (TRUE == ::ControlService(schService, SERVICE_CONTROL_STOP, &g_sStatus))
			{
				while (::QueryServiceStatus(schService, &g_sStatus))
				{
					if (g_sStatus.dwCurrentState == SERVICE_STOP_PENDING)
					{
						::Sleep(1000);
					}
					else
					{
						break;
					}
				}

				if (g_sStatus.dwCurrentState == SERVICE_STOPPED)
				{
					WriteDebug("Hooking Stop \n");
					printf("Hooking Stop \n");
					bRet = TRUE;
				}
				else
				{
					WriteDebug("Hooking failed \n");
					printf("Hooking failed \n");
					bRet = FALSE;
				}
			}



			// now remove the service
			if (TRUE == ::DeleteService(schService))
			{
				WriteDebug("Hooking removed \n");
				printf("Hooking removed \n");
				bRet = TRUE;
			}
			else
			{
				WriteDebug("Hooking DeleteService failed \n");
				printf("Hooking DeleteService failed \n");
				bRet = FALSE;
			}
			::CloseServiceHandle(schService);
		}
		else
		{
			WriteDebug("Hooking OpenService failed \n");
			printf("Hooking OpenService failed \n");
			bRet = FALSE;
		}
		::CloseServiceHandle(schSCManager);
	}
	else
	{
		WriteDebug("Hooking OpenSCManager failed \n");
		printf("Hooking OpenSCManager failed \n");
		bRet = FALSE;
	}
	return bRet;
}

BOOL StartServiceProc(WCHAR* ServiceName) {

	CString ErrorString;

	SC_HANDLE SCMhandle = NULL;
	SC_HANDLE OpenSChandle = NULL;
	char log[255];
	SCMhandle = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (SCMhandle == NULL) {
		int Err = GetLastError();
		ErrorString.Format(L"Start OpenSCManager : %d", Err);
		memcpy(log, (char*)(LPCTSTR)log, 255);
		WriteDebug(log);
		return FALSE;
	}

	OpenSChandle = ::OpenService(SCMhandle, ServiceName, SC_MANAGER_ALL_ACCESS);

	if (OpenSChandle == NULL) {
		CloseServiceHandle(SCMhandle);

		int Err = GetLastError();
		ErrorString.Format(L"Start OpenService : %d", Err);
		memcpy(log, (char*)(LPCTSTR)log, 255);
		WriteDebug(log);
		return FALSE;
	}

	BOOL StartResult = ::StartService(OpenSChandle, NULL, NULL);
	int Err = GetLastError();

	if (StartResult == FALSE) {
		CloseServiceHandle(SCMhandle);
		CloseServiceHandle(OpenSChandle);

		int Err = GetLastError();

		if (Err == 1056) {
			return TRUE;
		}
		ErrorString.Format(L"Start StartService : %d", Err);
		memcpy(log, (char*)(LPCTSTR)log, 255);
		WriteDebug(log);
		return FALSE;
	}

	CloseServiceHandle(SCMhandle);
	CloseServiceHandle(OpenSChandle);

	return TRUE;
}

//main
int main(int argc, char* argv[])
{
	SERVICE_TABLE_ENTRY dispatchTable[] =
	{
		{LPWSTR(*nameofservice),(LPSERVICE_MAIN_FUNCTION)ServiceMainFn}, {NULL,NULL}
	};



	if ((argc > 1) && ((*argv[1] == '-') || (*argv[1] == '/')))
	{
		if (_stricmp("install", argv[1] + 1) == 0)
		{
			InstallService();
		}
		else if (_stricmp("start", argv[1] + 1) == 0)
		{
			WCHAR* wszname = T2W(nameofservice.GetBuffer());
			StartServiceProc(wszname);
			nameofservice.ReleaseBuffer();
		}
		else if (_stricmp("start", argv[1] + 1) == 0)
		{
			WCHAR* wszname = T2W(nameofservice.GetBuffer());
			StartServiceProc(wszname);
			nameofservice.ReleaseBuffer();
		}
		else if (_stricmp("remove", argv[1] + 1) == 0)
		{
			RemoveService();
		}
		else
		{
			goto dispatch;
		}
		::exit(0);
	}

	// if it doesn't match any of the above parameters
	// the main control manager may be starting the main
	// so we must call StartServiceCtrlDispatcher

dispatch:
	// this is just to be friendly
	printf("%s -install to install the main\n", "Service");
	printf("%s -remove to remove the main\n", "Service");
	printf("%s -start to start the main\n", "Service");
	printf("\nStartServiceCtrlDispatcher being called.\n");
	printf("This may take several seconds. Please wait.\n");

	if (!StartServiceCtrlDispatcher(dispatchTable))
	{
		WriteDebug("StartServiceCtrlDispatcher failed. \n");
	}
	return 0;
}

void MySetStatus(DWORD dwState, DWORD dwAccept = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE)

{
	SERVICE_STATUS ss;
	ss.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	ss.dwCurrentState = dwState;
	ss.dwControlsAccepted = dwAccept;
	ss.dwWin32ExitCode = 0;
	ss.dwServiceSpecificExitCode = 0;
	ss.dwCheckPoint = 0;
	ss.dwWaitHint = 0;
	// 현재 상태를 보관해 둔다.
	g_dwNowState = dwState;
	SetServiceStatus(g_hSrv, &ss);
}


void ServiceMainFn(DWORD argc, LPTSTR* argv)
{
	// 서비스 핸들러를 등록한다.
	WriteDebug("서비스 시작\n");
	g_hSrv = RegisterServiceCtrlHandler(nameofservice, (LPHANDLER_FUNCTION)ServiceHandlerFn);
	if (g_hSrv == 0)
	{
		return;
	}


	// 서비스가 시작중임을 알린다.
	MySetStatus(SERVICE_START_PENDING);
	g_hExitEvent = CreateEvent(0, FALSE, FALSE, 0);
	ResetEvent(g_hExitEvent);
	CoInitialize(NULL); // COM 컴퍼넌트를 쓰기위한 라리브러리 초기화  ado를 쓰는 넘이라 이거 넣습니다. 필요 없으면 빼셔두
	AfxWinInit(::GetModuleHandle(NULL), NULL, ::GetCommandLine(), 0); //MFC를 쓰기 위한 초기화

	WriteDebug("시작 통보\n");
	// 서비스가 시작되었음을 알린다.
	MySetStatus(SERVICE_RUNNING);

	while (1)
	{
		DWORD dwRet = WaitForMultipleObjects(1, &g_hExitEvent, FALSE, INFINITE); //메인 프로세스가 알아서 하기 때문에 서비스는 정지
		if (dwRet == WAIT_FAILED)
		{
			continue;
		}
		else if (dwRet == WAIT_TIMEOUT)
		{
			continue;
		}
		WriteDebug("서비스 종료\n");
		break;
	}
	CoUninitialize();
	CloseHandle(g_hExitEvent);
	MySetStatus(SERVICE_STOPPED);
}

// 핸들러 함수
void ServiceHandlerFn(DWORD fdwControl)
{
	// 현재 상태와 같은 제어 코드일 경우는 처리할 필요 없다.
	if (fdwControl == g_dwNowState)return;

	switch (fdwControl)
	{
	case SERVICE_CONTROL_STOP:
		MySetStatus(SERVICE_STOP_PENDING, 0);
		SetEvent(g_hExitEvent); //서비스 프로세스를 시그널 시켜 줍니다.
		WriteDebug("종료 메세지\n");
		break;

	default:
		MySetStatus(g_dwNowState);
		break;
	}
}

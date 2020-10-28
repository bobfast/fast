#include<stdio.h>

//#include <atlstr.h>
#include<afxwin.h>
#include<Windows.h>
#include "winsvc.h"
#include <string>

//CREAT
BOOL CreateServiceProc(WCHAR* ServiceName, WCHAR* DisplayName, WCHAR* ExePath) {
	CString ErrorString;
	SC_HANDLE SCMhandle = NULL;
	SC_HANDLE CreateSChandle = NULL;
	SCMhandle = ::OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (SCMhandle == NULL) {
		int Err = GetLastError();
		ErrorString.Format(L"Create OpenSCManager : %d", Err);
		AfxMessageBox(ErrorString);
		return FALSE;
	}
	CreateSChandle = ::CreateService(SCMhandle, ServiceName, DisplayName, SC_MANAGER_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, ExePath, NULL, NULL, NULL, NULL, NULL);
	int Err = GetLastError();

	if (Err == 1073) {
		CloseServiceHandle(SCMhandle);
		return TRUE;
	}
	if (CreateSChandle == NULL) {
		CloseServiceHandle(SCMhandle);
		int Err = GetLastError();
		ErrorString.Format(L"Create CreateService : %d", Err);
		AfxMessageBox(ErrorString);
		return FALSE;
	}
	CloseServiceHandle(SCMhandle);
	CloseServiceHandle(CreateSChandle);
	return TRUE;
}

//START
BOOL StartServiceProc(WCHAR* ServiceName) {

	CString ErrorString;

	SC_HANDLE SCMhandle = NULL;
	SC_HANDLE OpenSChandle = NULL;

	SCMhandle = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (SCMhandle == NULL) {
		int Err = GetLastError();
		ErrorString.Format(L"Start OpenSCManager : %d", Err);
		AfxMessageBox(ErrorString);
		return FALSE;
	}

	OpenSChandle = ::OpenService(SCMhandle, ServiceName, SC_MANAGER_ALL_ACCESS);

	if (OpenSChandle == NULL) {
		CloseServiceHandle(SCMhandle);

		int Err = GetLastError();
		ErrorString.Format(L"Start OpenService : %d", Err);
		AfxMessageBox(ErrorString);
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
		AfxMessageBox(ErrorString);
		return FALSE;
	}

	CloseServiceHandle(SCMhandle);
	CloseServiceHandle(OpenSChandle);

	return TRUE;
}

//STOP
BOOL StopServiceProc(WCHAR* ServiceName) {

	CString ErrorString;

	SC_HANDLE SCMhandle = NULL;
	SC_HANDLE OpenSChandle = NULL;

	SCMhandle = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (SCMhandle == NULL) {
		int Err = GetLastError();
		ErrorString.Format(L"Stop OpenSCManager : %d", Err);
		AfxMessageBox(ErrorString);
		return 0;
	}

	OpenSChandle = ::OpenService(SCMhandle, ServiceName, SERVICE_ALL_ACCESS);

	if (OpenSChandle == NULL) {
		CloseServiceHandle(SCMhandle);

		int Err = GetLastError();
		ErrorString.Format(L"Stop OpenSCManager : %d", Err);
		AfxMessageBox(ErrorString);
		return 0;
	}

	SERVICE_STATUS ss;

	BOOL StatusResult = ::QueryServiceStatus(OpenSChandle, &ss);

	if (StatusResult == FALSE) {
		CloseServiceHandle(SCMhandle);
		CloseServiceHandle(OpenSChandle);

		int Err = GetLastError();
		ErrorString.Format(L"Stop QueryServiceStatus : %d", Err);
		AfxMessageBox(ErrorString);
		return 0;
	}

	if (ss.dwCurrentState != SERVICE_STOPPED) {
		BOOL ControlResult = ::ControlService(OpenSChandle, SERVICE_CONTROL_STOP, &ss);

		if (!ControlResult) {
			CloseServiceHandle(SCMhandle);
			CloseServiceHandle(OpenSChandle);

			int Err = GetLastError();
			ErrorString.Format(L"Stop ControlService : %d", Err);
			AfxMessageBox(ErrorString);
			return 0;
		}
	}

	CloseServiceHandle(SCMhandle);
	CloseServiceHandle(OpenSChandle);

	return TRUE;
}

//DELETE
BOOL DeleteServiceProc(WCHAR* ServiceName) {

	CString ErrorString;

	SC_HANDLE SCMhandle = NULL;
	SC_HANDLE OpenSChandle = NULL;

	SCMhandle = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (SCMhandle == NULL) {
		int Err = GetLastError();
		ErrorString.Format(L"Stop OpenSCManager : %d", Err);
		AfxMessageBox(ErrorString);
		return 0;
	}

	OpenSChandle = ::OpenService(SCMhandle, ServiceName, SERVICE_ALL_ACCESS);

	if (OpenSChandle == NULL) {
		CloseServiceHandle(SCMhandle);

		int Err = GetLastError();
		ErrorString.Format(L"Stop OpenSCManager : %d", Err);
		AfxMessageBox(ErrorString);
		return 0;
	}

	BOOL DeleteResult = ::DeleteService(OpenSChandle);

	if (DeleteResult == FALSE) {
		CloseServiceHandle(SCMhandle);
		CloseServiceHandle(OpenSChandle);

		int Err = GetLastError();
		ErrorString.Format(L"Stop OpenSCManager : %d", Err);
		AfxMessageBox(ErrorString);
		return 0;
	}

	CloseServiceHandle(SCMhandle);
	CloseServiceHandle(OpenSChandle);

	return TRUE;
}

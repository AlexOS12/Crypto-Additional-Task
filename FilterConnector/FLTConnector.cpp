#include "pch.h"
#include "FLTConnector.h"

int test(int a, int b) {
	return a + b;
}

int adjustPrivileges() {
	HANDLE hToken;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		return 1;
	}

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	LookupPrivilegeValue(NULL, SE_LOAD_DRIVER_NAME, &tp.Privileges[0].Luid);

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		CloseHandle(hToken);
		return 2;
	}

	DWORD error = GetLastError();

	if (error != ERROR_SUCCESS) {
		CloseHandle(hToken);
		return 3;
	}

	CloseHandle(hToken);
	return 0;
}

int loadDriver(LPCWSTR driverName) {
	/*HANDLE hToken;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		return 1;
	}

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	LookupPrivilegeValue(NULL, SE_LOAD_DRIVER_NAME, &tp.Privileges[0].Luid);

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		CloseHandle(hToken);
		return 2;
	}

	DWORD error = GetLastError();

	if (error != ERROR_SUCCESS) {
		CloseHandle(hToken);
		return 3;
	}

	CloseHandle(hToken);*/

	if (S_OK == FilterLoad(driverName)) {
		return 0;
	}

	return 4;
}

int unloadDriver(LPCWSTR driverName) {
	/*
	HANDLE hToken;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		return 1;
	}

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	LookupPrivilegeValue(NULL, SE_LOAD_DRIVER_NAME, &tp.Privileges[0].Luid);

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		CloseHandle(hToken);
		return 2;
	}

	DWORD error = GetLastError();

	if (error != ERROR_SUCCESS) {
		CloseHandle(hToken);
		return 3;
	}

	CloseHandle(hToken);
	*/
	if (S_OK == FilterUnload(driverName)) {
		return 0;
	}

	return 4;
}

int connectToDriver(LPCWSTR portName, HANDLE *hPort) {
	HRESULT res = FilterConnectCommunicationPort(portName, 0, NULL, 0, NULL, hPort);
	
	if (res == S_OK) {
		return 0;
	}
	else {
		return -1;
	}
}

int sendMessage(HANDLE hPort) {
	char buffer[48] = "aboba";
	char retBuffer[48] = { 0 };
	DWORD retLen = 0;
	HRESULT res = FilterSendMessage(hPort, buffer, 48, retBuffer, 48, &retLen);

	if (res == S_OK) {
		return 0;
	} else {
		return -1;
	}
}
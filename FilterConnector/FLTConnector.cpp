#include "pch.h"
#include "FLTConnector.h"

int test(int a, int b) {
	return a + b;
}

int loadDriver(LPCWSTR driverName) {
	//���� ������:
	// 0 - ��� ������ �������
	// 1 - �� ������� ������� ����� �������� ��������
	// 2 - �� ������� �������� �����
	// 3 - �� ����� ��������� ���������� ��������� ������
	// 4 - �� ������� ��������� �������


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

	if (S_OK == FilterLoad(driverName)) {
		return 0;
	}

	return 4;
	
}
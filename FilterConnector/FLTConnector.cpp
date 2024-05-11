#include "pch.h"
#include "FLTConnector.h"

int test(int a, int b) {
	return a + b;
}

int loadDriver(LPCWSTR driverName) {
	//Коды ошибок:
	// 0 - Все прошло успешно
	// 1 - Не удалось открыть токен текущего процесса
	// 2 - Не удалось изменить токен
	// 3 - Во время изменения привелегий произошла ошибка
	// 4 - Не удалось загрузить драйвер


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
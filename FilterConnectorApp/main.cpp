#include <stdio.h>
#include <Windows.h>
#include <fltUser.h>
#include <securitybaseapi.h>

HRESULT loadDriver(LPCWSTR drivername) {
	HANDLE hToken;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		printf("Could not open proccess token :(\n");
		exit(-1);
	}

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	LookupPrivilegeValue(NULL, SE_LOAD_DRIVER_NAME, &tp.Privileges[0].Luid);

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		printf("Could not adjust token :(\n");
		CloseHandle(hToken);
		exit(-2);
	}

	DWORD error = GetLastError();

	if (error != ERROR_SUCCESS) {
		printf("Error while adjusting privileges: %u :(\n", error);
		CloseHandle(hToken);
		exit(-3);
	}

	CloseHandle(hToken);

	printf("Privileges successfuly adjusted :)\n");
	printf("Loading driver...\n");

	return FilterLoad(drivername);
}


int main() {
	/*HRESULT	res = NULL;


	res = FilterLoad(L"PassThrough");

	if (res == S_OK) {
		printf("PassThrough successfuly started\n");
	}
	else {
		printf("What happened: %x\n", res);
	}*/

	printf("TOKEN_ADJUST_PRIVILEGES: %d\n", TOKEN_ADJUST_PRIVILEGES);

	printf("What happened: %x\n", loadDriver(L"PassThrough"));

	system("PAUSE");
}
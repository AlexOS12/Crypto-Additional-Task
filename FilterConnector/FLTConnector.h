#ifdef FLTCONNECTOR_EXPORTS
#define FLTCONNECTOR_API __declspec(dllexport)
#else
#define FLTCONNECTOR_API __declspec(dllimport)
#endif

#include "Windows.h"
#include "fltUser.h"

extern "C" {
	FLTCONNECTOR_API int test(int a, int b);
	//���� ������ ��� ������� loadDriver � unloadDriver:
	// 0 - ��� ������ �������
	// 1 - �� ������� ������� ����� �������� ��������
	// 2 - �� ������� �������� �����
	// 3 - �� ����� ��������� ���������� ��������� ������
	// 4 - �� ������� ��������� �������
	FLTCONNECTOR_API int loadDriver(LPCWSTR driverName);
	FLTCONNECTOR_API int unloadDriver(LPCWSTR driverName);
}

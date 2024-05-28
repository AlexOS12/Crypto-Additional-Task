#ifdef FLTCONNECTOR_EXPORTS
#define FLTCONNECTOR_API __declspec(dllexport)
#else
#define FLTCONNECTOR_API __declspec(dllimport)
#endif

#include "Windows.h"
#include "fltUser.h"
#include "FltMessage.h"


extern "C" {
	/// <summary>
	/// ������������ ��� �������� ����������� DLL
	/// </summary>
	/// <param name="a">����� ����� �����</param>
	/// <param name="b">����� ����� �����</param>
	/// <returns>����� ����� a � b</returns>
	FLTCONNECTOR_API int test(int a, int b);
	//���� ������ ��� ������� loadDriver � unloadDriver:
	// 0 - ��� ������ �������
	// 1 - �� ������� ������� ����� �������� ��������
	// 2 - �� ������� �������� �����
	// 3 - �� ����� ��������� ���������� ��������� ������
	// 4 - �� ������� ��������� �������

	/// <summary>
	/// ��������� �������� ���������� �� ������ ���������
	/// </summary>
	/// <returns>0 - ���� �� ������ �������
	/// 1 - ���� �� ������� ������� ����� �������� �������
	/// 2 - ���� �� ������� �������� ���������� ������
	///	3 - ���� �� ����� ��������� ���������� ��������� ������</returns>
	FLTCONNECTOR_API int adjustPrivileges();

	/// <summary>
	/// ��������� ������� �� �����
	/// </summary>
	/// <param name="driverName">��� �������� ��� �������</param>
	/// <returns>0 - ���� �� ������ �������, ����� - 4</returns>
	FLTCONNECTOR_API int loadDriver(LPCWSTR driverName);

	/// <summary>
	/// ��������� ������� �� �����
	/// </summary>
	/// <param name="driverName">��� �������� ��� ��������</param>
	/// <returns>0 - ���� �� ������ �������, ����� - 1</returns>
	FLTCONNECTOR_API int unloadDriver(LPCWSTR driverName);

	/// <summary>
	/// ����������� � �������� ��� ������ �����������
	/// </summary>
	/// <param name="portName">��� �����</param>
	/// <param name="hPort">[OUT] ����� ����� ��� �������</param>
	/// <returns>0 - ���� �� ������ �������, ����� - -1</returns>
	FLTCONNECTOR_API int connectToDriver(LPCWSTR portName, HANDLE *hPort);

	/// <summary>
	/// ���������� ��������� ��������
	/// </summary>
	/// <param name="hPort">����� ����� ��������</param>
	/// <param name="message">��������� ��� ��������</param>
	/// <returns>0 - ���� �� ������ �������, ����� - -1</returns>
	FLTCONNECTOR_API int sendMessage(HANDLE hPort, FltMessage* message);
}


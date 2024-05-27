#ifdef FLTCONNECTOR_EXPORTS
#define FLTCONNECTOR_API __declspec(dllexport)
#else
#define FLTCONNECTOR_API __declspec(dllimport)
#endif

#include "Windows.h"
#include "fltUser.h"
#include "FltMessage.h"


extern "C" {
	FLTCONNECTOR_API int test(int a, int b);
	//Коды ошибок для функций loadDriver и unloadDriver:
	// 0 - Все прошло успешно
	// 1 - Не удалось открыть токен текущего процесса
	// 2 - Не удалось изменить токен
	// 3 - Во время изменения привелегий произошла ошибка
	// 4 - Не удалось загрузить драйвер
	FLTCONNECTOR_API int adjustPrivileges();
	FLTCONNECTOR_API int loadDriver(LPCWSTR driverName);
	FLTCONNECTOR_API int unloadDriver(LPCWSTR driverName);
	FLTCONNECTOR_API int connectToDriver(LPCWSTR portName, HANDLE *hPort);
	FLTCONNECTOR_API int sendMessage(HANDLE hPort, FltMessage* message);
}


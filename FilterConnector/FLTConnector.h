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
	/// Используется для проверки подключения DLL
	/// </summary>
	/// <param name="a">Любое целое число</param>
	/// <param name="b">Любое целое число</param>
	/// <returns>Сумма чисел a и b</returns>
	FLTCONNECTOR_API int test(int a, int b);
	//Коды ошибок для функций loadDriver и unloadDriver:
	// 0 - Все прошло успешно
	// 1 - Не удалось открыть токен текущего процесса
	// 2 - Не удалось изменить токен
	// 3 - Во время изменения привелегий произошла ошибка
	// 4 - Не удалось загрузить драйвер

	/// <summary>
	/// Добавляет процессу привелегию на запуск драйверов
	/// </summary>
	/// <returns>0 - Если всё прошло успешно
	/// 1 - Если не удалось открыть токен текущего процесс
	/// 2 - Если не удалось изменить привелегие токена
	///	3 - Если во время изменения привелегий произошла ошибка</returns>
	FLTCONNECTOR_API int adjustPrivileges();

	/// <summary>
	/// Загружает драйвер по имени
	/// </summary>
	/// <param name="driverName">Имя драйвера для запуска</param>
	/// <returns>0 - Если всё прошло успешно, иначе - 4</returns>
	FLTCONNECTOR_API int loadDriver(LPCWSTR driverName);

	/// <summary>
	/// Выгружает драйвер по имени
	/// </summary>
	/// <param name="driverName">Имя драйвера для выгрузки</param>
	/// <returns>0 - если всё прошло успешно, иначе - 1</returns>
	FLTCONNECTOR_API int unloadDriver(LPCWSTR driverName);

	/// <summary>
	/// Подключение к драйверу для обмена сообщениями
	/// </summary>
	/// <param name="portName">Имя порта</param>
	/// <param name="hPort">[OUT] номер порта для общения</param>
	/// <returns>0 - если всё прошло успешно, иначе - -1</returns>
	FLTCONNECTOR_API int connectToDriver(LPCWSTR portName, HANDLE *hPort);

	/// <summary>
	/// Отправляет сообщение драйверу
	/// </summary>
	/// <param name="hPort">Номер порта драйвера</param>
	/// <param name="message">Сообщение для отправки</param>
	/// <returns>0 - если всё прошло успешно, иначе - -1</returns>
	FLTCONNECTOR_API int sendMessage(HANDLE hPort, FltMessage* message);
}


#ifndef FILTERCONNECTOR_H
#define FILTERCONNECTOR_H

#include <windows.h>
#include <string>
#include <QObject>
#include <QLibrary>
#include <QDir>
#include "FltMessage.h"

/*!
 * \brief The FilterConnector class
 * Класс для управления драйвером
 */
class FilterConnector : public QObject
{
    Q_OBJECT
public:
    FilterConnector();

    QLibrary lib; ///< Подгружаемая библиотека FilterConnector.dll
    HANDLE hPort; ///< Порт драйвера

    /*!
     * \brief testDLL Проверяет, что библиотека была успешно загружена
     * \return true - успех, false - ошибка
     */
    bool testDLL();

    /*!
     * \brief adjustPrivileges
     * Добавляет приложению привелегию на запуск драйверов
     * \return 0 - успех, иначе - ошибка
     */
    int adjustPrivileges();

    /*!
     * \brief loadDriver Загружает драйвер
     * \param driverName Имя драйвера для загрузки
     * \return 0 - успех, иначе - ошибка
     */
    int loadDriver(LPCWSTR driverName);

    /*!
     * \brief unloadDriver Выгружает драйвер
     * \param driverName Имя драйвера для выгрузки
     * \return 0 - успех, иначе - ошибка
     */
    int unloadDriver(LPCWSTR driverName);

    /*!
     * \brief connectToDriver Подключается к драйверу для обмена сообщениями
     * \param portName Имя порта драйвера
     * \return S_OK - успех, иначе - ошибка
     */
    HRESULT connectToDriver(LPCWSTR portName);

    /*!
     * \brief sendMessageToDriver Отправляет сообщения драйверу
     * \param portName Имя порта драйвера
     * \param message Сообщение драйверу
     * \return 0 - успех, иначе - ошибка
     */
    int sendMessageToDriver(LPCWSTR portName, FltMessage *message);
};

#endif // FILTERCONNECTOR_H

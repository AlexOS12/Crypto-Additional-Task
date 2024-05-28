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
 * ����� ��� ���������� ���������
 */
class FilterConnector : public QObject
{
    Q_OBJECT
public:
    FilterConnector();

    QLibrary lib; ///< ������������ ���������� FilterConnector.dll
    HANDLE hPort; ///< ���� ��������

    /*!
     * \brief testDLL ���������, ��� ���������� ���� ������� ���������
     * \return true - �����, false - ������
     */
    bool testDLL();

    /*!
     * \brief adjustPrivileges
     * ��������� ���������� ���������� �� ������ ���������
     * \return 0 - �����, ����� - ������
     */
    int adjustPrivileges();

    /*!
     * \brief loadDriver ��������� �������
     * \param driverName ��� �������� ��� ��������
     * \return 0 - �����, ����� - ������
     */
    int loadDriver(LPCWSTR driverName);

    /*!
     * \brief unloadDriver ��������� �������
     * \param driverName ��� �������� ��� ��������
     * \return 0 - �����, ����� - ������
     */
    int unloadDriver(LPCWSTR driverName);

    /*!
     * \brief connectToDriver ������������ � �������� ��� ������ �����������
     * \param portName ��� ����� ��������
     * \return S_OK - �����, ����� - ������
     */
    HRESULT connectToDriver(LPCWSTR portName);

    /*!
     * \brief sendMessageToDriver ���������� ��������� ��������
     * \param portName ��� ����� ��������
     * \param message ��������� ��������
     * \return 0 - �����, ����� - ������
     */
    int sendMessageToDriver(LPCWSTR portName, FltMessage *message);
};

#endif // FILTERCONNECTOR_H

#ifndef FILTERCONNECTOR_H
#define FILTERCONNECTOR_H

#include <windows.h>
#include <QObject>
#include <QLibrary>
#include <QDir>


class FilterConnector : public QObject
{
    Q_OBJECT
public:
    FilterConnector();

    // QLibrary lib = QLibrary(":/dll/FilterConnector.dll");
    QLibrary lib;
    HANDLE hPort;
    bool testDLL();

    int adjustPrivileges();
    int loadDriver(LPCWSTR driverName);
    int unloadDriver(LPCWSTR driverName);
    HRESULT connectToDriver(LPCWSTR portName);
    int sendMessageToDriver(LPCWSTR portName);
};

#endif // FILTERCONNECTOR_H

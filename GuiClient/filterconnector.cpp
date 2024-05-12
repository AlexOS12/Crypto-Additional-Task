#include "filterconnector.h"

FilterConnector::FilterConnector() {
    QString curDir = QDir::currentPath();
    this->lib.setFileName(curDir + "/FilterConnector.dll");
    qDebug() << curDir + "/FilterConnector.dll";
    lib.load();
    lib.loadHints();
}

bool FilterConnector::testDLL()
{
    typedef int (*testFunction)(int, int);

    testFunction test = (testFunction) lib.resolve("test");

    if (test) {
        int testRes = test(10, 5);
        if (testRes == 15) {
            return true;
        }
    }
    return false;
}

int FilterConnector::loadDriver(LPCWSTR driverName)
{
    typedef int (*loadDriverFunction)(LPCWSTR);

    loadDriverFunction loadDriver = (loadDriverFunction) lib.resolve("loadDriver");

    if (loadDriver) {
        return loadDriver(driverName);
    } else {
        return -1;
    }
}

int FilterConnector::unloadDriver(LPCWSTR driverName)
{
    typedef int (*unloadDriverFunction)(LPCWSTR);

    unloadDriverFunction unloadDriver = (unloadDriverFunction) lib.resolve("unloadDriver");

    if (unloadDriver) {
        return unloadDriver(driverName);
    } else {
        return -1;
    }
}

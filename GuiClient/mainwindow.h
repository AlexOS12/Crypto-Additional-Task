#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <Windows.h>
#include <QIcon>
#include <QString>
#include <QDir>
#include <QFile>
#include <QCryptographicHash>
#include <QSystemTrayIcon>
#include <QAction>
#include <QMenu>
#include <QCloseEvent>

#include "PTSettings.h"
#include "encryptor.h"
#include "filterconnector.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_cancelButton_clicked();

    void on_applyButton_clicked();

    void on_reloadDriverBtn_clicked();

    void trayIconActivated(QSystemTrayIcon::ActivationReason reason);

    void reloadDriverSlot();

    void on_RedButton_clicked();
private:
    bool filterLoaded = false;
    BOOL adminRights = FALSE;
    QString settingsFilePath;
    FilterConnector flt;

    void closeEvent(QCloseEvent *event);

    bool ReadSettings();
    bool WriteSettings();
    bool ReloadDriver();
    bool LoadDriver();
    bool UnloadDriver();

    PTSettings current, old;

    // Ключ может пока временный
    QByteArray key = QCryptographicHash::hash("temp_key", QCryptographicHash::Sha256);
    // Как и IV
    QByteArray iv = QCryptographicHash::hash("temp_iv", QCryptographicHash::Md5);

    Ui::MainWindow *ui;
    BOOL IsAppRunningAsAdminMode();

    QSystemTrayIcon *trayIcon;
    QMenu *trayIconMenu;

    QAction *RestoreAction;
    QAction *CloseAction;
    QAction *ReloadDriverAction;

    void createTrayIcon();
    void createActions();

    void showNotification(QString title, QString text);
};
#endif // MAINWINDOW_H

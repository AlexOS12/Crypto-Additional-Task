#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <Windows.h>
#include <QIcon>
#include <QString>
#include <QDir>
#include <QFile>
#include <QCryptographicHash>

#include "PTSettings.h"
#include "encryptor.h"

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

private:
    BOOL adminRights = FALSE;
    QString settingsFilePath;

    bool ReadSettings();
    bool WriteSettings();

    PTSettings current, old;

    // Ключ может пока временный
    QByteArray key = QCryptographicHash::hash("temp_key", QCryptographicHash::Sha256);
    // Как и IV
    QByteArray iv = QCryptographicHash::hash("temp_iv", QCryptographicHash::Md5);

    Ui::MainWindow *ui;
    BOOL IsAppRunningAsAdminMode();


};
#endif // MAINWINDOW_H

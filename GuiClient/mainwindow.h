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

/*!
 * \brief The MainWindow class
 * ������� ����� ���������
 */
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    /*!
     * \brief on_cancelButton_clicked
     * �������� ���������, ��������� ����� ������� ������ "�������"
     */
    void on_cancelButton_clicked();

    /*!
     * \brief on_applyButton_clicked
     * ���������� ���� � ���������� � ����. ��� ���������� �������� - ���������� ��� ��
     */
    void on_applyButton_clicked();

    /*!
     * \brief trayIconActivated
     * ���������� ��������� ������ ���������� � ����
     * \param �������, �� ������� ������ ���� ������������
     */
    void trayIconActivated(QSystemTrayIcon::ActivationReason reason);

    /*!
     * \brief on_RedButton_clicked
     * ��������� ��� ��������� ������� � ������������ �� ��� �������
     */
    void on_RedButton_clicked();

    /*!
     * \brief redBtnActionEvent
     * �� �� ��� � on_RedButton_cliked, ������ �� ����
     */
    void redBtnActionEvent();

private:
    bool filterLoaded = false; ///< �������� �� ������ �������
    bool appIsStillRunningShown = false; ///< ���� �� �������� ����������� � ������ ���������� � ����
    BOOL adminRights = FALSE; ///< �������� �� ���������� � ������� ��������������
    QString settingsFilePath; ///< ���� �� ����� � �����������
    FilterConnector flt; ///< ����� ������ � �������-��������

    /*!
     * \brief closeEvent ������� ��� �������� ����
     */
    void closeEvent(QCloseEvent *event);

    /*!
     * \brief ReadSettings ������ ��������� �� �����, ���������� � settingFilePath
     * \return true - � ������ ������, ����� - false
     */
    bool ReadSettings();

    /*!
     * \brief WriteSettings ���������� ��������� � ����, ��������� � settingFilePath
     * \return true - � ������ ������, ����� - false
     */
    bool WriteSettings();

    /*!
     * \brief LoadDriver ��������� PassThrough
     * \return true - � ������ ������, ����� - false
     */
    bool LoadDriver();

    /*!
     * \brief UnloadDriver ��������� PassThrough
     * \return true - � ������ ������, ����� - false
     */
    bool UnloadDriver();

    PTSettings current, old; ///< ������� ��������� � ������ ���������

    // ���� ����� ���� ���������
    QByteArray key = QCryptographicHash::hash("temp_key", QCryptographicHash::Sha256);
    // ��� � IV
    QByteArray iv = QCryptographicHash::hash("temp_iv", QCryptographicHash::Md5);

    Ui::MainWindow *ui;

    /*!
     * \brief IsAppRunningAsAdminMode
     * ���������, �������� �� ���������� � ������� ��������������
     * \return TRUE - ���������� �������� � ������� ��������������, ����� FALSE
     */
    BOOL IsAppRunningAsAdminMode();

    QSystemTrayIcon *trayIcon; ///< ������ ���������� � ����
    QMenu *trayIconMenu; ///< ���� ������ � ����

    QAction *RestoreAction; ///< �������� �������������� ����
    QAction *RedButtonAction; ///< �������� �������/���������� ��������
    QAction *CloseAction; ///< �������� �������� ����������

    /*!
     * \brief createTrayIcon ������ ������ � ����
     */
    void createTrayIcon();

    /*!
     * \brief createActions ������ �������� ��� ������
     */
    void createActions();

    /*!
     * \brief showNotification ���������� �����������
     * \param title ��������� �����������
     * \param text  ����� �����������
     */
    void showNotification(QString title, QString text);
};
#endif // MAINWINDOW_H

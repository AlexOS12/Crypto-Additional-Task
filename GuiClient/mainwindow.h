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
 * Основой класс программы
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
     * Отменяет изменения, внесенные после нажатия кнопки "Принять"
     */
    void on_cancelButton_clicked();

    /*!
     * \brief on_applyButton_clicked
     * Записывает ключ и расширение в файл. При запущенном драйвере - отправляет ему их
     */
    void on_applyButton_clicked();

    /*!
     * \brief trayIconActivated
     * Обработчик активации иконки приложения в трее
     * \param Причина, по которой иконка была активирована
     */
    void trayIconActivated(QSystemTrayIcon::ActivationReason reason);

    /*!
     * \brief on_RedButton_clicked
     * Запускает или выгружает драйвер в зависиимости от его статуса
     */
    void on_RedButton_clicked();

    /*!
     * \brief redBtnActionEvent
     * То же что и on_RedButton_cliked, только из трея
     */
    void redBtnActionEvent();

private:
    bool filterLoaded = false; ///< Загружен ли сейчас драйвер
    bool appIsStillRunningShown = false; ///< Было ли показано уведомление о работе приложения в фоне
    BOOL adminRights = FALSE; ///< Запущено ли приложение с правами Администратора
    QString settingsFilePath; ///< Путь до файла с настройками
    FilterConnector flt; ///< Класс работы с драйвер-фильтром

    /*!
     * \brief closeEvent Событие при закрытии окна
     */
    void closeEvent(QCloseEvent *event);

    /*!
     * \brief ReadSettings Читает настройки из файла, указанного в settingFilePath
     * \return true - в случае успеха, иначе - false
     */
    bool ReadSettings();

    /*!
     * \brief WriteSettings Записывает настройки в файл, указанный в settingFilePath
     * \return true - в случае успеха, иначе - false
     */
    bool WriteSettings();

    /*!
     * \brief LoadDriver Загружает PassThrough
     * \return true - в случае успеха, иначе - false
     */
    bool LoadDriver();

    /*!
     * \brief UnloadDriver Выгружает PassThrough
     * \return true - в случае успеха, иначе - false
     */
    bool UnloadDriver();

    PTSettings current, old; ///< Текущие настройки и старые настройки

    // Ключ может пока временный
    QByteArray key = QCryptographicHash::hash("temp_key", QCryptographicHash::Sha256);
    // Как и IV
    QByteArray iv = QCryptographicHash::hash("temp_iv", QCryptographicHash::Md5);

    Ui::MainWindow *ui;

    /*!
     * \brief IsAppRunningAsAdminMode
     * Проверяет, запущено ли приложение с правами Администратора
     * \return TRUE - приложение запущено с правами Администратора, иначе FALSE
     */
    BOOL IsAppRunningAsAdminMode();

    QSystemTrayIcon *trayIcon; ///< Иконка приложения в трее
    QMenu *trayIconMenu; ///< Меню иконки в трее

    QAction *RestoreAction; ///< Действие разворачивания окна
    QAction *RedButtonAction; ///< Действие запуска/отключения драйвера
    QAction *CloseAction; ///< Действие закрытия приложения

    /*!
     * \brief createTrayIcon Создаёт иконку в трее
     */
    void createTrayIcon();

    /*!
     * \brief createActions Создаёт действия для иконки
     */
    void createActions();

    /*!
     * \brief showNotification Отображает уведомление
     * \param title Заголовок уведомления
     * \param text  Текст уведомления
     */
    void showNotification(QString title, QString text);
};
#endif // MAINWINDOW_H

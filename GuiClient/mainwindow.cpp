#include "mainwindow.h"
#include "./ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    adminRights = IsAppRunningAsAdminMode();

    createActions();
    createTrayIcon();

    if (adminRights) {
        setWindowTitle("[ADMIN] PassThrough Settings");
        ui->adminIcoLabel->hide();
        ui->adminStatusLabel->hide();
        ui->RedButton->setIcon(QIcon(":/icons/admin.png"));
        ui->reloadDriverBtn->setIcon(QIcon(":/icons/admin.png"));
        this->trayIcon->setIcon(QIcon(":/icons/admin.png"));
    } else {
        setWindowTitle("PassThrough Settings");
        ui->RedButton->setEnabled(false);
        ui->RedButton->setToolTip("Запустите программу от имени администратора, чтобы выполнить этой действие");
        ui->reloadDriverBtn->setEnabled(false);
        ui->reloadDriverBtn->setToolTip("Запустите программу от имени администратора, чтобы выполнить этой действие");
        this->trayIcon->setIcon(QIcon(":/icons/non_admin.png"));
    }


    trayIcon->show();

    this->settingsFilePath = QDir::homePath() + "/ptsettings.pts";

    if (ReadSettings()) {
        ui->KeyLineEdit->setText(this->current.key);
        ui->ExtensionEdit->setText(this->current.extension);
    }
}

MainWindow::~MainWindow()
{
    delete ui;
}

bool MainWindow::ReadSettings()
{
    QFile file;
    file.setFileName(this->settingsFilePath);

    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return false;
    }

    try {
        QByteArray encrypted = file.readAll();
        QByteArray decrypted;

        Encryptor::getInstance().decrypt(encrypted, decrypted, this->key, this->iv);

        QList<QByteArray> parts = decrypted.split('\n');

        PTSettings sets(parts[0], parts[1]);

        this->current = sets;
        this->old = sets;
    } catch (...) {
        return false;
    }

    return true;

}

bool MainWindow::WriteSettings()
{
    QFile file;
    file.setFileName(this->settingsFilePath);

    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        return false;
    }

    try {
        QByteArray settings = this->current.toString().toUtf8();
        QByteArray encrypted;

        Encryptor::getInstance().encrypt(settings, encrypted, this->key, this->iv);

        file.write(encrypted);
    } catch (...) {
        return false;
    }

    return true;
}

bool MainWindow::ReloadDriver()
{
    // TODO
    // Реализовать перезапуска драйвера тут
    qDebug() << "Imagine driver is reloading...";
    showNotification("Reloading Driver", "Imagine Driver is reloading...");
    return true;
}

bool MainWindow::LoadDriver()
{
    qDebug() << "Imagine driver is loading...";
    showNotification("Driver Loading", "Imagine driver is loading...");
    return true;
}

bool MainWindow::UnloadDriver()
{
    qDebug() << "Imagine driver is unloading...";
    showNotification("Driver Unloading", "Imagine driver is unloading...");
    return true;
}

WINBOOL MainWindow::IsAppRunningAsAdminMode()
{
    BOOL fIsRunAsAdmin = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PSID pAdministratorsGroup = NULL;

    // Allocate and initialize a SID of the administrators group.

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(
            &NtAuthority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &pAdministratorsGroup))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

    // Determine whether the SID of administrators group is enabled in

    // the primary access token of the process.

    if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

Cleanup:
    // Centralized cleanup for all allocated resources.

    if (pAdministratorsGroup)
    {
        FreeSid(pAdministratorsGroup);
        pAdministratorsGroup = NULL;
    }

    // Throw the error if something failed in the function.

    if (ERROR_SUCCESS != dwError)
    {
        throw dwError;
    }

    return fIsRunAsAdmin;
}

void MainWindow::createTrayIcon()
{
    this->trayIcon = new QSystemTrayIcon(this);
    connect(this->trayIcon, &QSystemTrayIcon::activated, this, &MainWindow::trayIconActivated);

    trayIconMenu = new QMenu(this);
    trayIconMenu->addAction(RestoreAction);
    trayIconMenu->addAction(ReloadDriverAction);
    trayIconMenu->addAction(CloseAction);

    trayIcon->setContextMenu(trayIconMenu);

}

void MainWindow::createActions()
{

    this->RestoreAction = new QAction(tr("&Restore"), this);
    connect(RestoreAction, &QAction::triggered, this, &QWidget::showNormal);

    this->ReloadDriverAction = new QAction(tr("&Reload Driver"), this);

    if (this->adminRights) {
        ReloadDriverAction->setIcon(QIcon(":/icons/admin.png"));
    } else {
        ReloadDriverAction->setIcon(QIcon(":/icons/non_admin.png"));
        ReloadDriverAction->setEnabled(false);
    }

    connect(ReloadDriverAction, &QAction::triggered, this, &MainWindow::reloadDriverSlot);

    this->CloseAction = new QAction(tr("&Exit"), this);
    connect(CloseAction, &QAction::triggered, this, &QApplication::exit);
}

void MainWindow::showNotification(QString title, QString text)
{
    this->trayIcon->showMessage(title, text, QIcon(":/icons/admin.png"), 5'000);
}

void MainWindow::on_cancelButton_clicked()
{
    this->current = this->old;
    ui->KeyLineEdit->setText(current.key);
    ui->ExtensionEdit->setText(current.extension);
}


void MainWindow::on_applyButton_clicked()
{
    this->current.key = ui->KeyLineEdit->text();
    this->current.extension = ui->ExtensionEdit->text();

    this->old = current;

    WriteSettings();
}

void MainWindow::on_reloadDriverBtn_clicked()
{
    ReloadDriver();
}

void MainWindow::trayIconActivated(QSystemTrayIcon::ActivationReason reason)
{
    switch (reason) {
    case QSystemTrayIcon::DoubleClick:
        this->show();
        break;
    default:
        break;
    }
}

void MainWindow::reloadDriverSlot()
{
    ReloadDriver();
}


void MainWindow::on_RedButton_clicked()
{
    LoadDriver();
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    showNotification("App is still running", "This app is still running in the background. To access it use tray icon");
}


#include "mainwindow.h"
#include "./ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    adminRights = IsAppRunningAsAdminMode();

    if (adminRights) {
        setWindowTitle("[ADMIN] PassThrough Settings");
        ui->adminIcoLabel->hide();
        ui->adminStatusLabel->hide();
        ui->RedButton->setIcon(QIcon(":/icons/admin.png"));
    } else {
        setWindowTitle("PassThrough Settings");
        ui->RedButton->setEnabled(false);
        ui->RedButton->setToolTip("Запустите программу от имени администратора, чтобы выполнить этой действие");
    }

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
        QString key = file.readLine().trimmed();
        QString extension = file.readLine().trimmed();

        PTSettings sets(key, extension);

        this->current = sets;
        this->old = sets;
    } catch (...) {
        return false;
    }

}

bool MainWindow::WriteSettings()
{
    QFile file;
    file.setFileName(this->settingsFilePath);

    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        return false;
    }

    try {
        file.write((this->current.key + "\n" + this->current.extension).toUtf8());
    } catch (...) {
        return false;
    }
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


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
        this->trayIcon->setIcon(QIcon(":/icons/admin.png"));
    } else {
        setWindowTitle("PassThrough Settings");
        ui->RedButton->setEnabled(false);
        ui->RedButton->setToolTip("Запустите программу от имени администратора, чтобы выполнить этой действие");
        this->trayIcon->setIcon(QIcon(":/icons/non_admin.png"));
    }


    trayIcon->show();

    if (!flt.testDLL()) {
        qDebug() << "Не удалось подключить FLTConnector.dll :(";
        this->showNotification("Ошибка!", "Не удалось загрузить DLL");
    }

    if (this->adminRights) {
        int res = flt.adjustPrivileges();
        if (res != 0) {
            this->showNotification("Не удалось получить права", "Не удалось получить права на управление драйвером. Попробуйте перезапустить приложение. Код ошибки: " + QString::number(res));
        }
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
        QByteArray encrypted = file.readAll();
        QByteArray decrypted;

        Encryptor::getInstance().decrypt(encrypted, decrypted, this->key, this->iv);

        QList<QByteArray> parts = decrypted.split('\n');

        PTSettings sets(parts[0].trimmed(), parts[1].trimmed());

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

bool MainWindow::LoadDriver()
{
    int res = this->flt.loadDriver(L"PassThrough");
    if (res == 0) {
        if (!this->flt.connectToDriver(L"\\PassThrough")) {
            flt.unloadDriver(L"PassThrough");
            this->showNotification("Не удалось подключиться к драйверу", QString::number(res));
            return false;
        }
        QString initKeyHash = QCryptographicHash::hash(this->current.key.toUtf8(), QCryptographicHash::Md5);

        char key[33];

        for (int i = 0; i < initKeyHash.length(); i++)
            key[i] = initKeyHash.at(i).toLatin1();

        wchar_t ext[32] = { 0 };

        this->current.extension.toWCharArray(ext);

        FltMessage initMsg(key, ext);

        if (flt.sendMessageToDriver(L"\\PassThrough", &initMsg) != 0) {
            this->showNotification("Не удалось отправить сообщение", "");
            flt.unloadDriver(L"PassThrough");
            return false;
        }
        this->showNotification("Драйвер успешно загружен", "Драйвер был успешно запущен!");
        this->filterLoaded = true;
        return true;
    } else {
        this->filterLoaded = false;
        return false;
    }
}

bool MainWindow::UnloadDriver()
{
    int res = this->flt.unloadDriver(L"PassThrough");

    if (res == 0) {
        this->showNotification("Драйвер успешно выгружен", "Драйвер был успешно выгружен!");
        this->filterLoaded = false;
        return true;
    } else {
        this->filterLoaded = true;
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

void MainWindow::createTrayIcon()
{
    this->trayIcon = new QSystemTrayIcon(this);
    connect(this->trayIcon, &QSystemTrayIcon::activated, this, &MainWindow::trayIconActivated);

    trayIconMenu = new QMenu(this);
    trayIconMenu->addAction(RestoreAction);
    trayIconMenu->addAction(RedButtonAction);
    trayIconMenu->addAction(CloseAction);

    trayIcon->setContextMenu(trayIconMenu);

}

void MainWindow::createActions()
{
    this->RestoreAction = new QAction(tr("&Развернуть"), this);
    connect(RestoreAction, &QAction::triggered, this, &QWidget::showNormal);

    this->RedButtonAction = new QAction(tr("&Включить драйвер"), this);
    connect(RedButtonAction, &QAction::triggered, this, &MainWindow::redBtnActionEvent);

    if (this->adminRights) {
        RedButtonAction->setIcon(QIcon(":/icons/admin.png"));
    } else {
        RedButtonAction->setIcon(QIcon(":/icons/non_admin.png"));
        RedButtonAction->setEnabled(false);
    }

    this->CloseAction = new QAction(tr("&Выйти"), this);
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

    if (this->filterLoaded) {
        QString currentKeyHash = QCryptographicHash::hash(this->current.key.toUtf8(), QCryptographicHash::Md5);

        char key[33];

        for (int i = 0; i < currentKeyHash.length(); i++)
            key[i] = currentKeyHash.at(i).toLatin1();

        wchar_t ext[32] = { 0 };

        this->current.extension.toWCharArray(ext);

        FltMessage msg(key, ext);
        int res = flt.sendMessageToDriver(L"\\PassThrough", &msg);

        if (!res) {
            this->showNotification("Настройки драйвера Успешно обновлены", "");
        } else {
            this->showNotification("Не удалось обновить настройки драйвера", "Код ошибки: " + QString::number(res));
        }
    }

    WriteSettings();
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


void MainWindow::on_RedButton_clicked()
{
    if (!this->filterLoaded) {
        if (LoadDriver()) {
            this->ui->RedButton->setText("Выключить драйвер");
            this->RedButtonAction->setText("Выключить драйвер");
        }
    } else {
        if (UnloadDriver())
            this->ui->RedButton->setText("Включить драйвер");
            this->RedButtonAction->setText("Включить драйвер");
    }
}

void MainWindow::redBtnActionEvent()
{
    if (!this->filterLoaded) {
        if (this->LoadDriver())
            this->ui->RedButton->setText("Выключить драйвер");
            this->RedButtonAction->setText("Выключить драйвер");
    } else {
        if(this->UnloadDriver())
            this->ui->RedButton->setText("Включить драйвер");
            this->RedButtonAction->setText("Включить драйвер");
    }
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    if (!this->appIsStillRunningShown) {
        showNotification("App is still running", "This app is still running in the background. To access it use tray icon");
        this->appIsStillRunningShown = true;
    }
}


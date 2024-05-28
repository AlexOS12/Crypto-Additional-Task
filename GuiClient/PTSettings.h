#ifndef PTSETTINGS_H
#define PTSETTINGS_H

#include <QString>

/*!
 * \brief The PTSettings struct
 * Структура для хранения настроек
 */
struct PTSettings {
    PTSettings(PTSettings *other) {
        this->key = other->key;
        this->extension = other->extension;
    };

    PTSettings(QString key, QString extension) {
        this->key = key;
        this->extension = extension;
    };

    PTSettings(){};

    /*!
     * \brief toString Преобразует настройки в строку
     * \return Полученная строка
     */
    QString toString() {
        return this->key + "\n" + this->extension;
    }

    QString key;
    QString extension;
};

#endif // PTSETTINGS_H

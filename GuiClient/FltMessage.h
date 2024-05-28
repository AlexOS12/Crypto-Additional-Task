#ifndef FLTMESSAGE_H
#define FLTMESSAGE_H

#include <string>
#include <QByteArray>

/*!
 * \brief Структура сообщения для драйвера
 */
struct FltMessage{
    char key[33]; ///< Ключ для шифрования
    wchar_t extension[32]; ///< Расширения для расшифрования

    FltMessage(char key[33], wchar_t ext[32]) {
        memcpy(this->key, key, 32);
        this->key[32] = '\0';

        wmemcpy(this->extension, ext, 32);
    }
};


#endif // FLTMESSAGE_H

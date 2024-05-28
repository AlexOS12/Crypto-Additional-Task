#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

#include <QByteArray>
#include <QDataStream>
#include <QTextStream>
#include <QIODevice>
#include <QFile>
#include <QDebug>
#include <openssl/evp.h>

///
///  Класс для работы с шифрованием
///
class Encryptor
{
public:
    static Encryptor& getInstance()
    {
        static Encryptor singleton;
        return singleton;
    }

    /*!
     * \brief encrypt Функция шифрования буфера
     * \param in Входной буфер для шифрования
     * \param out Выходной буфер, в который сохраняется результат шифрования
     * \param QBAkey 32-байт ключ для шифрования
     * \param QBAiv 16-байт инициализирующий вектор
     * \return 0 - успех. 1 - ошибка
     */
    int encrypt(QByteArray &in, QByteArray &out, QByteArray QBAkey, QByteArray QBAiv);

    /*!
     * \brief decrypt Функия расшифровки буфера
     * \param in Входной буфер для расшифрования
     * \param out Выходной буфер для расшифрования
     * \param QBAkey 32-байт ключ для расшифровки
     * \param QBAiv 16-байт инициализирующий вектор
     * \return 0 - успех, 1 - ошибка
     */
    int decrypt(QByteArray &in, QByteArray &out, QByteArray QBAkey, QByteArray QBAiv);
private:
    Encryptor(){};
    Encryptor(const Encryptor& root) = delete;
    Encryptor& operator=(const Encryptor&) = delete;
};

#endif // ENCRYPTOR_H

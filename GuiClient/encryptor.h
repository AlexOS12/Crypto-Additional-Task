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
///  ����� ��� ������ � �����������
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
     * \brief encrypt ������� ���������� ������
     * \param in ������� ����� ��� ����������
     * \param out �������� �����, � ������� ����������� ��������� ����������
     * \param QBAkey 32-���� ���� ��� ����������
     * \param QBAiv 16-���� ���������������� ������
     * \return 0 - �����. 1 - ������
     */
    int encrypt(QByteArray &in, QByteArray &out, QByteArray QBAkey, QByteArray QBAiv);

    /*!
     * \brief decrypt ������ ����������� ������
     * \param in ������� ����� ��� �������������
     * \param out �������� ����� ��� �������������
     * \param QBAkey 32-���� ���� ��� �����������
     * \param QBAiv 16-���� ���������������� ������
     * \return 0 - �����, 1 - ������
     */
    int decrypt(QByteArray &in, QByteArray &out, QByteArray QBAkey, QByteArray QBAiv);
private:
    Encryptor(){};
    Encryptor(const Encryptor& root) = delete;
    Encryptor& operator=(const Encryptor&) = delete;
};

#endif // ENCRYPTOR_H

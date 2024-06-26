#ifndef PTSETTINGS_H
#define PTSETTINGS_H

#include <QString>

/*!
 * \brief The PTSettings struct
 * ��������� ��� �������� ��������
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
     * \brief toString ����������� ��������� � ������
     * \return ���������� ������
     */
    QString toString() {
        return this->key + "\n" + this->extension;
    }

    QString key;
    QString extension;
};

#endif // PTSETTINGS_H

#ifndef FLTMESSAGE_H
#define FLTMESSAGE_H

#include <string>

/// <summary>
/// Сообщение, которым клиент обменивается с драйвером
/// </summary>
struct FltMessage{
    char key[33];
    wchar_t extension[32];

    FltMessage(char key[33], wchar_t ext[32]) {
        memcpy(this->key, key, 32);
        //this->key[32] = '\0';

        wmemcpy(this->extension, ext, 32);
    }
};


#endif // FLTMESSAGE_H

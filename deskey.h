#ifndef DESKEY_H
#define DESKEY_H

#include <iostream>
#include "key.h"
#include "desconst.h"

#define DES_ROUND_NUMBER 16

class DesBaseKey : public BaseKey
//реализация интерфейса п. 3.1 для п. 5 задания на лабораторную работу
{
protected:
    void baseExpandKey(const tKey &key, std::vector<tRoundKey> &roundKeyVector);
private:
    std::vector<bool> shiftLeft(const std::vector<bool> &key_28, int shiftNumber);
    std::vector<bool> parityBitDrop(const tKey &key);
    std::vector<bool> compressionPermutation(const std::vector<bool> keyBits_56);
};

#endif // DESKEY_H

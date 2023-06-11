#include <iostream>
#include "key.h"

std::vector<tRoundKey> BaseKey::expandKey(const tKey &key)
//п. 3.1 задания на лабораторную работу
{
    std::vector<tRoundKey> roundKeyVector;
    preExpandKey(key, roundKeyVector);
    baseExpandKey(key, roundKeyVector);
    postExpandKey(key, roundKeyVector);
    return roundKeyVector;
}

void BaseKey::preExpandKey(const tKey &key, std::vector<tRoundKey> &roundKeyVector)
{

}

void BaseKey::postExpandKey(const tKey &key, std::vector<tRoundKey> &roundKeyVector)
{

}

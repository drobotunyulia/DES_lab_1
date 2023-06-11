#ifndef KEY_H
#define KEY_H

#include <vector>
#include <bitset>
#include <algorithm>

typedef std::vector<unsigned char> tKey;
typedef std::vector<unsigned char> tRoundKey;

class BaseKey
//п. 3.1 задания на лабораторную работу
{
public:
    std::vector<tRoundKey> expandKey(const tKey &key);
protected:
    virtual void preExpandKey(const tKey &key, std::vector<tRoundKey> &roundKeyVector);
    virtual void baseExpandKey(const tKey &key, std::vector<tRoundKey> &roundKeyVector) = 0;
    virtual void postExpandKey(const tKey &key, std::vector<tRoundKey> &roundKeyVector);
};

#endif // KEY_H

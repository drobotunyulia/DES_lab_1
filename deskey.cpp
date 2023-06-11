#include "deskey.h"
#include "cipher.h"

void DesBaseKey::baseExpandKey(const tKey &key, std::vector<tRoundKey> &roundKeyVector)
//развертывание ключей для алгоритма DES
{
    roundKeyVector.clear();
    std::vector<bool> keyBits_56 = parityBitDrop(key);
    std::vector<bool> keyBitsLeft_28;
    std::vector<bool> keyBitsRight_28;
    std::vector<bool> keyBits_48;
    keyBitsLeft_28.assign(keyBits_56.begin(), keyBits_56.begin() + 28);
    keyBitsRight_28.assign(keyBits_56.begin() + 28, keyBits_56.end());
    for(int round = 1; round <= DES_ROUND_NUMBER; round++)
    {
        if(round == 1 || round == 2 || round == 9 || round == 16)
        {
            keyBitsLeft_28 = shiftLeft(keyBitsLeft_28, 1);
            keyBitsRight_28 = shiftLeft(keyBitsRight_28, 1);
        }
        else
        {
            keyBitsLeft_28 = shiftLeft(keyBitsLeft_28, 2);
            keyBitsRight_28 = shiftLeft(keyBitsRight_28, 2);
        }
        std::copy(keyBitsLeft_28.begin(), keyBitsLeft_28.end(), keyBits_56.begin());
        std::copy(keyBitsRight_28.begin(), keyBitsRight_28.end(), keyBits_56.end() - 28);
        keyBits_48 = compressionPermutation(keyBits_56);
        tRoundKey resultRoundKey = bitsToBytes(keyBits_48);
        roundKeyVector.push_back(resultRoundKey);
    }
}

std::vector<bool> DesBaseKey::shiftLeft(const std::vector<bool> &key_28, int shiftNumber)
//побитовый сдвиг влево (нужен для развертывания ключей)
{
    std::vector<bool> resultKey_28 = key_28;
    std::rotate(resultKey_28.begin(), resultKey_28.begin() + shiftNumber, resultKey_28.end());
    return resultKey_28;
}

std::vector<bool> DesBaseKey::parityBitDrop(const tKey &key)
//удаление из 64-битного ключа контрольных разрядов (на выходе будем иметь 56-битный ключ)
{
    std::vector<bool> keyBits_64 = bytesToBits(key);
    std::vector<bool> resultKeyBits_56(56);
    for(size_t i = 0; i < DesTable::keyParityBitDropTable.size(); i++)
    {
        resultKeyBits_56[i] = keyBits_64[DesTable::keyParityBitDropTable[i] - 1];
    }
    return resultKeyBits_56;
}

std::vector<bool> DesBaseKey::compressionPermutation(const std::vector<bool> keyBits_56)
//завершающее преобразование ключа (сжатие с 56 до 48 бит)
{
    std::vector<bool> resultKeyBits_48(48);
    for(size_t i = 0; i < DesTable::keyCompressionTable.size(); i++)
    {
        resultKeyBits_48[i] = keyBits_56[DesTable::keyCompressionTable[i] - 1];
    }
    return resultKeyBits_48;
}

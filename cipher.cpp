#include "cipher.h"

tCipherBlock BaseCipher::transform(const tCipherBlock &block, const tRoundKey &roundKey)
//шифрующее преобразование (п. 3.2 задания на лабораторную работу)
{
    tCipherBlock outBlock;
    preTransform(block, roundKey, outBlock);
    baseTransform(outBlock, roundKey, outBlock);
    postTransform(outBlock, roundKey, outBlock);
    return outBlock;
}

void BaseCipher::preTransform(const tCipherBlock &block, const tRoundKey &roundKey, tCipherBlock &outBlock)
{
    outBlock = block;
}

void BaseCipher::postTransform(const tCipherBlock &block, const tRoundKey &roundKey, tCipherBlock &outBlock)
{
    outBlock = block;
}

tCipherBlock SymmetricCipher::encrypt(const tCipherBlock &plainBlock)
//метод шифрования (п. 3.3 задания на лабораторную работу)
{
    tCipherBlock cipherBlock;
    preEncrypt(plainBlock, cipherBlock);
    baseEncrypt(cipherBlock, cipherBlock);
    postEncrypt(cipherBlock, cipherBlock);
    return cipherBlock;
}

void SymmetricCipher::preEncrypt(const tCipherBlock &plainBlock, tCipherBlock &cipherBlock)
{
    cipherBlock = plainBlock;
}

void SymmetricCipher::postEncrypt(const tCipherBlock &plainBlock, tCipherBlock &cipherBlock)
{
    cipherBlock = plainBlock;
}

tCipherBlock SymmetricCipher::decrypt(const tCipherBlock &cipherBlock)
//метод дешифрования (п. 3.3 задания на лабораторную работу)
{
    tCipherBlock plainBlock;
    preDecrypt(cipherBlock, plainBlock);
    baseDecrypt(plainBlock, plainBlock);
    postDecrypt(plainBlock, plainBlock);
    return plainBlock;
}

void SymmetricCipher::preDecrypt(const tCipherBlock &cipherBlock, tCipherBlock &plainBlock)
{
    plainBlock = cipherBlock;
}

void SymmetricCipher::postDecrypt(const tCipherBlock &cipherBlock, tCipherBlock &plainBlock)
{
    plainBlock = cipherBlock;
}

void SymmetricCipher::expandKey(const tKey &key)
//метод настройки раундовых ключей (п. 3.3 задания на лабораторную работу)
{
    preExpandKey(key);
    baseExpandKey(key);
    postExpandKey(key);
}

void SymmetricCipher::preExpandKey(const tKey &key)
{

}

void SymmetricCipher::postExpandKey(const tKey &key)
{

}

FeistelCipher::FeistelCipher(BaseKey &baseKey, BaseCipher &baseCipher) :
    baseKey(baseKey),
    baseCipher(baseCipher)
//конструктор класса, реализующий функционал сети Фейстеля (п. 4 задания на лабораторную работу)
{

}

FeistelCipher::~FeistelCipher()
//деструктор класса, реализующий функционал сети Фейстеля (п. 4 задания на лабораторную работу)
//обнуляет все ключи в памяти
{
    for(size_t i = 0; i < roundKeyVector.size(); i++)
    {
        for(size_t j = 0; j < roundKeyVector[i].size(); j++)
        {
            roundKeyVector[i][j] = 0;
        }
        roundKeyVector[i].clear();
    }
    roundKeyVector.clear();
}

void FeistelCipher::baseEncrypt(const tCipherBlock &plainBlock, tCipherBlock &cipherBlock)
//шифрование для класса, реализующего функционал сети Фейстеля
{
    tCipherBlock leftBlock(plainBlock.begin(), plainBlock.begin() + plainBlock.size() / 2);
    tCipherBlock rightBlock(plainBlock.begin() + plainBlock.size() / 2, plainBlock.end());
    for(size_t i = 0; i < roundKeyVector.size(); i++)
    {
        leftBlock = xorBlocks(baseCipher.transform(rightBlock, roundKeyVector[i]), leftBlock);

        if(i != roundKeyVector.size() - 1)
        {
            leftBlock.swap(rightBlock);
        }
    }
    cipherBlock = mergeBlocks(leftBlock, rightBlock);
}

void FeistelCipher::baseDecrypt(const tCipherBlock &cipherBlock, tCipherBlock &plainBlock)
//дешифрование для класса, реализующего функционал сети Фейстеля
{
    tCipherBlock leftBlock(cipherBlock.begin(), cipherBlock.begin() + cipherBlock.size() / 2);
    tCipherBlock rightBlock(cipherBlock.begin() + cipherBlock.size() / 2, cipherBlock.end());
    for(int i = roundKeyVector.size() - 1; i >= 0; i--)
    {
        leftBlock = xorBlocks(baseCipher.transform(rightBlock, roundKeyVector[i]), leftBlock);

        if(i != 0)
        {
            leftBlock.swap(rightBlock);
        }
    }
    plainBlock = mergeBlocks(leftBlock, rightBlock);
}

void FeistelCipher::baseExpandKey(const tKey &key)
//развертывание ключей для класса, реализующего функционал сети Фейстеля
{
    this->roundKeyVector = baseKey.expandKey(key);
}

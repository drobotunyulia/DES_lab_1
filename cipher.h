#ifndef CIPHER_H
#define CIPHER_H

#include <vector>
#include <string>
#include "key.h"
#include "util.h"

typedef std::vector<unsigned char> tCipherBlock;

tCipherBlock permutationBits(const tCipherBlock &cipherBlock, const tCipherBlock &permutationBlock);
tCipherBlock sBoxTransform(const tCipherBlock &cipherBlock, const std::vector<std::vector<std::vector<unsigned char>>> &sBox, int numBits);

typedef std::vector<unsigned char> tCipherBlock;

class BaseCipher
//п. 3.2 задания на лабораторную работу
{
public:
    tCipherBlock transform(const tCipherBlock &block, const tRoundKey &roundKey);
protected:
    virtual void preTransform(const tCipherBlock &block, const tRoundKey &roundKey, tCipherBlock &outBlock);
    virtual void baseTransform(const tCipherBlock &block, const tRoundKey &roundKey, tCipherBlock &outBlock) = 0;
    virtual void postTransform(const tCipherBlock &block, const tRoundKey &roundKey, tCipherBlock &outBlock);
};

class SymmetricCipher
//п. 3.3 задания на лабораторную работу
{
public:
    tCipherBlock encrypt(const tCipherBlock &plainBlock);
    tCipherBlock decrypt(const tCipherBlock &cipherBlock);
    void expandKey(const tKey &key);
protected:
    virtual void preEncrypt(const tCipherBlock &plainBlock, tCipherBlock &cipherBlock);
    virtual void baseEncrypt(const tCipherBlock &plainBlock, tCipherBlock &cipherBlock) = 0;
    virtual void postEncrypt(const tCipherBlock &plainBlock, tCipherBlock &cipherBlock);

    virtual void preDecrypt(const tCipherBlock &cipherBlock, tCipherBlock &plainBlock);
    virtual void baseDecrypt(const tCipherBlock &cipherBlock, tCipherBlock &plainBlock) = 0;
    virtual void postDecrypt(const tCipherBlock &cipherBlock, tCipherBlock &plainBlock);

    virtual void preExpandKey(const tKey &key);
    virtual void baseExpandKey(const tKey &key) = 0;
    virtual void postExpandKey(const tKey &key);
};

class FeistelCipher : public SymmetricCipher
//п. 4 задания на лабораторную работу
{
public:
    FeistelCipher(BaseKey &baseKey, BaseCipher &baseCipher);
    ~FeistelCipher();
protected:
    void baseEncrypt(const tCipherBlock &plainBlock, tCipherBlock &cipherBlock);
    void baseDecrypt(const tCipherBlock &cipherBlock, tCipherBlock &plainBlock);
    void baseExpandKey(const tKey &key);
private:
    std::vector <tRoundKey> roundKeyVector;
    BaseKey &baseKey;
    BaseCipher &baseCipher;
};

#endif // CIPHER_H

#ifndef DESCIPHER_H
#define DESCIPHER_H

#include "cipher.h"
#include "desconst.h"
#include "deskey.h"

class DesBaseCipher : public BaseCipher
//реализация интерфейса п. 3.2 для п. 5 задания на лабораторную работу
{
protected:
    virtual void baseTransform(const tCipherBlock &block, const tRoundKey &roundKey, tCipherBlock &outBlock);
};

class DesCipher : public FeistelCipher
//п. 5 задания на лабораторную работу
{
public:
    DesCipher(DesBaseKey &desBaseKey, DesBaseCipher &desBaseCipher);
protected:
    virtual void preEncrypt(const tCipherBlock &plainBlock, tCipherBlock &cipherBlock);
    virtual void postEncrypt(const tCipherBlock &plainBlock, tCipherBlock &cipherBlock);
    virtual void preDecrypt(const tCipherBlock &cipherBlock, tCipherBlock &plainBlock);
    virtual void postDecrypt(const tCipherBlock &cipherBlock, tCipherBlock &plainBlock);
};

#endif // DESCIPHER_H

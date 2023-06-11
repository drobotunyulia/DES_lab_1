#ifndef CIPHERMODE_H
#define CIPHERMODE_H

#include <thread>
#include <fstream>
#include "descipher.h"

class CipherMode
//п. 4 задания на лабораторную работу
{
public:
    enum tMode
    {
        ECB,
        CBC,
        CFB,
        OFB,
        CTR,
        RD,
        RDH
    };
    CipherMode(const tKey &key, tMode mode, const std::vector<unsigned char> &initVector = {});
    ~CipherMode();
    size_t encrypt(const std::vector<unsigned char> &plainText, std::vector<unsigned char> &cipherText);
    size_t encrypt(const std::string &plainTextFileName, const std::string &cipherTextFileName);
    size_t decrypt(const std::vector<unsigned char> &cipherText, std::vector<unsigned char> &plainText);
    size_t decrypt(const std::string &cipherTextFileName, const std::string &plainTextFileName);
private:
    std::vector<unsigned char> padding(const std::vector<unsigned char> &text);
    std::vector<unsigned char> unpadding(const std::vector<unsigned char> &text);
    std::vector<unsigned char> longLongIntToBytes(unsigned long long value);
    unsigned long long int bytesToLongLongInt(const std::vector<unsigned char> &block);
    std::vector<unsigned char> longIntToBytes(unsigned long value);
    unsigned long long int bytesToLongInt(const std::vector<unsigned char> &block);
    std::vector<unsigned char> incCounterBlock(const std::vector<unsigned char> &counterBlock, unsigned int step);
    void stripBlock(std::vector<unsigned char> &block, size_t stripNum);
    unsigned long long getHash(const std::vector<unsigned char> &text);

    size_t ecbModeEncrypt(const std::vector<unsigned char> &plainText, std::vector<unsigned char> &cipherText);
    size_t ecbModeDecrypt(const std::vector<unsigned char> &cipherText, std::vector<unsigned char> &plainText);
    size_t cbcModeEncrypt(const std::vector<unsigned char> &plainText, std::vector<unsigned char> &cipherText);
    size_t cbcModeDecrypt(const std::vector<unsigned char> &cipherText, std::vector<unsigned char> &plainText);
    size_t cfbModeEncrypt(const std::vector<unsigned char> &plainText, std::vector<unsigned char> &cipherText);
    size_t cfbModeDecrypt(const std::vector<unsigned char> &cipherText, std::vector<unsigned char> &plainText);
    size_t ofbModeEncrypt(const std::vector<unsigned char> &plainText, std::vector<unsigned char> &cipherText);
    size_t ofbModeDecrypt(const std::vector<unsigned char> &cipherText, std::vector<unsigned char> &plainText);
    size_t ctrModeEncrypt(const std::vector<unsigned char> &plainText, std::vector<unsigned char> &cipherText);
    size_t ctrModeDecrypt(const std::vector<unsigned char> &cipherText, std::vector<unsigned char> &plainText);
    size_t rdModeEncrypt(const std::vector<unsigned char> &plainText, std::vector<unsigned char> &cipherText);
    size_t rdModeDecrypt(const std::vector<unsigned char> &cipherText, std::vector<unsigned char> &plainText);
    size_t rdhModeEncrypt(const std::vector<unsigned char> &plainText, std::vector<unsigned char> &cipherText);
    size_t rdhModeDecrypt(const std::vector<unsigned char> &cipherText, std::vector<unsigned char> &plainText);

    DesBaseCipher desBaseCipher;
    DesBaseKey desBaseKey;
    DesCipher cipher{DesCipher(desBaseKey, desBaseCipher)};
    tMode mode;
    std::vector<unsigned char> initVector;
};

#endif // CIPHERMODE_H

#include "descipher.h"

void DesBaseCipher::baseTransform(const tCipherBlock &block, const tRoundKey &roundKey, tCipherBlock &outBlock)
//переопределение метода шифрующего преобразования для алгоритма DES (п. 5 задания на лаборатрную работу)
{
    tCipherBlock block_48 = permutationBits(block, DesTable::expansionPermutationTable);
    block_48 = xorBlocks(block_48, roundKey);
    outBlock = sBoxTransform(block_48, DesTable::sBox, 6);
    outBlock = permutationBits(outBlock, DesTable::straightPermutationTable);
}

DesCipher::DesCipher(DesBaseKey &desBaseKey, DesBaseCipher &desBaseCipher) : FeistelCipher(desBaseKey, desBaseCipher)
//конструктор класса шифрования по алгоритму DES на базе класса из п. 4 задания на лабораторную работу
//(п. 5 задания на лаборатрную работу)
{

}

//переопределение методов шифрования и дешифрования для реализации алгоритма DES
void DesCipher::preEncrypt(const tCipherBlock &plainBlock, tCipherBlock &cipherBlock)
{
    cipherBlock = permutationBits(plainBlock, DesTable::initPermutationTable);
}

void DesCipher::postEncrypt(const tCipherBlock &plainBlock, tCipherBlock &cipherBlock)
{
    cipherBlock = permutationBits(plainBlock, DesTable::finalPermutationTable);
}

void DesCipher::preDecrypt(const tCipherBlock &cipherBlock, tCipherBlock &plainBlock)
{
    plainBlock = permutationBits(cipherBlock, DesTable::initPermutationTable);
}

void DesCipher::postDecrypt(const tCipherBlock &cipherBlock, tCipherBlock &plainBlock)
{
    plainBlock = permutationBits(cipherBlock, DesTable::finalPermutationTable);
}

#include "util.h"

void printBlock(const std::vector<unsigned char> &block)
//вывод массива байтов на экран
{
    for(size_t i = 0 ; i < block.size(); i++)
    {
        std::cout << std::setfill('0') << std::setw(2) << std::hex << "0x" << static_cast<int>(block[i]) << " ";
    }
    std::cout << std::endl;
}

std::vector<bool> decToBin(long long int value, int numBits)
//перевод десятичного числа в двоичный вид (битовая последовательность)
{
    int bitsCount{0};
    std::vector<bool> result;
    while(value > 0)
    {
        result.push_back(value % 2);
        value /= 2;
        bitsCount++;
    }
    for(int i = 0; i < numBits - bitsCount; i++)
    {
        result.push_back(false);
    }
    std::reverse(result.begin(), result.end());
    return result;
}

long long int binToDec(const std::vector<bool> &binBlock)
//перевод битовой последовательности в десятичное число
{
    long long int result{0};
    int pow_2{1};
    for(int i = binBlock.size() - 1; i >= 0; i--)
    {
        result += static_cast<long long int>(binBlock[i]) ? pow_2 : 0;
        pow_2 *= 2;
    }
    return result;
}

std::vector<unsigned char> xorBlocks(const std::vector<unsigned char> &block_1, const std::vector<unsigned char> &block_2)
//операция xor над двумя массивами байтов
{
    std::vector<unsigned char> result(std::max(block_1.size(), block_2.size()));
    for(size_t i = 0; i < std::min(block_1.size(), block_2.size()); i++)
    {
        result[i] = block_1[i] ^ block_2[i];
    }
    return result;
}

std::vector<bool> bytesToBits(const std::vector<unsigned char> &block)
//перевод массива байтов в битовую последовательность
{
    std::vector<bool> result(block.size() * CHAR_BIT);
    for(size_t i = 0; i < block.size(); i++)
    {
        result[i * CHAR_BIT]     = static_cast<bool>(block[i] & 0b10000000);
        result[i * CHAR_BIT + 1] = static_cast<bool>(block[i] & 0b01000000);
        result[i * CHAR_BIT + 2] = static_cast<bool>(block[i] & 0b00100000);
        result[i * CHAR_BIT + 3] = static_cast<bool>(block[i] & 0b00010000);
        result[i * CHAR_BIT + 4] = static_cast<bool>(block[i] & 0b00001000);
        result[i * CHAR_BIT + 5] = static_cast<bool>(block[i] & 0b00000100);
        result[i * CHAR_BIT + 6] = static_cast<bool>(block[i] & 0b00000010);
        result[i * CHAR_BIT + 7] = static_cast<bool>(block[i] & 0b00000001);
    }
    return result;
}

std::vector<unsigned char> bitsToBytes(const std::vector<bool> &block)
//перевод битовой последовательности в массив байтов
{
    std::vector<unsigned char> result(block.size() / CHAR_BIT);
    for(size_t i = 0; i < result.size(); i++)
    {
        unsigned char byte{0};
        byte = block[i * CHAR_BIT];
        result[i] = result[i] | (byte << 7);
        byte = 0;
        byte = block[i * CHAR_BIT + 1];
        result[i] = result[i] | (byte << 6);
        byte = 0;
        byte = block[i * CHAR_BIT + 2];
        result[i] = result[i] | (byte << 5);
        byte = 0;
        byte = block[i * CHAR_BIT + 3];
        result[i] = result[i] | (byte << 4);
        byte = 0;
        byte = block[i * CHAR_BIT + 4];
        result[i] = result[i] | (byte << 3);
        byte = 0;
        byte = block[i * CHAR_BIT + 5];
        result[i] = result[i] | (byte << 2);
        byte = 0;
        byte = block[i * CHAR_BIT + 6];
        result[i] = result[i] | (byte << 1);
        byte = 0;
        byte = block[i * CHAR_BIT + 7];
        result[i] = result[i] | byte;
    }
    return result;
}

std::pair<int, int> getRowColSBox(const std::vector<bool> &block)
//получение номера строки и колонки в S-box`е
{
    std::vector<bool> internalBlock = block;
    std::pair<int, int> result;
    result.first = 2 * static_cast<int>(*internalBlock.begin()) + static_cast<int>(*(internalBlock.end() - 1));
    internalBlock.erase(internalBlock.begin());
    internalBlock.erase(internalBlock.end());
    result.second = binToDec(internalBlock);
    return result;
}

std::vector<unsigned char> permutationBits(const  std::vector<unsigned char> &block, const  std::vector<unsigned char> &permutationBlock)
//перестановка бит в массиве байтов (п. 1 задания на лабораторную работу)
{
    std::vector<bool> bitsBlock = bytesToBits(block);
    std::vector<bool> bitsOutBlock(permutationBlock.size());
    for(size_t i = 0; i < permutationBlock.size(); i++)
    {
        bitsOutBlock[i] = bitsBlock[permutationBlock[i] - 1];
    }
     std::vector<unsigned char> outBlock = bitsToBytes(bitsOutBlock);
    return outBlock;
}

std::vector<unsigned char> sBoxTransform(const  std::vector<unsigned char> &block, const std::vector<std::vector<std::vector<unsigned char>>> &sBox, int numBits)
//замена группы бит (S-преобразование) (п. 2 задания на лабораторную работу)
{
    std::vector<bool> bitsBlock = bytesToBits(block);
    std::vector<std::vector<bool>> bitsInBlockVector(bitsBlock.size() / numBits);
    std::vector<std::vector<bool>> bitsOutBlockVector(bitsBlock.size() / numBits);
    for(size_t i = 0; i < bitsInBlockVector.size(); i++)
    {
        bitsInBlockVector[i].clear();
        for(int j = 0; j < numBits; j++)
        {
            bitsInBlockVector[i].push_back(bitsBlock[i * numBits + j]);
        }
        int sBoxRow = getRowColSBox(bitsInBlockVector[i]).first;
        int sBoxCol = getRowColSBox(bitsInBlockVector[i]).second;
        bitsOutBlockVector[i] = decToBin(sBox[i][sBoxRow][sBoxCol], numBits - 2);
    }
    bitsBlock.clear();
    for(size_t i = 0; i < bitsOutBlockVector.size(); i++)
    {
        for(size_t j = 0; j < bitsOutBlockVector[i].size(); j++)
        {
            bitsBlock.push_back(bitsOutBlockVector[i][j]);
        }
    }
     std::vector<unsigned char> result = bitsToBytes(bitsBlock);
    return result;
}

std::vector<unsigned char> mergeBlocks(const std::vector<unsigned char> &block_1, const std::vector<unsigned char> &block_2)
//слияние двух массивов байтов
{
    std::vector<unsigned char> result;
    result.insert(result.end(), block_1.begin(), block_1.end());
    result.insert(result.end(), block_2.begin(), block_2.end());
    return result;
}

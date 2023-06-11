#include "ciphermode.h"

CipherMode::CipherMode(const tKey &key, tMode mode, const std::vector<unsigned char> &initVector)
{
    this->mode = mode;
    this->initVector = initVector;
    cipher.expandKey(key);
}

CipherMode::~CipherMode()
{

}

std::vector<unsigned char> CipherMode::padding(const std::vector<unsigned char> &text)
//дополнение недостающих байтов в блоке (паддинг) в соответствии с PKCS7
{
    std::vector<unsigned char> internalText = text;
    size_t paddingNum = 8 - internalText.size() % 8;
    for(size_t i = 0; i < paddingNum; i++)
    {
        internalText.push_back(paddingNum);
    }
    return internalText;
}

std::vector<unsigned char> CipherMode::unpadding(const std::vector<unsigned char> &text)
//отсечение паддинга (примененного на этапе шиырования)
{
    std::vector<unsigned char> internalText = text;
    size_t paddingNum = static_cast<int>(*(internalText.end() - 1));
    for(size_t i = 0; i < paddingNum; i++)
    {
        internalText.erase(internalText.end() - 1);
    }
    return internalText;
}

std::vector<unsigned char> CipherMode::longLongIntToBytes(unsigned long long int value)
//перевод целого числа в байтовый массив длиной 8 байт
{
    std::vector<unsigned char> result(sizeof(unsigned long long int));
    unsigned char *ptrValue = reinterpret_cast<unsigned char*>(&value);
    std::copy(ptrValue, ptrValue + sizeof(unsigned long long int), result.begin());
    std::reverse(result.begin(), result.end());
    return result;
}

unsigned long long int CipherMode::bytesToLongLongInt(const std::vector<unsigned char> &block)
//перевод байтового массива в 64-разрядное число
{
    std::vector<unsigned char> internalBlock = block;
    std::reverse(internalBlock.begin(), internalBlock.end());
    unsigned long long int result{0};
    unsigned char *ptrValue = reinterpret_cast<unsigned char*>(&result);
    std::copy(internalBlock.begin(), internalBlock.end(), ptrValue);
    return result;
}

std::vector<unsigned char> CipherMode::longIntToBytes(unsigned long int value)
//перевод целого числа в байтовый массив длиной 4 байта
{
    std::vector<unsigned char> result(sizeof(unsigned long int));
    unsigned char *ptrValue = reinterpret_cast<unsigned char*>(&value);
    std::copy(ptrValue, ptrValue + sizeof(unsigned long int), result.begin());
    std::reverse(result.begin(), result.end());
    return result;
}

unsigned long long int CipherMode::bytesToLongInt(const std::vector<unsigned char> &block)
//перевод байтового массива в 32-разрядное число
{
    std::vector<unsigned char> internalBlock = block;
    std::reverse(internalBlock.begin(), internalBlock.end());
    unsigned long int result{0};
    unsigned char *ptrValue = reinterpret_cast<unsigned char*>(&result);
    std::copy(internalBlock.begin(), internalBlock.end(), ptrValue);
    return result;
}

std::vector<unsigned char> CipherMode::incCounterBlock(const std::vector<unsigned char> &counterBlock, unsigned int step)
//увеличение числа, представленного в виде массива байтов на величину step
//используется для увеличения счетчика в режимах CTR, RD, RD + H
{
    unsigned long long int value = bytesToLongLongInt(counterBlock);
    value += step;
    return longLongIntToBytes(value);
}

void CipherMode::stripBlock(std::vector<unsigned char> &block, size_t stripNum)
//удаление stripNum байтов в массиве, начиная с конца
//используется в режиме CTR
{
    for(size_t i = 0; i < stripNum; i++)
    {
        block.erase(block.end() - 1);
    }
}

unsigned long long CipherMode::getHash(const std::vector<unsigned char> &text)
//получение хэш-суммы от массива байтов (реализован простейший алгоритм получения суммы всех байтов в массиве)
//используется в режиме RD + H
{
    long long int result{0};
    for(size_t i = 0; i < text.size(); i++)
    {
        result = result + text[i];
    }
    return result;
}

size_t CipherMode::ecbModeEncrypt(const std::vector<unsigned char> &plainText, std::vector<unsigned char> &cipherText)
//зашифровывание массива байтов в режиме ECB
//реализовано параллельное шифрование кажодго блока в отедльности (каждый блок шифруется в отдельном потоке)
{
    size_t blockCount{0};
    std::vector<unsigned char> internalPlainText = padding(plainText);
    size_t blockNum = internalPlainText.size() / 8;
    std::vector<std::thread> blockCipherThreadVector;//в этом массиве хранятся и выполняются потоки
    cipherText.resize(internalPlainText.size());
    for(size_t i = 0; i < blockNum; i++)
    {
        blockCipherThreadVector.push_back(std::thread([this, i, &internalPlainText, &cipherText]()
        {
            //зашифровывание одного блока (выполняется в отдельном потоке)
            std::vector<unsigned char> block(8);
            std::copy(internalPlainText.begin() + 8 * i, internalPlainText.begin() + (8 * i + 8), block.begin());
            block = cipher.encrypt(block);
            std::copy(block.begin(), block.end(), cipherText.begin() + 8 * i);
        }));
    }
    for(auto &thread : blockCipherThreadVector)
    {
        //в этом цикле ждем завершения всех потоков
        blockCount++;
        thread.join();        
    }
    return blockCount;
}

size_t CipherMode::ecbModeDecrypt(const std::vector<unsigned char> &cipherText, std::vector<unsigned char> &plainText)
//расшифровывание массива байтов в режиме ECB
//реализовано параллельное шифрование кажодго блока в отедльности (каждый блок шифруется в отдельном потоке)
{
    size_t blockCount{0};
    std::vector<unsigned char> internalCipherText = cipherText;
    size_t blockNum = internalCipherText.size() / 8;
    std::vector<std::thread> blockCipherThreadVector;//в этом массиве хранятся и выполняются потоки
    plainText.resize(internalCipherText.size());
    for(size_t i = 0; i < blockNum; i++)
    {
        blockCipherThreadVector.push_back(std::thread([this, i, &internalCipherText, &plainText]()
        {
            //расшифровывание одного блока (выполняется в отдельном потоке)
            std::vector<unsigned char> block(8);
            std::copy(internalCipherText.begin() + 8 * i, internalCipherText.begin() + (8 * i + 8), block.begin());
            block = cipher.decrypt(block);
            std::copy(block.begin(), block.end(), plainText.begin() + 8 * i);
        }));
    }
    for(auto &thread : blockCipherThreadVector)
    {
        //в этом цикле ждем завершения всех потоков
        blockCount++;
        thread.join();
    }
    plainText = unpadding(plainText);
    return blockCount;
}

size_t CipherMode::cbcModeEncrypt(const std::vector<unsigned char> &plainText, std::vector<unsigned char> &cipherText)
//засшифровывание массива байтов в режиме CBC
{
    size_t blockCount{0};
    std::vector<unsigned char> internalPlainText = padding(plainText);
    tCipherBlock gamma = initVector;
    cipherText.resize(internalPlainText.size());

    size_t blockNum = internalPlainText.size() / 8;
    for(size_t i = 0; i < blockNum; i++)
    {
        blockCount++;
        std::vector<unsigned char> block(8);
        std::copy(internalPlainText.begin() + 8 * i, internalPlainText.begin() + (8 * i + 8), block.begin());
        block = xorBlocks(block, gamma);
        block = cipher.encrypt(block);
        gamma = block;
        std::copy(block.begin(), block.end(), cipherText.begin() + 8 * i);
    }

    return blockCount;
}

size_t CipherMode::cbcModeDecrypt(const std::vector<unsigned char> &cipherText, std::vector<unsigned char> &plainText)
//расшифровывание массива байтов в режиме CBC
{
    size_t blockCount{0};
    std::vector<unsigned char> internalCipherText = cipherText;
    tCipherBlock gamma = initVector;
    plainText.resize(internalCipherText.size());
    size_t blockNum = internalCipherText.size() / 8;
    for(size_t i = 0; i < blockNum; i++)
    {
        blockCount++;
        std::vector<unsigned char> block(8);
        std::copy(internalCipherText.begin() + 8 * i, internalCipherText.begin() + (8 * i + 8), block.begin());

        tCipherBlock plainBlock = cipher.decrypt(block);
        plainBlock  = xorBlocks(plainBlock, gamma);
        gamma = block;
        std::copy(plainBlock.begin(), plainBlock.end(), plainText.begin() + 8 * i);
    }
    plainText = unpadding(plainText);
    return blockCount;
}

size_t CipherMode::cfbModeEncrypt(const std::vector<unsigned char> &plainText, std::vector<unsigned char> &cipherText)
//зашифровывание массива байтов в режиме CFB
{
    size_t blockCount{0};
    std::vector<unsigned char> internalPlainText = padding(plainText);
    tCipherBlock gamma = initVector;
    cipherText.resize(internalPlainText.size());
    size_t blockNum = internalPlainText.size() / 8;
    for(size_t i = 0; i < blockNum; i++)
    {
        blockCount++;
        std::vector<unsigned char> block(8);
        std::copy(internalPlainText.begin() + 8 * i, internalPlainText.begin() + (8 * i + 8), block.begin());
        gamma = cipher.encrypt(gamma);
        block = xorBlocks(block, gamma);
        gamma = block;
        std::copy(block.begin(), block.end(), cipherText.begin() + 8 * i);
    }
    return blockCount;
}

size_t CipherMode::cfbModeDecrypt(const std::vector<unsigned char> &cipherText, std::vector<unsigned char> &plainText)
//расшифровывание массива байтов в режиме CFB
{
    size_t blockCount{0};
    std::vector<unsigned char> internalCipherText = cipherText;
    tCipherBlock gamma = initVector;
    plainText.resize(internalCipherText.size());
    size_t blockNum = internalCipherText.size() / 8;
    for(size_t i = 0; i < blockNum; i++)
    {
        blockCount++;
        std::vector<unsigned char> block(8);
        std::copy(internalCipherText.begin() + 8 * i, internalCipherText.begin() + (8 * i + 8), block.begin());
        gamma = cipher.encrypt(gamma);
        tCipherBlock plainBlock  = xorBlocks(block, gamma);
        gamma = block;
        std::copy(plainBlock.begin(), plainBlock.end(), plainText.begin() + 8 * i);
    }
    plainText = unpadding(plainText);
    return blockCount;
}

size_t CipherMode::ofbModeEncrypt(const std::vector<unsigned char> &plainText, std::vector<unsigned char> &cipherText)
//зашифровывание массива байтов в режиме OFB
{
    size_t blockCount{0};
    std::vector<unsigned char> internalPlainText = padding(plainText);

    cipherText.resize(internalPlainText.size());
    std::vector<unsigned char>gamma = initVector;
    size_t blockNum = internalPlainText.size() / 8;
    for(size_t i = 0; i < blockNum; i++)
    {
        blockCount++;
        std::vector<unsigned char> block(8);
        gamma = cipher.encrypt(gamma);
        std::copy(internalPlainText.begin() + 8 * i, internalPlainText.begin() + (8 * i + 8), block.begin());
        block = xorBlocks(block, gamma);
        std::copy(block.begin(), block.end(), cipherText.begin() + 8 * i);
    }
    return blockCount;
}

size_t CipherMode::ofbModeDecrypt(const std::vector<unsigned char> &cipherText, std::vector<unsigned char> &plainText)
//расшифровывание массива байтов в режиме OFB
{
    size_t blockCount{0};
    std::vector<unsigned char> internalCipherText = cipherText;
    size_t blockNum = internalCipherText.size() / 8;
    plainText.resize(internalCipherText.size());
    std::vector<unsigned char>gamma = initVector;
    for(size_t i = 0; i < blockNum; i++)
    {
        blockCount++;
        std::vector<unsigned char> block(8);
        gamma = cipher.encrypt(gamma);
        std::copy(internalCipherText.begin() + 8 * i, internalCipherText.begin() + (8 * i + 8), block.begin());
        block = xorBlocks(block, gamma);
        std::copy(block.begin(), block.end(), plainText.begin() + 8 * i);
    }
    plainText = unpadding(plainText);
    return blockCount;
}

size_t CipherMode::ctrModeEncrypt(const std::vector<unsigned char> &plainText, std::vector<unsigned char> &cipherText)
//зашифровывание массива байтов в режиме CTR
//реализовано параллельное шифрование кажодго блока в отедльности (каждый блок шифруется в отдельном потоке)
{
    size_t blockCount{0};
    std::vector<unsigned char> internalPlainText = plainText;
    size_t blockNum = internalPlainText.size() / 8;
    cipherText.resize(internalPlainText.size());
    std::vector<unsigned char> counter = this->initVector;
    //дополняем счетчик (counter) четырьмя нулями
    for(size_t i = 0; i < 4; i++)
    {
        counter.push_back(0);
    }
    std::vector<std::thread> blockCipherThreadVector;//в этом массиве хранятся и выполняются потоки
    for(size_t i = 0; i < blockNum; i++)
    {
        blockCipherThreadVector.push_back(std::thread([this, i, &internalPlainText, &cipherText, &counter, &blockCount]()
        {
            //зашифровывание одного блока (выполняется в отдельном потоке)
            std::vector<unsigned char> block(8);
            std::vector<unsigned char>gamma = incCounterBlock(counter, i);//увеличиваем значение счетчика для шифрования очередного блока
            gamma = cipher.encrypt(gamma);
            std::copy(internalPlainText.begin() + 8 * i, internalPlainText.begin() + (8 * i + 8), block.begin());
            block = xorBlocks(block, gamma);
            std::copy(block.begin(), block.end(), cipherText.begin() + 8 * i);
            if(internalPlainText.size() % 8 != 0 && i == ((internalPlainText.size() / 8) - 1))
            {
                //шифруем последний неполный блок (если он есть)
                block.resize(internalPlainText.size() % 8);
                incCounterBlock(counter, 1);
                gamma = cipher.encrypt(counter);
                std::copy(internalPlainText.begin() + (8 * i + 8), internalPlainText.end(), block.begin());
                this->stripBlock(gamma, 8 - (internalPlainText.size() % 8));
                block = xorBlocks(block, gamma);
                std::copy(block.begin(), block.end(), cipherText.begin() + (8 * i + 8));
                blockCount++;
            }
        }));
    }
    for(auto &thread : blockCipherThreadVector)
    {
        //в этом цикле ждем завершения всех потоков
        blockCount++;
        thread.join();
    }
    return blockCount;
}

size_t CipherMode::ctrModeDecrypt(const std::vector<unsigned char> &cipherText, std::vector<unsigned char> &plainText)
//расшифровывание массива байтов в режиме CTR (операции зашифровывания и расшифровывания в режиме CTR одинаковые)
{
    return this->ctrModeEncrypt(cipherText, plainText);
}

size_t CipherMode::rdModeEncrypt(const std::vector<unsigned char> &plainText, std::vector<unsigned char> &cipherText)
//зашифровывание массива байтов в режиме RD
//реализовано параллельное шифрование кажодго блока в отедльности (каждый блок шифруется в отдельном потоке)
{
    std::vector<unsigned char> randomDeltaBytes;
    std::srand(std::time(nullptr));
    //получаем массив случайных байтов длиной 4 байта
    for(size_t i = 0; i < 4; i++)
    {
        randomDeltaBytes.push_back(std::rand() % 0xff);
    }
    unsigned int randomDelta = bytesToLongInt(randomDeltaBytes);//переводим массив из 4-х байтов в число
    std::vector<unsigned char> counter = randomDeltaBytes;//this->longIntToBytes(randomDelta);
    std::vector<unsigned char> zeroBlock(4, 0);
    counter.insert(counter.begin(), zeroBlock.begin(), zeroBlock.end());//дополняем массив counter 4-мя нулями
    tCipherBlock startBlock = cipher.encrypt(counter);//шифруем значение счетчика для формирования первого блока зашифрованного сообщения
    size_t blockCount{0};
    std::vector<unsigned char> internalPlainText = padding(plainText);
    size_t blockNum = internalPlainText.size() / 8;
    cipherText.resize(internalPlainText.size());
    std::vector<std::thread> blockCipherThreadVector;//в этом массиве хранятся и выполняются потоки
    for(size_t i = 0; i < blockNum; i++)
    {
        blockCipherThreadVector.push_back(std::thread([this, i, &internalPlainText, &cipherText, &counter, randomDelta]()
        {
            //зашифровывание одного блока (выполняется в отдельном потоке)
            std::vector<unsigned char> gamma = counter;
            gamma = incCounterBlock(counter, randomDelta * i);//увеличиваем значение gamma на randomDelta для зашифровывания каждого блока
            std::vector<unsigned char> block(8);
            std::copy(internalPlainText.begin() + 8 * i, internalPlainText.begin() + (8 * i + 8), block.begin());
            block = xorBlocks(block, gamma);
            block = cipher.encrypt(block);
            std::copy(block.begin(), block.end(), cipherText.begin() + 8 * i);
        }));
    }
    for(auto &thread : blockCipherThreadVector)
    {
        //в этом цикле ждем завершения всех потоков
        blockCount++;
        thread.join();
    }
    cipherText.insert(cipherText.begin(), startBlock.begin(), startBlock.end());//вставляем в начало зашифрованного сообщения первый блок
                                                                                //с зашифрованным начальным значением counter
    return blockCount;
}

size_t CipherMode::rdModeDecrypt(const std::vector<unsigned char> &cipherText, std::vector<unsigned char> &plainText)
//расшифровывание массива байтов в режиме RD
//реализовано параллельное шифрование кажодго блока в отедльности (каждый блок шифруется в отдельном потоке)
{
    std::vector<unsigned char> internalCipherText = cipherText;
    tCipherBlock startBlock(8);
    std::copy(internalCipherText.begin(), internalCipherText.begin() + 8, startBlock.begin());
    startBlock = cipher.decrypt(startBlock);//расшифровываем первый блок с начальным значением counter
    std::vector<unsigned char> counter = startBlock;
    startBlock.erase(startBlock.begin(), startBlock.begin() + 4);
    unsigned int randomDelta = bytesToLongInt(startBlock);//переводим counter в число randomDelta
    internalCipherText.erase(internalCipherText.begin(), internalCipherText.begin() + 8);
    size_t blockNum = internalCipherText.size() / 8;
    plainText.resize(internalCipherText.size());
    size_t blockCount{0};
    std::vector<std::thread> blockCipherThreadVector;//в этом массиве хранятся и выполняются потоки
    for(size_t i = 0; i < blockNum; i++)
    {
        blockCipherThreadVector.push_back(std::thread([this, i, &internalCipherText, &plainText, &counter, randomDelta]()
        {
            //расшифровывание одного блока (выполняется в отдельном потоке)
            std::vector<unsigned char> gamma = counter;
            gamma = incCounterBlock(counter, randomDelta * i);//увеличиваем значение gamma на randomDelta для расшифровывания каждого блока
            std::vector<unsigned char> block(8);
            std::copy(internalCipherText.begin() + 8 * i, internalCipherText.begin() + (8 * i + 8), block.begin());
            block = cipher.decrypt(block);
            block = xorBlocks(block, gamma);
            std::copy(block.begin(), block.end(), plainText.begin() + 8 * i);
        }));
    }
    for(auto &thread : blockCipherThreadVector)
    {
        //в этом цикле ждем завершения всех потоков
        blockCount++;
        thread.join();
    }
    plainText = unpadding(plainText);
    return blockCount;
}

size_t CipherMode::rdhModeEncrypt(const std::vector<unsigned char> &plainText, std::vector<unsigned char> &cipherText)
//зашифровывание массива байтов в режиме RD + H (аналогично режиму RD, только еще добавляем в начало зашифрованного сообщения
//шифрованное значение хэш-суммы)
//реализовано параллельное шифрование кажодго блока в отедльности (каждый блок шифруется в отдельном потоке)
{
    std::vector<unsigned char> randomDeltaBytes;
    std::srand(std::time(nullptr));
    for(size_t i = 0; i < 4; i++)
    {
        randomDeltaBytes.push_back(std::rand() % 0xff);
    }
    unsigned int randomDelta = bytesToLongInt(randomDeltaBytes);

    std::vector<unsigned char> counter = this->longIntToBytes(randomDelta);
    std::vector<unsigned char> zeroBlock(4, 0);
    counter.insert(counter.begin(), zeroBlock.begin(), zeroBlock.end());
    tCipherBlock startBlock = cipher.encrypt(counter);
    tCipherBlock hashBlock = cipher.encrypt(longLongIntToBytes(getHash(plainText)));//считаем значение хэш-суммы исходного сообщения
    size_t blockCount{0};
    std::vector<unsigned char> internalPlainText = padding(plainText);
    size_t blockNum = internalPlainText.size() / 8;
    cipherText.resize(internalPlainText.size());
    std::vector<std::thread> blockCipherThreadVector;//в этом массиве хранятся и выполняются потоки
    for(size_t i = 0; i < blockNum; i++)
    {
        blockCipherThreadVector.push_back(std::thread([this, i, &internalPlainText, &cipherText, &counter, randomDelta]()
        {
            //зашифровывание одного блока (выполняется в отдельном потоке)
            std::vector<unsigned char> gamma = counter;
            gamma = incCounterBlock(counter, randomDelta * i);//увеличиваем значение gamma на randomDelta для расшифровывания каждого блока
            std::vector<unsigned char> block(8);
            std::copy(internalPlainText.begin() + 8 * i, internalPlainText.begin() + (8 * i + 8), block.begin());
            block = xorBlocks(block, counter);
            block = cipher.encrypt(block);
            std::copy(block.begin(), block.end(), cipherText.begin() + 8 * i);
        }));
    }
    for(auto &thread : blockCipherThreadVector)
    {
        //в этом цикле ждем завершения всех потоков
        blockCount++;
        thread.join();
    }
    cipherText.insert(cipherText.begin(), hashBlock.begin(), hashBlock.end());//вставляем в начало зашифрованного сообщения хэш-сумму
    cipherText.insert(cipherText.begin(), startBlock.begin(), startBlock.end());//вставляем в начало начальное значение counter
    return blockCount;
}

size_t CipherMode::rdhModeDecrypt(const std::vector<unsigned char> &cipherText, std::vector<unsigned char> &plainText)
//расшифровывание массива байтов в режиме RD + H (аналогично режиму RD, только еще проверяем правильность переданной в сообщении хэш-суммы)
//реализовано параллельное шифрование кажодго блока в отедльности (каждый блок шифруется в отдельном потоке)
{
    std::vector<unsigned char> internalCipherText = cipherText;
    tCipherBlock startBlock(8);
    tCipherBlock hashBlock(8);

    std::copy(internalCipherText.begin(), internalCipherText.begin() + 8, startBlock.begin());
    std::copy(internalCipherText.begin() + 8, internalCipherText.begin() + 16, hashBlock.begin());
    startBlock = cipher.decrypt(startBlock);
    hashBlock = cipher.decrypt(hashBlock);
    std::vector<unsigned char> counter = startBlock;
    startBlock.erase(startBlock.begin(), startBlock.begin() + 4);
    unsigned int randomDelta = bytesToLongInt(startBlock);
    internalCipherText.erase(internalCipherText.begin(), internalCipherText.begin() + 16);
    size_t blockNum = internalCipherText.size() / 8;
    plainText.resize(internalCipherText.size());
    size_t blockCount{0};
    std::vector<std::thread> blockCipherThreadVector;//в этом массиве хранятся и выполняются потоки
    for(size_t i = 0; i < blockNum; i++)
    {
        blockCipherThreadVector.push_back(std::thread([this, i, &internalCipherText, &plainText, &counter, randomDelta]()
        {
            //расшифровывание одного блока (выполняется в отдельном потоке)
            std::vector<unsigned char> gamma = counter;
            gamma = incCounterBlock(counter, randomDelta * i);//увеличиваем значение gamma на randomDelta для расшифровывания каждого блока
            std::vector<unsigned char> block(8);
            std::copy(internalCipherText.begin() + 8 * i, internalCipherText.begin() + (8 * i + 8), block.begin());
            block = cipher.decrypt(block);
            block = xorBlocks(block, counter);
            std::copy(block.begin(), block.end(), plainText.begin() + 8 * i);
        }));
    }
    for(auto &thread : blockCipherThreadVector)
    {
        //в этом цикле ждем завершения всех потоков
        blockCount++;
        thread.join();
    }
    plainText = unpadding(plainText);
    //проверяем правильность хэш-суммы
    if(bytesToLongLongInt(hashBlock) != getHash(plainText))
    {
        //если хэш-сумма не совпадает, возвращаем ноль
        return 0;
    }
    return blockCount;
}

size_t CipherMode::encrypt(const std::vector<unsigned char> &plainText, std::vector<unsigned char> &cipherText)
//зашифровываем массив байтов
{
    switch(mode) {
    case ECB:
        return this->ecbModeEncrypt(plainText, cipherText);
        break;
    case CBC:
        return this->cbcModeEncrypt(plainText, cipherText);
        break;
    case CFB:
        return this->cfbModeEncrypt(plainText, cipherText);
        break;
    case OFB:
        return this->ofbModeEncrypt(plainText, cipherText);
        break;
    case CTR:
        return this->ctrModeEncrypt(plainText, cipherText);
        break;
    case RD:
        return this->rdModeEncrypt(plainText, cipherText);
        break;
    case RDH:
        return this->rdhModeEncrypt(plainText, cipherText);
        break;
    default:
        return 0;
        break;
    }
}

size_t CipherMode::encrypt(const std::string &plainTextFileName, const std::string &cipherTextFileName)
//зашифровываем файл
{
    size_t blockCount{0};
    std::ifstream plainTextFile(plainTextFileName, std::ios::binary);
    if(plainTextFile.is_open())
    {
        plainTextFile.seekg(0, std::ios::end);
        std::streampos plainTextFileSize = plainTextFile.tellg();
        plainTextFile.seekg(0, std::ios::beg);
        std::vector<unsigned char> plainText(plainTextFileSize);
        plainTextFile.read(reinterpret_cast<char*>(plainText.data()), plainTextFileSize);
        plainTextFile.close();
        std::vector<unsigned char> cipherText;
        blockCount = this->encrypt(plainText, cipherText);
        std::ofstream cipherTextFile(cipherTextFileName, std::ios::binary);
        if(cipherTextFile.is_open())
        {
            cipherTextFile.write(reinterpret_cast<char*>(cipherText.data()), cipherText.size());
            plainTextFile.close();
            return blockCount;
        }
        return 0;
    }
    return 0;
}

size_t CipherMode::decrypt(const std::vector<unsigned char> &cipherText, std::vector<unsigned char> &plainText)
//расшифровываем массив байтов
{
    switch(mode) {
    case ECB:
        return this->ecbModeDecrypt(cipherText, plainText);
        break;
    case CBC:
        return this->cbcModeDecrypt(cipherText, plainText);
        break;
    case CFB:
        return this->cfbModeDecrypt(cipherText, plainText);
        break;
    case OFB:
        return this->ofbModeDecrypt(cipherText, plainText);
        break;
    case CTR:
        return this->ctrModeDecrypt(cipherText, plainText);
        break;
    case RD:
        return this->rdModeDecrypt(cipherText, plainText);
        break;
    case RDH:
        return this->rdhModeDecrypt(cipherText, plainText);
        break;
    default:
        return 0;
        break;
    }
}

size_t CipherMode::decrypt(const std::string &cipherTextFileName, const std::string &plainTextFileName)
//расшифровываем файл
{
    size_t blockCount{0};
    std::ifstream cipherTextFile(cipherTextFileName, std::ios::binary);
    if(cipherTextFile.is_open())
    {
        cipherTextFile.seekg(0, std::ios::end);
        std::streampos cipherTextFileSize = cipherTextFile.tellg();
        cipherTextFile.seekg(0, std::ios::beg);
        std::vector<unsigned char> cipherText(cipherTextFileSize);
        cipherTextFile.read(reinterpret_cast<char*>(cipherText.data()), cipherTextFileSize);
        cipherTextFile.close();
        std::vector<unsigned char> plainText;
        blockCount = this->decrypt(cipherText, plainText);
        std::ofstream plainTextFile(plainTextFileName, std::ios::binary);
        if(plainTextFile.is_open())
        {
            plainTextFile.write(reinterpret_cast<char*>(plainText.data()), plainText.size());
            cipherTextFile.close();
            return blockCount;
        }
        return 0;
    }
    return 0;
}

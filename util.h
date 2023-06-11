#ifndef UTIL_H
#define UTIL_H

#include <iostream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <climits>

void printBlock(const std::vector<unsigned char> &block);
std::vector<bool> decToBin(long long int value, int numBits);
long long int binToDec(const std::vector<bool> &binBlock);
std::vector<unsigned char> xorBlocks(const std::vector<unsigned char> &block_1, const std::vector<unsigned char> &block_2);
std::vector<bool> bytesToBits(const std::vector<unsigned char> &block);
std::vector<unsigned char> bitsToBytes(const std::vector<bool> &block);
std::pair<int, int> getRowColSBox(const std::vector<bool> &block);
std::vector<unsigned char> permutationBits(const  std::vector<unsigned char> &block, const  std::vector<unsigned char> &permutationBlock);
std::vector<unsigned char> sBoxTransform(const  std::vector<unsigned char> &block, const std::vector<std::vector<std::vector<unsigned char>>> &sBox, int numBits);
std::vector<unsigned char> mergeBlocks(const std::vector<unsigned char> &block_1, const std::vector<unsigned char> &block_2);


#endif // UTIL_H

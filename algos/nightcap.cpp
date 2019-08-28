#include "crypto/block.h"

void nightcap_hash(const char* input, char* output, unsigned int len)
{
        CBlockHeader block;
        memcpy(reinterpret_cast<unsigned char*>(&block), input, 100);
        uint256 powhash = block.GetPoWHash();
	memcpy((void*)output,reinterpret_cast<unsigned char*>(&powhash),32);
}

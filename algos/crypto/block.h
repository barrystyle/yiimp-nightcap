#include "uint256.h"

class CBlockHeader
{
public:
    // header
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
    uint128 hashMix;
    int32_t height;

    CBlockHeader()
    {
        SetNull();
    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        hashMix.SetNull();
        height = 0;
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetPoWHash() const;
    uint128 GetCMix() const;
};

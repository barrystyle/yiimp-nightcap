#include "dag.h"

uint256 CBlockHeader::GetPoWHash() const
{
    CDAGSystem sys;
    CHashimotoResult res = sys.Hashimoto(*this);
    return res.GetResult();
}

uint128 CBlockHeader::GetCMix() const
{
    CDAGSystem sys;
    CHashimotoResult res = sys.Hashimoto(*this);
    return res.GetCmix();
}

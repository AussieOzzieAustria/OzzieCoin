// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    const CBlockIndex* pindex = pindexLast;

    if (pindex->nHeight < params.nPastBlocksMin) {
        return nProofOfWorkLimit;
    }

    if (params.fPowAllowMinDifficultyBlocks)
    {
        // Special difficulty rule for testnet:
        // If the new block's timestamp is more than 2* 10 minutes
        // then allow mining of a min-difficulty block.
        if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
            return nProofOfWorkLimit;
    }

    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    int64_t nBlockTimeAverage = 0;
    int64_t nBlockTimeAveragePrev = 0;
    int64_t nBlockTimeCount = 0;
    int64_t nBlockTimeSum2 = 0;
    int64_t nBlockTimeCount2 = 0;
    int64_t LastBlockTime = 0;
    uint64_t CountBlocks = 0;
    arith_uint256 PastDifficultyAverage = 0;
    arith_uint256 PastDifficultyAveragePrev = 0;

    for (unsigned int i = 1; i <= params.nPastBlocksMax && pindex->nHeight > 0; i++) {
        CountBlocks++;

        if(i <= params.nPastBlocksMin) {
            if (CountBlocks == 1) {
                PastDifficultyAverage.SetCompact(pindex->nBits);
            }
            else {
                if (arith_uint256().SetCompact(pindex->nBits) > PastDifficultyAveragePrev) {
                    PastDifficultyAverage = ((arith_uint256().SetCompact(pindex->nBits) - PastDifficultyAveragePrev) / CountBlocks) + PastDifficultyAveragePrev;
                } else {
                    PastDifficultyAverage = PastDifficultyAveragePrev - ((PastDifficultyAveragePrev - arith_uint256().SetCompact(pindex->nBits)) / CountBlocks);
                }
            }
            PastDifficultyAveragePrev = PastDifficultyAverage;
        }

        if(LastBlockTime > 0){
            int64_t Diff = (LastBlockTime - pindex->GetBlockTime());
            if(nBlockTimeCount <= params.nPastBlocksMin) {
                nBlockTimeCount++;

                if (nBlockTimeCount == 1) {
                    nBlockTimeAverage = Diff;
                }
                else {
                    nBlockTimeAverage = ((Diff - nBlockTimeAveragePrev) / nBlockTimeCount) + nBlockTimeAveragePrev;
                }
                nBlockTimeAveragePrev = nBlockTimeAverage;
            }
            nBlockTimeCount2++;
            nBlockTimeSum2 += Diff;
        }
        LastBlockTime = pindex->GetBlockTime();

        if (pindex->pprev == nullptr) {
            assert(pindex);
            break;
        }
        pindex = pindex->pprev;
    }

    arith_uint256 bnNew(PastDifficultyAverage);
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);

    // Limit adjustment step
    if (nBlockTimeCount != 0 && nBlockTimeCount2 != 0) {
        double SmartAverage = ((((long double)nBlockTimeAverage)*0.7)+(((long double)nBlockTimeSum2 / (long double)nBlockTimeCount2)*0.3));
        if(SmartAverage < 1) SmartAverage = 1;
        double Shift = params.nPowTargetSpacing/SmartAverage;
        double fActualTimespan = ((long double)CountBlocks*(double)params.nPowTargetSpacing)/Shift;
        double fTargetTimespan = ((long double)CountBlocks*(double)params.nPowTargetSpacing);

        if (fActualTimespan < fTargetTimespan/3)
            fActualTimespan = fTargetTimespan/3;
        if (fActualTimespan > fTargetTimespan*3)
            fActualTimespan = fTargetTimespan*3;

        int64_t nActualTimespan = fActualTimespan;
        int64_t nTargetTimespan = fTargetTimespan;

        // Retarget

        // Litecoin: intermediate uint256 can overflow by 1 bit
        bool fShift = bnNew.bits() > bnPowLimit.bits() - 1;
        if (fShift)
            bnNew >>= 1;
        bnNew *= nActualTimespan;
        bnNew /= nTargetTimespan;
        if (fShift)
            bnNew <<= 1;
    }

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;
    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

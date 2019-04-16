// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/merkle.h>

#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>
#include <utilmoneystr.h>

#include <assert.h>

#include <chainparamsseeds.h>
#include <chainparamsimport.h>

int64_t CChainParams::GetCoinYearReward(int64_t nTime) const
{
    static const int64_t nSecondsInYear = 365 * 24 * 60 * 60;

    if (strNetworkID != "regtest")
    {
        // Y1 5%, Y2 4%, Y3 3%, Y4 2%, ... YN 2%
        int64_t nYearsSinceGenesis = (nTime - genesis.nTime) / nSecondsInYear;

        if (nYearsSinceGenesis >= 0 && nYearsSinceGenesis < 3)
            return (5 - nYearsSinceGenesis) * CENT;
    };

    return nCoinYearReward;
};

int64_t CChainParams::GetProofOfStakeReward(const CBlockIndex *pindexPrev, int64_t nFees) const
{
    int64_t nSubsidy;

    nSubsidy = (pindexPrev->nMoneySupply / COIN) * GetCoinYearReward(pindexPrev->nTime) / (365 * 24 * (60 * 60 / nTargetSpacing));

    if (LogAcceptCategory(BCLog::POS) && gArgs.GetBoolArg("-printcreation", false))
        LogPrintf("GetProofOfStakeReward(): create=%s\n", FormatMoney(nSubsidy).c_str());

    return nSubsidy + nFees;
};

bool CChainParams::CheckImportCoinbase(int nHeight, uint256 &hash) const
{
    for (auto &cth : Params().vImportedCoinbaseTxns)
    {
        if (cth.nHeight != (uint32_t)nHeight)
            continue;

        if (hash == cth.hash)
            return true;
        return error("%s - Hash mismatch at height %d: %s, expect %s.", __func__, nHeight, hash.ToString(), cth.hash.ToString());
    };

    return error("%s - Unknown height.", __func__);
};


const DevFundSettings *CChainParams::GetDevFundSettings(int64_t nTime) const
{
    for (size_t i = vDevFundSettings.size(); i-- > 0; )
    {
        if (nTime > vDevFundSettings[i].first)
            return &vDevFundSettings[i].second;
    };

    return nullptr;
};

bool CChainParams::IsBech32Prefix(const std::vector<unsigned char> &vchPrefixIn) const
{
    for (auto &hrp : bech32Prefixes)  {
        if (vchPrefixIn == hrp) {
            return true;
        }
    }

    return false;
};

bool CChainParams::IsBech32Prefix(const std::vector<unsigned char> &vchPrefixIn, CChainParams::Base58Type &rtype) const
{
    for (size_t k = 0; k < MAX_BASE58_TYPES; ++k) {
        auto &hrp = bech32Prefixes[k];
        if (vchPrefixIn == hrp) {
            rtype = static_cast<CChainParams::Base58Type>(k);
            return true;
        }
    }

    return false;
};

bool CChainParams::IsBech32Prefix(const char *ps, size_t slen, CChainParams::Base58Type &rtype) const
{
    for (size_t k = 0; k < MAX_BASE58_TYPES; ++k)
    {
        const auto &hrp = bech32Prefixes[k];
        size_t hrplen = hrp.size();
        if (hrplen > 0
            && slen > hrplen
            && strncmp(ps, (const char*)&hrp[0], hrplen) == 0)
        {
            rtype = static_cast<CChainParams::Base58Type>(k);
            return true;
        };
    };

    return false;
};

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

const std::pair<const char*, CAmount> regTestOutputs[] = {
    std::make_pair("235f61c7f9fd8618efec8a120089c0712d65a7e3", 10000 * COIN),
    std::make_pair("7830a530109c3649a3fc39e30402385522a3956f", 10000 * COIN),
    std::make_pair("17fa068bb6f855bcfbc6af9e89a431942d4445ee", 10000 * COIN),
    std::make_pair("bd9379da5ece09172d0d8f4071638d68f265443b", 10000 * COIN),
    std::make_pair("dfdae75cb66bdeae1901938e5297c49969c35bed", 10000 * COIN),
    std::make_pair("1e16370045bc2e26747782e679fff037512f5c08", 10000 * COIN),
    std::make_pair("1ac5fca8021611a70c8ae55bd5bb2e4728235384", 10000 * COIN),
    std::make_pair("24b96fe3560f0bd0cc8e077933f019994322da50", 10000 * COIN),
    std::make_pair("9a85015717e5ba846b684e342859970b02703387", 10000 * COIN),
    std::make_pair("543d12073213c639370fd269547d9b9fc31d28b3", 10000 * COIN),

    std::make_pair("38f8ef57f58e32383d204cd3c310be335cf7b925", 5000 * COIN),
    std::make_pair("7ca6bf150077dd0bb1fad88fd2ad9027a6205c77", 5000 * COIN),
    std::make_pair("e2baf167d4562221e3177d48eef7f0b441d6f329", 5000 * COIN),
    std::make_pair("8e52355e2df01b15bdd7d299a780f266760da999", 5000 * COIN),
    std::make_pair("8cbea35fd6fbd894376b46232f417db50bc3ee89", 5000 * COIN),
};
const size_t nGenesisOutputsRegtest = sizeof(regTestOutputs) / sizeof(regTestOutputs[0]);

const std::pair<const char*, CAmount> genesisOutputs[] = {
    /*std::make_pair("62a62c80e0b41f2857ba83eb438d5caa46e36bcb",7017084118),
    std::make_pair("c515c636ae215ebba2a98af433a3fa6c74f84415",221897417980),
    std::make_pair("711b5e1fd0b0f4cdf92cb53b00061ef742dda4fb",120499999),
    std::make_pair("20c17c53337d80408e0b488b5af7781320a0a311",18074999),
    std::make_pair("aba8c6f8dbcf4ecfb598e3c08e12321d884bfe0b",92637054909),
    std::make_pair("1f3277a84a18f822171d720f0132f698bcc370ca",3100771006662),
    std::make_pair("8fff14bea695ffa6c8754a3e7d518f8c53c3979a",465115650998),
    std::make_pair("e54967b4067d91a777587c9f54ee36dd9f1947c4",669097504996),
    std::make_pair("7744d2ac08f2e1d108b215935215a4e66d0262d2",802917005996),
    std::make_pair("a55a17e86246ea21cb883c12c709476a09b4885c",267639001997),
    std::make_pair("4e00dce8ab44fd4cafa34839edf8f68ba7839881",267639001997),
    std::make_pair("702cae5d2537bfdd5673ac986f910d6adb23510a",254257051898),
    std::make_pair("b19e494b0033c5608a7d153e57d7fdf3dfb51bb7",1204260290404),
    std::make_pair("6909b0f1c94ea1979ed76e10a5a49ec795a8f498",1204270995964),
    std::make_pair("05a06af3b29dade9f304244d934381ac495646c1",236896901156),
    std::make_pair("557e2b3205719931e22853b27920d2ebd6147531",155127107700),
    std::make_pair("ad16fb301bd21c60c5cb580b322aa2c61b6c5df2",115374999),
    std::make_pair("182c5cfb9d17aa8d8ff78940135ca8d822022f32",17306249),
    std::make_pair("b8a374a75f6d44a0bd1bf052da014efe564ae412",133819500998),
    std::make_pair("fadee7e2878172dad55068c8696621b1788dccb3",133713917412),
    std::make_pair("eacc4b108c28ed73b111ff149909aacffd2cdf78",173382671567),
    std::make_pair("dd87cc0b8e0fc119061f33f161104ce691d23657",245040727620),
    std::make_pair("1c8b0435eda1d489e9f0a16d3b9d65182f885377",200226012806),
    std::make_pair("15a724f2bc643041cb35c9475cd67b897d62ca52",436119839355),
    std::make_pair("626f86e9033026be7afbb2b9dbe4972ef4b3e085",156118097804),
    std::make_pair("a4a73d99269639541cb7e845a4c6ef3e3911fcd6",108968353176),
    std::make_pair("27929b31f11471aa4b77ca74bb66409ff76d24a2",126271503135),
    std::make_pair("2d6248888c7f72cc88e4883e4afd1025c43a7f0e",35102718156),
    std::make_pair("25d8debc253f5c3f70010f41c53348ed156e7baa",80306152234),*/
    std::make_pair("234f8d7f8c7085baddd32e6048f4ec239f94acec",7017084118),
    std::make_pair("7686c73a824b14cda1615c741b0e9f628ca69e43",221897417980),
    std::make_pair("1d52af3186038ec444d51c06112dd0d0ab3ad62b",120499999),
    std::make_pair("28e1bc847959ef358ee400e49e0c22062dcc6a8c",18074999),
    std::make_pair("5acf3b4364685a5b3c2c7d67598d714d541c0ed5",92637054909),
    std::make_pair("2484a5e32b4240816c9760957fb4a9675e702df5",3100771006662),
    std::make_pair("8a8c90fcd88031eb4ed59e672b8dcb81bb2af5a2",465115650998),
    std::make_pair("e13282973aee97bf02201c465553f6a0f6370c3f",669097504996),
    std::make_pair("411c4c2ff0354c22556438d56f24ec03ec549c21",802917005996),
    std::make_pair("52ab9537580d602f123dcae886d4b2f9b68d8d04",267639001997),
    std::make_pair("a3036ddbd5aef2ea55e79f2ee6866cddf6dc5466",267639001997),
    std::make_pair("2cbe8716e6f2ca880cd7083c0123b00f1afd149a",254257051898),
    std::make_pair("93d10284f6f73e221cfc69339d6abca4dc45ad91",1204260290404),
    std::make_pair("62f9f9d83209670c70ebe0aa28515093df8463fa",1204270995964),
    std::make_pair("7b54478cd891e58ee21b5db966e11c1742d60673",236896901156),
    std::make_pair("38e32e3edf13f0827245a05c6e1b6d1a5fbab58b",155127107700),
    std::make_pair("9077d34f2102e2f5cdf4661410bb6cdce7847d5a",115374999),
    std::make_pair("c04ce2a9310c7830a7c23e1b4a565a4775ba7459",17306249),
    std::make_pair("cb1353a07d124fdde6ef6a16faae70ba7dad4ddb",133819500998),
    std::make_pair("f4d4580b4ff181822918a72489344423be5887a7",133713917412),
    std::make_pair("b8be6f36317b1e07f9d345d6a3bead80f0eba1d0",173382671567),
    std::make_pair("529a36397c25a71c5ad2dedbd3d52435ec41d534",245040727620),
    std::make_pair("e6e1f627f8b0b5f65a5ae6cfb748a0e47f6885bb",200226012806),
    std::make_pair("c858f8ba8e3a96ff72798a268649ced170b37fda",436119839355),
    std::make_pair("67518254c2adb5ce0d3d149fedb3dd9b580fc64b",156118097804),
    std::make_pair("e346aa4bc6cf4d77efae79591dc92c411dc7cc12",108968353176),
    std::make_pair("291eaaef8a2deac70877e96f738befe1007982e6",126271503135),
    std::make_pair("1e243b0535d6c5b399ff869c48a74f7c92ce85d1",35102718156),
    std::make_pair("2b50627629cae7b55162059f4c134fb50963b088",80306152234),
    
};
const size_t nGenesisOutputs = sizeof(genesisOutputs) / sizeof(genesisOutputs[0]);

const std::pair<const char*, CAmount> genesisOutputsTestnet[] = {
    std::make_pair("47ee773a9809220234335a4d9228b05f0cc86eda",7017084118),
    std::make_pair("cfcb4737512842dc49bdabcd8e7c6f9b176930a1",221897417980),
    std::make_pair("92319ad616ace774f418405fb3615f00f07dc1fa",120499999),
    std::make_pair("a9ec24916808bd32b2b50dcd4ced3a7d0f96698d",18074999),
    std::make_pair("26c288e52c87ed9028eccc65de0023509068da93",92637054909),
    std::make_pair("9b6a03caeb5b7a641f42570ab2a100c0ee7d9a6e",3100771006662),
    std::make_pair("5747a0964aca5f13db0cbc9b71466e736c0d5c81",465115650998),
    std::make_pair("1d5a4eabd6718914d8fb66d7243ad52c46d6b0f9",669097504996),
    std::make_pair("6752ea9b9d9aa95e3de7c515b122d0b8fe892172",802917005996),
    std::make_pair("4a0e49a46692013466ed9ca36bd1aee1c9eb897e",267639001997),
    std::make_pair("a43e739ee6c40f1a41e4a63415852f1073dbaf86",267639001997),
    std::make_pair("fa3b7f7054b88d0241828a9f19d354ff29806225",245040727620),
    std::make_pair("46e2e9268de589a931275dfa51c89e091a486a6e",1204260290404),
    std::make_pair("1d5f43deae1effdba5cdf77b28ec297caeb7b750",1204270995964),
    std::make_pair("b901a7bf4688b2518598a9efb5edffef871ccc0b",236896901156),
    std::make_pair("8c6f1d1f74050fcbf6f2fc7b3b2d5e971c21d1c3",155127107700),
    std::make_pair("222288188a19db61fe9d1341a8be387edea4a5aa",115374999),
    std::make_pair("bc5f38bca8e36b3514095459b696a04546360399",17306249),
    std::make_pair("f6de8537f91e403c0418ce481140c29c3f298bcd",133819500998),
    std::make_pair("5975f2a6cde4b2468e7e919a28b31e76ad30f0b3",133713917412),
    std::make_pair("dff5dbf0d11782814888a9aeb70c1b0cd9fec125",173382671567),
    std::make_pair("4d9f421b7a10330890d76baf960b5d363d5352fd",254257051898),
    std::make_pair("6cee222035339f27722946ae890ab22c27c4aee4",200226012806),
    std::make_pair("2cbe6cbef4f56fd00d3ad9b966fb160e3ca9202e",436119839355),
    std::make_pair("ad1d720270f3deb70fd211cf73e9f7d33f7a217e",156118097804),
    std::make_pair("80787e57362a0cdf0bc502517e806006f651a98c",108968353176),
    std::make_pair("e2ed92db60593414eaf1c59ccfa5a0cdd4377bf7",126271503135),
    std::make_pair("07e2d10989cfd6d07aec30fa72c12b5ec550ae69",35102718156),
    std::make_pair("23639234cd1944eca3e889adf8e74ee958cb468a",80306152234),
};
const size_t nGenesisOutputsTestnet = sizeof(genesisOutputsTestnet) / sizeof(genesisOutputsTestnet[0]);


static CBlock CreateGenesisBlockRegTest(uint32_t nTime, uint32_t nNonce, uint32_t nBits)
{
    //const char *pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const char *pszTimestamp = "This is my Particl 2019-4-16 16:00:00 for regtest";
    CMutableTransaction txNew;
    txNew.nVersion = PARTICL_TXN_VERSION;
    txNew.SetType(TXN_COINBASE);
    txNew.vin.resize(1);
    uint32_t nHeight = 0;  // bip34
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp)) << OP_RETURN << nHeight;

    txNew.vpout.resize(nGenesisOutputsRegtest);
    for (size_t k = 0; k < nGenesisOutputsRegtest; ++k)
    {
        OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
        out->nValue = regTestOutputs[k].second;
        out->scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ParseHex(regTestOutputs[k].first) << OP_EQUALVERIFY << OP_CHECKSIG;
        txNew.vpout[k] = out;
    };

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = PARTICL_BLOCK_VERSION;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));

    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.hashWitnessMerkleRoot = BlockWitnessMerkleRoot(genesis);

    return genesis;
}

static CBlock CreateGenesisBlockTestNet(uint32_t nTime, uint32_t nNonce, uint32_t nBits)
{
    //const char *pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const char *pszTimestamp = "This is my Particl 2019-4-16 14:00:00 for testnet";

    CMutableTransaction txNew;
    txNew.nVersion = PARTICL_TXN_VERSION;
    txNew.SetType(TXN_COINBASE);
    txNew.vin.resize(1);
    uint32_t nHeight = 0;  // bip34
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp)) << OP_RETURN << nHeight;

    txNew.vpout.resize(nGenesisOutputsTestnet);
    for (size_t k = 0; k < nGenesisOutputsTestnet; ++k)
    {
        OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
        out->nValue = genesisOutputsTestnet[k].second;
        out->scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ParseHex(genesisOutputsTestnet[k].first) << OP_EQUALVERIFY << OP_CHECKSIG;
        txNew.vpout[k] = out;
    };


    // Foundation Fund Raiser Funds
    // rVDQRVBKnQEfNmykMSY9DHgqv8s7XZSf5R fc118af69f63d426f61c6a4bf38b56bcdaf8d069  PYQCm5hVEKtieKCbc8neCCSgCwfbhaAa6W
    // r9WFWQ6XD8p63Yu5f5Wkf8WhxmFNetdzeB 23dea8087c875fdb9296536b64fc544eabe26246
    OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
    out->nValue = 397364 * COIN;
    out->scriptPubKey = CScript() << OP_HASH160 << ParseHex("23dea8087c875fdb9296536b64fc544eabe26246") << OP_EQUAL;
    txNew.vpout.push_back(out);

    // rVDQRVBKnQEfNmykMSY9DHgqv8s7XZSf5R fc118af69f63d426f61c6a4bf38b56bcdaf8d069  PdB6aJxBMsgkHm4tPVBGUDMFVTztyzns22
    // r98NaKQ3oXzckiQT5Pd16FjGqyJ9rFiLEn 1fbb67a978162e8e63c143130a6f6814b99d793b
    out = MAKE_OUTPUT<CTxOutStandard>();
    out->nValue = 296138 * COIN;
    out->scriptPubKey = CScript() << OP_HASH160 << ParseHex("1fbb67a978162e8e63c143130a6f6814b99d793b") << OP_EQUAL;
    txNew.vpout.push_back(out);

    // Community Initative
    // rAybJ7dx4t6heHy99WqGcXkoT4Bh3V9qZ8 340288104577fcc3a6a84b98f7eac1a54e5287ee  PcWuoRnfpvMimmAjoGjSgtW4gnYW5zsdkV
    // rFUWZ2RLP3bBv5oaasaKFscrePfDzwbpgx 655b23695cd4a1848dde5d6e7f66f54be75ae167
    out = MAKE_OUTPUT<CTxOutStandard>();
    out->nValue = 156675 * COIN;
    out->scriptPubKey = CScript() << OP_HASH160 << ParseHex("655b23695cd4a1848dde5d6e7f66f54be75ae167") << OP_EQUAL;
    txNew.vpout.push_back(out);

    // Contributors Left Over Funds
    // rAvmLShYFZ78aAHhFfUFsrHMoBuPPyckm5 3379aa2a4379ae6c51c7777d72e8e0ffff71881b  Pkajhc4c5MVkkTzjczyrDLgAjG99ZWzB3K
    // rNXhMMsQbGQtuQnXReoHCc8m43wcgEkD5k b2be47f9ae9e308370945a0335ca1604f8686dba
    out = MAKE_OUTPUT<CTxOutStandard>();
    out->nValue = 216346 * COIN;
    out->scriptPubKey = CScript() << OP_HASH160 << ParseHex("b2be47f9ae9e308370945a0335ca1604f8686dba") << OP_EQUAL;
    txNew.vpout.push_back(out);

    // Reserved Particl for primary round
    // rLWLm1Hp7im3mq44Y1DgyirYgwvrmRASib 9c8c6c8c698f074180ecfdb38e8265c11f2a62cf 
    // rELBQdUu3qML8BTchq6dEKvCVPQu86Hkc6 58cfb4202d4d6a2821d07fa0d9fb87cceaf393a5
    out = MAKE_OUTPUT<CTxOutStandard>();
    out->nValue = 996000 * COIN;
    out->scriptPubKey = CScript() << 1512000000 << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_HASH160<< ParseHex("58cfb4202d4d6a2821d07fa0d9fb87cceaf393a5") << OP_EQUAL; // 2017-11-30
    txNew.vpout.push_back(out);


    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = PARTICL_BLOCK_VERSION;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));

    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.hashWitnessMerkleRoot = BlockWitnessMerkleRoot(genesis);

    return genesis;
}

static CBlock CreateGenesisBlockMainNet(uint32_t nTime, uint32_t nNonce, uint32_t nBits)
{
    //const char *pszTimestamp = "BTC 000000000000000000c679bc2209676d05129834627c7b1c02d1018b224c6f37";
    const char *pszTimestamp = "This is my Particl 2019-4-16 11:00:00";

    CMutableTransaction txNew;
    txNew.nVersion = PARTICL_TXN_VERSION;
    txNew.SetType(TXN_COINBASE);

    txNew.vin.resize(1);
    uint32_t nHeight = 0;  // bip34
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp)) << OP_RETURN << nHeight;

    txNew.vpout.resize(nGenesisOutputs);
    for (size_t k = 0; k < nGenesisOutputs; ++k)
    {
        OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
        out->nValue = genesisOutputs[k].second;
        out->scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ParseHex(genesisOutputs[k].first) << OP_EQUALVERIFY << OP_CHECKSIG;
        txNew.vpout[k] = out;
    };

    // Foundation Fund Raiser Funds
    // Ps3KXuZowK7R5NF9LygAxJwiZjShCgqkLY
    OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
    out->nValue = 397364 * COIN;
    out->scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ParseHex("d1a71777c47753bc974603016393dc52ee28f36c") << OP_EQUALVERIFY << OP_CHECKSIG;
    txNew.vpout.push_back(out);

    // RGPs8ud1qvHzbCjLw4k9TABEmhxykW7Bkg  4e0bfb0b03a2981c774402caac92bed8297d9ab0
    out = MAKE_OUTPUT<CTxOutStandard>();
    out->nValue = 296138 * COIN;
    out->scriptPubKey = CScript() << OP_HASH160 << ParseHex("4e0bfb0b03a2981c774402caac92bed8297d9ab0") << OP_EQUAL;
    txNew.vpout.push_back(out);

    // Community Initative
    // RKKgSiQcMjbC8TABRoyyny1gTU4fAEiQz9
    // RNPqqewbDQPAiTPPyfa3xZf6CgrJDx6Jef 8fdba6fb0f962f11dd0a836b678802bd6a0a7cc1
    out = MAKE_OUTPUT<CTxOutStandard>();
    out->nValue = 156675 * COIN;
    out->scriptPubKey = CScript() << OP_HASH160 << ParseHex("8fdba6fb0f962f11dd0a836b678802bd6a0a7cc1") << OP_EQUAL;
    txNew.vpout.push_back(out);

    // Contributors Left Over Funds
    // RKiaVeyLUp7EmwHtCP92j8Vc1AodhpWi2U
    // RCB3PjTZRQV98YB4Sf5YzJV8TP63xN4Dx1 1fbea1856791d93e58d680277820ce4716c534b5
    out = MAKE_OUTPUT<CTxOutStandard>();
    out->nValue = 216346 * COIN;
    out->scriptPubKey = CScript() << OP_HASH160 << ParseHex("1fbea1856791d93e58d680277820ce4716c534b5") << OP_EQUAL;
    txNew.vpout.push_back(out);

    // Reserved Particl for primary round
    // RNnoeeqBTkpPQH8d29Gf45dszVj9RtbmCu
    // RPasye328KCNk6TB5E4d2EQPkWYX7k1bk6 9cea23580606a81797fd7887670f19ea316fded8
    out = MAKE_OUTPUT<CTxOutStandard>();
    out->nValue = 996000 * COIN;
    //out->scriptPubKey = CScript() << 1512000000 << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_HASH160<< ParseHex(//"9433643b4fd5de3ebd7fdd68675f978f34585af1") << OP_EQUAL; // 2017-11-30
    out->scriptPubKey = CScript() << 1512000000 << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_HASH160<< ParseHex("9cea23580606a81797fd7887670f19ea316fded8") << OP_EQUAL; // 2017-11-30
    txNew.vpout.push_back(out);


    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = PARTICL_BLOCK_VERSION;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));

    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.hashWitnessMerkleRoot = BlockWitnessMerkleRoot(genesis);

    return genesis;
}



void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";

        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 0;
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.OpIsCoinstakeTime = 1510272000; // 2017-11-10 00:00:00 UTC
        consensus.fAllowOpIsCoinstakeWithP2PKH = false;
        consensus.nPaidSmsgTime = 0x5C791EC0;   // 2019-03-01 12:00:00
        consensus.csp2shTime = 0x5C791EC0;      // 2019-03-01 12:00:00
        consensus.powLimit = uint256S("000000000000bfffffffffffffffffffffffffffffffffffffffffffffffffff");

        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1479168000; // November 15th, 2016.
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1510704000; // November 15th, 2017.

        // The best chain should have at least this much work.
        //consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000467b28adaecf2f81c8");
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0xff704cb42547da4efb2b32054c72c7682b7634ac34fda4ec88fe7badc666338c"); // 376100

        consensus.nMinRCTOutputDepth = 12;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0xf2;
        pchMessageStart[2] = 0xef;
        pchMessageStart[3] = 0xb4;
        nDefaultPort = 51738;
        nBIP44ID = 0x8000002C;

        nModifierInterval = 10 * 60;    // 10 minutes
        nStakeMinConfirmations = 225;   // 225 * 2 minutes
        nTargetSpacing = 120;           // 2 minutes
        nTargetTimespan = 24 * 60;      // 24 mins

        AddImportHashesMain(vImportedCoinbaseTxns);
        SetLastImportHeight();

        nPruneAfterHeight = 100000;

        //genesis = CreateGenesisBlockMainNet(1500296400, 31429, 0x1f00ffff); // 2017-07-17 13:00:00
        //genesis = CreateGenesisBlockMainNet(1552629600, 102250, 0x1f00ffff); // 2017-07-17 13:00:00
        //genesis = CreateGenesisBlockMainNet(1552720800, 121100, 0x1f00ffff); // 2017-07-17 13:00:00
        //genesis = CreateGenesisBlockMainNet(1555383600, 155555, 0x1f00ffff); // 2017-07-17 13:00:00
        genesis = CreateGenesisBlockMainNet(1555394400, 71459, 0x1f00ffff); // 2017-07-17 13:00:00
        consensus.hashGenesisBlock = genesis.GetHash();

        //assert(consensus.hashGenesisBlock == uint256S("0x0000ee0784c195317ac95623e22fddb8c7b8825dc3998e0bb924d66866eccf4c"));
        //assert(genesis.hashMerkleRoot == uint256S("0xc95fb023cf4bc02ddfed1a59e2b2f53edd1a726683209e2780332edf554f1e3e"));
        //assert(genesis.hashWitnessMerkleRoot == uint256S("0x619e94a7f9f04c8a1d018eb8bcd9c42d3c23171ebed8f351872256e36959d66c"));
        
        assert(consensus.hashGenesisBlock == uint256S("0x0000201e7cf86f570a9e3b408524932460653bf8331c33c48ae656e09380068a"));
        assert(genesis.hashMerkleRoot == uint256S("0xe827264b07436e3a4cccbbe150e83367d04381cbff2913eafb35d22ea0128f8f"));
        assert(genesis.hashWitnessMerkleRoot == uint256S("0x256d3aa8e997ca954c394ce29a607dd4e5d3cff49d9302a5e56e490e84eed3d8"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        //vSeeds.emplace_back("mainnet-seed.particl.io");
        //vSeeds.emplace_back("dnsseed-mainnet.particl.io");
        //vSeeds.emplace_back("mainnet.particl.io");


        /*vDevFundSettings.emplace_back(0,
            DevFundSettings("RJAPhgckEgRGVPZa9WoGSWW24spskSfLTQ", 10, 60));
        vDevFundSettings.emplace_back(consensus.OpIsCoinstakeTime,
            DevFundSettings("RBiiQBnQsVPPQkUaJVQTjsZM9K2xMKozST", 10, 60));*/
        vDevFundSettings.emplace_back(0,
            DevFundSettings("PY1MxQnXXJV859EWwwf5qPKwmcEQhy84Hh", 10, 60));
        vDevFundSettings.emplace_back(consensus.OpIsCoinstakeTime,
            DevFundSettings("RPBw2AUFnDCv2jU6xBeRuc7EqifRNzWQBJ", 10, 60));


        base58Prefixes[PUBKEY_ADDRESS]     = {0x38}; // P
        base58Prefixes[SCRIPT_ADDRESS]     = {0x3c};
        base58Prefixes[PUBKEY_ADDRESS_256] = {0x39};
        base58Prefixes[SCRIPT_ADDRESS_256] = {0x3d};
        base58Prefixes[SECRET_KEY]         = {0x6c};
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x69, 0x6e, 0x82, 0xd1}; // PPAR
        base58Prefixes[EXT_SECRET_KEY]     = {0x8f, 0x1d, 0xae, 0xb8}; // XPAR
        base58Prefixes[STEALTH_ADDRESS]    = {0x14};
        base58Prefixes[EXT_KEY_HASH]       = {0x4b}; // X
        base58Prefixes[EXT_ACC_HASH]       = {0x17}; // A
        base58Prefixes[EXT_PUBLIC_KEY_BTC] = {0x04, 0x88, 0xB2, 0x1E}; // xpub
        base58Prefixes[EXT_SECRET_KEY_BTC] = {0x04, 0x88, 0xAD, 0xE4}; // xprv

        bech32Prefixes[PUBKEY_ADDRESS].assign       ("ph","ph"+2);
        bech32Prefixes[SCRIPT_ADDRESS].assign       ("pr","pr"+2);
        bech32Prefixes[PUBKEY_ADDRESS_256].assign   ("pl","pl"+2);
        bech32Prefixes[SCRIPT_ADDRESS_256].assign   ("pj","pj"+2);
        bech32Prefixes[SECRET_KEY].assign           ("px","px"+2);
        bech32Prefixes[EXT_PUBLIC_KEY].assign       ("pep","pep"+3);
        bech32Prefixes[EXT_SECRET_KEY].assign       ("pex","pex"+3);
        bech32Prefixes[STEALTH_ADDRESS].assign      ("ps","ps"+2);
        bech32Prefixes[EXT_KEY_HASH].assign         ("pek","pek"+3);
        bech32Prefixes[EXT_ACC_HASH].assign         ("pea","pea"+3);
        bech32Prefixes[STAKE_ONLY_PKADDR].assign    ("pcs","pcs"+3);

        bech32_hrp = "bc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                /*{ 5000,     uint256S("0xe786020ab94bc5461a07d744f3631a811b4ebf424fceda12274f2321883713f4")},
                { 15000,    uint256S("0xafc73ac299f2e6dd309077d230fccef547b9fc24379c1bf324dd3683b13c61c3")},
                { 30000,    uint256S("0x35d95c12799323d7b418fd64df9d88ef67ef27f057d54033b5b2f38a5ecaacbf")},
                { 91000,    uint256S("0x4d1ffaa5b51431918a0c74345e2672035c743511359ac8b1be67467b02ff884c")},
                { 112250,   uint256S("0x89e4b23471aea7a875df835d6f89613fd87ba649e7a1d8cb892917d0080ef337")},
                { 128650,   uint256S("0x43597f7dd16719ab2ea63e9c34266120c85cf592a4ec61f82822003da6874408")},
                { 159010,   uint256S("0xb724d359a10aaa51755a65da830f4aaf4e44aad0246ebf5f73171122bc4b3997")},
                { 170880,   uint256S("0x03d23bd24386ebeb41c81f84145c46cc3f64e4d114b2b8d2bb14e5855f254f2a")},
                { 213800,   uint256S("0xfd6c0e5f7444a9e09a5fa1652db73d5b8628aeabe162529a5356be700509aa80")},
                { 254275,   uint256S("0x7f454ac5629ef667f40f900357d30bd63b7983363255880fd155fadbc9add957")},
                { 282130,   uint256S("0xf720421256795081c1d985e997bb81d040d557f24b9e2d16a1c13d21734fb2b1")},
                { 303640,   uint256S("0x7cc035d7888ee6d824cec8ff01a6287a71873d874f72a5fd3706d227b88f8e99")},
                { 357320,   uint256S("0x20b01f2bef93197bb014d27125939cd8d4f6a34257fdb498ae64c8644b8f2289")},
                { 376100,   uint256S("0xff704cb42547da4efb2b32054c72c7682b7634ac34fda4ec88fe7badc666338c")},*/
                { 0000,     uint256S("0x0000201e7cf86f570a9e3b408524932460653bf8331c33c48ae656e09380068a")},
            }
        };

        chainTxData = ChainTxData {
            // Data from rpc: getchaintxstats 4096 ff704cb42547da4efb2b32054c72c7682b7634ac34fda4ec88fe7badc666338c
            /* nTime    */ 1555383600,
            /* nTxCount */ 419347,
            /* dTxRate  */ 0.008
        };

        /* disable fallback fee on mainnet */
        m_fallback_fee_enabled = false;
    }

    void SetOld()
    {
        consensus.BIP16Exception = uint256S("0x00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22");
        consensus.BIP34Height = 227931;
        consensus.BIP34Hash = uint256S("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
        consensus.BIP65Height = 388381; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP66Height = 363725; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        genesis = CreateGenesisBlock(1231006505, 2083236893, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 0;
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.OpIsCoinstakeTime = 0;
        consensus.fAllowOpIsCoinstakeWithP2PKH = true; // TODO: clear for next testnet
        consensus.nPaidSmsgTime = 0;
        consensus.csp2shTime = 0x5C67FB40; // 2019-02-16 12:00:00

        consensus.powLimit = uint256S("000000000005ffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400; // March 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1462060800; // May 1st 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1493596800; // May 1st 2017

        // The best chain should have at least this much work.
        //consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000003d577d5f2d3d2c767");
        consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000000000000000000000000");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0xeecbeafc4b338901e3dfb6eeaefc128ef477dfe1e6f0f96bd63da27caf113ddc"); // 331600

        consensus.nMinRCTOutputDepth = 12;

        pchMessageStart[0] = 0x08;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x05;
        pchMessageStart[3] = 0x0b;
        nDefaultPort = 51938;
        nBIP44ID = 0x80000001;

        nModifierInterval = 10 * 60;    // 10 minutes
        nStakeMinConfirmations = 225;   // 225 * 2 minutes
        nTargetSpacing = 120;           // 2 minutes
        nTargetTimespan = 24 * 60;      // 24 mins


        AddImportHashesTest(vImportedCoinbaseTxns);
        SetLastImportHeight();

        nPruneAfterHeight = 1000;


        //genesis = CreateGenesisBlockTestNet(1502309248, 5924, 0x1f00ffff);
        //genesis = CreateGenesisBlockTestNet(1552629600, 225979, 0x1f00ffff);
        genesis = CreateGenesisBlockTestNet(1555394400, 108924, 0x1f00ffff);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x00008ab5d5d46776fa2e39fc63f13f9ede4c8319d701bc0f631ea522581d3a90"));
        assert(genesis.hashMerkleRoot == uint256S("0x11b6fc39cda0cd677d6e7682774cb64180534e4985799e6134aea5c83d835cf8"));
        assert(genesis.hashWitnessMerkleRoot == uint256S("0xe4b8d6a03ef85a7c9328a35277d2cefe948c3f0233c5205dbec05418528205b3"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        //vSeeds.emplace_back("testnet-seed.particl.io");
        //vSeeds.emplace_back("dnsseed-testnet.particl.io");

        //vDevFundSettings.push_back(std::make_pair(0, DevFundSettings("rTvv9vsbu269mjYYEecPYinDG8Bt7D86qD", 10, 60)));
        vDevFundSettings.push_back(std::make_pair(0, DevFundSettings("rNMdL2EHrUVwdVN5tsVBRny5UGshbsoiWD", 10, 60)));

        base58Prefixes[PUBKEY_ADDRESS]     = {0x76}; // p
        base58Prefixes[SCRIPT_ADDRESS]     = {0x7a};
        base58Prefixes[PUBKEY_ADDRESS_256] = {0x77};
        base58Prefixes[SCRIPT_ADDRESS_256] = {0x7b};
        base58Prefixes[SECRET_KEY]         = {0x2e};
        base58Prefixes[EXT_PUBLIC_KEY]     = {0xe1, 0x42, 0x78, 0x00}; // ppar
        base58Prefixes[EXT_SECRET_KEY]     = {0x04, 0x88, 0x94, 0x78}; // xpar
        base58Prefixes[STEALTH_ADDRESS]    = {0x15}; // T
        base58Prefixes[EXT_KEY_HASH]       = {0x89}; // x
        base58Prefixes[EXT_ACC_HASH]       = {0x53}; // a
        base58Prefixes[EXT_PUBLIC_KEY_BTC] = {0x04, 0x35, 0x87, 0xCF}; // tpub
        base58Prefixes[EXT_SECRET_KEY_BTC] = {0x04, 0x35, 0x83, 0x94}; // tprv

        bech32Prefixes[PUBKEY_ADDRESS].assign       ("tph","tph"+3);
        bech32Prefixes[SCRIPT_ADDRESS].assign       ("tpr","tpr"+3);
        bech32Prefixes[PUBKEY_ADDRESS_256].assign   ("tpl","tpl"+3);
        bech32Prefixes[SCRIPT_ADDRESS_256].assign   ("tpj","tpj"+3);
        bech32Prefixes[SECRET_KEY].assign           ("tpx","tpx"+3);
        bech32Prefixes[EXT_PUBLIC_KEY].assign       ("tpep","tpep"+4);
        bech32Prefixes[EXT_SECRET_KEY].assign       ("tpex","tpex"+4);
        bech32Prefixes[STEALTH_ADDRESS].assign      ("tps","tps"+3);
        bech32Prefixes[EXT_KEY_HASH].assign         ("tpek","tpek"+4);
        bech32Prefixes[EXT_ACC_HASH].assign         ("tpea","tpea"+4);
        bech32Prefixes[STAKE_ONLY_PKADDR].assign    ("tpcs","tpcs"+4);

        bech32_hrp = "tb";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                /*{127620, uint256S("0xe5ab909fc029b253bad300ccf859eb509e03897e7853e8bfdde2710dbf248dd1")},
                {210920, uint256S("0x5534f546c3b5a264ca034703b9694fabf36d749d66e0659eef5f0734479b9802")},
                {259290, uint256S("0x58267bdf935a2e0716cb910d055b8cdaa019089a5f71c3db90765dc7101dc5dc")},
                {312860, uint256S("0xaba2e3b2dcf1970b53b67c869325c5eefd3a107e62518fa4640ddcfadf88760d")},
                {331600, uint256S("0xeecbeafc4b338901e3dfb6eeaefc128ef477dfe1e6f0f96bd63da27caf113ddc")},*/
                {000000, uint256S("0x00008ab5d5d46776fa2e39fc63f13f9ede4c8319d701bc0f631ea522581d3a90")},
            }
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096 eecbeafc4b338901e3dfb6eeaefc128ef477dfe1e6f0f96bd63da27caf113ddc
            /* nTime    */ 1555394400,
            /* nTxCount */ 356622,
            /* dTxRate  */ 0.006
        };

        /* enable fallback fee on testnet */
        m_fallback_fee_enabled = true;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Exception = uint256();
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.OpIsCoinstakeTime = 0;
        consensus.fAllowOpIsCoinstakeWithP2PKH = false;
        consensus.nPaidSmsgTime = 0;
        consensus.csp2shTime = 0;

        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        consensus.nMinRCTOutputDepth = 1;

        pchMessageStart[0] = 0x09;
        pchMessageStart[1] = 0x12;
        pchMessageStart[2] = 0x06;
        pchMessageStart[3] = 0x0c;
        nDefaultPort = 11938;
        nBIP44ID = 0x80000001;


        nModifierInterval = 2 * 60;     // 2 minutes
        nStakeMinConfirmations = 12;
        nTargetSpacing = 5;             // 5 seconds
        nTargetTimespan = 16 * 60;      // 16 mins
        nStakeTimestampMask = 0;

        SetLastImportHeight();

        nPruneAfterHeight = 1000;


        //genesis = CreateGenesisBlockRegTest(1487714923, 0, 0x207fffff);
        //genesis = CreateGenesisBlockRegTest(1552629600, 3, 0x207fffff);
        genesis = CreateGenesisBlockRegTest(1555401600, 3, 0x207fffff);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x2b4059e9347ec5cd00f160fd292e75a35141915230a54c562e56a0eb4b1913e5"));
        assert(genesis.hashMerkleRoot == uint256S("0x886dbb9002a3ee2c7f9cdc4ed63ea0bffc3a6e5f25a9cc4d8f2120e6abf80b40"));
        assert(genesis.hashWitnessMerkleRoot == uint256S("0x4147056d508ed74706dbf9ab46933e982720b8e3badeedbbefe3d5c891d69577"));


        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {
               // {0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")},
               {0, uint256S("0x2b4059e9347ec5cd00f160fd292e75a35141915230a54c562e56a0eb4b1913e5")},
            }
        };

        base58Prefixes[PUBKEY_ADDRESS]     = {0x76}; // p
        base58Prefixes[SCRIPT_ADDRESS]     = {0x7a};
        base58Prefixes[PUBKEY_ADDRESS_256] = {0x77};
        base58Prefixes[SCRIPT_ADDRESS_256] = {0x7b};
        base58Prefixes[SECRET_KEY]         = {0x2e};
        base58Prefixes[EXT_PUBLIC_KEY]     = {0xe1, 0x42, 0x78, 0x00}; // ppar
        base58Prefixes[EXT_SECRET_KEY]     = {0x04, 0x88, 0x94, 0x78}; // xpar
        base58Prefixes[STEALTH_ADDRESS]    = {0x15}; // T
        base58Prefixes[EXT_KEY_HASH]       = {0x89}; // x
        base58Prefixes[EXT_ACC_HASH]       = {0x53}; // a
        base58Prefixes[EXT_PUBLIC_KEY_BTC] = {0x04, 0x35, 0x87, 0xCF}; // tpub
        base58Prefixes[EXT_SECRET_KEY_BTC] = {0x04, 0x35, 0x83, 0x94}; // tprv

        bech32Prefixes[PUBKEY_ADDRESS].assign       ("tph","tph"+3);
        bech32Prefixes[SCRIPT_ADDRESS].assign       ("tpr","tpr"+3);
        bech32Prefixes[PUBKEY_ADDRESS_256].assign   ("tpl","tpl"+3);
        bech32Prefixes[SCRIPT_ADDRESS_256].assign   ("tpj","tpj"+3);
        bech32Prefixes[SECRET_KEY].assign           ("tpx","tpx"+3);
        bech32Prefixes[EXT_PUBLIC_KEY].assign       ("tpep","tpep"+4);
        bech32Prefixes[EXT_SECRET_KEY].assign       ("tpex","tpex"+4);
        bech32Prefixes[STEALTH_ADDRESS].assign      ("tps","tps"+3);
        bech32Prefixes[EXT_KEY_HASH].assign         ("tpek","tpek"+4);
        bech32Prefixes[EXT_ACC_HASH].assign         ("tpea","tpea"+4);
        bech32Prefixes[STAKE_ONLY_PKADDR].assign    ("tpcs","tpcs"+4);

        bech32_hrp = "bcrt";

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        /* enable fallback fee on regtest */
        m_fallback_fee_enabled = true;
    }

    void SetOld()
    {
        genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        /*
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        */

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

const CChainParams *pParams() {
    return globalChainParams.get();
};

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}


void SetOldParams(std::unique_ptr<CChainParams> &params)
{
    if (params->NetworkID() == CBaseChainParams::MAIN)
        return ((CMainParams*)params.get())->SetOld();
    if (params->NetworkID() == CBaseChainParams::REGTEST)
        return ((CRegTestParams*)params.get())->SetOld();
};

void ResetParams(std::string sNetworkId, bool fParticlModeIn)
{
    // Hack to pass old unit tests
    globalChainParams = CreateChainParams(sNetworkId);
    if (!fParticlModeIn)
    {
        SetOldParams(globalChainParams);
    };
};

/**
 * Mutable handle to regtest params
 */
CChainParams &RegtestParams()
{
    return *globalChainParams.get();
};

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}


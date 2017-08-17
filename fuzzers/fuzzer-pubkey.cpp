#include "fuzzer.h"
#include "pubkey.h"
#include "base58.h"

/* Fuzzers classes CBitcoinSecret, CKey, CPubKey */

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    static ECCVerifyHandle global;
    ECC_Start();
    SelectParams(CBaseChainParams::MAIN);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    CBitcoinSecret bsecret1;
    std::string s;
    s.append((const char*)data, size);
    if ( bsecret1.SetString (s) == false ) {
        return 0;
    }
    CKey key1  = bsecret1.GetKey();
    CPubKey pubkey1  = key1.GetPubKey();
    key1.VerifyPubKey(pubkey1);
    key1.GetPrivKey();

    CTxDestination(pubkey1.GetID());

    return 0;
}

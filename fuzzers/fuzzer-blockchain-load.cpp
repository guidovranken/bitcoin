#include "fuzzer.h"

/* Fuzzes these functions:
 *  - LoadExternalBlockFile()
 */

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FILE* fp;
    static const CChainParams chainparams = Params("main");

    fp = fopen("/tmp/bootstrap", "wb");
    if ( fp == NULL )
    {
        abort();
    }
    fwrite(data, size, 1, fp);
    fclose(fp);
    fp = fopen("/tmp/bootstrap", "rb");
    LoadExternalBlockFile(chainparams, fp);
    return 0;
}


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
    static const CChainParams chainparams = Params("main");

    FILE* fp = std::tmpfile();
    if ( fwrite(data, 1, size, fp) != size ) {
        abort();
    }
    rewind(fp);
    LoadExternalBlockFile(chainparams, fp);
    return 0;
}


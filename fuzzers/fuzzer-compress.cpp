#include "fuzzer.h"
#include "merkleblock.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if ( size < (sizeof(uint64_t)) ) {
        return 0;
    }

    uint64_t a;

    memcpy(&a, data, sizeof(a)); data += sizeof(a);
    CTxOutCompressor::CompressAmount(a);
    CTxOutCompressor::DecompressAmount(a);
    CTxOutCompressor::DecompressAmount(CTxOutCompressor::CompressAmount(a));
    CTxOutCompressor::CompressAmount(CTxOutCompressor::DecompressAmount(a));
    CTxOutCompressor toc(to);
    return 0;
}

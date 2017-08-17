#include "fuzzer.h"
#include "base58.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::string s58, s32, s64;
    std::vector<unsigned char> vchRet;
    s58.append((const char*)data, size);
    s32 = s58;
    s64 = s58;

    EncodeBase58(data, data+size);
    DecodeBase58(s58, vchRet);

    EncodeBase32(data, size);
    DecodeBase32(s32);

    EncodeBase64(data, size);
    DecodeBase64(s64);
    return 0;
}

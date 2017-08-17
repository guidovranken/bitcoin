#include "fuzzer.h"
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    size_t i = 0;
    CMedianFilter<char> filter(200, 0);
    while ( i < size ) {
        filter.input((char)data[i++]);
        filter.median();
    }
    filter.sorted();

    return 0;
}
